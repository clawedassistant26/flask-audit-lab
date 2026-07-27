"""Expense tracker API - VULNERABLE build.

This file is the audit target. It contains nine deliberate, realistic
vulnerabilities documented in AUDIT.md (findings F-01 to F-09). Every flaw here
is the kind that shows up in real code review, not a contrived puzzle.

DO NOT DEPLOY THIS. It exists so the hardened build can be diffed against it and
so the exploit suite has something real to attack.
"""

import hashlib
import logging
import sqlite3
import time
import traceback

from flask import Flask, g, jsonify, request

LOG = logging.getLogger("expenses.vulnerable")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    description TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    is_approved INTEGER NOT NULL DEFAULT 0
);
"""


def create_app(db_path):
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    with app.app_context():
        conn = sqlite3.connect(db_path)
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()

    # F-03 (A02 Cryptographic Failures): unsalted single-round MD5. Any breach of
    # the users table is an instant plaintext recovery via rainbow tables.
    def hash_password(password):
        return hashlib.md5(password.encode()).hexdigest()

    # F-04 (A07 Identification & Authentication Failures): the session token is
    # derived from public data (username) plus the current unix second. An
    # attacker who knows the username and roughly when the victim logged in can
    # regenerate the token by brute-forcing a small time window.
    def issue_token(username):
        return hashlib.md5(f"{username}{int(time.time())}".encode()).hexdigest()

    def current_user():
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return None
        row = db().execute(
            "SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id "
            "WHERE sessions.token = ?",
            (token,),
        ).fetchone()
        return row

    @app.post("/register")
    def register():
        payload = request.get_json(silent=True) or {}
        username = payload.get("username", "")
        password = payload.get("password", "")
        if not username or not password:
            return jsonify({"error": "username and password required"}), 400
        try:
            cur = db().execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password)),
            )
            db().commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "username taken"}), 409
        return jsonify({"id": cur.lastrowid, "username": username}), 201

    # F-06 (A04 Insecure Design): no throttling, lockout, or backoff. Credential
    # stuffing runs at whatever rate the network allows.
    @app.post("/login")
    def login():
        payload = request.get_json(silent=True) or {}
        username = payload.get("username", "")
        password = payload.get("password", "")
        row = db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            return jsonify({"error": "no such user"}), 404
        if row["password_hash"] != hash_password(password):
            return jsonify({"error": "wrong password"}), 401
        token = issue_token(username)
        db().execute(
            "INSERT OR REPLACE INTO sessions (token, user_id) VALUES (?, ?)",
            (token, row["id"]),
        )
        db().commit()
        # F-08 (A09 Logging & Monitoring Failures): the bearer token is written
        # to the log in full. Anyone with log access can replay live sessions.
        LOG.info("login ok user=%s token=%s", username, token)
        return jsonify({"token": token})

    @app.get("/expenses")
    def list_expenses():
        user = current_user()
        if user is None:
            return jsonify({"error": "unauthorized"}), 401
        rows = db().execute(
            "SELECT * FROM expenses WHERE user_id = ?", (user["id"],)
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    # F-07 (A08 Software & Data Integrity Failures): mass assignment. Every key
    # in the request body is written straight into the row, so a client can set
    # is_approved or reassign user_id.
    @app.post("/expenses")
    def create_expense():
        user = current_user()
        if user is None:
            return jsonify({"error": "unauthorized"}), 401
        payload = request.get_json(silent=True) or {}
        payload.setdefault("user_id", user["id"])
        columns = ", ".join(payload.keys())
        placeholders = ", ".join("?" for _ in payload)
        cur = db().execute(
            f"INSERT INTO expenses ({columns}) VALUES ({placeholders})",
            tuple(payload.values()),
        )
        db().commit()
        return jsonify({"id": cur.lastrowid}), 201

    # F-02 (A01 Broken Access Control): classic IDOR. The row is fetched by id
    # with no check that it belongs to the caller.
    @app.get("/expenses/<int:expense_id>")
    def get_expense(expense_id):
        user = current_user()
        if user is None:
            return jsonify({"error": "unauthorized"}), 401
        row = db().execute(
            "SELECT * FROM expenses WHERE id = ?", (expense_id,)
        ).fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(dict(row))

    # F-01 (A03 Injection): the search term is formatted into the SQL string, so
    # the caller controls the WHERE clause and can escape their own user_id.
    @app.get("/expenses/search")
    def search_expenses():
        user = current_user()
        if user is None:
            return jsonify({"error": "unauthorized"}), 401
        q = request.args.get("q", "")
        sql = (
            "SELECT * FROM expenses WHERE user_id = "
            f"{user['id']} AND description LIKE '%{q}%'"
        )
        rows = db().execute(sql).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.get("/admin/report")
    def admin_report():
        user = current_user()
        if user is None:
            return jsonify({"error": "unauthorized"}), 401
        if not user["is_admin"]:
            return jsonify({"error": "forbidden"}), 403
        rows = db().execute("SELECT * FROM expenses").fetchall()
        return jsonify([dict(r) for r in rows])

    @app.get("/rates")
    def rates():
        # Deliberately raises, to exercise the error handler below.
        divisor = int(request.args.get("divisor", "1"))
        return jsonify({"rate": 100 / divisor})

    # F-05 (A05 Security Misconfiguration): the exception handler returns the
    # full traceback, leaking file paths, library versions and code structure.
    @app.errorhandler(Exception)
    def handle_error(exc):
        return (
            jsonify({"error": str(exc), "traceback": traceback.format_exc()}),
            500,
        )

    return app


if __name__ == "__main__":
    # Debug mode in a runnable entrypoint: the Werkzeug console is an RCE
    # primitive if this is ever exposed. Part of F-05.
    create_app("expenses.db").run(debug=True)
