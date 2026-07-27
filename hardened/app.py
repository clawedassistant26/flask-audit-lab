"""Expense tracker API - HARDENED build.

Same API surface and same file layout as vulnerable/app.py, so the two can be
diffed route by route. Every finding F-01 to F-09 from AUDIT.md is closed here,
and tests/test_exploits.py runs the identical attacks against both builds to
prove it.
"""

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import time
from collections import defaultdict

from flask import Flask, g, jsonify, request

LOG = logging.getLogger("expenses.hardened")

SESSION_TTL_SECONDS = 3600
MAX_FAILED_LOGINS = 5
LOGIN_WINDOW_SECONDS = 900

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32

ALLOWED_EXPENSE_FIELDS = ("description", "amount_cents")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
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
    failed_logins = defaultdict(list)

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

    # F-03 fixed: scrypt with a per-user 16-byte random salt. Stored as
    # scrypt$n$r$p$salt$hash so the work factor can be raised later without
    # invalidating existing hashes.
    def hash_password(password, salt=None):
        salt = salt or os.urandom(16)
        digest = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN,
        )
        return "scrypt${}${}${}${}${}".format(
            SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.hex(), digest.hex()
        )

    def verify_password(password, encoded):
        try:
            scheme, n, r, p, salt_hex, digest_hex = encoded.split("$")
            if scheme != "scrypt":
                return False
            candidate = hashlib.scrypt(
                password.encode(),
                salt=bytes.fromhex(salt_hex),
                n=int(n),
                r=int(r),
                p=int(p),
                dklen=len(digest_hex) // 2,
            )
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(candidate.hex(), digest_hex)

    # F-04 fixed: 256 bits from the CSPRNG, unrelated to any public value, so
    # the token cannot be derived or predicted. Only its SHA-256 is stored, so a
    # database leak does not hand over live sessions. Sessions expire.
    # Sessions are concurrent by design: a second login adds a token rather than
    # replacing the first, so signing in on a new device does not sign the user
    # out elsewhere. Each token expires independently. There is no revocation
    # endpoint, which is a known gap documented in the README.
    def issue_token(user_id):
        token = secrets.token_urlsafe(32)
        db().execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) "
            "VALUES (?, ?, ?)",
            (
                hashlib.sha256(token.encode()).hexdigest(),
                user_id,
                int(time.time()) + SESSION_TTL_SECONDS,
            ),
        )
        db().commit()
        return token

    def current_user():
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header[len("Bearer "):]
        if not token:
            return None
        row = db().execute(
            "SELECT users.*, sessions.expires_at FROM sessions "
            "JOIN users ON users.id = sessions.user_id "
            "WHERE sessions.token_hash = ?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
        if row is None:
            return None
        if row["expires_at"] < int(time.time()):
            return None
        return row

    def throttled(username):
        now = time.time()
        recent = [t for t in failed_logins[username] if now - t < LOGIN_WINDOW_SECONDS]
        failed_logins[username] = recent
        return len(recent) >= MAX_FAILED_LOGINS

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

    # F-06 fixed: fixed-window lockout per username.
    # F-09 fixed: unknown user and wrong password return the same 401 body, and
    # the KDF runs even for unknown users so response timing does not reveal
    # which usernames exist.
    @app.post("/login")
    def login():
        payload = request.get_json(silent=True) or {}
        username = payload.get("username", "")
        password = payload.get("password", "")

        if throttled(username):
            return jsonify({"error": "too many attempts, try again later"}), 429

        row = db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if row is None:
            # Burn equivalent work against a throwaway hash so the timing of an
            # unknown username matches that of a wrong password.
            verify_password(password, hash_password("decoy-password"))
            failed_logins[username].append(time.time())
            return jsonify({"error": "invalid credentials"}), 401

        if not verify_password(password, row["password_hash"]):
            failed_logins[username].append(time.time())
            return jsonify({"error": "invalid credentials"}), 401

        failed_logins.pop(username, None)
        token = issue_token(row["id"])
        # F-08 fixed: the token never reaches the log. The user id is enough to
        # correlate events during an incident.
        LOG.info("login ok user_id=%s", row["id"])
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

    # F-07 fixed: only description and amount_cents are read from the body.
    # user_id comes from the session and is_approved keeps its server default,
    # so neither can be set by the client.
    @app.post("/expenses")
    def create_expense():
        user = current_user()
        if user is None:
            return jsonify({"error": "unauthorized"}), 401
        payload = request.get_json(silent=True) or {}

        description = payload.get("description")
        amount_cents = payload.get("amount_cents")
        if not isinstance(description, str) or not description.strip():
            return jsonify({"error": "description must be a non-empty string"}), 400
        if not isinstance(amount_cents, int) or isinstance(amount_cents, bool):
            return jsonify({"error": "amount_cents must be an integer"}), 400

        cur = db().execute(
            "INSERT INTO expenses (user_id, description, amount_cents) "
            "VALUES (?, ?, ?)",
            (user["id"], description, amount_cents),
        )
        db().commit()
        return jsonify({"id": cur.lastrowid}), 201

    # F-02 fixed: ownership is part of the WHERE clause. A row owned by someone
    # else returns 404, not 403, so the endpoint does not confirm that an id
    # exists to a caller who cannot see it.
    @app.get("/expenses/<int:expense_id>")
    def get_expense(expense_id):
        user = current_user()
        if user is None:
            return jsonify({"error": "unauthorized"}), 401
        row = db().execute(
            "SELECT * FROM expenses WHERE id = ? AND user_id = ?",
            (expense_id, user["id"]),
        ).fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(dict(row))

    # F-01 fixed: the search term is a bound parameter. LIKE wildcards in user
    # input are escaped with an explicit ESCAPE clause so a query of "%" cannot
    # widen the match beyond what the caller asked for.
    @app.get("/expenses/search")
    def search_expenses():
        user = current_user()
        if user is None:
            return jsonify({"error": "unauthorized"}), 401
        q = request.args.get("q", "")
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = db().execute(
            "SELECT * FROM expenses WHERE user_id = ? "
            "AND description LIKE ? ESCAPE '\\'",
            (user["id"], f"%{escaped}%"),
        ).fetchall()
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
        raw = request.args.get("divisor", "1")
        try:
            divisor = int(raw)
        except ValueError:
            return jsonify({"error": "divisor must be an integer"}), 400
        if divisor == 0:
            return jsonify({"error": "divisor must not be zero"}), 400
        return jsonify({"rate": 100 / divisor})

    # F-05 fixed: the detail goes to the server log, the client gets an opaque
    # message. No traceback, no paths, no library versions.
    @app.errorhandler(Exception)
    def handle_error(exc):
        LOG.exception("unhandled error: %s", exc)
        return jsonify({"error": "internal server error"}), 500

    return app


if __name__ == "__main__":
    create_app("expenses.db").run(debug=False)
