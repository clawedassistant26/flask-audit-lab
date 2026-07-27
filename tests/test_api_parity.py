"""The hardening must not change what a legitimate client sees.

Every test here runs against both builds. If a fix broke the product, one of
these fails. This is the half of an audit deliverable that clients actually
care about: the findings are closed and the API still works.
"""

import sqlite3


def test_register_returns_the_new_user(either):
    response = either.register("user", "user-password-1")

    assert response.status_code == 201
    assert response.get_json()["username"] == "user"


def test_duplicate_username_is_rejected(either):
    either.register("user", "user-password-1")

    assert either.register("user", "other-password-1").status_code == 409


def test_register_requires_both_fields(either):
    assert either.register("", "user-password-1").status_code == 400
    assert either.register("user", "").status_code == 400


def test_login_returns_a_usable_token(either):
    either.register("user", "user-password-1")

    token = either.login("user", "user-password-1").get_json()["token"]

    assert either.client.get("/expenses", headers=either.auth(token)).status_code == 200


def test_logging_in_twice_keeps_both_sessions_alive(either):
    """Sessions are concurrent: a second login does not end the first."""
    either.register("user", "user-password-1")

    first = either.login("user", "user-password-1").get_json()["token"]
    second = either.login("user", "user-password-1").get_json()["token"]

    assert either.client.get("/expenses", headers=either.auth(first)).status_code == 200
    assert either.client.get("/expenses", headers=either.auth(second)).status_code == 200


def test_wrong_password_is_rejected(either):
    either.register("user", "user-password-1")

    assert either.login("user", "nope").status_code == 401


def test_expenses_require_authentication(either):
    for path in ["/expenses", "/expenses/1", "/expenses/search?q=x", "/admin/report"]:
        assert either.client.get(path).status_code == 401, path

    assert either.client.post("/expenses", json={"description": "x"}).status_code == 401


def test_a_garbage_token_is_rejected(either):
    assert (
        either.client.get("/expenses", headers=either.auth("not-a-real-token")).status_code
        == 401
    )


def test_create_and_list_round_trip(either):
    token = either.token_for("user", "user-password-1")

    created = either.add_expense(token, "team lunch", 4200)
    assert created.status_code == 201

    rows = either.client.get("/expenses", headers=either.auth(token)).get_json()
    assert len(rows) == 1
    assert rows[0]["description"] == "team lunch"
    assert rows[0]["amount_cents"] == 4200


def test_new_expenses_start_unapproved(either):
    token = either.token_for("user", "user-password-1")
    either.add_expense(token, "team lunch", 4200)

    rows = either.client.get("/expenses", headers=either.auth(token)).get_json()

    assert rows[0]["is_approved"] == 0


def test_owner_can_fetch_their_own_expense_by_id(either):
    token = either.token_for("user", "user-password-1")
    new_id = either.add_expense(token, "team lunch", 4200).get_json()["id"]

    response = either.client.get(f"/expenses/{new_id}", headers=either.auth(token))

    assert response.status_code == 200
    assert response.get_json()["description"] == "team lunch"


def test_missing_expense_returns_404(either):
    token = either.token_for("user", "user-password-1")

    assert either.client.get("/expenses/999", headers=either.auth(token)).status_code == 404


def test_search_finds_the_callers_own_rows(either):
    token = either.token_for("user", "user-password-1")
    either.add_expense(token, "team lunch", 4200)
    either.add_expense(token, "train ticket", 1500)

    rows = either.client.get(
        "/expenses/search?q=lunch", headers=either.auth(token)
    ).get_json()

    assert [r["description"] for r in rows] == ["team lunch"]


def test_search_with_no_match_is_empty(either):
    token = either.token_for("user", "user-password-1")
    either.add_expense(token, "team lunch", 4200)

    rows = either.client.get(
        "/expenses/search?q=zzzz", headers=either.auth(token)
    ).get_json()

    assert rows == []


def test_users_only_see_their_own_expenses(either):
    alice = either.token_for("alice", "alice-password-1")
    bob = either.token_for("bob", "bob-password-1")
    either.add_expense(alice, "alice dinner", 3000)
    either.add_expense(bob, "bob taxi", 1200)

    alice_rows = either.client.get("/expenses", headers=either.auth(alice)).get_json()

    assert [r["description"] for r in alice_rows] == ["alice dinner"]


def test_admin_report_is_forbidden_for_normal_users(either):
    token = either.token_for("user", "user-password-1")

    assert either.client.get("/admin/report", headers=either.auth(token)).status_code == 403


def test_admin_report_returns_every_expense(either):
    alice = either.token_for("alice", "alice-password-1")
    either.add_expense(alice, "alice dinner", 3000)
    bob = either.token_for("bob", "bob-password-1")
    either.add_expense(bob, "bob taxi", 1200)

    conn = sqlite3.connect(either.db_path)
    conn.execute("UPDATE users SET is_admin = 1 WHERE username = 'alice'")
    conn.commit()
    conn.close()

    rows = either.client.get("/admin/report", headers=either.auth(alice)).get_json()

    assert len(rows) == 2


def test_rates_works_for_valid_input(either):
    response = either.client.get("/rates?divisor=4")

    assert response.status_code == 200
    assert response.get_json()["rate"] == 25
