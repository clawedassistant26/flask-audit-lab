"""Checks openapi.yaml against the hardened build it claims to describe.

A specification nobody tests drifts from the code within a release or two. These
tests fail the build when the two disagree, in either direction: an undocumented
route and a documented route that does not exist are both errors.
"""

import re
from pathlib import Path

import pytest
import yaml

SPEC_PATH = Path(__file__).resolve().parent.parent / "openapi.yaml"

# Flask adds these automatically; they are not part of the published API.
IGNORED_ENDPOINTS = {"static"}


@pytest.fixture(scope="module")
def spec():
    with SPEC_PATH.open() as handle:
        return yaml.safe_load(handle)


def flask_routes(app):
    """The app's routes as (path, method) pairs in OpenAPI path syntax."""
    routes = set()
    for rule in app.url_map.iter_rules():
        if rule.endpoint in IGNORED_ENDPOINTS:
            continue
        path = re.sub(r"<(?:[^:<>]+:)?([^<>]+)>", r"{\1}", rule.rule)
        for method in rule.methods - {"HEAD", "OPTIONS"}:
            routes.add((path, method.lower()))
    return routes


def spec_routes(spec):
    return {
        (path, method)
        for path, operations in spec["paths"].items()
        for method in operations
        if method in {"get", "post", "put", "patch", "delete"}
    }


def test_spec_is_valid_openapi():
    from openapi_spec_validator import validate
    from openapi_spec_validator.readers import read_from_filename

    loaded, _ = read_from_filename(str(SPEC_PATH))
    validate(loaded)


def test_every_route_in_the_app_is_documented(hardened, spec):
    undocumented = flask_routes(hardened.app) - spec_routes(spec)

    assert undocumented == set(), f"routes missing from openapi.yaml: {undocumented}"


def test_every_documented_route_exists_in_the_app(hardened, spec):
    missing = spec_routes(spec) - flask_routes(hardened.app)

    assert missing == set(), f"documented but not implemented: {missing}"


DOCUMENTED_CASES = [
    ("post", "/register", 201),
    ("post", "/register", 400),
    ("post", "/register", 409),
    ("post", "/login", 200),
    ("post", "/login", 401),
    ("post", "/login", 429),
    ("get", "/expenses", 200),
    ("get", "/expenses", 401),
    ("post", "/expenses", 201),
    ("post", "/expenses", 400),
    ("post", "/expenses", 401),
    ("get", "/expenses/search", 200),
    ("get", "/expenses/search", 401),
    ("get", "/expenses/{expense_id}", 200),
    ("get", "/expenses/{expense_id}", 401),
    ("get", "/expenses/{expense_id}", 404),
    ("get", "/admin/report", 401),
    ("get", "/admin/report", 403),
    ("get", "/rates", 200),
    ("get", "/rates", 400),
]


@pytest.mark.parametrize("method,path,status", DOCUMENTED_CASES)
def test_response_codes_asserted_elsewhere_are_documented(spec, method, path, status):
    """Every status code the suite observes must appear in the spec."""
    documented = spec["paths"][path][method]["responses"]

    assert str(status) in documented


def test_error_responses_use_the_documented_shape(hardened):
    """Every error in the spec is {"error": "..."}. Confirm the app agrees."""
    token = hardened.token_for("user", "user-password-1")
    cases = [
        hardened.client.get("/expenses"),
        hardened.client.get("/expenses/999", headers=hardened.auth(token)),
        hardened.client.get("/admin/report", headers=hardened.auth(token)),
        hardened.client.get("/rates?divisor=0"),
        hardened.client.post("/register", json={"username": "", "password": ""}),
        hardened.client.post("/login", json={"username": "ghost", "password": "x"}),
    ]

    for response in cases:
        body = response.get_json()
        assert response.status_code >= 400
        assert list(body.keys()) == ["error"], body
        assert isinstance(body["error"], str) and body["error"]


def test_expense_objects_match_the_documented_schema(hardened, spec):
    token = hardened.token_for("user", "user-password-1")
    hardened.add_expense(token, "team lunch", 4200)

    expense = hardened.client.get("/expenses", headers=hardened.auth(token)).get_json()[0]

    schema = spec["components"]["schemas"]["Expense"]
    assert set(expense.keys()) == set(schema["properties"].keys())
    for field in schema["required"]:
        assert field in expense
    assert isinstance(expense["amount_cents"], int)
    assert expense["is_approved"] in schema["properties"]["is_approved"]["enum"]


def test_login_success_matches_the_documented_schema(hardened):
    hardened.register("user", "user-password-1")

    body = hardened.login("user", "user-password-1").get_json()

    assert list(body.keys()) == ["token"]
    assert isinstance(body["token"], str)


def test_documented_security_matches_which_routes_need_a_token(hardened, spec):
    """Routes marked `security: []` must be reachable without a bearer token.

    Rejecting bad credentials is not the same as demanding a token, so this
    looks for the missing-token error specifically rather than any 401. A login
    that returns "invalid credentials" is behaving correctly.
    """
    unauthenticated = [
        (path, method)
        for path, operations in spec["paths"].items()
        for method, operation in operations.items()
        if method in {"get", "post"} and operation.get("security") == []
    ]
    assert unauthenticated, "expected some routes to be documented as public"

    for path, method in unauthenticated:
        response = hardened.client.open(path, method=method.upper(), json={})
        body = response.get_json() or {}
        assert body.get("error") != "unauthorized", f"{method} {path} demanded a token"


def test_routes_without_explicit_security_do_require_a_token(hardened, spec):
    """The inverse: anything relying on the global security block must 401."""
    protected = [
        (path, method)
        for path, operations in spec["paths"].items()
        for method, operation in operations.items()
        if method in {"get", "post"} and "security" not in operation
    ]
    assert protected, "expected some routes to inherit the global security block"

    for path, method in protected:
        concrete = path.replace("{expense_id}", "1")
        response = hardened.client.open(concrete, method=method.upper(), json={})
        assert response.status_code == 401, f"{method} {path} did not require a token"
        assert response.get_json()["error"] == "unauthorized"
