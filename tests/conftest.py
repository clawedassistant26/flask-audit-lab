"""Loads both builds side by side so one attack can be fired at each.

Both files are called app.py, so they are loaded from their paths under
distinct module names rather than by package import.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(module_name, relative_path):
    spec = importlib.util.spec_from_file_location(module_name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


vulnerable_app = _load("vulnerable_app", "vulnerable/app.py")
hardened_app = _load("hardened_app", "hardened/app.py")


class Build:
    """One running build plus the helpers an attacker or a user needs."""

    def __init__(self, name, module, db_path):
        self.name = name
        self.module = module
        self.db_path = str(db_path)
        self.app = module.create_app(self.db_path)
        self.app.config.update(TESTING=False, PROPAGATE_EXCEPTIONS=False)
        self.client = self.app.test_client()

    def register(self, username, password):
        return self.client.post(
            "/register", json={"username": username, "password": password}
        )

    def login(self, username, password):
        return self.client.post(
            "/login", json={"username": username, "password": password}
        )

    def token_for(self, username, password):
        self.register(username, password)
        response = self.login(username, password)
        assert response.status_code == 200, response.get_json()
        return response.get_json()["token"]

    def auth(self, token):
        return {"Authorization": f"Bearer {token}"}

    def add_expense(self, token, description, amount_cents):
        return self.client.post(
            "/expenses",
            json={"description": description, "amount_cents": amount_cents},
            headers=self.auth(token),
        )


@pytest.fixture
def vulnerable(tmp_path):
    return Build("vulnerable", vulnerable_app, tmp_path / "vulnerable.db")


@pytest.fixture
def hardened(tmp_path):
    return Build("hardened", hardened_app, tmp_path / "hardened.db")


@pytest.fixture(params=["vulnerable", "hardened"])
def either(request, vulnerable, hardened):
    """Both builds, for the parity tests that assert the API still works."""
    return vulnerable if request.param == "vulnerable" else hardened
