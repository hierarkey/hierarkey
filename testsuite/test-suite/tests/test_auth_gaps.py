# tests/test_auth_gaps.py
#
# Tests that fill the gaps in sections 2.1–2.4 of the test plan.
# Existing coverage lives in test_auth.py and test_auth_full.py; this
# file only adds what is missing there.

import json
import os
import tempfile

import pytest
import requests

import hkey
import helpers


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def server_url():
    return os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")


def admin_token():
    hkey.login()
    return hkey.client.AUTH_TOKEN


def _login_json(name, password):
    """Log in as *name* via the CLI and return the parsed JSON response."""
    result = hkey.run_unauth(
        "auth", "login",
        "--name", name,
        "--insecure-password", password,
        "--json",
    )
    return result


def _create_user(name, password="SecurePassword1!", activate=True, must_change=False):
    args = [
        "account", "create",
        "--type", "user",
        "--name", name,
        "--insecure-password", password,
    ]
    if activate:
        args.append("--activate")
    if must_change:
        args.append("--must-change-password")
    result = hkey.run(*args)
    if result.returncode != 0:
        assert "name already exists" in result.stderr, (
            f"unexpected error creating account {name}: {result.stderr}"
        )


def _create_sa_passphrase(name, passphrase="ServicePassphrase1!"):
    result = hkey.run(
        "account", "create",
        "--type", "service",
        "--name", name,
        "--auth", "passphrase",
        "--insecure-passphrase", passphrase,
        "--activate",
    )
    if result.returncode != 0:
        assert "name already exists" in result.stderr, (
            f"unexpected error creating SA {name}: {result.stderr}"
        )
        hkey.run("account", "enable", "--name", name)


# ---------------------------------------------------------------------------
# 2.1 User Login — missing cases
# ---------------------------------------------------------------------------

class TestUserLogin:

    def test_login_disabled_account_returns_error(self):
        """2.1.5 — Login with a disabled account is rejected."""
        _create_user("login-disabled-user", activate=True)
        hkey.run("account", "disable", "--name", "login-disabled-user")

        result = _login_json("login-disabled-user", "SecurePassword1!")
        assert result.returncode != 0, "Expected login to fail for disabled account"

    def test_successful_login_clears_failed_attempt_counter(self):
        """2.1.7 — A successful login resets the failed-attempt counter.

        Strategy: make several failed attempts (well below the lockout threshold),
        log in successfully, then make the same number of failed attempts again.
        If the counter were NOT reset the cumulative total would approach the
        threshold; if it IS reset the account remains well below it.
        We confirm by verifying a valid login still works after the second batch.
        """
        name = "login-counter-reset"
        password = "SecurePassword1!"
        _create_user(name, password=password, activate=True)

        # Phase 1: a few failed logins
        for _ in range(3):
            hkey.run_unauth("auth", "login", "--name", name, "--insecure-password", "wrong!")

        # Successful login — should reset the counter
        result = _login_json(name, password)
        assert result.returncode == 0, f"Successful login after failures failed: {result.stderr}"

        # Phase 2: same number of failed logins again
        for _ in range(3):
            hkey.run_unauth("auth", "login", "--name", name, "--insecure-password", "wrong!")

        # Account must still be usable — counter should have been reset after phase 1
        result = _login_json(name, password)
        assert result.returncode == 0, (
            "Account is locked after 3+3 failures with a reset in between; "
            "counter was not cleared on successful login"
        )

    def test_must_change_password_token_rejected_on_regular_endpoints(self):
        """2.1.8 — A must_change_password login token is rejected on general endpoints.

        The server issues a token with 'change_password' scope when must_change_password
        is set. That token must not be accepted on ordinary API endpoints.
        """
        name = "mcp-user"
        password = "SecurePassword1!"
        _create_user(name, password=password, activate=True, must_change=True)

        # Log in — the server should issue a change_password-scoped token
        result = _login_json(name, password)
        assert result.returncode == 0, f"Login failed: {result.stderr}"
        data = json.loads(result.stdout)
        token = data["access_token"]

        # Using the scoped token on a general endpoint must fail
        r = requests.get(
            f"{server_url()}/v1/system/status",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code in (401, 403), (
            f"Expected 401/403 for change_password-scoped token on /v1/system/status, "
            f"got {r.status_code}: {r.text}"
        )

    def test_system_accounts_cannot_login_via_password_endpoint(self):
        """2.1.9 — System accounts ($system etc.) are rejected at the login endpoint."""
        result = hkey.run_unauth(
            "auth", "login",
            "--name", "$system",
            "--insecure-password", "anything",
        )
        assert result.returncode != 0, "Expected login for $system account to fail"


# ---------------------------------------------------------------------------
# 2.2 Token Refresh — missing cases
# ---------------------------------------------------------------------------

class TestTokenRefresh:

    def test_old_access_token_remains_valid_after_refresh(self):
        """2.2.5 — An access token that has not expired stays valid after a refresh."""
        # Obtain a fresh login so we control both tokens
        result = hkey.run_unauth(
            "auth", "login",
            "--name", "admin",
            "--insecure-password", "admin_test_password",
            "--json",
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        old_access = data["access_token"]
        refresh = data["refresh_token"]

        # Perform a refresh to get a new pair
        result = hkey.run_unauth("auth", "refresh", "--refresh-token", refresh, "--json")
        assert result.returncode == 0
        new_access = json.loads(result.stdout)["access_token"]
        assert new_access != old_access, "Refresh did not issue a new access token"

        # The old access token must still work (it has not expired)
        result = hkey.run_as(old_access, "auth", "whoami")
        assert result.returncode == 0, (
            f"Old access token was rejected after refresh: {result.stderr}"
        )

        # The new token also works
        result = hkey.run_as(new_access, "auth", "whoami")
        assert result.returncode == 0, (
            f"New access token was rejected: {result.stderr}"
        )


# ---------------------------------------------------------------------------
# 2.3 Whoami — missing cases
# ---------------------------------------------------------------------------

class TestWhoami:

    def test_whoami_reports_user_account_type(self):
        """2.3.3 — whoami returns account_type = 'user' for a user account (admin)."""
        result = hkey.run("auth", "whoami", "--json")
        assert result.returncode == 0, f"whoami failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert data.get("account_type") == "user", (
            f"Expected account_type 'user' for admin, got: {data.get('account_type')}"
        )

    def test_whoami_reports_service_account_type(self):
        """2.3.3 — whoami returns account_type = 'service' for a service account."""
        _create_sa_passphrase("sa-whoami-type")

        # Obtain a token for the service account
        result = hkey.run_unauth(
            "auth", "sa", "token",
            "--method", "passphrase",
            "--name", "sa-whoami-type",
            "--passphrase", "ServicePassphrase1!",
        )
        assert result.returncode == 0
        token = json.loads(result.stdout)["access_token"]

        result = hkey.run_as(token, "auth", "whoami", "--json")
        assert result.returncode == 0, f"whoami as SA failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert data.get("account_type") == "service", (
            f"Expected account_type 'service', got: {data.get('account_type')}"
        )


# ---------------------------------------------------------------------------
# 2.4 Service Account — Passphrase — missing cases
# ---------------------------------------------------------------------------

class TestSaPassphrase:

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_SA_PASSPHRASE_AUTH_DISABLED"),
        reason=(
            "Requires server started with auth.allow_passphrase_auth = false. "
            "Set HKEY_TEST_SA_PASSPHRASE_AUTH_DISABLED=1 to run."
        ),
    )
    def test_passphrase_auth_disabled_by_config_returns_error(self):
        """2.4.5 — Passphrase auth disabled in server config returns an error."""
        _create_sa_passphrase("sa-pass-disabled-cfg")

        result = hkey.run_unauth(
            "auth", "sa", "token",
            "--method", "passphrase",
            "--name", "sa-pass-disabled-cfg",
            "--passphrase", "ServicePassphrase1!",
        )
        assert result.returncode != 0, (
            "Expected passphrase auth to fail when disabled by config"
        )
        # Should surface a 'disabled' or 'forbidden' message
        assert any(
            word in (result.stdout + result.stderr).lower()
            for word in ("disabled", "forbidden", "not allowed", "403")
        )

    def test_change_password_scope_rejected_on_sa_token_endpoint(self):
        """2.4.6 — Requesting 'change_password' scope on the SA token endpoint is rejected."""
        _create_sa_passphrase("sa-scope-reject")

        # Post directly to the server so we can inject the scope field,
        # which the CLI does not expose.
        payload = {
            "auth": {
                "method": "passphrase",
                "account_name": "sa-scope-reject",
                "passphrase": "ServicePassphrase1!",
            },
            "scope": "change_password",
        }
        r = requests.post(
            f"{server_url()}/v1/auth/service-account/token",
            json=payload,
        )
        assert r.status_code in (400, 422), (
            f"Expected 400/422 for change_password scope on SA token endpoint, "
            f"got {r.status_code}: {r.text}"
        )

    def test_refresh_scope_rejected_on_sa_token_endpoint(self):
        """2.4.6 (variant) — Requesting 'refresh' scope on the SA token endpoint is rejected."""
        _create_sa_passphrase("sa-scope-refresh-reject")

        payload = {
            "auth": {
                "method": "passphrase",
                "account_name": "sa-scope-refresh-reject",
                "passphrase": "ServicePassphrase1!",
            },
            "scope": "refresh",
        }
        r = requests.post(
            f"{server_url()}/v1/auth/service-account/token",
            json=payload,
        )
        assert r.status_code in (400, 422), (
            f"Expected 400/422 for refresh scope on SA token endpoint, "
            f"got {r.status_code}: {r.text}"
        )
