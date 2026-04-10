# tests/test_rbac_gaps.py
#
# Tests that fill the gaps in section 8 of the test plan.
# Many items (8.3.4, 8.3.6, 8.3.7, 8.3.9, 8.3.10, 8.4.5, 8.4.7) are already
# covered by test_rbac_full.py — this file adds only genuine new tests:
#
#   8.1.9  Update role name (via HTTP PATCH — CLI does not expose this)
#   8.1.11 Search/list roles
#   8.2.11 Describe rule by short ID prefix
#   8.2.12 Search/list rules
#   8.4.3  Account with secret:reveal only cannot create secrets
#   8.4.4  Deny rule overrides allow rule
#   8.4.6  Secret-scoped rule only applies to that specific secret
#   8.4.8  Removing binding revokes access

import json
import os
import uuid

import pytest
import requests

import hkey
import helpers


def server_url():
    return os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")


def _auth_header():
    hkey.login()
    return {"Authorization": f"Bearer {hkey.client.AUTH_TOKEN}"}


def _unique(prefix="x"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _limited_token(account_name, password="SecurePassword1!"):
    """Create a user with no RBAC permissions and return their access token."""
    helpers.create_user_account(account_name, password=password, activate=True)
    return helpers.login_as(account_name, password)


def _ns_create(path):
    result = hkey.run("namespace", "create", "--namespace", path)
    assert result.returncode == 0, f"namespace create '{path}' failed: {result.stderr}"


def _secret_create(ref, value="test-value"):
    result = hkey.run("secret", "create", "--ref", ref, "--value", value)
    assert result.returncode == 0, f"secret create '{ref}' failed: {result.stderr}"


# ---------------------------------------------------------------------------
# 8.1.9 — Update role name via HTTP PATCH
# ---------------------------------------------------------------------------

class TestUpdateRoleName:

    def test_update_role_name_via_http(self):
        """8.1.9 — PATCH /v1/rbac/role/{name} with a new name renames the role."""
        original_name = _unique("role-rename-src")
        new_name = _unique("role-rename-dst")

        result = hkey.run("rbac", "role", "create", "--name", original_name)
        assert result.returncode == 0, f"role create failed: {result.stderr}"

        r = requests.patch(
            f"{server_url()}/v1/rbac/role/{original_name}",
            json={"name": new_name},
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"PATCH role name failed: {r.text}"
        data = r.json()
        entry = data.get("data", data)
        assert entry["name"] == new_name, f"Expected name '{new_name}', got: {entry}"

        # Original name should no longer exist
        r2 = requests.get(
            f"{server_url()}/v1/rbac/role/{original_name}",
            headers=_auth_header(),
        )
        assert r2.status_code == 404, (
            f"Expected 404 for old role name after rename, got {r2.status_code}"
        )

        # Clean up
        hkey.run("rbac", "role", "delete", "--name", new_name, "--force")

    def test_update_role_name_conflict_returns_409(self):
        """8.1.9 — Renaming a role to an existing name returns 409."""
        role_a = _unique("role-conflict-a")
        role_b = _unique("role-conflict-b")

        hkey.run("rbac", "role", "create", "--name", role_a)
        hkey.run("rbac", "role", "create", "--name", role_b)

        r = requests.patch(
            f"{server_url()}/v1/rbac/role/{role_a}",
            json={"name": role_b},
            headers=_auth_header(),
        )
        assert r.status_code == 409, (
            f"Expected 409 on role name conflict, got {r.status_code}: {r.text}"
        )

        # Clean up
        hkey.run("rbac", "role", "delete", "--name", role_a, "--force")
        hkey.run("rbac", "role", "delete", "--name", role_b, "--force")


# ---------------------------------------------------------------------------
# 8.1.11 — Search/list roles
# ---------------------------------------------------------------------------

class TestSearchRoles:

    def test_search_roles_returns_list(self):
        """8.1.11 — POST /v1/rbac/role/search returns a list of roles."""
        r = requests.post(
            f"{server_url()}/v1/rbac/role/search",
            json={},
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"role search failed: {r.text}"
        body = r.json()
        data = body.get("data", body)
        assert "entries" in data, f"Expected 'entries' key in response: {data}"
        assert isinstance(data["entries"], list)

    def test_search_roles_includes_created_role(self):
        """8.1.11 — A newly created role appears in the search results."""
        name = _unique("role-search")
        hkey.run("rbac", "role", "create", "--name", name, "--description", "search-test")

        r = requests.post(
            f"{server_url()}/v1/rbac/role/search",
            json={},
            headers=_auth_header(),
        )
        assert r.status_code == 200
        data = r.json().get("data", r.json())
        names = [e["name"] for e in data.get("entries", [])]
        assert name in names, f"Expected role '{name}' in search results, got: {names}"

        hkey.run("rbac", "role", "delete", "--name", name, "--force")

    def test_search_roles_via_cli(self):
        """8.1.11 (CLI) — hkey rbac role list returns roles in JSON."""
        result = hkey.run("rbac", "role", "list", "--json")
        assert result.returncode == 0, f"rbac role list failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert isinstance(data, list), f"Expected list from rbac role list: {data}"


# ---------------------------------------------------------------------------
# 8.2.11 — Describe rule by short ID prefix
# ---------------------------------------------------------------------------

class TestDescribeRuleByShortId:

    def test_describe_rule_by_short_id(self):
        """8.2.11 — GET /v1/rbac/rule/{short_id} resolves by prefix."""
        # Create a rule and get its full ID
        result = hkey.run(
            "rbac", "rule", "create",
            "--rule", "allow secret:reveal to all",
            "--json",
        )
        assert result.returncode == 0, f"rule create failed: {result.stderr}"
        rule_data = json.loads(result.stdout)
        rule_id = str(rule_data.get("id", rule_data.get("data", {}).get("id", "")))
        assert rule_id, f"No rule id in response: {rule_data}"

        # Use first 8 chars as short ID prefix
        short_prefix = rule_id[:8]

        r = requests.get(
            f"{server_url()}/v1/rbac/rule/{short_prefix}",
            headers=_auth_header(),
        )
        assert r.status_code == 200, (
            f"GET /v1/rbac/rule/{short_prefix} failed: {r.text}"
        )
        data = r.json().get("data", r.json())
        assert str(data.get("id", "")).startswith(short_prefix) or data.get("id") == rule_id, (
            f"Returned rule id doesn't match: {data}"
        )

        # Clean up
        hkey.run("rbac", "rule", "delete", "--id", rule_id)

    def test_describe_rule_by_full_id(self):
        """8.2.11 — GET /v1/rbac/rule/{full_id} also resolves correctly."""
        result = hkey.run(
            "rbac", "rule", "create",
            "--rule", "allow secret:create to all",
            "--json",
        )
        assert result.returncode == 0
        rule_data = json.loads(result.stdout)
        rule_id = str(rule_data.get("id", rule_data.get("data", {}).get("id", "")))

        r = requests.get(
            f"{server_url()}/v1/rbac/rule/{rule_id}",
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"GET rule by full id failed: {r.text}"
        data = r.json().get("data", r.json())
        assert str(data.get("id")) == rule_id

        hkey.run("rbac", "rule", "delete", "--id", rule_id)


# ---------------------------------------------------------------------------
# 8.2.12 — Search/list rules
# ---------------------------------------------------------------------------

class TestSearchRules:

    def test_search_rules_returns_list(self):
        """8.2.12 — POST /v1/rbac/rule/search returns a list of rules."""
        r = requests.post(
            f"{server_url()}/v1/rbac/rule/search",
            json={},
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"rule search failed: {r.text}"
        body = r.json()
        data = body.get("data", body)
        assert "entries" in data, f"Expected 'entries' key in response: {data}"
        assert isinstance(data["entries"], list)

    def test_search_rules_includes_created_rule(self):
        """8.2.12 — A newly created rule appears in search results."""
        result = hkey.run(
            "rbac", "rule", "create",
            "--rule", "allow namespace:describe to all",
            "--json",
        )
        assert result.returncode == 0
        rule_data = json.loads(result.stdout)
        rule_id = str(rule_data.get("id", rule_data.get("data", {}).get("id", "")))

        r = requests.post(
            f"{server_url()}/v1/rbac/rule/search",
            json={},
            headers=_auth_header(),
        )
        assert r.status_code == 200
        data = r.json().get("data", r.json())
        ids = [str(e.get("id")) for e in data.get("entries", [])]
        assert rule_id in ids, f"Expected rule '{rule_id}' in search results"

        hkey.run("rbac", "rule", "delete", "--id", rule_id)

    def test_search_rules_via_cli(self):
        """8.2.12 (CLI) — hkey rbac rule list returns rules in JSON."""
        result = hkey.run("rbac", "rule", "list", "--json")
        assert result.returncode == 0, f"rbac rule list failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert isinstance(data, list), f"Expected list from rbac rule list: {data}"


# ---------------------------------------------------------------------------
# 8.4.3 — Account with secret:reveal only cannot create secrets
# ---------------------------------------------------------------------------

class TestRevealOnlyCannotCreate:

    def test_reveal_only_user_cannot_create_secret(self):
        """8.4.3 — A user bound only to secret:reveal is denied secret:create."""
        ns = f"/rbac-reveal-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        name = _unique("rbac-reveal-only")
        helpers.create_user_account(name, activate=True)
        hkey.run(
            "rbac", "bind",
            "--name", name,
            "--rule", f"allow secret:reveal to namespace {ns}",
        )
        token = helpers.login_as(name, "SecurePassword1!")

        result = hkey.run_as(
            token,
            "secret", "create",
            "--ref", f"{ns}:reveal-only-test",
            "--value", "blocked",
        )
        assert result.returncode != 0, (
            "Expected secret:create to fail for user with only secret:reveal"
        )


# ---------------------------------------------------------------------------
# 8.4.4 — Deny rule overrides allow rule
# ---------------------------------------------------------------------------

class TestDenyOverridesAllow:

    def test_deny_overrides_allow_for_secret_create(self):
        """8.4.4 — A deny rule for secret:create takes precedence over an allow rule."""
        ns = f"/rbac-deny-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        name = _unique("rbac-deny-test")
        helpers.create_user_account(name, activate=True)

        # Grant broad allow then specific deny for this namespace
        hkey.run(
            "rbac", "bind",
            "--name", name,
            "--rule", "allow secret:create to all",
        )
        hkey.run(
            "rbac", "bind",
            "--name", name,
            "--rule", f"deny secret:create to namespace {ns}",
        )
        token = helpers.login_as(name, "SecurePassword1!")

        result = hkey.run_as(
            token,
            "secret", "create",
            "--ref", f"{ns}:deny-test",
            "--value", "blocked-by-deny",
        )
        assert result.returncode != 0, (
            "Expected secret:create to fail because deny overrides allow"
        )

    def test_deny_does_not_affect_other_namespace(self):
        """8.4.4 — The deny rule only blocks the targeted namespace; others are unaffected."""
        ns_allowed = f"/rbac-allow-{uuid.uuid4().hex[:8]}"
        ns_denied = f"/rbac-deny2-{uuid.uuid4().hex[:8]}"
        _ns_create(ns_allowed)
        _ns_create(ns_denied)

        name = _unique("rbac-deny-scope")
        helpers.create_user_account(name, activate=True)

        hkey.run(
            "rbac", "bind",
            "--name", name,
            "--rule", "allow secret:create to all",
        )
        hkey.run(
            "rbac", "bind",
            "--name", name,
            "--rule", f"deny secret:create to namespace {ns_denied}",
        )
        token = helpers.login_as(name, "SecurePassword1!")

        # Should succeed in the allowed namespace
        result = hkey.run_as(
            token,
            "secret", "create",
            "--ref", f"{ns_allowed}:should-work",
            "--value", "ok",
        )
        assert result.returncode == 0, (
            f"Expected create to succeed in non-denied namespace: {result.stderr}"
        )

        # Should fail in the denied namespace
        result = hkey.run_as(
            token,
            "secret", "create",
            "--ref", f"{ns_denied}:should-fail",
            "--value", "blocked",
        )
        assert result.returncode != 0, (
            "Expected create to fail in the denied namespace"
        )


# ---------------------------------------------------------------------------
# 8.4.6 — Secret-scoped rule only applies to that specific secret
# ---------------------------------------------------------------------------

class TestSecretScopedRule:

    def test_secret_scoped_reveal_only_applies_to_that_secret(self):
        """8.4.6 — A rule scoped to one secret does not grant access to others."""
        ns = f"/rbac-scoped-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        ref_allowed = f"{ns}:allowed-secret"
        ref_blocked = f"{ns}:blocked-secret"
        _secret_create(ref_allowed, "value-a")
        _secret_create(ref_blocked, "value-b")

        name = _unique("rbac-scoped-user")
        helpers.create_user_account(name, activate=True)
        hkey.run(
            "rbac", "bind",
            "--name", name,
            "--rule", f"allow secret:reveal to secret {ref_allowed}",
        )
        token = helpers.login_as(name, "SecurePassword1!")

        # Can reveal the permitted secret
        result = hkey.run_as(
            token,
            "secret", "reveal",
            "--ref", f"{ref_allowed}@active",
        )
        assert result.returncode == 0, (
            f"Expected reveal to succeed for the permitted secret: {result.stderr}"
        )

        # Cannot reveal the other secret in the same namespace
        result = hkey.run_as(
            token,
            "secret", "reveal",
            "--ref", f"{ref_blocked}@active",
        )
        assert result.returncode != 0, (
            "Expected reveal to fail for a secret not covered by the scoped rule"
        )


# ---------------------------------------------------------------------------
# 8.4.8 — Removing binding revokes access
# ---------------------------------------------------------------------------

class TestUnbindRevokesAccess:

    def test_unbind_revokes_access(self):
        """8.4.8 — After unbinding a rule, previously allowed operations are denied."""
        ns = f"/rbac-unbind-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)
        _secret_create(f"{ns}:revoke-test", "secret-value")

        name = _unique("rbac-unbind-user")
        helpers.create_user_account(name, activate=True)

        # Bind a rule to give reveal access
        result = hkey.run(
            "rbac", "bind",
            "--name", name,
            "--rule", f"allow secret:reveal to namespace {ns}",
        )
        assert result.returncode == 0, f"bind failed: {result.stderr}"

        token = helpers.login_as(name, "SecurePassword1!")

        # Confirm access works before unbind
        result_before = hkey.run_as(
            token,
            "secret", "reveal",
            "--ref", f"{ns}:revoke-test@active",
        )
        assert result_before.returncode == 0, (
            f"Expected reveal to succeed before unbind: {result_before.stderr}"
        )

        # Query bindings to find the direct rule IDs to unbind
        r = requests.post(
            f"{server_url()}/v1/rbac/bindings",
            json={"account": name},
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"bindings query failed: {r.text}"
        # Response: { "data": { "account": "...", "roles": [...], "rules": [...] } }
        bindings_data = r.json().get("data", r.json())
        direct_rules = bindings_data.get("rules", [])
        assert direct_rules, "Expected at least one direct rule binding"

        for rule in direct_rules:
            rule_id = str(rule.get("id", ""))
            if rule_id:
                hkey.run("rbac", "unbind", "--name", name, "--rule-id", rule_id)

        # Refresh token so the new permission state is evaluated
        token = helpers.login_as(name, "SecurePassword1!")

        # Access should now be denied
        result_after = hkey.run_as(
            token,
            "secret", "reveal",
            "--ref", f"{ns}:revoke-test@active",
        )
        assert result_after.returncode != 0, (
            "Expected reveal to fail after binding was removed"
        )
