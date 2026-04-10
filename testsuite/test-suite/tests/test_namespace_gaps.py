# tests/test_namespace_gaps.py
#
# Tests that fill the gaps in section 5 of the test plan.
# Existing coverage lives in test_namespace.py and test_namespace_full.py.
#
#   5.2.2   Describe namespace by short ID
#   5.1.13  RBAC: namespace create requires namespace:create
#   5.3.10  RBAC: namespace update requires namespace:update:meta
#   5.4.9   Cannot delete the /$hierarkey system namespace
#   5.4.10  RBAC: namespace disable/delete require namespace:delete

import json
import os
import uuid

import pytest
import requests

import hkey
import helpers


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def server_url():
    return os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")


def _auth_header():
    hkey.login()
    return {"Authorization": f"Bearer {hkey.client.AUTH_TOKEN}"}


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _ns_create(path):
    result = hkey.run("namespace", "create", "--namespace", path)
    assert result.returncode == 0, f"namespace create '{path}' failed: {result.stderr}"


def _ns_describe_json(path):
    result = hkey.run("namespace", "describe", "--namespace", path, "--json")
    assert result.returncode == 0, f"namespace describe '{path}' failed: {result.stderr}"
    return json.loads(result.stdout)["entry"]


def _limited_token(account_name, password="SecurePassword1!"):
    """Create a user with no RBAC permissions and return their access token."""
    helpers.create_user_account(account_name, password=password, activate=True)
    return helpers.login_as(account_name, password)


# ---------------------------------------------------------------------------
# 5.2.2 — Describe namespace by short ID
# ---------------------------------------------------------------------------

class TestDescribeByShortId:

    def test_describe_by_short_id_via_cli(self):
        """5.2.2 — `namespace describe --id <short_id>` returns the same data as --namespace."""
        ns = f"/ns-sid-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        entry_by_name = _ns_describe_json(ns)
        short_id = entry_by_name["short_id"]
        assert short_id, f"No short_id in describe output: {entry_by_name}"

        result = hkey.run("namespace", "describe", "--id", short_id, "--json")
        assert result.returncode == 0, f"describe --id failed: {result.stderr}"
        entry_by_id = json.loads(result.stdout)["entry"]

        assert entry_by_id["namespace"] == ns
        assert entry_by_id["short_id"] == short_id

    def test_describe_by_short_id_via_http(self):
        """5.2.2 (HTTP) — GET /v1/namespaces/id/{id} returns namespace data."""
        ns = f"/ns-sid-http-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        entry = _ns_describe_json(ns)
        short_id = entry["short_id"]

        r = requests.get(
            f"{server_url()}/v1/namespaces/id/{short_id}",
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"GET /id/{short_id} failed: {r.text}"
        data = r.json().get("data", r.json())
        assert data["entry"]["namespace"] == ns


# ---------------------------------------------------------------------------
# 5.1.13 — RBAC: namespace:create is required to create a namespace
# ---------------------------------------------------------------------------

class TestRbacNamespaceCreate:

    def test_create_fails_without_namespace_create_permission(self):
        """5.1.13 — A user without namespace:create is denied when creating a namespace."""
        name = _unique("rbac-ns-create")
        token = _limited_token(name)

        result = hkey.run_as(
            token,
            "namespace", "create",
            "--namespace", f"/rbac-denied-{uuid.uuid4().hex[:8]}",
        )
        assert result.returncode != 0, (
            "Expected namespace create to fail for user without namespace:create permission"
        )

    def test_create_succeeds_with_namespace_create_permission(self):
        """5.1.13 (positive) — A user with namespace:create can create a namespace."""
        name = _unique("rbac-ns-create-ok")
        helpers.create_user_account(name, activate=True)
        hkey.run(
            "rbac", "bind",
            "--name", name,
            "--rule", "allow namespace:create to all",
        )
        token = helpers.login_as(name, "SecurePassword1!")
        ns = f"/rbac-allowed-{uuid.uuid4().hex[:8]}"

        result = hkey.run_as(token, "namespace", "create", "--namespace", ns)
        assert result.returncode == 0, (
            f"Expected namespace create to succeed with namespace:create permission: {result.stderr}"
        )


# ---------------------------------------------------------------------------
# 5.3.10 — RBAC: namespace:update:meta is required to update a namespace
# ---------------------------------------------------------------------------

class TestRbacNamespaceUpdate:

    def test_update_fails_without_permission(self):
        """5.3.10 — A user without namespace:update:meta is denied when updating a namespace."""
        ns = f"/rbac-upd-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        name = _unique("rbac-ns-upd")
        token = _limited_token(name)

        result = hkey.run_as(
            token,
            "namespace", "update",
            "--namespace", ns,
            "--description", "should be denied",
        )
        assert result.returncode != 0, (
            "Expected namespace update to fail for user without namespace:update:meta"
        )

    def test_update_succeeds_with_permission(self):
        """5.3.10 (positive) — A user with namespace:update:meta can update a namespace."""
        ns = f"/rbac-upd-ok-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        name = _unique("rbac-ns-upd-ok")
        helpers.create_user_account(name, activate=True)
        hkey.run(
            "rbac", "bind",
            "--name", name,
            "--rule", f"allow namespace:update:meta to namespace {ns}",
        )
        token = helpers.login_as(name, "SecurePassword1!")

        result = hkey.run_as(
            token,
            "namespace", "update",
            "--namespace", ns,
            "--description", "permitted update",
        )
        assert result.returncode == 0, (
            f"Expected namespace update to succeed with namespace:update:meta: {result.stderr}"
        )


# ---------------------------------------------------------------------------
# 5.4.9 — Cannot delete the /$hierarkey system namespace
# ---------------------------------------------------------------------------

class TestSystemNamespaceProtection:

    def test_cannot_delete_hierarkey_system_namespace(self):
        """5.4.9 — The /$hierarkey system namespace cannot be deleted.

        The server rejects the request with 403 when the namespace exists, or
        404 when it has not been created in this environment. Either way the
        delete must not succeed.
        """
        r = requests.delete(
            f"{server_url()}/v1/namespaces/%2F%24hierarkey",
            headers=_auth_header(),
        )
        assert r.status_code in (403, 404), (
            f"Expected 403 (protected) or 404 (not created), got {r.status_code}: {r.text}"
        )
        if r.status_code == 403:
            assert "cannot be deleted" in r.text.lower() or "forbidden" in r.text.lower(), (
                f"Unexpected 403 body: {r.text}"
            )

    def test_cannot_delete_hierarkey_via_cli(self):
        """5.4.9 (CLI) — hkey namespace delete --namespace /$hierarkey is rejected."""
        # First disable is required before delete in the CLI flow, but the
        # system namespace cannot be disabled either.  Either step must fail.
        result = hkey.run(
            "namespace", "delete",
            "--namespace", "/$hierarkey",
            "--confirm",
        )
        assert result.returncode != 0, (
            "Expected CLI delete of /$hierarkey to fail"
        )


# ---------------------------------------------------------------------------
# 5.4.10 — RBAC: namespace:delete is required to disable/delete a namespace
# ---------------------------------------------------------------------------

class TestRbacNamespaceDelete:

    def test_disable_fails_without_permission(self):
        """5.4.10 — A user without namespace:delete cannot disable a namespace."""
        ns = f"/rbac-dis-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        name = _unique("rbac-ns-dis")
        token = _limited_token(name)

        result = hkey.run_as(token, "namespace", "disable", "--namespace", ns)
        assert result.returncode != 0, (
            "Expected namespace disable to fail for user without namespace:delete"
        )

    def test_delete_fails_without_permission(self):
        """5.4.10 — A user without namespace:delete cannot delete a namespace."""
        ns = f"/rbac-del-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        # Admin disables it first (delete requires disabled state)
        hkey.run("namespace", "disable", "--namespace", ns)

        name = _unique("rbac-ns-del")
        token = _limited_token(name)

        result = hkey.run_as(
            token,
            "namespace", "delete",
            "--namespace", ns,
            "--confirm",
        )
        assert result.returncode != 0, (
            "Expected namespace delete to fail for user without namespace:delete"
        )

    def test_disable_succeeds_with_permission(self):
        """5.4.10 (positive) — A user with namespace:delete can disable a namespace."""
        ns = f"/rbac-dis-ok-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        name = _unique("rbac-ns-dis-ok")
        helpers.create_user_account(name, activate=True)
        hkey.run(
            "rbac", "bind",
            "--name", name,
            "--rule", f"allow namespace:delete to namespace {ns}",
        )
        token = helpers.login_as(name, "SecurePassword1!")

        result = hkey.run_as(token, "namespace", "disable", "--namespace", ns)
        assert result.returncode == 0, (
            f"Expected namespace disable to succeed with namespace:delete permission: {result.stderr}"
        )
