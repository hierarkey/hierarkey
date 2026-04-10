# tests/test_audit_gaps.py
#
# Tests for section 9: Audit Logging.
#
# ALL tests in this file require the Commercial Edition (EE) with the Audit
# feature enabled.  Set HKEY_TEST_EE=1 in the environment to run them.
#
#   9.1  Event Coverage
#   9.2  Event Query (filtering, pagination)
#   9.3  Audit Chain Integrity (verify endpoint)

import json
import os
import uuid

import pytest
import requests

import hkey
import helpers

# ---------------------------------------------------------------------------
# Skip guard — all tests require the EE Audit feature
# ---------------------------------------------------------------------------

EE_ENABLED = os.environ.get("HKEY_TEST_EE", "0") == "1"
skip_if_not_ee = pytest.mark.skipif(
    not EE_ENABLED,
    reason="HKEY_TEST_EE=1 required — Audit logging is a Commercial Edition feature",
)


def server_url():
    return os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")


def _auth_header():
    hkey.login()
    return {"Authorization": f"Bearer {hkey.client.AUTH_TOKEN}"}


def _unique(prefix="x"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _query_events(filter_body=None):
    """POST /v1/audit/events with an optional filter dict; return response."""
    r = requests.post(
        f"{server_url()}/v1/audit/events",
        json=filter_body or {},
        headers=_auth_header(),
    )
    return r


def _query_events_ok(filter_body=None):
    """Query audit events, assert 200, return the AuditQueryResult dict."""
    r = _query_events(filter_body)
    assert r.status_code == 200, f"audit/events failed: {r.text}"
    return r.json().get("data", r.json())


def _verify_chain(from_seq=None, limit=None):
    """POST /v1/audit/verify; return response."""
    body = {}
    if from_seq is not None:
        body["from_seq"] = from_seq
    if limit is not None:
        body["limit"] = limit
    return requests.post(
        f"{server_url()}/v1/audit/verify",
        json=body,
        headers=_auth_header(),
    )


# ---------------------------------------------------------------------------
# Community-edition gate test (runs always)
# ---------------------------------------------------------------------------

def test_audit_endpoints_require_ee():
    """Audit endpoints return 403 on Community Edition (or 200 on EE)."""
    r = _query_events({})
    if EE_ENABLED:
        assert r.status_code == 200, f"Expected 200 on EE, got {r.status_code}: {r.text}"
    else:
        assert r.status_code == 403, (
            f"Expected 403 on Community Edition, got {r.status_code}: {r.text}"
        )


# ---------------------------------------------------------------------------
# 9.2.1 — Query all events returns list with correct schema
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditQuerySchema:

    def test_query_returns_expected_fields(self):
        """9.2.1 — POST /v1/audit/events returns events, total, page, limit."""
        data = _query_events_ok()
        assert "events" in data, f"Missing 'events' key: {data}"
        assert "total" in data, f"Missing 'total' key: {data}"
        assert "page" in data, f"Missing 'page' key: {data}"
        assert "limit" in data, f"Missing 'limit' key: {data}"
        assert isinstance(data["events"], list)
        assert data["total"] >= 0

    def test_each_event_has_required_fields(self):
        """9.2.1 — Each event row has the expected schema fields."""
        data = _query_events_ok({"limit": 5})
        required_fields = {"seq", "id", "event_type", "outcome", "created_at", "chain_hash"}
        for event in data["events"][:5]:
            missing = required_fields - set(event.keys())
            assert not missing, f"Event missing fields {missing}: {event}"


# ---------------------------------------------------------------------------
# 9.1 — Event Coverage
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditEventCoverage:

    def test_auth_login_success_is_logged(self):
        """9.1.1 — auth.login_success event is logged on successful login."""
        name = _unique("audit-login")
        helpers.create_user_account(name, activate=True)

        helpers.login_as(name, "SecurePassword1!")

        data = _query_events_ok({"event_type": "auth.login_success"})
        actor_names = [e.get("actor_name") for e in data["events"]]
        assert name in actor_names, (
            f"Expected auth.login_success event for '{name}', got names: {actor_names[:10]}"
        )

    def test_auth_login_failure_is_logged(self):
        """9.1.2 — auth.login failure event is logged on failed login."""
        name = _unique("audit-login-fail")
        helpers.create_user_account(name, activate=True)

        # Attempt login with wrong password
        hkey.run_unauth(
            "auth", "login",
            "--name", name,
            "--insecure-password", "WrongPassword999!",
        )

        data = _query_events_ok({"event_type": "auth.login_failure"})
        # Failed logins have no authenticated actor, so actor_name is None.
        # The attempted username is stored in resource_name instead.
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected auth.login_failure event for '{name}', got names: {resource_names[:10]}"
        )

    def test_pat_issued_is_logged(self):
        """9.1.5 — pat.issued event is logged on PAT creation."""
        result = hkey.run("pat", "create", "--description", f"audit-pat-{uuid.uuid4().hex[:6]}", "--json")
        assert result.returncode == 0
        pat_id = str(json.loads(result.stdout).get("id", ""))

        data = _query_events_ok({"event_type": "pat.issued"})
        assert data["total"] > 0, "Expected at least one pat.issued event"

        # Revoke to clean up
        if pat_id:
            hkey.run("pat", "revoke", "--id", pat_id)

    def test_pat_revoked_is_logged(self):
        """9.1.6 — pat.revoked event is logged on PAT revocation."""
        result = hkey.run("pat", "create", "--description", "audit-pat-revoke", "--json")
        assert result.returncode == 0
        pat_id = str(json.loads(result.stdout).get("id", ""))

        result = hkey.run("pat", "revoke", "--id", pat_id)
        assert result.returncode == 0, f"pat revoke failed: {result.stderr}"

        data = _query_events_ok({"event_type": "pat.revoked"})
        assert data["total"] > 0, "Expected at least one pat.revoked event"

    def test_account_create_is_logged(self):
        """9.1.7 — account.create event is logged on account creation."""
        name = _unique("audit-acct-create")
        helpers.create_user_account(name, activate=True)

        data = _query_events_ok({"event_type": "account.create"})
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected account.create event for '{name}', got: {resource_names[:10]}"
        )

    def test_secret_create_is_logged(self):
        """9.1.14 — secret.create event is logged when a secret is created."""
        ns = f"/audit-ns-{uuid.uuid4().hex[:8]}"
        hkey.run("namespace", "create", "--namespace", ns)
        ref = f"{ns}:audit-sec"
        hkey.run("secret", "create", "--ref", ref, "--value", "secret-value")

        data = _query_events_ok({"event_type": "secret.create"})
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert any(ref in (n or "") for n in resource_names), (
            f"Expected secret.create event for '{ref}', got: {resource_names[:10]}"
        )

    def test_secret_read_is_logged(self):
        """9.1.15 — secret.read event is logged on reveal."""
        ns = f"/audit-rev-{uuid.uuid4().hex[:8]}"
        hkey.run("namespace", "create", "--namespace", ns)
        ref = f"{ns}:audit-reveal"
        hkey.run("secret", "create", "--ref", ref, "--value", "read-me")

        hkey.run("secret", "reveal", "--ref", f"{ref}@active")

        data = _query_events_ok({"event_type": "secret.read"})
        assert data["total"] > 0, "Expected at least one secret.read event"

    def test_namespace_create_is_logged(self):
        """9.1.20 — namespace.create event is logged when a namespace is created."""
        ns = f"/audit-ns-log-{uuid.uuid4().hex[:8]}"
        hkey.run("namespace", "create", "--namespace", ns)

        data = _query_events_ok({"event_type": "namespace.create"})
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert any(ns in (n or "") for n in resource_names), (
            f"Expected namespace.create event for '{ns}', got: {resource_names[:10]}"
        )

    def test_rbac_bind_is_logged(self):
        """9.1.27 — rbac.bind event is logged when a binding is created."""
        name = _unique("audit-bind")
        helpers.create_user_account(name, activate=True)
        ns = f"/audit-bind-ns-{uuid.uuid4().hex[:8]}"
        hkey.run("namespace", "create", "--namespace", ns)

        result = hkey.run(
            "rbac", "bind",
            "--name", name,
            "--rule", f"allow secret:read to namespace {ns}",
        )
        assert result.returncode == 0, f"rbac bind failed: {result.stderr}"

        data = _query_events_ok({"event_type": "rbac.bind"})
        assert data["total"] > 0, "Expected at least one rbac.bind event"

    def test_rbac_denied_produces_denied_outcome(self):
        """9.1.29 — An RBAC-denied operation produces outcome='denied' in the audit log."""
        name = _unique("audit-denied")
        helpers.create_user_account(name, activate=True)
        token = helpers.login_as(name, "SecurePassword1!")

        # Attempt to list namespaces — a user with no permissions is denied
        ns = f"/audit-denied-{uuid.uuid4().hex[:8]}"
        hkey.run("namespace", "create", "--namespace", ns)

        # Try to create a secret (should be denied)
        hkey.run_as(
            token,
            "secret", "create",
            "--ref", f"{ns}:denied-secret",
            "--value", "blocked",
        )

        data = _query_events_ok({"outcome": "denied"})
        assert data["total"] > 0, "Expected at least one audit event with outcome='denied'"
        outcomes = {e["outcome"] for e in data["events"]}
        assert "denied" in outcomes, f"Expected 'denied' outcome; got: {outcomes}"


# ---------------------------------------------------------------------------
# 9.2 — Event Query with Filters
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditQueryFilters:

    def test_filter_by_event_type(self):
        """9.2.2 — filter event_type='secret.create' returns only secret.create events."""
        data = _query_events_ok({"event_type": "secret.create"})
        for event in data["events"]:
            assert event["event_type"] == "secret.create", (
                f"Unexpected event type: {event['event_type']}"
            )

    def test_filter_by_wildcard_event_type(self):
        """9.2.3 — filter event_type='secret.*' returns all secret.* events."""
        # Create a secret so there is at least one event
        ns = f"/audit-wc-{uuid.uuid4().hex[:8]}"
        hkey.run("namespace", "create", "--namespace", ns)
        hkey.run("secret", "create", "--ref", f"{ns}:wc-secret", "--value", "wc")

        data = _query_events_ok({"event_type": "secret.*"})
        assert data["total"] > 0, "Expected at least one secret.* event"
        for event in data["events"]:
            assert event["event_type"].startswith("secret."), (
                f"Wildcard filter returned non-secret event: {event['event_type']}"
            )

    def test_filter_by_outcome_success(self):
        """9.2.5 — filter outcome='success' returns only success events."""
        data = _query_events_ok({"outcome": "success", "limit": 20})
        for event in data["events"]:
            assert event["outcome"] == "success", (
                f"Unexpected outcome: {event['outcome']}"
            )

    def test_filter_by_outcome_denied(self):
        """9.2.5 — filter outcome='denied' returns only denied events."""
        data = _query_events_ok({"outcome": "denied", "limit": 20})
        for event in data["events"]:
            assert event["outcome"] == "denied", (
                f"Unexpected outcome: {event['outcome']}"
            )

    def test_filter_by_actor_id(self):
        """9.2.4 — filter actor_id returns only events from that actor."""
        # Get our own actor ID via whoami
        r = requests.get(
            f"{server_url()}/v1/auth/whoami",
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"whoami failed: {r.text}"
        whoami = r.json().get("data", r.json())
        actor_id = (
            whoami.get("account_id")
            or whoami.get("id")
            or (whoami.get("account") or {}).get("id")
        )
        assert actor_id, f"Could not extract actor_id from whoami: {whoami}"

        data = _query_events_ok({"actor_id": actor_id, "limit": 10})
        for event in data["events"]:
            assert str(event.get("actor_id")) == str(actor_id), (
                f"Unexpected actor_id: {event.get('actor_id')} != {actor_id}"
            )

    def test_actor_name_populated_in_events(self):
        """9.2.7 — actor_name field is populated in audit events."""
        data = _query_events_ok({"event_type": "auth.login_success", "limit": 5})
        for event in data["events"]:
            assert event.get("actor_name") is not None, (
                f"actor_name missing in event: {event}"
            )

    def test_pagination(self):
        """9.2.8 — Pagination: page 0 and page 1 return different events."""
        page0 = _query_events_ok({"page": 0, "limit": 5})
        page1 = _query_events_ok({"page": 1, "limit": 5})

        if page0["total"] <= 5:
            pytest.skip("Not enough events to test pagination")

        ids_page0 = {e["id"] for e in page0["events"]}
        ids_page1 = {e["id"] for e in page1["events"]}
        assert ids_page0.isdisjoint(ids_page1), (
            "Pages 0 and 1 should not share events"
        )
        assert page0["page"] == 0
        assert page1["page"] == 1

    def test_date_range_filter(self):
        """9.2.6 — Date range filter from/to narrows down results."""
        from datetime import datetime, timezone, timedelta

        # Use a wide range that should include all events
        far_past = "2020-01-01T00:00:00Z"
        far_future = "2099-01-01T00:00:00Z"

        data_all = _query_events_ok({})
        data_range = _query_events_ok({"from": far_past, "to": far_future})

        # Both should return the same total
        assert data_all["total"] == data_range["total"], (
            f"Wide date range should match all events: {data_all['total']} vs {data_range['total']}"
        )

        # Narrow range in the future should return 0
        future_from = "2098-01-01T00:00:00Z"
        data_empty = _query_events_ok({"from": future_from})
        assert data_empty["total"] == 0, (
            f"Expected 0 events in far-future range, got {data_empty['total']}"
        )


# ---------------------------------------------------------------------------
# 9.3 — Audit Chain Integrity
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditChainIntegrity:

    def test_verify_passes_on_unmodified_log(self):
        """9.3.1 — POST /v1/audit/verify returns valid=true on an unmodified log."""
        r = _verify_chain()
        assert r.status_code == 200, f"audit/verify failed: {r.text}"
        data = r.json().get("data", r.json())
        assert data["valid"] is True, (
            f"Expected audit chain to be valid; got: {data}"
        )
        assert data["total_checked"] >= 0
        assert data["first_broken_seq"] is None

    def test_verify_with_from_seq(self):
        """9.3.1 — Verification with from_seq=1 covers all events from the start."""
        r = _verify_chain(from_seq=1)
        assert r.status_code == 200, f"audit/verify with from_seq=1 failed: {r.text}"
        data = r.json().get("data", r.json())
        assert data["valid"] is True, f"Expected chain to be valid: {data}"

    def test_verify_with_limit(self):
        """9.3.1 — Verification with a small limit only checks that many events."""
        # First ensure there is at least one event
        data_q = _query_events_ok({"limit": 1})
        if data_q["total"] == 0:
            pytest.skip("No audit events to verify")

        r = _verify_chain(from_seq=1, limit=1)
        assert r.status_code == 200, f"audit/verify with limit=1 failed: {r.text}"
        result = r.json().get("data", r.json())
        assert result["total_checked"] <= 1, (
            f"Expected at most 1 event checked with limit=1: {result}"
        )
        assert result["valid"] is True

    def test_verify_response_schema(self):
        """9.3.1 — verify response has valid, total_checked, first_broken_seq fields."""
        r = _verify_chain()
        assert r.status_code == 200
        data = r.json().get("data", r.json())
        assert "valid" in data, f"Missing 'valid' field: {data}"
        assert "total_checked" in data, f"Missing 'total_checked' field: {data}"
        assert "first_broken_seq" in data, f"Missing 'first_broken_seq' field: {data}"
        assert isinstance(data["valid"], bool)
        assert isinstance(data["total_checked"], int)


# ---------------------------------------------------------------------------
# 9.1  Additional event coverage — account lifecycle
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditAccountEvents:

    def test_account_update_is_logged(self):
        """9.1.10 — account.update event is logged when an account is updated via HTTP PATCH."""
        name = _unique("audit-acct-upd")
        helpers.create_user_account(name, activate=True)

        r = requests.patch(
            f"{server_url()}/v1/accounts/{name}",
            json={"full_name": "Audit Test User"},
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"account update failed: {r.text}"

        data = _query_events_ok({"event_type": "account.update"})
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected account.update event for '{name}', got: {resource_names[:10]}"
        )

    def test_account_delete_is_logged(self):
        """9.1.9 — account.delete event is logged when an account is deleted."""
        name = _unique("audit-acct-del")
        helpers.create_user_account(name, activate=True)

        r = requests.delete(
            f"{server_url()}/v1/accounts/{name}",
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"account delete failed: {r.text}"

        data = _query_events_ok({"event_type": "account.delete"})
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected account.delete event for '{name}', got: {resource_names[:10]}"
        )

    def test_account_status_change_lock_is_logged(self):
        """9.1.11 — account.status_change event is logged when an account is locked."""
        name = _unique("audit-acct-lock")
        helpers.create_user_account(name, activate=True)

        result = hkey.run("account", "lock", "--name", name)
        assert result.returncode == 0, f"account lock failed: {result.stderr}"

        data = _query_events_ok({"event_type": "account.status_change"})
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected account.status_change event for lock of '{name}': {resource_names[:10]}"
        )

    def test_account_status_change_unlock_is_logged(self):
        """9.1.11 — account.status_change event is logged when an account is unlocked."""
        name = _unique("audit-acct-unlk")
        helpers.create_user_account(name, activate=True)
        hkey.run("account", "lock", "--name", name)
        hkey.run("account", "unlock", "--name", name)

        data = _query_events_ok({"event_type": "account.status_change"})
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected account.status_change event for unlock of '{name}': {resource_names[:10]}"
        )

    def test_account_promote_is_logged(self):
        """9.1.12 — account.promote event is logged when an account is promoted to admin."""
        name = _unique("audit-promote")
        helpers.create_user_account(name, activate=True)

        result = hkey.run("account", "promote", "--name", name)
        assert result.returncode == 0, f"account promote failed: {result.stderr}"

        data = _query_events_ok({"event_type": "account.promote"})
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected account.promote event for '{name}': {resource_names[:10]}"
        )
        # Clean up — demote back
        hkey.run("account", "demote", "--name", name)

    def test_account_demote_is_logged(self):
        """9.1.12 — account.demote event is logged when an account is demoted."""
        name = _unique("audit-demote")
        helpers.create_user_account(name, activate=True)
        hkey.run("account", "promote", "--name", name)

        result = hkey.run("account", "demote", "--name", name)
        assert result.returncode == 0, f"account demote failed: {result.stderr}"

        data = _query_events_ok({"event_type": "account.demote"})
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected account.demote event for '{name}': {resource_names[:10]}"
        )

    def test_account_password_change_is_logged(self):
        """9.1.13 — account.password_change event is logged on admin password reset."""
        name = _unique("audit-pw-chg")
        helpers.create_user_account(name, activate=True)

        result = hkey.run(
            "account", "change-pw",
            "--name", name,
            "--insecure-new-password", "NewSecurePassword2!",
        )
        assert result.returncode == 0, f"account change-pw failed: {result.stderr}"

        data = _query_events_ok({"event_type": "account.password_change"})
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected account.password_change event for '{name}': {resource_names[:10]}"
        )


# ---------------------------------------------------------------------------
# 9.1  Additional event coverage — secret lifecycle
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditSecretEvents:

    def _setup_ns_and_secret(self, ns_suffix, key):
        ns = f"/audit-sec-{ns_suffix}-{uuid.uuid4().hex[:8]}"
        hkey.run("namespace", "create", "--namespace", ns)
        ref = f"{ns}:{key}"
        hkey.run("secret", "create", "--ref", ref, "--value", "initial-value")
        return ns, ref

    def test_secret_update_is_logged(self):
        """9.1.17 — secret.update event is logged when secret metadata is updated."""
        ns, ref = self._setup_ns_and_secret("upd", "audit-upd-sec")

        result = hkey.run(
            "secret", "update",
            "--ref", ref,
            "--description", "updated-description",
        )
        assert result.returncode == 0, f"secret update failed: {result.stderr}"

        data = _query_events_ok({"event_type": "secret.update"})
        assert data["total"] > 0, "Expected at least one secret.update event"

    def test_secret_delete_is_logged(self):
        """9.1.18 — secret.delete event is logged when a secret is deleted."""
        ns, ref = self._setup_ns_and_secret("del", "audit-del-sec")

        # Disable namespace first, then disable secret, then delete
        result = hkey.run("secret", "disable", "--ref", ref)
        assert result.returncode == 0, f"secret disable failed: {result.stderr}"
        result = hkey.run("secret", "delete", "--ref", ref, "--confirm")
        assert result.returncode == 0, f"secret delete failed: {result.stderr}"

        data = _query_events_ok({"event_type": "secret.delete"})
        assert data["total"] > 0, "Expected at least one secret.delete event"

    def test_secret_revise_is_logged(self):
        """9.1.19 — secret.revise event is logged when a new revision is created."""
        ns, ref = self._setup_ns_and_secret("rev", "audit-rev-sec")

        result = hkey.run("secret", "revise", "--ref", ref, "--value", "revised-value")
        assert result.returncode == 0, f"secret revise failed: {result.stderr}"

        data = _query_events_ok({"event_type": "secret.revise"})
        assert data["total"] > 0, "Expected at least one secret.revise event"

    def test_secret_read_denied_is_logged(self):
        """9.1.16 — A denied secret.read produces an audit event with outcome='denied'."""
        ns, ref = self._setup_ns_and_secret("denied", "audit-denied-sec")

        name = _unique("audit-denied-user")
        helpers.create_user_account(name, activate=True)
        token = helpers.login_as(name, "SecurePassword1!")

        # Attempt reveal without permission
        hkey.run_as(token, "secret", "reveal", "--ref", f"{ref}@active")

        data = _query_events_ok({"event_type": "secret.read", "outcome": "denied"})
        assert data["total"] > 0, "Expected secret.read denied event after unauthorized reveal"


# ---------------------------------------------------------------------------
# 9.1  Additional event coverage — namespace lifecycle
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditNamespaceEvents:

    def test_namespace_delete_is_logged(self):
        """9.1.21 — namespace.delete event is logged when a namespace is deleted."""
        ns = f"/audit-ns-del-{uuid.uuid4().hex[:8]}"
        hkey.run("namespace", "create", "--namespace", ns)
        hkey.run("namespace", "disable", "--namespace", ns)

        result = hkey.run("namespace", "delete", "--namespace", ns, "--confirm")
        assert result.returncode == 0, f"namespace delete failed: {result.stderr}"

        data = _query_events_ok({"event_type": "namespace.delete"})
        assert data["total"] > 0, "Expected at least one namespace.delete event"
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert any(ns in (n or "") for n in resource_names), (
            f"Expected namespace.delete event for '{ns}': {resource_names[:10]}"
        )

    def test_namespace_kek_rotate_is_logged(self):
        """9.1.22 — namespace.kek_rotate event is logged when the KEK is rotated."""
        ns = f"/audit-kek-rot-{uuid.uuid4().hex[:8]}"
        hkey.run("namespace", "create", "--namespace", ns)

        result = hkey.run("rekey", "kek", "--namespace", ns)
        assert result.returncode == 0, f"rekey kek failed: {result.stderr}"

        data = _query_events_ok({"event_type": "namespace.kek_rotate"})
        assert data["total"] > 0, "Expected at least one namespace.kek_rotate event"
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert any(ns in (n or "") for n in resource_names), (
            f"Expected namespace.kek_rotate event for '{ns}': {resource_names[:10]}"
        )


# ---------------------------------------------------------------------------
# 9.1  Additional event coverage — master key lifecycle
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditMasterkeyEvents:

    def test_masterkey_create_is_logged(self):
        """9.1.23 — masterkey.create event is logged when a master key is created."""
        name = _unique("audit-mk-create")
        result = hkey.run(
            "masterkey", "create",
            "--name", name,
            "--provider", "passphrase",
            "--insecure-passphrase", "AuditTestPassphrase1!",
        )
        assert result.returncode == 0, f"masterkey create failed: {result.stderr}"

        data = _query_events_ok({"event_type": "masterkey.create"})
        assert data["total"] > 0, "Expected at least one masterkey.create event"
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected masterkey.create event for '{name}': {resource_names[:10]}"
        )

    def test_masterkey_lock_is_logged(self):
        """9.1.24 — masterkey.lock event is logged when a master key is locked."""
        name = _unique("audit-mk-lock")
        hkey.run(
            "masterkey", "create",
            "--name", name,
            "--provider", "passphrase",
            "--insecure-passphrase", "AuditLockPassphrase1!",
        )
        result = hkey.run("masterkey", "lock", "--name", name)
        assert result.returncode == 0, f"masterkey lock failed: {result.stderr}"

        data = _query_events_ok({"event_type": "masterkey.lock"})
        assert data["total"] > 0, "Expected at least one masterkey.lock event"
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected masterkey.lock event for '{name}': {resource_names[:10]}"
        )

    def test_masterkey_unlock_success_is_logged(self):
        """9.1.25 — masterkey.unlock event is logged on successful unlock."""
        name = _unique("audit-mk-unlock")
        passphrase = "AuditUnlockPassphrase1!"
        hkey.run(
            "masterkey", "create",
            "--name", name,
            "--provider", "passphrase",
            "--insecure-passphrase", passphrase,
        )
        hkey.run("masterkey", "lock", "--name", name)

        result = hkey.run(
            "masterkey", "unlock",
            "--name", name,
            "--insecure-passphrase", passphrase,
        )
        assert result.returncode == 0, f"masterkey unlock failed: {result.stderr}"

        data = _query_events_ok({"event_type": "masterkey.unlock"})
        assert data["total"] > 0, "Expected at least one masterkey.unlock event"
        events_for_key = [
            e for e in data["events"]
            if e.get("resource_name") == name and e.get("outcome") == "success"
        ]
        assert events_for_key, (
            f"Expected masterkey.unlock success event for '{name}': {data['events'][:5]}"
        )

    def test_masterkey_unlock_failure_is_logged(self):
        """9.1.25 — masterkey.unlock failure is logged when wrong passphrase is used."""
        name = _unique("audit-mk-uf")
        passphrase = "CorrectPassphrase1!"
        hkey.run(
            "masterkey", "create",
            "--name", name,
            "--provider", "passphrase",
            "--insecure-passphrase", passphrase,
        )
        hkey.run("masterkey", "lock", "--name", name)

        # Unlock with wrong passphrase — should fail
        hkey.run(
            "masterkey", "unlock",
            "--name", name,
            "--insecure-passphrase", "WrongPassphrase1!",
        )

        data = _query_events_ok({"event_type": "masterkey.unlock"})
        failure_events = [
            e for e in data["events"]
            if e.get("resource_name") == name and e.get("outcome") in ("failure", "denied")
        ]
        assert failure_events, (
            f"Expected masterkey.unlock failure event for '{name}': {data['events'][:5]}"
        )

        # Re-unlock with correct passphrase to leave key in clean state
        hkey.run(
            "masterkey", "unlock",
            "--name", name,
            "--insecure-passphrase", passphrase,
        )


# ---------------------------------------------------------------------------
# 9.1  Additional event coverage — RBAC
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditRbacEvents:

    def test_rbac_role_create_is_logged(self):
        """9.1.28 — rbac.role_create event is logged when a role is created."""
        name = _unique("audit-role")
        result = hkey.run("rbac", "role", "create", "--name", name)
        assert result.returncode == 0, f"rbac role create failed: {result.stderr}"

        data = _query_events_ok({"event_type": "rbac.role_create"})
        assert data["total"] > 0, "Expected at least one rbac.role_create event"
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected rbac.role_create event for '{name}': {resource_names[:10]}"
        )

        hkey.run("rbac", "role", "delete", "--name", name, "--force")

    def test_rbac_role_update_is_logged(self):
        """9.1.28 — rbac.role_update event is logged when a role is updated."""
        name = _unique("audit-role-upd")
        hkey.run("rbac", "role", "create", "--name", name)

        r = requests.patch(
            f"{server_url()}/v1/rbac/role/{name}",
            json={"description": "updated-via-audit-test"},
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"role update failed: {r.text}"

        data = _query_events_ok({"event_type": "rbac.role_update"})
        assert data["total"] > 0, "Expected at least one rbac.role_update event"

        hkey.run("rbac", "role", "delete", "--name", name, "--force")

    def test_rbac_unbind_is_logged(self):
        """9.1.27 (unbind) — rbac.unbind event is logged when a binding is removed."""
        name = _unique("audit-unbind")
        helpers.create_user_account(name, activate=True)
        ns = f"/audit-unbind-ns-{uuid.uuid4().hex[:8]}"
        hkey.run("namespace", "create", "--namespace", ns)

        hkey.run(
            "rbac", "bind",
            "--name", name,
            "--rule", f"allow secret:read to namespace {ns}",
        )

        # Get the binding to find the rule id
        r = requests.post(
            f"{server_url()}/v1/rbac/bindings",
            json={"account": name},
            headers=_auth_header(),
        )
        assert r.status_code == 200
        bindings_data = r.json().get("data", r.json())
        rules = bindings_data.get("rules", [])
        if rules:
            rule_id = str(rules[0].get("id", ""))
            hkey.run("rbac", "unbind", "--name", name, "--rule-id", rule_id)

        data = _query_events_ok({"event_type": "rbac.unbind"})
        assert data["total"] > 0, "Expected at least one rbac.unbind event"


# ---------------------------------------------------------------------------
# 6.3.18 / 6.3.19  — Audit events during secret reveal
# (these belong to section 6 but require EE and are grouped here)
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditSecretReveal:

    def test_successful_reveal_is_logged_as_secret_read(self):
        """6.3.18 — A successful secret reveal produces a secret.read audit event."""
        ns = f"/audit-reveal-ok-{uuid.uuid4().hex[:8]}"
        hkey.run("namespace", "create", "--namespace", ns)
        ref = f"{ns}:reveal-audit"
        hkey.run("secret", "create", "--ref", ref, "--value", "reveal-me")

        result = hkey.run("secret", "reveal", "--ref", f"{ref}@active")
        assert result.returncode == 0, f"reveal failed: {result.stderr}"

        data = _query_events_ok({"event_type": "secret.read", "outcome": "success"})
        assert data["total"] > 0, "Expected secret.read success event after reveal"

    def test_denied_reveal_is_logged_with_denied_outcome(self):
        """6.3.19 — A permission-denied reveal produces a secret.read event with outcome='denied'."""
        ns = f"/audit-reveal-denied-{uuid.uuid4().hex[:8]}"
        hkey.run("namespace", "create", "--namespace", ns)
        hkey.run("secret", "create", "--ref", f"{ns}:no-access", "--value", "hidden")

        name = _unique("audit-no-access")
        helpers.create_user_account(name, activate=True)
        token = helpers.login_as(name, "SecurePassword1!")

        hkey.run_as(token, "secret", "reveal", "--ref", f"{ns}:no-access@active")

        data = _query_events_ok({"event_type": "secret.read", "outcome": "denied"})
        assert data["total"] > 0, "Expected secret.read denied event after permission-denied reveal"


# ---------------------------------------------------------------------------
# 7.3.4 / 7.4.7 / 7.4.8 — Masterkey audit events from section 7
# (require EE and are grouped here)
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditMasterkeyActivation:

    def test_masterkey_activate_is_logged(self):
        """7.3.4 — masterkey.activate event is logged when a master key is activated.

        This test is guarded by HKEY_TEST_MASTERKEY_ROTATION=1 because activating
        a different key changes the active master key permanently.
        """
        import os
        if os.environ.get("HKEY_TEST_MASTERKEY_ROTATION") != "1":
            pytest.skip("HKEY_TEST_MASTERKEY_ROTATION=1 required to activate a different master key")

        name = _unique("audit-mk-act")
        hkey.run(
            "masterkey", "create",
            "--name", name,
            "--provider", "insecure",
        )
        result = hkey.run("masterkey", "activate", "--name", name)
        assert result.returncode == 0, f"masterkey activate failed: {result.stderr}"

        data = _query_events_ok({"event_type": "masterkey.activate"})
        assert data["total"] > 0, "Expected at least one masterkey.activate event"
        resource_names = [e.get("resource_name") for e in data["events"]]
        assert name in resource_names, (
            f"Expected masterkey.activate event for '{name}': {resource_names[:10]}"
        )

    def test_masterkey_activate_failure_is_logged(self):
        """7.3.5 — masterkey.activate failure is logged when activation fails.

        Triggering a failure by attempting to activate a non-existent key name is
        sufficient: the handler calls the service, receives an error, and logs an
        AuditOutcome::Failure event before returning 404.
        """
        nonexistent = f"no-such-key-{uuid.uuid4().hex[:8]}"
        hkey.run("masterkey", "activate", "--name", nonexistent)  # expected to fail

        data = _query_events_ok({"event_type": "masterkey.activate", "outcome": "failure"})
        assert data["total"] > 0, (
            "Expected at least one masterkey.activate failure event; "
            "check that the server logs audit events for failed activations"
        )


# ---------------------------------------------------------------------------
# 9.1  SA token audit events (passphrase and keysig)
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditSaTokenEvents:

    def test_sa_token_passphrase_success_is_logged(self):
        """9.1.3 — auth.service_account_token success event is logged on SA token issuance."""
        name = _unique("audit-sa-pass")
        passphrase = "SaPassphrase16chars!"
        hkey.run(
            "account", "create",
            "--type", "service",
            "--name", name,
            "--auth", "passphrase",
            "--passphrase", passphrase,
            "--activate",
        )

        hkey.run(
            "auth", "sa-token",
            "--name", name,
            "--passphrase", passphrase,
        )

        data = _query_events_ok({"event_type": "auth.service_account_token", "outcome": "success"})
        actor_names = [e.get("actor_name") for e in data["events"]]
        assert name in actor_names, (
            f"Expected auth.service_account_token success event for '{name}', got: {actor_names[:10]}"
        )

    def test_sa_token_passphrase_failure_is_logged(self):
        """9.1.4 — auth.service_account_token failure is logged on SA token auth failure."""
        name = _unique("audit-sa-fail")
        passphrase = "SaPassphrase16chars!"
        hkey.run(
            "account", "create",
            "--type", "service",
            "--name", name,
            "--auth", "passphrase",
            "--passphrase", passphrase,
            "--activate",
        )

        # Attempt with wrong passphrase — should fail
        hkey.run(
            "auth", "sa-token",
            "--name", name,
            "--passphrase", "WrongPassphrase999!",
        )

        data = _query_events_ok({"event_type": "auth.service_account_token", "outcome": "failure"})
        assert data["total"] > 0, (
            "Expected at least one auth.service_account_token failure event; "
            "check that the server logs audit events for failed SA token requests"
        )

    def test_sa_token_bad_keysig_failure_is_logged(self):
        """9.1.4 — auth.service_account_token failure is logged when keysig verification fails."""
        import base64
        import json as _json
        import os
        import time

        name = _unique("audit-sa-badsig")

        # Create SA with ed25519
        result = hkey.run(
            "account", "create",
            "--type", "service",
            "--name", name,
            "--auth", "ed25519",
            "--generate-keypair",
            "--print-private-key-once",
            "--activate",
            "--json",
        )
        assert result.returncode == 0, f"Failed to create ed25519 SA: {result.stderr}"

        # Send a token request with a completely invalid signature
        audience = os.environ.get("HKEY_TEST_AUTH_AUDIENCE", "hierarkey-server")
        nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        ts = int(time.time())
        payload = {
            "auth": {
                "method": "key_sig",
                "account_name": name,
                "key_id": "default",
                "alg": "Ed25519",
                "nonce": nonce,
                "ts": ts,
                "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            }
        }
        requests.post(f"{server_url()}/v1/auth/service-account/token", json=payload)

        data = _query_events_ok({"event_type": "auth.service_account_token", "outcome": "failure"})
        assert data["total"] > 0, (
            "Expected at least one auth.service_account_token failure event after bad keysig"
        )


# ---------------------------------------------------------------------------
# 9.1.8  account.create failure audit event
# ---------------------------------------------------------------------------

@skip_if_not_ee
class TestAuditAccountCreateFailure:

    def test_account_create_failure_is_logged(self):
        """9.1.8 — account.create failure is logged when account creation fails (duplicate name)."""
        name = _unique("audit-acct-dup")
        # Create once — should succeed
        hkey.run(
            "account", "create",
            "--type", "user",
            "--name", name,
            "--password", "SecurePassword1!",
            "--activate",
        )

        # Try to create again with the same name — should fail with 409
        r = requests.post(
            f"{server_url()}/v1/accounts",
            json={"account_type": "user", "name": name, "password": "SecurePassword1!"},
            headers=_auth_header(),
        )
        assert r.status_code in (409, 422), (
            f"Expected 409/422 for duplicate account name, got {r.status_code}: {r.text}"
        )

        data = _query_events_ok({"event_type": "account.create", "outcome": "failure"})
        assert data["total"] > 0, (
            "Expected at least one account.create failure event; "
            "check that the server logs audit events for failed account creation attempts"
        )
