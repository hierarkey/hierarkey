# tests/test_secret_gaps.py
#
# Tests that fill the gaps in section 6 of the test plan.
# Existing coverage lives in test_secret_create.py and test_secret_reveal.py.
#
#   6.1.19  RBAC: secret:create is required to create a secret
#   6.2.1   Describe secret by ref
#   6.2.2   Describe secret by short ID
#   6.2.3   Describe shows metadata (labels, description, type)
#   6.2.4   Describe shows revision list
#   6.2.6   Search secrets in namespace
#   6.2.7   Search by label
#   6.2.8   RBAC: describe requires secret:describe
#   6.3.4   Reveal @latest revision
#   6.3.20  RBAC: reveal requires secret:reveal
#   6.4.x   Update Secret Metadata
#   6.5.x   Revise (Create New Revision)
#   6.6.x   Activate Revision
#   6.7.x   Annotate Revision
#   6.8.x   Delete Secret
#   6.9.x   Secret Types
#   6.10.x  Disable / Enable Secret (HTTP + CLI tests in TestDisableEnableSecretCLI)
#   6.11.x  Restore Deleted Secret (HTTP + CLI tests in TestRestoreSecretCLI)

import base64
import json
import os
import tempfile
import uuid

import pytest
import requests

import hkey
import helpers


def _server_url():
    return os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")


def _admin_token():
    hkey.login()
    return hkey.client.AUTH_TOKEN


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _uid(prefix="s"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _ns(suffix=None):
    suffix = suffix or uuid.uuid4().hex[:8]
    return f"/sgap-{suffix}"


def _setup(ns, key="secret/key", value="initial-value", **kwargs):
    """Create namespace + secret and return the (ns, ref, value) triple."""
    helpers.create_namespace(ns)
    ref = f"{ns}:{key}"
    helpers.create_secret(ref, value, **kwargs)
    return ref


def _describe_json(ref_or_id, use_id=False):
    if use_id:
        result = hkey.run("secret", "describe", "--id", ref_or_id, "--json")
    else:
        result = hkey.run("secret", "describe", "--ref", ref_or_id, "--json")
    assert result.returncode == 0, f"describe failed: {result.stderr}"
    return json.loads(result.stdout)


def _limited_token(name):
    """Create a user with no RBAC permissions and return their access token."""
    helpers.create_user_account(name, activate=True)
    return helpers.login_as(name, "SecurePassword1!")


def _generate_test_cert_pem():
    """Return a minimal self-signed DER-encoded PEM certificate string."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import NameOID
    import datetime

    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, None)
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ---------------------------------------------------------------------------
# 6.1.19 — RBAC: secret:create is required
# ---------------------------------------------------------------------------

class TestRbacSecretCreate:

    def test_create_fails_without_permission(self):
        """6.1.19 — A user without secret:create cannot create a secret."""
        ns = _ns()
        helpers.create_namespace(ns)

        name = _uid("rbac-sc")
        token = _limited_token(name)

        result = hkey.run_as(token, "secret", "create", "--ref", f"{ns}:key", "--value", "v")
        assert result.returncode != 0, "Expected secret create to fail without secret:create"

    def test_create_succeeds_with_permission(self):
        """6.1.19 (positive) — A user with secret:create can create a secret."""
        ns = _ns()
        helpers.create_namespace(ns)

        name = _uid("rbac-sc-ok")
        helpers.create_user_account(name, activate=True)
        hkey.run("rbac", "bind", "--name", name, "--rule", f"allow secret:create to namespace {ns}")
        token = helpers.login_as(name, "SecurePassword1!")

        result = hkey.run_as(token, "secret", "create", "--ref", f"{ns}:key", "--value", "v")
        assert result.returncode == 0, f"Expected success with secret:create permission: {result.stderr}"


# ---------------------------------------------------------------------------
# 6.2 — Describe & Search Secrets
# ---------------------------------------------------------------------------

class TestDescribeAndSearch:

    def test_describe_by_ref(self):
        """6.2.1 — `secret describe --ref ns:key` returns secret data."""
        ns = _ns()
        ref = _setup(ns)

        data = _describe_json(ref)
        assert data["ref_ns"] == ns
        assert data["ref_key"] == "secret/key"

    def test_describe_by_short_id(self):
        """6.2.2 — `secret describe --id sec_...` returns the same data as --ref."""
        ns = _ns()
        ref = _setup(ns)

        by_ref = _describe_json(ref)
        short_id = by_ref["short_id"]
        assert short_id.startswith("sec_"), f"Unexpected short_id format: {short_id}"

        by_id = _describe_json(short_id, use_id=True)
        assert by_id["ref_ns"] == ns
        assert by_id["ref_key"] == "secret/key"
        assert by_id["short_id"] == short_id

    def test_describe_shows_metadata(self):
        """6.2.3 — describe includes description, labels, and secret type."""
        ns = _ns()
        ref = f"{ns}:secret/key"
        helpers.create_namespace(ns)
        helpers.create_secret(
            ref,
            "value",
            description="my desc",
            labels=["env=prod", "app=test"],
        )

        data = _describe_json(ref)
        assert data["description"] == "my desc"
        assert data["labels"].get("env") == "prod"
        assert data["labels"].get("app") == "test"
        assert "secret_type" in data

    def test_describe_shows_revision_list(self):
        """6.2.4 — describe includes a revision list."""
        ns = _ns()
        ref = _setup(ns)

        # Create a second revision
        hkey.run("secret", "revise", "--ref", ref, "--value", "revised-value", "--activate")

        data = _describe_json(ref)
        assert len(data["revisions"]) >= 2, "Expected at least 2 revisions in describe output"
        revisions = sorted(data["revisions"], key=lambda r: r["revision"])
        assert revisions[0]["revision"] == 1
        assert revisions[1]["revision"] == 2

    def test_search_in_namespace(self):
        """6.2.6 — `secret search --namespace ns` returns secrets in that namespace."""
        ns = _ns()
        helpers.create_namespace(ns)
        helpers.create_secret(f"{ns}:alpha", "a")
        helpers.create_secret(f"{ns}:beta", "b")

        result = hkey.run("secret", "search", "--namespace", ns, "--json")
        assert result.returncode == 0, f"search failed: {result.stderr}"
        data = json.loads(result.stdout)
        keys = {e["ref_key"] for e in data["entries"]}
        assert "alpha" in keys
        assert "beta" in keys

    def test_search_by_label(self):
        """6.2.7 — `secret search --label key=val` returns only matching secrets."""
        ns = _ns()
        helpers.create_namespace(ns)
        helpers.create_secret(f"{ns}:matched", "a", labels=["tier=gold"])
        helpers.create_secret(f"{ns}:unmatched", "b", labels=["tier=silver"])

        result = hkey.run(
            "secret", "search",
            "--namespace", ns,
            "--label", "tier=gold",
            "--json",
        )
        assert result.returncode == 0, f"search failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["total"] == 1
        assert data["entries"][0]["ref_key"] == "matched"

    def test_describe_requires_secret_describe_permission(self):
        """6.2.8 — A user without secret:describe cannot describe a secret."""
        ns = _ns()
        ref = _setup(ns)

        name = _uid("rbac-sd")
        token = _limited_token(name)

        result = hkey.run_as(token, "secret", "describe", "--ref", ref, "--json")
        assert result.returncode != 0, "Expected describe to fail without secret:describe"


# ---------------------------------------------------------------------------
# 6.3.4 — Reveal @latest revision
# ---------------------------------------------------------------------------

class TestRevealLatest:

    def test_reveal_latest_revision(self):
        """6.3.4 — Revealing @latest returns the most recently created revision."""
        ns = _ns()
        ref = _setup(ns, value="original")

        # Add a second revision (not yet activated)
        hkey.run("secret", "revise", "--ref", ref, "--value", "newer-value")

        result = hkey.run("secret", "reveal", "--ref", f"{ref}@latest")
        assert result.returncode == 0, f"Reveal @latest failed: {result.stderr}"
        assert "newer-value" in result.stdout

    def test_reveal_latest_matches_describe_latest_revision(self):
        """6.3.4 (cross-check) — @latest revision matches latest_revision in describe."""
        ns = _ns()
        ref = _setup(ns, value="v1")
        hkey.run("secret", "revise", "--ref", ref, "--value", "v2")

        data = _describe_json(ref)
        latest_rev = data["latest_revision"]
        assert latest_rev == 2

        # @latest should give us v2
        result = hkey.run("secret", "reveal", "--ref", f"{ref}@latest")
        assert "v2" in result.stdout


# ---------------------------------------------------------------------------
# 6.3.20 — RBAC: secret:reveal is required
# ---------------------------------------------------------------------------

class TestRbacReveal:

    def test_reveal_fails_without_permission(self):
        """6.3.20 — A user without secret:reveal cannot reveal a secret."""
        ns = _ns()
        ref = _setup(ns)

        name = _uid("rbac-rv")
        token = _limited_token(name)

        result = hkey.run_as(token, "secret", "reveal", "--ref", ref)
        assert result.returncode != 0, "Expected reveal to fail without secret:reveal"

    def test_reveal_succeeds_with_permission(self):
        """6.3.20 (positive) — A user with secret:reveal can reveal a secret."""
        ns = _ns()
        ref = _setup(ns, value="secret-value")

        name = _uid("rbac-rv-ok")
        helpers.create_user_account(name, activate=True)
        hkey.run("rbac", "bind", "--name", name, "--rule", f"allow secret:reveal to namespace {ns}")
        token = helpers.login_as(name, "SecurePassword1!")

        result = hkey.run_as(token, "secret", "reveal", "--ref", ref)
        assert result.returncode == 0, f"Expected reveal to succeed with secret:reveal: {result.stderr}"
        assert "secret-value" in result.stdout


# ---------------------------------------------------------------------------
# 6.4 — Update Secret Metadata
# ---------------------------------------------------------------------------

class TestUpdateSecret:

    def test_update_description(self):
        """6.4.1 — Update secret description via CLI."""
        ns = _ns()
        ref = _setup(ns)

        result = hkey.run("secret", "update", "--ref", ref, "--description", "updated desc")
        assert result.returncode == 0, f"update failed: {result.stderr}"

        data = _describe_json(ref)
        assert data["description"] == "updated desc"

    def test_update_labels(self):
        """6.4.2 — Update secret labels via CLI."""
        ns = _ns()
        ref = _setup(ns)

        result = hkey.run("secret", "update", "--ref", ref, "--label", "env=staging")
        assert result.returncode == 0, f"update labels failed: {result.stderr}"

        data = _describe_json(ref)
        assert data["labels"].get("env") == "staging"

    def test_clear_description(self):
        """6.4.3 — Clear description leaves it null/absent."""
        ns = _ns()
        ref = f"{ns}:secret/key"
        helpers.create_namespace(ns)
        helpers.create_secret(ref, "v", description="to be cleared")

        result = hkey.run("secret", "update", "--ref", ref, "--clear-description")
        assert result.returncode == 0, f"clear-description failed: {result.stderr}"

        data = _describe_json(ref)
        assert not data.get("description"), "Expected description to be cleared"

    def test_update_nonexistent_secret_fails(self):
        """6.4.4 — Updating a non-existent secret returns an error."""
        ns = _ns()
        helpers.create_namespace(ns)

        result = hkey.run("secret", "update", "--ref", f"{ns}:no-such-key", "--description", "x")
        assert result.returncode != 0, "Expected update of non-existent secret to fail"

    def test_update_requires_secret_update_meta_permission(self):
        """6.4.5 — A user without secret:update:meta cannot update a secret."""
        ns = _ns()
        ref = _setup(ns)

        name = _uid("rbac-um")
        token = _limited_token(name)

        result = hkey.run_as(token, "secret", "update", "--ref", ref, "--description", "denied")
        assert result.returncode != 0, "Expected update to fail without secret:update:meta"


# ---------------------------------------------------------------------------
# 6.5 — Revise (Create New Revision)
# ---------------------------------------------------------------------------

class TestReviseSecret:

    def test_revise_increments_revision_counter(self):
        """6.5.1 — Revising a secret increments latest_revision."""
        ns = _ns()
        ref = _setup(ns, value="v1")

        result = hkey.run("secret", "revise", "--ref", ref, "--value", "v2")
        assert result.returncode == 0, f"revise failed: {result.stderr}"

        data = _describe_json(ref)
        assert data["latest_revision"] == 2

    def test_revise_with_activate_makes_new_revision_active(self):
        """6.5.2 — revise --activate makes the new revision the active one."""
        ns = _ns()
        ref = _setup(ns, value="old-value")

        result = hkey.run("secret", "revise", "--ref", ref, "--value", "new-value", "--activate")
        assert result.returncode == 0, f"revise --activate failed: {result.stderr}"

        revealed = hkey.run("secret", "reveal", "--ref", ref)
        assert "new-value" in revealed.stdout

        data = _describe_json(ref)
        assert data["active_revision"] == 2

    def test_revise_without_activate_keeps_old_revision_active(self):
        """6.5.3 — revise without --activate leaves the active revision unchanged."""
        ns = _ns()
        ref = _setup(ns, value="v1")

        result = hkey.run("secret", "revise", "--ref", ref, "--value", "v2")
        assert result.returncode == 0, f"revise failed: {result.stderr}"

        data = _describe_json(ref)
        assert data["active_revision"] == 1, "Active revision should remain 1 after revise without --activate"
        assert data["latest_revision"] == 2

        revealed = hkey.run("secret", "reveal", "--ref", ref)
        assert "v1" in revealed.stdout

    def test_reveal_new_revision_by_number(self):
        """6.5.4 — The new revision can be revealed by explicit revision number."""
        ns = _ns()
        ref = _setup(ns, value="first")
        hkey.run("secret", "revise", "--ref", ref, "--value", "second")

        result = hkey.run("secret", "reveal", "--ref", f"{ref}@2")
        assert result.returncode == 0, f"Reveal @2 failed: {result.stderr}"
        assert "second" in result.stdout

    def test_revise_with_note(self):
        """6.5.6 — Revising with --note stores the note in the revision description."""
        ns = _ns()
        ref = _setup(ns, value="v1")

        result = hkey.run("secret", "revise", "--ref", ref, "--value", "v2", "--note", "quarterly rotation")
        assert result.returncode == 0, f"revise --note failed: {result.stderr}"

        data = _describe_json(ref)
        rev2 = next((r for r in data["revisions"] if r["revision"] == 2), None)
        assert rev2 is not None
        assert "quarterly rotation" in (rev2.get("description") or "")

    def test_revise_nonexistent_secret_fails(self):
        """6.5.7 — Revising a non-existent secret returns an error."""
        ns = _ns()
        helpers.create_namespace(ns)

        result = hkey.run("secret", "revise", "--ref", f"{ns}:ghost", "--value", "x")
        assert result.returncode != 0, "Expected revise of non-existent secret to fail"

    def test_revise_requires_secret_revise_permission(self):
        """6.5.8 — A user without secret:revise cannot revise a secret."""
        ns = _ns()
        ref = _setup(ns)

        name = _uid("rbac-rr")
        token = _limited_token(name)

        result = hkey.run_as(token, "secret", "revise", "--ref", ref, "--value", "x")
        assert result.returncode != 0, "Expected revise to fail without secret:revise"


# ---------------------------------------------------------------------------
# 6.6 — Activate Revision
# ---------------------------------------------------------------------------

class TestActivateRevision:

    def test_activate_older_revision(self):
        """6.6.1 — Activating an older revision makes it the active one."""
        ns = _ns()
        ref = _setup(ns, value="v1")
        hkey.run("secret", "revise", "--ref", ref, "--value", "v2", "--activate")

        # Active is now 2; re-activate revision 1
        result = hkey.run("secret", "activate", "--ref", f"{ref}@1")
        assert result.returncode == 0, f"activate @1 failed: {result.stderr}"

        data = _describe_json(ref)
        assert data["active_revision"] == 1

    def test_reveal_returns_newly_activated_value(self):
        """6.6.2 — After activation, reveal returns the value of the newly active revision."""
        ns = _ns()
        ref = _setup(ns, value="old")
        hkey.run("secret", "revise", "--ref", ref, "--value", "new", "--activate")

        # Switch back to revision 1
        hkey.run("secret", "activate", "--ref", f"{ref}@1")

        result = hkey.run("secret", "reveal", "--ref", ref)
        assert "old" in result.stdout

    def test_activate_nonexistent_revision_fails(self):
        """6.6.3 — Activating a non-existent revision returns an error."""
        ns = _ns()
        ref = _setup(ns)

        result = hkey.run("secret", "activate", "--ref", f"{ref}@999")
        assert result.returncode != 0, "Expected activate of non-existent revision to fail"

    def test_activate_already_active_is_idempotent(self):
        """6.6.4 — Re-activating the already-active revision succeeds without error."""
        ns = _ns()
        ref = _setup(ns)

        data = _describe_json(ref)
        active = data["active_revision"]

        result = hkey.run("secret", "activate", "--ref", f"{ref}@{active}")
        assert result.returncode == 0, f"Idempotent activate failed: {result.stderr}"


# ---------------------------------------------------------------------------
# 6.7 — Annotate Revision
# ---------------------------------------------------------------------------

class TestAnnotateRevision:

    def test_annotate_active_revision(self):
        """6.7.1 — Annotating the active revision stores a note on that revision."""
        ns = _ns()
        ref = _setup(ns)

        result = hkey.run("secret", "annotate", "--ref", ref, "--note", "review me")
        assert result.returncode == 0, f"annotate failed: {result.stderr}"

        data = _describe_json(ref)
        active = data["active_revision"]
        rev = next((r for r in data["revisions"] if r["revision"] == active), None)
        assert rev is not None
        assert "review me" in (rev.get("description") or "")

    def test_annotate_specific_revision(self):
        """6.7.2 — Annotating a specific revision by @N stores the note on that revision."""
        ns = _ns()
        ref = _setup(ns, value="v1")
        hkey.run("secret", "revise", "--ref", ref, "--value", "v2", "--activate")

        result = hkey.run("secret", "annotate", "--ref", f"{ref}@1", "--note", "legacy revision")
        assert result.returncode == 0, f"annotate @1 failed: {result.stderr}"

        data = _describe_json(ref)
        rev1 = next((r for r in data["revisions"] if r["revision"] == 1), None)
        assert rev1 is not None
        assert "legacy revision" in (rev1.get("description") or "")

    def test_clear_annotation(self):
        """6.7.3 — --clear-note removes the annotation from the active revision."""
        ns = _ns()
        ref = _setup(ns)
        hkey.run("secret", "annotate", "--ref", ref, "--note", "initial note")

        result = hkey.run("secret", "annotate", "--ref", ref, "--clear-note")
        assert result.returncode == 0, f"clear-note failed: {result.stderr}"

        data = _describe_json(ref)
        active = data["active_revision"]
        rev = next((r for r in data["revisions"] if r["revision"] == active), None)
        assert rev is not None
        assert not rev.get("description"), "Expected annotation to be cleared"

    def test_annotate_nonexistent_secret_fails(self):
        """6.7.4 — Annotating a non-existent secret returns an error."""
        ns = _ns()
        helpers.create_namespace(ns)

        result = hkey.run("secret", "annotate", "--ref", f"{ns}:no-such", "--note", "x")
        assert result.returncode != 0, "Expected annotate of non-existent secret to fail"


# ---------------------------------------------------------------------------
# 6.8 — Delete Secret
# ---------------------------------------------------------------------------

class TestDeleteSecret:

    def test_delete_secret_removes_from_list(self):
        """6.8.1 — Deleting a secret causes it to no longer appear in search results."""
        ns = _ns()
        ref = _setup(ns)

        result = hkey.run("secret", "delete", "--ref", ref, "--confirm")
        assert result.returncode == 0, f"delete failed: {result.stderr}"

        data = helpers.get_secrets_json(ns)
        assert helpers.find_secret(data, "secret/key") is None, "Deleted secret still appears in list"

    def test_reveal_deleted_secret_fails(self):
        """6.8.2 — Revealing a deleted secret returns an error."""
        ns = _ns()
        ref = _setup(ns)
        hkey.run("secret", "delete", "--ref", ref, "--confirm")

        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode != 0, "Expected reveal of deleted secret to fail"

    def test_delete_nonexistent_secret_fails(self):
        """6.8.3 — Deleting a non-existent secret returns an error."""
        ns = _ns()
        helpers.create_namespace(ns)

        result = hkey.run("secret", "delete", "--ref", f"{ns}:ghost", "--confirm")
        assert result.returncode != 0, "Expected delete of non-existent secret to fail"

    def test_delete_requires_secret_delete_permission(self):
        """6.8.4 — A user without secret:delete cannot delete a secret."""
        ns = _ns()
        ref = _setup(ns)

        name = _uid("rbac-del")
        token = _limited_token(name)

        result = hkey.run_as(token, "secret", "delete", "--ref", ref, "--confirm")
        assert result.returncode != 0, "Expected delete to fail without secret:delete"


# ---------------------------------------------------------------------------
# 6.9 — Secret Types
# ---------------------------------------------------------------------------

class TestSecretTypes:

    def test_create_with_type_password(self):
        """6.9.1 — Creating with --type password stores and returns the correct type."""
        ns = _ns()
        helpers.create_namespace(ns)
        ref = f"{ns}:pw"

        result = hkey.run("secret", "create", "--ref", ref, "--type", "password", "--value", "hunter2")
        assert result.returncode == 0, f"create --type password failed: {result.stderr}"

        data = _describe_json(ref)
        assert data["secret_type"] == "password"

    def test_create_with_type_opaque(self):
        """6.9.2 — Creating with --type opaque (generic binary) stores the correct type."""
        ns = _ns()
        helpers.create_namespace(ns)
        ref = f"{ns}:opaque"

        result = hkey.run("secret", "create", "--ref", ref, "--type", "opaque", "--value", "rawdata")
        assert result.returncode == 0, f"create --type opaque failed: {result.stderr}"

        data = _describe_json(ref)
        assert data["secret_type"] == "opaque"

    def test_create_with_type_certificate(self):
        """6.9.3 — Creating with --type certificate accepts a valid PEM certificate."""
        ns = _ns()
        helpers.create_namespace(ns)
        ref = f"{ns}:cert"

        pem = _generate_test_cert_pem()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(pem)
            pem_path = f.name
        try:
            result = hkey.run("secret", "create", "--ref", ref, "--type", "certificate", "--from-file", pem_path)
            assert result.returncode == 0, f"create --type certificate failed: {result.stderr}"
        finally:
            os.unlink(pem_path)

        data = _describe_json(ref)
        assert data["secret_type"] == "certificate"

    def test_secret_type_preserved_in_describe(self):
        """6.9.4 — The secret_type field in describe matches the type used at creation."""
        ns = _ns()
        helpers.create_namespace(ns)

        for stype in ("password", "opaque"):
            ref = f"{ns}:{stype}-test"
            hkey.run("secret", "create", "--ref", ref, "--type", stype, "--value", "val")
            data = _describe_json(ref)
            assert data["secret_type"] == stype, f"Expected {stype}, got {data['secret_type']}"

    def test_invalid_certificate_pem_is_rejected(self):
        """6.9.5 — Creating with --type certificate rejects an invalid PEM value."""
        ns = _ns()
        helpers.create_namespace(ns)

        result = hkey.run(
            "secret", "create",
            "--ref", f"{ns}:bad-cert",
            "--type", "certificate",
            "--value", "this is not a certificate",
        )
        assert result.returncode != 0, "Expected invalid certificate PEM to be rejected"


# ---------------------------------------------------------------------------
# 6.10 — Disable / Enable Secret
# ---------------------------------------------------------------------------

class TestDisableEnableSecret:

    def _disable(self, short_id):
        return requests.post(
            f"{_server_url()}/v1/secrets/{short_id}/disable",
            headers={"Authorization": f"Bearer {_admin_token()}"},
        )

    def _enable(self, short_id):
        return requests.post(
            f"{_server_url()}/v1/secrets/{short_id}/enable",
            headers={"Authorization": f"Bearer {_admin_token()}"},
        )

    def test_disable_prevents_reveal(self):
        """6.10.1 — A disabled secret cannot be revealed."""
        ns = _ns()
        ref = _setup(ns, value="should-be-hidden")
        short_id = _describe_json(ref)["short_id"]

        r = self._disable(short_id)
        assert r.status_code == 200, f"disable failed: {r.text}"

        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode != 0, "Expected reveal to fail for disabled secret"

    def test_disabled_secret_appears_in_list_with_status(self):
        """6.10.2 — Disabled secrets still appear in list with status='disabled'."""
        ns = _ns()
        ref = _setup(ns)
        short_id = _describe_json(ref)["short_id"]

        r = self._disable(short_id)
        assert r.status_code == 200

        list_data = helpers.get_secrets_json(ns)
        entry = helpers.find_secret(list_data, "secret/key")
        assert entry is not None, "Disabled secret should still appear in list"
        assert entry["status"] == "disabled", f"Expected status 'disabled', got '{entry['status']}'"

    def test_enable_restores_revealability(self):
        """6.10.3 — Re-enabling a disabled secret makes it revealable again."""
        ns = _ns()
        ref = _setup(ns, value="comes-back")
        short_id = _describe_json(ref)["short_id"]

        self._disable(short_id)

        r = self._enable(short_id)
        assert r.status_code == 200, f"enable failed: {r.text}"

        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode == 0, f"Expected reveal to succeed after re-enable: {result.stderr}"
        assert "comes-back" in result.stdout

    def test_disable_already_disabled_fails(self):
        """6.10.4 — Disabling an already-disabled secret returns an error."""
        ns = _ns()
        ref = _setup(ns)
        short_id = _describe_json(ref)["short_id"]

        self._disable(short_id)

        r = self._disable(short_id)
        assert r.status_code != 200, f"Expected error when disabling already-disabled secret"

    def test_enable_active_secret_fails(self):
        """6.10.5 — Enabling an already-active secret returns an error."""
        ns = _ns()
        ref = _setup(ns)
        short_id = _describe_json(ref)["short_id"]

        r = self._enable(short_id)
        assert r.status_code != 200, f"Expected error when enabling an active secret"

    def test_enable_deleted_secret_returns_not_found(self):
        """6.10.6 — Deleted secrets are invisible to the enable endpoint (returns 404)."""
        ns = _ns()
        ref = _setup(ns)
        short_id = _describe_json(ref)["short_id"]

        hkey.run("secret", "delete", "--ref", ref, "--confirm")

        # Deleted secrets are excluded from short-id lookups
        r = self._enable(short_id)
        assert r.status_code == 404, f"Expected 404 for enable of deleted secret, got {r.status_code}"


# ---------------------------------------------------------------------------
# 6.11 — Restore Deleted Secret
# ---------------------------------------------------------------------------

class TestRestoreSecret:

    def _restore(self, secret_uuid):
        return requests.post(
            f"{_server_url()}/v1/secrets/{secret_uuid}/restore",
            headers={"Authorization": f"Bearer {_admin_token()}"},
        )

    def test_restore_makes_secret_revealable(self):
        """6.11.1 — Restoring a deleted secret makes it active and revealable again."""
        ns = _ns()
        ref = _setup(ns, value="lives-again")
        data = _describe_json(ref)
        secret_id = data["id"]

        hkey.run("secret", "delete", "--ref", ref, "--confirm")

        # Verify it's gone from the list
        list_data = helpers.get_secrets_json(ns)
        assert helpers.find_secret(list_data, "secret/key") is None

        r = self._restore(secret_id)
        assert r.status_code == 200, f"restore failed: {r.text}"

        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode == 0, f"Expected reveal to succeed after restore: {result.stderr}"
        assert "lives-again" in result.stdout

    def test_restore_makes_secret_appear_in_list(self):
        """6.11.2 — A restored secret reappears in list with status='active'."""
        ns = _ns()
        ref = _setup(ns)
        data = _describe_json(ref)
        secret_id = data["id"]

        hkey.run("secret", "delete", "--ref", ref, "--confirm")

        self._restore(secret_id)

        list_data = helpers.get_secrets_json(ns)
        entry = helpers.find_secret(list_data, "secret/key")
        assert entry is not None, "Restored secret should appear in list"
        assert entry["status"] == "active", f"Expected status 'active', got '{entry['status']}'"

    def test_deleted_secret_can_be_recreated_with_same_name(self):
        """6.11.3 — After deletion, a new secret with the same ref can be created."""
        ns = _ns()
        ref = _setup(ns, value="original")
        first_id = _describe_json(ref)["id"]

        hkey.run("secret", "delete", "--ref", ref, "--confirm")

        # Create a new secret with the same ref — must succeed (partial unique index)
        helpers.create_secret(ref, "replacement")

        data = _describe_json(ref)
        assert data["id"] != first_id, "New secret should have a different UUID"
        assert data["status"] == "active"

    def test_restore_active_secret_fails(self):
        """6.11.4 — Trying to restore a non-deleted secret returns an error."""
        ns = _ns()
        ref = _setup(ns)
        secret_id = _describe_json(ref)["id"]

        r = self._restore(secret_id)
        assert r.status_code != 200, f"Expected error when restoring non-deleted secret"

    def test_restore_nonexistent_id_fails(self):
        """6.11.5 — Restoring a random UUID that doesn't exist returns an error."""
        fake_id = str(uuid.uuid4())

        r = self._restore(fake_id)
        assert r.status_code in (404, 400), (
            f"Expected 404 or 400 for nonexistent secret, got {r.status_code}"
        )


# ---------------------------------------------------------------------------
# 6.10 (CLI) — Disable / Enable Secret via hkey CLI
# ---------------------------------------------------------------------------

class TestDisableEnableSecretCLI:

    def test_disable_via_cli_ref_prevents_reveal(self):
        """6.10.CLI.1 — `hkey secret disable --ref` blocks reveal."""
        ns = _ns()
        ref = _setup(ns, value="hidden-value")

        result = hkey.run("secret", "disable", "--ref", ref)
        assert result.returncode == 0, f"disable failed: {result.stderr}"
        assert "disabled successfully" in result.stdout

        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode != 0, "Expected reveal to fail after CLI disable"

    def test_disable_via_cli_short_id_prevents_reveal(self):
        """6.10.CLI.2 — `hkey secret disable --id sec_...` blocks reveal."""
        ns = _ns()
        ref = _setup(ns, value="also-hidden")
        short_id = _describe_json(ref)["short_id"]

        result = hkey.run("secret", "disable", "--id", short_id)
        assert result.returncode == 0, f"disable --id failed: {result.stderr}"

        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode != 0, "Expected reveal to fail after CLI disable by ID"

    def test_enable_via_cli_ref_restores_reveal(self):
        """6.10.CLI.3 — `hkey secret enable --ref` makes a disabled secret revealable again."""
        ns = _ns()
        ref = _setup(ns, value="comes-back-cli")
        short_id = _describe_json(ref)["short_id"]

        # Disable via HTTP (to isolate enable CLI under test)
        import requests
        requests.post(
            f"{_server_url()}/v1/secrets/{short_id}/disable",
            headers={"Authorization": f"Bearer {_admin_token()}"},
        )

        result = hkey.run("secret", "enable", "--ref", ref)
        assert result.returncode == 0, f"enable --ref failed: {result.stderr}"
        assert "enabled successfully" in result.stdout

        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode == 0, f"Expected reveal to succeed after CLI enable: {result.stderr}"
        assert "comes-back-cli" in result.stdout

    def test_enable_via_cli_short_id_restores_reveal(self):
        """6.10.CLI.4 — `hkey secret enable --id sec_...` restores revealability."""
        ns = _ns()
        ref = _setup(ns, value="back-by-id")
        short_id = _describe_json(ref)["short_id"]

        import requests
        requests.post(
            f"{_server_url()}/v1/secrets/{short_id}/disable",
            headers={"Authorization": f"Bearer {_admin_token()}"},
        )

        result = hkey.run("secret", "enable", "--id", short_id)
        assert result.returncode == 0, f"enable --id failed: {result.stderr}"

        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode == 0, f"Reveal after enable by ID failed: {result.stderr}"
        assert "back-by-id" in result.stdout

    def test_disable_json_output(self):
        """6.10.CLI.5 — `hkey secret disable --json` returns JSON with disabled=true."""
        ns = _ns()
        ref = _setup(ns)

        result = hkey.run("secret", "disable", "--ref", ref, "--json")
        assert result.returncode == 0, f"disable --json failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert data.get("disabled") is True

    def test_enable_json_output(self):
        """6.10.CLI.6 — `hkey secret enable --json` returns JSON with enabled=true."""
        ns = _ns()
        ref = _setup(ns)
        short_id = _describe_json(ref)["short_id"]

        import requests
        requests.post(
            f"{_server_url()}/v1/secrets/{short_id}/disable",
            headers={"Authorization": f"Bearer {_admin_token()}"},
        )

        result = hkey.run("secret", "enable", "--ref", ref, "--json")
        assert result.returncode == 0, f"enable --json failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert data.get("enabled") is True

    def test_disable_nonexistent_secret_fails(self):
        """6.10.CLI.7 — Disabling a non-existent secret returns an error."""
        ns = _ns()
        helpers.create_namespace(ns)

        result = hkey.run("secret", "disable", "--ref", f"{ns}:no-such-key")
        assert result.returncode != 0, "Expected disable of non-existent secret to fail"

    def test_enable_nonexistent_secret_fails(self):
        """6.10.CLI.8 — Enabling a non-existent secret returns an error."""
        ns = _ns()
        helpers.create_namespace(ns)

        result = hkey.run("secret", "enable", "--ref", f"{ns}:no-such-key")
        assert result.returncode != 0, "Expected enable of non-existent secret to fail"


# ---------------------------------------------------------------------------
# 6.11 (CLI) — Restore Deleted Secret via hkey CLI
# ---------------------------------------------------------------------------

class TestRestoreSecretCLI:

    def test_restore_via_cli_uuid_makes_secret_revealable(self):
        """6.11.CLI.1 — `hkey secret restore --id <uuid>` restores a deleted secret."""
        ns = _ns()
        ref = _setup(ns, value="restored-cli")
        secret_uuid = _describe_json(ref)["id"]

        hkey.run("secret", "delete", "--ref", ref, "--confirm")

        result = hkey.run("secret", "restore", "--id", secret_uuid)
        assert result.returncode == 0, f"restore --id <uuid> failed: {result.stderr}"
        assert "restored successfully" in result.stdout

        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode == 0, f"Expected reveal to succeed after restore: {result.stderr}"
        assert "restored-cli" in result.stdout

    def test_restore_via_cli_short_id_makes_secret_revealable(self):
        """6.11.CLI.2 — `hkey secret restore --id sec_...` also works with the short ID."""
        ns = _ns()
        ref = _setup(ns, value="restored-by-short-id")
        short_id = _describe_json(ref)["short_id"]

        hkey.run("secret", "delete", "--ref", ref, "--confirm")

        result = hkey.run("secret", "restore", "--id", short_id)
        assert result.returncode == 0, f"restore --id <short_id> failed: {result.stderr}"

        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode == 0, f"Expected reveal to succeed after restore: {result.stderr}"
        assert "restored-by-short-id" in result.stdout

    def test_restore_reappears_in_list(self):
        """6.11.CLI.3 — A restored secret reappears in the list with status='active'."""
        ns = _ns()
        ref = _setup(ns)
        secret_uuid = _describe_json(ref)["id"]

        hkey.run("secret", "delete", "--ref", ref, "--confirm")
        hkey.run("secret", "restore", "--id", secret_uuid)

        list_data = helpers.get_secrets_json(ns)
        entry = helpers.find_secret(list_data, "secret/key")
        assert entry is not None, "Restored secret should appear in list"
        assert entry["status"] == "active", f"Expected status 'active', got '{entry['status']}'"

    def test_restore_json_output(self):
        """6.11.CLI.4 — `hkey secret restore --json` returns JSON with restored=true."""
        ns = _ns()
        ref = _setup(ns)
        secret_uuid = _describe_json(ref)["id"]

        hkey.run("secret", "delete", "--ref", ref, "--confirm")

        result = hkey.run("secret", "restore", "--id", secret_uuid, "--json")
        assert result.returncode == 0, f"restore --json failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert data.get("restored") is True

    def test_restore_nonexistent_id_fails(self):
        """6.11.CLI.5 — Restoring a random UUID that doesn't exist returns an error."""
        result = hkey.run("secret", "restore", "--id", str(uuid.uuid4()))
        assert result.returncode != 0, "Expected restore of nonexistent secret to fail"
