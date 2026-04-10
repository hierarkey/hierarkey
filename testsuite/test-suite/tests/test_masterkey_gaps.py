# tests/test_masterkey_gaps.py
#
# Tests that fill the gaps in section 7 of the test plan.
# Existing coverage lives in test_rotation.py.
#
#   7.1.3   Describe specific master key by name
#   7.1.4   Describe non-existent master key returns error
#   7.2.2   Create with passphrase provider
#   7.2.3   Create insecure key without allow_insecure_masterkey returns 403
#   7.2.4   Create passphrase key without providing passphrase returns 400
#   7.3.1   Activate pending master key → status becomes Active  [ROTATION]
#   7.3.2   Activate already-active key is idempotent
#   7.3.3   Activate non-existent key returns error
#   7.4.1   Lock unlocked master key → status becomes Locked
#   7.4.2   Lock already-locked key is idempotent
#   7.4.3   Reveal secret fails when master key is locked          [ROTATION]
#   7.4.4   Unlock with correct passphrase
#   7.4.5   Unlock with wrong passphrase returns error
#   7.4.6   Secret is revealable again after unlock                [ROTATION]
#   7.4.9   Lock non-existent key returns error
#   7.5.1   Delete retired master key succeeds                     [ROTATION]
#   7.5.2   Cannot delete active/draining/pending master key
#   7.5.3   Delete non-existent key returns error
#   7.6.1-4 Full rotation workflow                                  [ROTATION]
#
# [ROTATION] tests require HKEY_TEST_MASTERKEY_ROTATION=1 and permanently
# change the active master key in the test environment.  Run them separately
# on a disposable instance; they are not appropriate for CI against a shared
# server.

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


def _uid(prefix="mk"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _mk_describe_json(name):
    result = hkey.run("masterkey", "describe", "--name", name, "--json")
    assert result.returncode == 0, f"masterkey describe '{name}' failed: {result.stderr}"
    return json.loads(result.stdout)


def _mk_create_passphrase(name, passphrase="TestPassphrase123!"):
    """Create a passphrase-backed master key; return the passphrase used."""
    result = hkey.run(
        "masterkey", "create",
        "--name", name,
        "--usage", "wrap_kek",
        "--provider", "passphrase",
        "--insecure-passphrase", passphrase,
    )
    assert result.returncode == 0, f"masterkey create (passphrase) '{name}' failed: {result.stderr}"
    return passphrase


# ---------------------------------------------------------------------------
# 7.1.3 — Describe specific master key by name
# ---------------------------------------------------------------------------

class TestDescribeMasterKey:

    def test_describe_by_name(self):
        """7.1.3 — `masterkey describe --name root` returns the key's details."""
        data = _mk_describe_json("root")
        mk = data["master_key"]
        assert mk["name"] == "root"
        assert mk["status"] == "active"
        assert "keyring" in data
        assert data["keyring"]["locked"] is False

    def test_describe_nonexistent_returns_error(self):
        """7.1.4 — Describing a non-existent master key returns an error."""
        result = hkey.run("masterkey", "describe", "--name", "no-such-key-xyz")
        assert result.returncode != 0, "Expected describe of non-existent key to fail"


# ---------------------------------------------------------------------------
# 7.2 — Create Master Keys
# ---------------------------------------------------------------------------

class TestCreateMasterKey:

    def test_create_with_passphrase_provider(self):
        """7.2.2 — Creating a master key with the passphrase provider succeeds."""
        name = _uid("mk-pp")
        _mk_create_passphrase(name)

        data = _mk_describe_json(name)
        mk = data["master_key"]
        assert mk["name"] == name
        assert mk["status"] == "pending"
        assert data["keyring"]["provider"] == "passphrase"

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_MASTERKEY_INSECURE_DISABLED"),
        reason=(
            "Requires server started with masterkey.allow_insecure_masterkey = false. "
            "Set HKEY_TEST_MASTERKEY_INSECURE_DISABLED=1 to run."
        ),
    )
    def test_create_insecure_without_config_returns_403(self):
        """7.2.3 — Creating an insecure master key when the config flag is off returns 403."""
        r = requests.post(
            f"{server_url()}/v1/masterkeys",
            json={
                "name": _uid("mk-insec"),
                "usage": "wrap_kek",
                "provider": "insecure",
                "labels": {},
            },
            headers=_auth_header(),
        )
        assert r.status_code == 403, (
            f"Expected 403 when allow_insecure_masterkey is false, got {r.status_code}: {r.text}"
        )

    def test_create_passphrase_without_passphrase_returns_400(self):
        """7.2.4 — Creating a passphrase key without providing a passphrase returns 400."""
        r = requests.post(
            f"{server_url()}/v1/masterkeys",
            json={
                "name": _uid("mk-nopass"),
                "usage": "wrap_kek",
                "provider": "passphrase",
                "labels": {},
                # passphrase intentionally omitted
            },
            headers=_auth_header(),
        )
        assert r.status_code == 400, (
            f"Expected 400 when passphrase is missing, got {r.status_code}: {r.text}"
        )


# ---------------------------------------------------------------------------
# 7.3 — Activate
# ---------------------------------------------------------------------------

class TestActivateMasterKey:

    def test_activate_already_active_is_idempotent(self):
        """7.3.2 — Activating the already-active 'root' key returns success without error."""
        result = hkey.run("masterkey", "activate", "--name", "root")
        assert result.returncode == 0, (
            f"Expected idempotent activate of active key to succeed: {result.stderr}"
        )
        assert "already activated" in result.stdout.lower() or result.returncode == 0

    def test_activate_nonexistent_returns_error(self):
        """7.3.3 — Activating a non-existent master key returns an error."""
        result = hkey.run("masterkey", "activate", "--name", "no-such-key-xyz")
        assert result.returncode != 0, "Expected activate of non-existent key to fail"

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_MASTERKEY_ROTATION"),
        reason=(
            "Activating a new key permanently changes the active master key. "
            "Set HKEY_TEST_MASTERKEY_ROTATION=1 to run on a disposable instance."
        ),
    )
    def test_activate_pending_key_becomes_active(self):
        """7.3.1 — Activating a pending master key changes its status to active. [ROTATION]"""
        name = _uid("mk-act")
        hkey.run(
            "masterkey", "create",
            "--name", name,
            "--usage", "wrap_kek",
            "--provider", "insecure",
        )

        data_before = _mk_describe_json(name)
        assert data_before["master_key"]["status"] == "pending"

        result = hkey.run("masterkey", "activate", "--name", name)
        assert result.returncode == 0, f"activate failed: {result.stderr}"

        data_after = _mk_describe_json(name)
        assert data_after["master_key"]["status"] == "active"


# ---------------------------------------------------------------------------
# 7.4 — Lock & Unlock
# ---------------------------------------------------------------------------

class TestLockUnlockMasterKey:

    def test_lock_passphrase_key(self):
        """7.4.1 — Locking an unlocked passphrase master key sets locked = true."""
        name = _uid("mk-lock")
        passphrase = _mk_create_passphrase(name)

        # Passphrase key is auto-unlocked after creation (passphrase was just provided)
        data_before = _mk_describe_json(name)
        assert data_before["keyring"]["locked"] is False, "Expected key to be unlocked after creation"

        result = hkey.run("masterkey", "lock", "--name", name)
        assert result.returncode == 0, f"lock failed: {result.stderr}"

        data_after = _mk_describe_json(name)
        assert data_after["keyring"]["locked"] is True, "Expected key to be locked after lock command"

    def test_lock_already_locked_is_idempotent(self):
        """7.4.2 — Locking an already-locked key returns success without error."""
        name = _uid("mk-lock2")
        _mk_create_passphrase(name)

        hkey.run("masterkey", "lock", "--name", name)

        result = hkey.run("masterkey", "lock", "--name", name)
        assert result.returncode == 0, f"Expected idempotent lock to succeed: {result.stderr}"
        assert "already locked" in result.stdout.lower() or result.returncode == 0

    def test_unlock_with_correct_passphrase(self):
        """7.4.4 — Unlocking with the correct passphrase sets locked = false."""
        name = _uid("mk-unlock")
        passphrase = _mk_create_passphrase(name)
        hkey.run("masterkey", "lock", "--name", name)

        result = hkey.run("masterkey", "unlock", "--name", name, "--insecure-passphrase", passphrase)
        assert result.returncode == 0, f"unlock failed: {result.stderr}"

        data = _mk_describe_json(name)
        assert data["keyring"]["locked"] is False, "Expected key to be unlocked after unlock"

    def test_unlock_with_wrong_passphrase_fails(self):
        """7.4.5 — Unlocking with a wrong passphrase returns an error."""
        name = _uid("mk-badpw")
        _mk_create_passphrase(name, passphrase="CorrectPassphrase123!")
        hkey.run("masterkey", "lock", "--name", name)

        result = hkey.run(
            "masterkey", "unlock",
            "--name", name,
            "--insecure-passphrase", "WrongPassphrase999!",
        )
        assert result.returncode != 0, "Expected unlock with wrong passphrase to fail"

    def test_lock_nonexistent_returns_error(self):
        """7.4.9 — Locking a non-existent master key returns an error."""
        result = hkey.run("masterkey", "lock", "--name", "no-such-key-xyz")
        assert result.returncode != 0, "Expected lock of non-existent key to fail"

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_MASTERKEY_ROTATION"),
        reason=(
            "Requires activating a non-root key. "
            "Set HKEY_TEST_MASTERKEY_ROTATION=1 to run on a disposable instance."
        ),
    )
    def test_reveal_fails_when_active_key_is_locked(self):
        """7.4.3 — Revealing a secret fails when the master key wrapping its KEK is locked. [ROTATION]"""
        # This test requires the currently-active master key to be a passphrase key.
        # It assumes the rotation test has already been run (active key is not 'root').
        active_name = os.environ.get("HKEY_TEST_ACTIVE_MASTERKEY_NAME", "root")

        ns = "/mk-lock-reveal"
        helpers.create_namespace(ns)
        helpers.create_secret(f"{ns}:pw", "secret-value")

        hkey.run("masterkey", "lock", "--name", active_name)
        try:
            result = hkey.run("secret", "reveal", "--ref", f"{ns}:pw")
            assert result.returncode != 0, "Expected reveal to fail when master key is locked"
        finally:
            passphrase = os.environ.get("HKEY_TEST_ACTIVE_MASTERKEY_PASSPHRASE", "")
            if passphrase:
                hkey.run("masterkey", "unlock", "--name", active_name, "--insecure-passphrase", passphrase)
            else:
                hkey.run("masterkey", "unlock", "--name", active_name)

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_MASTERKEY_ROTATION"),
        reason=(
            "Requires activating a non-root key. "
            "Set HKEY_TEST_MASTERKEY_ROTATION=1 to run on a disposable instance."
        ),
    )
    def test_reveal_works_after_unlock(self):
        """7.4.6 — Revealing a secret succeeds after the master key is unlocked. [ROTATION]"""
        active_name = os.environ.get("HKEY_TEST_ACTIVE_MASTERKEY_NAME", "root")

        ns = "/mk-unlock-reveal"
        helpers.create_namespace(ns)
        helpers.create_secret(f"{ns}:token", "my-token")

        hkey.run("masterkey", "lock", "--name", active_name)

        passphrase = os.environ.get("HKEY_TEST_ACTIVE_MASTERKEY_PASSPHRASE", "")
        if passphrase:
            hkey.run("masterkey", "unlock", "--name", active_name, "--insecure-passphrase", passphrase)
        else:
            hkey.run("masterkey", "unlock", "--name", active_name)

        result = hkey.run("secret", "reveal", "--ref", f"{ns}:token")
        assert result.returncode == 0, f"Expected reveal to succeed after unlock: {result.stderr}"
        assert "my-token" in result.stdout


# ---------------------------------------------------------------------------
# 7.5 — Delete
# ---------------------------------------------------------------------------

class TestDeleteMasterKey:

    def test_cannot_delete_pending_key(self):
        """7.5.2 (pending) — A pending master key (has no KEKs but isn't retired) cannot be deleted."""
        name = _uid("mk-del-p")
        hkey.run(
            "masterkey", "create",
            "--name", name,
            "--usage", "wrap_kek",
            "--provider", "insecure",
        )
        # pending key → should fail (only retired keys can be deleted)
        result = hkey.run("masterkey", "delete", "--name", name)
        assert result.returncode != 0, "Expected deleting a pending (non-retired) key to fail"

    def test_cannot_delete_active_key(self):
        """7.5.2 (active) — The active master key protecting KEKs cannot be deleted."""
        result = hkey.run("masterkey", "delete", "--name", "root")
        assert result.returncode != 0, "Expected deleting the active master key to fail"

    def test_delete_nonexistent_returns_error(self):
        """7.5.3 — Deleting a non-existent master key returns an error."""
        result = hkey.run("masterkey", "delete", "--name", "no-such-key-xyz")
        assert result.returncode != 0, "Expected delete of non-existent key to fail"

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_MASTERKEY_ROTATION"),
        reason=(
            "Deleting a retired key requires a full rotation first. "
            "Set HKEY_TEST_MASTERKEY_ROTATION=1 to run on a disposable instance."
        ),
    )
    def test_delete_retired_key_succeeds(self):
        """7.5.1 — A fully-retired master key (no KEKs remaining) can be deleted. [ROTATION]"""
        # After rotation, the old key should be in 'retired' state.
        # The rotation class test_full_rotation_workflow below sets this up.
        old_name = os.environ.get("HKEY_TEST_RETIRED_MASTERKEY_NAME")
        assert old_name, "Set HKEY_TEST_RETIRED_MASTERKEY_NAME to the name of a retired master key"

        data = _mk_describe_json(old_name)
        assert data["master_key"]["status"] == "retired", (
            f"Key '{old_name}' is not retired (status: {data['master_key']['status']})"
        )

        result = hkey.run("masterkey", "delete", "--name", old_name)
        assert result.returncode == 0, f"Expected delete of retired key to succeed: {result.stderr}"


# ---------------------------------------------------------------------------
# 7.6 — Master Key Rotation (Rewrap KEKs)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not os.environ.get("HKEY_TEST_MASTERKEY_ROTATION"),
    reason=(
        "Master key rotation permanently changes the active key. "
        "Set HKEY_TEST_MASTERKEY_ROTATION=1 to run on a disposable test instance. "
        "WARNING: after this class runs, the active master key will NO LONGER be 'root'."
    ),
)
class TestMasterKeyRotation:
    """
    Full rotation workflow: create new key → activate → rewrap KEKs → retire old.

    These tests are designed to run in sequence (pytest collects them in definition
    order within the class).  They share state via the environment:
      HKEY_TEST_ROTATION_NEW_KEY_NAME  — set by test_create_and_activate_new_key
      HKEY_TEST_ROTATION_OLD_KEY_NAME  — name of the key that becomes draining
    """

    def test_rewrap_all_keks_with_new_masterkey(self):
        """7.6.1 — After activation, rewrap-keks migrates all KEKs to the new master key."""
        ns = "/mk-rot-ns"
        helpers.create_namespace(ns)
        helpers.create_secret(f"{ns}:s1", "val1")
        helpers.create_secret(f"{ns}:s2", "val2")

        new_name = _uid("mk-new")
        # Create + activate new key
        hkey.run(
            "masterkey", "create",
            "--name", new_name,
            "--usage", "wrap_kek",
            "--provider", "insecure",
        )
        result = hkey.run("masterkey", "activate", "--name", new_name)
        assert result.returncode == 0, f"activate failed: {result.stderr}"

        # Store for use in subsequent tests
        os.environ["HKEY_TEST_ROTATION_NEW_KEY_NAME"] = new_name

        # Find the now-draining key (should be root or whatever was active before)
        from hkey import run as hrun
        status_result = hrun("masterkey", "status", "--json")
        assert status_result.returncode == 0
        status_data = json.loads(status_result.stdout)
        draining = next(
            (e["master_key"]["name"] for e in status_data["entries"]
             if e["master_key"]["status"] == "draining"),
            None,
        )
        assert draining, "Expected a draining key after activating new master key"
        os.environ["HKEY_TEST_ROTATION_OLD_KEY_NAME"] = draining

        # Rewrap all KEKs from draining → new active
        result = hkey.run("rewrap", "kek", "--from", draining)
        assert result.returncode == 0, f"rewrap kek failed: {result.stderr}"

    def test_secrets_still_revealable_after_rewrap(self):
        """7.6.2 — All secrets are still revealable after KEKs are rewrapped."""
        ns = "/mk-rot-ns"
        result = hkey.run("secret", "reveal", "--ref", f"{ns}:s1")
        assert result.returncode == 0, f"reveal s1 failed: {result.stderr}"
        assert "val1" in result.stdout

        result = hkey.run("secret", "reveal", "--ref", f"{ns}:s2")
        assert result.returncode == 0, f"reveal s2 failed: {result.stderr}"
        assert "val2" in result.stdout

    def test_old_key_retired_after_rewrap(self):
        """7.6.3 — The old master key enters retired state once all its KEKs are rewrapped."""
        old_name = os.environ.get("HKEY_TEST_ROTATION_OLD_KEY_NAME")
        assert old_name, "HKEY_TEST_ROTATION_OLD_KEY_NAME not set — run test_rewrap first"

        data = _mk_describe_json(old_name)
        assert data["master_key"]["status"] == "retired", (
            f"Expected '{old_name}' to be retired after rewrap, got: {data['master_key']['status']}"
        )
        # Expose the retired key name for the delete test
        os.environ["HKEY_TEST_RETIRED_MASTERKEY_NAME"] = old_name

    def test_full_rotation_workflow_new_key_is_active(self):
        """7.6.4 — After the full rotation, the new master key is the active one."""
        new_name = os.environ.get("HKEY_TEST_ROTATION_NEW_KEY_NAME")
        assert new_name, "HKEY_TEST_ROTATION_NEW_KEY_NAME not set — run test_rewrap first"

        data = _mk_describe_json(new_name)
        assert data["master_key"]["status"] == "active", (
            f"Expected '{new_name}' to be active, got: {data['master_key']['status']}"
        )
        assert data["keyring"]["locked"] is False
