# tests/test_auth_adv.py
#
# Tests for sections 2.5–2.8 of the test plan.
#
#   2.5  Service Account — Ed25519 Key Signature (missing cases)
#   2.6  mTLS Authentication (Community Edition behaviour)
#   2.7  Brute Force Protection (missing cases)
#   2.8  MFA (Enterprise Edition — skipped in CE)
#
# Existing keysig coverage lives in test_auth_full.py (2.5.1–2.5.3).
# This file only adds what is missing there.

import base64
import json
import os
import tempfile
import time
import uuid

import pytest
import requests

import hkey


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def server_url():
    return os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")


def _sa_token_url():
    return f"{server_url()}/v1/auth/service-account/token"


def _auth_audience():
    """Audience used by the CLI when constructing keysig messages."""
    return os.environ.get("HKEY_TEST_AUTH_AUDIENCE", "hierarkey-server")


def _unique_name(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _create_sa_ed25519(name):
    """Create an SA with ed25519 auth; return the PEM private key string."""
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
    assert result.returncode == 0, f"Failed to create ed25519 SA {name}: {result.stderr}"
    data = json.loads(result.stdout)
    priv_key = data.get("private_key")
    assert priv_key is not None, "No private_key in response"
    return priv_key


def _sign_keysig_payload(pem_priv_key, account_name, nonce=None, ts=None):
    """
    Build a complete /v1/auth/service-account/token payload signed with
    the given Ed25519 private key.

    Use nonce/ts overrides to inject invalid values for negative tests.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    if nonce is None:
        nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    if ts is None:
        ts = int(time.time())

    private_key = load_pem_private_key(pem_priv_key.encode(), password=None)

    audience = _auth_audience()
    msg = (
        f"hierarkey.sa_auth.v1|purpose:auth_token|method:POST"
        f"|audience:{audience}|account:{account_name}|ts:{ts}|nonce:{nonce}"
    )
    sig_bytes = private_key.sign(msg.encode())
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

    return {
        "auth": {
            "method": "key_sig",
            "account_name": account_name,
            "key_id": "default",
            "alg": "Ed25519",
            "nonce": nonce,
            "ts": ts,
            "sig": sig_b64,
        }
    }


# ---------------------------------------------------------------------------
# 2.5 Service Account — Ed25519 Key Signature — missing cases
# ---------------------------------------------------------------------------

class TestSaKeySig:

    def test_nonce_too_short_returns_400(self):
        """2.5.4 — A nonce shorter than 32 characters is rejected before signature check."""
        name = _unique_name("sa-ks-short-nonce")
        priv_key = _create_sa_ed25519(name)

        # Sign with a valid key but a nonce that is only 8 chars long
        payload = _sign_keysig_payload(priv_key, name, nonce="short123")
        r = requests.post(_sa_token_url(), json=payload)
        assert r.status_code == 400, (
            f"Expected 400 for nonce < 32 chars, got {r.status_code}: {r.text}"
        )

    def test_timestamp_outside_window_returns_400(self):
        """2.5.5 — A timestamp outside ±60 s of server time is rejected."""
        name = _unique_name("sa-ks-old-ts")
        priv_key = _create_sa_ed25519(name)

        # ts = 1 is the Unix epoch: guaranteed to be outside the ±60-second window
        payload = _sign_keysig_payload(priv_key, name, ts=1)
        r = requests.post(_sa_token_url(), json=payload)
        assert r.status_code == 400, (
            f"Expected 400 for stale timestamp, got {r.status_code}: {r.text}"
        )

    def test_replayed_nonce_returns_400(self):
        """2.5.6 — Submitting the same signed request twice is rejected on the second attempt."""
        name = _unique_name("sa-ks-replay")
        priv_key = _create_sa_ed25519(name)

        nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        payload = _sign_keysig_payload(priv_key, name, nonce=nonce)

        r1 = requests.post(_sa_token_url(), json=payload)
        assert r1.status_code == 200, (
            f"First keysig request should succeed, got {r1.status_code}: {r1.text}"
        )

        r2 = requests.post(_sa_token_url(), json=payload)
        assert r2.status_code == 400, (
            f"Expected 400 for replayed nonce, got {r2.status_code}: {r2.text}"
        )

    def test_locked_sa_returns_401(self):
        """2.5.7 — A temporarily-locked SA cannot obtain a keysig token."""
        name = _unique_name("sa-ks-locked")
        priv_key = _create_sa_ed25519(name)

        # Verify auth works before locking
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(priv_key)
            key_path = f.name
        try:
            result = hkey.run_unauth(
                "auth", "sa", "token",
                "--method", "keysig",
                "--name", name,
                "--private-key", key_path,
            )
            assert result.returncode == 0, f"Initial keysig should succeed: {result.stderr}"

            hkey.run("account", "lock", "--name", name, "--reason", "testing keysig lockout")

            result = hkey.run_unauth(
                "auth", "sa", "token",
                "--method", "keysig",
                "--name", name,
                "--private-key", key_path,
            )
            assert result.returncode != 0, "Expected keysig to fail for locked SA"
        finally:
            os.unlink(key_path)

    def test_disabled_sa_returns_401(self):
        """2.5.8 — A disabled SA cannot obtain a keysig token."""
        name = _unique_name("sa-ks-disabled")
        priv_key = _create_sa_ed25519(name)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(priv_key)
            key_path = f.name
        try:
            hkey.run("account", "disable", "--name", name)

            result = hkey.run_unauth(
                "auth", "sa", "token",
                "--method", "keysig",
                "--name", name,
                "--private-key", key_path,
            )
            assert result.returncode != 0, "Expected keysig to fail for disabled SA"
        finally:
            os.unlink(key_path)

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_SA_ED25519_AUTH_DISABLED"),
        reason=(
            "Requires server started with auth.allow_ed25519_auth = false. "
            "Set HKEY_TEST_SA_ED25519_AUTH_DISABLED=1 to run."
        ),
    )
    def test_ed25519_auth_disabled_by_config_returns_error(self):
        """2.5.9 — Ed25519 auth disabled in server config returns a 403."""
        name = _unique_name("sa-ks-cfg-disabled")
        priv_key = _create_sa_ed25519(name)

        payload = _sign_keysig_payload(priv_key, name)
        r = requests.post(_sa_token_url(), json=payload)
        assert r.status_code == 403, (
            f"Expected 403 when ed25519 auth is disabled, got {r.status_code}: {r.text}"
        )

    def test_failed_keysig_increments_counter_and_triggers_lockout(self):
        """2.5.10 + 2.5.11 — Repeated keysig failures with a wrong key lock the account.

        This test makes max_failed_login_attempts (default 10) bad attempts
        with a different SA's private key, then verifies the account is
        temporarily locked (correct key also fails).
        """
        name = _unique_name("sa-ks-bf")
        priv_key = _create_sa_ed25519(name)

        # Create a second SA whose key we'll mis-use as the "wrong" key
        other_name = _unique_name("sa-ks-bf-other")
        wrong_key = _create_sa_ed25519(other_name)

        max_attempts = int(os.environ.get("HKEY_TEST_MAX_FAILED_ATTEMPTS", "10"))

        # Make max_attempts bad requests (signed with the wrong key)
        for i in range(max_attempts):
            payload = _sign_keysig_payload(wrong_key, name)
            r = requests.post(_sa_token_url(), json=payload)
            # Each attempt returns 400 (bad signature) until lockout kicks in
            assert r.status_code in (400, 401), (
                f"Attempt {i+1}: unexpected status {r.status_code}: {r.text}"
            )

        # Now try with the CORRECT key — should also be rejected due to lockout
        payload = _sign_keysig_payload(priv_key, name)
        r = requests.post(_sa_token_url(), json=payload)
        assert r.status_code == 401, (
            f"Expected 401 (account locked) after {max_attempts} failed attempts; "
            f"got {r.status_code}: {r.text}"
        )


# ---------------------------------------------------------------------------
# 2.6 mTLS Authentication — Community Edition behaviour
# ---------------------------------------------------------------------------

class TestMtls:

    def test_mtls_returns_not_implemented_in_ce(self):
        """2.6.1 — The mTLS method returns 501 in Community Edition."""
        payload = {"auth": {"method": "mtls"}}
        r = requests.post(_sa_token_url(), json=payload)
        assert r.status_code == 501, (
            f"Expected 501 (Not Implemented) for mTLS in CE, got {r.status_code}: {r.text}"
        )

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_EE"),
        reason="mTLS auth is only available in Hierarkey EE. Set HKEY_TEST_EE=1 to run.",
    )
    def test_valid_client_certificate_authenticates_account(self):
        """2.6.2 — A client certificate registered to an account grants a token. `[EE]`"""
        # EE-specific: requires a TLS-terminating proxy that injects X-Client-Cert,
        # plus an account with a registered certificate fingerprint.
        pytest.skip("EE test: mTLS setup not yet implemented in test suite")

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_EE"),
        reason="mTLS auth is only available in Hierarkey EE. Set HKEY_TEST_EE=1 to run.",
    )
    def test_certificate_not_registered_returns_401(self):
        """2.6.3 — A certificate that is not registered to any account returns 401. `[EE]`"""
        pytest.skip("EE test: mTLS setup not yet implemented in test suite")

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_EE"),
        reason="mTLS auth is only available in Hierarkey EE. Set HKEY_TEST_EE=1 to run.",
    )
    def test_revoked_or_expired_certificate_returns_401(self):
        """2.6.4 — A revoked or expired certificate returns 401. `[EE]`"""
        pytest.skip("EE test: mTLS setup not yet implemented in test suite")


# ---------------------------------------------------------------------------
# 2.7 Brute Force Protection — missing cases
# ---------------------------------------------------------------------------

class TestBruteForce:

    def test_n_consecutive_failed_logins_locks_account(self):
        """2.7.1 — N consecutive wrong-password logins trigger a temporary lockout."""
        name = _unique_name("bf-user")
        password = "SecurePassword1!"

        # Create user
        result = hkey.run(
            "account", "create",
            "--type", "user",
            "--name", name,
            "--insecure-password", password,
            "--activate",
        )
        assert result.returncode == 0, f"Failed to create user: {result.stderr}"

        max_attempts = int(os.environ.get("HKEY_TEST_MAX_FAILED_ATTEMPTS", "10"))

        for _ in range(max_attempts):
            hkey.run_unauth(
                "auth", "login",
                "--name", name,
                "--insecure-password", "WrongPassword999!",
            )

        # Correct password must now also be rejected (account is locked)
        result = hkey.run_unauth(
            "auth", "login",
            "--name", name,
            "--insecure-password", password,
        )
        assert result.returncode != 0, (
            f"Expected login to fail after {max_attempts} wrong attempts (account should be locked)"
        )

    @pytest.mark.xfail(
        reason=(
            "Requires waiting for the lockout duration to elapse. "
            "Not practical in standard CI (default: 15 minutes)."
        )
    )
    def test_lockout_expires_and_account_unlocks_automatically(self):
        """2.7.3 — Temporary lockout expires and the account unlocks without admin action."""
        # This test requires a server configured with a very short lockout_duration_minutes
        # (e.g. 1 second) and cannot be run in standard CI without that config.
        raise AssertionError("Not implemented: requires short-duration lockout config")

    def test_counter_resets_after_successful_login(self):
        """2.7.5 — Successful login resets the failed-attempt counter.

        Already covered by TestUserLogin.test_successful_login_clears_failed_attempt_counter
        in test_auth_gaps.py; this case is listed here for cross-reference completeness.
        Cross-ref: test_auth_gaps.py::TestUserLogin::test_successful_login_clears_failed_attempt_counter
        """
        pytest.skip("Already covered in test_auth_gaps.py — see cross-ref in docstring")


# ---------------------------------------------------------------------------
# 2.8 MFA — Enterprise Edition only
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not os.environ.get("HKEY_TEST_EE"),
    reason=(
        "MFA is only available in the Hierarkey Enterprise Edition. "
        "Set HKEY_TEST_EE=1 to run these tests against an EE server."
    ),
)
class TestMfa:

    def test_mfa_enabled_login_returns_mfa_required(self):
        """2.8.1 — Login with MFA-enabled account returns mfa_required: true."""
        # EE-specific; implementation depends on EE account management API
        pytest.skip("EE test: MFA account setup not yet implemented in test suite")

    def test_mfa_valid_totp_code_succeeds(self):
        """2.8.2 — Verify MFA challenge with a valid TOTP code succeeds."""
        pytest.skip("EE test: requires MFA-enabled account and TOTP library")

    def test_mfa_invalid_code_returns_401(self):
        """2.8.3 — Verify MFA challenge with an invalid code returns 401."""
        pytest.skip("EE test: requires MFA-enabled account")

    def test_mfa_token_grants_full_access(self):
        """2.8.4 — A token obtained after MFA verification grants normal access."""
        pytest.skip("EE test: requires full MFA flow")
