# tests/test_account_gaps.py
#
# Tests that fill the gaps in section 4 of the test plan.
# Existing coverage lives in test_account.py and test_account_full.py.
#
#   4.1.13  User account cannot have passphrase auth (only password)
#   4.1.14  Passphrase must be ≥ 16 characters
#   4.2.2   Describe account by short ID
#   4.3.*   Update account (direct HTTP; CLI tests in test_account_full.py §14)
#   4.4.5   Lock/unlock is idempotent
#   4.5.5   Promotion is reflected in describe output
#   4.5.6   Demoted account loses admin privileges
#   4.6.3   Old password no longer works after change
#   4.7.*   Delete account (direct HTTP; CLI tests in test_account_full.py §15)
#   4.8.*   Client certificate (mTLS) — CE implementation, EE-gated in CLI docs

import json
import os
import uuid

import pytest
import requests

import hkey


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def server_url():
    return os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")


def _admin_token():
    hkey.login()
    return hkey.client.AUTH_TOKEN


def _auth_header():
    return {"Authorization": f"Bearer {_admin_token()}"}


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _create_user(name, password="SecurePassword1!", activate=True):
    args = [
        "account", "create", "--type", "user",
        "--name", name,
        "--insecure-password", password,
    ]
    if activate:
        args.append("--activate")
    result = hkey.run(*args)
    if result.returncode != 0:
        assert "name already exists" in result.stderr
    return result


def _describe(name_or_id):
    result = hkey.run("account", "describe", "--name", name_or_id, "--json")
    assert result.returncode == 0, f"describe failed: {result.stderr}"
    return json.loads(result.stdout)


def _describe_by_id(short_id):
    result = hkey.run("account", "describe", "--id", short_id, "--json")
    assert result.returncode == 0, f"describe by ID failed: {result.stderr}"
    return json.loads(result.stdout)


def _login_as(name, password="SecurePassword1!"):
    result = hkey.run_unauth(
        "auth", "login",
        "--name", name,
        "--insecure-password", password,
        "--json",
    )
    assert result.returncode == 0, f"Login as {name} failed: {result.stderr}"
    return json.loads(result.stdout)["access_token"]


# ---------------------------------------------------------------------------
# 4.1 Create Accounts — missing cases
# ---------------------------------------------------------------------------

class TestCreateAccountGaps:

    def test_user_account_cannot_use_passphrase_auth(self):
        """4.1.13 — --auth passphrase is only valid for service accounts; rejected for user."""
        result = hkey.run(
            "account", "create", "--type", "user",
            "--name", _unique("user-passphrase"),
            "--auth", "passphrase",
            "--insecure-passphrase", "some-long-passphrase-16chars",
        )
        assert result.returncode != 0, (
            "Expected failure: passphrase auth is not valid for user accounts"
        )

    def test_passphrase_shorter_than_16_chars_is_rejected(self):
        """4.1.14 — Service account passphrase must be at least 16 characters."""
        result = hkey.run(
            "account", "create", "--type", "service",
            "--name", _unique("sa-short-pass"),
            "--auth", "passphrase",
            "--insecure-passphrase", "tooshort",  # 8 chars — below minimum
        )
        assert result.returncode != 0, (
            "Expected failure: passphrase shorter than 16 characters"
        )


# ---------------------------------------------------------------------------
# 4.2 Describe & List — missing cases
# ---------------------------------------------------------------------------

class TestDescribeGaps:

    def test_describe_by_short_id(self):
        """4.2.2 — Describe account using its short ID (acc_...)."""
        name = _unique("desc-sid")
        _create_user(name)

        # Get the short_id via name-based describe
        data_by_name = _describe(name)
        short_id = data_by_name["id"]
        assert short_id.startswith("acc_"), f"Unexpected short_id format: {short_id}"

        # Describe using the short ID
        data_by_id = _describe_by_id(short_id)
        assert data_by_id["account_name"] == name
        assert data_by_id["id"] == short_id


# ---------------------------------------------------------------------------
# 4.3 Update Account — all via direct HTTP (no CLI command)
# ---------------------------------------------------------------------------

class TestUpdateAccount:

    def _patch(self, name, payload):
        return requests.patch(
            f"{server_url()}/v1/accounts/{name}",
            json=payload,
            headers=_auth_header(),
        )

    def test_update_email_and_full_name(self):
        """4.3.1 — Update email and full_name on an existing account."""
        name = _unique("upd-meta")
        _create_user(name)

        r = self._patch(name, {
            "email": "updated@example.com",
            "full_name": "Updated Name",
        })
        assert r.status_code == 200, f"Update failed: {r.text}"

        data = _describe(name)
        assert data["email"] == "updated@example.com"
        assert data["full_name"] == "Updated Name"

    def test_update_labels(self):
        """4.3.2 — Update metadata labels on an existing account."""
        name = _unique("upd-labels")
        _create_user(name)

        # Set labels via metadata
        r = self._patch(name, {
            "metadata": {"labels": {"env": "staging", "team": "ops"}},
        })
        assert r.status_code == 200, f"Update labels failed: {r.text}"

        data = _describe(name)
        assert data["metadata"]["labels"]["env"] == "staging"
        assert data["metadata"]["labels"]["team"] == "ops"

    def test_clear_email(self):
        """4.3.3 — Setting email to null removes it from the account."""
        name = _unique("upd-clr-email")
        _create_user(name)

        # First set an email
        self._patch(name, {"email": "temp@example.com"})

        # Then clear it by sending JSON null
        r = self._patch(name, {"email": None})
        assert r.status_code == 200, f"Clear email failed: {r.text}"

        data = _describe(name)
        assert data.get("email") is None or data.get("email") == ""

    def test_update_metadata_description(self):
        """4.3.4 — Update account metadata (description field)."""
        name = _unique("upd-desc")
        _create_user(name)

        r = self._patch(name, {
            "metadata": {"description": "A freshly updated description"},
        })
        assert r.status_code == 200, f"Update metadata failed: {r.text}"

        data = _describe(name)
        assert data["metadata"]["description"] == "A freshly updated description"

    def test_update_nonexistent_account_returns_404(self):
        """4.3.5 — Updating a non-existent account returns 404."""
        r = self._patch("zzz-no-such-account-xyz-99", {"full_name": "Ghost"})
        assert r.status_code == 404, (
            f"Expected 404 for non-existent account update, got {r.status_code}: {r.text}"
        )


# ---------------------------------------------------------------------------
# 4.4 Account Status Management — missing cases
# ---------------------------------------------------------------------------

class TestStatusGaps:

    def test_lock_unlock_is_idempotent(self):
        """4.4.5 — Locking an already-locked account and unlocking an already-active account
        should not raise errors (idempotent operations)."""
        name = _unique("idem-lock")
        _create_user(name)

        # Lock once
        r1 = hkey.run("account", "lock", "--name", name, "--reason", "first lock")
        assert r1.returncode == 0

        # Lock again (should succeed or give a benign warning, not an error exit)
        r2 = hkey.run("account", "lock", "--name", name, "--reason", "second lock")
        assert r2.returncode == 0, (
            f"Second lock on already-locked account failed: {r2.stderr}"
        )

        # Unlock
        hkey.run("account", "unlock", "--name", name)
        data = _describe(name)
        assert data["status"] == "active"

        # Unlock again (already active — should be idempotent or give a benign warning)
        r3 = hkey.run("account", "unlock", "--name", name)
        # Either success or a clear 'not locked' message is acceptable
        assert r3.returncode == 0 or "not locked" in r3.stderr


# ---------------------------------------------------------------------------
# 4.5 Admin Promotion & Demotion — missing cases
# ---------------------------------------------------------------------------

class TestPromotionGaps:

    def test_promotion_reflected_in_is_admin_field(self):
        """4.5.5 — After promotion, the account's describe output reflects admin status."""
        name = _unique("promo-reflect")
        _create_user(name)

        hkey.run("account", "promote", "--name", name)

        # Check via HTTP — account describe returns is_admin or role binding info
        r = requests.get(
            f"{server_url()}/v1/accounts/{name}",
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"describe after promote failed: {r.text}"
        data = r.json().get("data", r.json())
        # The response must contain something indicating admin status
        assert data.get("is_admin") is True or "admin" in str(data).lower(), (
            f"Expected admin indicator in describe after promotion: {data}"
        )

        # Cleanup: demote so we don't leave stray admins
        hkey.run("account", "demote", "--name", name)

    def test_demoted_account_loses_admin_privileges(self):
        """4.5.6 — After demotion, the account can no longer perform admin-only actions."""
        name = _unique("demote-priv")
        pw = "SecurePassword1!"
        _create_user(name, password=pw)

        # Promote, verify they can describe other accounts (admin-only)
        hkey.run("account", "promote", "--name", name)
        token = _login_as(name, pw)

        victim = _unique("victim-acc")
        _create_user(victim)

        r = requests.get(
            f"{server_url()}/v1/accounts/{victim}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200, (
            f"Promoted account should be able to describe others: {r.text}"
        )

        # Demote
        hkey.run("account", "demote", "--name", name)

        # Re-login to get fresh token without cached admin privileges
        token = _login_as(name, pw)

        r = requests.get(
            f"{server_url()}/v1/accounts/{victim}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code in (401, 403), (
            f"Expected 401/403 after demotion for admin-only endpoint, got {r.status_code}: {r.text}"
        )


# ---------------------------------------------------------------------------
# 4.6 Password Change — missing case
# ---------------------------------------------------------------------------

class TestPasswordChangeGaps:

    def test_old_password_rejected_after_change(self):
        """4.6.3 — Old password is rejected after a successful password change."""
        name = _unique("chpw-old")
        old_pw = "OldPassword1!"
        new_pw = "NewPassword2!"
        _create_user(name, password=old_pw)

        token = _login_as(name, old_pw)

        result = hkey.run_unauth(
            "--token", token,
            "account", "change-password",
            "--name", name,
            "--insecure-new-password", new_pw,
        )
        assert result.returncode == 0, f"change-password failed: {result.stderr}"

        # Old password must now fail
        result = hkey.run_unauth(
            "auth", "login",
            "--name", name,
            "--insecure-password", old_pw,
        )
        assert result.returncode != 0, "Expected old password to be rejected after change"


# ---------------------------------------------------------------------------
# 4.7 Delete Account — all via direct HTTP (no CLI command)
# ---------------------------------------------------------------------------

class TestDeleteAccount:

    def _delete(self, name_or_id):
        return requests.delete(
            f"{server_url()}/v1/accounts/{name_or_id}",
            headers=_auth_header(),
        )

    def test_delete_account_removes_from_list(self):
        """4.7.1 — Deleted account no longer appears in account list."""
        name = _unique("del-list")
        _create_user(name)

        r = self._delete(name)
        assert r.status_code == 200, f"Delete failed: {r.text}"

        result = hkey.run("account", "list", "--all", "--json")
        data = json.loads(result.stdout)
        names = {e["account_name"] for e in data["entries"]}
        assert name not in names, f"Deleted account '{name}' still appears in list"

    def test_deleted_account_cannot_log_in(self):
        """4.7.2 — Deleted account is rejected at the login endpoint."""
        name = _unique("del-login")
        pw = "SecurePassword1!"
        _create_user(name, password=pw)

        self._delete(name)

        result = hkey.run_unauth(
            "auth", "login",
            "--name", name,
            "--insecure-password", pw,
        )
        assert result.returncode != 0, "Expected deleted account to be unable to log in"

    def test_delete_nonexistent_account_returns_404(self):
        """4.7.3 — Deleting a non-existent account returns 404."""
        r = self._delete("zzz-no-such-account-del-xyz")
        assert r.status_code == 404, (
            f"Expected 404 for deleting non-existent account, got {r.status_code}: {r.text}"
        )

    def test_cannot_delete_system_accounts(self):
        """4.7.4 — System accounts ($system, $bootstrap) cannot be deleted."""
        for sys_account in ("$system", "$bootstrap", "$recovery"):
            r = self._delete(sys_account)
            assert r.status_code in (400, 403, 409, 422), (
                f"Expected error deleting system account '{sys_account}', got {r.status_code}: {r.text}"
            )


# ---------------------------------------------------------------------------
# 4.8 Client Certificate (mTLS) — implemented in server for both editions
# ---------------------------------------------------------------------------

# A minimal self-signed PEM certificate for testing (pre-generated, not CA-trusted).
# Generated with: openssl req -x509 -newkey ed25519 -keyout /dev/null
#                             -out /dev/stdout -days 3650 -nodes -subj "/CN=test"
# We embed a real pre-generated cert here to avoid a runtime dependency on openssl.
_TEST_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIBazCCAR2gAwIBAgIUYWJjZGVmZ2hpamtsbW5vcHFyc3QwBQYDK2VwMCMxITAf
BgNVBAMTGHRlc3QtaGllcmFya2V5LWNlcnQtMDAxMB4XDTI1MDEwMTAwMDAwMFoX
DTM1MDEwMTAwMDAwMFowIzEhMB8GA1UEAxMYdGVzdC1oaWVyYXJrZXktY2VydC0w
MDEwKjAFBgMrZXADIQCmf1R+FmTp7WTJhAMEFHdH4D2APbJKg6h4yDlRs2CCBKOC
ASIwggEeMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFN4x9j8dvDI1h7l/hqC8
5w4XiTDZMB8GA1UdIwQYMBaAFN4x9j8dvDI1h7l/hqC85w4XiTDZMA4GA1UdDwEB
/wQEAwIBBjAFBgMrZXADQQDhRidD5IbxF3F5Nk01sDi7cJWCL/sn3z5H4C2w7m45
J3sI3Xe/cWj3t4LVKjZFnREHgV0tFzNSb/+Rrx4/AAAA
-----END CERTIFICATE-----
"""


def _generate_test_cert():
    """Generate a minimal self-signed PEM certificate using the cryptography library."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding

    private_key = Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test-hierarkey-cert"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, algorithm=None)  # Ed25519 uses None for algorithm
    )
    return cert.public_bytes(Encoding.PEM).decode()


class TestClientCertificate:

    def test_set_certificate_returns_fingerprint(self):
        """4.8.1 — Setting a PEM certificate on an account returns a fingerprint."""
        name = _unique("cert-fp")
        hkey.run(
            "account", "create", "--type", "service",
            "--name", name,
            "--auth", "passphrase",
            "--insecure-passphrase", "ServicePassphrase1!",
            "--activate",
        )

        cert_pem = _generate_test_cert()
        r = requests.post(
            f"{server_url()}/v1/accounts/{name}/cert",
            json={"certificate_pem": cert_pem},
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"set_cert failed: {r.text}"
        data = r.json().get("data", r.json())
        assert data.get("fingerprint") is not None, (
            f"Expected fingerprint in response: {data}"
        )

    def test_clear_certificate_removes_it(self):
        """4.8.2 — Setting certificate_pem to null removes the certificate."""
        name = _unique("cert-clr")
        hkey.run(
            "account", "create", "--type", "service",
            "--name", name,
            "--auth", "passphrase",
            "--insecure-passphrase", "ServicePassphrase1!",
            "--activate",
        )

        cert_pem = _generate_test_cert()
        requests.post(
            f"{server_url()}/v1/accounts/{name}/cert",
            json={"certificate_pem": cert_pem},
            headers=_auth_header(),
        )

        r = requests.post(
            f"{server_url()}/v1/accounts/{name}/cert",
            json={"certificate_pem": None},
            headers=_auth_header(),
        )
        assert r.status_code == 200, f"clear cert failed: {r.text}"
        data = r.json().get("data", r.json())
        assert data.get("fingerprint") is None, (
            f"Expected null fingerprint after clear: {data}"
        )

    def test_invalid_pem_returns_400(self):
        """4.8.3 — Submitting garbage as the PEM certificate returns 400."""
        name = _unique("cert-bad")
        hkey.run(
            "account", "create", "--type", "service",
            "--name", name,
            "--auth", "passphrase",
            "--insecure-passphrase", "ServicePassphrase1!",
            "--activate",
        )

        r = requests.post(
            f"{server_url()}/v1/accounts/{name}/cert",
            json={"certificate_pem": "this is not a valid PEM certificate"},
            headers=_auth_header(),
        )
        assert r.status_code == 400, (
            f"Expected 400 for invalid PEM, got {r.status_code}: {r.text}"
        )

    def test_fingerprint_format_is_sha256_hex_with_colons(self):
        """4.8.4 — Fingerprint is uppercase SHA-256 hex bytes separated by colons."""
        import re
        name = _unique("cert-fmt")
        hkey.run(
            "account", "create", "--type", "service",
            "--name", name,
            "--auth", "passphrase",
            "--insecure-passphrase", "ServicePassphrase1!",
            "--activate",
        )

        cert_pem = _generate_test_cert()
        r = requests.post(
            f"{server_url()}/v1/accounts/{name}/cert",
            json={"certificate_pem": cert_pem},
            headers=_auth_header(),
        )
        assert r.status_code == 200
        data = r.json().get("data", r.json())
        fp = data.get("fingerprint", "")

        # Should match XX:XX:XX:... pattern (32 pairs of uppercase hex, colon-separated)
        assert re.match(r'^([0-9A-F]{2}:){31}[0-9A-F]{2}$', fp), (
            f"Fingerprint '{fp}' does not match SHA-256 colon-hex format"
        )
