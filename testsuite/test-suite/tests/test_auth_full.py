import json
import os
import tempfile
import uuid

import hkey


# ============================================================
# Helpers
# ============================================================

def _login_admin_json():
    """Return the full JSON body from an admin login."""
    result = hkey.run_unauth(
        "auth", "login",
        "--name", "admin",
        "--insecure-password", "admin_test_password",
        "--json",
    )
    assert result.returncode == 0, f"admin login failed: {result.stderr}"
    return json.loads(result.stdout)


def _create_sa_passphrase(name, passphrase="ServicePassphrase1!"):
    """Create (or reuse) an active service account with passphrase bootstrap."""
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
        # account exists — make sure it's active
        hkey.run("account", "enable", "--name", name)


def _create_sa_ed25519(name):
    """
    Create a fresh service account with ed25519 bootstrap.
    Returns the PEM-encoded private key string.
    The account name must not already exist.
    """
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
    assert result.returncode == 0, f"Failed to create SA {name}: {result.stderr}"
    data = json.loads(result.stdout)
    priv_key = data.get("private_key")
    assert priv_key is not None, "No private_key in service account creation response"
    return priv_key


def _unique_sa_name(prefix):
    """Generate a unique SA name for tests that need a fresh account."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# ============================================================
# SECTION 1 – auth refresh
# ============================================================

def test_auth_refresh_returns_new_tokens():
    """Refreshing a valid refresh token yields a new access+refresh token pair."""
    login_data = _login_admin_json()
    refresh_token = login_data["refresh_token"]

    result = hkey.run_unauth("auth", "refresh", "--refresh-token", refresh_token, "--json")
    assert result.returncode == 0, f"refresh failed: {result.stderr}"
    data = json.loads(result.stdout)

    assert data["access_token"].startswith("hkat_")
    assert data["refresh_token"].startswith("hkrt_")
    assert "expires_at" in data
    assert "account_name" in data
    assert data["account_name"] == "admin"


def test_auth_refresh_new_token_is_usable():
    """Token obtained via refresh can authenticate subsequent requests."""
    login_data = _login_admin_json()
    refresh_token = login_data["refresh_token"]

    result = hkey.run_unauth("auth", "refresh", "--refresh-token", refresh_token, "--json")
    assert result.returncode == 0
    new_access_token = json.loads(result.stdout)["access_token"]

    result = hkey.run_as(new_access_token, "auth", "whoami")
    assert result.returncode == 0, f"whoami with refreshed token failed: {result.stderr}"
    assert "admin" in result.stdout


def test_auth_refresh_human_readable_output():
    """Non-JSON refresh output contains expected labels and token prefixes."""
    login_data = _login_admin_json()
    refresh_token = login_data["refresh_token"]

    result = hkey.run_unauth("auth", "refresh", "--refresh-token", refresh_token)
    assert result.returncode == 0, f"refresh failed: {result.stderr}"
    out = result.stdout

    assert "admin" in out
    assert "hkat_" in out
    assert "hkrt_" in out


def test_auth_refresh_invalid_token_fails():
    """An invalid refresh token is rejected by the server."""
    result = hkey.run_unauth("auth", "refresh", "--refresh-token", "hkrt_bogus_invalid_000")
    assert result.returncode != 0


def test_auth_refresh_access_token_not_accepted_as_refresh():
    """Passing an access token (hkat_) where a refresh token is expected is rejected."""
    login_data = _login_admin_json()
    access_token = login_data["access_token"]

    result = hkey.run_unauth("auth", "refresh", "--refresh-token", access_token)
    assert result.returncode != 0


# ============================================================
# SECTION 2 – auth sa token --method passphrase
# ============================================================

def test_sa_token_passphrase_json_fields():
    """sa token (passphrase) returns all expected JSON fields."""
    _create_sa_passphrase("sa-pass-fields")

    result = hkey.run_unauth(
        "auth", "sa", "token",
        "--method", "passphrase",
        "--name", "sa-pass-fields",
        "--passphrase", "ServicePassphrase1!",
    )
    assert result.returncode == 0, f"sa token failed: {result.stderr}"
    data = json.loads(result.stdout)

    assert data["access_token"].startswith("hkat_")
    assert "expires_at" in data
    assert "account_name" in data
    assert data["account_name"] == "sa-pass-fields"
    # SA tokens do not carry a refresh token (service accounts re-authenticate directly)
    assert data.get("refresh_token", "") == ""


def test_sa_token_passphrase_token_is_usable():
    """Token from passphrase SA auth can authenticate subsequent requests."""
    _create_sa_passphrase("sa-pass-usable")

    result = hkey.run_unauth(
        "auth", "sa", "token",
        "--method", "passphrase",
        "--name", "sa-pass-usable",
        "--passphrase", "ServicePassphrase1!",
    )
    assert result.returncode == 0
    access_token = json.loads(result.stdout)["access_token"]

    result = hkey.run_as(access_token, "auth", "whoami")
    assert result.returncode == 0, f"whoami with SA token failed: {result.stderr}"
    assert "sa-pass-usable" in result.stdout


def test_sa_token_passphrase_format_env():
    """--format env emits shell-exportable variable assignments."""
    _create_sa_passphrase("sa-pass-env")

    result = hkey.run_unauth(
        "auth", "sa", "token",
        "--method", "passphrase",
        "--name", "sa-pass-env",
        "--passphrase", "ServicePassphrase1!",
        "--format", "env",
    )
    assert result.returncode == 0, f"sa token --format env failed: {result.stderr}"
    out = result.stdout
    assert "export HKEY_ACCESS_TOKEN=hkat_" in out
    assert "export HKEY_EXPIRES_AT=" in out
    # HKEY_REFRESH_TOKEN is present but empty for SA tokens (no refresh token issued)
    assert "HKEY_REFRESH_TOKEN" in out


def test_sa_token_passphrase_print_access_token():
    """--print access-token outputs only the access_token field."""
    _create_sa_passphrase("sa-pass-print-at")

    result = hkey.run_unauth(
        "auth", "sa", "token",
        "--method", "passphrase",
        "--name", "sa-pass-print-at",
        "--passphrase", "ServicePassphrase1!",
        "--print", "access-token",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "access_token" in data
    assert "refresh_token" not in data
    assert data["access_token"].startswith("hkat_")


def test_sa_token_passphrase_print_refresh_token():
    """--print refresh-token outputs only the refresh_token field (empty for SA tokens)."""
    _create_sa_passphrase("sa-pass-print-rt")

    result = hkey.run_unauth(
        "auth", "sa", "token",
        "--method", "passphrase",
        "--name", "sa-pass-print-rt",
        "--passphrase", "ServicePassphrase1!",
        "--print", "refresh-token",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "refresh_token" in data
    assert "access_token" not in data


def test_sa_token_passphrase_write_to_file():
    """--write saves the token response to the specified file."""
    _create_sa_passphrase("sa-pass-write")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
        out_path = f.name

    try:
        result = hkey.run_unauth(
            "auth", "sa", "token",
            "--method", "passphrase",
            "--name", "sa-pass-write",
            "--passphrase", "ServicePassphrase1!",
            "--write", out_path,
        )
        assert result.returncode == 0, f"sa token --write failed: {result.stderr}"
        assert result.stdout.strip() == "", "stdout should be empty when --write is used"

        with open(out_path) as fh:
            data = json.loads(fh.read())
        assert data["access_token"].startswith("hkat_")
    finally:
        os.unlink(out_path)


def test_sa_token_passphrase_wrong_passphrase_fails():
    """Wrong passphrase is rejected."""
    _create_sa_passphrase("sa-pass-wrong")

    result = hkey.run_unauth(
        "auth", "sa", "token",
        "--method", "passphrase",
        "--name", "sa-pass-wrong",
        "--passphrase", "CompletelyWrongPassphrase999!",
    )
    assert result.returncode != 0


def test_sa_token_passphrase_inactive_account_fails():
    """Inactive (disabled) service account cannot obtain a token."""
    _create_sa_passphrase("sa-pass-inactive")
    hkey.run("account", "disable", "--name", "sa-pass-inactive")

    result = hkey.run_unauth(
        "auth", "sa", "token",
        "--method", "passphrase",
        "--name", "sa-pass-inactive",
        "--passphrase", "ServicePassphrase1!",
    )
    assert result.returncode != 0


# ============================================================
# SECTION 3 – auth sa token --method keysig
# ============================================================

def test_sa_token_keysig_json_fields():
    """sa token (keysig) returns all expected JSON fields."""
    name = _unique_sa_name("sa-keysig-fields")
    priv_key = _create_sa_ed25519(name)

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
        assert result.returncode == 0, f"keysig token failed: {result.stderr}"
        data = json.loads(result.stdout)

        assert data["access_token"].startswith("hkat_")
        assert "expires_at" in data
        assert data["account_name"] == name
        # SA tokens do not carry a refresh token
        assert data.get("refresh_token", "") == ""
    finally:
        os.unlink(key_path)


def test_sa_token_keysig_token_is_usable():
    """Token from keysig SA auth can authenticate subsequent requests."""
    name = _unique_sa_name("sa-keysig-use")
    priv_key = _create_sa_ed25519(name)

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
        assert result.returncode == 0
        token = json.loads(result.stdout)["access_token"]

        result = hkey.run_as(token, "auth", "whoami")
        assert result.returncode == 0, f"whoami with keysig token failed: {result.stderr}"
        assert name in result.stdout
    finally:
        os.unlink(key_path)


def test_sa_token_keysig_wrong_key_fails():
    """Signing with a key that doesn't match the registered public key is rejected."""
    name = _unique_sa_name("sa-keysig-badkey")
    _create_sa_ed25519(name)  # creates account; discard private key

    # Use a freshly-generated private key that was never registered
    other_name = _unique_sa_name("sa-keysig-other")
    wrong_priv_key = _create_sa_ed25519(other_name)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        f.write(wrong_priv_key)
        key_path = f.name
    try:
        result = hkey.run_unauth(
            "auth", "sa", "token",
            "--method", "keysig",
            "--name", name,
            "--private-key", key_path,
        )
        assert result.returncode != 0
    finally:
        os.unlink(key_path)


def test_sa_token_keysig_nonexistent_key_file_fails():
    """Pointing --private-key at a missing file is rejected before hitting the server."""
    name = _unique_sa_name("sa-keysig-nofile")
    _create_sa_ed25519(name)

    result = hkey.run_unauth(
        "auth", "sa", "token",
        "--method", "keysig",
        "--name", name,
        "--private-key", "/tmp/this_file_does_not_exist_abc123.pem",
    )
    assert result.returncode != 0
