# tests/test_auth.py
import json

import hkey

def test_auth_whoami_without_login():
    # No token, unauthenticated call — fails locally before hitting the server
    result = hkey.run_unauth("auth", "whoami")
    assert result.returncode != 0
    assert "token" in result.stderr.lower() or "auth" in result.stderr.lower()


def test_auth_login_fail():
    # Wrong username
    result = hkey.run_unauth(
        "auth",
        "login",
        "--name",
        "invalid_user",
        "--insecure-password",
        "wrong_password",
    )
    assert result.returncode == 12

    # Right username, wrong password
    result = hkey.run_unauth(
        "auth",
        "login",
        "--name",
        "admin",
        "--insecure-password",
        "wrong_password",
    )
    assert result.returncode == 12


def test_auth_login_success():
    # Here we *do* use hkey.run, which relies on the global token
    # set up by hkey.login() (via the session fixture).
    result = hkey.run("auth", "whoami")
    assert result.returncode == 0
    assert "admin" in result.stdout
    assert "acc_" in result.stdout
    assert "Hierarkey Administrator" in result.stdout
    assert "tok_" in result.stdout
    assert "Login access token" in result.stdout


def test_auth_login_json_format():
    result = hkey.run_unauth(
        "auth",
        "login",
        "--name",
        "admin",
        "--insecure-password",
        "admin_test_password",
        "--json",
    )
    assert result.returncode == 0

    data = json.loads(result.stdout)
    assert "account_id" in data
    assert "account_short_id" in data
    assert "account_name" in data
    assert "scope" in data
    assert "access_token" in data
    assert "expires_at" in data
    assert "refresh_token" in data
    assert "refresh_expires_at" in data

    access_token = data.get("access_token")
    assert access_token is not None
    assert access_token.startswith("hkat_")

    refresh_token = data.get("refresh_token")
    assert refresh_token.startswith("hkrt_")

    assert refresh_token != access_token