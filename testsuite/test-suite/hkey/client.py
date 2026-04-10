import json
import subprocess
from os import environ

AUTH_TOKEN = None

def logout():
    """Clear cached auth token."""
    global AUTH_TOKEN
    AUTH_TOKEN = None


def run_unauth(*args):
    """Run hkey CLI without authentication token."""
    hkey_bin = environ.get("HKEY_TEST_HKEY_BIN")
    if hkey_bin is None:
        raise RuntimeError("HKEY_TEST_HKEY_BIN is not set")

    hkey_server_url = environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")

    result = subprocess.run(
        [hkey_bin, "--server", hkey_server_url] + list(args),
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    return result


def login():
    """
    Login once and cache the token globally.

    Uses the CLI's JSON output from `auth login` and stores the `token`
    in the AUTH_TOKEN global.
    """
    global AUTH_TOKEN

    if AUTH_TOKEN is not None:
        # Already logged in
        return

    result = run_unauth(
        "auth",
        "login",
        "--name",
        "admin",
        "--insecure-password",
        "admin_test_password",
        "--json",
    )
    assert result.returncode == 0, f"login failed: {result.stdout}\n{result.stderr}"
    data = json.loads(result.stdout)
    token = data.get("access_token")
    assert token is not None, "No access_token in login response"
    assert token.startswith("hkat_"), "Token does not have expected prefix"
    AUTH_TOKEN = token


def run(*args):
    """
    Run hkey CLI with authentication token.

    Automatically logs in (once per process) if needed.
    """
    global AUTH_TOKEN
    if AUTH_TOKEN is None:
        login()

    hkey_bin = environ.get("HKEY_TEST_HKEY_BIN")
    if hkey_bin is None:
        raise RuntimeError("HKEY_TEST_HKEY_BIN is not set")

    hkey_server_url = environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")

    result = subprocess.run(
        [hkey_bin, "--server", hkey_server_url, "--token", AUTH_TOKEN] + list(args),
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    return result


def run_as(token, *args):
    """Run hkey CLI with a specific authentication token."""
    hkey_bin = environ.get("HKEY_TEST_HKEY_BIN")
    if hkey_bin is None:
        raise RuntimeError("HKEY_TEST_HKEY_BIN is not set")

    hkey_server_url = environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")

    result = subprocess.run(
        [hkey_bin, "--server", hkey_server_url, "--token", token] + list(args),
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    return result

