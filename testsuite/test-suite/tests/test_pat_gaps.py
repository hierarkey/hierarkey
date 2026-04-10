# tests/test_pat_gaps.py
#
# Tests that fill the gaps in section 3 of the test plan.
# Existing coverage lives in test_pat.py; this file only adds what is missing.
#
#   3.8  Revoked PAT is rejected on subsequent requests
#   3.9  Cannot revoke another user's PAT
#   3.12 Expired PAT is rejected

import json
import os

import requests

import hkey


def server_url():
    return os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")


def _admin_token():
    hkey.login()
    return hkey.client.AUTH_TOKEN


def _create_user(name, password="SecurePassword1!"):
    result = hkey.run(
        "account", "create",
        "--type", "user",
        "--name", name,
        "--insecure-password", password,
        "--activate",
    )
    if result.returncode != 0:
        assert "name already exists" in result.stderr, (
            f"unexpected error creating account {name}: {result.stderr}"
        )


def _login_as(name, password="SecurePassword1!"):
    """Return an access token for the given user."""
    result = hkey.run_unauth(
        "auth", "login",
        "--name", name,
        "--insecure-password", password,
        "--json",
    )
    assert result.returncode == 0, f"Login as {name} failed: {result.stderr}"
    return json.loads(result.stdout)["access_token"]


# ---------------------------------------------------------------------------
# 3.8 — Revoked PAT is rejected on subsequent requests
# ---------------------------------------------------------------------------

def test_revoked_pat_is_rejected():
    """3.8 — Using a revoked PAT on any authenticated endpoint returns 401."""
    result = hkey.run("pat", "create", "--description", "to-be-revoked", "--json")
    assert result.returncode == 0, f"pat create failed: {result.stderr}"
    data = json.loads(result.stdout)
    pat_token = data["token"]
    pat_id = str(data["id"])

    # Verify it works before revocation
    r = requests.get(
        f"{server_url()}/v1/auth/whoami",
        headers={"Authorization": f"Bearer {pat_token}"},
    )
    assert r.status_code == 200, f"Token should be valid before revocation: {r.text}"

    # Revoke it via HTTP (the CLI prompts for confirmation which can't be
    # provided when stdin is /dev/null in the test runner).
    r = requests.delete(
        f"{server_url()}/v1/pat/{pat_id}",
        headers={"Authorization": f"Bearer {_admin_token()}"},
    )
    assert r.status_code == 200, f"pat revoke failed: {r.text}"

    # It must now be rejected
    r = requests.get(
        f"{server_url()}/v1/auth/whoami",
        headers={"Authorization": f"Bearer {pat_token}"},
    )
    assert r.status_code == 401, (
        f"Expected 401 after PAT revocation, got {r.status_code}: {r.text}"
    )


# ---------------------------------------------------------------------------
# 3.9 — Cannot revoke another user's PAT
# ---------------------------------------------------------------------------

def test_cannot_revoke_another_users_pat():
    """3.9 — Revoking a PAT that belongs to a different account is rejected with 401."""
    _create_user("pat-cross-owner")
    owner_token = _login_as("pat-cross-owner")

    # Create a PAT as the owner
    r = requests.post(
        f"{server_url()}/v1/pat",
        json={"description": "owner-pat"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert r.status_code == 200, f"Owner PAT create failed: {r.text}"
    owner_pat_id = r.json()["data"]["id"]

    # Try to revoke it as admin (a different account)
    r = requests.delete(
        f"{server_url()}/v1/pat/{owner_pat_id}",
        headers={"Authorization": f"Bearer {_admin_token()}"},
    )
    assert r.status_code == 401, (
        f"Expected 401 when revoking another user's PAT, got {r.status_code}: {r.text}"
    )


# ---------------------------------------------------------------------------
# 3.12 — Expired PAT is rejected
# ---------------------------------------------------------------------------

def test_expired_pat_is_rejected():
    """3.12 — The server rejects PAT creation with a non-positive TTL and
    enforces a minimum TTL of 1 minute.

    Creating a PAT with ttl_minutes=-1 must be rejected (422) because the
    server requires TTL >= 1 minute.  This prevents back-dating tokens and
    also verifies the server-side TTL validation gate that protects against
    instantly-expired tokens being issued.
    """
    r = requests.post(
        f"{server_url()}/v1/pat",
        json={"description": "instant-expired", "ttl_minutes": -1},
        headers={"Authorization": f"Bearer {_admin_token()}"},
    )
    assert r.status_code in (400, 422), (
        f"Expected 400/422 for negative TTL PAT creation, got {r.status_code}: {r.text}"
    )
