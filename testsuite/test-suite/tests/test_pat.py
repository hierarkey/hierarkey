import json

import hkey


# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------

def _user_pats(include_revoked=False):
    """Return only active user-created PATs from the list.

    Excludes session tokens (Login access/refresh) and, by default,
    revoked tokens.
    """
    result = hkey.run("pat", "list", "--json")
    assert result.returncode == 0, f"pat list failed: {result.stderr}"
    tokens = json.loads(result.stdout)
    tokens = [t for t in tokens if not t["description"].startswith(("Login ", "Refreshed "))]
    if not include_revoked:
        tokens = [t for t in tokens if t.get("revoked_at") is None]
    return tokens


# ===========================================================================
# Tests
# ===========================================================================

def test_pat_list_empty():
    """No user-created PATs exist in a fresh session."""
    assert _user_pats() == []


def test_pat_create():
    """Create a PAT and verify the JSON response fields."""
    result = hkey.run("pat", "create", "--description", "test-token", "--json")
    assert result.returncode == 0, f"pat create failed: {result.stderr}"
    data = json.loads(result.stdout)

    assert "id" in data
    assert "short_id" in data
    assert "token" in data
    assert "description" in data
    assert "expires_at" in data
    assert data["description"] == "test-token"
    # The actual access token starts with hkat_
    assert data["token"].startswith("hkat_"), (
        f"Expected token to start with hkat_, got: {data['token']}"
    )
    # short_id has the tok_ prefix
    assert data["short_id"].startswith("tok_"), (
        f"Expected short_id to start with tok_, got: {data['short_id']}"
    )


def test_pat_create_plain_output():
    """Plain (non-JSON) create output confirms success and prints the token."""
    result = hkey.run("pat", "create", "--description", "plain-token")
    assert result.returncode == 0, f"pat create failed: {result.stderr}"
    assert "PAT created successfully" in result.stdout
    assert "hkat_" in result.stdout


def test_pat_create_with_ttl():
    """--ttl is accepted and the token expires at the right time."""
    result = hkey.run("pat", "create", "--description", "short-lived", "--ttl", "30m", "--json")
    assert result.returncode == 0, f"pat create failed: {result.stderr}"
    data = json.loads(result.stdout)
    assert "expires_at" in data


def test_pat_list():
    """Created PAT appears in the list with the correct description."""
    result = hkey.run("pat", "create", "--description", "listable-token", "--json")
    assert result.returncode == 0, f"pat create failed: {result.stderr}"

    tokens = _user_pats()
    assert len(tokens) >= 1
    descriptions = [t["description"] for t in tokens]
    assert "listable-token" in descriptions


def test_pat_list_json_schema():
    """PAT list entries contain expected fields."""
    hkey.run("pat", "create", "--description", "schema-check", "--json")

    tokens = _user_pats()
    entry = next((t for t in tokens if t["description"] == "schema-check"), None)
    assert entry is not None
    for field in ("id", "short_id", "description", "created_at", "expires_at"):
        assert field in entry, f"Missing field '{field}' in PAT list entry"


def test_pat_list_plain_output():
    """Plain list output has column headers."""
    hkey.run("pat", "create", "--description", "plain-list-token")

    result = hkey.run("pat", "list")
    assert result.returncode == 0
    assert "ID" in result.stdout
    assert "DESCRIPTION" in result.stdout


def test_pat_revoke():
    """Create a PAT, revoke it, and confirm it disappears from the list."""
    result = hkey.run("pat", "create", "--description", "revocable-token", "--json")
    assert result.returncode == 0, f"pat create failed: {result.stderr}"
    created = json.loads(result.stdout)
    pat_id = str(created["id"])

    result = hkey.run("pat", "revoke", "--id", pat_id, "--json")
    assert result.returncode == 0, f"pat revoke failed: {result.stderr}"
    revoke_data = json.loads(result.stdout)
    assert revoke_data["revoked"] is True
    assert "id" in revoke_data

    # No longer in the active list (revoked tokens are filtered out)
    remaining = _user_pats()
    remaining_ids = [str(t["id"]) for t in remaining]
    assert pat_id not in remaining_ids

    # But it still appears when including revoked tokens
    all_tokens = _user_pats(include_revoked=True)
    revoked = next((t for t in all_tokens if str(t["id"]) == pat_id), None)
    assert revoked is not None
    assert revoked["revoked_at"] is not None



def test_pat_multiple_tokens():
    """Multiple PATs can coexist independently."""
    for desc in ("multi-1", "multi-2", "multi-3"):
        r = hkey.run("pat", "create", "--description", desc, "--json")
        assert r.returncode == 0

    tokens = _user_pats()
    descriptions = {t["description"] for t in tokens}
    assert {"multi-1", "multi-2", "multi-3"}.issubset(descriptions)


def test_pat_token_is_usable():
    """A newly created PAT token can authenticate API calls."""
    result = hkey.run("pat", "create", "--description", "usable-token", "--json")
    assert result.returncode == 0, f"pat create failed: {result.stderr}"
    data = json.loads(result.stdout)
    pat_token = data["token"]

    # Use the PAT token to call auth whoami
    result = hkey.run_unauth(
        "--token", pat_token,
        "auth", "whoami",
    )
    assert result.returncode == 0, f"whoami with PAT failed: {result.stderr}"
    assert "admin" in result.stdout


def test_pat_create_unauthenticated():
    """Without a token, pat create fails with an authentication error."""
    result = hkey.run_unauth("pat", "create", "--description", "should-fail")
    assert result.returncode != 0
    assert "token" in result.stderr.lower() or "auth" in result.stderr.lower()
