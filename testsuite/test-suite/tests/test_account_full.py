import json
import os
import tempfile

import hkey
import helpers


# ---------------------------------------------------------------------------
# Helpers local to this test file
# ---------------------------------------------------------------------------

def account_describe(name):
    """Return parsed JSON for `hkey account describe --account <name>`."""
    result = hkey.run("account", "describe", "--name", name, "--json")
    assert result.returncode == 0, (
        f"account describe '{name}' failed: {result.stderr}"
    )
    return json.loads(result.stdout.strip())


def account_create_user(name, password="testpassword1234", **kwargs):
    """Create a user account and assert success. Extra kwargs are passed as flags."""
    args = [
        "account", "create", "--type", "user",
        "--name", name,
        "--insecure-password", password,
    ]
    for k, v in kwargs.items():
        flag = "--" + k.replace("_", "-")
        if v is True:
            args.append(flag)
        elif v is not False and v is not None:
            args.extend([flag, str(v)])
    result = hkey.run(*args)
    assert result.returncode == 0, (
        f"account create '{name}' failed: {result.stderr}"
    )
    return result


def login_as(name, password):
    """Login as a user and return the token string."""
    result = hkey.run_unauth(
        "auth", "login",
        "--name", name,
        "--insecure-password", password,
        "--json",
    )
    assert result.returncode == 0, (
        f"login as '{name}' failed: {result.stderr}"
    )
    data = json.loads(result.stdout)
    return data["access_token"]


# ===========================================================================
# 1. Initial state verification
# ===========================================================================

def test_clean_setup():
    """Verify the initial 4 system accounts exist."""
    result = hkey.run("account", "list", "--all", "--json")
    assert result.returncode == 0

    data = json.loads(result.stdout)
    assert data["total"] >= 4

    names = {e["account_name"] for e in data["entries"]}
    assert "admin" in names
    assert "$system" in names
    assert "$bootstrap" in names
    assert "$recovery" in names


# ===========================================================================
# 2. Create user accounts
# ===========================================================================

def test_create_user_minimal():
    """Create a user with minimum flags; default status is disabled."""
    result = hkey.run(
        "account", "create", "--type", "user",
        "--name", "full_u1",
        "--insecure-password", "testpassword1234",
    )
    assert result.returncode == 0
    assert "User account created successfully" in result.stdout

    data = account_describe("full_u1")
    assert data["account_name"] == "full_u1"
    assert data["account_type"] == "user"
    assert data["status"] == "disabled"


def test_create_user_with_activate():
    """--activate flag creates an immediately active account."""
    result = hkey.run(
        "account", "create", "--type", "user",
        "--name", "full_u2",
        "--insecure-password", "testpassword1234",
        "--activate",
    )
    assert result.returncode == 0

    data = account_describe("full_u2")
    assert data["status"] == "active"


def test_create_user_full_metadata():
    """Create a user with all metadata options."""
    result = hkey.run(
        "account", "create", "--type", "user",
        "--name", "full_u3",
        "--insecure-password", "testpassword1234",
        "--activate",
        "--email", "full_u3@example.org",
        "--full-name", "Full User Three",
        "--description", "A test user",
        "--label", "team=backend",
        "--label", "env=test",
    )
    assert result.returncode == 0

    data = account_describe("full_u3")
    assert data["email"] == "full_u3@example.org"
    assert data["full_name"] == "Full User Three"
    assert data["metadata"]["description"] == "A test user"
    assert data["metadata"]["labels"]["team"] == "backend"
    assert data["metadata"]["labels"]["env"] == "test"
    assert data["status"] == "active"
    assert data["must_change_password"] is False


def test_create_user_generate_password():
    """--generate-password returns the password in JSON output."""
    result = hkey.run(
        "account", "create", "--type", "user",
        "--name", "full_u4",
        "--generate-password",
        "--activate",
        "--json",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "generated_secret" in data
    pw = data["generated_secret"]
    assert len(pw) > 8

    # Verify the generated password actually works for login
    login_result = hkey.run_unauth(
        "auth", "login",
        "--name", "full_u4",
        "--insecure-password", pw,
        "--json",
    )
    assert login_result.returncode == 0


def test_create_user_must_change_password():
    """--must-change-password creates a login with change_password scope."""
    result = hkey.run(
        "account", "create", "--type", "user",
        "--name", "full_u5",
        "--generate-password",
        "--must-change-password",
        "--activate",
        "--json",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    initial_pw = data["generated_secret"]

    desc = account_describe("full_u5")
    assert desc["must_change_password"] is True
    assert desc["password_changed_at"] is None

    login_result = hkey.run_unauth(
        "auth", "login",
        "--name", "full_u5",
        "--insecure-password", initial_pw,
        "--json",
    )
    assert login_result.returncode == 0
    login_data = json.loads(login_result.stdout)
    assert login_data["scope"] == "change_password"
    change_token = login_data["access_token"]

    # Change the password using the restricted token
    result = hkey.run_unauth(
        "--token", change_token,
        "account", "change-password",
        "--name", "full_u5",
        "--insecure-new-password", "newsecurepassword9999",
    )
    assert result.returncode == 0

    desc = account_describe("full_u5")
    assert desc["must_change_password"] is False
    assert desc["password_changed_at"] is not None

    # Reuse of the change-password token must fail
    result2 = hkey.run_unauth(
        "--token", change_token,
        "account", "change-password",
        "--name", "full_u5",
        "--insecure-new-password", "anotherpassword9999",
    )
    assert result2.returncode == 12


def test_create_user_rejects_invalid_names():
    """Validate account name rules.

    Validation may be caught at the clap argument-parsing level (exit 2,
    plain error format) or at the server level (exit 12, code=ValidationFailed).
    Either way the command must fail and the expected message must appear on
    stderr.
    """
    invalid = [
        ("aa", "name is too short"),
        ("a" * 65, "name is too long"),
        ("name with spaces", "name contains invalid characters"),
        ("name/with/slash", "name contains invalid characters"),
        ("name..double.dot", "name contains invalid characters"),
        ("name-_mixed", "name contains invalid characters"),
        (".startswithdot", "name contains invalid characters"),
        ("endswithdash-", "name contains invalid characters"),
        ("$systemname", "Cannot create accounts starting with a $"),
    ]
    for name, expected_msg in invalid:
        r = hkey.run(
            "account", "create", "--type", "user",
            "--name", name,
            "--insecure-password", "passwordpassword1234",
        )
        assert r.returncode != 0, f"Expected failure for name '{name}'"
        assert expected_msg in r.stderr, (
            f"Name '{name}': expected '{expected_msg}' in stderr.\n"
            f"  stdout: {r.stdout!r}\n"
            f"  stderr: {r.stderr!r}"
        )


def test_create_user_canonical_name_collision():
    """Account names are case-insensitive; creating a duplicate should fail."""
    r1 = hkey.run(
        "account", "create", "--type", "user",
        "--name", "canon_u1",
        "--insecure-password", "testpassword1234",
    )
    assert r1.returncode == 0

    r2 = hkey.run(
        "account", "create", "--type", "user",
        "--name", "CANON_U1",
        "--insecure-password", "testpassword1234",
    )
    assert r2.returncode == 12
    assert "name already exists" in r2.stderr


# ===========================================================================
# 3. Create service accounts
# ===========================================================================

def test_create_service_with_insecure_passphrase():
    """Create service account using passphrase auth (insecure flag)."""
    result = hkey.run(
        "account", "create", "--type", "service",
        "--name", "svc_u1",
        "--auth", "passphrase",
        "--insecure-passphrase", "my-service-passphrase-long-enough",
        "--description", "A test service account",
        "--label", "team=ops",
    )
    assert result.returncode == 0, result.stderr

    data = account_describe("svc_u1")
    assert data["account_type"] == "service"
    assert data["status"] == "disabled"
    assert data["metadata"]["description"] == "A test service account"
    assert data["metadata"]["labels"]["team"] == "ops"


def test_create_service_with_passphrase_activate():
    """Service account with --activate is immediately active."""
    result = hkey.run(
        "account", "create", "--type", "service",
        "--name", "svc_u2",
        "--auth", "passphrase",
        "--insecure-passphrase", "my-service-passphrase-long-enough",
        "--activate",
    )
    assert result.returncode == 0, result.stderr

    data = account_describe("svc_u2")
    assert data["status"] == "active"


def test_create_service_generate_passphrase_json():
    """--generate-passphrase with --json returns the passphrase."""
    result = hkey.run(
        "account", "create", "--type", "service",
        "--name", "svc_u3",
        "--auth", "passphrase",
        "--generate-passphrase",
        "--activate",
        "--json",
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert "passphrase" in data
    assert len(data["passphrase"]) > 8


def test_create_service_ed25519_generate_keypair():
    """--auth ed25519 --generate-keypair --print-private-key-once works."""
    result = hkey.run(
        "account", "create", "--type", "service",
        "--name", "svc_u4",
        "--auth", "ed25519",
        "--generate-keypair",
        "--print-private-key-once",
        "--activate",
        "--json",
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert "private_key" in data
    assert "BEGIN" in data["private_key"]  # PEM format


def test_create_service_ed25519_out_private_key():
    """--generate-keypair with --out-private-key writes the key to a file."""
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        key_path = f.name

    try:
        result = hkey.run(
            "account", "create", "--type", "service",
            "--name", "svc_u5",
            "--auth", "ed25519",
            "--generate-keypair",
            "--out-private-key", key_path,
            "--activate",
        )
        assert result.returncode == 0, result.stderr

        with open(key_path) as f:
            contents = f.read()
        assert "BEGIN" in contents
    finally:
        try:
            os.unlink(key_path)
        except FileNotFoundError:
            pass


def test_create_service_rejects_system_name():
    """Service accounts cannot have system-reserved names."""
    result = hkey.run(
        "account", "create", "--type", "service",
        "--name", "$service",
        "--auth", "passphrase",
        "--insecure-passphrase", "my-service-passphrase-long-enough",
    )
    assert result.returncode == 12


def test_create_service_rejects_user_flags():
    """User-only flags (--email etc.) are rejected for service accounts."""
    result = hkey.run(
        "account", "create", "--type", "service",
        "--name", "svc_bad1",
        "--auth", "passphrase",
        "--insecure-passphrase", "my-service-passphrase-long-enough",
        "--email", "nope@example.org",
    )
    assert result.returncode != 0


def test_create_service_requires_auth():
    """Service account creation without --auth should fail."""
    result = hkey.run(
        "account", "create", "--type", "service",
        "--name", "svc_bad2",
    )
    assert result.returncode != 0


# ===========================================================================
# 4. list command
# ===========================================================================

def test_list_default_shows_active_users_only():
    """Default list shows only active user accounts."""
    # Create one active, one disabled user
    account_create_user("list_u1", activate=True)
    account_create_user("list_u2")  # disabled by default

    result = hkey.run("account", "list", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)

    names = {e["account_name"] for e in data["entries"]}
    assert "list_u1" in names
    assert "list_u2" not in names  # disabled — excluded by default
    # system/service accounts are excluded by default too
    assert "$system" not in names


def test_list_all_types_and_statuses():
    """--all includes all types and statuses."""
    result = hkey.run("account", "list", "--all", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)

    names = {e["account_name"] for e in data["entries"]}
    assert "$system" in names
    assert "admin" in names


def test_list_filter_by_type_service():
    """--type service returns only service accounts."""
    # --all conflicts with --type; use --type alone (shows active service accounts by default)
    result = hkey.run("account", "list", "--type", "service", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)

    for entry in data["entries"]:
        assert entry["account_type"] == "service"


def test_list_filter_by_status_disabled():
    """--status disabled returns only disabled accounts."""
    account_create_user("list_u3")  # disabled by default

    result = hkey.run("account", "list", "--status", "disabled", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)

    for entry in data["entries"]:
        assert entry["status"] == "disabled"
    names = {e["account_name"] for e in data["entries"]}
    assert "list_u3" in names


def test_list_prefix_filter():
    """--prefix filters account names by prefix."""
    account_create_user("pfx_abc1")
    account_create_user("pfx_abc2")
    account_create_user("pfx_abc3")
    # Enable them so default list includes them
    for n in ["pfx_abc1", "pfx_abc2", "pfx_abc3"]:
        hkey.run("account", "enable", "--name", n)

    result = hkey.run("account", "list", "--prefix", "pfx_abc", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)

    names = {e["account_name"] for e in data["entries"]}
    assert "pfx_abc1" in names
    assert "pfx_abc2" in names
    assert "pfx_abc3" in names
    # other accounts should not appear
    assert "admin" not in names


def test_list_prefix_no_match():
    """--prefix with no matching accounts returns empty result."""
    result = hkey.run("account", "list", "--prefix", "zzz_no_such_prefix_", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["total"] == 0


def test_list_limit_and_offset():
    """--limit and --offset support pagination."""
    # Enable some accounts so they show up in the default active-user list
    for i in range(1, 4):
        name = f"pg_u{i}"
        try:
            account_create_user(name, activate=True)
        except AssertionError:
            pass  # might already exist from a previous run

    result_all = hkey.run("account", "list", "--all", "--json")
    data_all = json.loads(result_all.stdout)
    total = data_all["total"]

    if total < 2:
        return  # not enough accounts to test pagination

    result_p1 = hkey.run("account", "list", "--all", "--limit", "1", "--json")
    data_p1 = json.loads(result_p1.stdout)
    assert len(data_p1["entries"]) == 1

    result_p2 = hkey.run("account", "list", "--all", "--limit", "1", "--offset", "1", "--json")
    data_p2 = json.loads(result_p2.stdout)
    assert len(data_p2["entries"]) == 1

    # The two pages should have different accounts
    assert data_p1["entries"][0]["account_name"] != data_p2["entries"][0]["account_name"]


def test_list_table_output():
    """--table flag produces tabular output."""
    result = hkey.run("account", "list", "--all", "--table")
    assert result.returncode == 0
    # Table output has a markdown-style header separator
    assert "|" in result.stdout


def test_list_plain_output():
    """Default (non-JSON, non-table) output has a header row."""
    result = hkey.run("account", "list", "--all")
    assert result.returncode == 0
    assert "NAME" in result.stdout
    assert "STATUS" in result.stdout


# ===========================================================================
# 5. search command
# ===========================================================================

def test_search_query_matches_name():
    """Free-text -q query matches account name."""
    account_create_user("srch_unique_xyz", activate=True)

    result = hkey.run("account", "search", "-q", "srch_unique_xyz", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["total"] >= 1
    names = [e["account_name"] for e in data["entries"]]
    assert "srch_unique_xyz" in names


def test_search_by_label():
    """--label key=value filters accounts."""
    hkey.run(
        "account", "create", "--type", "user",
        "--name", "srch_lbl1",
        "--insecure-password", "testpassword1234",
        "--activate",
        "--label", "project=alpha",
    )
    hkey.run(
        "account", "create", "--type", "user",
        "--name", "srch_lbl2",
        "--insecure-password", "testpassword1234",
        "--activate",
        "--label", "project=beta",
    )

    result = hkey.run(
        "account", "search",
        "--label", "project=alpha",
        "--all",
        "--json",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    names = [e["account_name"] for e in data["entries"]]
    assert "srch_lbl1" in names
    assert "srch_lbl2" not in names


def test_search_by_has_label():
    """--has-label key matches accounts that have the label key (any value)."""
    hkey.run(
        "account", "create", "--type", "user",
        "--name", "srch_haslbl1",
        "--insecure-password", "testpassword1234",
        "--activate",
        "--label", "owner=alice",
    )
    hkey.run(
        "account", "create", "--type", "user",
        "--name", "srch_nolbl1",
        "--insecure-password", "testpassword1234",
        "--activate",
    )

    result = hkey.run(
        "account", "search",
        "--has-label", "owner",
        "--all",
        "--json",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    names = [e["account_name"] for e in data["entries"]]
    assert "srch_haslbl1" in names
    assert "srch_nolbl1" not in names


def test_search_filter_by_type():
    """--type service only returns service accounts."""
    # --all conflicts with --type; use --type alone (default status filter applies)
    result = hkey.run(
        "account", "search",
        "--type", "service",
        "--json",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    for entry in data["entries"]:
        assert entry["account_type"] == "service"


def test_search_filter_by_status():
    """--status disabled only returns disabled accounts."""
    account_create_user("srch_dis1")  # disabled by default

    # --all overrides --status; use --status without --all to actually filter
    result = hkey.run(
        "account", "search",
        "--status", "disabled",
        "--json",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    for entry in data["entries"]:
        assert entry["status"] == "disabled"
    names = [e["account_name"] for e in data["entries"]]
    assert "srch_dis1" in names


def test_search_sort_desc():
    """--sort-by name --desc returns results in descending name order."""
    result = hkey.run(
        "account", "search",
        "--sort-by", "name",
        "--desc",
        "--all",
        "--json",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    names = [e["account_name"] for e in data["entries"]]
    assert names == sorted(names, reverse=True)


def test_search_sort_asc():
    """--sort-by name (ascending) returns results in ascending name order."""
    result = hkey.run(
        "account", "search",
        "--sort-by", "name",
        "--all",
        "--json",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    names = [e["account_name"] for e in data["entries"]]
    assert names == sorted(names)


def test_search_limit_and_offset():
    """--limit and --offset paginate search results."""
    result_all = hkey.run("account", "search", "--all", "--sort-by", "name", "--json")
    data_all = json.loads(result_all.stdout)
    total = data_all["total"]

    if total < 2:
        return

    r1 = hkey.run("account", "search", "--all", "--sort-by", "name", "--limit", "1", "--json")
    d1 = json.loads(r1.stdout)
    assert len(d1["entries"]) == 1

    r2 = hkey.run("account", "search", "--all", "--sort-by", "name", "--limit", "1", "--offset", "1", "--json")
    d2 = json.loads(r2.stdout)
    assert len(d2["entries"]) == 1

    assert d1["entries"][0]["account_name"] != d2["entries"][0]["account_name"]


def test_search_created_after():
    """--created-after filters out accounts created before the cutoff."""
    result = hkey.run(
        "account", "search",
        "--created-after", "2099-01-01T00:00:00Z",
        "--all",
        "--json",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    # No accounts created in the future
    assert data["total"] == 0


def test_search_created_before():
    """--created-before returns accounts created before the cutoff."""
    result = hkey.run(
        "account", "search",
        "--created-before", "2099-01-01T00:00:00Z",
        "--all",
        "--json",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    # All accounts should be before 2099
    assert data["total"] > 0


# ===========================================================================
# 6. describe command
# ===========================================================================

def test_describe_json_output():
    """describe --json returns structured account data."""
    account_create_user("desc_u1", email="desc_u1@example.org", full_name="Desc One")
    data = account_describe("desc_u1")

    assert data["account_name"] == "desc_u1"
    assert data["email"] == "desc_u1@example.org"
    assert data["full_name"] == "Desc One"
    assert "account_type" in data
    assert "status" in data
    assert "created_at" in data


def test_describe_plain_output():
    """describe without --json prints human-readable output."""
    account_create_user("desc_u2")

    result = hkey.run("account", "describe", "--name", "desc_u2")
    assert result.returncode == 0
    assert "desc_u2" in result.stdout
    assert "Status:" in result.stdout
    assert "Type:" in result.stdout


def test_describe_not_found():
    """Describing a non-existent account returns an error."""
    result = hkey.run("account", "describe", "--name", "nonexistent_xyzzy_12345")
    assert result.returncode == 12


def test_describe_created_by():
    """created_by field is populated with the admin account after creation."""
    account_create_user("desc_u3")
    data = account_describe("desc_u3")

    assert data["created_by"] is not None
    assert data["created_by"]["name"] == "admin"
    assert data["created_by"]["id"].startswith("acc_")


# ===========================================================================
# 7. enable / disable / lock / unlock — status lifecycle
# ===========================================================================

def test_enable_disabled_account():
    """enable transitions an account from disabled to active."""
    account_create_user("lc_u1")  # starts disabled

    result = hkey.run("account", "enable", "--name", "lc_u1")
    assert result.returncode == 0

    data = account_describe("lc_u1")
    assert data["status"] == "active"


def test_disable_active_account():
    """disable transitions an account from active to disabled."""
    account_create_user("lc_u2", activate=True)

    result = hkey.run("account", "disable", "--name", "lc_u2")
    assert result.returncode == 0

    data = account_describe("lc_u2")
    assert data["status"] == "disabled"


def test_lock_active_account():
    """lock transitions an account from active to locked."""
    account_create_user("lc_u3", activate=True)

    result = hkey.run("account", "lock", "--name", "lc_u3", "--reason", "test lock")
    assert result.returncode == 0

    data = account_describe("lc_u3")
    assert data["status"] == "locked"
    assert data["status_reason"] == "test lock"


def test_unlock_locked_account():
    """unlock transitions an account from locked back to active."""
    account_create_user("lc_u4", activate=True)
    hkey.run("account", "lock", "--name", "lc_u4", "--reason", "temp lock")

    result = hkey.run("account", "unlock", "--name", "lc_u4", "--reason", "unlocking now")
    assert result.returncode == 0

    data = account_describe("lc_u4")
    assert data["status"] == "active"
    assert data["status_reason"] == "unlocking now"


def test_status_changed_at_updates():
    """status_changed_at changes with each status transition."""
    account_create_user("lc_u5", activate=True)
    data0 = account_describe("lc_u5")
    t0 = data0["status_changed_at"]

    hkey.run("account", "disable", "--name", "lc_u5")
    data1 = account_describe("lc_u5")
    t1 = data1["status_changed_at"]

    hkey.run("account", "enable", "--name", "lc_u5")
    data2 = account_describe("lc_u5")
    t2 = data2["status_changed_at"]

    assert t1 != t0
    assert t2 != t1


def test_reason_field_is_optional():
    """enable/disable/lock/unlock work without --reason."""
    account_create_user("lc_u6", activate=True)

    r = hkey.run("account", "disable", "--name", "lc_u6")
    assert r.returncode == 0

    r = hkey.run("account", "enable", "--name", "lc_u6")
    assert r.returncode == 0

    r = hkey.run("account", "lock", "--name", "lc_u6")
    assert r.returncode == 0

    r = hkey.run("account", "unlock", "--name", "lc_u6")
    assert r.returncode == 0


def test_cannot_unlock_disabled_account():
    """unlock on a disabled (not locked) account is an error."""
    account_create_user("lc_u7")  # disabled

    result = hkey.run("account", "unlock", "--name", "lc_u7")
    assert result.returncode == 12
    assert "not locked" in result.stderr


def test_enable_locked_account():
    """enable works on a locked account (transitions to active)."""
    account_create_user("lc_u8", activate=True)
    hkey.run("account", "lock", "--name", "lc_u8", "--reason", "test")

    result = hkey.run("account", "enable", "--name", "lc_u8", "--reason", "force re-enable")
    assert result.returncode == 0

    data = account_describe("lc_u8")
    assert data["status"] == "active"


def test_disable_locked_account():
    """disable works on a locked account."""
    account_create_user("lc_u9", activate=True)
    hkey.run("account", "lock", "--name", "lc_u9", "--reason", "test")

    result = hkey.run("account", "disable", "--name", "lc_u9", "--reason", "disabling")
    assert result.returncode == 0

    data = account_describe("lc_u9")
    assert data["status"] == "disabled"


def test_status_changed_by_field():
    """status_changed_by is set to the acting admin after a lock."""
    account_create_user("lc_u10", activate=True)
    hkey.run("account", "lock", "--name", "lc_u10", "--reason", "audit test")

    data = account_describe("lc_u10")
    assert data["status_changed_by"] is not None
    assert data["status_changed_by"]["name"] == "admin"


# ===========================================================================
# 8. Temporary lock (--locked-until)
# ===========================================================================

def test_lock_with_locked_until():
    """lock --locked-until sets a future unlock timestamp."""
    account_create_user("tmp_u1", activate=True)

    result = hkey.run(
        "account", "lock",
        "--name", "tmp_u1",
        "--reason", "temporary lock",
        "--locked-until", "2099-12-31T23:59:59Z",
    )
    assert result.returncode == 0

    data = account_describe("tmp_u1")
    assert data["status"] == "locked"
    # locked_until should be set
    assert data.get("locked_until") is not None


# ===========================================================================
# 9. Self-action protection
# ===========================================================================

def test_cannot_lock_self():
    """An account cannot lock itself."""
    account_create_user("self_u1", activate=True)
    token = login_as("self_u1", "testpassword1234")

    result = hkey.run_unauth(
        "--token", token,
        "account", "lock",
        "--name", "self_u1",
        "--reason", "self-lock attempt",
    )
    assert result.returncode == 12
    assert "Cannot lock your own account" in result.stderr


def test_cannot_disable_self():
    """An account cannot disable itself."""
    account_create_user("self_u2", activate=True)
    token = login_as("self_u2", "testpassword1234")

    result = hkey.run_unauth(
        "--token", token,
        "account", "disable",
        "--name", "self_u2",
        "--reason", "self-disable attempt",
    )
    assert result.returncode == 12
    assert "Cannot disable your own account" in result.stderr


# ===========================================================================
# 10. System account protection
# ===========================================================================

def test_cannot_lock_system_account():
    """System accounts cannot be locked."""
    result = hkey.run("account", "lock", "--name", "$system", "--reason", "test")
    assert result.returncode == 12
    assert "System accounts cannot be locked" in result.stderr


def test_cannot_disable_system_account():
    """System accounts cannot be disabled."""
    result = hkey.run("account", "disable", "--name", "$system", "--reason", "test")
    assert result.returncode == 12
    assert "System accounts cannot be disabled" in result.stderr


def test_lock_nonexistent_account():
    """Locking a non-existent account returns NotFound."""
    result = hkey.run("account", "lock", "--name", "zzz_no_such_account_xyz", "--reason", "test")
    assert result.returncode == 12


# ===========================================================================
# 11. promote / demote
# ===========================================================================

def test_promote_and_demote_user():
    """Promote a user to admin and demote back.

    Note: promote/demote operates via RBAC role bindings — it does NOT change
    account_type (which stays "user"). The server grants/revokes the
    platform:admin role without altering the account_type column.
    """
    account_create_user("promo_u1", activate=True)

    # Before: regular user
    data_before = account_describe("promo_u1")
    assert data_before["account_type"] == "user"

    # Promote
    result = hkey.run("account", "promote", "--name", "promo_u1")
    assert result.returncode == 0
    assert "promoted" in result.stdout

    # account_type stays "user" — promote only grants an RBAC role
    data_promoted = account_describe("promo_u1")
    assert data_promoted["account_type"] == "user"

    # Demote
    result = hkey.run("account", "demote", "--name", "promo_u1")
    assert result.returncode == 0
    assert "demoted" in result.stdout

    data_demoted = account_describe("promo_u1")
    assert data_demoted["account_type"] == "user"


def test_cannot_demote_last_admin():
    """Demoting the last/only admin account should fail."""
    # Check how many admins exist; only proceed if admin is the sole admin
    result = hkey.run("account", "list", "--all", "--json")
    data = json.loads(result.stdout)
    admin_count = sum(1 for e in data["entries"] if e["account_type"] == "admin")

    if admin_count > 1:
        # There are multiple admins — skip this specific scenario
        return

    result = hkey.run("account", "demote", "--name", "admin")
    assert result.returncode == 12


def test_cannot_promote_service_account():
    """Service accounts cannot be promoted to admin."""
    # svc_u1 was created earlier; if not present, create it
    try:
        data = account_describe("svc_prom1")
    except AssertionError:
        hkey.run(
            "account", "create", "--type", "service",
            "--name", "svc_prom1",
            "--auth", "passphrase",
            "--insecure-passphrase", "my-service-passphrase-long-enough",
        )

    result = hkey.run("account", "promote", "--name", "svc_prom1")
    assert result.returncode == 12


def test_promote_nonexistent_account():
    """Promoting a non-existent account returns an error."""
    result = hkey.run("account", "promote", "--name", "zzz_no_such_promo_xyz")
    assert result.returncode == 12


# ===========================================================================
# 12. change-password
# ===========================================================================

def test_change_password_user_changes_own_password():
    """A user can change their own password using their own token."""
    account_create_user("chpw_u1", activate=True)

    # Login as the user to get their own token
    token = login_as("chpw_u1", "testpassword1234")

    result = hkey.run_unauth(
        "--token", token,
        "account", "change-password",
        "--name", "chpw_u1",
        "--insecure-new-password", "newpassword5678",
    )
    assert result.returncode == 0, f"change-password failed: {result.stderr}"
    assert "Password changed successfully" in result.stdout

    # Verify the new password works
    login_result = hkey.run_unauth(
        "auth", "login",
        "--name", "chpw_u1",
        "--insecure-password", "newpassword5678",
        "--json",
    )
    assert login_result.returncode == 0


def test_change_password_admin_cannot_change_another_user():
    """Admin cannot change another user's password (only the user themselves can)."""
    account_create_user("chpw_u1b", activate=True)

    result = hkey.run(
        "account", "change-password",
        "--name", "chpw_u1b",
        "--insecure-new-password", "newpassword5678",
    )
    assert result.returncode == 12
    assert "only change your own password" in result.stderr


def test_change_password_generates_password():
    """--generate-password creates a new password and outputs it."""
    account_create_user("chpw_u2", activate=True)

    # Login as the user to get their own token (only the user can change their password)
    token = login_as("chpw_u2", "testpassword1234")

    result = hkey.run_unauth(
        "--token", token,
        "account", "change-password",
        "--name", "chpw_u2",
        "--generate-password",
        "--json",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "generated_secret" in data
    new_pw = data["generated_secret"]
    assert len(new_pw) > 8

    # New password must work for login
    login_result = hkey.run_unauth(
        "auth", "login",
        "--name", "chpw_u2",
        "--insecure-password", new_pw,
        "--json",
    )
    assert login_result.returncode == 0


# ===========================================================================
# 13. Authentication integration
# ===========================================================================

def test_login_disabled_user_fails():
    """Logging in as a disabled user is rejected."""
    account_create_user("auth_u1")  # disabled

    result = hkey.run_unauth(
        "auth", "login",
        "--name", "auth_u1",
        "--insecure-password", "testpassword1234",
        "--json",
    )
    assert result.returncode == 12
    assert "User disabled" in result.stderr


def test_login_locked_user_fails():
    """Logging in as a locked user is rejected."""
    account_create_user("auth_u2", activate=True)
    hkey.run("account", "lock", "--name", "auth_u2", "--reason", "auth test")

    result = hkey.run_unauth(
        "auth", "login",
        "--name", "auth_u2",
        "--insecure-password", "testpassword1234",
        "--json",
    )
    assert result.returncode == 12
    # Admin-locked accounts return "User disabled" from the auth service
    assert "User disabled" in result.stderr


def test_login_enabled_user_succeeds():
    """A freshly enabled user can log in."""
    account_create_user("auth_u3")
    hkey.run("account", "enable", "--name", "auth_u3")

    result = hkey.run_unauth(
        "auth", "login",
        "--name", "auth_u3",
        "--insecure-password", "testpassword1234",
        "--json",
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["account_name"] == "auth_u3"
    assert data["scope"] == "auth"
    assert data["access_token"].startswith("hkat_")


def test_login_wrong_password_fails():
    """Wrong password yields Unauthorized."""
    account_create_user("auth_u4", activate=True)

    result = hkey.run_unauth(
        "auth", "login",
        "--name", "auth_u4",
        "--insecure-password", "definitely_wrong_password",
        "--json",
    )
    assert result.returncode == 12
    assert "invalid credentials" in result.stderr.lower()


def test_service_account_login_with_ed25519():
    """A service account with ed25519 auth can obtain a token."""
    import tempfile, os

    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        key_path = f.name

    try:
        # Create service account with ed25519 keypair; capture private key
        result = hkey.run(
            "account", "create", "--type", "service",
            "--name", "svc_login1",
            "--auth", "ed25519",
            "--generate-keypair",
            "--out-private-key", key_path,
            "--activate",
            "--json",
        )
        assert result.returncode == 0, f"create failed: {result.stderr}"

        result = hkey.run_unauth(
            "auth", "sa", "token",
            "--method", "keysig",
            "--name", "svc_login1",
            "--private-key", key_path,
        )
        assert result.returncode == 0, f"sa token failed: {result.stderr}"
    finally:
        try:
            os.unlink(key_path)
        except FileNotFoundError:
            pass
