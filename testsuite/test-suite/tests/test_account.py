import json

import hkey
import helpers

def test_account_clean_setup():
    result = hkey.run("account", "list", "--json")
    assert result.returncode == 0

    data = helpers.get_accounts_json()
    assert data['total'] == 4

    account_names = [entry['account_name'] for entry in data['entries']]
    assert "admin" in account_names
    assert "$system" in account_names
    assert "$bootstrap" in account_names
    assert "$recovery" in account_names

def test_create_user_account_minimal():
    result = hkey.run("account", "create", "--type", "user", "--name", "testuser", "--insecure-password", "testpassword")
    assert result.returncode == 0

    data = helpers.account_describe("testuser")
    assert data['account_name'] == "testuser"
    assert data['account_type'] == "user"
    assert data['status'] == "disabled"

    result = hkey.run("auth", "login", "--name", "testuser", "--insecure-password", "testpassword")
    assert result.returncode == 12
    assert "User disabled" in result.stderr

    result = hkey.run("account", "enable", "--name", "testuser")
    assert result.returncode == 0

    result = hkey.run("auth", "login", "--name", "testuser", "--insecure-password", "testpassword", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['account_name'] == "testuser"
    assert data['scope'] == "auth"
    assert 'access_token' in data
    assert data['access_token'].startswith("hkat_")

def test_create_user_account_full():
    result = hkey.run(
        "account", "create",
        "--type", "user",
        "--name", "fulluser",
        "--full-name", "Full User",
        "--email", "fulluser@example.org",
        "--activate",
        "--insecure-password", "fullpassword",
        "--description", "A full user account",
        "--label", "team=devops",
        "--label", "env=staging"
    )
    assert result.returncode == 0

    data = helpers.account_describe("fulluser")
    assert data['account_name'] == "fulluser"
    assert data['email'] == "fulluser@example.org"
    assert data['full_name'] == "Full User"
    assert data["must_change_password"] is False
    assert data['account_type'] == "user"
    assert data['status'] == "active"
    assert data['metadata']['description'] == "A full user account"
    assert data['metadata']['labels']['team'] == "devops"
    assert data['metadata']['labels']['env'] == "staging"

def test_reject_incorrect_names():
    invalid = [
        ("aa",                    "name is too short"),
        ("a" * 65,                "name is too long"),
        ("name with spaces",      "name contains invalid characters"),
        ("name/with/slash",       "name contains invalid characters"),
        ("name..with.-multidots", "cannot have consecutive special characters"),
        ("name-_with-dashes",     "cannot have consecutive special characters"),
        (".startswithdash",       "must start with an alphanumeric character"),
        ("endswithdash-",         "cannot end with a special character"),
        ("$systemname",           "Cannot create accounts starting with a $"),
        ("name$system",           "name contains invalid characters"),
    ]

    for name, expected_msg in invalid:
        result = hkey.run(
            "account", "create", "--type", "user",
            "--name", name,
            "--insecure-password", "passwordpassword1234",
        )
        assert result.returncode != 0, f"Expected failure for name '{name}', got returncode 0"
        assert expected_msg in result.stderr, (
            f"Name '{name}': expected '{expected_msg}' in stderr.\n"
            f"  stdout: {result.stdout!r}\n"
            f"  stderr: {result.stderr!r}"
        )


def test_canonical_usernames():
    result = hkey.run("account", "create", "--type", "user", "--name", "canon_user", "--insecure-password", "passwordpassword1234")
    assert result.returncode == 0

    result = hkey.run("account", "create", "--type", "user", "--name", "CANON_USER", "--insecure-password", "passwordpassword1234")
    assert result.returncode == 12
    assert "name already exists" in result.stderr


def test_create_service_account():
    result = hkey.run(
        "account", "create", "--type", "service",
        "--name", "serviceaccount1",
        "--auth", "ed25519",
        "--generate-keypair",
        "--print-private-key-once",
        "--description", "A service account",
        "--label", "foo=bar",
    )
    assert result.returncode == 0

    data = helpers.account_describe("serviceaccount1")
    assert data['account_name'] == "serviceaccount1"
    assert data['account_type'] == "service"
    assert data['status'] == "disabled"
    assert data['metadata']['description'] == "A service account"
    assert data['metadata']['labels']["foo"] == "bar"


def test_create_service_account_with_system_name():
    result = hkey.run("account", "create", "--type", "service", "--name", "$service",
                      "--auth", "ed25519", "--generate-keypair", "--print-private-key-once")
    assert result.returncode == 12


def test_passwords():
    result = hkey.run("account", "create", "--type", "user", "--name", "passworduser",
                      "--generate-password", "--json", "--activate")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert 'generated_secret' in data
    initial_password = data['generated_secret']

    result = hkey.run("auth", "login", "--name", "passworduser", "--insecure-password", initial_password, "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['account_name'] == "passworduser"
    assert data['scope'] == "auth"

    result = hkey.run("auth", "login", "--name", "passworduser", "--insecure-password", "thisisprobablynotthecorrectpassword", "--json")
    assert result.returncode == 12
    assert "User not found or invalid credentials" in result.stderr

    result = hkey.run("account", "create", "--type", "user", "--name", "passworduser2",
                      "--must-change-password", "--generate-password", "--json", "--activate")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert 'generated_secret' in data
    initial_password = data['generated_secret']

    data = helpers.account_describe("passworduser2")
    assert data["must_change_password"] is True
    assert data["password_changed_at"] is None

    result = hkey.run("auth", "login", "--name", "passworduser2", "--insecure-password", initial_password, "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['account_name'] == "passworduser2"
    assert data['scope'] == "change_password"
    assert "access_token" in data
    token = data["access_token"]

    result = hkey.run_unauth("account", "change-password", "--name", "passworduser2",
                             "--token", token, "--insecure-new-password", "newsecurepassword1234")
    assert result.returncode == 0
    assert "Password changed successfully" in result.stdout

    data = helpers.account_describe("passworduser2")
    assert data["must_change_password"] is False
    assert data["password_changed_at"] is not None

    result = hkey.run_unauth("account", "change-password", "--name", "passworduser2",
                             "--token", token, "--insecure-new-password", "newsecurepassword1234")
    assert result.returncode == 12
    assert "authentication error: unauthenticated" in result.stderr


def test_create_user_for_disabled_check():
    result = hkey.run("account", "create", "--type", "user", "--name", "passworduser3",
                      "--generate-password", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert 'generated_secret' in data
    assert data['data']['status'] == "disabled"
    initial_password = data['generated_secret']

    result = hkey.run("auth", "login", "--name", "passworduser3", "--insecure-password", initial_password, "--json")
    assert "User disabled" in result.stderr
    assert result.returncode == 12


def test_create_user_for_locked_check():
    result = hkey.run("account", "create", "--type", "user", "--name", "passworduser4",
                      "--generate-password", "--activate", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert 'generated_secret' in data
    assert data['data']['status'] == "active"
    initial_password = data['generated_secret']

    result = hkey.run("account", "lock", "--name", "passworduser4", "--reason", "test locking")
    assert result.returncode == 0

    data = helpers.account_describe("passworduser4")
    assert data['status'] == "locked"
    assert data['status_reason'] == "test locking"

    result = hkey.run("auth", "login", "--name", "passworduser4", "--insecure-password", initial_password, "--json")
    assert "User disabled" in result.stderr
    assert result.returncode == 12

def test_account_status():
    result = hkey.run("account", "create", "--type", "user", "--name", "status1",
                      "--generate-password", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['data']['status'] == "disabled"
    last_changed_at = data['data']['status_changed_at']

    result = hkey.run("account", "create", "--type", "user", "--name", "status2",
                      "--generate-password", "--activate", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['data']['status'] == "active"
    last_changed_at = data['data']['status_changed_at']

    result = hkey.run("account", "disable", "--name", "status2")
    assert result.returncode == 0
    data = helpers.account_describe("status2")
    assert data['status'] == "disabled"
    assert data['status_changed_at'] != last_changed_at
    last_changed_at = data['status_changed_at']

    result = hkey.run("account", "enable", "--name", "status2")
    assert result.returncode == 0
    data = helpers.account_describe("status2")
    assert data['status'] == "active"
    assert data['status_changed_at'] != last_changed_at
    last_changed_at = data['status_changed_at']

    result = hkey.run("account", "lock", "--name", "status2", "--reason", "testing lock")
    assert result.returncode == 0
    data = helpers.account_describe("status2")
    assert data['status'] == "locked"
    assert data['status_reason'] == "testing lock"
    assert data['status_changed_at'] != last_changed_at
    last_changed_at = data['status_changed_at']

    result = hkey.run("account", "unlock", "--name", "status2")
    assert result.returncode == 0
    data = helpers.account_describe("status2")
    assert data['status'] == "active"
    assert data['status_changed_at'] != last_changed_at
    last_changed_at = data['status_changed_at']

    result = hkey.run("account", "lock", "--name", "status2", "--reason", "testing lock to disabled")
    assert result.returncode == 0
    data = helpers.account_describe("status2")
    assert data['status'] == "locked"
    assert data['status_reason'] == "testing lock to disabled"
    assert data['status_changed_at'] != last_changed_at
    last_changed_at = data['status_changed_at']

    result = hkey.run("account", "disable", "--name", "status2", "--reason", "disabling locked account")
    assert result.returncode == 0
    data = helpers.account_describe("status2")
    assert data['status'] == "disabled"
    assert data['status_reason'] == "disabling locked account"
    assert data['status_changed_at'] != last_changed_at
    last_changed_at = data['status_changed_at']

    result = hkey.run("account", "unlock", "--name", "status2", "--reason", "trying to unlock disabled account")
    assert result.returncode == 12
    assert "account is not locked" in result.stderr
    assert data['status_changed_at'] == last_changed_at

    result = hkey.run("account", "enable", "--name", "status2", "--reason", "enabling disabled account")
    assert result.returncode == 0
    data = helpers.account_describe("status2")
    assert data['status'] == "active"
    assert data['status_reason'] == "enabling disabled account"
    assert data['status_changed_at'] != last_changed_at
    last_changed_at = data['status_changed_at']

    result = hkey.run("account", "lock", "--name", "status2", "--reason", "testing lock again")
    assert result.returncode == 0
    data = helpers.account_describe("status2")
    assert data['status'] == "locked"
    assert data['status_reason'] == "testing lock again"
    assert data['status_changed_at'] != last_changed_at
    last_changed_at = data['status_changed_at']

    result = hkey.run("account", "enable", "--name", "status2", "--reason", "enabling from locked status")
    assert result.returncode == 0
    data = helpers.account_describe("status2")
    assert data['status'] == "active"
    assert data['status_reason'] == "enabling from locked status"
    assert data['status_changed_at'] is not None
    assert data['status_changed_at'] != last_changed_at

def test_login_while_locked():
    result = hkey.run("account", "create", "--type", "user", "--name", "locked1",
                      "--generate-password", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    initial_password = data['generated_secret']
    assert data['data']['status'] == "disabled"

    result = hkey.run("auth", "login", "--name", "locked1", "--insecure-password", initial_password, "--json")
    assert result.returncode == 12
    assert "User disabled" in result.stderr

    result = hkey.run("account", "enable", "--name", "locked1")
    assert result.returncode == 0

    result = hkey.run("auth", "login", "--name", "locked1", "--insecure-password", initial_password, "--json")
    assert result.returncode == 0

    result = hkey.run("account", "lock", "--name", "locked1", "--reason", "testing lock")
    assert result.returncode == 0

    result = hkey.run("auth", "login", "--name", "locked1", "--insecure-password", initial_password, "--json")
    assert result.returncode == 12
    assert "User disabled" in result.stderr

def test_try_to_lock_system_accounts():
    result = hkey.run("account", "lock", "--name", "$system", "--reason", "testing lock")
    assert result.returncode == 12
    assert "System accounts cannot be locked" in result.stderr

def test_try_to_disable_system_accounts():
    result = hkey.run("account", "disable", "--name", "$system", "--reason", "testing disable")
    assert result.returncode == 12
    assert "System accounts cannot be disabled" in result.stderr

def test_try_lock_not_existing_user():
    result = hkey.run("account", "lock", "--name", "nonexistinguser", "--reason", "testing lock")
    assert result.returncode == 12
    assert "Account 'nonexistinguser' not found" in result.stderr

def test_try_to_lock_ourselves():
    result = hkey.run("account", "create", "--type", "user", "--name", "me1",
                      "--generate-password", "--activate", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    initial_password = data['generated_secret']
    assert data['data']['status'] == "active"

    result = hkey.run_unauth("auth", "login", "--name", "me1", "--insecure-password", initial_password, "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "access_token" in data
    token = data["access_token"]

    result = hkey.run_unauth("--token", token, "account", "lock", "--name", "me1", "--reason", "testing lock ourselves")
    assert result.returncode == 12
    assert "Cannot lock your own account" in result.stderr

    result = hkey.run_unauth("--token", token, "account", "disable", "--name", "me1", "--reason", "testing disable ourselves")
    assert result.returncode == 12
    assert "Cannot disable your own account" in result.stderr

    result = hkey.run("account", "lock", "--name", "me1", "--reason", "admin locking me1")
    assert result.returncode == 0


def test_account_describe_created_by():
    """Create a user as admin; describe --json should include created_by with admin's name."""
    result = hkey.run("account", "create", "--type", "user", "--name", "audituser1",
                      "--insecure-password", "AuditPassw0rd!", "--activate")
    assert result.returncode == 0

    data = helpers.account_describe("audituser1")
    assert data["created_by"] is not None, "created_by should be set after admin creates a user"
    assert data["created_by"]["name"] == "admin"
    acc_id = data["created_by"]["id"]
    assert acc_id is not None
    assert acc_id.startswith("acc_"), f"Expected created_by.id to start with 'acc_', got: {acc_id}"


def test_account_describe_updated_by():
    """Create then lock a user as admin; describe --json should include status_changed_by with admin's name."""
    result = hkey.run("account", "create", "--type", "user", "--name", "audituser2",
                      "--insecure-password", "AuditPassw0rd!", "--activate")
    assert result.returncode == 0

    result = hkey.run("account", "lock", "--name", "audituser2", "--reason", "audit test lock")
    assert result.returncode == 0

    data = helpers.account_describe("audituser2")
    assert data["status"] == "locked"
    assert data["status_changed_by"] is not None, "status_changed_by should be set after locking"
    assert data["status_changed_by"]["name"] == "admin"
