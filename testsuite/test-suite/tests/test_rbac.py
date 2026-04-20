import json

import hkey
import helpers

def test_rbac_role():
    result = hkey.run("rbac", "role", "list", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)

    admin = next((r for r in data if r['name'] == "platform:admin"), None)
    assert admin is not None, "platform:admin role not found"
    assert admin['is_system'] == True
    assert admin['role_count'] == 1

def test_rbac_rule():
    result = hkey.run("rbac", "rule", "list", "--json")
    data = json.loads(result.stdout)
    assert result.returncode == 0

    # The default platform:admin rule must always be present, regardless of
    # rules created by other tests that may run before this one.
    admin_rules = [r for r in data if r['permission'] == 'platform:admin']
    assert len(admin_rules) == 1, f"Expected exactly one platform:admin rule, found: {admin_rules}"
    assert admin_rules[0]['effect'] == "allow"
    assert admin_rules[0]['target'] == "all"
    assert admin_rules[0]['account_count'] == 0
    assert admin_rules[0]['role_count'] == 1

def test_rbac_add_new_role():
    result = hkey.run("rbac", "role", "create", "--name", "test_role_a", "--description", "Test role A")
    assert result.returncode == 0

    result = hkey.run("rbac", "role", "list", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)

    role_a = next((r for r in data if r['name'] == "test_role_a"), None)
    assert role_a is not None, "test_role_a not found"
    assert role_a['is_system'] == False
    assert role_a['role_count'] == 0

def test_rbac_add_rule_to_role():
    # Create test_role_a here because clear_all_rbac() runs between tests
    result = hkey.run("rbac", "role", "create", "--name", "test_role_a", "--description", "Test role A")
    assert result.returncode == 0

    result = hkey.run("rbac", "rule", "create", "--rule", "allow secret:reveal to namespace /prod", "--json")
    assert result.returncode == 0
    rule1 = json.loads(result.stdout)['data']
    assert rule1['effect'] == "allow"
    assert rule1['permission'] == "secret:reveal"
    assert rule1['target'] == "namespace /prod"

    result = hkey.run("rbac", "rule", "create", "--rule", "allow secret:create to namespace /test", "--json")
    assert result.returncode == 0
    rule2 = json.loads(result.stdout)['data']
    assert rule2['effect'] == "allow"
    assert rule2['permission'] == "secret:create"
    assert rule2['target'] == "namespace /test"

    result = hkey.run("rbac", "role", "create", "--name", "test_role_b", "--description", "Test role B")
    assert result.returncode == 0

    result = hkey.run("rbac", "role", "describe", "--name", "test_role_b", "--json")
    assert result.returncode == 0
    role1 = json.loads(result.stdout)
    assert role1['role']['name'] == "test_role_b"
    assert role1['role']['is_system'] == False
    assert len(role1['rules']) == 0

    result = hkey.run("rbac", "role", "add", "--name", "test_role_b", "--rule-id", rule1['id'])
    assert result.returncode == 0

    result = hkey.run("rbac", "role", "describe", "--name", "test_role_b", "--json")
    assert result.returncode == 0
    role = json.loads(result.stdout)
    assert role['role']['name'] == "test_role_b"
    assert role['role']['is_system'] == False
    assert len(role['rules']) == 1

    result = hkey.run("rbac", "role", "add", "--name", "test_role_b", "--rule-id", rule2['id'])
    assert result.returncode == 0

    result = hkey.run("rbac", "role", "describe", "--name", "test_role_b", "--json")
    assert result.returncode == 0
    role = json.loads(result.stdout)
    assert role['role']['name'] == "test_role_b"
    assert role['role']['is_system'] == False
    assert len(role['rules']) == 2

    result = hkey.run("rbac", "role", "add", "--name", "test_role_b", "--rule", "allow secret:delete to namespace /prod")
    assert result.returncode == 0

    result = hkey.run("rbac", "role", "describe", "--name", "test_role_b", "--json")
    assert result.returncode == 0
    role = json.loads(result.stdout)
    assert role['role']['name'] == "test_role_b"
    assert role['role']['is_system'] == False
    assert len(role['rules']) == 3

    result = hkey.run("rbac", "role", "list", "--json")
    assert result.returncode == 0
    rows = json.loads(result.stdout)
    by_name = {r['name']: r for r in rows}

    assert "platform:admin" in by_name
    assert by_name["platform:admin"]['role_count'] == 1
    assert "test_role_a" in by_name
    assert by_name["test_role_a"]['role_count'] == 0
    assert "test_role_b" in by_name
    assert by_name["test_role_b"]['role_count'] == 3

def test_add_rule_to_roles():
    pass


def test_rbac_bind_account_to_role():
    """Create a role with a rule, bind a named account to it, verify the bind succeeds."""
    # Create a user to bind
    helpers.create_user_account("bindtestuser", activate=True)

    # Create a role
    result = hkey.run("rbac", "role", "create", "--name", "bind-test-role",
                      "--description", "Role for bind test")
    assert result.returncode == 0, f"role create failed: {result.stderr}"

    # Add a rule to the role
    result = hkey.run("rbac", "role", "add", "--name", "bind-test-role",
                      "--rule", "allow secret:reveal to namespace /bindtest")
    assert result.returncode == 0, f"role add rule failed: {result.stderr}"

    # Verify the role has the rule
    result = hkey.run("rbac", "role", "describe", "--name", "bind-test-role", "--json")
    assert result.returncode == 0
    role_data = json.loads(result.stdout)
    assert len(role_data["rules"]) == 1

    # Bind the account to the role
    result = hkey.run("rbac", "bind", "--name", "bindtestuser", "--role", "bind-test-role")
    assert result.returncode == 0, f"rbac bind failed: {result.stderr}"


def test_rbac_access_enforcement():
    """End-to-end RBAC permission check: user cannot access secret until granted a role."""
    # 1. Create namespace and secret as admin
    helpers.create_namespace("/rbactest")
    helpers.create_secret("/rbactest:mysecret", "supersecret")

    # 2. Create and activate a regular user
    helpers.create_user_account("rbacenforceuser", password="RbacPassword1!", activate=True)

    # 3. Login as that user, get token
    token = helpers.login_as("rbacenforceuser", "RbacPassword1!")
    assert token.startswith("hkat_"), f"Unexpected token format: {token}"

    # 4. As that user: secret reveal should fail with return code 12 (no permission)
    result = hkey.run_as(token, "secret", "reveal", "--ref", "/rbactest:mysecret")
    assert result.returncode == 12, (
        f"Expected rc=12 (no permission) but got rc={result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )

    # 5. Create role and rule granting read access to /rbactest
    result = hkey.run("rbac", "role", "create", "--name", "read-rbactest",
                      "--description", "Read access to /rbactest namespace")
    assert result.returncode == 0, f"role create failed: {result.stderr}"

    result = hkey.run("rbac", "role", "add", "--name", "read-rbactest",
                      "--rule", "allow secret:reveal to namespace /rbactest")
    assert result.returncode == 0, f"role add rule failed: {result.stderr}"

    # 6. Bind rbacenforceuser to read-rbactest role
    result = hkey.run("rbac", "bind", "--name", "rbacenforceuser", "--role", "read-rbactest")
    assert result.returncode == 0, f"rbac bind failed: {result.stderr}"

    # 7. As that user: secret reveal should now succeed
    result = hkey.run_as(token, "secret", "reveal", "--ref", "/rbactest:mysecret")
    assert result.returncode == 0, (
        f"Expected rc=0 (access granted) but got rc={result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
