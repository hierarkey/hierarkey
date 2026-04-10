import json
import hkey
import helpers


# ============================================================
# SECTION 1 – Initial State
# ============================================================

def test_rbac_initial_state():
    """After a clean reset there should be exactly 1 system role and 1 system rule."""
    result = hkey.run("rbac", "role", "list", "--json")
    assert result.returncode == 0
    roles = json.loads(result.stdout)
    # Filter to system roles only (non-system roles may accumulate since role delete is not yet
    # fully implemented, so we cannot rely on the total count).
    system_roles = [r for r in roles if r.get('is_system')]
    assert len(system_roles) == 1
    role = system_roles[0]
    assert role['name'] == "platform:admin"
    assert role['is_system'] is True
    assert role['role_count'] == 1        # one rule inside the role

    result = hkey.run("rbac", "rule", "list", "--json")
    assert result.returncode == 0
    rules = json.loads(result.stdout)
    # Find the platform:admin wildcard rule (may be more rules if tests leaked, but at minimum
    # the bootstrap rule must be present).
    admin_rules = [r for r in rules if r.get('permission') == 'platform:admin' and r.get('target') == 'all']
    assert len(admin_rules) == 1
    rule = admin_rules[0]
    assert rule['effect'] == "allow"
    assert rule['role_count'] == 1        # contained in 1 role
    assert rule['account_count'] == 0


# ============================================================
# SECTION 2 – Role Management
# ============================================================

def test_role_create_name_only():
    result = hkey.run("rbac", "role", "create", "--name", "simple-role")
    assert result.returncode == 0

    result = hkey.run("rbac", "role", "list", "--json")
    assert result.returncode == 0
    roles = json.loads(result.stdout)
    role = next((r for r in roles if r['name'] == "simple-role"), None)
    assert role is not None
    assert role['is_system'] is False
    assert role['role_count'] == 0


def test_role_create_with_description():
    result = hkey.run("rbac", "role", "create", "--name", "desc-role",
                      "--description", "My test role")
    assert result.returncode == 0

    result = hkey.run("rbac", "role", "describe", "--name", "desc-role", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['role']['name'] == "desc-role"
    assert data['role']['description'] == "My test role"
    assert data['role']['is_system'] is False
    assert isinstance(data['rules'], list)


def test_role_create_duplicate_name():
    hkey.run("rbac", "role", "create", "--name", "unique-role")
    result = hkey.run("rbac", "role", "create", "--name", "unique-role")
    assert result.returncode != 0


def test_role_list_includes_system_and_user_roles():
    for name in ["bravo-role", "alpha-role"]:
        hkey.run("rbac", "role", "create", "--name", name)

    result = hkey.run("rbac", "role", "list", "--json")
    assert result.returncode == 0
    roles = json.loads(result.stdout)
    # role delete is a stub CLI command so roles from prior tests may persist; check presence only
    assert any(r['name'] == "platform:admin" and r['is_system'] is True for r in roles)
    assert any(r['name'] == "bravo-role" and r['is_system'] is False for r in roles)
    assert any(r['name'] == "alpha-role" and r['is_system'] is False for r in roles)


def test_role_describe_empty_role():
    hkey.run("rbac", "role", "create", "--name", "empty-role")
    result = hkey.run("rbac", "role", "describe", "--name", "empty-role", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['role']['name'] == "empty-role"
    assert data['role']['is_system'] is False
    assert data['rules'] == []


def test_role_describe_not_found():
    result = hkey.run("rbac", "role", "describe", "--name", "nonexistent-role", "--json")
    assert result.returncode != 0


def test_role_update_description():
    hkey.run("rbac", "role", "create", "--name", "updatable-role",
             "--description", "original description")

    result = hkey.run("rbac", "role", "update", "--name", "updatable-role",
                      "--description", "updated description")
    assert result.returncode == 0

    result = hkey.run("rbac", "role", "describe", "--name", "updatable-role", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['role']['description'] == "updated description"


def test_role_update_clear_description():
    hkey.run("rbac", "role", "create", "--name", "clearable-role",
             "--description", "will be cleared")

    result = hkey.run("rbac", "role", "update", "--name", "clearable-role",
                      "--clear-description")
    assert result.returncode == 0

    result = hkey.run("rbac", "role", "describe", "--name", "clearable-role", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert not data['role'].get('description')


def test_role_describe_includes_created_at():
    hkey.run("rbac", "role", "create", "--name", "audit-role")
    result = hkey.run("rbac", "role", "describe", "--name", "audit-role", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['role'].get('created_at') is not None
    assert data['role'].get('created_by') is not None


# ============================================================
# SECTION 3 – Rule Management
# ============================================================

def test_rule_create_all_secret_permissions():
    """Every secret:* permission must be accepted."""
    permissions = [
        "secret:reveal",
        "secret:list",
        "secret:describe",
        "secret:create",
        "secret:revise",
        "secret:delete",
        "secret:restore",
        "secret:update:meta",
        "secret:lifecycle",
        "secret:history:read",
        "secret:rollback",
        "secret:*",
    ]
    for perm in permissions:
        result = hkey.run("rbac", "rule", "create", "--rule",
                          f"allow {perm} to namespace /test", "--json")
        assert result.returncode == 0, f"permission '{perm}' rejected: {result.stderr}"
        data = json.loads(result.stdout)['data']
        assert data['permission'] == perm
        assert data['effect'] == "allow"


def test_rule_create_all_namespace_permissions():
    permissions = [
        "namespace:create",
        "namespace:list",
        "namespace:describe",
        "namespace:update:meta",
        "namespace:delete",
        "namespace:policy:read",
        "namespace:policy:write",
        "namespace:kek_rotate",
        "namespace:*",
    ]
    for perm in permissions:
        result = hkey.run("rbac", "rule", "create", "--rule",
                          f"allow {perm} to namespace /test", "--json")
        assert result.returncode == 0, f"permission '{perm}' rejected: {result.stderr}"
        data = json.loads(result.stdout)['data']
        assert data['permission'] == perm


def test_rule_create_global_permissions():
    global_cases = [
        ("audit:read",     "to all"),
        ("rbac:admin",     "to all"),
        ("platform:admin", "to all"),
        ("all",            "to all"),
    ]
    for perm, target_str in global_cases:
        result = hkey.run("rbac", "rule", "create", "--rule",
                          f"allow {perm} {target_str}", "--json")
        assert result.returncode == 0, f"permission '{perm}' rejected: {result.stderr}"
        data = json.loads(result.stdout)['data']
        assert data['permission'] == perm
        assert data['target'] == "all"


def test_rule_create_deny_effect():
    result = hkey.run("rbac", "rule", "create", "--rule",
                      "deny secret:reveal to namespace /restricted", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)['data']
    assert data['effect'] == "deny"
    assert data['permission'] == "secret:reveal"
    assert data['target'] == "namespace /restricted"


def test_rule_create_namespace_target_patterns():
    """Exact, subtree, and multi-level namespace targets."""
    cases = [
        ("allow secret:reveal to namespace /prod",       "namespace /prod"),
        ("allow secret:reveal to namespace /prod/**",    "namespace /prod/**"),
        ("allow secret:reveal to namespace /prod/app1",  "namespace /prod/app1"),
        ("allow secret:reveal to namespace /a/b/c/**",   "namespace /a/b/c/**"),
    ]
    for spec, expected_target in cases:
        result = hkey.run("rbac", "rule", "create", "--rule", spec, "--json")
        assert result.returncode == 0, f"spec '{spec}' rejected: {result.stderr}"
        data = json.loads(result.stdout)['data']
        assert data['target'] == expected_target, \
            f"spec '{spec}': expected target '{expected_target}', got '{data['target']}'"


def test_rule_create_secret_target():
    result = hkey.run("rbac", "rule", "create", "--rule",
                      "allow secret:reveal to secret /prod:db/password", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)['data']
    assert data['target'] == "secret /prod:db/password"
    assert data['permission'] == "secret:reveal"


def test_rule_create_all_target():
    result = hkey.run("rbac", "rule", "create", "--rule",
                      "allow platform:admin to all", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)['data']
    assert data['target'] == "all"
    assert data['effect'] == "allow"


def test_rule_create_case_insensitive():
    """Effect and permission tokens are case-insensitive."""
    result = hkey.run("rbac", "rule", "create", "--rule",
                      "ALLOW SECRET:REVEAL to namespace /test", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)['data']
    assert data['effect'] == "allow"
    assert data['permission'] == "secret:reveal"


def test_rule_create_invalid_specs():
    """Invalid rule specs must be rejected (non-zero exit)."""
    invalid = [
        "allow secret:read to namespace /test",          # secret:read is not a valid permission
        "grant secret:reveal to namespace /test",         # 'grant' is not allow/deny
        "allow unknown:permission to namespace /test",    # unknown permission
        "allow secret:reveal to unknowntarget /test",     # invalid target kind
        "allow secret:reveal to namespace",               # missing namespace pattern
        "allow secret:reveal namespace /test",            # missing 'to'
        "allow secret:reveal to namespace /test/",        # trailing slash in pattern
        "allow secret:reveal to namespace //double",      # double slash
        "",                                               # empty
    ]
    for spec in invalid:
        result = hkey.run("rbac", "rule", "create", "--rule", spec)
        assert result.returncode != 0, \
            f"Expected failure for spec {spec!r}, but got rc=0\nstdout: {result.stdout}"


def test_rule_describe():
    result = hkey.run("rbac", "rule", "create", "--rule",
                      "allow secret:reveal to namespace /describe-test", "--json")
    assert result.returncode == 0
    rule_id = json.loads(result.stdout)['data']['id']

    result = hkey.run("rbac", "rule", "describe", "--id", rule_id, "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['id'] == rule_id
    assert data['effect'] == "allow"
    assert data['permission'] == "secret:reveal"
    assert data['target'] == "namespace /describe-test"
    assert data.get('created_at') is not None
    assert data.get('created_by') is not None


def test_rule_describe_not_found():
    result = hkey.run("rbac", "rule", "describe", "--id", "rul_doesnotexist", "--json")
    assert result.returncode != 0


def test_rule_list_shows_counts():
    result = hkey.run("rbac", "rule", "create", "--rule",
                      "allow secret:reveal to namespace /test", "--json")
    rule_id = json.loads(result.stdout)['data']['id']

    result = hkey.run("rbac", "rule", "list", "--json")
    assert result.returncode == 0
    rules = json.loads(result.stdout)
    rule = next((r for r in rules if r['id'] == rule_id), None)
    assert rule is not None
    assert rule['role_count'] == 0
    assert rule['account_count'] == 0


# ============================================================
# SECTION 4 – Role–Rule Association
# ============================================================

def test_role_add_rule_inline():
    hkey.run("rbac", "role", "create", "--name", "inline-role")
    result = hkey.run("rbac", "role", "add", "--name", "inline-role",
                      "--rule", "allow secret:reveal to namespace /prod")
    assert result.returncode == 0

    result = hkey.run("rbac", "role", "describe", "--name", "inline-role", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert len(data['rules']) == 1
    assert data['rules'][0]['permission'] == "secret:reveal"


def test_role_add_rule_by_id():
    result = hkey.run("rbac", "rule", "create", "--rule",
                      "allow secret:create to namespace /dev", "--json")
    rule_id = json.loads(result.stdout)['data']['id']

    hkey.run("rbac", "role", "create", "--name", "byid-role")
    result = hkey.run("rbac", "role", "add", "--name", "byid-role", "--rule-id", rule_id)
    assert result.returncode == 0

    result = hkey.run("rbac", "role", "describe", "--name", "byid-role", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert len(data['rules']) == 1
    assert data['rules'][0]['id'] == rule_id


def test_role_add_multiple_rules():
    hkey.run("rbac", "role", "create", "--name", "multi-role")
    for perm in ["secret:reveal", "secret:list", "secret:describe"]:
        result = hkey.run("rbac", "role", "add", "--name", "multi-role",
                          "--rule", f"allow {perm} to namespace /prod")
        assert result.returncode == 0, f"add rule '{perm}' failed: {result.stderr}"

    result = hkey.run("rbac", "role", "describe", "--name", "multi-role", "--json")
    data = json.loads(result.stdout)
    assert len(data['rules']) == 3


def test_role_add_rule_updates_rule_role_count():
    result = hkey.run("rbac", "rule", "create", "--rule",
                      "allow secret:reveal to namespace /test", "--json")
    rule_id = json.loads(result.stdout)['data']['id']

    # Initially in 0 roles
    result = hkey.run("rbac", "rule", "list", "--json")
    rule = next(r for r in json.loads(result.stdout) if r['id'] == rule_id)
    assert rule['role_count'] == 0

    # Add to a role -> count becomes 1
    hkey.run("rbac", "role", "create", "--name", "count-role")
    hkey.run("rbac", "role", "add", "--name", "count-role", "--rule-id", rule_id)

    result = hkey.run("rbac", "rule", "list", "--json")
    rule = next(r for r in json.loads(result.stdout) if r['id'] == rule_id)
    assert rule['role_count'] == 1


def test_role_add_rule_mutual_exclusion():
    """--rule and --rule-id cannot both be provided."""
    result = hkey.run("rbac", "rule", "create", "--rule",
                      "allow secret:reveal to namespace /test", "--json")
    rule_id = json.loads(result.stdout)['data']['id']

    hkey.run("rbac", "role", "create", "--name", "excl-role")
    result = hkey.run("rbac", "role", "add", "--name", "excl-role",
                      "--rule", "allow secret:reveal to namespace /test",
                      "--rule-id", rule_id)
    assert result.returncode != 0


def test_role_add_invalid_rule_spec():
    hkey.run("rbac", "role", "create", "--name", "invalid-spec-role")
    result = hkey.run("rbac", "role", "add", "--name", "invalid-spec-role",
                      "--rule", "allow secret:read to namespace /test")
    assert result.returncode != 0


def test_role_add_nonexistent_role():
    result = hkey.run("rbac", "role", "add", "--name", "no-such-role",
                      "--rule", "allow secret:reveal to namespace /test")
    assert result.returncode != 0


def test_role_add_nonexistent_rule_id():
    hkey.run("rbac", "role", "create", "--name", "existing-role")
    result = hkey.run("rbac", "role", "add", "--name", "existing-role",
                      "--rule-id", "rul_doesnotexist")
    assert result.returncode != 0


# ============================================================
# SECTION 5 – Bindings
# ============================================================

def test_bind_account_to_role():
    helpers.create_user_account("bindtest-a2r", activate=True)
    hkey.run("rbac", "role", "create", "--name", "a2r-role")
    result = hkey.run("rbac", "bind", "--name", "bindtest-a2r", "--role", "a2r-role")
    assert result.returncode == 0, f"bind failed: {result.stderr}"


def test_bind_account_to_role_appears_in_bindings():
    helpers.create_user_account("bindtest-bindings", activate=True)
    hkey.run("rbac", "role", "create", "--name", "bindings-role")
    hkey.run("rbac", "role", "add", "--name", "bindings-role",
             "--rule", "allow secret:reveal to namespace /bindings-test")
    hkey.run("rbac", "bind", "--name", "bindtest-bindings", "--role", "bindings-role")

    result = hkey.run("rbac", "bindings", "--account", "bindtest-bindings", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    role_names = [entry['role']['name'] for entry in data.get('roles', [])]
    assert "bindings-role" in role_names
    # The rules under that role are also returned
    all_rules = [r for entry in data['roles'] for r in entry['rules']]
    assert any(r['permission'] == "secret:reveal" for r in all_rules)


def test_bind_account_to_rule_inline():
    helpers.create_user_account("bindtest-a2ri", activate=True)
    result = hkey.run("rbac", "bind", "--name", "bindtest-a2ri",
                      "--rule", "allow secret:reveal to namespace /bindtest")
    assert result.returncode == 0, f"inline-rule bind failed: {result.stderr}"


def test_bind_account_to_rule_inline_appears_in_bindings():
    helpers.create_user_account("bindtest-drule", activate=True)
    hkey.run("rbac", "bind", "--name", "bindtest-drule",
             "--rule", "allow secret:create to namespace /druletest")

    result = hkey.run("rbac", "bindings", "--account", "bindtest-drule", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert any(r['permission'] == "secret:create" for r in data.get('rules', []))


def test_bind_account_to_rule_by_id():
    helpers.create_user_account("bindtest-byid", activate=True)
    result = hkey.run("rbac", "rule", "create", "--rule",
                      "allow secret:describe to namespace /byid-test", "--json")
    rule_id = json.loads(result.stdout)['data']['id']

    result = hkey.run("rbac", "bind", "--name", "bindtest-byid", "--rule-id", rule_id)
    assert result.returncode == 0, f"bind by rule-id failed: {result.stderr}"


def test_bind_account_to_rule_updates_account_count():
    helpers.create_user_account("bindtest-acnt", activate=True)
    result = hkey.run("rbac", "rule", "create", "--rule",
                      "allow secret:reveal to namespace /acnt-test", "--json")
    rule_id = json.loads(result.stdout)['data']['id']

    result = hkey.run("rbac", "rule", "list", "--json")
    rule = next(r for r in json.loads(result.stdout) if r['id'] == rule_id)
    assert rule['account_count'] == 0

    hkey.run("rbac", "bind", "--name", "bindtest-acnt", "--rule-id", rule_id)

    result = hkey.run("rbac", "rule", "list", "--json")
    rule = next(r for r in json.loads(result.stdout) if r['id'] == rule_id)
    assert rule['account_count'] == 1


def test_bind_label_to_role():
    hkey.run("rbac", "role", "create", "--name", "label-role")
    result = hkey.run("rbac", "bind", "--account-label", "team=backend", "--role", "label-role")
    assert result.returncode == 0, f"label bind failed: {result.stderr}"


def test_bind_label_to_rule_inline():
    result = hkey.run("rbac", "bind", "--account-label", "env=prod",
                      "--rule", "allow secret:reveal to namespace /prod")
    assert result.returncode == 0, f"label->rule inline bind failed: {result.stderr}"


def test_bind_nonexistent_account():
    hkey.run("rbac", "role", "create", "--name", "tmp-role-1")
    result = hkey.run("rbac", "bind", "--name", "no-such-user-xyz", "--role", "tmp-role-1")
    assert result.returncode != 0


def test_bind_nonexistent_role():
    helpers.create_user_account("bindtest-norole", activate=True)
    result = hkey.run("rbac", "bind", "--name", "bindtest-norole", "--role", "no-such-role-xyz")
    assert result.returncode != 0


def test_bind_nonexistent_rule_id():
    helpers.create_user_account("bindtest-norule", activate=True)
    result = hkey.run("rbac", "bind", "--name", "bindtest-norule",
                      "--rule-id", "rul_doesnotexist")
    assert result.returncode != 0


def test_bindings_defaults_to_current_user():
    """rbac bindings without --account returns the calling user's bindings."""
    result = hkey.run("rbac", "bindings", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    # admin is bound to the platform:admin role
    role_names = [entry['role']['name'] for entry in data.get('roles', [])]
    assert "platform:admin" in role_names


# ============================================================
# SECTION 6 – Explain
# ============================================================

def test_explain_no_permission_denied():
    helpers.create_user_account("explain-noperm", activate=True)
    result = hkey.run("rbac", "explain", "--account", "explain-noperm",
                      "--permission", "secret:reveal",
                      "--namespace", "/test", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['allowed'] is False
    assert data['verdict'] == "denied"
    assert data['matched_rule'] is None


def test_explain_allowed_via_role_binding():
    helpers.create_user_account("explain-role", activate=True)
    hkey.run("rbac", "role", "create", "--name", "explain-reader-role")
    hkey.run("rbac", "role", "add", "--name", "explain-reader-role",
             "--rule", "allow secret:reveal to namespace /explainns")
    hkey.run("rbac", "bind", "--name", "explain-role", "--role", "explain-reader-role")

    result = hkey.run("rbac", "explain", "--account", "explain-role",
                      "--permission", "secret:reveal",
                      "--namespace", "/explainns", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['allowed'] is True
    assert data['verdict'] == "allowed"
    assert data['matched_rule'] is not None
    assert data['matched_rule']['permission'] == "secret:reveal"


def test_explain_allowed_via_direct_rule_binding():
    helpers.create_user_account("explain-direct", activate=True)
    hkey.run("rbac", "bind", "--name", "explain-direct",
             "--rule", "allow secret:list to namespace /directns")

    result = hkey.run("rbac", "explain", "--account", "explain-direct",
                      "--permission", "secret:list",
                      "--namespace", "/directns", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['allowed'] is True


def test_explain_with_namespace_resource():
    helpers.create_user_account("explain-ns", activate=True)
    hkey.run("rbac", "bind", "--name", "explain-ns",
             "--rule", "allow namespace:describe to namespace /myns")

    result = hkey.run("rbac", "explain", "--account", "explain-ns",
                      "--permission", "namespace:describe",
                      "--namespace", "/myns", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['allowed'] is True


def test_explain_with_secret_resource():
    helpers.create_user_account("explain-secret", activate=True)
    hkey.run("rbac", "bind", "--name", "explain-secret",
             "--rule", "allow secret:reveal to secret /secretns:mykey")

    result = hkey.run("rbac", "explain", "--account", "explain-secret",
                      "--permission", "secret:reveal",
                      "--secret", "/secretns:mykey", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['allowed'] is True


def test_explain_permission_subsumption_secret_wildcard():
    """secret:* should subsume all secret:X permissions."""
    helpers.create_user_account("explain-swild", activate=True)
    hkey.run("rbac", "bind", "--name", "explain-swild",
             "--rule", "allow secret:* to namespace /prodns")

    for perm in ["secret:reveal", "secret:create", "secret:list",
                 "secret:describe", "secret:revise", "secret:delete"]:
        result = hkey.run("rbac", "explain", "--account", "explain-swild",
                          "--permission", perm,
                          "--namespace", "/prodns", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data['allowed'] is True, \
            f"Expected '{perm}' allowed via secret:* but got denied"


def test_explain_permission_subsumption_all():
    """'all' permission should grant every other permission."""
    helpers.create_user_account("explain-allperm", activate=True)
    hkey.run("rbac", "bind", "--name", "explain-allperm",
             "--rule", "allow all to all")

    for perm in ["secret:reveal", "namespace:create", "rbac:admin", "audit:read"]:
        result = hkey.run("rbac", "explain", "--account", "explain-allperm",
                          "--permission", perm,
                          "--namespace", "/anyns", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data['allowed'] is True, \
            f"Expected '{perm}' allowed via 'all' but got denied"


def test_explain_namespace_subtree_matches_child_namespaces():
    helpers.create_user_account("explain-subtree", activate=True)
    hkey.run("rbac", "bind", "--name", "explain-subtree",
             "--rule", "allow secret:reveal to namespace /org/**")

    # /org/team1 -> allowed (child)
    result = hkey.run("rbac", "explain", "--account", "explain-subtree",
                      "--permission", "secret:reveal",
                      "--namespace", "/org/team1", "--json")
    assert result.returncode == 0
    assert json.loads(result.stdout)['allowed'] is True

    # /org/a/b/c -> allowed (deeper child)
    result = hkey.run("rbac", "explain", "--account", "explain-subtree",
                      "--permission", "secret:reveal",
                      "--namespace", "/org/a/b/c", "--json")
    assert result.returncode == 0
    assert json.loads(result.stdout)['allowed'] is True

    # /org itself -> denied (/** requires at least one more segment)
    result = hkey.run("rbac", "explain", "--account", "explain-subtree",
                      "--permission", "secret:reveal",
                      "--namespace", "/org", "--json")
    assert result.returncode == 0
    assert json.loads(result.stdout)['allowed'] is False


def test_explain_wrong_namespace_denied():
    helpers.create_user_account("explain-wrongns", activate=True)
    hkey.run("rbac", "bind", "--name", "explain-wrongns",
             "--rule", "allow secret:reveal to namespace /prod")

    result = hkey.run("rbac", "explain", "--account", "explain-wrongns",
                      "--permission", "secret:reveal",
                      "--namespace", "/staging", "--json")
    assert result.returncode == 0
    assert json.loads(result.stdout)['allowed'] is False


def test_explain_wrong_permission_denied():
    helpers.create_user_account("explain-wrongperm", activate=True)
    hkey.run("rbac", "bind", "--name", "explain-wrongperm",
             "--rule", "allow secret:reveal to namespace /test")

    # Has reveal but not create
    result = hkey.run("rbac", "explain", "--account", "explain-wrongperm",
                      "--permission", "secret:create",
                      "--namespace", "/test", "--json")
    assert result.returncode == 0
    assert json.loads(result.stdout)['allowed'] is False


def test_explain_namespace_rule_grants_secret_access():
    """A rule targeting a namespace also grants access to secrets within it."""
    helpers.create_user_account("explain-nsec", activate=True)
    hkey.run("rbac", "bind", "--name", "explain-nsec",
             "--rule", "allow secret:reveal to namespace /myprod")

    result = hkey.run("rbac", "explain", "--account", "explain-nsec",
                      "--permission", "secret:reveal",
                      "--secret", "/myprod:db/password", "--json")
    assert result.returncode == 0
    assert json.loads(result.stdout)['allowed'] is True


def test_explain_verbose_shows_near_misses():
    helpers.create_user_account("explain-verbose", activate=True)
    # Rule for a different namespace -> will be a near-miss
    hkey.run("rbac", "bind", "--name", "explain-verbose",
             "--rule", "allow secret:reveal to namespace /other")

    result = hkey.run("rbac", "explain", "--account", "explain-verbose",
                      "--permission", "secret:reveal",
                      "--namespace", "/different",
                      "--near-misses", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data['allowed'] is False
    assert isinstance(data['near_misses'], list)
    assert len(data['near_misses']) > 0
    nm = data['near_misses'][0]
    assert 'rule' in nm
    assert 'reason' in nm


def test_explain_requires_namespace_or_secret():
    helpers.create_user_account("explain-noreso", activate=True)
    # No --namespace and no --secret -> CLI error
    result = hkey.run("rbac", "explain", "--account", "explain-noreso",
                      "--permission", "secret:reveal")
    assert result.returncode != 0


def test_explain_invalid_account():
    result = hkey.run("rbac", "explain", "--account", "no-such-user-abcxyz",
                      "--permission", "secret:reveal",
                      "--namespace", "/test", "--json")
    assert result.returncode != 0


def test_explain_invalid_permission_token():
    helpers.create_user_account("explain-badperm", activate=True)
    result = hkey.run("rbac", "explain", "--account", "explain-badperm",
                      "--permission", "secret:read",   # invalid
                      "--namespace", "/test", "--json")
    assert result.returncode != 0


# ============================================================
# SECTION 7 – E2E Enforcement
# ============================================================

def test_e2e_access_denied_before_bind_allowed_after():
    """User has no access -> bind role -> access granted."""
    helpers.create_namespace("/e2e/app")
    helpers.create_secret("/e2e/app:db/pass", "topsecret")
    helpers.create_user_account("e2e-user1", password="E2ePassword1!", activate=True)
    token = helpers.login_as("e2e-user1", "E2ePassword1!")

    # Before binding – must fail
    result = hkey.run_as(token, "secret", "reveal", "--ref", "/e2e/app:db/pass")
    assert result.returncode != 0, "Expected rc!=0 before binding, got rc=0"

    # Grant access
    hkey.run("rbac", "role", "create", "--name", "e2e-reader")
    hkey.run("rbac", "role", "add", "--name", "e2e-reader",
             "--rule", "allow secret:reveal to namespace /e2e/app")
    hkey.run("rbac", "bind", "--name", "e2e-user1", "--role", "e2e-reader")

    # After binding – must succeed
    result = hkey.run_as(token, "secret", "reveal", "--ref", "/e2e/app:db/pass")
    assert result.returncode == 0, f"Expected rc=0 after binding, got rc={result.returncode}\n{result.stderr}"


def test_e2e_secret_wildcard_permission():
    """secret:* grants both reveal and create."""
    helpers.create_namespace("/e2e/wild")
    helpers.create_secret("/e2e/wild:existing", "val")
    helpers.create_user_account("e2e-wild", password="WildPassword1!", activate=True)
    token = helpers.login_as("e2e-wild", "WildPassword1!")

    hkey.run("rbac", "role", "create", "--name", "wildcard-role")
    hkey.run("rbac", "role", "add", "--name", "wildcard-role",
             "--rule", "allow secret:* to namespace /e2e/wild")
    hkey.run("rbac", "bind", "--name", "e2e-wild", "--role", "wildcard-role")

    result = hkey.run_as(token, "secret", "reveal", "--ref", "/e2e/wild:existing")
    assert result.returncode == 0, f"reveal failed: {result.stderr}"

    result = hkey.run_as(token, "secret", "create",
                         "--ref", "/e2e/wild:newkey", "--value", "newvalue")
    assert result.returncode == 0, f"create failed: {result.stderr}"


def test_e2e_scoped_role_no_access_to_other_namespace():
    """Role scoped to /e2e/prod must not grant access to /e2e/staging."""
    helpers.create_namespace("/e2e/prod")
    helpers.create_namespace("/e2e/staging")
    helpers.create_secret("/e2e/prod:secret", "prodval")
    helpers.create_secret("/e2e/staging:secret", "stagingval")
    helpers.create_user_account("e2e-scoped", password="ScopedPass1!", activate=True)
    token = helpers.login_as("e2e-scoped", "ScopedPass1!")

    hkey.run("rbac", "role", "create", "--name", "prod-only-role")
    hkey.run("rbac", "role", "add", "--name", "prod-only-role",
             "--rule", "allow secret:reveal to namespace /e2e/prod")
    hkey.run("rbac", "bind", "--name", "e2e-scoped", "--role", "prod-only-role")

    result = hkey.run_as(token, "secret", "reveal", "--ref", "/e2e/prod:secret")
    assert result.returncode == 0, f"/e2e/prod: {result.stderr}"

    result = hkey.run_as(token, "secret", "reveal", "--ref", "/e2e/staging:secret")
    assert result.returncode != 0, "Expected denial for /e2e/staging, got rc=0"


def test_e2e_subtree_pattern_grants_access_to_children():
    """/** pattern grants access to all child namespaces."""
    helpers.create_namespace("/e2e/org/team1")
    helpers.create_namespace("/e2e/org/team2")
    helpers.create_secret("/e2e/org/team1:key", "val1")
    helpers.create_secret("/e2e/org/team2:key", "val2")
    helpers.create_user_account("e2e-subtree", password="SubtreePass1!", activate=True)
    token = helpers.login_as("e2e-subtree", "SubtreePass1!")

    hkey.run("rbac", "role", "create", "--name", "org-subtree-role")
    hkey.run("rbac", "role", "add", "--name", "org-subtree-role",
             "--rule", "allow secret:reveal to namespace /e2e/org/**")
    hkey.run("rbac", "bind", "--name", "e2e-subtree", "--role", "org-subtree-role")

    for ns in ["/e2e/org/team1", "/e2e/org/team2"]:
        result = hkey.run_as(token, "secret", "reveal", "--ref", f"{ns}:key")
        assert result.returncode == 0, f"reveal in {ns} failed: {result.stderr}"

    # The parent /e2e/org itself is NOT covered by /**
    helpers.create_namespace("/e2e/org")
    helpers.create_secret("/e2e/org:root-key", "rootval")
    result = hkey.run_as(token, "secret", "reveal", "--ref", "/e2e/org:root-key")
    assert result.returncode != 0, "Expected denial for /e2e/org (not a child), got rc=0"


def test_e2e_multiple_roles_grant_different_namespaces():
    """User with two roles can access both namespaces."""
    helpers.create_namespace("/e2e/ns1")
    helpers.create_namespace("/e2e/ns2")
    helpers.create_secret("/e2e/ns1:key", "v1")
    helpers.create_secret("/e2e/ns2:key", "v2")
    helpers.create_user_account("e2e-multirole", password="MultiRole12!", activate=True)
    token = helpers.login_as("e2e-multirole", "MultiRole12!")

    for ns in ["/e2e/ns1", "/e2e/ns2"]:
        role_name = f"role-for-{ns.replace('/', '-').strip('-')}"
        hkey.run("rbac", "role", "create", "--name", role_name)
        hkey.run("rbac", "role", "add", "--name", role_name,
                 "--rule", f"allow secret:reveal to namespace {ns}")
        hkey.run("rbac", "bind", "--name", "e2e-multirole", "--role", role_name)

    for ns in ["/e2e/ns1", "/e2e/ns2"]:
        result = hkey.run_as(token, "secret", "reveal", "--ref", f"{ns}:key")
        assert result.returncode == 0, f"{ns} reveal failed: {result.stderr}"
