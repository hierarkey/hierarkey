import json
import hkey

# ------------------------------------------------------------------------------------------

def clear_all_namespaces():
    """Disable + destroy all namespaces that are currently visible."""
    result = hkey.run("namespace", "list", "--json", "--all", "--limit", "1000")
    assert result.returncode == 0

    data = json.loads(result.stdout)
    for entry in data['entries']:
        if entry["status"] in ("destroyed", "deleted"):
            continue

        print(f"Processing namespace {entry['namespace']} with status {entry['status']}")
        ns = entry["namespace"]

        # Disable if still active
        if entry["status"] == "active":
            print(f"Disabling namespace {ns}...")
            result = hkey.run("namespace", "disable", "--namespace", ns)
            assert result.returncode == 0

        # Hard delete (--delete-secrets in case the namespace still has secrets)
        result = hkey.run("namespace", "delete", "--namespace", ns, "--confirm", "--delete-secrets")
        assert result.returncode == 0


def get_namespaces_json(*extra_args):
    """Helper to list namespaces as JSON."""
    args = ["namespace", "list", "--json", *extra_args]
    result = hkey.run(*args)
    assert result.returncode == 0, f"list failed: {result.stdout}\n{result.stderr}"
    stdout = result.stdout.strip()
    if not stdout:
        return []
    return json.loads(stdout)


def get_accounts_json(*extra_args):
    """Helper to list accounts as JSON."""
    args = ["account", "list", "--all", "--json", *extra_args]
    result = hkey.run(*args)
    assert result.returncode == 0, f"list failed: {result.stdout}\n{result.stderr}"
    stdout = result.stdout.strip()
    if not stdout:
        return []
    return json.loads(stdout)


def find_namespace(data, ns):
    """Helper to find a namespace entry by name in a list."""
    return next((n for n in data['entries'] if n["namespace"] == ns), None)


def create_namespace(ns, **kwargs):
    """Helper to create a namespace."""
    args = ["namespace", "create", "--namespace", ns]
    if "description" in kwargs:
        args.extend(["--description", kwargs["description"]])
    for label in kwargs.get("labels", []):
        args.extend(["--label", label])
    result = hkey.run(*args)
    assert result.returncode == 0, f"Failed to create namespace {ns}: {result.stderr}"


# ------------------------------------------------------------------------------------------


def get_secrets_json(namespace, *extra_args):
    """Helper to list secrets as JSON."""
    args = ["secret", "list", "--namespace", namespace, "--json", *extra_args]
    result = hkey.run(*args)
    assert result.returncode == 0, f"list failed: {result.stdout}\n{result.stderr}"
    stdout = result.stdout.strip()
    if not stdout:
        return []
    return json.loads(stdout)


def find_secret(data, path):
    """Helper to find a secret entry by path in a list."""
    return next((s for s in data['entries'] if s["ref_key"] == path), None)


def create_secret(ref, value, **kwargs):
    """Helper to create a secret."""
    args = ["secret", "create", "--ref", ref]

    if "value" in kwargs:
        args.extend(["--value", kwargs["value"]])
    elif "value_hex" in kwargs:
        args.extend(["--value-hex", kwargs["value_hex"]])
    elif "value_base64" in kwargs:
        args.extend(["--value-base64", kwargs["value_base64"]])
    else:
        args.extend(["--value", value])

    if "description" in kwargs:
        args.extend(["--description", kwargs["description"]])
    for label in kwargs.get("labels", []):
        args.extend(["--label", label])

    result = hkey.run(*args)
    assert result.returncode == 0, f"Failed to create secret {ref}: {result.stderr}"
    return result


# ------------------------------------------------------------------------------------------

def clear_all_pats():
    """Revoke all non-session PATs (created by tests, not Login access/refresh tokens)."""
    result = hkey.run("pat", "list", "--json")
    if result.returncode == 0 and result.stdout.strip():
        pats = json.loads(result.stdout)
        for pat in pats:
            if pat.get("revoked_at") is None and not pat.get("description", "").startswith(("Login ", "Refreshed ")):
                hkey.run("pat", "revoke", "--id", pat["id"])


def clear_all_rbac():
    """Delete all non-system RBAC roles and orphaned rules."""
    result = hkey.run("rbac", "role", "list", "--json")
    if result.returncode == 0 and result.stdout.strip():
        roles = json.loads(result.stdout)
        for role in roles:
            if not role.get('is_system', True):
                hkey.run("rbac", "role", "delete", "--name", role['name'], "--force")

    result = hkey.run("rbac", "rule", "list", "--json")
    if result.returncode == 0 and result.stdout.strip():
        rules = json.loads(result.stdout)
        for rule in rules:
            if rule.get('role_count', 1) == 0 and rule.get('account_count', 1) == 0:
                hkey.run("rbac", "rule", "delete", "--id", rule['id'])


def create_user_account(name, password="SecurePassword1!", activate=False):
    """Create a user account, re-using it if it already exists."""
    args = ["account", "create", "--type", "user", "--name", name, "--insecure-password", password]
    if activate:
        args.append("--activate")
    result = hkey.run(*args)
    if result.returncode != 0:
        if "name already exists" in result.stderr:
            if activate:
                hkey.run("account", "enable", "--name", name)
        else:
            assert False, f"Failed to create account {name}: {result.stderr}"


def login_as(name, password):
    """Log in as a user and return the access token."""
    result = hkey.run_unauth("auth", "login", "--name", name, "--insecure-password", password, "--json")
    assert result.returncode == 0, f"login as {name} failed: {result.stderr}"
    data = json.loads(result.stdout)
    token = data.get("access_token")
    assert token is not None, f"No access_token in login response for {name}"
    return token


# ------------------------------------------------------------------------------------------

def account_describe(account_name):
    """Helper to describe an account and return JSON data."""
    args = ["account", "describe", "--name", account_name, "--json"]
    result = hkey.run(*args)
    assert result.returncode == 0, f"describe failed: {result.stdout}\n{result.stderr}"
    stdout = result.stdout.strip()
    if not stdout:
        return []
    data = json.loads(stdout)
    return data