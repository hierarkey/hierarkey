import hkey
import helpers


def test_namespace_nothing_found():
    result = hkey.run("namespace", "list")
    assert result.returncode == 0
    assert "No namespaces found" in result.stdout

    data = helpers.get_namespaces_json()
    assert data['entries'] == []
    assert data['total'] == 0


def test_namespace_create_invalid():
    invalids = [
        "without_starting/slash",
        "with space",
        "with*asterisk",
        "/$special",
        "/withhash#12",
        "/with:colon",
    ]
    for invalid_name in invalids:
        result = hkey.run("namespace", "create", "--namespace", invalid_name)
        assert result.returncode != 0, f"Expected failure for '{invalid_name}'"
        assert "Invalid input:" in result.stderr or "Error:" in result.stderr, (
            f"Expected error message in stderr for '{invalid_name}', got: {result.stderr!r}"
        )


def test_namespace_create_valid():
    valids = [
        "/valid_namespace",
        "/anotherValid123",
        "/with-dash_and_underscore",
        "/UPPERlower123",
        "/123numeric_start",
    ]
    for valid_name in valids:
        result = hkey.run("namespace", "create", "--namespace", valid_name)
        assert result.returncode == 0, f"create {valid_name} failed: {result.stdout}\n{result.stderr}"

    data = helpers.get_namespaces_json()
    names = {entry["namespace"] for entry in data['entries']}
    assert names == set(valids)

    # Check basic JSON schema
    for entry in data['entries']:
        assert "short_id" in entry
        assert "namespace" in entry
        assert "status" in entry
        assert "description" in entry
        assert "labels" in entry
        assert "created_at" in entry
        assert "updated_at" in entry
        assert "active_kek_revision" in entry
        assert "latest_kek_revision" in entry
        assert "keks" in entry
        assert "secret_summary" in entry
        assert "total" in entry['secret_summary']
        assert "latest_enabled" in entry['secret_summary']
        assert "disabled" in entry['secret_summary']


def test_namespace_create_with_labels_and_description():
    ns = "/prod/app1"
    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--label", "env=prod",
        "--label", "app=app1",
        "--description", "Production namespace for app1",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    assert len(data['entries']) == 1
    entry = data['entries'][0]

    assert entry["namespace"] == ns
    assert entry["description"] == "Production namespace for app1"
    assert entry["labels"] == {"env": "prod", "app": "app1"}
    assert entry["status"] == "active"
    assert entry["active_kek_revision"] == 1
    assert entry["latest_kek_revision"] == 1
    assert entry["secret_summary"]['total'] == 0


def test_namespace_prod_and_test_list():
    for ns, env, app, desc in [
        ("/prod/app1", "prod", "app1", "Production namespace for app1"),
        ("/prod/app2", "prod", "app2", "Production namespace for app2"),
        ("/test/app1", "test", "app1", "Test namespace for app1"),
    ]:
        result = hkey.run(
            "namespace", "create",
            "--namespace", ns,
            "--label", f"env={env}",
            "--label", f"app={app}",
            "--description", desc,
        )
        assert result.returncode == 0

    data = helpers.get_namespaces_json()
    names = {n["namespace"] for n in data['entries']}
    assert names == {"/prod/app1", "/prod/app2", "/test/app1"}


def test_namespace_disable_and_enable():
    for app in ("app1", "app2", "app3"):
        result = hkey.run(
            "namespace", "create",
            "--namespace", f"/prod/{app}",
            "--label", "env=prod",
            "--label", f"app={app}",
            "--description", f"Production namespace for {app}",
        )
        assert result.returncode == 0

    # Disable /prod/app1
    result = hkey.run("namespace", "disable", "--namespace", "/prod/app1")
    assert result.returncode == 0

    # Default list: disabled namespace is hidden
    data = helpers.get_namespaces_json()
    assert helpers.find_namespace(data, "/prod/app1") is None
    assert helpers.find_namespace(data, "/prod/app2") is not None
    assert helpers.find_namespace(data, "/prod/app3") is not None

    # List including disabled
    data = helpers.get_namespaces_json("--status", "disabled")
    ns = helpers.find_namespace(data, "/prod/app1")
    assert ns is not None
    assert ns["status"] == "disabled"
    assert ns["active_kek_revision"] is None

    # Restore
    result = hkey.run("namespace", "enable", "--namespace", "/prod/app1")
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    ns = helpers.find_namespace(data, "/prod/app1")
    assert ns is not None
    assert ns["status"] == "active"
    assert ns["active_kek_revision"] == ns["latest_kek_revision"]


def test_namespace_disable_is_idempotent():
    ns = "/test/app1"
    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--label", "env=test",
        "--label", "app=app1",
        "--description", "Test namespace for app1",
    )
    assert result.returncode == 0

    result = hkey.run("namespace", "disable", "--namespace", ns)
    assert result.returncode == 0

    # Second disable: no-op or clean error
    result = hkey.run("namespace", "disable", "--namespace", ns)
    assert result.returncode in (0, 12)

    data = helpers.get_namespaces_json("--status", "disabled")
    ns_entry = helpers.find_namespace(data, ns)
    assert ns_entry is not None
    assert ns_entry["status"] == "disabled"


def test_namespace_destroy_requires_disable_first():
    ns = "/temp/to-destroy"
    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--label", "env=test",
        "--description", "Will be destroyed in tests",
    )
    assert result.returncode == 0

    # Delete should fail while active
    result = hkey.run("namespace", "delete", "--namespace", ns, "--confirm")
    assert result.returncode == 12

    # Disable + delete
    result = hkey.run("namespace", "disable", "--namespace", ns)
    assert result.returncode == 0
    result = hkey.run("namespace", "delete", "--namespace", ns, "--confirm")
    assert result.returncode == 0

    # Should not appear anywhere
    data = helpers.get_namespaces_json()
    assert helpers.find_namespace(data, ns) is None

    data = helpers.get_namespaces_json("--status", "disabled")
    assert helpers.find_namespace(data, ns) is None

    # Restore should fail
    result = hkey.run("namespace", "enable", "--namespace", ns)
    assert result.returncode == 12


def test_namespace_recreate_after_destroy_resets_revision():
    ns = "/recreate/ns"

    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--label", "env=dev",
        "--description", "Temporary namespace for recreate test",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    first = helpers.find_namespace(data, ns)
    assert first is not None
    assert first["latest_kek_revision"] == 1

    result = hkey.run("namespace", "disable", "--namespace", ns)
    assert result.returncode == 0
    result = hkey.run("namespace", "delete", "--namespace", ns, "--confirm")
    assert result.returncode == 0

    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--label", "env=dev",
        "--description", "Recreated namespace",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(data, ns)
    assert ns_entry is not None
    assert ns_entry["status"] == "active"
    assert ns_entry["active_kek_revision"] == 1
    assert ns_entry["latest_kek_revision"] == 1


def test_namespace_update_description():
    ns = "/update/desc"

    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--description", "Initial description",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(data, ns)
    assert ns_entry["description"] == "Initial description"

    result = hkey.run(
        "namespace", "update",
        "--namespace", ns,
        "--description", "Updated description",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(data, ns)
    assert ns_entry["description"] == "Updated description"

    result = hkey.run(
        "namespace", "update",
        "--namespace", ns,
        "--clear-description",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(data, ns)
    assert ns_entry["description"] is None or ns_entry["description"] == ""


def test_namespace_update_labels():
    ns = "/update/labels"

    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--label", "env=dev",
        "--label", "app=myapp",
        "--label", "version=1.0",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(data, ns)
    assert ns_entry["labels"] == {"env": "dev", "app": "myapp", "version": "1.0"}

    # Update existing label and add new one
    result = hkey.run(
        "namespace", "update",
        "--namespace", ns,
        "--label", "env=prod",
        "--label", "team=backend",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(data, ns)
    assert ns_entry["labels"]["env"] == "prod"
    assert ns_entry["labels"]["app"] == "myapp"
    assert ns_entry["labels"]["version"] == "1.0"
    assert ns_entry["labels"]["team"] == "backend"

    # Remove specific label
    result = hkey.run(
        "namespace", "update",
        "--namespace", ns,
        "--remove-label", "version",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(data, ns)
    assert "version" not in ns_entry["labels"]
    assert ns_entry["labels"]["env"] == "prod"
    assert ns_entry["labels"]["app"] == "myapp"
    assert ns_entry["labels"]["team"] == "backend"

    # Clear all labels
    result = hkey.run(
        "namespace", "update",
        "--namespace", ns,
        "--clear-labels",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(data, ns)
    assert ns_entry["labels"] == {}


def test_namespace_update_combined():
    ns = "/update/combined"

    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--label", "env=dev",
        "--label", "app=myapp",
        "--description", "Original description",
    )
    assert result.returncode == 0

    result = hkey.run(
        "namespace", "update",
        "--namespace", ns,
        "--description", "New description",
        "--label", "env=prod",
        "--label", "owner=john",
        "--remove-label", "app",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(data, ns)
    assert ns_entry["description"] == "New description"
    assert ns_entry["labels"]["env"] == "prod"
    assert ns_entry["labels"]["owner"] == "john"
    assert "app" not in ns_entry["labels"]


def test_namespace_update_nonexistent():
    result = hkey.run(
        "namespace", "update",
        "--namespace", "/does/not/exist",
        "--description", "Test",
    )
    assert result.returncode == 12


def test_namespace_update_disabled():
    ns = "/update/disabled"

    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--label", "env=dev",
    )
    assert result.returncode == 0

    result = hkey.run("namespace", "disable", "--namespace", ns)
    assert result.returncode == 0

    # Update on a disabled namespace: may succeed or fail
    result = hkey.run(
        "namespace", "update",
        "--namespace", ns,
        "--description", "Updated while disabled",
    )
    if result.returncode == 0:
        data = helpers.get_namespaces_json("--status", "disabled")
        ns_entry = helpers.find_namespace(data, ns)
        assert ns_entry["description"] == "Updated while disabled"
    else:
        assert result.returncode == 12


def test_namespace_update_remove_multiple_labels():
    ns = "/update/multi-remove"

    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--label", "env=dev",
        "--label", "app=myapp",
        "--label", "version=1.0",
        "--label", "owner=alice",
        "--label", "team=backend",
    )
    assert result.returncode == 0

    result = hkey.run(
        "namespace", "update",
        "--namespace", ns,
        "--remove-label", "version",
        "--remove-label", "owner",
        "--remove-label", "team",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(data, ns)
    assert ns_entry["labels"] == {"env": "dev", "app": "myapp"}


def test_namespace_update_label_edge_cases():
    ns = "/update/edge"

    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--label", "env=dev",
    )
    assert result.returncode == 0

    # Remove non-existent label: should be idempotent (0) or a clean error (12)
    result = hkey.run(
        "namespace", "update",
        "--namespace", ns,
        "--remove-label", "does_not_exist",
    )
    assert result.returncode in (0, 12)


def test_namespace_update_description_and_clear_description_conflict():
    ns = "/update/conflict"

    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--description", "Original",
    )
    assert result.returncode == 0

    # --description and --clear-description are mutually exclusive
    result = hkey.run(
        "namespace", "update",
        "--namespace", ns,
        "--description", "New description",
        "--clear-description",
    )
    assert result.returncode != 0


def test_namespace_update_labels_and_clear_labels():
    ns = "/update/clear-conflict"

    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--label", "env=dev",
    )
    assert result.returncode == 0

    # --clear-labels + --label: clears existing and applies the new ones
    result = hkey.run(
        "namespace", "update",
        "--namespace", ns,
        "--clear-labels",
        "--label", "env=prod",
        "--label", "team=frontend",
    )
    assert result.returncode == 0

    data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(data, ns)
    assert ns_entry["labels"] == {"env": "prod", "team": "frontend"}


def test_namespace_search_no_query():
    """Search without a query returns all active namespaces."""
    for ns in ("/search/alpha", "/search/beta", "/other/gamma"):
        hkey.run("namespace", "create", "--namespace", ns)

    result = hkey.run("namespace", "search", "--json")
    assert result.returncode == 0, f"namespace search failed: {result.stderr}"
    import json
    data = json.loads(result.stdout)
    names = {e["namespace"] for e in data["entries"]}
    assert "/search/alpha" in names
    assert "/search/beta" in names
    assert "/other/gamma" in names


def test_namespace_search_with_query():
    """Search with a query filters results by prefix."""
    for ns in ("/prefix/one", "/prefix/two", "/other/three"):
        hkey.run("namespace", "create", "--namespace", ns)

    result = hkey.run("namespace", "search", "--query", "/prefix", "--json")
    assert result.returncode == 0, f"namespace search failed: {result.stderr}"
    import json
    data = json.loads(result.stdout)
    names = {e["namespace"] for e in data["entries"]}
    assert "/prefix/one" in names
    assert "/prefix/two" in names
    assert "/other/three" not in names


def test_namespace_search_no_results():
    """Search with a query that matches nothing returns an empty list."""
    result = hkey.run("namespace", "search", "--query", "/does/not/exist/at/all", "--json")
    assert result.returncode == 0
    import json
    data = json.loads(result.stdout)
    assert data["entries"] == []


def test_namespace_search_plain_output():
    """Plain search output has column headers."""
    hkey.run("namespace", "create", "--namespace", "/plain/search")
    result = hkey.run("namespace", "search")
    assert result.returncode == 0
    assert "NAMESPACE" in result.stdout


def test_namespace_update_no_changes():
    ns = "/update/nochange"

    result = hkey.run(
        "namespace", "create",
        "--namespace", ns,
        "--description", "Test",
        "--label", "env=dev",
    )
    assert result.returncode == 0

    # Update without any changes (may succeed or require at least one flag)
    hkey.run("namespace", "update", "--namespace", ns)

    # Either way, verify nothing changed
    data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(data, ns)
    assert ns_entry["description"] == "Test"
    assert ns_entry["labels"] == {"env": "dev"}
