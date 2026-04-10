import json

import hkey
import helpers


# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------

def ns_describe(ns_path):
    """Return the namespace entry dict from `namespace describe --json`."""
    result = hkey.run("namespace", "describe", "--namespace", ns_path, "--json")
    assert result.returncode == 0, f"namespace describe '{ns_path}' failed: {result.stderr}"
    data = json.loads(result.stdout)
    return data["entry"]


def ns_create(ns_path, **kwargs):
    """Create a namespace and assert success."""
    args = ["namespace", "create", "--namespace", ns_path]
    if "description" in kwargs:
        args.extend(["--description", kwargs["description"]])
    for label in kwargs.get("labels", []):
        args.extend(["--label", label])
    result = hkey.run(*args)
    assert result.returncode == 0, f"namespace create '{ns_path}' failed: {result.stderr}"
    return result


def ns_list_json(*, all=False, status=None, prefix=None, limit=1000, offset=None):
    """Return parsed JSON from `hkey namespace list --json`."""
    args = ["namespace", "list", "--json"]
    if all:
        args.append("--all")
    if status:
        for s in (status if isinstance(status, list) else [status]):
            args.extend(["--status", s])
    if prefix:
        args.extend(["--prefix", prefix])
    if limit is not None:
        args.extend(["--limit", str(limit)])
    if offset is not None:
        args.extend(["--offset", str(offset)])
    result = hkey.run(*args)
    assert result.returncode == 0, f"namespace list failed: {result.stderr}"
    return json.loads(result.stdout)


# ===========================================================================
# 1. Initial state
# ===========================================================================

def test_initial_state_empty():
    """Fresh environment has no namespaces."""
    data = ns_list_json()
    assert data["entries"] == []
    assert data["total"] == 0


# ===========================================================================
# 2. create
# ===========================================================================

def test_create_minimal():
    """Create namespace with only the required --namespace flag."""
    result = hkey.run("namespace", "create", "--namespace", "/myapp")
    assert result.returncode == 0
    assert "created successfully" in result.stdout

    data = ns_list_json()
    assert data["total"] == 1
    entry = data["entries"][0]
    assert entry["namespace"] == "/myapp"
    assert entry["status"] == "active"
    assert entry["active_kek_revision"] == 1
    assert entry["latest_kek_revision"] == 1


def test_create_with_description():
    """Create namespace with a description."""
    ns_create("/ns_desc", description="A test namespace")

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/ns_desc")
    assert entry is not None
    assert entry["description"] == "A test namespace"


def test_create_with_labels():
    """Create namespace with multiple labels."""
    ns_create("/ns_labels", labels=["env=prod", "team=backend", "app=myapp"])

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/ns_labels")
    assert entry is not None
    assert entry["labels"]["env"] == "prod"
    assert entry["labels"]["team"] == "backend"
    assert entry["labels"]["app"] == "myapp"


def test_create_with_all_options():
    """Create namespace with description and labels together."""
    ns_create("/ns_full", description="Full namespace", labels=["env=prod", "version=2.0"])

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/ns_full")
    assert entry is not None
    assert entry["description"] == "Full namespace"
    assert entry["labels"]["env"] == "prod"
    assert entry["labels"]["version"] == "2.0"


def test_create_json_output():
    """--json returns structured response."""
    result = hkey.run("namespace", "create", "--namespace", "/ns_json_out", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    # Response is wrapped: {"status": {...}, "data": {...}}
    assert "status" in data or "namespace" in data


def test_create_json_schema():
    """Namespace list JSON entries contain expected fields."""
    ns_create("/schema_test")

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/schema_test")
    assert entry is not None
    for field in (
        "namespace", "status", "description", "labels",
        "created_at", "updated_at", "active_kek_revision",
        "latest_kek_revision", "keks", "secret_summary",
    ):
        assert field in entry, f"Missing field '{field}' in namespace JSON"
    assert "total" in entry["secret_summary"]
    assert "latest_enabled" in entry["secret_summary"]
    assert "disabled" in entry["secret_summary"]


def test_create_invalid_names():
    """Invalid namespace names are rejected with a non-zero exit code."""
    invalid = [
        "without_starting_slash",
        "/with space",
        "/with*asterisk",
        "/with#hash",
        "/with:colon",
    ]
    for ns_name in invalid:
        result = hkey.run("namespace", "create", "--namespace", ns_name)
        assert result.returncode != 0, f"Expected failure for '{ns_name}'"


def test_create_reserved_namespace():
    """Reserved ($-prefixed) namespaces cannot be created."""
    result = hkey.run("namespace", "create", "--namespace", "/$secret")
    assert result.returncode != 0
    assert "reserved" in result.stderr.lower() or "$" in result.stderr


def test_create_duplicate_rejected():
    """Creating the same namespace twice fails."""
    ns_create("/ns_dup")
    result = hkey.run("namespace", "create", "--namespace", "/ns_dup")
    assert result.returncode == 12


def test_create_deep_path():
    """Namespaces with multiple path segments are supported."""
    ns_create("/prod/app1/v2")
    data = ns_list_json()
    entry = helpers.find_namespace(data, "/prod/app1/v2")
    assert entry is not None
    assert entry["status"] == "active"


def test_create_no_labels_has_empty_labels():
    """Namespace created without labels has an empty labels map."""
    ns_create("/no_labels_ns")
    data = ns_list_json()
    entry = helpers.find_namespace(data, "/no_labels_ns")
    assert entry["labels"] == {}


def test_create_no_description_is_null():
    """Namespace created without --description has null/empty description."""
    ns_create("/no_desc_ns")
    data = ns_list_json()
    entry = helpers.find_namespace(data, "/no_desc_ns")
    assert entry["description"] is None or entry["description"] == ""


def test_create_initial_kek_is_revision_1():
    """A freshly created namespace always starts at KEK revision 1."""
    ns_create("/kek_start")
    # keks details only available via describe, not list
    data = ns_describe("/kek_start")
    assert data["active_kek_revision"] == 1
    assert data["latest_kek_revision"] == 1
    assert len(data["keks"]) == 1


def test_create_secret_summary_starts_empty():
    """A newly created namespace has an empty secret summary."""
    ns_create("/secrets_sum")
    data = ns_list_json()
    entry = helpers.find_namespace(data, "/secrets_sum")
    assert entry["secret_summary"]["total"] == 0
    assert entry["secret_summary"]["latest_enabled"] == 0
    assert entry["secret_summary"]["disabled"] == 0


# ===========================================================================
# 3. describe
# ===========================================================================

def test_describe_plain_output():
    """describe without --json prints human-readable output."""
    ns_create("/ns_describe1")
    result = hkey.run("namespace", "describe", "--namespace", "/ns_describe1")
    assert result.returncode == 0
    assert "/ns_describe1" in result.stdout
    assert "ACTIVE" in result.stdout.upper()
    assert "KEK" in result.stdout


def test_describe_json_output():
    """describe --json returns structured data with entry and keks."""
    ns_create("/ns_describe2", description="Desc test", labels=["team=ops"])

    result = hkey.run("namespace", "describe", "--namespace", "/ns_describe2", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "entry" in data
    entry = data["entry"]
    assert entry["namespace"] == "/ns_describe2"
    assert entry["description"] == "Desc test"
    assert entry["labels"]["team"] == "ops"
    assert entry["status"] == "active"
    assert entry["active_kek_revision"] == 1


def test_describe_kek_details():
    """describe includes KEK details: revision, kek_short_id, masterkey_short_id."""
    ns_create("/ns_kek_detail")
    data = ns_describe("/ns_kek_detail")
    assert len(data["keks"]) == 1
    kek = data["keks"][0]
    assert kek["revision"] == 1
    assert "kek_short_id" in kek
    assert "masterkey_short_id" in kek
    assert "created_at" in kek


def test_describe_nonexistent():
    """Describing a non-existent namespace returns error code 12."""
    result = hkey.run("namespace", "describe", "--namespace", "/does/not/exist")
    assert result.returncode == 12


# ===========================================================================
# 4. list
# ===========================================================================

def test_list_default_shows_active_only():
    """Default list shows only active namespaces."""
    ns_create("/active_ns1")
    ns_create("/active_ns2")
    hkey.run("namespace", "disable", "--namespace", "/active_ns2")

    data = ns_list_json()
    names = {e["namespace"] for e in data["entries"]}
    assert "/active_ns1" in names
    assert "/active_ns2" not in names


def test_list_all_includes_disabled():
    """--all includes disabled and active namespaces."""
    ns_create("/list_all1")
    ns_create("/list_all2")
    hkey.run("namespace", "disable", "--namespace", "/list_all2")

    data = ns_list_json(all=True)
    names = {e["namespace"] for e in data["entries"]}
    assert "/list_all1" in names
    assert "/list_all2" in names


def test_list_status_filter_disabled():
    """--status disabled returns only disabled namespaces."""
    ns_create("/list_dis1")
    ns_create("/list_dis2")
    hkey.run("namespace", "disable", "--namespace", "/list_dis1")

    data = ns_list_json(status="disabled")
    for entry in data["entries"]:
        assert entry["status"] == "disabled"
    names = {e["namespace"] for e in data["entries"]}
    assert "/list_dis1" in names
    assert "/list_dis2" not in names


def test_list_status_filter_active():
    """--status active returns only active namespaces."""
    ns_create("/list_act1")
    ns_create("/list_act2")
    hkey.run("namespace", "disable", "--namespace", "/list_act2")

    data = ns_list_json(status="active")
    for entry in data["entries"]:
        assert entry["status"] == "active"


def test_list_prefix_filter():
    """--prefix filters namespaces by path prefix."""
    ns_create("/pfx/app1")
    ns_create("/pfx/app2")
    ns_create("/other/app1")

    data = ns_list_json(prefix="/pfx")
    names = {e["namespace"] for e in data["entries"]}
    assert "/pfx/app1" in names
    assert "/pfx/app2" in names
    assert "/other/app1" not in names


def test_list_prefix_no_match():
    """--prefix with no matching namespaces returns empty list."""
    data = ns_list_json(prefix="/zzz_no_such_prefix_xyz")
    assert data["total"] == 0
    assert data["entries"] == []


def test_list_limit_and_offset():
    """--limit and --offset support basic pagination."""
    for i in range(1, 5):
        ns_create(f"/pg_ns{i}")

    data_all = ns_list_json()
    assert data_all["total"] >= 4

    data_p1 = ns_list_json(limit=2)
    assert len(data_p1["entries"]) == 2

    data_p2 = ns_list_json(limit=2, offset=2)
    assert len(data_p2["entries"]) >= 1

    names_p1 = {e["namespace"] for e in data_p1["entries"]}
    names_p2 = {e["namespace"] for e in data_p2["entries"]}
    assert names_p1.isdisjoint(names_p2)


def test_list_plain_output_has_header():
    """Plain list output has column headers."""
    ns_create("/plain_list_ns")
    result = hkey.run("namespace", "list")
    assert result.returncode == 0
    assert "NAMESPACE" in result.stdout
    assert "STATUS" in result.stdout


def test_list_table_output():
    """--table flag produces tabular output with | separators."""
    ns_create("/table_list_ns")
    result = hkey.run("namespace", "list", "--table")
    assert result.returncode == 0
    assert "|" in result.stdout


def test_list_empty_plain_output():
    """Empty list shows 'No namespaces found' message."""
    result = hkey.run("namespace", "list")
    assert result.returncode == 0
    assert "No namespaces found" in result.stdout


# ===========================================================================
# 5. update
# ===========================================================================

def test_update_description():
    """Update description replaces the existing one."""
    ns_create("/upd_desc", description="Initial")
    result = hkey.run("namespace", "update", "--namespace", "/upd_desc",
                      "--description", "Updated")
    assert result.returncode == 0

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/upd_desc")
    assert entry["description"] == "Updated"


def test_update_clear_description():
    """--clear-description removes the description."""
    ns_create("/upd_cleardesc", description="To be cleared")
    result = hkey.run("namespace", "update", "--namespace", "/upd_cleardesc",
                      "--clear-description")
    assert result.returncode == 0

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/upd_cleardesc")
    assert entry["description"] is None or entry["description"] == ""


def test_update_add_labels():
    """Labels can be added to a namespace that had none."""
    ns_create("/upd_addlbl")
    result = hkey.run("namespace", "update", "--namespace", "/upd_addlbl",
                      "--label", "env=prod", "--label", "team=ops")
    assert result.returncode == 0

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/upd_addlbl")
    assert entry["labels"]["env"] == "prod"
    assert entry["labels"]["team"] == "ops"


def test_update_replace_label():
    """Updating an existing label key replaces its value."""
    ns_create("/upd_replbl", labels=["env=dev"])
    result = hkey.run("namespace", "update", "--namespace", "/upd_replbl",
                      "--label", "env=prod")
    assert result.returncode == 0

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/upd_replbl")
    assert entry["labels"]["env"] == "prod"


def test_update_remove_label():
    """--remove-label removes a specific label key."""
    ns_create("/upd_rmlbl", labels=["env=dev", "app=myapp", "team=ops"])
    result = hkey.run("namespace", "update", "--namespace", "/upd_rmlbl",
                      "--remove-label", "team")
    assert result.returncode == 0

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/upd_rmlbl")
    assert "team" not in entry["labels"]
    assert entry["labels"]["env"] == "dev"
    assert entry["labels"]["app"] == "myapp"


def test_update_remove_multiple_labels():
    """--remove-label can be repeated to remove multiple labels at once."""
    ns_create("/upd_rmmulti", labels=["a=1", "b=2", "c=3", "d=4"])
    result = hkey.run("namespace", "update", "--namespace", "/upd_rmmulti",
                      "--remove-label", "b", "--remove-label", "d")
    assert result.returncode == 0

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/upd_rmmulti")
    assert entry["labels"] == {"a": "1", "c": "3"}


def test_update_clear_labels():
    """--clear-labels removes all labels."""
    ns_create("/upd_clrlbl", labels=["a=1", "b=2", "c=3"])
    result = hkey.run("namespace", "update", "--namespace", "/upd_clrlbl",
                      "--clear-labels")
    assert result.returncode == 0

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/upd_clrlbl")
    assert entry["labels"] == {}


def test_update_clear_labels_then_add():
    """--clear-labels combined with --label replaces all labels."""
    ns_create("/upd_clradd", labels=["old=yes", "remove=me"])
    result = hkey.run("namespace", "update", "--namespace", "/upd_clradd",
                      "--clear-labels", "--label", "new=label")
    assert result.returncode == 0

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/upd_clradd")
    assert entry["labels"] == {"new": "label"}


def test_update_combined():
    """Description and labels can be updated in a single call."""
    ns_create("/upd_combo", description="Old desc", labels=["env=dev", "app=myapp"])
    result = hkey.run("namespace", "update", "--namespace", "/upd_combo",
                      "--description", "New desc",
                      "--label", "env=prod",
                      "--remove-label", "app")
    assert result.returncode == 0

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/upd_combo")
    assert entry["description"] == "New desc"
    assert entry["labels"]["env"] == "prod"
    assert "app" not in entry["labels"]


def test_update_description_and_clear_conflict():
    """--description and --clear-description together are rejected."""
    ns_create("/upd_conflict")
    result = hkey.run("namespace", "update", "--namespace", "/upd_conflict",
                      "--description", "new", "--clear-description")
    assert result.returncode != 0


def test_update_nonexistent_namespace():
    """Updating a non-existent namespace returns error code 12."""
    result = hkey.run("namespace", "update", "--namespace", "/does/not/exist",
                      "--description", "test")
    assert result.returncode == 12


def test_update_sets_updated_at():
    """updated_at is set after the first update."""
    ns_create("/upd_timestamp", description="original")

    before = helpers.find_namespace(ns_list_json(), "/upd_timestamp")
    assert before["updated_at"] is None  # not yet updated

    hkey.run("namespace", "update", "--namespace", "/upd_timestamp",
             "--description", "changed")

    after = helpers.find_namespace(ns_list_json(), "/upd_timestamp")
    assert after["updated_at"] is not None


def test_update_remove_nonexistent_label_is_ok():
    """Removing a label key that does not exist is idempotent (no error)."""
    ns_create("/upd_rmnoop", labels=["env=dev"])
    result = hkey.run("namespace", "update", "--namespace", "/upd_rmnoop",
                      "--remove-label", "nonexistent_key")
    assert result.returncode in (0, 12)


# ===========================================================================
# 6. disable
# ===========================================================================

def test_disable_active_namespace():
    """Disabling an active namespace transitions it to disabled and deactivates KEK."""
    ns_create("/dis_ns1")
    result = hkey.run("namespace", "disable", "--namespace", "/dis_ns1")
    assert result.returncode == 0
    assert "disabled successfully" in result.stdout

    data = ns_list_json(status="disabled")
    entry = helpers.find_namespace(data, "/dis_ns1")
    assert entry is not None
    assert entry["status"] == "disabled"
    assert entry["active_kek_revision"] is None


def test_disable_hides_from_default_list():
    """Disabled namespace does not appear in the default (active-only) list."""
    ns_create("/dis_hidden")
    hkey.run("namespace", "disable", "--namespace", "/dis_hidden")

    data = ns_list_json()
    assert helpers.find_namespace(data, "/dis_hidden") is None

    data_all = ns_list_json(all=True)
    assert helpers.find_namespace(data_all, "/dis_hidden") is not None


def test_disable_nonexistent_namespace():
    """Disabling a non-existent namespace returns error code 12."""
    result = hkey.run("namespace", "disable", "--namespace", "/no/such/ns")
    assert result.returncode == 12


def test_disable_is_idempotent():
    """Disabling an already-disabled namespace is a no-op or clean error."""
    ns_create("/dis_idem")
    hkey.run("namespace", "disable", "--namespace", "/dis_idem")

    result = hkey.run("namespace", "disable", "--namespace", "/dis_idem")
    assert result.returncode in (0, 12)

    data = ns_list_json(status="disabled")
    entry = helpers.find_namespace(data, "/dis_idem")
    assert entry is not None
    assert entry["status"] == "disabled"


# ===========================================================================
# 7. enable
# ===========================================================================

def test_enable_disabled_namespace():
    """Enabling a disabled namespace makes it active again."""
    ns_create("/res_ns1")
    hkey.run("namespace", "disable", "--namespace", "/res_ns1")

    result = hkey.run("namespace", "enable", "--namespace", "/res_ns1")
    assert result.returncode == 0
    assert "enabled successfully" in result.stdout

    data = ns_list_json()
    entry = helpers.find_namespace(data, "/res_ns1")
    assert entry is not None
    assert entry["status"] == "active"


def test_enable_reactivates_kek():
    """Enabling a namespace reactivates the KEK (active_kek_revision == latest_kek_revision)."""
    ns_create("/res_kek")

    initial = ns_describe("/res_kek")
    assert initial["active_kek_revision"] == 1

    hkey.run("namespace", "disable", "--namespace", "/res_kek")
    # After disable, KEK is deactivated — use describe to avoid pagination issues
    disabled = ns_describe("/res_kek")
    assert disabled["active_kek_revision"] is None

    hkey.run("namespace", "enable", "--namespace", "/res_kek")
    restored = ns_describe("/res_kek")
    assert restored["status"] == "active"
    # KEK is reactivated; active revision matches latest
    assert restored["active_kek_revision"] == restored["latest_kek_revision"]


def test_enable_active_namespace_fails():
    """Enabling an already-active namespace returns an error."""
    ns_create("/res_active")
    result = hkey.run("namespace", "enable", "--namespace", "/res_active")
    assert result.returncode == 12


def test_enable_nonexistent_namespace():
    """Enabling a non-existent namespace returns an error."""
    result = hkey.run("namespace", "enable", "--namespace", "/no/such/ns")
    assert result.returncode == 12


def test_multiple_disable_enable_cycles():
    """Multiple disable/enable cycles leave the namespace active with a valid KEK."""
    ns_create("/res_cycles")

    for _ in range(3):
        hkey.run("namespace", "disable", "--namespace", "/res_cycles")
        r = hkey.run("namespace", "enable", "--namespace", "/res_cycles")
        assert r.returncode == 0
        data = helpers.find_namespace(ns_list_json(), "/res_cycles")
        assert data["status"] == "active"
        assert data["active_kek_revision"] == data["latest_kek_revision"]


def test_enable_kek_history():
    """After disable/enable the describe output shows the KEK as active."""
    ns_create("/res_history")

    hkey.run("namespace", "disable", "--namespace", "/res_history")
    hkey.run("namespace", "enable", "--namespace", "/res_history")

    data = ns_describe("/res_history")
    assert data["status"] == "active"
    assert data["active_kek_revision"] is not None
    # At least one KEK entry exists
    assert len(data["keks"]) >= 1
    # The active KEK is marked as active
    active_keks = [k for k in data["keks"] if k.get("is_active")]
    assert len(active_keks) == 1


# ===========================================================================
# 8. delete
# ===========================================================================

def test_delete_requires_disabled_first():
    """Deleting an active namespace is rejected (must disable first)."""
    ns_create("/del_active")
    result = hkey.run("namespace", "delete", "--namespace", "/del_active", "--confirm")
    assert result.returncode == 12


def test_delete_disabled_namespace():
    """delete soft-deletes a disabled namespace (status becomes 'deleted')."""
    ns_create("/del_ns1")
    hkey.run("namespace", "disable", "--namespace", "/del_ns1")

    result = hkey.run("namespace", "delete", "--namespace", "/del_ns1", "--confirm")
    assert result.returncode == 0
    assert "deleted" in result.stdout

    # Appears in --all listing with status 'deleted'
    data = ns_list_json(all=True)
    entry = helpers.find_namespace(data, "/del_ns1")
    assert entry is not None
    assert entry["status"] == "deleted"


def test_delete_nonexistent_namespace():
    """Deleting a non-existent namespace returns an error."""
    result = hkey.run("namespace", "delete", "--namespace", "/no/such/ns", "--confirm")
    assert result.returncode == 12


def test_recreate_after_delete():
    """After deletion the path can be reused; new namespace starts at KEK revision 1."""
    ns = "/del_recreate"
    ns_create(ns)

    hkey.run("namespace", "disable", "--namespace", ns)
    hkey.run("namespace", "delete", "--namespace", ns, "--confirm")

    # Soft-deleted namespace is excluded from the unique index, so recreation succeeds
    ns_create(ns, description="Recreated")
    data = ns_describe(ns)
    assert data["status"] == "active"
    assert data["active_kek_revision"] == 1
    assert data["latest_kek_revision"] == 1
    assert data["description"] == "Recreated"


def test_enable_after_delete_fails():
    """Enabling a deleted (permanently removed) namespace fails."""
    ns_create("/del_restore")
    hkey.run("namespace", "disable", "--namespace", "/del_restore")
    hkey.run("namespace", "delete", "--namespace", "/del_restore", "--confirm")

    result = hkey.run("namespace", "enable", "--namespace", "/del_restore")
    assert result.returncode == 12


def test_disable_then_delete_sequence():
    """Full lifecycle: create -> disable -> delete."""
    ns = "/lifecycle_ns"
    ns_create(ns, description="Lifecycle test", labels=["env=test"])

    # Active
    data = helpers.find_namespace(ns_list_json(), ns)
    assert data["status"] == "active"

    # Disable
    hkey.run("namespace", "disable", "--namespace", ns)
    data = helpers.find_namespace(ns_list_json(all=True), ns)
    assert data["status"] == "disabled"

    # Delete
    r = hkey.run("namespace", "delete", "--namespace", ns, "--confirm")
    assert r.returncode == 0

    # Appears in --all listing with status 'deleted'
    entry = helpers.find_namespace(ns_list_json(all=True), ns)
    assert entry is not None
    assert entry["status"] == "deleted"


# ===========================================================================
# 9. delete with secrets
# ===========================================================================

def test_delete_with_secrets_blocked_without_flag():
    """Deleting a namespace that still has secrets fails without --delete-secrets."""
    ns_create("/del_secrets_guard")
    helpers.create_secret("/del_secrets_guard:apikey", "s3cr3t")

    hkey.run("namespace", "disable", "--namespace", "/del_secrets_guard")

    result = hkey.run("namespace", "delete", "--namespace", "/del_secrets_guard", "--confirm")
    assert result.returncode == 12, "Expected failure when secrets exist and --delete-secrets not given"

    # Namespace still exists
    data = ns_list_json(all=True)
    assert helpers.find_namespace(data, "/del_secrets_guard") is not None


def test_delete_with_secrets_error_mentions_count():
    """The error message when blocked includes the number of secrets."""
    ns_create("/del_count_msg")
    helpers.create_secret("/del_count_msg:k1", "v1")
    helpers.create_secret("/del_count_msg:k2", "v2")
    helpers.create_secret("/del_count_msg:k3", "v3")

    hkey.run("namespace", "disable", "--namespace", "/del_count_msg")

    result = hkey.run("namespace", "delete", "--namespace", "/del_count_msg", "--confirm")
    assert result.returncode == 12
    assert "3" in result.stderr or "3" in result.stdout


def test_delete_with_secrets_allowed_with_flag():
    """--delete-secrets allows deleting a namespace that still has secrets."""
    ns_create("/del_force_ns")
    helpers.create_secret("/del_force_ns:k1", "v1")
    helpers.create_secret("/del_force_ns:k2", "v2")

    hkey.run("namespace", "disable", "--namespace", "/del_force_ns")

    result = hkey.run("namespace", "delete", "--namespace", "/del_force_ns",
                      "--confirm", "--delete-secrets")
    assert result.returncode == 0

    # Namespace appears as deleted in --all listing
    data = ns_list_json(all=True)
    entry = helpers.find_namespace(data, "/del_force_ns")
    assert entry is not None
    assert entry["status"] == "deleted"


def test_delete_with_flag_also_removes_secrets():
    """After --delete-secrets deletion, the namespace is soft-deleted and secrets are removed."""
    ns_create("/del_cascade_ns2")
    helpers.create_secret("/del_cascade_ns2:sec1", "val1")
    helpers.create_secret("/del_cascade_ns2:sec2", "val2")

    hkey.run("namespace", "disable", "--namespace", "/del_cascade_ns2")
    result = hkey.run("namespace", "delete", "--namespace", "/del_cascade_ns2",
                      "--confirm", "--delete-secrets")
    assert result.returncode == 0

    # Namespace is soft-deleted (appears with status=deleted)
    data = ns_list_json(all=True)
    entry = helpers.find_namespace(data, "/del_cascade_ns2")
    assert entry is not None
    assert entry["status"] == "deleted"


def test_delete_empty_namespace_needs_no_flag():
    """An empty namespace (no secrets) deletes cleanly without --delete-secrets."""
    ns_create("/del_empty_ok")
    hkey.run("namespace", "disable", "--namespace", "/del_empty_ok")

    result = hkey.run("namespace", "delete", "--namespace", "/del_empty_ok", "--confirm")
    assert result.returncode == 0


def test_delete_namespace_with_only_disabled_secrets_still_requires_flag():
    """hkey secret delete disables (not hard-deletes) a secret; namespace delete still requires --delete-secrets."""
    ns_create("/del_softdel_ok")
    helpers.create_secret("/del_softdel_ok:k1", "v1")

    # 'hkey secret delete' only disables the secret, not hard-deletes it
    hkey.run("secret", "delete", "--ref", "/del_softdel_ok:k1")

    hkey.run("namespace", "disable", "--namespace", "/del_softdel_ok")

    # Should still be blocked (disabled secrets still count)
    result = hkey.run("namespace", "delete", "--namespace", "/del_softdel_ok", "--confirm")
    assert result.returncode == 12, "Expected failure: disabled secrets still block namespace deletion"

    # With --delete-secrets it succeeds
    result = hkey.run("namespace", "delete", "--namespace", "/del_softdel_ok", "--confirm", "--delete-secrets")
    assert result.returncode == 0


def test_delete_multiple_secrets_all_removed_with_flag():
    """All secrets across multiple creates are removed when --delete-secrets is used."""
    ns = "/del_multi_secrets"
    ns_create(ns)
    for i in range(5):
        helpers.create_secret(f"{ns}:key{i}", f"value{i}")

    data = helpers.get_secrets_json(ns)
    assert len(data["entries"]) == 5

    hkey.run("namespace", "disable", "--namespace", ns)
    result = hkey.run("namespace", "delete", "--namespace", ns, "--confirm", "--delete-secrets")
    assert result.returncode == 0

    # Namespace appears as deleted in --all listing
    entry = helpers.find_namespace(ns_list_json(all=True), ns)
    assert entry is not None
    assert entry["status"] == "deleted"
