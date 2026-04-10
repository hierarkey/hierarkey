import json

import hkey
import helpers


# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------

def mk_status_json():
    """Return parsed JSON from `hkey masterkey status --json`."""
    result = hkey.run("masterkey", "status", "--json")
    assert result.returncode == 0, f"masterkey status failed: {result.stderr}"
    return json.loads(result.stdout)


def mk_find(data, name):
    """Find a master key entry by name in the status response."""
    return next(
        (e for e in data["entries"] if e["master_key"]["name"] == name),
        None,
    )


def mk_create(name):
    """Create an insecure wrap_kek master key; assert success."""
    result = hkey.run(
        "masterkey", "create",
        "--name", name,
        "--usage", "wrap_kek",
        "--provider", "insecure",
    )
    assert result.returncode == 0, f"masterkey create '{name}' failed: {result.stderr}"
    return result


def rekey_kek(namespace):
    """Run `hkey rekey kek --namespace <namespace>`."""
    return hkey.run("rekey", "kek", "--namespace", namespace)


def rewrap_dek(namespace):
    """Run `hkey rewrap dek --namespace <namespace>`."""
    return hkey.run("rewrap", "dek", "--namespace", namespace)


def assert_secret_value(ref, expected):
    """Assert that revealing a secret contains the expected plaintext value."""
    result = hkey.run("secret", "reveal", "--ref", ref)
    assert result.returncode == 0, f"reveal '{ref}' failed: {result.stderr}"
    assert expected in result.stdout, f"reveal '{ref}': expected {expected!r} in {result.stdout!r}"


def ns_describe(ns_path):
    """Return the namespace entry dict from `namespace describe --json`."""
    result = hkey.run("namespace", "describe", "--namespace", ns_path, "--json")
    assert result.returncode == 0, f"namespace describe '{ns_path}' failed: {result.stderr}"
    data = json.loads(result.stdout)
    return data["entry"]


# ===========================================================================
# 1. Initial state (read-only)
# ===========================================================================

def test_root_masterkey_is_active():
    """The bootstrapped 'root' insecure master key is active and unlocked."""
    data = mk_status_json()
    assert data["total"] >= 1

    root = mk_find(data, "root")
    assert root is not None, "Expected a master key named 'root'"
    assert root["master_key"]["status"] == "active"
    assert root["keyring"]["locked"] is False


def test_masterkey_status_json_schema():
    """masterkey status --json returns expected top-level fields."""
    data = mk_status_json()
    assert "entries" in data
    assert "total" in data
    assert data["total"] == len(data["entries"])

    entry = data["entries"][0]
    assert "master_key" in entry
    assert "keyring" in entry
    mk = entry["master_key"]
    for field in ("id", "short_id", "name", "usage", "status"):
        assert field in mk, f"Missing field '{field}' in master_key JSON"


# ===========================================================================
# 2. masterkey create (does not affect active key)
# ===========================================================================

def test_masterkey_create_pending():
    """Creating a new insecure master key starts in Pending status."""
    mk_create("test_create_pending_1")

    data = mk_status_json()
    entry = mk_find(data, "test_create_pending_1")
    assert entry is not None
    assert entry["master_key"]["status"] == "pending"


def test_masterkey_create_insecure_unlocked():
    """Insecure master keys are auto-unlocked on creation."""
    mk_create("test_create_unlocked_1")

    data = mk_status_json()
    entry = mk_find(data, "test_create_unlocked_1")
    assert entry is not None
    assert entry["keyring"]["locked"] is False


def test_masterkey_create_duplicate_rejected():
    """Creating a master key with a duplicate name fails."""
    mk_create("test_dup_mk_1")

    result = hkey.run(
        "masterkey", "create",
        "--name", "test_dup_mk_1",
        "--usage", "wrap_kek",
        "--provider", "insecure",
    )
    assert result.returncode != 0


# ===========================================================================
# 3. rekey kek (namespace KEK rotation)
# ===========================================================================

def test_rekey_kek_increments_revision():
    """rekey kek creates a new KEK revision for the namespace."""
    helpers.create_namespace("/test_rekey_rev")

    data_before = ns_describe("/test_rekey_rev")
    assert data_before["active_kek_revision"] == 1
    assert data_before["latest_kek_revision"] == 1

    result = rekey_kek("/test_rekey_rev")
    assert result.returncode == 0, f"rekey kek failed: {result.stderr}"
    assert "New KEK created" in result.stdout

    data_after = ns_describe("/test_rekey_rev")
    assert data_after["latest_kek_revision"] == 2
    assert data_after["active_kek_revision"] == 2
    assert len(data_after["keks"]) == 2


def test_rekey_kek_multiple_revisions():
    """Multiple rekey kek calls increment the revision each time."""
    helpers.create_namespace("/test_rekey_multi")

    for expected_rev in range(2, 5):
        result = rekey_kek("/test_rekey_multi")
        assert result.returncode == 0

        data = ns_describe("/test_rekey_multi")
        assert data["latest_kek_revision"] == expected_rev
        assert data["active_kek_revision"] == expected_rev


def test_rekey_kek_nonexistent_namespace():
    """rekey kek on a non-existent namespace fails."""
    result = rekey_kek("/no_such_ns_xyz")
    assert result.returncode != 0


def test_rekey_kek_output_contains_kek_id():
    """rekey kek output includes KEK short ID and revision number."""
    helpers.create_namespace("/test_rekey_output")

    result = rekey_kek("/test_rekey_output")
    assert result.returncode == 0
    assert "KEK ID:" in result.stdout
    assert "Revision:" in result.stdout
    assert "MasterKey:" in result.stdout


def test_rekey_kek_new_kek_uses_active_masterkey():
    """New KEK revision is wrapped under the currently active master key."""
    helpers.create_namespace("/test_rekey_masterkey")

    result = rekey_kek("/test_rekey_masterkey")
    assert result.returncode == 0

    data = ns_describe("/test_rekey_masterkey")
    new_kek = next(k for k in data["keks"] if k["revision"] == 2)
    assert new_kek["masterkey_short_id"] is not None
    assert new_kek["masterkey_short_id"] != ""

    # The root master key should still be active
    mk_data = mk_status_json()
    root = mk_find(mk_data, "root")
    assert root["master_key"]["status"] == "active"


def test_rekey_kek_active_kek_changes():
    """After rekey kek, only the new revision is marked active in describe output."""
    helpers.create_namespace("/test_rekey_active_flag")

    rekey_kek("/test_rekey_active_flag")

    data = ns_describe("/test_rekey_active_flag")
    active_keks = [k for k in data["keks"] if k.get("is_active")]
    assert len(active_keks) == 1
    assert active_keks[0]["revision"] == 2


# ===========================================================================
# 4. rewrap dek
# ===========================================================================

def test_rewrap_dek_no_secrets_is_ok():
    """rewrap dek on a namespace with no secrets reports already on active KEK."""
    helpers.create_namespace("/test_rewrap_empty_ns")
    result = rewrap_dek("/test_rewrap_empty_ns")
    assert result.returncode == 0
    assert "already using the active KEK" in result.stdout


def test_rewrap_dek_nonexistent_namespace():
    """rewrap dek on a non-existent namespace fails."""
    result = rewrap_dek("/no_such_ns_rewrap")
    assert result.returncode != 0


def test_rewrap_dek_no_rekey_is_noop():
    """rewrap dek without a prior rekey reports all DEKs already on active KEK."""
    helpers.create_namespace("/test_rewrap_noop")
    helpers.create_secret("/test_rewrap_noop:s1", "value_one")

    result = rewrap_dek("/test_rewrap_noop")
    assert result.returncode == 0
    assert "already using the active KEK" in result.stdout


def test_rewrap_dek_after_rekey_reports_rewrapped():
    """After rekey kek, rewrap dek reports secrets were rewrapped."""
    helpers.create_namespace("/test_rewrap_dek_count")
    helpers.create_secret("/test_rewrap_dek_count:alpha", "alpha_value")
    helpers.create_secret("/test_rewrap_dek_count:beta", "beta_value")
    helpers.create_secret("/test_rewrap_dek_count:gamma", "gamma_value")

    rekey_kek("/test_rewrap_dek_count")

    result = rewrap_dek("/test_rewrap_dek_count")
    assert result.returncode == 0
    assert "Rewrapped 3" in result.stdout


def test_rewrap_dek_idempotent():
    """Running rewrap dek twice results in 0 rewrapped on the second run."""
    helpers.create_namespace("/test_rewrap_dek_idem")
    helpers.create_secret("/test_rewrap_dek_idem:s1", "value_one")

    rekey_kek("/test_rewrap_dek_idem")

    r1 = rewrap_dek("/test_rewrap_dek_idem")
    assert r1.returncode == 0
    assert "Rewrapped 1" in r1.stdout

    r2 = rewrap_dek("/test_rewrap_dek_idem")
    assert r2.returncode == 0
    assert "already using the active KEK" in r2.stdout


# ===========================================================================
# 5. Plaintext survives rotation
# ===========================================================================

def test_secret_survives_rekey_kek():
    """Secret plaintext is still readable immediately after a namespace KEK rotation."""
    helpers.create_namespace("/test_survive_rekey")
    helpers.create_secret("/test_survive_rekey:mykey", "super_secret_value")

    result = rekey_kek("/test_survive_rekey")
    assert result.returncode == 0

    assert_secret_value("/test_survive_rekey:mykey", "super_secret_value")


def test_secret_survives_rewrap_dek():
    """Secret plaintext is still readable after DEK rewrap to new KEK."""
    helpers.create_namespace("/test_survive_rewrap")
    helpers.create_secret("/test_survive_rewrap:mykey", "another_secret_value")

    rekey_kek("/test_survive_rewrap")

    result = rewrap_dek("/test_survive_rewrap")
    assert result.returncode == 0

    assert_secret_value("/test_survive_rewrap:mykey", "another_secret_value")


def test_multiple_secrets_survive_rewrap():
    """All secrets in a namespace survive DEK rewrap."""
    helpers.create_namespace("/test_multi_survive")
    secrets = {
        "/test_multi_survive:key1": "value_one",
        "/test_multi_survive:key2": "value_two",
        "/test_multi_survive:key3": "value_three",
    }
    for ref, val in secrets.items():
        helpers.create_secret(ref, val)

    rekey_kek("/test_multi_survive")
    rewrap_dek("/test_multi_survive")

    for ref, expected in secrets.items():
        assert_secret_value(ref, expected)


def test_secret_created_after_rekey_uses_new_kek():
    """A secret created after rekey kek is immediately under the new KEK (no rewrap needed)."""
    helpers.create_namespace("/test_post_rekey_secret")
    helpers.create_secret("/test_post_rekey_secret:old", "old_secret")

    rekey_kek("/test_post_rekey_secret")

    # Create a new secret — its DEK should already use KEK rev 2
    helpers.create_secret("/test_post_rekey_secret:new", "new_secret")

    # rewrap dek should only rewrap the 'old' secret (1 rewrap)
    result = rewrap_dek("/test_post_rekey_secret")
    assert result.returncode == 0
    assert "Rewrapped 1" in result.stdout

    assert_secret_value("/test_post_rekey_secret:old", "old_secret")
    assert_secret_value("/test_post_rekey_secret:new", "new_secret")


# ===========================================================================
# 6. End-to-end namespace rotation flow
# ===========================================================================

def test_end_to_end_namespace_kek_rotation():
    """
    Full namespace-level rotation flow:
      create namespace -> create secrets -> rekey kek -> verify readable
      -> rewrap dek -> verify still readable -> rekey again -> rewrap -> verify
    """
    ns = "/test_e2e_rotation"
    helpers.create_namespace(ns)

    ref1 = f"{ns}:db_password"
    ref2 = f"{ns}:api_key"
    helpers.create_secret(ref1, "db_pass_v1")
    helpers.create_secret(ref2, "api_key_v1")

    # Round 1: KEK rotation
    r = rekey_kek(ns)
    assert r.returncode == 0

    data = ns_describe(ns)
    assert data["active_kek_revision"] == 2
    assert data["latest_kek_revision"] == 2

    # Secrets readable with DEKs still under old KEK (rev 1)
    assert_secret_value(ref1, "db_pass_v1")
    assert_secret_value(ref2, "api_key_v1")

    # Rewrap DEKs to KEK rev 2
    r = rewrap_dek(ns)
    assert r.returncode == 0
    assert "Rewrapped 2" in r.stdout

    # Secrets still readable after rewrap
    assert_secret_value(ref1, "db_pass_v1")
    assert_secret_value(ref2, "api_key_v1")

    # Round 2: Another KEK rotation
    r = rekey_kek(ns)
    assert r.returncode == 0

    data = ns_describe(ns)
    assert data["active_kek_revision"] == 3

    r = rewrap_dek(ns)
    assert r.returncode == 0
    assert "Rewrapped 2" in r.stdout

    assert_secret_value(ref1, "db_pass_v1")
    assert_secret_value(ref2, "api_key_v1")

    data = ns_describe(ns)
    assert len(data["keks"]) == 3
