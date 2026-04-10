import tempfile
import os
import base64

import hkey
import helpers

def test_secret_create_with_value():
    ns = "/test/app1"
    helpers.create_namespace(ns)

    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:database/password",
        "--value",
        "my-secret-password",
    )
    assert result.returncode == 0

    # Verify secret was created
    data = helpers.get_secrets_json(ns)
    assert len(data['entries']) == 1
    secret = data['entries'][0]
    assert secret["ref_key"] == "database/password"

    # Verify namespace secrets count updated
    ns_data = helpers.get_namespaces_json()
    ns_entry = helpers.find_namespace(ns_data, ns)
    assert ns_entry["secret_summary"]['total'] == 1


def test_secret_create_with_description_and_labels():
    ns = "/prod/app1"
    helpers.create_namespace(ns)

    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:api/key",
        "--value",
        "abc123xyz",
        "--description",
        "API key for external service",
        "--label",
        "env=prod",
        "--label",
        "service=external-api",
    )
    assert result.returncode == 0

    data = helpers.get_secrets_json(ns)
    secret = helpers.find_secret(data, "api/key")
    assert secret is not None
    assert secret["description"] == "API key for external service"
    assert secret["labels"]["env"] == "prod"
    assert secret["labels"]["service"] == "external-api"


def test_secret_create_multiple_in_namespace():
    ns = "/test/multi"
    helpers.create_namespace(ns)

    secrets = [
        ("db/username", "admin"),
        ("db/password", "secret123"),
        ("api/key", "key-abc-123"),
        ("config/token", "token-xyz-789"),
    ]

    for path, value in secrets:
        result = hkey.run(
            "secret",
            "create",
            "--ref",
            f"{ns}:{path}",
            "--value",
            value,
        )
        assert result.returncode == 0

    data = helpers.get_secrets_json(ns)
    assert len(data['entries']) == len(secrets)
    assert data['total'] == len(secrets)

    paths = {s["ref_key"] for s in data['entries']}
    expected_paths = {path for path, _ in secrets}
    assert paths == expected_paths


def test_secret_create_hierarchical_paths():
    ns = "/test/hierarchy"
    helpers.create_namespace(ns)

    paths = [
        "app/db/host",
        "app/db/port",
        "app/db/user",
        "app/cache/host",
        "app/cache/port",
        "service/api/key",
        "service/api/secret",
    ]

    for path in paths:
        result = hkey.run(
            "secret",
            "create",
            "--ref",
            f"{ns}:{path}",
            "--value",
            f"value-for-{path}",
        )
        assert result.returncode == 0

    data = helpers.get_secrets_json(ns)
    assert len(data['entries']) == len(paths)
    assert data['total'] == len(paths)


# -------------------
# Tests - Value Formats
# -------------------

def test_secret_create_with_hex_value():
    ns = "/test/hex"
    helpers.create_namespace(ns)

    hex_value = "deadbeef"
    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:binary/data",
        "--value-hex",
        hex_value,
    )
    assert result.returncode == 0

    data = helpers.get_secrets_json(ns)
    assert len(data['entries']) == 1
    assert data['total'] == 1


def test_secret_create_with_base64_value():
    ns = "/test/b64"
    helpers.create_namespace(ns)

    original = b"some binary data \x00\x01\x02"
    b64_value = base64.b64encode(original).decode('ascii')

    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:encoded/data",
        "--value-base64",
        b64_value,
    )
    assert result.returncode == 0

    data = helpers.get_secrets_json(ns)
    assert len(data['entries']) == 1
    assert data['total'] == 1


def test_secret_create_from_file():
    ns = "/test/file"
    helpers.create_namespace(ns)

    # Create a temporary file with binary content
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
        f.write(b"binary content\x00\x01\x02\xff")
        temp_path = f.name

    try:
        result = hkey.run(
            "secret",
            "create",
            "--ref",
            f"{ns}:from/file",
            "--from-file",
            temp_path,
        )
        assert result.returncode == 0

        data = helpers.get_secrets_json(ns)
        assert len(data['entries']) == 1
        assert data['total'] == 1
    finally:
        os.unlink(temp_path)


def test_secret_create_empty_value():
    ns = "/test/empty"
    helpers.create_namespace(ns)

    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:empty/secret",
        "--value",
        "",
    )
    # May succeed or fail depending on implementation
    # If it succeeds, verify it was created
    if result.returncode == 0:
        data = helpers.get_secrets_json(ns)
        assert len(data['entries']) == 1
        assert data['total'] == 1


# -------------------
# Tests - Invalid Refs
# -------------------

def test_secret_create_invalid_ref_format():
    ns = "/test/invalid"
    helpers.create_namespace(ns)

    invalid_refs = [
        "no-namespace-separator",
        "/namespace-only",
        "namespace:path",  # Missing leading slash
        "/ns:",  # Empty path
        f"{ns}:with space",
        f"{ns}:with*asterisk",
        f"{ns}:with#hash",
    ]

    for ref in invalid_refs:
        result = hkey.run(
            "secret",
            "create",
            "--ref",
            ref,
            "--value",
            "test",
        )
        assert result.returncode == 2, f"Expected failure for ref: {ref}"


def test_secret_create_valid_ref_formats():
    ns = "/test/valid"
    helpers.create_namespace(ns)

    valid_paths = [
        "simple",
        "with-dash",
        "with_underscore",
        "with123numbers",
        "path/to/secret",
        "deep/path/to/some/secret",
        "UPPERCASE",
        "MixedCase",
    ]

    for path in valid_paths:
        result = hkey.run(
            "secret",
            "create",
            "--ref",
            f"{ns}:{path}",
            "--value",
            "test",
        )
        assert result.returncode == 0, f"Failed for path: {path}"


def test_secretutils_create_namespace_not_exists():
    result = hkey.run(
        "secret",
        "create",
        "--ref",
        "/nonexistent:secret/path",
        "--value",
        "test",
    )
    assert result.returncode == 12


def test_secret_create_in_disabled_namespace():
    ns = "/test/disabled"
    helpers.create_namespace(ns)

    # Disable the namespace
    result = hkey.run("namespace", "disable", "--namespace", ns)
    assert result.returncode == 0

    # Try to create secret in disabled namespace
    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:secret/path",
        "--value",
        "test",
    )
    assert result.returncode == 12


# -------------------
# Tests - Duplicate Detection
# -------------------

def test_secret_create_duplicate_path():
    ns = "/test/dup"
    helpers.create_namespace(ns)

    ref = f"{ns}:duplicate/secret"

    # Create first time
    result = hkey.run(
        "secret",
        "create",
        "--ref",
        ref,
        "--value",
        "first-value",
    )
    assert result.returncode == 0

    # Try to create again with same path
    result = hkey.run(
        "secret",
        "create",
        "--ref",
        ref,
        "--value",
        "second-value",
    )
    assert result.returncode == 12


# -------------------
# Tests - Multiple Value Flags Conflict
# -------------------

def test_secret_create_multiple_value_flags():
    ns = "/test/conflict"
    helpers.create_namespace(ns)

    # Try to specify both --value and --value-hex
    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:conflict/test",
        "--value",
        "text",
        "--value-hex",
        "deadbeef",
    )
    assert result.returncode in (2, 12)

    # Try to specify both --value and --value-base64
    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:conflict/test2",
        "--value",
        "text",
        "--value-base64",
        "dGVzdA==",
    )
    assert result.returncode in (2, 12)


def test_secret_create_no_value_specified():
    ns = "/test/novalue"
    helpers.create_namespace(ns)

    # Try to create without any value flag
    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:no/value",
    )
    # Should fail or prompt for value (depending on implementation)
    # If --use-editor or --stdin is required, this should fail
    assert result.returncode == 2


# -------------------
# Tests - Special Characters in Values
# -------------------

def test_secret_create_with_special_characters():
    ns = "/test/special"
    helpers.create_namespace(ns)

    special_values = [
        "password with spaces",
        "pass@word!with#special$chars%",
        "unicode: 你好世界",
        "newline\ncharacter",
        "tab\tcharacter",
        "quote\"and'apostrophe",
        "backslash\\character",
        '{"json": "value"}',
        "<xml>value</xml>",
    ]

    for i, value in enumerate(special_values):
        result = hkey.run(
            "secret",
            "create",
            "--ref",
            f"{ns}:special/test{i}",
            "--value",
            value,
        )
        assert result.returncode == 0, f"Failed for value: {value}"

    data = helpers.get_secrets_json(ns)
    assert len(data['entries']) == len(special_values)
    assert data['total'] == len(special_values)


# -------------------
# Tests - Large Values
# -------------------

def test_secret_create_large_value():
    ns = "/test/large"
    helpers.create_namespace(ns)

    # Create a large value (e.g., 1MB)
    large_value = "x" * (5 * 1024 * 1024)

    # save to file and use --from-file
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
        f.write(large_value.encode('utf-8'))
        temp_path = f.name

    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:large/secret",
        "--from-file",
        temp_path
    )
    os.unlink(temp_path)

    # May succeed or fail depending on size limits
    # Just verify it doesn't crash
    assert result.returncode in (0, 2)


# -------------------
# Tests - Labels Edge Cases
# -------------------

def test_secret_create_multiple_labels():
    ns = "/test/labels"
    helpers.create_namespace(ns)

    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:multi/labels",
        "--value",
        "test",
        "--label",
        "env=prod",
        "--label",
        "app=myapp",
        "--label",
        "version=1.0",
        "--label",
        "owner=alice",
        "--label",
        "team=backend",
    )
    assert result.returncode == 0

    data = helpers.get_secrets_json(ns)
    secret = data['entries'][0]
    assert len(secret["labels"]) == 5
    assert secret["labels"]["env"] == "prod"
    assert secret["labels"]["owner"] == "alice"


def test_secret_create_duplicate_label_keys():
    ns = "/test/duplabel"
    helpers.create_namespace(ns)

    # Specify same label key twice
    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:dup/label",
        "--value",
        "test",
        "--label",
        "env=dev",
        "--label",
        "env=prod",
    )
    # Behavior depends on implementation:
    # - May take the last value (env=prod)
    # - May fail with error
    # Just verify it doesn't crash
    assert result.returncode in (0, 2)


def test_secret_create_invalid_label_format():
    ns = "/test/badlabel"
    helpers.create_namespace(ns)

    invalid_labels = [
        "no-equals-sign",
        "=no-key",
        # "multiple=equals=signs",
        "",
    ]

    for label in invalid_labels:
        result = hkey.run(
            "secret",
            "create",
            "--ref",
            f"{ns}:test",
            "--value",
            "test",
            "--label",
            label,
        )
        assert result.returncode == 2, f"Expected failure for label: {label}"


# -------------------
# Tests - Path Normalization
# -------------------

def test_secret_create_path_with_leading_slash():
    ns = "/test/slash"
    helpers.create_namespace(ns)

    # Try creating with leading slash in path (after colon)
    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:/leading/slash",
        "--value",
        "test",
    )
    # May normalize or reject - verify behavior is consistent
    assert result.returncode in (0, 2)


def test_secret_create_path_with_trailing_slash():
    ns = "/test/trailing"
    helpers.create_namespace(ns)

    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:trailing/slash/",
        "--value",
        "test",
    )
    # May normalize or reject
    assert result.returncode in (0, 2)


def test_secret_create_path_with_double_slashes():
    ns = "/test/double"
    helpers.create_namespace(ns)

    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns}:path//with//double",
        "--value",
        "test",
    )
    # Should likely fail or normalize
    assert result.returncode in (0, 2)


# -------------------
# Tests - Cross-Namespace
# -------------------

def test_secret_create_same_path_different_namespaces():
    ns1 = "/prod/app1"
    ns2 = "/test/app1"

    helpers.create_namespace(ns1)
    helpers.create_namespace(ns2)

    path = "database/password"

    # Create in first namespace
    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns1}:{path}",
        "--value",
        "prod-password",
    )
    assert result.returncode == 0

    # Create same path in second namespace
    result = hkey.run(
        "secret",
        "create",
        "--ref",
        f"{ns2}:{path}",
        "--value",
        "test-password",
    )
    assert result.returncode == 0

    # Verify both exist independently
    data1 = helpers.get_secrets_json(ns1)
    data2 = helpers.get_secrets_json(ns2)

    assert len(data1['entries']) == 1
    assert len(data2['entries']) == 1
    assert helpers.find_secret(data1, path) is not None
    assert helpers.find_secret(data2, path) is not None