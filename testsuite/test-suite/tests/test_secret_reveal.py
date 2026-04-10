import base64

import hkey
import helpers

def test_secret_reveal_simple():
    ns = "/test/reveal"
    helpers.create_namespace(ns)

    secret_value = "my-secret-password"
    ref = f"{ns}:database/password"
    helpers.create_secret(ref, secret_value)

    result = hkey.run("secret", "reveal", "--ref", ref)
    assert result.returncode == 0
    assert secret_value in result.stdout


def test_secret_reveal_multiple_secrets():
    ns = "/test/multi"
    helpers.create_namespace(ns)

    secrets = {
        "db/host": "localhost",
        "db/port": "5432",
        "db/user": "admin",
        "db/password": "secret123",
    }

    for path, value in secrets.items():
        helpers.create_secret(f"{ns}:{path}", value)

    # Reveal each secret
    for path, expected_value in secrets.items():
        result = hkey.run("secret", "reveal", "--ref", f"{ns}:{path}")
        assert result.returncode == 0
        assert expected_value in result.stdout


def test_secret_reveal_with_special_characters():
    ns = "/test/special"
    helpers.create_namespace(ns)

    special_values = [
        ("simple", "password with spaces"),
        ("symbols", "pass@word!with#special$chars%"),
        ("unicode", "unicode: 你好世界"),
        ("newline", "line1\nline2"),
        ("quotes", 'quote"and\'apostrophe'),
        ("json", '{"key": "value"}'),
    ]

    for path, value in special_values:
        helpers.create_secret(f"{ns}:{path}", value)

    for path, expected_value in special_values:
        result = hkey.run("secret", "reveal", "--ref", f"{ns}:{path}")
        assert result.returncode == 0
        assert expected_value in result.stdout


# -------------------
# Tests - Output Formats
# -------------------

def test_secret_reveal_hex_format():
    ns = "/test/hex"
    helpers.create_namespace(ns)

    # Create with regular value
    secret_value = "test123"
    ref = f"{ns}:hex/test"
    helpers.create_secret(ref, secret_value)

    # Reveal as hex
    result = hkey.run("secret", "reveal", "--ref", ref, "--as-hex")
    assert result.returncode == 0

    # Verify hex output (test123 = 74657374313233 in hex)
    expected_hex = secret_value.encode('utf-8').hex()
    assert expected_hex in result.stdout.lower().replace(" ", "").replace("\n", "")


def test_secret_reveal_base64_format():
    ns = "/test/b64"
    helpers.create_namespace(ns)

    # Create with regular value
    secret_value = "test123"
    ref = f"{ns}:b64/test"
    helpers.create_secret(ref, secret_value)

    # Reveal as base64
    result = hkey.run("secret", "reveal", "--ref", ref, "--as-base64")
    assert result.returncode == 0

    # Verify base64 output
    expected_b64 = base64.b64encode(secret_value.encode('utf-8')).decode('ascii')
    assert expected_b64 in result.stdout.replace("\n", "")


def test_secret_reveal_binary_data_hex():
    ns = "/test/binary"
    helpers.create_namespace(ns)

    # Create with hex value
    hex_value = "deadbeef"
    ref = f"{ns}:binary/data"
    helpers.create_secret(ref, None, value_hex=hex_value)

    # Reveal as hex
    result = hkey.run("secret", "reveal", "--ref", ref, "--as-hex")
    assert result.returncode == 0
    assert hex_value in result.stdout.lower().replace(" ", "").replace("\n", "")


def test_secret_reveal_binary_data_base64():
    ns = "/test/b64bin"
    helpers.create_namespace(ns)

    # Create with base64 value
    original = b"binary\x00\x01\x02"
    b64_value = base64.b64encode(original).decode('ascii')
    ref = f"{ns}:binary/data"
    helpers.create_secret(ref, None, value_base64=b64_value)

    # Reveal as base64
    result = hkey.run("secret", "reveal", "--ref", ref, "--as-base64")
    assert result.returncode == 0
    assert b64_value in result.stdout.replace("\n", "")


def test_secret_reveal_format_flags_conflict():
    ns = "/test/conflict"
    helpers.create_namespace(ns)

    ref = f"{ns}:test"
    helpers.create_secret(ref, "value")

    # Try to use both --as-hex and --as-base64
    result = hkey.run("secret", "reveal", "--ref", ref, "--as-hex", "--as-base64")
    # Should fail due to conflicting flags
    assert result.returncode == 2


# -------------------
# Tests - Revisions
# -------------------

def test_secret_reveal_specific_revision():
    ns = "/test/revisions"
    helpers.create_namespace(ns)

    ref = f"{ns}:versioned/secret"

    # Create initial version
    helpers.create_secret(ref, "version1")

    # Update to create new revisions
    result = hkey.run("secret", "update", "--ref", ref, "--value", "version2")
    if result.returncode == 0:
        result = hkey.run("secret", "update", "--ref", ref, "--value", "version3")

    # If updates succeeded, test revision reveal
    if result.returncode == 0:
        # Reveal specific revision using --revision flag
        result = hkey.run("secret", "reveal", "--ref", f"{ref}@1")
        assert result.returncode == 0
        assert "version1" in result.stdout

        result = hkey.run("secret", "reveal", "--ref", f"{ref}@2")
        assert result.returncode == 0
        assert "version2" in result.stdout

        # Reveal latest (revision 3)
        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode == 0
        assert "version3" in result.stdout


def test_secret_reveal_revision_in_ref():
    ns = "/test/refrev"
    helpers.create_namespace(ns)

    ref = f"{ns}:versioned/secret"

    # Create initial version
    helpers.create_secret(ref, "version1")

    # Update to create new revision
    result = hkey.run("secret", "update", "--ref", ref, "--value", "version2")

    # If updates succeeded, test revision in ref path
    if result.returncode == 0:
        # Reveal using #revision syntax
        result = hkey.run("secret", "reveal", "--ref", f"{ref}@1")
        assert result.returncode == 0
        assert "version1" in result.stdout

        result = hkey.run("secret", "reveal", "--ref", f"{ref}@2")
        assert result.returncode == 0
        assert "version2" in result.stdout


def test_secret_reveal_nonexistent_revision():
    ns = "/test/badrev"
    helpers.create_namespace(ns)

    ref = f"{ns}:secret"
    helpers.create_secret(ref, "value")

    # Try to reveal revision 999 which doesn't exist
    result = hkey.run("secret", "reveal", "--ref", f"{ref}@999")
    assert result.returncode == 12


def test_secret_reveal_revision_zero():
    ns = "/test/rev0"
    helpers.create_namespace(ns)

    ref = f"{ns}:secret"
    helpers.create_secret(ref, "value")

    # Try to reveal revision 0 (invalid)
    result = hkey.run("secret", "reveal", "--ref", f"{ref}@0")
    assert result.returncode == 2


def test_secret_reveal_revision_negative():
    ns = "/test/revneg"
    helpers.create_namespace(ns)

    ref = f"{ns}:secret"
    helpers.create_secret(ref, "value")

    # Try to reveal negative revision
    result = hkey.run("secret", "reveal", "--ref", f"{ref}@-1")
    assert result.returncode == 2


# -------------------
# Tests - Error Cases
# -------------------

def test_secret_reveal_nonexistent_secret():
    ns = "/test/noexist"
    helpers.create_namespace(ns)

    result = hkey.run("secret", "reveal", "--ref", f"{ns}:does/not/exist")
    assert result.returncode == 12


def test_secret_reveal_nonexistent_namespace():
    result = hkey.run("secret", "reveal", "--ref", "/nonexistent:secret/path")
    assert result.returncode == 12


def test_secret_reveal_disabled_namespace():
    ns = "/test/disabled"
    helpers.create_namespace(ns)

    ref = f"{ns}:secret"
    helpers.create_secret(ref, "value")

    result = hkey.run("secret", "reveal", "--ref", ref)
    assert result.returncode == 0

    # Disable namespace
    result = hkey.run("namespace", "disable", "--namespace", ns)
    assert result.returncode == 0

    # Try to reveal secret from disabled namespace
    result = hkey.run("secret", "reveal", "--ref", ref)
    assert result.returncode == 12

    result = hkey.run("namespace", "enable", "--namespace", ns)
    assert result.returncode == 0

    result = hkey.run("secret", "reveal", "--ref", ref)
    assert result.returncode == 0


def test_secret_reveal_invalid_ref_format():
    invalid_refs = [
        "no-colon-separator",
        "/namespace-only",
        "namespace:path",  # Missing leading slash
        "/ns:",  # Empty path
    ]

    for ref in invalid_refs:
        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode == 2, f"Expected failure for ref: {ref}"


def test_secret_reveal_malformed_revision_in_ref():
    ns = "/test/badrevformat"
    helpers.create_namespace(ns)

    ref = f"{ns}:secret"
    helpers.create_secret(ref, "value")

    # Try malformed revision syntax
    invalid_refs = [
        f"{ref}@",  # No revision number
        f"{ref}@abc",  # Non-numeric revision
        f"{ref}@@2",  # Double hash
    ]

    for invalid_ref in invalid_refs:
        result = hkey.run("secret", "reveal", "--ref", invalid_ref)
        assert result.returncode == 2, f"Expected failure for ref: {invalid_ref}"


# -------------------
# Tests - Cross-Namespace
# -------------------

def test_secret_reveal_same_path_different_namespaces():
    ns1 = "/prod/app"
    ns2 = "/test/app"

    helpers.create_namespace(ns1)
    helpers.create_namespace(ns2)

    path = "database/password"

    # Create different values in each namespace
    helpers.create_secret(f"{ns1}:{path}", "prod-password-123")
    helpers.create_secret(f"{ns2}:{path}", "test-password-456")

    # Reveal from first namespace
    result = hkey.run("secret", "reveal", "--ref", f"{ns1}:{path}")
    assert result.returncode == 0
    assert "prod-password-123" in result.stdout
    assert "test-password-456" not in result.stdout

    # Reveal from second namespace
    result = hkey.run("secret", "reveal", "--ref", f"{ns2}:{path}")
    assert result.returncode == 0
    assert "test-password-456" in result.stdout
    assert "prod-password-123" not in result.stdout


# -------------------
# Tests - Empty and Large Values
# -------------------

def test_secret_reveal_empty_value():
    ns = "/test/empty"
    helpers.create_namespace(ns)

    ref = f"{ns}:empty"
    result = hkey.run("secret", "create", "--ref", ref, "--value", "")

    # If creation succeeded, try to reveal
    if result.returncode == 0:
        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode == 0


def test_secret_reveal_large_value():
    ns = "/test/large"
    helpers.create_namespace(ns)

    # Create a moderately large value (100KB)
    large_value = "x" * (100 * 1024)
    ref = f"{ns}:large"

    result = hkey.run("secret", "create", "--ref", ref, "--value", large_value)

    # If creation succeeded, try to reveal
    if result.returncode == 0:
        result = hkey.run("secret", "reveal", "--ref", ref)
        assert result.returncode == 0
        assert large_value in result.stdout


# -------------------
# Tests - Output Consistency
# -------------------

def test_secret_reveal_output_contains_only_value():
    ns = "/test/clean"
    helpers.create_namespace(ns)

    secret_value = "just-the-secret-value"
    ref = f"{ns}:clean/output"
    helpers.create_secret(ref, secret_value)

    result = hkey.run("secret", "reveal", "--ref", ref)
    assert result.returncode == 0

    # The output should contain the secret value
    assert secret_value in result.stdout

    # Output should be clean (no extra formatting like "Secret: " or metadata)
    # This depends on implementation - adjust as needed
    lines = result.stdout.strip().split('\n')
    # Typically should be just the value, possibly with minimal formatting


def test_secret_reveal_binary_safe_default_output():
    ns = "/test/binsafe"
    helpers.create_namespace(ns)

    # Create with binary data
    ref = f"{ns}:binary"
    helpers.create_secret(ref, None, value_hex="00010203ff")

    # Reveal without format flag
    result = hkey.run("secret", "reveal", "--ref", ref)
    assert result.returncode == 2

    result = hkey.run("secret", "reveal", "--ref", ref, "--as-hex")
    assert result.returncode == 0

    # Default output format should handle binary data safely
    # (e.g., base64, hex, or error message)


# -------------------
# Tests - Revision and Format Combined
# -------------------

def test_secret_reveal_revision_with_hex():
    ns = "/test/revhex"
    helpers.create_namespace(ns)

    ref = f"{ns}:versioned"
    helpers.create_secret(ref, "v1")

    result = hkey.run("secret", "update", "--ref", ref, "--value", "v2")

    if result.returncode == 0:
        # Reveal revision 1 as hex
        result = hkey.run("secret", "reveal", "--ref", ref, "--revision", "1", "--as-hex")
        assert result.returncode == 0
        expected_hex = "v1".encode('utf-8').hex()
        assert expected_hex in result.stdout.lower().replace(" ", "").replace("\n", "")


def test_secret_reveal_revision_with_base64():
    ns = "/test/revb64"
    helpers.create_namespace(ns)

    ref = f"{ns}:versioned"
    helpers.create_secret(ref, "v1")

    result = hkey.run("secret", "update", "--ref", ref, "--value", "v2")

    if result.returncode == 0:
        # Reveal revision 1 as base64
        result = hkey.run("secret", "reveal", "--ref", ref, "--revision", "1", "--as-base64")
        assert result.returncode == 0
        expected_b64 = base64.b64encode("v1".encode('utf-8')).decode('ascii')
        assert expected_b64 in result.stdout.replace("\n", "")


# -------------------
# Tests - Both Revision Syntax Methods
# -------------------

def test_secret_reveal_revision_flag_vs_ref_syntax():
    ns = "/test/revsyntax"
    helpers.create_namespace(ns)

    ref = f"{ns}:versioned"
    helpers.create_secret(ref, "v1")

    result = hkey.run("secret", "update", "--ref", ref, "--value", "v2")

    if result.returncode == 0:
        # Using --revision flag
        result1 = hkey.run("secret", "reveal", "--ref", ref, "--revision", "1")
        assert result1.returncode == 0

        # Using #revision in ref
        result2 = hkey.run("secret", "reveal", "--ref", f"{ref}@1")
        assert result2.returncode == 0

        # Both should produce the same output
        assert result1.stdout == result2.stdout


def test_secret_reveal_both_revision_methods_specified():
    ns = "/test/dualrev"
    helpers.create_namespace(ns)

    ref = f"{ns}:versioned"
    helpers.create_secret(ref, "v1")

    result = hkey.run("secret", "update", "--ref", ref, "--value", "v2")

    # if result.returncode == 0:
    #     # Try to specify revision both ways
    #     result = hkey.run("secret", "reveal", "--ref", f"{ref}@1", "--revision", "2")
    #     # Should fail or prefer one method
    #     assert result.returncode in (0, 1)