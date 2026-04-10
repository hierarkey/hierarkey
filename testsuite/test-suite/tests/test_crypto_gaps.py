# tests/test_crypto_gaps.py
#
# Tests for section 10: Encryption & Cryptography.
#
# These tests exercise the observable cryptographic properties of the server
# through its public API.  Direct inspection of ciphertext bytes is not
# possible from the API, so the tests use behavioral proxies:
#
#   10.1.1  End-to-end crypto chain: secret encrypts and decrypts correctly
#   10.1.2  Rotating KEK (namespace rekey) keeps secret revealable
#   10.1.3  Rewrapping DEKs keeps secret plaintext unchanged
#   10.1.4  Two secrets in same namespace are independent (proxy)
#   10.1.5  Two namespaces have independent KEKs (KEK rotate in one does not
#           affect the other)
#   10.2.2  Multiple revisions of a secret all decrypt correctly

import os
import uuid

import hkey
import helpers


def _unique(prefix="x"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _ns_create(path):
    result = hkey.run("namespace", "create", "--namespace", path)
    assert result.returncode == 0, f"namespace create '{path}' failed: {result.stderr}"


def _secret_create(ref, value):
    result = hkey.run("secret", "create", "--ref", ref, "--value", value)
    assert result.returncode == 0, f"secret create '{ref}' failed: {result.stderr}"


def _reveal(ref):
    """Reveal the active revision of a secret and return its plaintext."""
    result = hkey.run("secret", "reveal", "--ref", f"{ref}@active")
    assert result.returncode == 0, f"secret reveal '{ref}@active' failed: {result.stderr}"
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# 10.1.1 — End-to-end crypto chain
# ---------------------------------------------------------------------------

class TestEndToEndCrypto:

    def test_secret_encrypts_and_decrypts_correctly(self):
        """10.1.1 — A secret created in a namespace can be revealed with its original value."""
        ns = f"/crypto-e2e-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        ref = f"{ns}:e2e-secret"
        plaintext = f"top-secret-{uuid.uuid4().hex}"
        _secret_create(ref, plaintext)

        revealed = _reveal(ref)
        assert revealed == plaintext, (
            f"Expected '{plaintext}', got '{revealed}'"
        )

    def test_binary_value_survives_crypto_roundtrip(self):
        """10.1.1 — A secret stored as base64 round-trips through encryption correctly."""
        import base64
        ns = f"/crypto-b64-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        raw_bytes = bytes(range(32))  # deterministic non-ASCII bytes
        b64_value = base64.b64encode(raw_bytes).decode()

        result = hkey.run(
            "secret", "create",
            "--ref", f"{ns}:b64-secret",
            "--value-base64", b64_value,
        )
        assert result.returncode == 0, f"create base64 secret failed: {result.stderr}"

        result = hkey.run("secret", "reveal", "--ref", f"{ns}:b64-secret@active", "--output", "base64")
        assert result.returncode == 0, f"reveal base64 secret failed: {result.stderr}"
        assert result.stdout.strip() == b64_value, (
            f"Base64 value changed after crypto roundtrip: {result.stdout.strip()!r}"
        )


# ---------------------------------------------------------------------------
# 10.1.2 — Rotating KEK keeps secrets revealable
# ---------------------------------------------------------------------------

class TestKekRotation:

    def test_secret_revealable_after_kek_rotate(self):
        """10.1.2 — After rotating the namespace KEK, the secret is still revealable."""
        ns = f"/crypto-kek-rot-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        ref = f"{ns}:after-kek-rotate"
        plaintext = f"kek-rotate-value-{uuid.uuid4().hex[:8]}"
        _secret_create(ref, plaintext)

        # Rotate KEK for this namespace
        result = hkey.run("rekey", "kek", "--namespace", ns)
        assert result.returncode == 0, f"rekey kek failed: {result.stderr}"

        # Secret must still be revealable
        revealed = _reveal(ref)
        assert revealed == plaintext, (
            f"Secret value changed after KEK rotation: got '{revealed}', expected '{plaintext}'"
        )

    def test_secret_revealable_after_kek_rotate_with_dek_migrate(self):
        """10.1.2 — After rotate + DEK migration, the secret is still revealable."""
        ns = f"/crypto-kek-mig-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        ref = f"{ns}:after-kek-migrate"
        plaintext = f"migrate-value-{uuid.uuid4().hex[:8]}"
        _secret_create(ref, plaintext)

        # Rotate KEK and immediately migrate DEKs
        result = hkey.run(
            "rekey", "kek",
            "--namespace", ns,
            "--migrate-deks",
            "--yes",
        )
        assert result.returncode == 0, f"rekey kek --migrate-deks failed: {result.stderr}"

        revealed = _reveal(ref)
        assert revealed == plaintext, (
            f"Secret value changed after KEK rotate + DEK migrate: got '{revealed}'"
        )


# ---------------------------------------------------------------------------
# 10.1.3 — Rewrapping DEKs keeps secret plaintext unchanged
# ---------------------------------------------------------------------------

class TestDekRewrap:

    def test_plaintext_unchanged_after_dek_rewrap(self):
        """10.1.3 — After rewrapping DEKs in a namespace, plaintext is unchanged."""
        ns = f"/crypto-dek-rw-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        ref = f"{ns}:dek-rewrap-test"
        plaintext = f"dek-rewrap-value-{uuid.uuid4().hex[:8]}"
        _secret_create(ref, plaintext)

        # Rotate the KEK so there is a new active KEK to rewrap DEKs onto
        result = hkey.run("rekey", "kek", "--namespace", ns)
        assert result.returncode == 0, f"rekey kek failed: {result.stderr}"

        # Rewrap all DEKs to the new active KEK
        result = hkey.run("rewrap", "dek", "--namespace", ns)
        assert result.returncode == 0, f"rewrap dek failed: {result.stderr}"

        # Plaintext must be identical after rewrap
        revealed = _reveal(ref)
        assert revealed == plaintext, (
            f"Plaintext changed after DEK rewrap: got '{revealed}', expected '{plaintext}'"
        )

    def test_multiple_secrets_all_revealable_after_dek_rewrap(self):
        """10.1.3 — All secrets in a namespace are still correct after DEK rewrap."""
        ns = f"/crypto-dek-multi-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        secrets = {
            f"{ns}:alpha": "alpha-value",
            f"{ns}:beta":  "beta-value",
            f"{ns}:gamma": "gamma-value",
        }
        for ref, value in secrets.items():
            _secret_create(ref, value)

        # Rotate KEK then rewrap all DEKs
        hkey.run("rekey", "kek", "--namespace", ns)
        hkey.run("rewrap", "dek", "--namespace", ns)

        for ref, expected in secrets.items():
            revealed = _reveal(ref)
            assert revealed == expected, (
                f"Secret '{ref}' has wrong value after DEK rewrap: got '{revealed}'"
            )


# ---------------------------------------------------------------------------
# 10.1.4 — Two secrets in same namespace are independent
# ---------------------------------------------------------------------------

class TestSecretsAreIndependent:

    def test_two_secrets_reveal_independently(self):
        """10.1.4 — Two secrets created in the same namespace reveal different values."""
        ns = f"/crypto-indep-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        ref_a = f"{ns}:independent-a"
        ref_b = f"{ns}:independent-b"
        _secret_create(ref_a, "value-for-a")
        _secret_create(ref_b, "value-for-b")

        assert _reveal(ref_a) == "value-for-a", "Secret A has wrong value"
        assert _reveal(ref_b) == "value-for-b", "Secret B has wrong value"
        assert _reveal(ref_a) != _reveal(ref_b), (
            "Different secrets should not have the same plaintext value in this test"
        )


# ---------------------------------------------------------------------------
# 10.1.5 — Two namespaces have independent KEKs
# ---------------------------------------------------------------------------

class TestNamespacesAreIndependent:

    def test_kek_rotate_in_one_namespace_does_not_affect_another(self):
        """10.1.5 — Rotating the KEK in namespace A does not affect secrets in namespace B."""
        ns_a = f"/crypto-ns-a-{uuid.uuid4().hex[:8]}"
        ns_b = f"/crypto-ns-b-{uuid.uuid4().hex[:8]}"
        _ns_create(ns_a)
        _ns_create(ns_b)

        ref_a = f"{ns_a}:ns-a-secret"
        ref_b = f"{ns_b}:ns-b-secret"
        plaintext_a = "ns-a-value"
        plaintext_b = "ns-b-value"
        _secret_create(ref_a, plaintext_a)
        _secret_create(ref_b, plaintext_b)

        # Rotate KEK only in namespace A
        result = hkey.run("rekey", "kek", "--namespace", ns_a)
        assert result.returncode == 0, f"rekey kek for ns_a failed: {result.stderr}"

        # Both secrets must still be revealable with original values
        assert _reveal(ref_a) == plaintext_a, "Namespace A secret broken after its own KEK rotate"
        assert _reveal(ref_b) == plaintext_b, "Namespace B secret affected by namespace A's KEK rotate"


# ---------------------------------------------------------------------------
# 10.2.2 — Multiple revisions all decrypt correctly
# ---------------------------------------------------------------------------

class TestMultipleRevisions:

    def test_all_revisions_decrypt_correctly(self):
        """10.2.2 — Every revision of a multi-version secret reveals with the correct value."""
        ns = f"/crypto-revisions-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        ref = f"{ns}:multi-rev"
        values = ["rev-one", "rev-two", "rev-three"]

        # Create the first revision
        result = hkey.run("secret", "create", "--ref", ref, "--value", values[0])
        assert result.returncode == 0

        # Add additional revisions
        for v in values[1:]:
            result = hkey.run(
                "secret", "revise",
                "--ref", ref,
                "--value", v,
            )
            assert result.returncode == 0, f"revise to '{v}' failed: {result.stderr}"

        # Verify each numbered revision reveals correctly
        for i, expected in enumerate(values, start=1):
            result = hkey.run("secret", "reveal", "--ref", f"{ref}@{i}")
            assert result.returncode == 0, f"reveal @{i} failed: {result.stderr}"
            assert result.stdout.strip() == expected, (
                f"Revision {i}: expected '{expected}', got '{result.stdout.strip()}'"
            )

    def test_active_revision_independent_of_non_active(self):
        """10.2.2 — Activating a specific revision does not corrupt the others."""
        ns = f"/crypto-active-rev-{uuid.uuid4().hex[:8]}"
        _ns_create(ns)

        ref = f"{ns}:active-rev-test"
        _secret_create(ref, "original")
        hkey.run("secret", "revise", "--ref", ref, "--value", "second")
        hkey.run("secret", "revise", "--ref", ref, "--value", "third")

        # Activate revision 2
        result = hkey.run("secret", "activate", "--ref", f"{ref}@2")
        assert result.returncode == 0, f"activate @2 failed: {result.stderr}"

        # Active should now be "second"
        assert _reveal(ref) == "second", "Activated revision should be 'second'"

        # All numbered revisions should still be correct
        assert hkey.run("secret", "reveal", "--ref", f"{ref}@1").stdout.strip() == "original"
        assert hkey.run("secret", "reveal", "--ref", f"{ref}@2").stdout.strip() == "second"
        assert hkey.run("secret", "reveal", "--ref", f"{ref}@3").stdout.strip() == "third"
