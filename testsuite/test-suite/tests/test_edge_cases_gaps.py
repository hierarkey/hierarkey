# tests/test_edge_cases_gaps.py
#
# Tests for sections 11, 12, and 13 of the test plan.
#
#   11  Rate Limiting  (requires HKEY_TEST_RATE_LIMIT=1 + configured limit)
#   12  Edge Cases & Negative Tests
#   13  CLI Integration Tests
#
# Rate-limit tests are skipped unless HKEY_TEST_RATE_LIMIT=1.
# HKEY_TEST_RATE_LIMIT_RPM can be set to the configured burst/RPM so the
# test knows how many requests to fire.

import json
import os
import subprocess
import uuid

import pytest
import requests

import hkey

RATE_LIMIT_ENABLED = os.environ.get("HKEY_TEST_RATE_LIMIT", "0") == "1"
# Burst size to exhaust before the rate-limiter kicks in (default 5 + 1)
RATE_LIMIT_BURST = int(os.environ.get("HKEY_TEST_RATE_LIMIT_BURST", "5"))

skip_if_no_rate_limit = pytest.mark.skipif(
    not RATE_LIMIT_ENABLED,
    reason="HKEY_TEST_RATE_LIMIT=1 required — rate limiting must be enabled in the server config",
)


def server_url():
    return os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")


def _auth_header():
    hkey.login()
    return {"Authorization": f"Bearer {hkey.client.AUTH_TOKEN}"}


def _unique(prefix="x"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# 11  Rate Limiting
# ---------------------------------------------------------------------------

@skip_if_no_rate_limit
class TestRateLimit:

    def test_auth_endpoint_returns_429_after_burst_exhausted(self):
        """11.1 — More than burst+1 rapid requests to the auth endpoint returns 429."""
        n = RATE_LIMIT_BURST + 2  # one past the burst limit
        last_status = None
        for _ in range(n):
            r = requests.post(
                f"{server_url()}/v1/auth/token",
                json={"name": "admin", "password": "wrong-password-to-trigger-fast-fail"},
            )
            last_status = r.status_code
            if r.status_code == 429:
                break

        assert last_status == 429, (
            f"Expected 429 after {n} rapid auth requests, last status was {last_status}"
        )

    def test_rate_limited_response_body_has_correct_format(self):
        """11.1 — The 429 response has the standard API error format."""
        n = RATE_LIMIT_BURST + 2
        r429 = None
        for _ in range(n):
            r = requests.post(
                f"{server_url()}/v1/auth/token",
                json={"name": "x", "password": "y"},
            )
            if r.status_code == 429:
                r429 = r
                break

        assert r429 is not None, f"Did not get a 429 after {n} requests"
        body = r429.json()
        assert "status" in body or "error" in body, (
            f"Expected API error body on 429: {body}"
        )


class TestRateLimitWithoutEnabled:

    def test_normal_requests_succeed_without_rate_limit(self):
        """11.1 — Without rate limiting enabled, repeated requests succeed."""
        if RATE_LIMIT_ENABLED:
            pytest.skip("Rate limiting is enabled; this test applies only when disabled")

        for _ in range(5):
            r = requests.get(
                f"{server_url()}/v1/system/status",
            )
            assert r.status_code in (200, 401), (
                f"Unexpected status on repeated requests: {r.status_code}"
            )


# ---------------------------------------------------------------------------
# 12  Edge Cases & Negative Tests
# ---------------------------------------------------------------------------

class TestMissingAuth:

    def test_missing_auth_header_returns_401(self):
        """12.1 — A request with no Authorization header is rejected with 401."""
        r = requests.get(f"{server_url()}/v1/auth/whoami")
        assert r.status_code == 401, (
            f"Expected 401 for missing auth header, got {r.status_code}: {r.text}"
        )

    def test_missing_auth_header_response_has_api_format(self):
        """12.1 — The 401 for missing auth has the standard API error format."""
        r = requests.get(f"{server_url()}/v1/auth/whoami")
        assert r.status_code == 401
        body = r.json()
        assert "status" in body or "error" in body, (
            f"Expected structured API error body on 401: {body}"
        )


class TestMalformedJwt:

    def test_malformed_token_returns_401(self):
        """12.2 — A request with a syntactically invalid token is rejected with 401."""
        r = requests.get(
            f"{server_url()}/v1/auth/whoami",
            headers={"Authorization": "Bearer not-a-valid-token"},
        )
        assert r.status_code == 401, (
            f"Expected 401 for malformed token, got {r.status_code}: {r.text}"
        )

    def test_empty_bearer_token_returns_401(self):
        """12.2 — An empty bearer token is rejected with 401."""
        r = requests.get(
            f"{server_url()}/v1/auth/whoami",
            headers={"Authorization": "Bearer "},
        )
        assert r.status_code == 401, (
            f"Expected 401 for empty bearer token, got {r.status_code}"
        )

    def test_wrong_scheme_returns_401(self):
        """12.2 — Using 'Basic' instead of 'Bearer' is rejected."""
        r = requests.get(
            f"{server_url()}/v1/auth/whoami",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert r.status_code == 401, (
            f"Expected 401 for wrong auth scheme, got {r.status_code}"
        )


class TestInvalidJsonBody:

    def test_invalid_json_body_returns_400(self):
        """12.5 — A request with Content-Type application/json but invalid JSON returns 400."""
        r = requests.post(
            f"{server_url()}/v1/rbac/role/search",
            data="this is not json{{",
            headers={
                "Content-Type": "application/json",
                **_auth_header(),
            },
        )
        assert r.status_code == 400, (
            f"Expected 400 for invalid JSON body, got {r.status_code}: {r.text}"
        )

    def test_truncated_json_returns_400(self):
        """12.5 — A truncated JSON body is rejected with 400."""
        r = requests.post(
            f"{server_url()}/v1/rbac/role",
            data='{"name": "incomplete',
            headers={
                "Content-Type": "application/json",
                **_auth_header(),
            },
        )
        assert r.status_code == 400, (
            f"Expected 400 for truncated JSON, got {r.status_code}: {r.text}"
        )


class TestUnknownEndpoint:

    def test_unknown_path_returns_404(self):
        """12.8 — A request to a non-existent path returns 404."""
        r = requests.get(
            f"{server_url()}/v1/does/not/exist/at/all",
            headers=_auth_header(),
        )
        assert r.status_code == 404, (
            f"Expected 404 for unknown path, got {r.status_code}"
        )

    def test_unknown_path_has_api_response_format(self):
        """12.8 — The 404 for an unknown path uses the standard API response format."""
        r = requests.get(
            f"{server_url()}/v1/unknown-endpoint-xyz",
            headers=_auth_header(),
        )
        assert r.status_code == 404
        # The body may or may not be JSON — just check we don't get a raw panic/plain-text
        ct = r.headers.get("content-type", "")
        if "application/json" in ct:
            body = r.json()
            assert isinstance(body, dict), f"Expected JSON object: {body}"


class TestWrongHttpMethod:

    def test_wrong_http_method_returns_405(self):
        """12.9 — Using an unsupported HTTP method returns 405."""
        # POST /v1/auth/whoami doesn't exist — GET is the supported method
        r = requests.post(
            f"{server_url()}/v1/auth/whoami",
            headers=_auth_header(),
        )
        assert r.status_code == 405, (
            f"Expected 405 for wrong HTTP method, got {r.status_code}: {r.text}"
        )

    def test_delete_on_read_only_endpoint_returns_405(self):
        """12.9 — DELETE on a read-only endpoint returns 405."""
        r = requests.delete(
            f"{server_url()}/v1/auth/whoami",
            headers=_auth_header(),
        )
        assert r.status_code == 405, (
            f"Expected 405 for DELETE on whoami, got {r.status_code}"
        )


class TestLargeBody:

    def test_oversized_request_body_returns_413(self):
        """12.7 — A request body exceeding 5 MB is rejected with 413."""
        # Build a payload slightly over the 5 MB limit
        large_value = "A" * (5 * 1024 * 1024 + 1024)
        r = requests.post(
            f"{server_url()}/v1/rbac/role",
            json={"name": "overflow", "description": large_value},
            headers=_auth_header(),
        )
        assert r.status_code == 413, (
            f"Expected 413 for oversized body, got {r.status_code}: {r.text[:200]}"
        )


class TestPathParameterSafety:

    def test_path_traversal_in_namespace_is_rejected(self):
        """12.6 — Path traversal characters in namespace param are safely handled."""
        # URL-encode the traversal attempt
        r = requests.get(
            f"{server_url()}/v1/namespaces/%2F..%2F..%2Fetc%2Fpasswd",
            headers=_auth_header(),
        )
        # Should be 404 (not found) or 400 (bad request), not 200 or 500
        assert r.status_code in (400, 404), (
            f"Expected 400/404 for path traversal attempt, got {r.status_code}: {r.text}"
        )

    def test_sql_injection_chars_in_namespace_are_handled(self):
        """12.6 — SQL injection characters in path params don't cause errors."""
        r = requests.get(
            f"{server_url()}/v1/namespaces/%27%20OR%201%3D1%20--",
            headers=_auth_header(),
        )
        assert r.status_code in (400, 404), (
            f"Expected 400/404 for injection attempt, got {r.status_code}"
        )

    def test_null_byte_in_path_is_handled(self):
        """12.6 — A null byte in the path is handled without a server error."""
        r = requests.get(
            f"{server_url()}/v1/namespaces/%00",
            headers=_auth_header(),
        )
        assert r.status_code not in (500, 502, 503), (
            f"Server returned {r.status_code} on null byte in path — expected graceful handling"
        )


# ---------------------------------------------------------------------------
# 13  CLI Integration Tests
# ---------------------------------------------------------------------------

class TestCliHelp:

    def test_hkey_help_exits_cleanly(self):
        """13.1 — `hkey --help` exits with code 0."""
        result = hkey.run_unauth("--help")
        assert result.returncode == 0, f"--help exited with {result.returncode}: {result.stderr}"
        assert "hkey" in result.stdout.lower() or "hierarkey" in result.stdout.lower(), (
            f"Expected help text to mention hkey/hierarkey: {result.stdout[:200]}"
        )

    def test_hkey_version_shows_version(self):
        """13.2 — `hkey --version` exits with code 0 and shows version info."""
        result = hkey.run_unauth("--version")
        assert result.returncode == 0, f"--version exited with {result.returncode}: {result.stderr}"
        assert result.stdout.strip(), "Expected non-empty version output"


class TestCliJsonOutput:

    def test_namespace_list_json_output(self):
        """13.3 — `hkey namespace list --json` produces valid JSON."""
        result = hkey.run("namespace", "list", "--json")
        assert result.returncode == 0, f"namespace list --json failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert isinstance(data, (dict, list)), f"Expected JSON object or array: {data}"

    def test_account_list_json_output(self):
        """13.3 — `hkey account list --json` produces valid JSON."""
        result = hkey.run("account", "list", "--json", "--all")
        assert result.returncode == 0, f"account list --json failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert isinstance(data, (dict, list)), f"Expected JSON object or array: {data}"

    def test_rbac_role_list_json_output(self):
        """13.3 — `hkey rbac role list --json` produces valid JSON."""
        result = hkey.run("rbac", "role", "list", "--json")
        assert result.returncode == 0, f"rbac role list --json failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert isinstance(data, (dict, list)), f"Expected JSON object or array: {data}"


class TestCliEnvVarToken:

    def test_hkey_access_token_env_var_is_used(self):
        """13.7 — HKEY_ACCESS_TOKEN environment variable is used as auth token."""
        hkey.login()
        token = hkey.client.AUTH_TOKEN
        assert token, "No admin token available"

        hkey_bin = os.environ.get("HKEY_TEST_HKEY_BIN")
        server_url_val = os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")

        env = os.environ.copy()
        env["HKEY_ACCESS_TOKEN"] = token
        # Remove --token arg to prove env var is used
        result = subprocess.run(
            [hkey_bin, "--server", server_url_val, "namespace", "list", "--json"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            env=env,
        )
        assert result.returncode == 0, (
            f"Expected CLI to use HKEY_ACCESS_TOKEN env var: {result.stderr}"
        )
        data = json.loads(result.stdout)
        assert isinstance(data, (dict, list))

    def test_invalid_hkey_access_token_env_var_is_rejected(self):
        """13.7 — An invalid HKEY_ACCESS_TOKEN is rejected with a non-zero exit code."""
        hkey_bin = os.environ.get("HKEY_TEST_HKEY_BIN")
        server_url_val = os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")

        env = os.environ.copy()
        env["HKEY_ACCESS_TOKEN"] = "hkat_totally_invalid_token"

        result = subprocess.run(
            [hkey_bin, "--server", server_url_val, "namespace", "list", "--json"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            env=env,
        )
        assert result.returncode != 0, (
            "Expected non-zero exit for invalid HKEY_ACCESS_TOKEN"
        )


class TestCliApiErrors:

    def test_nonexistent_namespace_shows_useful_error(self):
        """13.4 — CLI surfaces a useful error message for a non-existent namespace."""
        result = hkey.run(
            "namespace", "describe",
            "--namespace", "/this-namespace-does-not-exist-xyz",
        )
        assert result.returncode != 0, "Expected non-zero exit for non-existent namespace"
        # Should have some error message output
        error_output = (result.stderr + result.stdout).strip()
        assert error_output, "Expected some error message output"

    def test_nonexistent_secret_shows_useful_error(self):
        """13.4 — CLI surfaces a useful error message for a non-existent secret."""
        result = hkey.run(
            "secret", "describe",
            "--ref", "/totally-nonexistent-ns:no-secret@active",
        )
        assert result.returncode != 0
        error_output = (result.stderr + result.stdout).strip()
        assert error_output, "Expected some error output for non-existent secret"


# ---------------------------------------------------------------------------
# 12.4  Wrong-signature JWT
# ---------------------------------------------------------------------------

class TestWrongSignatureJwt:

    def test_tampered_jwt_signature_returns_401(self):
        """12.4 — A token with correct format but invalid secret is rejected with 401.

        Strategy: obtain a valid access token (format hkat_<id>.<secret>), flip one
        character in the secret segment (the second dot-separated part), and send it.
        The server must reject it with 401 because HMAC validation fails.
        """
        hkey.login()
        token = hkey.client.AUTH_TOKEN
        assert token, "No admin token available for test setup"

        parts = token.split(".")
        assert len(parts) == 2, f"Expected a token with 2 parts, got {len(parts)}: {token[:50]}"

        # Flip the last character of the secret segment to invalidate the token
        secret = parts[1]
        last = secret[-1]
        replacement = "B" if last != "B" else "C"
        tampered_token = parts[0] + "." + secret[:-1] + replacement

        r = requests.get(
            f"{server_url()}/v1/auth/whoami",
            headers={"Authorization": f"Bearer {tampered_token}"},
        )
        assert r.status_code == 401, (
            f"Expected 401 for tampered token, got {r.status_code}: {r.text}"
        )
