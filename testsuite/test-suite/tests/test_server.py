# tests/test_server.py
#
# Section 1.1 — Health & Readiness
# Section 1.2 — Security Headers
#
# These tests make direct HTTP requests to the server rather than going
# through the hkey CLI, because they need access to raw response headers
# and low-level HTTP behaviour that the CLI does not expose.

import os
import pytest
import requests
import hkey


def server_url():
    return os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "http://localhost:8080")


def admin_token():
    """Return a valid admin access token, logging in if necessary."""
    hkey.login()
    return hkey.client.AUTH_TOKEN


# ---------------------------------------------------------------------------
# 1.1 Health & Readiness
# ---------------------------------------------------------------------------

class TestHealthReadiness:

    def test_healthz_returns_200_without_auth(self):
        """1.1.1 — GET /healthz returns 200 with no authentication."""
        r = requests.get(f"{server_url()}/healthz")
        assert r.status_code == 200

    def test_readyz_returns_200_when_db_reachable(self):
        """1.1.2 — GET /readyz returns 200 when the database is reachable."""
        r = requests.get(f"{server_url()}/readyz")
        assert r.status_code == 200

    @pytest.mark.xfail(
        reason="Requires deliberately breaking DB connectivity; not run in standard CI"
    )
    def test_readyz_returns_non_200_when_db_unreachable(self):
        """1.1.3 — GET /readyz returns non-200 when the database is unreachable."""
        r = requests.get(f"{server_url()}/readyz")
        assert r.status_code != 200

    def test_about_public_returns_version_without_auth(self):
        """1.1.4 — GET /about returns version, edition and build info without auth."""
        r = requests.get(f"{server_url()}/about")
        assert r.status_code == 200
        data = r.json()
        # Expect a nested data object with version fields
        payload = data.get("data", data)
        assert "version" in payload or any("version" in str(v).lower() for v in payload.values()), \
            f"No version info found in response: {data}"

    def test_system_about_admin_requires_auth(self):
        """1.1.5 (auth guard) — GET /v1/system/about returns 401 without a token."""
        r = requests.get(f"{server_url()}/v1/system/about")
        assert r.status_code == 401

    def test_system_about_admin_returns_data_with_auth(self):
        """1.1.5 — GET /v1/system/about returns system info when authenticated."""
        r = requests.get(
            f"{server_url()}/v1/system/about",
            headers={"Authorization": f"Bearer {admin_token()}"},
        )
        assert r.status_code == 200
        data = r.json()
        payload = data.get("data", data)
        # Should contain something about version or edition
        assert payload, f"Empty data in system about response: {data}"

    def test_system_status_requires_auth(self):
        """1.1.6 (auth guard) — GET /v1/system/status returns 401 without a token."""
        r = requests.get(f"{server_url()}/v1/system/status")
        assert r.status_code == 401

    def test_system_status_returns_data_with_auth(self):
        """1.1.6 — GET /v1/system/status returns master key status and DB info."""
        r = requests.get(
            f"{server_url()}/v1/system/status",
            headers={"Authorization": f"Bearer {admin_token()}"},
        )
        assert r.status_code == 200
        data = r.json()
        payload = data.get("data", data)
        assert payload, f"Empty data in system status response: {data}"


# ---------------------------------------------------------------------------
# 1.2 Security Headers
# ---------------------------------------------------------------------------

# Endpoints to probe for security headers. We use a mix of authenticated
# and unauthenticated endpoints so we cover both code paths.
PROBE_ENDPOINTS = [
    "/healthz",
    "/readyz",
    "/about",
]

PROBE_ENDPOINTS_AUTHED = [
    "/v1/system/about",
    "/v1/system/status",
]


class TestSecurityHeaders:

    def _get(self, path, token=None):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return requests.get(f"{server_url()}{path}", headers=headers)

    @pytest.mark.parametrize("path", PROBE_ENDPOINTS)
    def test_x_content_type_options_nosniff_public(self, path):
        """1.2.1 — Responses include X-Content-Type-Options: nosniff (public endpoints)."""
        r = self._get(path)
        assert r.headers.get("X-Content-Type-Options", "").lower() == "nosniff", \
            f"Missing or wrong X-Content-Type-Options on {path}: {dict(r.headers)}"

    @pytest.mark.parametrize("path", PROBE_ENDPOINTS_AUTHED)
    def test_x_content_type_options_nosniff_authed(self, path):
        """1.2.1 — Responses include X-Content-Type-Options: nosniff (authed endpoints)."""
        r = self._get(path, token=admin_token())
        assert r.headers.get("X-Content-Type-Options", "").lower() == "nosniff", \
            f"Missing or wrong X-Content-Type-Options on {path}: {dict(r.headers)}"

    @pytest.mark.parametrize("path", PROBE_ENDPOINTS)
    def test_x_frame_options_deny_public(self, path):
        """1.2.2 — Responses include X-Frame-Options: DENY (public endpoints)."""
        r = self._get(path)
        assert r.headers.get("X-Frame-Options", "").upper() == "DENY", \
            f"Missing or wrong X-Frame-Options on {path}: {dict(r.headers)}"

    @pytest.mark.parametrize("path", PROBE_ENDPOINTS_AUTHED)
    def test_x_frame_options_deny_authed(self, path):
        """1.2.2 — Responses include X-Frame-Options: DENY (authed endpoints)."""
        r = self._get(path, token=admin_token())
        assert r.headers.get("X-Frame-Options", "").upper() == "DENY", \
            f"Missing or wrong X-Frame-Options on {path}: {dict(r.headers)}"

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_HKEY_SERVER_URL", "").startswith("https://"),
        reason="HSTS header only meaningful over HTTPS; set HKEY_TEST_HKEY_SERVER_URL to an https:// address to run"
    )
    def test_hsts_header_present_over_https(self):
        """1.2.3 — HTTPS responses include Strict-Transport-Security."""
        r = self._get("/healthz")
        hsts = r.headers.get("Strict-Transport-Security", "")
        assert hsts, f"Missing Strict-Transport-Security header: {dict(r.headers)}"
        assert "max-age=" in hsts, f"HSTS header missing max-age: {hsts}"

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_CORS_ALLOWED_ORIGIN"),
        reason="CORS not configured; set HKEY_TEST_CORS_ALLOWED_ORIGIN to an allowed origin to run"
    )
    def test_cors_header_present_for_configured_origin(self):
        """1.2.4 — CORS headers are returned for an allowed origin."""
        origin = os.environ.get("HKEY_TEST_CORS_ALLOWED_ORIGIN", "http://localhost:3000")
        r = requests.get(
            f"{server_url()}/healthz",
            headers={"Origin": origin},
        )
        assert r.status_code == 200
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        assert acao, \
            f"No Access-Control-Allow-Origin header for origin '{origin}': {dict(r.headers)}"

    @pytest.mark.skipif(
        not os.environ.get("HKEY_TEST_CORS_ALLOWED_ORIGIN"),
        reason="CORS not configured; set HKEY_TEST_CORS_ALLOWED_ORIGIN to an allowed origin to run"
    )
    def test_cors_preflight_for_configured_origin(self):
        """1.2.4 — CORS preflight (OPTIONS) succeeds for an allowed origin."""
        origin = os.environ.get("HKEY_TEST_CORS_ALLOWED_ORIGIN", "http://localhost:3000")
        r = requests.options(
            f"{server_url()}/healthz",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
            },
        )
        # 200 or 204 are both valid preflight responses
        assert r.status_code in (200, 204), \
            f"Unexpected preflight status {r.status_code}: {r.text}"
        assert r.headers.get("Access-Control-Allow-Origin"), \
            f"No ACAO header in preflight response: {dict(r.headers)}"

    def test_cors_header_absent_for_unconfigured_origin(self):
        """1.2.5 — CORS headers are NOT returned for an unlisted origin."""
        rogue_origin = os.environ.get("HKEY_TEST_CORS_DISALLOWED_ORIGIN", "http://evil.example.com")
        r = requests.get(
            f"{server_url()}/healthz",
            headers={"Origin": rogue_origin},
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        assert acao != "*" and acao != rogue_origin, \
            f"Server reflected disallowed origin '{rogue_origin}' in ACAO: {acao}"
