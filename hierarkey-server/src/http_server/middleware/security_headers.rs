// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::global::config::ServerMode;
use crate::http_server::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, Request, header};
use axum::middleware::Next;
use axum::response::Response;

pub async fn security_headers_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let cfg = &state.config.security_headers;

    let mut response = next.run(request).await;

    if !cfg.enabled {
        return response;
    }

    let h = response.headers_mut();

    // Prevent MIME-type sniffing (the original issue).
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));

    // Deny framing — prevents clickjacking.
    h.insert(HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY"));

    // No referrer information leaked to third parties.
    h.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );

    // Disable the legacy XSS auditor; modern browsers use CSP instead, and the
    // auditor can itself introduce vulnerabilities.
    h.insert(HeaderName::from_static("x-xss-protection"), HeaderValue::from_static("0"));

    // Pure JSON API — no content should be loaded from anywhere.
    h.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'"),
    );

    // Disable browser APIs that make no sense for an API server.
    h.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=(), payment=(), usb=()"),
    );

    // Never cache responses — critical for a secrets manager.
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    // HSTS: only emit when explicitly enabled AND the server is running in TLS mode.
    // Sending HSTS over plain HTTP is incorrect and would lock browsers out.
    if cfg.hsts_enabled && matches!(state.config.server.mode, ServerMode::Tls) {
        let mut hsts = format!("max-age={}", cfg.hsts_max_age_seconds);
        if cfg.hsts_include_subdomains {
            hsts.push_str("; includeSubDomains");
        }
        if cfg.hsts_preload {
            hsts.push_str("; preload");
        }
        if let Ok(value) = HeaderValue::from_str(&hsts) {
            h.insert(header::STRICT_TRANSPORT_SECURITY, value);
        }
    }

    response
}
