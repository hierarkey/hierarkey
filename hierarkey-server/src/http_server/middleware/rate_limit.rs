// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::http_server::AppState;
use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorBody, ApiErrorCode, ApiStatus};
use std::net::IpAddr;

/// Extract the client IP address, preferring proxy headers over the raw peer address.
fn extract_client_ip(headers: &HeaderMap, fallback: Option<IpAddr>) -> IpAddr {
    if let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(val) = forwarded.to_str()
    {
        let first = val.split(',').next().unwrap_or("").trim();
        if let Ok(ip) = first.parse::<IpAddr>() {
            return ip;
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip")
        && let Ok(val) = real_ip.to_str()
        && let Ok(ip) = val.trim().parse::<IpAddr>()
    {
        return ip;
    }
    fallback.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

/// Rate-limit middleware for auth endpoints.
///
/// When `state.auth_rate_limiter` is `Some`, checks the per-IP token bucket and
/// returns `429 Too Many Requests` if the bucket is exhausted.
pub async fn auth_rate_limit_middleware(State(state): State<AppState>, request: Request<Body>, next: Next) -> Response {
    if let Some(ref limiter) = state.auth_rate_limiter {
        let peer_addr = request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|c| c.0.ip());
        let ip = extract_client_ip(request.headers(), peer_addr);

        if limiter.check_key(&ip).is_err() {
            metrics::counter!("hierarkey_rate_limit_exceeded_total", "endpoint" => "auth").increment(1);
            let message = "Too many requests, please try again later".to_string();
            let status = ApiStatus::new(ApiCode::RateLimited, message.clone());
            let body = ApiResponse::<()> {
                status,
                error: Some(ApiErrorBody {
                    code: ApiErrorCode::RateLimited,
                    message,
                    details: None,
                }),
                data: None,
            };
            return (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
        }
    }
    next.run(request).await
}
