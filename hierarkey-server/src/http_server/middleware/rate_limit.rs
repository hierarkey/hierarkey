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
use ipnet::IpNet;
use std::net::IpAddr;

/// Extract the client IP address for rate-limiting purposes.
///
/// Proxy-supplied headers (`X-Forwarded-For`, `X-Real-IP`) are **only** trusted
/// when `peer_ip` falls within one of `trusted_cidrs`. If the list is empty, or
/// the peer is not a known proxy, the raw peer address is used directly so that
/// an attacker cannot bypass rate limiting by spoofing these headers.
fn extract_client_ip(headers: &HeaderMap, peer_ip: Option<IpAddr>, trusted_cidrs: &[IpNet]) -> IpAddr {
    let peer = peer_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    let peer_is_trusted = !trusted_cidrs.is_empty() && trusted_cidrs.iter().any(|cidr| cidr.contains(&peer));

    if peer_is_trusted {
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
    }

    peer
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
        let ip = extract_client_ip(request.headers(), peer_addr, &state.config.trusted_proxy_cidrs);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn xff(ip: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", ip.parse().unwrap());
        h
    }

    fn real_ip(ip: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", ip.parse().unwrap());
        h
    }

    fn trusted(cidr: &str) -> Vec<IpNet> {
        vec![cidr.parse().unwrap()]
    }

    fn peer(ip: &str) -> Option<IpAddr> {
        Some(ip.parse().unwrap())
    }

    #[test]
    fn no_trusted_cidrs_ignores_xff_and_returns_peer() {
        let ip = extract_client_ip(&xff("1.2.3.4"), peer("5.6.7.8"), &[]);
        assert_eq!(ip, "5.6.7.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn no_trusted_cidrs_ignores_x_real_ip_and_returns_peer() {
        let ip = extract_client_ip(&real_ip("1.2.3.4"), peer("5.6.7.8"), &[]);
        assert_eq!(ip, "5.6.7.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn peer_not_in_trusted_cidr_ignores_xff() {
        let ip = extract_client_ip(&xff("1.2.3.4"), peer("8.8.8.8"), &trusted("10.0.0.0/8"));
        assert_eq!(ip, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_peer_uses_xff_first_entry() {
        let ip = extract_client_ip(&xff("1.2.3.4, 10.0.0.1"), peer("10.0.0.2"), &trusted("10.0.0.0/8"));
        assert_eq!(ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_peer_uses_x_real_ip_when_no_xff() {
        let ip = extract_client_ip(&real_ip("1.2.3.4"), peer("10.0.0.2"), &trusted("10.0.0.0/8"));
        assert_eq!(ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_peer_falls_back_to_peer_when_xff_invalid() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        let ip = extract_client_ip(&h, peer("10.0.0.2"), &trusted("10.0.0.0/8"));
        assert_eq!(ip, "10.0.0.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn no_peer_and_no_trusted_cidrs_returns_localhost() {
        let ip = extract_client_ip(&xff("1.2.3.4"), None, &[]);
        assert_eq!(ip, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }
}
