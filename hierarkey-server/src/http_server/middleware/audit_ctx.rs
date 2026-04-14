// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::{Actor, CallContext, Entrypoint, RequestId, TraceId};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

fn request_id_from_headers(headers: &HeaderMap) -> Option<RequestId> {
    headers
        .get("X-Hierarkey-Request-Id")
        .and_then(|value| value.to_str().ok())
        .and_then(|s| RequestId::from_str(s).ok())
}

fn client_ip_from_request(req: &Request<Body>) -> Option<IpAddr> {
    req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ci| ci.0.ip())
}

pub async fn audit_ctx_middleware(mut req: Request<Body>, next: Next) -> Response {
    let headers = req.headers().clone();

    let request_id = request_id_from_headers(&headers).unwrap_or_default();
    let trace_id = TraceId::new();
    let client_ip = client_ip_from_request(&req);

    let ctx = CallContext {
        actor: Actor::System,
        actor_name: None,
        request_id,
        trace_id,
        entrypoint: Entrypoint::Api,
        client_ip,
    };

    req.extensions_mut().insert(ctx);

    next.run(req).await
}
