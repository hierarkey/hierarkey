// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::{Actor, CallContext, Entrypoint, RequestId, TraceId};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::net::{IpAddr, SocketAddr};

fn client_ip_from_request(req: &Request<Body>) -> Option<IpAddr> {
    req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ci| ci.0.ip())
}

pub async fn audit_ctx_middleware(mut req: Request<Body>, next: Next) -> Response {
    // Request IDs are always generated server-side. Accepting a client-supplied
    // X-Hierarkey-Request-Id would allow an attacker to plant chosen identifiers
    // in the audit trail.
    let request_id = RequestId::new();
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
