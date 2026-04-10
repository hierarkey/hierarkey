// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use axum::body::Body;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use tracing::info;

/// A middleware that logs incoming requests and outgoing responses.
pub async fn logging_middleware(req: Request<Body>, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    let ids = req
        .extensions()
        .get::<CallContext>()
        .map(|a| (a.request_id, a.trace_id));

    if let Some((request_id, trace_id)) = ids {
        info!("request: {} {} request_id={} trace_id={}", method, path, request_id, trace_id);
    } else {
        info!("request: {} {}", method, path);
    }

    let response = next.run(req).await;
    let status = response.status();

    info!("response: {} {} - {}", method, path, status.as_u16());
    response
}
