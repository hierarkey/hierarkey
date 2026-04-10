// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;

#[derive(Serialize)]
struct HealthzResponse {
    status: &'static str,
}

pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(HealthzResponse { status: "alive" }))
}
