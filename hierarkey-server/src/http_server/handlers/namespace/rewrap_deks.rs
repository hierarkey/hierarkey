// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::Serialize;

#[derive(Serialize)]
pub struct RewrapDeksResponse {
    rewrapped: usize,
    skipped: usize,
}

#[axum::debug_handler]
pub(crate) async fn rewrap_deks(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(param): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<RewrapDeksResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::SecretRewrapFailed,
    };

    let namespace = super::resolve_namespace(&state, &call_ctx, ctx, &param).await?;

    let (rewrapped, skipped) = state
        .secret_service
        .rewrap_deks_for_namespace(&call_ctx, namespace.id)
        .await
        .ctx(ctx)?;
    metrics::counter!("hierarkey_dek_rewraps_total").increment(rewrapped as u64);

    let status = ApiStatus::new(ApiCode::SecretRewrapped, "DEKs rewrapped successfully");

    Ok(Json(ApiResponse::ok(status, RewrapDeksResponse { rewrapped, skipped })))
}
