// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::service::audit::ChainVerifyResult;
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use hierarkey_core::license::Feature;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct VerifyRequest {
    /// Start verification from this seq (inclusive, default 1).
    pub from_seq: Option<i64>,
    /// Maximum events to check (default 10 000, max 100 000).
    pub limit: Option<i64>,
}

#[axum::debug_handler]
pub(crate) async fn verify(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(_call_ctx): Extension<CallContext>,
    ApiJson(req): ApiJson<VerifyRequest>,
) -> ApiResult<Json<ApiResponse<ChainVerifyResult>>> {
    if !state
        .audit_service
        .license_service
        .get_effective_license()
        .has_feature(&Feature::Audit)
    {
        return Err(HttpError::forbidden(
            ApiErrorCtx {
                fail_code: ApiCode::AuditVerifyFailed,
            },
            "Audit logging is only available in the Commercial edition.",
        ));
    }

    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AuditVerifyFailed,
    };

    let result = state
        .audit_service
        .verify_chain(req.from_seq, req.limit)
        .await
        .ctx(ctx)?;

    let msg = if result.valid {
        "Audit chain integrity verified"
    } else {
        "Audit chain integrity check failed — chain is broken"
    };

    let status = ApiStatus::new(ApiCode::AuditVerifySucceeded, msg);
    Ok(Json(ApiResponse::ok(status, result)))
}
