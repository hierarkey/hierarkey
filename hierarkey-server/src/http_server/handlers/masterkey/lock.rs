// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::{ApiJson, ApiPath};
use crate::http_server::handlers::ApiResult;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use crate::service::masterkey::MasterKeyLockOutcome;
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct LockRequest {
    reason: Option<String>,
}

#[axum::debug_handler]
pub(crate) async fn lock(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(name): ApiPath<String>,
    ApiJson(payload): ApiJson<LockRequest>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::MasterKeyLockFailed,
    };

    let master_key = super::resolve_masterkey(&state, &call_ctx, ctx, &name).await?;

    let result = state.masterkey_service.lock(&call_ctx, &master_key, payload.reason);
    if result.is_err() {
        state
            .audit_service
            .log(
                AuditEvent::from_ctx(&call_ctx, event_type::MASTERKEY_LOCK, AuditOutcome::Failure)
                    .with_resource_ref("masterkey", &master_key.name),
            )
            .await;
    }
    let result = result.map_err(|e| HttpError::from_lock_error(e, ctx))?;

    let status = match result {
        MasterKeyLockOutcome::AlreadyLocked => {
            ApiStatus::new(ApiCode::MasterKeyAlreadyLocked, "Masterkey was already locked".to_string())
        }
        MasterKeyLockOutcome::Locked => {
            state
                .audit_service
                .log(
                    AuditEvent::from_ctx(&call_ctx, event_type::MASTERKEY_LOCK, AuditOutcome::Success)
                        .with_resource_ref("masterkey", &master_key.name),
                )
                .await;
            ApiStatus::new(ApiCode::MasterKeyLocked, "Masterkey locked successfully".to_string())
        }
    };

    Ok(Json(ApiResponse::ok_no_data(status)))
}
