// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::manager::secret::SecretId;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use std::str::FromStr;

#[axum::debug_handler]
pub async fn restore(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(sec_id_str): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::SecretRestoreFailed,
    };

    let secret_id = SecretId::from_str(&sec_id_str).map_err(|_| HttpError {
        http: StatusCode::BAD_REQUEST,
        fail_code: ApiCode::SecretRestoreFailed,
        reason: ApiErrorCode::InvalidRequest,
        message: format!("Invalid secret ID: '{sec_id_str}'"),
        details: None,
    })?;

    // We need the secret for audit logging; fetch it via find_by_id_any before restoring.
    let secret = state
        .secret_service
        .find_deleted_secret(&call_ctx, secret_id)
        .await
        .ctx(ctx)?
        .ok_or_else(|| HttpError::not_found(ctx, format!("Deleted secret '{sec_id_str}' not found")))?;

    let result = state.secret_service.restore_secret(&call_ctx, secret_id).await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_STATUS_CHANGE, outcome).with_resource(
                "secret",
                secret.id.0,
                &secret.ref_key,
            )
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_STATUS_CHANGE, AuditOutcome::Success).with_resource(
                "secret",
                secret.id.0,
                &secret.ref_key,
            ),
        )
        .await;

    let status = ApiStatus::new(ApiCode::SecretRestored, format!("Secret '{sec_id_str}' restored successfully"));

    Ok(Json(ApiResponse::ok_no_data(status)))
}
