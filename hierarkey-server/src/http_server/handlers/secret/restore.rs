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

/// Resolve a secret ID from either a full UUID/ULID string or a ShortId (e.g. `sec_abc12345`).
/// Searches both active and deleted secrets so that restore operations can find deleted secrets.
async fn resolve_secret_id_any(state: &AppState, ctx: ApiErrorCtx, input: &str) -> Result<SecretId, HttpError> {
    if let Ok(id) = SecretId::from_str(input) {
        return Ok(id);
    }

    if input.starts_with(SecretId::PREFIX) {
        let row: Option<(SecretId,)> = sqlx::query_as("SELECT id FROM secrets WHERE short_id = $1 LIMIT 1")
            .bind(input)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| {
                HttpError::simple(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ctx.fail_code,
                    ApiErrorCode::DbError,
                    format!("database error: {e}"),
                )
            })?;
        return row
            .map(|(id,)| id)
            .ok_or_else(|| HttpError::not_found(ctx, format!("Secret '{input}' not found")));
    }

    Err(HttpError {
        http: StatusCode::BAD_REQUEST,
        fail_code: ctx.fail_code,
        reason: ApiErrorCode::InvalidRequest,
        message: format!("Invalid secret ID: '{input}'"),
        details: None,
    })
}

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

    let secret_id = resolve_secret_id_any(&state, ctx, &sec_id_str).await?;

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
