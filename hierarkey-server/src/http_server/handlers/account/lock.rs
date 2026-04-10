// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::{ApiJson, ApiPath};
use crate::http_server::handlers::ApiResult;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct LockRequest {
    reason: Option<String>,
    locked_until: Option<DateTime<Utc>>,
}

#[axum::debug_handler]
pub(crate) async fn lock(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(account_name): ApiPath<String>,
    ApiJson(req): ApiJson<LockRequest>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountLockFailed,
    };

    let result = super::resolve_account(&state, &call_ctx, ctx, &account_name).await?;
    let account = match result {
        Some(account) => account,
        None => {
            return Err(HttpError::not_found(ctx, format!("Account '{account_name}' not found")));
        }
    };

    let result = state
        .account_service
        .lock(&call_ctx, account.id, req.reason, req.locked_until)
        .await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_STATUS_CHANGE, outcome)
                .with_resource("account", account.id.0, account.name.as_str())
                .with_metadata(serde_json::json!({"action": "lock"}))
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_STATUS_CHANGE, AuditOutcome::Success)
                .with_resource("account", account.id.0, account.name.as_str())
                .with_metadata(serde_json::json!({"action": "lock"})),
        )
        .await;

    let status = ApiStatus::new(ApiCode::AccountLock, "Account locked successfully");
    Ok(Json(ApiResponse::ok_no_data(status)))
}
