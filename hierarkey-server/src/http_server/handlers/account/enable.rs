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
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EnableRequest {
    reason: Option<String>,
}

#[axum::debug_handler]
pub(crate) async fn enable(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(account_name): ApiPath<String>,
    ApiJson(req): ApiJson<EnableRequest>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountEnableFailed,
    };

    let result = super::resolve_account(&state, &call_ctx, ctx, &account_name).await?;
    let account = match result {
        Some(account) => account,
        None => {
            return Err(HttpError::not_found(ctx, format!("Account '{account_name}' not found")));
        }
    };

    // Sanity check: we could not be here if we are disabled to begin with
    if account.id == _auth.user.id {
        return Err(HttpError::bad_request(ctx, "Cannot enable your own account".to_string()));
    }
    let result = state.account_service.enable(&call_ctx, account.id, req.reason).await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_STATUS_CHANGE, outcome)
                .with_resource("account", account.id.0, account.name.as_str())
                .with_metadata(serde_json::json!({"action": "enable"}))
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_STATUS_CHANGE, AuditOutcome::Success)
                .with_resource("account", account.id.0, account.name.as_str())
                .with_metadata(serde_json::json!({"action": "enable"})),
        )
        .await;

    let status = ApiStatus::new(ApiCode::AccountEnable, "Account enabled successfully");
    Ok(Json(ApiResponse::ok_no_data(status)))
}
