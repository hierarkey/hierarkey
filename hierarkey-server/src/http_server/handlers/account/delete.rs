// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde_json::json;

#[axum::debug_handler]
pub(crate) async fn delete(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(account_name): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountDeleteFailed,
    };

    let result = super::resolve_account(&state, &call_ctx, ctx, &account_name).await?;
    let account = match result {
        Some(account) => account,
        None => {
            return Err(HttpError::not_found(ctx, format!("Account '{account_name}' not found")));
        }
    };

    let result = state.account_service.delete_account(&call_ctx, account.id).await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_DELETE, outcome).with_resource(
                "account",
                account.id.0,
                account.name.as_str(),
            )
        })
        .await
        .ctx(ctx)?;

    let snapshot = json!({
        "account_type": account.account_type.to_string(),
        "email": account.email,
        "full_name": account.full_name,
        "description": account.metadata.description(),
        "labels": account.metadata.labels(),
    });

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_DELETE, AuditOutcome::Success)
                .with_resource("account", account.id.0, account.name.as_str())
                .with_metadata(snapshot),
        )
        .await;

    let status = ApiStatus::new(ApiCode::AccountDeleted, "Account deleted successfully");
    Ok(Json(ApiResponse::ok_no_data(status)))
}
