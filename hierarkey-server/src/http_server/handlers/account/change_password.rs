// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::{ApiJson, ApiPath};
use crate::http_server::handlers::ApiResult;
use crate::manager::account::Password;
use crate::manager::token::TokenPurpose;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
pub struct ChangePasswordBody {
    pub password: Zeroizing<String>,
}

#[axum::debug_handler]
pub(crate) async fn change_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(account_name): ApiPath<String>,
    ApiJson(payload): ApiJson<ChangePasswordBody>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountPasswordRotateFailed,
    };

    let Some(account) = super::resolve_account(&state, &call_ctx, ctx, &account_name).await? else {
        return Err(HttpError {
            http: StatusCode::NOT_FOUND,
            fail_code: ApiCode::AccountPasswordRotateFailed,
            reason: ApiErrorCode::NotFound,
            message: format!("User '{account_name}' not found or not active"),
            details: None,
        });
    };

    // Only the account owner may change their own password.
    // Admin/RBAC override can be added here later.
    if account.id != auth.user.id {
        return Err(HttpError {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ApiCode::AccountPasswordRotateFailed,
            reason: ApiErrorCode::Unauthorized,
            message: "You can only change your own password".into(),
            details: None,
        });
    }

    let password = Password::new(&payload.password);
    let result = state
        .account_service
        .update_password(&call_ctx, &account, &password)
        .await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_PASSWORD_CHANGE, outcome).with_resource(
                "account",
                account.id.0,
                account.name.as_str(),
            )
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_PASSWORD_CHANGE, AuditOutcome::Success).with_resource(
                "account",
                account.id.0,
                account.name.as_str(),
            ),
        )
        .await;

    // We successfully changed the password. If we did this with a token with the
    // ChangePwd scope, we should now revoke that token.
    if auth.pat.purpose == TokenPurpose::ChangePwd {
        state
            .token_service
            .revoke_token(&call_ctx, auth.pat.id)
            .await
            .ctx(ctx)?;
    }

    let status = ApiStatus::new(ApiCode::AccountPasswordRotated, "Password updated successfully".to_string());
    Ok(Json(ApiResponse::ok_no_data(status)))
}
