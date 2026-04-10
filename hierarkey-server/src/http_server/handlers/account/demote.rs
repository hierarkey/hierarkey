// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::service::ApiMapErr;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};

#[axum::debug_handler]
pub(crate) async fn demote(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountDemotionFailed,
    };

    let result = super::resolve_account(&state, &call_ctx, ctx, &name).await?;
    let account = match result {
        Some(account) => account,
        None => {
            return Err(HttpError::not_found(ctx, format!("Account '{name}' not found")));
        }
    };

    let result = state.account_service.revoke_admin(&call_ctx, account.id).await;
    if result.is_err() {
        state
            .audit_service
            .log(
                AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_DEMOTE, AuditOutcome::Failure).with_resource(
                    "account",
                    account.id.0,
                    account.name.as_str(),
                ),
            )
            .await;
    }
    result.api_err(ApiCode::AccountDemotionFailed)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_DEMOTE, AuditOutcome::Success).with_resource(
                "account",
                account.id.0,
                account.name.as_str(),
            ),
        )
        .await;

    let status = ApiStatus::new(ApiCode::AccountDemotion, "Account demoted successfully to regular user");
    Ok(Json(ApiResponse::ok_no_data(status)))
}
