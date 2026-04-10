// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::manager::token::PatId;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};

#[axum::debug_handler]
pub(crate) async fn revoke(
    State(state): State<AppState>,
    auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AuthTokenRevokeFailed,
    };

    let pat_id = PatId::try_from(id.as_str()).ctx(ctx)?;

    let Some(token_info) = state.auth_service.pat_info(&call_ctx, pat_id).await.ctx(ctx)? else {
        return Err(HttpError {
            http: StatusCode::NOT_FOUND,
            fail_code: ApiCode::AuthTokenRevokeFailed,
            reason: ApiErrorCode::NotFound,
            message: format!("Token '{pat_id}' is not found, cannot revoke"),
            details: None,
        });
    };

    // Only the token owner may revoke it. Admin/RBAC override can be added here later.
    if token_info.account_id != auth.user.id {
        return Err(HttpError {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ApiCode::AuthTokenRevokeFailed,
            reason: ApiErrorCode::Unauthorized,
            message: format!("Unauthorized to revoke token '{pat_id}'"),
            details: None,
        });
    }

    let result = state.auth_service.pat_revoke(&call_ctx, pat_id).await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::PAT_REVOKED, outcome).with_resource(
                "pat",
                pat_id.0,
                pat_id.to_string(),
            )
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::PAT_REVOKED, AuditOutcome::Success).with_resource(
                "pat",
                pat_id.0,
                pat_id.to_string(),
            ),
        )
        .await;

    let status = ApiStatus::new(ApiCode::AuthTokenRevoked, "Token revoked successfully".to_string());

    Ok(Json(ApiResponse::ok_no_data(status)))
}
