// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};

#[axum::debug_handler]
pub async fn disable(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(sec_ref): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::SecretDisableFailed,
    };

    let secret = super::resolve_secret(&state, &call_ctx, ctx, &sec_ref).await?;

    let result = state.secret_service.disable_secret(&call_ctx, secret.id).await;
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

    let status = ApiStatus::new(ApiCode::SecretDisabled, format!("Secret '{sec_ref}' disabled successfully"));

    Ok(Json(ApiResponse::ok_no_data(status)))
}
