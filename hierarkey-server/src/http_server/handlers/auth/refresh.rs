// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::auth_response::{AuthResponse, AuthScope};
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use zeroize::Zeroizing;

#[axum::debug_handler]
pub(crate) async fn refresh(
    State(state): State<AppState>,
    Extension(call_ctx): Extension<CallContext>,
    req: axum::http::Request<axum::body::Body>,
) -> ApiResult<Json<ApiResponse<AuthResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AuthLoginFailed,
    };

    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| HttpError {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ctx.fail_code,
            reason: hierarkey_core::api::status::ApiErrorCode::Unauthorized,
            message: "Bearer refresh token required".into(),
            details: None,
        })?;

    let (account, access_str, access_pat, refresh_str, refresh_pat) = state
        .auth_service
        .exchange_refresh_token(&call_ctx, token)
        .await
        .inspect_err(|_| metrics::counter!("hierarkey_auth_token_refreshes_total", "result" => "failure").increment(1))
        .ctx(ctx)?;
    metrics::counter!("hierarkey_auth_token_refreshes_total", "result" => "success").increment(1);

    let data = AuthResponse {
        account_id: account.id,
        account_short_id: account.short_id.to_string(),
        account_name: account.name,
        scope: AuthScope::Auth,
        access_token: Zeroizing::new(access_str),
        expires_at: access_pat.expires_at,
        refresh_token: Zeroizing::new(refresh_str),
        refresh_expires_at: refresh_pat.expires_at,
        mfa_required: false,
        mfa_method: None,
    };

    let status = ApiStatus::new(ApiCode::AuthLoginSucceeded, "Token refreshed successfully".to_string());
    Ok(Json(ApiResponse::ok(status, data)))
}
