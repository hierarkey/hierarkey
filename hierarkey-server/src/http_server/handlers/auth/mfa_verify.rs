// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::auth_response::{AuthResponse, AuthScope};
use crate::manager::token::TokenPurpose;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Deserialize, Serialize)]
pub struct MfaVerifyRequest {
    /// The short-lived MFA-challenge token returned by `POST /auth/login`.
    pub challenge_token: Zeroizing<String>,
    /// The TOTP code or backup code to verify.
    pub code: Zeroizing<String>,
    /// Requested access-token TTL in minutes (capped by server config).
    #[serde(default)]
    pub ttl_minutes: Option<u32>,
}

#[axum::debug_handler]
pub(crate) async fn mfa_verify(
    State(state): State<AppState>,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(req): ApiJson<MfaVerifyRequest>,
) -> ApiResult<Json<ApiResponse<AuthResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::MfaChallengeFailed,
    };

    let mfa_provider = state.mfa_provider.as_ref().ok_or_else(|| HttpError {
        http: StatusCode::NOT_IMPLEMENTED,
        fail_code: ctx.fail_code,
        reason: ApiErrorCode::Forbidden,
        message: "MFA is not available on this server".into(),
        details: None,
    })?;

    // Validate the MFA-challenge token. This also checks expiry.
    let (account, pat) = state
        .auth_service
        .authenticate(&call_ctx, req.challenge_token.trim())
        .await
        .map_err(|_| HttpError {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::Unauthorized,
            message: "invalid or expired challenge token".into(),
            details: None,
        })?;

    // Ensure this token has the MfaChallenge purpose (not a regular auth token).
    if pat.purpose != TokenPurpose::MfaChallenge {
        return Err(HttpError {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::Unauthorized,
            message: "token is not an MFA challenge token".into(),
            details: None,
        });
    }

    // Revoke the challenge token immediately — it is single-use.
    let _ = state.auth_service.pat_revoke(&call_ctx, pat.id).await;

    // Delegate code verification to the commercial provider.
    let verify_result = mfa_provider.verify_code(&state, &call_ctx, &account, &req.code).await;
    if verify_result.is_err() {
        state
            .audit_service
            .log(
                AuditEvent::from_ctx(&call_ctx, event_type::AUTH_MFA_VERIFY_FAILURE, AuditOutcome::Failure).with_actor(
                    account.id.0,
                    "account",
                    account.name.as_str(),
                ),
            )
            .await;
    }
    verify_result?;

    // Code is valid — issue full access + refresh tokens.
    let access_ttl = match req.ttl_minutes {
        Some(t) if t == 0 || t as i64 > crate::manager::token::MAX_TTL_MINUTES => {
            return Err(HttpError::bad_request(ctx, "ttl_minutes out of range"));
        }
        Some(t) => t as i64,
        None => state.auth_service.access_token_ttl_minutes,
    };
    let refresh_ttl = state.auth_service.refresh_token_ttl_minutes;

    let (access_str, access_pat) = state
        .auth_service
        .create_pat(&call_ctx, &account, "MFA login access token", access_ttl, AuthScope::Auth)
        .await
        .ctx(ctx)?;

    let (refresh_str, refresh_pat) = state
        .auth_service
        .create_pat(&call_ctx, &account, "MFA login refresh token", refresh_ttl, AuthScope::Refresh)
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::AUTH_MFA_VERIFY_SUCCESS, AuditOutcome::Success).with_actor(
                account.id.0,
                "account",
                account.name.as_str(),
            ),
        )
        .await;

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

    let status = ApiStatus::new(
        ApiCode::AuthLoginSucceeded,
        "MFA verification successful, login complete".to_string(),
    );
    Ok(Json(ApiResponse::ok(status, data)))
}
