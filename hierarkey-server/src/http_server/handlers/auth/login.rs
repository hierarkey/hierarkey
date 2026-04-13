// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::auth_response::{AuthRequest, AuthResponse, AuthScope};
use crate::manager::account::Password;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use crate::service::auth::PasswordOrPassphrase;
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use zeroize::Zeroizing;

#[axum::debug_handler]
pub(crate) async fn login(
    State(state): State<AppState>,
    Extension(call_ctx): Extension<CallContext>,
    // No authentication required for login
    ApiJson(req): ApiJson<AuthRequest>,
) -> ApiResult<Json<ApiResponse<AuthResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AuthLoginFailed,
    };

    let password = Password::new(&req.password);
    let auth_result = state
        .auth_service
        .authenticate_with_name_secret(&call_ctx, &req.account_name, &PasswordOrPassphrase::Password(password))
        .await;

    if auth_result.is_err() {
        metrics::counter!("hierarkey_auth_logins_total", "result" => "failure").increment(1);
        state
            .audit_service
            .log(
                AuditEvent::from_ctx(&call_ctx, event_type::AUTH_LOGIN_FAILURE, AuditOutcome::Failure)
                    .with_metadata(serde_json::json!({"account_name": req.account_name.to_string()})),
            )
            .await;
    } else {
        metrics::counter!("hierarkey_auth_logins_total", "result" => "success").increment(1);
    }
    let account = auth_result.ctx(ctx)?;

    // Credentials verified — record this stage before branching into token issuance.
    // AUTH_LOGIN_SUCCESS is emitted below only after a token is actually created.
    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::AUTH_LOGIN_CREDENTIALS_OK, AuditOutcome::Success)
                .with_actor(account.id.0, "account", account.name.as_str()),
        )
        .await;

    if account.must_change_password {
        let (token_str, pat) = state
            .auth_service
            .create_pat(&call_ctx, &account, "Change password token", 10, AuthScope::ChangePassword)
            .await
            .ctx(ctx)?;

        state
            .audit_service
            .log(
                AuditEvent::from_ctx(&call_ctx, event_type::AUTH_LOGIN_SUCCESS, AuditOutcome::Success)
                    .with_actor(account.id.0, "account", account.name.as_str())
                    .with_metadata(serde_json::json!({"scope": "change_password"})),
            )
            .await;

        let data = AuthResponse {
            account_id: account.id,
            account_short_id: account.short_id.to_string(),
            account_name: account.name,
            scope: AuthScope::ChangePassword,
            access_token: Zeroizing::new(token_str.clone()),
            expires_at: pat.expires_at,
            refresh_token: Zeroizing::new(String::new()),
            refresh_expires_at: pat.expires_at,
            mfa_required: false,
            mfa_method: None,
        };

        let status = ApiStatus::new(ApiCode::AuthPasswordChangeRequired, "Password change required".to_string());
        return Ok(Json(ApiResponse::ok(status, data)));
    }

    // MFA check: if MFA is enabled for this account and a provider is registered,
    // issue a short-lived challenge token instead of a full auth token.
    if account.mfa_enabled {
        match &state.mfa_provider {
            None => {
                return Err(HttpError {
                    http: StatusCode::FORBIDDEN,
                    fail_code: ctx.fail_code,
                    reason: ApiErrorCode::Forbidden,
                    message: "MFA is enabled for this account but the MFA provider is not available in this edition"
                        .into(),
                    details: None,
                });
            }
            Some(provider) => {
                let challenge = provider.begin_challenge(&state, &call_ctx, &account).await?;

                state
                    .audit_service
                    .log(
                        AuditEvent::from_ctx(&call_ctx, event_type::AUTH_LOGIN_SUCCESS, AuditOutcome::Success)
                            .with_actor(account.id.0, "account", account.name.as_str())
                            .with_metadata(serde_json::json!({"scope": "mfa_challenge"})),
                    )
                    .await;

                let data = AuthResponse {
                    account_id: account.id,
                    account_short_id: account.short_id.to_string(),
                    account_name: account.name.clone(),
                    scope: AuthScope::MfaChallenge,
                    access_token: challenge.challenge_token,
                    expires_at: challenge.expires_at,
                    refresh_token: Zeroizing::new(String::new()),
                    refresh_expires_at: challenge.expires_at,
                    mfa_required: true,
                    mfa_method: Some(challenge.method.as_str().to_string()),
                };
                let status = ApiStatus::new(ApiCode::MfaChallengeRequired, "MFA verification required".to_string());
                return Ok(Json(ApiResponse::ok(status, data)));
            }
        }
    }

    let access_ttl = req.ttl_minutes as i64;
    let refresh_ttl = state.auth_service.refresh_token_ttl_minutes;

    let (access_str, access_pat) = state
        .auth_service
        .create_pat(&call_ctx, &account, "Login access token", access_ttl, req.scope)
        .await
        .ctx(ctx)?;

    let (refresh_str, refresh_pat) = state
        .auth_service
        .create_pat(&call_ctx, &account, "Login refresh token", refresh_ttl, AuthScope::Refresh)
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::AUTH_LOGIN_SUCCESS, AuditOutcome::Success)
                .with_actor(account.id.0, "account", account.name.as_str())
                .with_metadata(serde_json::json!({"scope": "auth"})),
        )
        .await;

    let data = AuthResponse {
        account_id: account.id,
        account_short_id: account.short_id.to_string(),
        account_name: account.name,
        scope: access_pat.purpose.into(),
        access_token: Zeroizing::new(access_str),
        expires_at: access_pat.expires_at,
        refresh_token: Zeroizing::new(refresh_str),
        refresh_expires_at: refresh_pat.expires_at,
        mfa_required: false,
        mfa_method: None,
    };

    let status = ApiStatus::new(ApiCode::AuthLoginSucceeded, "Login successful".to_string());
    Ok(Json(ApiResponse::ok(status, data)))
}
