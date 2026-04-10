// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::auth::ed25519::{Ed25519Crypto, Ed25519PublicKey};
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::auth_response::{AuthResponse, AuthScope};
use crate::manager::account::AccountStatus;
use crate::service::account::{AccountType, Password};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use crate::service::auth::PasswordOrPassphrase;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::{Extension, Json};
use base64::Engine;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::resources::AccountName;
use serde::{Deserialize, Serialize};
use tracing::debug;
use zeroize::Zeroizing;

const ED25519_SIG_LEN: usize = 64;
const TS_WINDOW: u64 = 60;

/// Public key algorithms that can be used for key signatuer authentication
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum KeySigAlgo {
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum SaAuthRequest {
    /// Simple username/passphrase. Only available when configured in the config
    Passphrase {
        account_name: AccountName,
        passphrase: Zeroizing<String>,
    },

    /// Public/private key proof.
    ///
    /// JSON:
    /// {
    ///   "method": "key_sig",
    ///   "account": "app1",
    ///   "key_id": "sak_....",
    ///   "alg": "ed25519",
    ///   "nonce": "base64-or-hex",
    ///   "ts": 1700000000,
    ///   "sig": "base64"
    /// }
    KeySig {
        account_name: AccountName,
        key_id: String,
        alg: KeySigAlgo,
        nonce: String,
        ts: u64,
        sig: String,
    },

    /// Mutual TLS certificate authentication.
    /// This method is only available in the Hierarkey Commercial Edition.
    Mtls {},
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthTokenRequest {
    /// How we bootstrap / authenticate.
    pub auth: SaAuthRequest,
    #[serde(default)]
    pub scope: Option<AuthScope>,
    #[serde(default)]
    pub audience: Option<String>,
    /// Requested token lifetime in minutes. Capped to the server-configured maximum.
    #[serde(default)]
    pub ttl_minutes: Option<u32>,
}

#[axum::debug_handler]
pub(crate) async fn token(
    State(state): State<AppState>,
    Extension(call_ctx): Extension<CallContext>,
    method: Method,
    headers: HeaderMap,
    // No authentication required for login
    ApiJson(req): ApiJson<AuthTokenRequest>,
) -> ApiResult<Json<ApiResponse<AuthResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AuthTokenFailed,
    };

    // Validate the requested scope. Service-account tokens are always Auth
    // tokens; requesting ChangePassword here is nonsensical and is rejected
    // rather than silently ignored.
    let scope = match req.scope {
        None | Some(AuthScope::Auth) => AuthScope::Auth,
        Some(AuthScope::ChangePassword) => {
            return Err(HttpError::bad_request(
                ctx,
                "invalid scope for service account token: 'change_password' is not supported here",
            ));
        }
        Some(AuthScope::Refresh) => {
            return Err(HttpError::bad_request(
                ctx,
                "invalid scope for service account token: 'refresh' is not supported here",
            ));
        }
        Some(AuthScope::MfaChallenge) => {
            return Err(HttpError::bad_request(
                ctx,
                "invalid scope for service account token: 'mfa_challenge' is not supported here",
            ));
        }
    };

    let access_ttl = req
        .ttl_minutes
        .map(|t| t as i64)
        .unwrap_or(state.auth_service.access_token_ttl_minutes);

    let data: AuthResponse = match req.auth {
        SaAuthRequest::Passphrase {
            account_name,
            passphrase,
        } => {
            if !state.config.auth.allow_passphrase_auth {
                return Err(HttpError::forbidden(
                    ctx,
                    "passphrase authentication is disabled by server configuration",
                ));
            }
            authenticate_passphrase(&state, &call_ctx, ctx, account_name, passphrase, scope, access_ttl).await?
        }
        SaAuthRequest::KeySig {
            key_id,
            account_name,
            nonce,
            ts,
            sig,
            alg,
        } => {
            if !state.config.auth.allow_ed25519_auth {
                return Err(HttpError::forbidden(
                    ctx,
                    "Ed25519 key signature authentication is disabled by server configuration",
                ));
            }
            authenticate_keysig(
                &state,
                &call_ctx,
                ctx,
                key_id,
                account_name,
                nonce,
                ts,
                sig,
                alg,
                scope,
                method.as_str(),
                access_ttl,
            )
            .await?
        }
        SaAuthRequest::Mtls {} => {
            let Some(ref provider) = state.mtls_auth_provider else {
                return Err(HttpError {
                    http: StatusCode::NOT_IMPLEMENTED,
                    fail_code: ctx.fail_code,
                    reason: ApiErrorCode::Unauthorized,
                    message: "mTLS authentication is only available in the Hierarkey Commercial Edition".into(),
                    details: None,
                });
            };
            let peer_cert = extract_peer_cert_der(&headers);
            provider
                .authenticate(&state, &call_ctx, ctx, peer_cert, scope, access_ttl)
                .await?
        }
    };

    let status = ApiStatus::new(
        ApiCode::AuthTokenSucceeded,
        "Service account authenticated successful".to_string(),
    );
    Ok(Json(ApiResponse::ok(status, data)))
}

async fn authenticate_passphrase(
    state: &AppState,
    call_ctx: &CallContext,
    error_ctx: ApiErrorCtx,
    account_name: AccountName,
    passphrase: Zeroizing<String>,
    scope: AuthScope,
    ttl_minutes: i64,
) -> Result<AuthResponse, HttpError> {
    let account_row = state
        .account_service
        .find_by_name(call_ctx, &account_name)
        .await
        .map_err(|e| HttpError::bad_request(error_ctx, format!("failed to query account: {e}")))?
        .ok_or_else(|| HttpError::not_found(error_ctx, format!("account '{account_name}' not found")))?;

    if account_row.account_type == AccountType::System {
        return Err(HttpError::forbidden(
            error_ctx,
            "system accounts cannot authenticate via this endpoint",
        ));
    }

    if account_row.account_type != AccountType::Service {
        return Err(HttpError::forbidden(
            error_ctx,
            "only service accounts can use this token endpoint",
        ));
    }

    if account_row.passphrase_hash.is_none() {
        return Err(HttpError::forbidden(
            error_ctx,
            "passphrase authentication not allowed for this service account",
        ));
    }

    let passphrase = Password::new(&passphrase);
    let result = state
        .auth_service
        .authenticate_with_id_secret(call_ctx, account_row.id, &PasswordOrPassphrase::Passphrase(passphrase))
        .await;
    let user = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(call_ctx, event_type::AUTH_SERVICE_ACCOUNT_TOKEN, outcome).with_actor(
                account_row.id.0,
                "service_account",
                account_row.name.as_str(),
            )
        })
        .await
        .ctx(error_ctx)?;

    let (token_str, pat) = state
        .auth_service
        .create_pat(call_ctx, &user, "Service Account Token", ttl_minutes, scope)
        .await
        .ctx(error_ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(call_ctx, event_type::AUTH_SERVICE_ACCOUNT_TOKEN, AuditOutcome::Success).with_actor(
                account_row.id.0,
                "service_account",
                account_row.name.as_str(),
            ),
        )
        .await;

    Ok(AuthResponse {
        account_id: account_row.id,
        account_short_id: account_row.short_id.to_string(),
        account_name: account_row.name,
        scope: pat.purpose.into(),
        access_token: Zeroizing::new(token_str.clone()),
        expires_at: pat.expires_at,
        refresh_token: Zeroizing::new(String::new()),
        refresh_expires_at: pat.expires_at,
        mfa_required: false,
        mfa_method: None,
    })
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_keysig(
    state: &AppState,
    call_ctx: &CallContext,
    ctx: ApiErrorCtx,
    _key_id: String,
    account_name: AccountName,
    nonce: String,
    ts: u64,
    sig_b64: String,
    alg: KeySigAlgo,
    scope: AuthScope,
    method: &str,
    ttl_minutes: i64,
) -> Result<AuthResponse, HttpError> {
    if alg != KeySigAlgo::Ed25519 {
        return Err(HttpError::bad_request(ctx, "unsupported signature algorithm"));
    }

    if nonce.len() < 32 {
        return Err(HttpError::bad_request(ctx, "nonce must be at least 32 characters long"));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| HttpError {
            http: StatusCode::INTERNAL_SERVER_ERROR,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::InternalError,
            message: "system time is before UNIX_EPOCH".into(),
            details: None,
        })?
        .as_secs();

    if ts > now + TS_WINDOW || ts < now - TS_WINDOW {
        return Err(HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::ValidationFailed,
            message: "timestamp is outside of acceptable window".into(),
            details: None,
        });
    }

    // Reject replayed nonces before any DB work. The cache retains each nonce
    // for 2x the timestamp acceptance window, so every legitimately valid nonce
    // is tracked until it can no longer be replayed.
    if !state.sa_nonce_cache.try_consume(&nonce) {
        return Err(HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::ValidationFailed,
            message: "nonce has already been used".into(),
            details: None,
        });
    }

    // Resolve SA (by explicit account or by key_id mapping; choose what you support).
    let account_row = state
        .account_service
        .find_by_name(call_ctx, &account_name)
        .await
        .map_err(|e| HttpError::bad_request(ctx, format!("failed to query account: {e}")))?
        .ok_or_else(|| HttpError::not_found(ctx, format!("account '{account_name}' not found")))?;

    if account_row.account_type == AccountType::System {
        return Err(HttpError::forbidden(
            ctx,
            "system accounts cannot authenticate via this endpoint",
        ));
    }

    if account_row.account_type != AccountType::Service {
        return Err(HttpError::forbidden(ctx, "only service accounts can use this token endpoint"));
    }

    // Check temporary lockout (failed-attempt throttle).
    if let Some(locked_until) = account_row.locked_until
        && locked_until > chrono::Utc::now()
    {
        return Err(HttpError {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::Unauthorized,
            message: "account is temporarily locked due to repeated failed login attempts".into(),
            details: None,
        });
    }

    // Reject permanently disabled/deleted accounts.
    if account_row.status != AccountStatus::Active {
        return Err(HttpError {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::Unauthorized,
            message: "account is not active".into(),
            details: None,
        });
    }

    let Some(public_key_str) = account_row.public_key.as_ref() else {
        return Err(HttpError::forbidden(
            ctx,
            "key signature authentication not allowed for this service account",
        ));
    };
    let public_key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(public_key_str.as_bytes())
        .map_err(|_| HttpError {
            http: StatusCode::INTERNAL_SERVER_ERROR,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::InternalError,
            message: "invalid public key encoding for service account".into(),
            details: None,
        })?;
    if public_key_bytes.len() != 32 {
        return Err(HttpError::forbidden(ctx, "invalid public key size"));
    }
    let public_key_bytes: [u8; 32] = public_key_bytes.try_into().map_err(|_| HttpError {
        http: StatusCode::INTERNAL_SERVER_ERROR,
        fail_code: ctx.fail_code,
        reason: ApiErrorCode::InternalError,
        message: "invalid public key encoding for service account".into(),
        details: None,
    })?;
    let public_key = Ed25519PublicKey::from_bytes(public_key_bytes).map_err(|_| HttpError {
        http: StatusCode::INTERNAL_SERVER_ERROR,
        fail_code: ctx.fail_code,
        reason: ApiErrorCode::InternalError,
        message: "invalid public key encoding for service account".into(),
        details: None,
    })?;

    // We need to build up our signature and verify it
    let msg = format!(
        "hierarkey.sa_auth.v1|purpose:auth_token|method:{}|audience:{}|account:{}|ts:{}|nonce:{}",
        method, state.config.auth.audience, account_row.name, ts, nonce
    );
    debug!("Verifying signature for message: {}", msg);

    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|_| HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::ValidationFailed,
            message: "invalid signature encoding".into(),
            details: None,
        })?;

    if sig.len() != ED25519_SIG_LEN {
        return Err(HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::ValidationFailed,
            message: "invalid signature length".into(),
            details: None,
        });
    }

    if Ed25519Crypto::verify(&public_key, msg.as_bytes(), sig.as_slice()).is_err() {
        if let Err(e) = state.auth_service.record_failed_login(call_ctx, account_row.id).await {
            tracing::warn!("Failed to record failed keysig login for account {}: {e}", account_row.id);
        }
        state
            .audit_service
            .log(
                AuditEvent::from_ctx(call_ctx, event_type::AUTH_SERVICE_ACCOUNT_TOKEN, AuditOutcome::Failure)
                    .with_actor(account_row.id.0, "service_account", account_row.name.as_str()),
            )
            .await;
        return Err(HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::ValidationFailed,
            message: "signature verification failed".into(),
            details: None,
        });
    }

    let _ = state
        .auth_service
        .record_successful_login(call_ctx, account_row.id)
        .await;

    let user = state
        .account_service
        .get_by_id(call_ctx, account_row.id)
        .await
        .ctx(ctx)?;

    let (token_str, pat) = state
        .auth_service
        .create_pat(call_ctx, &user, "Service Account Token", ttl_minutes, scope)
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(call_ctx, event_type::AUTH_SERVICE_ACCOUNT_TOKEN, AuditOutcome::Success).with_actor(
                account_row.id.0,
                "service_account",
                account_row.name.as_str(),
            ),
        )
        .await;

    Ok(AuthResponse {
        account_id: account_row.id,
        account_short_id: account_row.short_id.to_string(),
        account_name: account_row.name,
        scope: pat.purpose.into(),
        access_token: Zeroizing::new(token_str.clone()),
        expires_at: pat.expires_at,
        refresh_token: Zeroizing::new(String::new()),
        refresh_expires_at: pat.expires_at,
        mfa_required: false,
        mfa_method: None,
    })
}

/// Extract the client-certificate DER bytes from the `X-Client-Cert` header.
///
/// This header is set by TLS-terminating proxies (nginx, envoy, haproxy) that
/// forward the client certificate to the upstream server. The value is expected
/// to be standard base64-encoded DER (no line wrapping).
///
/// Returns `None` when the header is absent or cannot be decoded.
pub fn extract_peer_cert_der(headers: &HeaderMap) -> Option<Vec<u8>> {
    let value = headers.get("x-client-cert")?;
    let b64 = value.to_str().ok()?;
    base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()
}
