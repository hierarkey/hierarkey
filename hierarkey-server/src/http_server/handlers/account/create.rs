// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::account_response::{CreateAccountRequest, ServiceBootstrap};
use crate::manager::account::{AccountDto, Password};
use crate::service::account::{AccountData, CustomAccountData, CustomServiceAccountData, CustomUserAccountData};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::Labels;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::resources::AccountName;
use zeroize::Zeroizing;

#[axum::debug_handler]
pub(crate) async fn create(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(req): ApiJson<CreateAccountRequest>,
) -> ApiResult<Json<ApiResponse<AccountDto>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountCreateFailed,
    };

    match req {
        CreateAccountRequest::User {
            name,
            email,
            full_name,
            is_active,
            must_change_password,
            description,
            labels,
            password,
        } => {
            create_user_account(
                state,
                ctx,
                call_ctx,
                name,
                email,
                full_name,
                is_active,
                must_change_password,
                description,
                labels,
                password,
            )
            .await
        }
        CreateAccountRequest::Service {
            name,
            is_active,
            description,
            labels,
            bootstrap,
        } => create_service_account(state, ctx, call_ctx, name, is_active, description, labels, bootstrap).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn create_service_account(
    state: AppState,
    ctx: ApiErrorCtx,
    call_ctx: CallContext,
    account_name: AccountName,
    is_active: bool,
    description: Option<String>,
    labels: Labels,
    bootstrap: ServiceBootstrap,
) -> ApiResult<Json<ApiResponse<AccountDto>>> {
    if account_name.is_system_name() {
        return Err(HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::AccountCreateFailed,
            reason: ApiErrorCode::ValidationFailed,
            message: "Cannot create accounts starting with a $ (reserved for system accounts)".into(),
            details: None,
        });
    }

    let custom = match bootstrap {
        ServiceBootstrap::Passphrase { passphrase } => {
            validate_passphrase(&passphrase)?;
            CustomAccountData::Service(CustomServiceAccountData::Passphrase {
                passphrase: Password::new(&passphrase),
            })
        }
        ServiceBootstrap::Ed25519 { public_key } => {
            let _pk = parse_ed25519_public_key_b64(&public_key)?;
            CustomAccountData::Service(CustomServiceAccountData::Ed25519 { public_key })
        }
    };

    let data = AccountData {
        account_name,
        is_active,
        description,
        labels,
        custom,
    };
    let result = state.account_service.create_account(&call_ctx, &data).await;
    let account = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_CREATE, outcome)
                .with_metadata(serde_json::json!({"account_type": "service"}))
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_CREATE, AuditOutcome::Success)
                .with_resource("account", account.id.0, account.name.as_str())
                .with_metadata(serde_json::json!({"account_type": "service"})),
        )
        .await;

    let data = AccountDto::from(&account);

    let status = ApiStatus::new(ApiCode::AccountCreated, "Account created successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}

#[allow(clippy::too_many_arguments)]
async fn create_user_account(
    state: AppState,
    ctx: ApiErrorCtx,
    call_ctx: CallContext,
    account_name: AccountName,
    email: Option<String>,
    full_name: Option<String>,
    is_active: bool,
    must_change_password: bool,
    description: Option<String>,
    labels: Labels,
    password: Zeroizing<String>,
) -> ApiResult<Json<ApiResponse<AccountDto>>> {
    if account_name.is_system_name() {
        return Err(HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::AccountCreateFailed,
            reason: ApiErrorCode::ValidationFailed,
            message: "Cannot create accounts starting with a $ (reserved for system accounts)".into(),
            details: None,
        });
    }

    let custom = CustomAccountData::User(CustomUserAccountData {
        email,
        password: Password::new(&password),
        must_change_password,
        full_name: full_name.clone(),
    });

    let data = AccountData {
        account_name,
        is_active,
        description,
        labels,
        custom,
    };
    let result = state.account_service.create_account(&call_ctx, &data).await;
    let account = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_CREATE, outcome)
                .with_metadata(serde_json::json!({"account_type": "user"}))
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_CREATE, AuditOutcome::Success)
                .with_resource("account", account.id.0, account.name.as_str())
                .with_metadata(serde_json::json!({"account_type": "user"})),
        )
        .await;

    let data = AccountDto::from(&account);

    let status = ApiStatus::new(ApiCode::AccountCreated, "Account created successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}

fn parse_ed25519_public_key_b64(s: &str) -> Result<[u8; 32], HttpError> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let bytes = b64.decode(s.as_bytes()).map_err(|_| HttpError {
        http: StatusCode::BAD_REQUEST,
        fail_code: ApiCode::AccountCreateFailed,
        reason: ApiErrorCode::ValidationFailed,
        message: "Invalid ed25519 public key (base64 decode failed)".into(),
        details: None,
    })?;

    if bytes.len() != 32 {
        return Err(HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::AccountCreateFailed,
            reason: ApiErrorCode::ValidationFailed,
            message: "Invalid ed25519 public key (expected 32 bytes)".into(),
            details: None,
        });
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn validate_passphrase(p: &Zeroizing<String>) -> Result<(), HttpError> {
    if p.trim().len() < 16 {
        return Err(HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::AccountCreateFailed,
            reason: ApiErrorCode::ValidationFailed,
            message: "Passphrase must be at least 16 characters".into(),
            details: None,
        });
    }
    Ok(())
}
