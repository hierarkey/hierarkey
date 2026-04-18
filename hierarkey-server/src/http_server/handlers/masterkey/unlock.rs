// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::{ApiJson, ApiPath};
use crate::http_server::handlers::ApiResult;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use crate::service::masterkey::MasterKeyUnlockError;
use crate::service::masterkey::provider::UnlockArgs;
use crate::service::masterkey::{MasterKeyProviderType, MasterKeyUnlockOutcome};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
pub struct UnlockRequest {
    passphrase: Option<Zeroizing<String>>,
    pin: Option<Zeroizing<String>>,
}

#[axum::debug_handler]
pub(crate) async fn unlock(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(name): ApiPath<String>,
    ApiJson(payload): ApiJson<UnlockRequest>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::MasterKeyUnlockFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let master_key = super::resolve_masterkey(&state, &call_ctx, ctx, &name).await?;

    let provider_type = state.masterkey_service.keyring().provider_for(&master_key).ctx(ctx)?;
    let args = match provider_type {
        MasterKeyProviderType::Passphrase => {
            let passphrase = payload.passphrase.ok_or_else(|| HttpError {
                http: axum::http::StatusCode::BAD_REQUEST,
                fail_code: ApiCode::MasterKeyUnlockFailed,
                reason: hierarkey_core::api::status::ApiErrorCode::InvalidRequest,
                message: "passphrase is required to unlock a passphrase-backed master key".to_string(),
                details: None,
            })?;
            UnlockArgs::Passphrase(passphrase)
        }
        MasterKeyProviderType::Insecure => UnlockArgs::None,
        MasterKeyProviderType::Pkcs11 => {
            let pin = payload.pin.ok_or_else(|| HttpError {
                http: axum::http::StatusCode::BAD_REQUEST,
                fail_code: ApiCode::MasterKeyUnlockFailed,
                reason: hierarkey_core::api::status::ApiErrorCode::InvalidRequest,
                message: "pin is required to unlock a PKCS#11 master key".to_string(),
                details: None,
            })?;
            UnlockArgs::Pkcs11 { pin }
        }
    };

    let result = match state.masterkey_service.unlock(&call_ctx, &master_key, &args) {
        Ok(outcome) => outcome,
        Err(e) => {
            let audit_outcome = match &e {
                MasterKeyUnlockError::CkError(hierarkey_core::CkError::Rbac(_))
                | MasterKeyUnlockError::CkError(hierarkey_core::CkError::PermissionDenied) => AuditOutcome::Denied,
                _ => AuditOutcome::Failure,
            };
            state
                .audit_service
                .log(
                    AuditEvent::from_ctx(&call_ctx, event_type::MASTERKEY_UNLOCK, audit_outcome)
                        .with_resource_ref("masterkey", &master_key.name),
                )
                .await;
            return Err(HttpError::from_unlock_error(e, ctx));
        }
    };

    let status = match result {
        MasterKeyUnlockOutcome::AlreadyUnlocked => {
            ApiStatus::new(ApiCode::MasterKeyAlreadyUnlocked, "Masterkey was already unlocked".to_string())
        }
        MasterKeyUnlockOutcome::Unlocked => {
            state
                .audit_service
                .log(
                    AuditEvent::from_ctx(&call_ctx, event_type::MASTERKEY_UNLOCK, AuditOutcome::Success)
                        .with_resource_ref("masterkey", &master_key.name),
                )
                .await;
            ApiStatus::new(ApiCode::MasterKeyUnlocked, "Masterkey unlocked successfully".to_string())
        }
    };

    Ok(Json(ApiResponse::ok_no_data(status)))
}
