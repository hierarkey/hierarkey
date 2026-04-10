// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::masterkey_response::{MasterKeyResponse, MasterKeyStatusResponse};
use crate::manager::masterkey::{MasterKeyFileType, MasterKeyStatus, MasterKeyUsage};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use crate::service::masterkey::provider::UnlockArgs;
use crate::service::masterkey::{BackendCreate, CreateMasterKeyRequest, MasterKeyProviderType};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::ApiCode::MasterKeyCreateFailed;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::{Labels, Metadata};
use zeroize::Zeroizing;

#[derive(serde::Deserialize)]
pub struct ApiRequest {
    pub name: String,
    pub description: Option<String>,
    pub labels: Labels,
    pub usage: MasterKeyUsage,
    pub provider: MasterKeyProviderType,
    // For "passphrase" provider
    pub passphrase: Option<Zeroizing<String>>,
    // For "pkcs11" provider
    pub pkcs11_key_label: Option<String>,
    pub pkcs11_slot: Option<u64>,
    pub pkcs11_token_label: Option<String>,
    pub pkcs11_pin: Option<Zeroizing<String>>,
}

#[axum::debug_handler]
pub(crate) async fn create(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(payload): ApiJson<ApiRequest>,
) -> ApiResult<Json<ApiResponse<MasterKeyStatusResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::MasterKeyCreateFailed,
    };

    let mut metadata = Metadata::default();
    if let Some(ref description) = payload.description {
        metadata.add_description(description);
    }
    metadata.add_labels(payload.labels.clone());

    let mut creation_passphrase: Option<Zeroizing<String>> = None;
    let backend_create_args = match payload.provider {
        MasterKeyProviderType::Insecure => {
            if !state.config.masterkey.allow_insecure_masterkey {
                return Err(HttpError {
                    http: StatusCode::FORBIDDEN,
                    fail_code: MasterKeyCreateFailed,
                    reason: ApiErrorCode::Forbidden,
                    message: "Insecure master key provider is not allowed; \
                              set masterkey.allow_insecure_masterkey = true in the server config (dev/test only)"
                        .to_string(),
                    details: None,
                });
            }
            BackendCreate::Insecure {
                file_type: MasterKeyFileType::Insecure,
            }
        }
        MasterKeyProviderType::Passphrase => {
            let Some(passphrase) = payload.passphrase else {
                return Err(HttpError {
                    http: StatusCode::BAD_REQUEST,
                    fail_code: MasterKeyCreateFailed,
                    reason: ApiErrorCode::InvalidRequest,
                    message: "Passphrase is required for passphrase master key provider".to_string(),
                    details: None,
                });
            };
            creation_passphrase = Some(passphrase.clone());
            BackendCreate::Passphrase {
                file_type: MasterKeyFileType::Passphrase,
                passphrase,
            }
        }
        MasterKeyProviderType::Pkcs11 => {
            let Some(key_label) = payload.pkcs11_key_label else {
                return Err(HttpError {
                    http: StatusCode::BAD_REQUEST,
                    fail_code: MasterKeyCreateFailed,
                    reason: ApiErrorCode::InvalidRequest,
                    message: "pkcs11_key_label is required for pkcs11 master key provider".to_string(),
                    details: None,
                });
            };
            BackendCreate::Pkcs11 {
                slot: payload.pkcs11_slot,
                token_label: payload.pkcs11_token_label,
                key_label,
                pin: payload.pkcs11_pin,
            }
        }
    };

    let req = CreateMasterKeyRequest {
        name: payload.name,
        usage: payload.usage,
        metadata,
        backend: backend_create_args,
        status: MasterKeyStatus::Pending,
    };
    let result = state.masterkey_service.create_master_key(&call_ctx, &req).await;
    let masterkey = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::MASTERKEY_CREATE, outcome)
                .with_metadata(serde_json::json!({"provider": format!("{:?}", payload.provider)}))
        })
        .await
        .ctx(ctx)?;

    state
        .masterkey_service
        .load_into_keyring(&call_ctx, &masterkey)
        .await
        .ctx(ctx)?;

    // For passphrase keys, unlock immediately using the passphrase that was
    // just provided — the key would otherwise be loaded as locked.
    if let Some(passphrase) = creation_passphrase {
        let unlock_args = UnlockArgs::Passphrase(passphrase);
        state
            .masterkey_service
            .unlock(&call_ctx, &masterkey, &unlock_args)
            .map_err(|e| HttpError::from_unlock_error(e, ctx))?;
    }

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::MASTERKEY_CREATE, AuditOutcome::Success)
                .with_resource_ref("masterkey", &masterkey.name)
                .with_metadata(serde_json::json!({"provider": format!("{:?}", payload.provider)})),
        )
        .await;

    let created_by_name = super::resolve_actor_name(&state, &call_ctx, masterkey.created_by).await;
    let data = MasterKeyStatusResponse {
        master_key: MasterKeyResponse::from(&masterkey).with_actors(created_by_name, None, None),
        keyring: state.masterkey_service.keyring().status(&masterkey).ctx(ctx)?,
        kek_count: None, // newly created key has no KEKs yet
    };

    let status = ApiStatus::new(
        ApiCode::MasterKeyStatusSuccess,
        "Masterkey status fetched successfully".to_string(),
    );

    Ok(Json(ApiResponse::ok(status, data)))
}
