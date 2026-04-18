// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::{ApiJson, ApiPath};
use crate::http_server::handlers::ApiResult;
use crate::manager::masterkey::MasterKeyStatus;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use crate::service::kek::{MasterKeyRetrievable, RewrapKekFilter};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::resources::NamespaceString;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Default)]
pub struct RewrapKeksRequest {
    /// Rewrap only KEKs for this namespace path (e.g. "/prod").
    /// Mutually exclusive with `kek_id`.
    pub namespace: Option<String>,
    /// Rewrap only this specific KEK by short ID (e.g. "kek_abc123").
    /// Mutually exclusive with `namespace`.
    pub kek_id: Option<String>,
}

#[derive(Serialize)]
pub struct RewrapKeksResponse {
    pub rewrapped: usize,
    pub remaining: usize,
    pub retired: bool,
}

/// POST /v1/masterkeys/{name}/rewrap-keks
///
/// Rewrap KEKs wrapped under the named (draining) master key to the currently
/// active master key. Without a body, rewraps all KEKs. With `namespace` or
/// `kek_id` in the body, rewraps only the matching subset.
/// Auto-retires the source key when no KEKs remain under it.
#[axum::debug_handler]
pub(crate) async fn rewrap_keks(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(name): ApiPath<String>,
    ApiJson(req): ApiJson<RewrapKeksRequest>,
) -> ApiResult<Json<ApiResponse<RewrapKeksResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::MasterKeyRewrapKeksFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    if req.namespace.is_some() && req.kek_id.is_some() {
        return Err(HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::MasterKeyRewrapKeksFailed,
            reason: ApiErrorCode::InvalidRequest,
            message: "Specify at most one of `namespace` or `kek_id`, not both".to_string(),
            details: None,
        });
    }

    let old_mk = super::resolve_masterkey(&state, &call_ctx, ctx, &name).await?;

    if old_mk.status != MasterKeyStatus::Draining {
        return Err(HttpError {
            http: StatusCode::CONFLICT,
            fail_code: ApiCode::MasterKeyRewrapKeksFailed,
            reason: ApiErrorCode::Conflict,
            message: format!(
                "Master key '{}' is not draining (status: {}); only draining keys can have their KEKs rewrapped",
                old_mk.name, old_mk.status
            ),
            details: None,
        });
    }

    let new_mk = state
        .masterkey_service
        .find_active(old_mk.usage)
        .await
        .ctx(ctx)?
        .ok_or_else(|| HttpError::not_found(ctx, "No active master key found".to_string()))?;

    if new_mk.id == old_mk.id {
        return Err(HttpError {
            http: StatusCode::CONFLICT,
            fail_code: ApiCode::MasterKeyRewrapKeksFailed,
            reason: ApiErrorCode::Conflict,
            message: "Source and target master key are the same".to_string(),
            details: None,
        });
    }

    // Resolve the filter
    let filter = if let Some(ns_path) = &req.namespace {
        let ns_str = NamespaceString::try_from(ns_path.as_str()).map_err(|_| HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::MasterKeyRewrapKeksFailed,
            reason: ApiErrorCode::InvalidRequest,
            message: format!("Invalid namespace path: '{ns_path}'"),
            details: None,
        })?;
        let ns = state
            .namespace_service
            .fetch_by_namespace(&call_ctx, &ns_str)
            .await
            .ctx(ctx)?
            .ok_or_else(|| HttpError::not_found(ctx, format!("Namespace '{ns_path}' not found")))?;
        RewrapKekFilter::Namespace(ns.id)
    } else if let Some(kek_short_id) = &req.kek_id {
        let enc_kek = state
            .kek_service
            .find_kek_by_short_id(kek_short_id)
            .await
            .ctx(ctx)?
            .ok_or_else(|| HttpError::not_found(ctx, format!("KEK '{kek_short_id}' not found")))?;
        RewrapKekFilter::Kek(enc_kek.id)
    } else {
        RewrapKekFilter::All
    };

    let (rewrapped, remaining) = state
        .kek_service
        .rewrap_keks_to_new_masterkey(&old_mk, &new_mk, &filter)
        .await
        .ctx(ctx)?;
    metrics::counter!("hierarkey_kek_rewraps_total").increment(rewrapped as u64);

    // Auto-retire the source key when no KEKs remain under it.
    let retired = remaining == 0;
    if retired {
        state.masterkey_service.retire(&call_ctx, &old_mk).await.ctx(ctx)?;
    }

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::MASTERKEY_ROTATE, AuditOutcome::Success)
                .with_resource_ref("masterkey", &old_mk.name)
                .with_metadata(serde_json::json!({
                    "rewrapped": rewrapped,
                    "remaining": remaining,
                    "retired": retired,
                    "target_masterkey": new_mk.name,
                })),
        )
        .await;

    let msg = if retired {
        format!(
            "Rewrapped {rewrapped} KEK(s) from '{}' to '{}'; '{}' is now retired",
            old_mk.name, new_mk.name, old_mk.name
        )
    } else {
        format!(
            "Rewrapped {rewrapped} KEK(s) from '{}' to '{}'; {remaining} KEK(s) still remain",
            old_mk.name, new_mk.name
        )
    };

    Ok(Json(ApiResponse::ok(
        ApiStatus::new(ApiCode::MasterKeyRewrapKeks, msg),
        RewrapKeksResponse {
            rewrapped,
            remaining,
            retired,
        },
    )))
}
