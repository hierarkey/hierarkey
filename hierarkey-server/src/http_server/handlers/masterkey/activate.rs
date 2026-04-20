// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use crate::service::masterkey::MasterKeyActivateOutcome;
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};

#[axum::debug_handler]
pub(crate) async fn activate(
    State(state): State<AppState>,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::MasterKeyActivateFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let master_key = match super::resolve_masterkey(&state, &call_ctx, ctx, &name).await {
        Ok(k) => k,
        Err(e) => {
            state
                .audit_service
                .log(
                    AuditEvent::from_ctx(&call_ctx, event_type::MASTERKEY_ACTIVATE, AuditOutcome::Failure)
                        .with_resource_ref("masterkey", &name),
                )
                .await;
            return Err(e);
        }
    };

    let activate_result = state.masterkey_service.activate(&call_ctx, &master_key).await;
    if activate_result.is_err() {
        state
            .audit_service
            .log(
                AuditEvent::from_ctx(&call_ctx, event_type::MASTERKEY_ACTIVATE, AuditOutcome::Failure)
                    .with_resource_ref("masterkey", &master_key.name),
            )
            .await;
    }
    let result = activate_result.map_err(|e| HttpError::from_activate_error(e, ctx))?;

    let status = match result {
        MasterKeyActivateOutcome::AlreadyActivated => ApiStatus::new(
            ApiCode::MasterKeyAlreadyActivated,
            "Masterkey was already activated".to_string(),
        ),
        MasterKeyActivateOutcome::Activated => {
            state
                .audit_service
                .log(
                    AuditEvent::from_ctx(&call_ctx, event_type::MASTERKEY_ACTIVATE, AuditOutcome::Success)
                        .with_resource_ref("masterkey", &master_key.name),
                )
                .await;
            ApiStatus::new(ApiCode::MasterKeyActivated, "Masterkey activated successfully".to_string())
        }
    };

    Ok(Json(ApiResponse::ok_no_data(status)))
}
