// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};

#[axum::debug_handler]
pub(crate) async fn delete(
    State(state): State<AppState>,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::MasterKeyDeleteFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let master_key = super::resolve_masterkey(&state, &call_ctx, ctx, &name).await?;

    let result = state.masterkey_service.delete(&call_ctx, &master_key).await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::MASTERKEY_DELETE, outcome)
                .with_resource_ref("masterkey", &master_key.name)
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::MASTERKEY_DELETE, AuditOutcome::Success)
                .with_resource_ref("masterkey", &master_key.name),
        )
        .await;

    Ok(Json(ApiResponse::ok_no_data(ApiStatus::new(
        ApiCode::MasterKeyDeleted,
        format!("Master key '{}' deleted successfully.", master_key.name),
    ))))
}
