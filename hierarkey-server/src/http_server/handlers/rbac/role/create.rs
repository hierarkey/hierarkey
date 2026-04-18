// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::api::v1::dto::rbac::role::RoleDto;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::Metadata;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
}

#[axum::debug_handler]
pub async fn create(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(req): ApiJson<CreateRoleRequest>,
) -> ApiResult<Json<ApiResponse<RoleDto>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::RbacRoleCreateFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let mut metadata = Metadata::new();
    if let Some(desc) = &req.description {
        metadata.add_description(desc);
    }

    let result = state
        .rbac_service
        .role_create(&call_ctx, req.name.to_string(), metadata)
        .await;
    let role = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::RBAC_ROLE_CREATE, outcome)
                .with_metadata(serde_json::json!({"name": req.name}))
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::RBAC_ROLE_CREATE, AuditOutcome::Success)
                .with_resource_ref("rbac_role", &role.name),
        )
        .await;

    let created_by = super::super::resolve_actor_ref(&state, &call_ctx, role.created_by).await;
    let data = RoleDto::from(&role).with_actors(created_by, None);
    let status = ApiStatus::new(ApiCode::RbacRoleCreated, "Rbac role created successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
