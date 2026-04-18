// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::api::v1::dto::rbac::role::RoleListItemDto;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::rbac::{Permission, RbacResource};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SearchRoleRequest {}

#[derive(Serialize, Deserialize)]
pub struct SearchRoleResponse {
    pub entries: Vec<RoleListItemDto>,
}

#[axum::debug_handler]
pub async fn search(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(_req): ApiJson<SearchRoleRequest>,
) -> ApiResult<Json<ApiResponse<SearchRoleResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::RbacRoleListFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let roles = state.rbac_service.role_search(&call_ctx).await.ctx(ctx)?;

    let data = SearchRoleResponse {
        entries: roles.iter().map(RoleListItemDto::from).collect(),
    };

    let status = ApiStatus::new(ApiCode::RbacRoleList, "Rbac role searched successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
