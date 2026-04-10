// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::api::v1::dto::rbac::role::RoleWithRulesDto;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};

#[axum::debug_handler]
pub async fn describe(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<RoleWithRulesDto>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::RbacRoleDescribeFailed,
    };

    let role_with_rules = state.rbac_service.role_get_by_name(&call_ctx, &name).await.ctx(ctx)?;

    let created_by = super::super::resolve_actor_ref(&state, &call_ctx, role_with_rules.role.created_by).await;
    let updated_by = match role_with_rules.role.updated_by {
        Some(id) => super::super::resolve_actor_ref(&state, &call_ctx, id).await,
        None => None,
    };
    let mut data = RoleWithRulesDto::from(&role_with_rules);
    data.role = data.role.with_actors(created_by, updated_by);
    let status = ApiStatus::new(ApiCode::RbacRoleDescribe, "Rbac role described successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
