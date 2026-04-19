// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditFilter, AuditQueryResult};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use hierarkey_core::license::Feature;

#[axum::debug_handler]
pub(crate) async fn events(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(filter): ApiJson<AuditFilter>,
) -> ApiResult<Json<ApiResponse<AuditQueryResult>>> {
    if !state
        .audit_service
        .license_service
        .get_effective_license()
        .has_feature(&Feature::Audit)
    {
        return Err(HttpError::forbidden(
            ApiErrorCtx {
                fail_code: ApiCode::AuditQueryFailed,
            },
            "Audit logging is only available in the Commercial edition.",
        ));
    }

    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AuditQueryFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let result = state.audit_service.query(&filter).await.ctx(ctx)?;

    let status = ApiStatus::new(ApiCode::AuditQuerySucceeded, "Audit events retrieved successfully");
    Ok(Json(ApiResponse::ok(status, result)))
}
