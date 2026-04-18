// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ResolveOne;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};

#[axum::debug_handler]
pub async fn delete(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::RbacRuleDeleteFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let result = state
        .rbac_service
        .resolve_short_rule_id(&call_ctx, &id)
        .await
        .ctx(ctx)?;

    let rule_id = match result {
        ResolveOne::None => return Err(HttpError::not_found(ctx, "Rule not found")),
        ResolveOne::One(rule_id) => rule_id,
        ResolveOne::Many(total) => {
            return match total {
                Some(total) => Err(HttpError::bad_request(ctx, format!("Ambiguous id: {total} rules match"))),
                None => Err(HttpError::bad_request(ctx, "Ambiguous id: multiple rules match".to_string())),
            };
        }
    };

    let result = state.rbac_service.rule_delete(&call_ctx, rule_id).await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::RBAC_RULE_DELETE, outcome)
                .with_resource_ref("rbac_rule", id.clone())
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::RBAC_RULE_DELETE, AuditOutcome::Success)
                .with_resource_ref("rbac_rule", id),
        )
        .await;

    let status = ApiStatus::new(ApiCode::RbacRuleDeleted, "Rbac rule deleted successfully");
    Ok(Json(ApiResponse::ok(status, ())))
}
