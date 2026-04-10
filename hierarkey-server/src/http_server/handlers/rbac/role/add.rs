// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ResolveOne;
use crate::api::v1::dto::rbac::role::RoleWithRulesDto;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::{ApiJson, ApiPath};
use crate::http_server::handlers::ApiResult;
use crate::rbac::spec::RuleSpec;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::Metadata;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AddRuleToRoleRequest {
    pub spec: Option<String>,
    pub rule_id: Option<String>,
}

#[axum::debug_handler]
pub async fn add(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(name): ApiPath<String>,
    ApiJson(req): ApiJson<AddRuleToRoleRequest>,
) -> ApiResult<Json<ApiResponse<RoleWithRulesDto>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::RbacRoleUpdateFailed,
    };

    if req.spec.is_none() && req.rule_id.is_none() {
        return Err(HttpError::bad_request(
            ctx,
            "Either spec or rule_id must be provided".to_string(),
        ));
    }

    let role = state.rbac_service.role_get_by_name(&call_ctx, &name).await.ctx(ctx)?;

    let rule_id = match (&req.spec, &req.rule_id) {
        (Some(spec), None) => {
            let metadata = Metadata::new(); // We don't store anything like labels or description yet.

            // Create the rule implicitly from the provided spec
            let spec = RuleSpec::try_from(spec.as_str())
                .map_err(|e| HttpError::bad_request(ctx, format!("Invalid rule spec: {e}")))?;
            let rule = state
                .rbac_service
                .rule_create(&call_ctx, spec, metadata)
                .await
                .ctx(ctx)?;
            rule.id
        }
        (None, Some(prefix)) => {
            // Find the id based on the short_id (prefix)
            let result = state
                .rbac_service
                .resolve_short_rule_id(&call_ctx, prefix)
                .await
                .ctx(ctx)?;

            match result {
                ResolveOne::None => {
                    return Err(HttpError::bad_request(
                        ctx,
                        "No rule not found matching the provided id (prefix)".to_string(),
                    ));
                }
                ResolveOne::One(rule_id) => rule_id,
                ResolveOne::Many(total) => {
                    return match total {
                        Some(total) => Err(HttpError::bad_request(
                            ctx,
                            format!("Ambiguous rule_id: {total} rules match the provided short id"),
                        )),
                        None => Err(HttpError::bad_request(
                            ctx,
                            "Ambiguous rule_id: multiple rules match the provided short id".to_string(),
                        )),
                    };
                }
            }
        }
        _ => unreachable!(), // This case is already handled above
    };

    let result = state.rbac_service.role_add_rule(&call_ctx, role.role.id, rule_id).await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::RBAC_ROLE_UPDATE, outcome)
                .with_resource_ref("rbac_role", &role.role.name)
                .with_metadata(serde_json::json!({"action": "add_rule"}))
        })
        .await
        .ctx(ctx)?;

    // Reload role (with new rule)
    let role = state.rbac_service.role_get(&call_ctx, role.role.id).await.ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::RBAC_ROLE_UPDATE, AuditOutcome::Success)
                .with_resource_ref("rbac_role", &role.role.name)
                .with_metadata(serde_json::json!({"action": "add_rule"})),
        )
        .await;

    let data = RoleWithRulesDto::from(&role);
    let status = ApiStatus::new(ApiCode::RbacRoleCreated, "Rbac rule added to role successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
