// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::api::v1::dto::rbac::rule::RuleDto;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::rbac::spec::RuleSpec;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::Metadata;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CreateRuleRequest {
    pub spec: String,
}

#[axum::debug_handler]
pub async fn create(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(req): ApiJson<CreateRuleRequest>,
) -> ApiResult<Json<ApiResponse<RuleDto>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::RbacRuleCreateFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let spec = RuleSpec::try_from(req.spec.as_str()).map_err(|e| HttpError::bad_request(ctx, e.to_string()))?;

    let metadata = Metadata::new();

    let result = state.rbac_service.rule_create(&call_ctx, spec, metadata).await;
    let rule = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::RBAC_RULE_CREATE, outcome)
                .with_metadata(serde_json::json!({"spec": req.spec}))
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::RBAC_RULE_CREATE, AuditOutcome::Success)
                .with_resource_ref("rbac_rule", rule.spec.to_string()),
        )
        .await;

    let created_by = super::super::resolve_actor_ref(&state, &call_ctx, rule.created_by).await;
    let data = RuleDto::from(&rule).with_actors(created_by, None);
    let status = ApiStatus::new(ApiCode::RbacRuleCreated, "Rbac rule created successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
