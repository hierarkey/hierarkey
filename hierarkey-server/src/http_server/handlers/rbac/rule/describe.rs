// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ResolveOne;
use crate::api::v1::dto::rbac::rule::RuleDto;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
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
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<RuleDto>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::RbacRuleDescribeFailed,
    };

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

    let rule = state.rbac_service.rule_get(&call_ctx, rule_id).await.ctx(ctx)?;

    let created_by = super::super::resolve_actor_ref(&state, &call_ctx, rule.created_by).await;
    let updated_by = match rule.updated_by {
        Some(id) => super::super::resolve_actor_ref(&state, &call_ctx, id).await,
        None => None,
    };
    let data = RuleDto::from(&rule).with_actors(created_by, updated_by);
    let status = ApiStatus::new(ApiCode::RbacRuleDescribe, "Rbac rule described successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
