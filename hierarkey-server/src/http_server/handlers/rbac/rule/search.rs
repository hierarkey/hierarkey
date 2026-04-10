// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::api::v1::dto::rbac::rule::RuleListItemDto;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SearchRuleRequest {}

#[derive(Serialize, Deserialize)]
pub struct SearchRuleResponse {
    pub entries: Vec<RuleListItemDto>,
}

#[axum::debug_handler]
pub async fn search(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(_req): ApiJson<SearchRuleRequest>,
) -> ApiResult<Json<ApiResponse<SearchRuleResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::RbacRuleListFailed,
    };

    let rules = state.rbac_service.rule_search(&call_ctx).await.ctx(ctx)?;

    let data = SearchRuleResponse {
        entries: rules.iter().map(RuleListItemDto::from).collect(),
    };

    let status = ApiStatus::new(ApiCode::RbacRuleList, "Rbac rule searched successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
