// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::api::v1::dto::rbac::bindings::{AccountBindingsDto, AllBindingsDto};
use crate::api::v1::dto::rbac::role::RoleWithRulesDto;
use crate::api::v1::dto::rbac::rule::RuleDto;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use hierarkey_core::resources::AccountName;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct BindingsRequest {
    pub account: Option<AccountName>,
}

#[axum::debug_handler]
pub async fn bindings(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(req): ApiJson<BindingsRequest>,
) -> ApiResult<Json<ApiResponse<AccountBindingsDto>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::RbacBindingsListFailed,
    };

    let (account_id, account_short_id) = match req.account {
        None => {
            let id = *call_ctx.actor.require_account_id().ctx(ctx)?;
            let account = state.account_service.get_by_id(&call_ctx, id).await.ctx(ctx)?;
            (id, account.short_id.to_string())
        }
        Some(ref name) => {
            let account = state
                .account_service
                .find_by_name(&call_ctx, name)
                .await
                .ctx(ctx)?
                .ok_or_else(|| HttpError::not_found(ctx, "Account not found"))?;
            (account.id, account.short_id.to_string())
        }
    };

    let bindings = state
        .rbac_service
        .get_bindings_for_account(&call_ctx, account_id)
        .await
        .ctx(ctx)?;

    let data = AccountBindingsDto {
        account: account_short_id,
        roles: bindings.roles.iter().map(RoleWithRulesDto::from).collect(),
        rules: bindings.direct_rules.iter().map(RuleDto::from).collect(),
    };

    let status = ApiStatus::new(ApiCode::RbacBindingsList, "Bindings retrieved successfully");
    Ok(Json(ApiResponse::ok(status, data)))
}

#[axum::debug_handler]
pub async fn bindings_all(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
) -> ApiResult<Json<ApiResponse<AllBindingsDto>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::RbacBindingsListAllFailed,
    };

    let all_bindings = state
        .rbac_service
        .get_bindings_for_all_accounts(&call_ctx)
        .await
        .ctx(ctx)?;

    let entries = all_bindings
        .into_iter()
        .map(|(short_id, bindings)| AccountBindingsDto {
            account: short_id,
            roles: bindings.roles.iter().map(RoleWithRulesDto::from).collect(),
            rules: bindings.direct_rules.iter().map(RuleDto::from).collect(),
        })
        .collect();

    let data = AllBindingsDto { entries };
    let status = ApiStatus::new(ApiCode::RbacBindingsListAll, "All bindings retrieved successfully");
    Ok(Json(ApiResponse::ok(status, data)))
}
