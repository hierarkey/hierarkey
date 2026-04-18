// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ResolveOne;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use hierarkey_core::resources::AccountName;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct UnbindRequest {
    pub account_name: Option<AccountName>,
    pub account_label: Option<(String, String)>,
    pub role: Option<String>,
    pub rule_id: Option<String>,
}

#[axum::debug_handler]
pub async fn unbind(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(req): ApiJson<UnbindRequest>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::RbacBindingDeleteFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let account_id = match &req.account_name {
        Some(account_name) => {
            let account = state
                .account_service
                .find_by_name(&call_ctx, account_name)
                .await
                .ctx(ctx)?;
            match account {
                Some(account) => Some(account.id),
                None => return Err(HttpError::not_found(ctx, "Account with the specified name does not exist")),
            }
        }
        None => None,
    };

    let role_id = match &req.role {
        Some(role_name) => {
            let role = state
                .rbac_service
                .role_get_by_name(&call_ctx, role_name)
                .await
                .ctx(ctx)?;
            Some(role.role.id)
        }
        None => None,
    };

    let rule_id = match &req.rule_id {
        Some(rule_id_str) => {
            let result = state
                .rbac_service
                .resolve_short_rule_id(&call_ctx, rule_id_str)
                .await
                .ctx(ctx)?;
            let rule_id = match result {
                ResolveOne::None => {
                    return Err(HttpError::not_found(ctx, "No rule found matching the provided id"));
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
            };
            Some(rule_id)
        }
        None => None,
    };

    let result = state
        .rbac_service
        .unbind(&call_ctx, account_id, req.account_label.clone(), role_id, rule_id)
        .await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::RBAC_UNBIND, outcome).with_metadata(serde_json::json!({
                "account": req.account_name.as_ref().map(|n| n.as_str()),
                "role": req.role,
            }))
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::RBAC_UNBIND, AuditOutcome::Success).with_metadata(
                serde_json::json!({
                    "account": req.account_name.as_ref().map(|n| n.as_str()),
                    "role": req.role,
                }),
            ),
        )
        .await;

    let status = ApiStatus::new(ApiCode::RbacBindingDeleted, "Rbac binding removed successfully");

    Ok(Json(ApiResponse::ok_no_data(status)))
}
