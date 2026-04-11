// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::api::v1::dto::rbac::rule::RuleDto;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::rbac::{NearMissReason, RbacAllowedRequest, RbacResource};
use hierarkey_core::Labels;
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use hierarkey_core::resources::AccountName;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
pub struct ExplainRequest {
    pub account: AccountName,
    pub permission: String,
    pub namespace: Option<String>,
    pub secret: Option<String>,
    pub verbose: bool,
}

#[derive(Serialize, Deserialize)]
pub struct NearMissDto {
    pub rule: RuleDto,
    pub reason: String,
    /// The failing `where` condition expression, present only when `reason` is `condition_mismatch`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ExplainResponseDto {
    pub allowed: bool,
    pub verdict: String,
    pub matched_rule: Option<RuleDto>,
    pub near_misses: Vec<NearMissDto>,
}

#[axum::debug_handler]
pub async fn explain(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(req): ApiJson<ExplainRequest>,
) -> ApiResult<Json<ApiResponse<ExplainResponseDto>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::RbacExplainFailed,
    };

    let permission =
        crate::rbac::Permission::from_str(&req.permission).map_err(|e| HttpError::bad_request(ctx, e.to_string()))?;

    let resource = match (&req.namespace, &req.secret) {
        (Some(ns), None) => RbacResource::Namespace { path: ns.clone() },
        (None, Some(sec)) => {
            let (namespace, path) = sec
                .split_once(':')
                .ok_or_else(|| HttpError::bad_request(ctx, "secret must be in the form 'namespace:path'"))?;
            RbacResource::Secret {
                namespace: namespace.to_string(),
                path: path.to_string(),
            }
        }
        _ => {
            return Err(HttpError::bad_request(
                ctx,
                "exactly one of 'namespace' or 'secret' must be set",
            ));
        }
    };

    let account = state
        .account_service
        .find_by_name(&call_ctx, &req.account)
        .await
        .ctx(ctx)?
        .ok_or_else(|| HttpError::not_found(ctx, "Account not found"))?;

    let explain_result = state
        .rbac_service
        .explain(
            &call_ctx,
            RbacAllowedRequest {
                subject: account.id,
                permission,
                resource,
                resource_labels: Labels::new(),
            },
            req.verbose,
        )
        .await
        .ctx(ctx)?;

    let matched_rule = explain_result.matched_rule.as_ref().map(RuleDto::from);

    let near_misses = explain_result
        .near_misses
        .iter()
        .map(|nm| {
            let (reason, condition) = match &nm.reason {
                NearMissReason::PermissionMismatch => ("permission_mismatch".to_string(), None),
                NearMissReason::TargetMismatch => ("target_mismatch".to_string(), None),
                NearMissReason::ConditionMismatch(cond) => {
                    ("condition_mismatch".to_string(), Some(cond.to_string()))
                }
                NearMissReason::LostToHigherSpecificity => ("lost_to_higher_specificity".to_string(), None),
            };
            NearMissDto { rule: RuleDto::from(&nm.rule), reason, condition }
        })
        .collect();

    let verdict = if explain_result.allowed { "allowed" } else { "denied" }.to_string();

    let data = ExplainResponseDto {
        allowed: explain_result.allowed,
        verdict,
        matched_rule,
        near_misses,
    };

    let status = ApiStatus::new(ApiCode::RbacExplain, "Rbac explain completed successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
