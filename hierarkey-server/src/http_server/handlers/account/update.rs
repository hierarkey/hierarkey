// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::{ApiJson, ApiPath};
use crate::http_server::handlers::ApiResult;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::Metadata;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::{Deserialize, Serialize};

mod double_option {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(Some)
    }
}

#[derive(Serialize, Deserialize)]
pub struct UpdateRequest {
    #[serde(default, deserialize_with = "double_option::deserialize")]
    email: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    full_name: Option<Option<String>>,
    metadata: Option<Metadata>,
}

#[axum::debug_handler]
pub(crate) async fn update(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(account_name): ApiPath<String>,
    ApiJson(req): ApiJson<UpdateRequest>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountUpdateFailed,
    };

    let result = super::resolve_account(&state, &call_ctx, ctx, &account_name).await?;
    let account = match result {
        Some(account) => account,
        None => {
            return Err(HttpError::not_found(ctx, format!("Account '{account_name}' not found")));
        }
    };

    let result = state
        .account_service
        .update_profile(&call_ctx, account.id, req.email, req.full_name, req.metadata)
        .await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_UPDATE, outcome).with_resource(
                "account",
                account.id.0,
                account.name.as_str(),
            )
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_UPDATE, AuditOutcome::Success).with_resource(
                "account",
                account.id.0,
                account.name.as_str(),
            ),
        )
        .await;

    let status = ApiStatus::new(ApiCode::AccountUpdated, "Account updated successfully");
    Ok(Json(ApiResponse::ok_no_data(status)))
}
