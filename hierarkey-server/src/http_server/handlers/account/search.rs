// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::manager::account::AccountDto;
use crate::service::account::AccountSearchQuery;
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::Serialize;

#[derive(Serialize)]
pub struct AccountSearchResponse {
    entries: Vec<AccountDto>,
    total: usize,
}

#[axum::debug_handler]
pub(crate) async fn search(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(payload): ApiJson<AccountSearchQuery>,
) -> ApiResult<Json<ApiResponse<AccountSearchResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountListFailed,
    };

    let (accounts, total) = state
        .account_service
        .search_accounts(&call_ctx, &payload)
        .await
        .ctx(ctx)?;

    // let entries = accounts.into_iter().map(|u| AccountResponse::from(&u)).collect();
    let data = AccountSearchResponse {
        entries: accounts,
        total,
    };

    let status = ApiStatus::new(ApiCode::AccountListSucceeded, "Account list retrieved successfully".to_string());

    Ok(Json(ApiResponse::ok(status, data)))
}
