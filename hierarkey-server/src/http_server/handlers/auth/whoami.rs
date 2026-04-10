// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::http_server::AppState;
use crate::http_server::auth_user::AuthUser;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::auth_response::WhoamiResponse;
use crate::http_server::handlers::pat_response::PatResponse;
use crate::manager::account::AccountDto;
use axum::Json;
use axum::extract::State;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};

#[axum::debug_handler]
pub(crate) async fn whoami(
    State(_state): State<AppState>,
    auth: AuthUser,
) -> ApiResult<Json<ApiResponse<WhoamiResponse>>> {
    let data = WhoamiResponse {
        account: AccountDto::from(&auth.user),
        token: PatResponse::from(&auth.pat),
    };

    let status = ApiStatus::new(ApiCode::AuthWhoamiSucceeded, "Whoami retrieved successfully".to_string());

    Ok(Json(ApiResponse::ok(status, data)))
}
