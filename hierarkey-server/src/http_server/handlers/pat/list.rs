// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::global::{DEFAULT_LIMIT_VALUE, DEFAULT_OFFSET_VALUE, MAX_LIMIT_VALUE};
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiQuery;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::pat_response::PatResponse;
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Default)]
pub struct ListQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Serialize)]
pub struct ListBody {
    tokens: Vec<PatResponse>,
    total: usize,
    limit: usize,
    offset: usize,
}

#[axum::debug_handler]
pub(crate) async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiQuery(query): ApiQuery<ListQuery>,
) -> ApiResult<Json<ApiResponse<ListBody>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AuthTokenListFailed,
    };

    let limit = query.limit.unwrap_or(DEFAULT_LIMIT_VALUE).min(MAX_LIMIT_VALUE);
    let offset = query.offset.unwrap_or(DEFAULT_OFFSET_VALUE);

    let (tokens, total) = state
        .auth_service
        .list_pat(&call_ctx, auth.user.id, limit, offset)
        .await
        .ctx(ctx)?;

    let tokens: Vec<PatResponse> = tokens.into_iter().map(|p| PatResponse::from(&p)).collect();
    let data = ListBody {
        tokens,
        total,
        limit,
        offset,
    };

    let status = ApiStatus::new(
        ApiCode::AuthTokenListSucceeded,
        "Personal access token list retrieved successfully".to_string(),
    );

    Ok(Json(ApiResponse::ok(status, data)))
}
