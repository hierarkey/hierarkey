// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::secret_response::{SecretResponse, SecretSearchResponse};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::search::query::SecretSearchRequest;
use hierarkey_core::api::status::{ApiCode, ApiStatus};

#[axum::debug_handler]
pub(crate) async fn search(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(search_req): ApiJson<SecretSearchRequest>,
) -> ApiResult<Json<ApiResponse<SecretSearchResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::SecretFetchFailed,
    };

    // RBAC filtering is done per-item in the service layer; results are
    // silently restricted to secrets in namespaces the caller is permitted to list.

    // Search for secrets
    let search_response = state
        .secret_service
        .search_secrets(&call_ctx, &search_req)
        .await
        .ctx(ctx)?;

    let entries = search_response
        .secrets
        .into_iter()
        .map(|entry| SecretResponse::new(entry, vec![]))
        .collect();

    let data = SecretSearchResponse {
        entries,
        total: search_response.total,
        limit: search_response.limit,
        offset: search_response.offset,
    };

    let status = ApiStatus::new(ApiCode::SecretFetched, "secrets successfully searched");

    Ok(Json(ApiResponse::ok(status, data)))
}
