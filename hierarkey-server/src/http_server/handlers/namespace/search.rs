// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::global::{DEFAULT_LIMIT_VALUE, DEFAULT_OFFSET_VALUE, MAX_LIMIT_VALUE};
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::namespace_response::{NamespaceResponse, NamespaceSearchResponse};
use crate::service::namespace::NamespaceSearchQuery;
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};

#[axum::debug_handler]
pub(crate) async fn search(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(query): ApiJson<NamespaceSearchQuery>,
) -> ApiResult<Json<ApiResponse<NamespaceSearchResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::NamespaceFetchFailed,
    };

    // RBAC filtering is done per-item in the service layer; results are
    // silently restricted to namespaces the caller is permitted to list.
    let (entries, total) = state.namespace_service.search(&call_ctx, &query).await.ctx(ctx)?;

    let entries = entries
        .into_iter()
        .map(|entry| NamespaceResponse::new_from_search(&entry))
        .collect();

    let data = NamespaceSearchResponse {
        entries,
        total,
        limit: query.limit.unwrap_or(DEFAULT_LIMIT_VALUE).min(MAX_LIMIT_VALUE),
        offset: query.offset.unwrap_or(DEFAULT_OFFSET_VALUE),
    };

    let status = ApiStatus::new(ApiCode::NamespaceFetched, "Namespaces successfully searched");

    Ok(Json(ApiResponse::ok(status, data)))
}
