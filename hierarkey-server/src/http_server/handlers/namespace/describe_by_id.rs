// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::global::resource::ResourceStatus;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::namespace::describe::SearchResponse;
use crate::http_server::handlers::namespace_response::NamespaceResponse;
use crate::manager::account::AccountId;
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};

#[axum::debug_handler]
pub(crate) async fn describe_by_id(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(id_str): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<SearchResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::NamespaceFetched,
    };

    // resolve_namespace handles both ns_<short_id> prefix lookups and full UUID/path lookups.
    let namespace = super::resolve_namespace(&state, &call_ctx, ctx, &id_str).await?;

    let keks = state
        .namespace_service
        .fetch_kek_assignments(&call_ctx, namespace.id)
        .await
        .ctx(ctx)?;
    let created_by_name = super::resolve_actor_name(&state, &call_ctx, namespace.created_by.map(AccountId)).await;
    let updated_by_name = super::resolve_actor_name(&state, &call_ctx, namespace.updated_by.map(AccountId)).await;
    let entry = NamespaceResponse::new(&namespace, keks).with_actors(created_by_name, updated_by_name);

    let ns_id = namespace.id;
    let total_secrets = state
        .secret_service
        .count_secrets_in_namespace(&call_ctx, ns_id)
        .await
        .ctx(ctx)?;
    let active_secrets = state
        .secret_service
        .count_secrets_by_status(&call_ctx, ns_id, ResourceStatus::Active)
        .await
        .ctx(ctx)?;
    let disabled_secrets = state
        .secret_service
        .count_secrets_by_status(&call_ctx, ns_id, ResourceStatus::Disabled)
        .await
        .ctx(ctx)?;

    use crate::http_server::handlers::namespace::describe::SecretInfo;
    let info = SecretInfo {
        total_secrets,
        latest_enabled: active_secrets,
        disabled: disabled_secrets,
    };

    let data = SearchResponse {
        entry,
        secret_info: info,
    };

    let status = ApiStatus::new(ApiCode::NamespaceFetched, "Namespace fetched successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
