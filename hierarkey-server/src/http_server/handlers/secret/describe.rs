// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::secret_response::SecretResponse;
use crate::manager::account::AccountId;
use crate::rbac::{Permission, RbacResource};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};

#[axum::debug_handler]
pub(crate) async fn describe(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(sec_ref): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::SecretFetchFailed,
    };

    let secret = super::resolve_secret(&state, &call_ctx, ctx, &sec_ref).await?;

    state
        .rbac_service
        .require_permission(
            &call_ctx,
            Permission::SecretDescribe,
            RbacResource::Secret {
                namespace: secret.ref_ns.clone(),
                path: secret.ref_key.clone(),
            },
        )
        .await
        .ctx(ctx)?;

    let revisions = state
        .secret_service
        .get_secret_revisions(&call_ctx, secret.id)
        .await
        .ctx(ctx)?;

    let created_by_name = super::resolve_actor_name(&state, &call_ctx, secret.created_by.map(AccountId)).await;
    let updated_by_name = super::resolve_actor_name(&state, &call_ctx, secret.updated_by.map(AccountId)).await;

    let data = SecretResponse::new(secret, revisions).with_actors(created_by_name, updated_by_name);

    let status = ApiStatus::new(ApiCode::NamespaceFetched, "Namespace fetched successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
