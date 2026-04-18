// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::masterkey_response::{MasterKeyResponse, MasterKeyStatusResponse};
use crate::manager::masterkey::MasterKeyStatus;
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
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<MasterKeyStatusResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::MasterKeyStatusFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let master_key = super::resolve_masterkey(&state, &call_ctx, ctx, &name).await?;

    let kek_count = match master_key.status {
        MasterKeyStatus::Active | MasterKeyStatus::Draining => {
            let counts = state.kek_service.count_keks_by_masterkey().await.ctx(ctx)?;
            Some(*counts.get(&master_key.id).unwrap_or(&0))
        }
        _ => None,
    };

    let created_by_name = super::resolve_actor_name(&state, &call_ctx, master_key.created_by).await;
    let updated_by_name = super::resolve_actor_name(&state, &call_ctx, master_key.updated_by).await;
    let retired_by_name = super::resolve_actor_name(&state, &call_ctx, master_key.retired_by).await;
    let data = MasterKeyStatusResponse {
        master_key: MasterKeyResponse::from(&master_key).with_actors(created_by_name, updated_by_name, retired_by_name),
        keyring: state.masterkey_service.keyring().status(&master_key).ctx(ctx)?,
        kek_count,
    };

    let status = ApiStatus::new(
        ApiCode::MasterKeyStatusSuccess,
        "Masterkey status fetched successfully".to_string(),
    );

    Ok(Json(ApiResponse::ok(status, data)))
}
