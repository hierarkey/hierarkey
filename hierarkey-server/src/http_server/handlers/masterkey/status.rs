// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::masterkey_response::{MasterKeyResponse, MasterKeyStatusResponse};
use crate::manager::masterkey::MasterKeyStatus;
use crate::rbac::{Permission, RbacResource};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::Serialize;

#[derive(Serialize)]
pub struct ListBody {
    entries: Vec<MasterKeyStatusResponse>,
    total: usize,
}

#[axum::debug_handler]
pub(crate) async fn status(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
) -> ApiResult<Json<ApiResponse<ListBody>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::MasterKeyStatusFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let mut entries: Vec<MasterKeyStatusResponse> = Vec::new();

    let kek_counts = state.kek_service.count_keks_by_masterkey().await.ctx(ctx)?;
    let master_keys = state.masterkey_service.find_all(&call_ctx).await.ctx(ctx)?;
    for master_key in master_keys {
        let keyring = state.masterkey_service.keyring().status(&master_key).ctx(ctx)?;
        let kek_count = match master_key.status {
            MasterKeyStatus::Active | MasterKeyStatus::Draining => Some(*kek_counts.get(&master_key.id).unwrap_or(&0)),
            _ => None,
        };
        entries.push(MasterKeyStatusResponse {
            master_key: MasterKeyResponse::from(&master_key),
            keyring,
            kek_count,
        });
    }

    let total = entries.len();
    let data = ListBody { entries, total };

    let status = ApiStatus::new(
        ApiCode::MasterKeyStatusSuccess,
        "Masterkey list retrieved successfully".to_string(),
    );

    Ok(Json(ApiResponse::ok(status, data)))
}
