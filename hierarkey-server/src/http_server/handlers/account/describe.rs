// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::manager::account::{AccountDto, AccountId, AccountRef};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};

/// Resolve an AccountId to an AccountRef (short_id + name). Returns None if not found.
async fn resolve_ref(state: &AppState, call_ctx: &CallContext, id: AccountId) -> Option<AccountRef> {
    state
        .account_service
        .get_by_id(call_ctx, id)
        .await
        .ok()
        .map(|acc| AccountRef {
            id: acc.short_id.clone(),
            name: acc.name.clone(),
        })
}

#[axum::debug_handler]
pub(crate) async fn describe(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(account_name): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<AccountDto>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountRetrievalFailed,
    };

    let Some(account) = super::resolve_account(&state, &call_ctx, ctx, &account_name).await? else {
        return Err(HttpError {
            http: StatusCode::NOT_FOUND,
            fail_code: ApiCode::AccountRetrievalFailed,
            reason: ApiErrorCode::NotFound,
            message: format!("Account '{account_name}' not found"),
            details: None,
        });
    };

    // Users may describe their own account; admins may describe any account.
    if !call_ctx.actor.is_system() {
        let actor_id = call_ctx
            .actor
            .require_account_id()
            .map_err(|e| HttpError::forbidden(ctx, e.to_string()))?;
        if *actor_id != account.id
            && !state
                .account_service
                .is_admin(&call_ctx, *actor_id)
                .await
                .map_err(|e| HttpError::forbidden(ctx, e.to_string()))?
        {
            return Err(HttpError::forbidden(
                ctx,
                "Admin privilege required to describe another account",
            ));
        }
    }

    let mut data = AccountDto::from(&account);
    data.created_by = match account.created_by {
        Some(id) => resolve_ref(&state, &call_ctx, id).await,
        None => None,
    };
    data.status_changed_by = match account.status_changed_by {
        Some(id) => resolve_ref(&state, &call_ctx, id).await,
        None => None,
    };
    data.updated_by = match account.updated_by {
        Some(id) => resolve_ref(&state, &call_ctx, id).await,
        None => None,
    };
    data.deleted_by = match account.deleted_by {
        Some(id) => resolve_ref(&state, &call_ctx, id).await,
        None => None,
    };

    let status = ApiStatus::new(ApiCode::AccountRetrieve, "Account fetch successfully");
    Ok(Json(ApiResponse::ok(status, data)))
}
