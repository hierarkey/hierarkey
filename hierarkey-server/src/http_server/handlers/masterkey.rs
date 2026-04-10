// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

mod activate;
mod create;
mod delete;
mod describe;
mod lock;
mod rewrap_keks;
mod status;
mod unlock;

pub(crate) use activate::activate;
pub(crate) use create::create;
pub(crate) use delete::delete;
pub(crate) use describe::describe;
pub(crate) use lock::lock;
pub(crate) use rewrap_keks::rewrap_keks;
pub(crate) use status::status;
pub(crate) use unlock::unlock;

use crate::ResolveOne;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::manager::masterkey::MasterKey;

pub(super) use super::common::resolve_actor_name;

pub(crate) async fn resolve_masterkey(
    state: &AppState,
    call_ctx: &CallContext,
    ctx: ApiErrorCtx,
    param: &str,
) -> Result<MasterKey, HttpError> {
    if param.starts_with("mk_") {
        let result = state
            .masterkey_service
            .resolve_short_masterkey_id(param)
            .await
            .ctx(ctx)?;
        let id = match result {
            ResolveOne::None => return Err(HttpError::not_found(ctx, format!("Masterkey '{param}' not found"))),
            ResolveOne::One(id) => id,
            ResolveOne::Many(n) => return Err(super::common::ambiguous_id_error(ctx, "masterkeys", n, param)),
        };
        state
            .masterkey_service
            .find_masterkey_by_id(call_ctx, id)
            .await
            .ctx(ctx)?
            .ok_or_else(|| HttpError::not_found(ctx, format!("Masterkey '{param}' not found")))
    } else {
        state
            .masterkey_service
            .find_by_name(call_ctx, param)
            .await
            .ctx(ctx)?
            .ok_or_else(|| HttpError::not_found(ctx, format!("Masterkey '{param}' not found")))
    }
}
