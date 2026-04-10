// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

mod activate;
mod annotate;
mod create;
mod delete;
mod describe;
mod disable;
mod enable;
mod restore;
mod reveal;
mod revise;
pub mod search;
mod update;
mod validation;

pub(crate) use activate::activate;
pub(crate) use annotate::annotate;
pub(crate) use create::create;
pub(crate) use delete::delete;
pub(crate) use describe::describe;
pub(crate) use disable::disable;
pub(crate) use enable::enable;
pub(crate) use restore::restore;
pub(crate) use reveal::reveal;
pub(crate) use revise::revise;
pub(crate) use search::search;
pub(crate) use update::update;

use crate::ResolveOne;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::manager::secret::Secret;
use hierarkey_core::resources::SecretRef;

pub(super) use super::common::resolve_actor_name;

pub(crate) async fn resolve_secret(
    state: &AppState,
    call_ctx: &CallContext,
    ctx: ApiErrorCtx,
    param: &str,
) -> Result<Secret, HttpError> {
    if param.starts_with("sec_") {
        let result = state.secret_service.resolve_short_secret_id(param).await.ctx(ctx)?;
        let id = match result {
            ResolveOne::None => return Err(HttpError::not_found(ctx, format!("Secret '{param}' not found"))),
            ResolveOne::One(id) => id,
            ResolveOne::Many(n) => return Err(super::common::ambiguous_id_error(ctx, "secrets", n, param)),
        };
        state
            .secret_service
            .find_secret(call_ctx, id)
            .await
            .ctx(ctx)?
            .ok_or_else(|| HttpError::not_found(ctx, format!("Secret '{param}' not found")))
    } else {
        let sec_ref = SecretRef::from_string(&format!("/{param}")).ctx(ctx)?;
        state
            .secret_service
            .find_by_ref(call_ctx, &sec_ref)
            .await
            .ctx(ctx)?
            .ok_or_else(|| HttpError::not_found(ctx, format!("Secret '{param}' not found")))
    }
}
