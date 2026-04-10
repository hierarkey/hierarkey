// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

mod create;
mod delete;
pub(crate) mod describe;
mod describe_by_id;
mod disable;
mod enable;
mod rewrap_deks;
mod rotate_kek;
mod search;
mod update;

pub(crate) use create::create;
pub(crate) use delete::delete;
pub(crate) use describe::describe;
pub(crate) use describe_by_id::describe_by_id;
pub(crate) use disable::disable;
pub(crate) use enable::enable;
pub(crate) use rewrap_deks::rewrap_deks;
pub(crate) use rotate_kek::rotate_kek;
pub(crate) use search::search;
pub(crate) use update::update;

use crate::ResolveOne;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::manager::namespace::Namespace;
use hierarkey_core::resources::NamespaceString;
use std::str::FromStr;

pub(super) use super::common::resolve_actor_name;

pub(crate) async fn resolve_namespace(
    state: &AppState,
    call_ctx: &CallContext,
    ctx: ApiErrorCtx,
    param: &str,
) -> Result<Namespace, HttpError> {
    if param.starts_with("ns_") {
        let result = state
            .namespace_service
            .resolve_short_namespace_id(param)
            .await
            .ctx(ctx)?;
        match result {
            ResolveOne::Many(n) => return Err(super::common::ambiguous_id_error(ctx, "namespaces", n, param)),
            ResolveOne::One(id) => {
                return state
                    .namespace_service
                    .fetch(call_ctx, id)
                    .await
                    .ctx(ctx)?
                    .ok_or_else(|| HttpError::not_found(ctx, format!("Namespace '{param}' not found")));
            }
            // No short-ID match — fall through to path-based lookup below
            ResolveOne::None => {}
        }
    }

    // If the param was URL-encoded as a full path (e.g. %2F%24hierarkey → /$hierarkey),
    // it already has a leading slash; avoid creating a double-slash.
    let path_str = if param.starts_with('/') {
        param.to_string()
    } else {
        format!("/{param}")
    };
    let ns_path = NamespaceString::from_str(&path_str).ctx(ctx)?;
    state
        .namespace_service
        .fetch_by_namespace(call_ctx, &ns_path)
        .await
        .ctx(ctx)?
        .ok_or_else(|| HttpError::not_found(ctx, format!("Namespace '/{param}' not found")))
}
