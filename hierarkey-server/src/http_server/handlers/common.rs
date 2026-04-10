// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError};
use crate::manager::account::AccountId;

/// Resolve an account ID to a display name. Returns `None` if `id` is `None` or the account
/// is not found.
///
/// Call sites that store actor IDs as `Option<uuid::Uuid>` should pass `.map(AccountId)`.
pub(super) async fn resolve_actor_name(
    state: &AppState,
    call_ctx: &CallContext,
    id: Option<AccountId>,
) -> Option<String> {
    let id = id?;
    state
        .account_service
        .find_by_id(call_ctx, id)
        .await
        .ok()
        .flatten()
        .map(|a| a.name.to_string())
}

/// Build the "ambiguous short ID" error returned when a prefix resolves to more than one resource.
///
/// `kind` should be the plural resource name (e.g. `"secrets"`, `"namespaces"`).
pub(super) fn ambiguous_id_error(ctx: ApiErrorCtx, kind: &str, n: Option<usize>, param: &str) -> HttpError {
    let msg = match n {
        Some(n) => format!("Ambiguous id: {n} {kind} match '{param}'"),
        None => format!("Ambiguous id: multiple {kind} match '{param}'"),
    };
    HttpError::bad_request(ctx, msg)
}
