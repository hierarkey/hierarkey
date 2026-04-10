// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

pub mod bind;
pub mod bindings;
pub mod explain;
pub mod role;
pub mod rule;
pub mod unbind;

use crate::api::v1::dto::global::AccountRefDto;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::manager::account::AccountId;
use hierarkey_core::resources::AccountName;

/// Resolve an AccountId to an AccountRefDto (short_id + name). Returns None if not found.
pub(super) async fn resolve_actor_ref(
    state: &AppState,
    call_ctx: &CallContext,
    id: AccountId,
) -> Option<AccountRefDto> {
    state
        .account_service
        .find_by_id(call_ctx, id)
        .await
        .ok()
        .flatten()
        .map(|a| AccountRefDto {
            account_id: a.short_id.to_string(),
            account_name: AccountName::try_from(a.name.as_str()).unwrap_or_else(|_| AccountName::unknown()),
        })
}
