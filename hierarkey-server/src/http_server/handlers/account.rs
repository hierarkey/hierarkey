// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::Account;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::manager::account::AccountId;
use hierarkey_core::resources::AccountName;

/// Resolve an account from a path parameter that is either a name, a full UUID/ULID ID
/// (`acc_<ulid>`), or a short ID (`acc_<8-12 hex chars>`).
pub(super) async fn resolve_account(
    state: &AppState,
    call_ctx: &CallContext,
    ctx: ApiErrorCtx,
    name_or_id: &str,
) -> Result<Option<Account>, HttpError> {
    if name_or_id.starts_with(AccountId::PREFIX) {
        match AccountId::try_from(name_or_id) {
            Ok(id) => state.account_service.find_by_id(call_ctx, id).await.ctx(ctx),
            Err(_) => {
                // Not a UUID/ULID — treat as a ShortId (e.g. acc_1a2b3c4d)
                state
                    .account_service
                    .find_by_short_id(call_ctx, name_or_id)
                    .await
                    .ctx(ctx)
            }
        }
    } else {
        let name = AccountName::try_from(name_or_id.to_string()).ctx(ctx)?;
        state.account_service.find_by_name(call_ctx, &name).await.ctx(ctx)
    }
}

mod change_password;
mod create;
mod delete;
mod demote;
mod describe;
mod disable;
mod enable;
mod federated_identity;
mod lock;
mod promote;
mod search;
mod set_cert;
mod unlock;
mod update;

pub(crate) use change_password::change_password;
pub(crate) use create::create;
pub(crate) use delete::delete;
pub(crate) use demote::demote;
pub(crate) use describe::describe;
pub(crate) use disable::disable;
pub(crate) use enable::enable;
pub(crate) use federated_identity::{
    describe as federated_identity_describe, link as federated_identity_link, unlink as federated_identity_unlink,
};
pub(crate) use lock::lock;
pub(crate) use promote::promote;
pub(crate) use search::search;
pub(crate) use set_cert::set_cert;
pub(crate) use unlock::unlock;
pub(crate) use update::update;
