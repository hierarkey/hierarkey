// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::manager::account::AccountId;
use crate::uuid_id;
use hierarkey_core::CkResult;
use hierarkey_core::error::auth::AuthError;
use std::net::IpAddr;

/// Contextual information about the caller and how an action was initiated, used for auditing and
/// authorization purposes. This is passed through the call stack to provide consistent context for
/// logging, permission checks, and audit trails.
#[derive(Clone, Debug)]
pub struct CallContext {
    /// Which account ($system / user) performed the action. Might be "$system" for automated actions.
    pub actor: Actor,
    /// Human-readable name of the actor, if known (e.g. the account name).
    pub actor_name: Option<String>,
    /// Unique request ID
    pub request_id: RequestId,
    /// Trace ID for correlating related actions
    pub trace_id: TraceId,
    /// How the action was initiated
    pub entrypoint: Entrypoint,
    /// Client IP address of the incoming HTTP request (None for background jobs / CLI).
    pub client_ip: Option<IpAddr>,
}

impl CallContext {
    pub fn job() -> Self {
        let request_id = RequestId::new();
        let trace_id = TraceId::new();
        Self {
            actor: Actor::System,
            actor_name: None,
            request_id,
            trace_id,
            entrypoint: Entrypoint::Job,
            client_ip: None,
        }
    }

    /// For CLI / background job / startup code acting as the system
    pub fn system() -> Self {
        Self {
            actor: Actor::System,
            actor_name: None,
            request_id: RequestId::new(),
            trace_id: TraceId::new(),
            entrypoint: Entrypoint::Job,
            client_ip: None,
        }
    }

    /// For tests or direct service calls on behalf of a known account
    pub fn for_account(account_id: AccountId) -> Self {
        Self {
            actor: Actor::Account(account_id),
            actor_name: None,
            request_id: RequestId::new(),
            trace_id: TraceId::new(),
            entrypoint: Entrypoint::Api,
            client_ip: None,
        }
    }
}

// Actor represents who performed the action, which can be either a specific user account or the
// system itself. This is important for auditing and authorization checks, as it allows us to
// determine the source of an action and apply appropriate permissions or logging.
// Note that though we have a separate System enum, it still maps to a special built-in account
// "$system" in the database, which is used for permissions checks and audit trails. The Actor enum
// just provides a convenient way to represent this in the code without having to deal with the
// special account ID everywhere.
#[derive(Clone, Debug)]
pub enum Actor {
    /// Action performed by a specific user account
    Account(AccountId),
    /// Action performed by the system ($system built-in account)
    System,
}

impl Actor {
    pub fn is_system(&self) -> bool {
        matches!(self, Actor::System)
    }

    pub fn is_account(&self) -> bool {
        matches!(self, Actor::Account(_))
    }

    pub fn account_id(&self) -> Option<&AccountId> {
        match self {
            Actor::Account(id) => Some(id),
            Actor::System => None,
        }
    }

    pub fn require_account_id(&self) -> CkResult<&AccountId> {
        match self {
            Actor::Account(id) => Ok(id),
            Actor::System => Err(AuthError::Forbidden {
                reason: "Expected account actor",
            }
            .into()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Entrypoint {
    /// Action initiated via the HTTP API
    Api,
    /// Action initiated via a background job
    Job,
}

use crate::global::uuid_id::Identifier;
uuid_id!(RequestId, "req_");
uuid_id!(TraceId, "trc_");
