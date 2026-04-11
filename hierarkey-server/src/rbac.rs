// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::global::uuid_id::Identifier;
use crate::uuid_id;
use hierarkey_core::Labels;

mod match_kind;
mod parser;
mod pattern;
mod permission;
mod policy_effect;
pub mod spec;
mod target;
mod target_kind;
mod where_;

use crate::manager::account::AccountId;
pub use match_kind::MatchKind;
pub use pattern::{AccountPattern, NamespacePattern, Pattern, SecretPattern};
pub use permission::Permission;
pub use policy_effect::PolicyEffect;
pub use target::Target;
pub use target_kind::TargetKind;
pub use where_::WhereClause;
pub use where_::WhereExpr;
pub use where_::WhereOperator;

uuid_id!(RuleId, "rul_");
uuid_id!(RoleId, "rol_");

/// A query to check if a given subject has permissions on resource
#[derive(Debug, Clone)]
pub struct RbacAllowedRequest {
    pub subject: AccountId,      // e.g. who?
    pub permission: Permission,  // e.g. "secret:reveal"
    pub resource: RbacResource,  // e.g. "namespace:prod" or "secret-ref:uuid"
    pub resource_labels: Labels, // labels of the target resource, used to evaluate `where` conditions
}

/// Represents a resource in the RBAC system that permissions can be applied to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbacResource {
    /// Platform-level resource: RBAC administration, roles, rules, bindings.
    Platform,
    /// Access to a namespace itself (create/list/delete/policy/etc)
    Namespace { path: String }, // "/prod" or "/test/app1"
    /// Access to a secret within a namespace (read/revise/delete/etc)
    Secret { namespace: String, path: String }, // namespace="/prod", path="db/password"
    /// Access to an account (describe/disable/label/etc)
    Account { name: String }, // "john.doe"
}

impl std::fmt::Display for RbacResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RbacResource::Namespace { path } => write!(f, "namespace:{path}"),
            RbacResource::Secret { namespace, path } => write!(f, "secret:{namespace}:{path}"),
            RbacResource::Account { name } => write!(f, "account:{name}"),
            RbacResource::Platform => write!(f, "platform"),
        }
    }
}

/// The RBAC permission result. Either the permission is allowed or not. Will return the matches
/// rule of there is a match.
#[derive(Debug, Clone)]
pub struct RbacAllowedResponse {
    pub allowed: bool,
    pub matched_rule: Option<RuleId>,
}

// Reason why a rule was a "near miss" (i.e. it matched the subject and permission, but not
// the resource). This can be used for debugging and explaining why a permission check failed.
#[derive(Debug, Clone)]
pub enum NearMissReason {
    PermissionMismatch,
    TargetMismatch,
    /// The rule matched on permission and target, but its `where` condition failed against
    /// the resource's labels. The failing condition expression is included.
    ConditionMismatch(WhereExpr),
    LostToHigherSpecificity,
}

#[derive(Debug, Clone)]
pub struct RbacNearMiss {
    pub rule: crate::manager::rbac::rule::Rule,
    pub reason: NearMissReason,
}

#[derive(Debug, Clone)]
pub struct RbacExplainResponse {
    pub allowed: bool,
    pub matched_rule: Option<crate::manager::rbac::rule::Rule>,
    pub near_misses: Vec<RbacNearMiss>,
}
