// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::rbac::parser::parse_rule_spec;
use crate::rbac::{Permission, PolicyEffect, Target, WhereExpr};
use hierarkey_core::CkError;
use hierarkey_core::error::validation::ValidationError;

#[derive(Debug, Clone)]
pub struct RuleSpec {
    pub effect: PolicyEffect,         // allow | deny
    pub permission: Permission,       // secret:read, secret:*, ...
    pub target: Target,               // namespace /prod/**, secret /prod:db/*, ...
    pub condition: Option<WhereExpr>, // optional conditions
}

impl std::fmt::Display for RuleSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} to {}", self.effect, self.permission, self.target)?;
        if let Some(cond) = &self.condition {
            write!(f, " where {cond}")?;
        }
        Ok(())
    }
}

impl TryFrom<&str> for RuleSpec {
    type Error = CkError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        parse_rule_spec(value).map_err(|e| ValidationError::Custom(format!("failed to parse rule spec: {e}")).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::{MatchKind, NamespacePattern, WhereClause};

    fn simple_spec() -> RuleSpec {
        RuleSpec {
            effect: PolicyEffect::Allow,
            permission: Permission::SecretReveal,
            target: Target::Namespace(NamespacePattern {
                base: "/prod".to_string(),
                kind: MatchKind::Exact,
            }),
            condition: None,
        }
    }

    #[test]
    fn display_without_condition() {
        assert_eq!(simple_spec().to_string(), "allow secret:reveal to namespace /prod");
    }

    #[test]
    fn display_deny_effect() {
        let mut spec = simple_spec();
        spec.effect = PolicyEffect::Deny;
        assert_eq!(spec.to_string(), "deny secret:reveal to namespace /prod");
    }

    #[test]
    fn display_with_condition() {
        let mut spec = simple_spec();
        spec.condition = Some(WhereExpr {
            clauses: vec![WhereClause {
                key: "env".to_string(),
                value: "prod".to_string(),
            }],
        });
        assert_eq!(spec.to_string(), "allow secret:reveal to namespace /prod where env=prod");
    }

    #[test]
    fn display_target_all() {
        let spec = RuleSpec {
            effect: PolicyEffect::Allow,
            permission: Permission::PlatformAdmin,
            target: Target::All,
            condition: None,
        };
        assert_eq!(spec.to_string(), "allow platform:admin to all");
    }

    #[test]
    fn try_from_valid_spec() {
        let spec = RuleSpec::try_from("allow secret:reveal to namespace /prod/**").unwrap();
        assert_eq!(spec.effect, PolicyEffect::Allow);
        assert_eq!(spec.permission, Permission::SecretReveal);
    }

    #[test]
    fn try_from_invalid_spec_returns_error() {
        assert!(RuleSpec::try_from("not a valid rule").is_err());
        assert!(RuleSpec::try_from("").is_err());
    }

    #[test]
    fn try_from_deny_effect() {
        let spec = RuleSpec::try_from("deny secret:* to namespace /prod").unwrap();
        assert_eq!(spec.effect, PolicyEffect::Deny);
        assert_eq!(spec.permission, Permission::SecretAll);
    }
}
