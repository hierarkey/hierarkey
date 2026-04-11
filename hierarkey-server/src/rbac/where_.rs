// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::Labels;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhereExpr {
    pub clauses: Vec<WhereClause>,
}

impl WhereExpr {
    /// Returns `true` if all clauses match the provided label set (AND semantics).
    /// An empty clause list always evaluates to `true`.
    /// A clause with a key not present in `labels` evaluates to `false`.
    pub fn evaluate(&self, labels: &Labels) -> bool {
        self.clauses.iter().all(|c| labels.get(&c.key).map(|v| v == &c.value).unwrap_or(false))
    }
}

impl std::fmt::Display for WhereExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let clauses_str = self.clauses.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",");
        write!(f, "{clauses_str}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhereClause {
    pub key: String,
    pub value: String,
}

impl std::fmt::Display for WhereClause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.key, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clause_display() {
        let c = WhereClause {
            key: "mfa".to_string(),
            value: "true".to_string(),
        };
        assert_eq!(c.to_string(), "mfa=true");
    }

    #[test]
    fn expr_display_single_clause() {
        let e = WhereExpr {
            clauses: vec![WhereClause {
                key: "env".to_string(),
                value: "prod".to_string(),
            }],
        };
        assert_eq!(e.to_string(), "env=prod");
    }

    #[test]
    fn expr_display_multiple_clauses() {
        let e = WhereExpr {
            clauses: vec![
                WhereClause {
                    key: "role".to_string(),
                    value: "admin".to_string(),
                },
                WhereClause {
                    key: "env".to_string(),
                    value: "prod".to_string(),
                },
            ],
        };
        assert_eq!(e.to_string(), "role=admin,env=prod");
    }

    #[test]
    fn expr_display_empty_clauses() {
        let e = WhereExpr { clauses: vec![] };
        assert_eq!(e.to_string(), "");
    }

    fn labels(pairs: &[(&str, &str)]) -> Labels {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn clause(key: &str, value: &str) -> WhereClause {
        WhereClause { key: key.to_string(), value: value.to_string() }
    }

    #[test]
    fn evaluate_empty_expr_always_true() {
        let e = WhereExpr { clauses: vec![] };
        assert!(e.evaluate(&labels(&[])));
        assert!(e.evaluate(&labels(&[("env", "prod")])));
    }

    #[test]
    fn evaluate_single_matching_clause() {
        let e = WhereExpr { clauses: vec![clause("env", "prod")] };
        assert!(e.evaluate(&labels(&[("env", "prod")])));
    }

    #[test]
    fn evaluate_single_non_matching_value() {
        let e = WhereExpr { clauses: vec![clause("env", "prod")] };
        assert!(!e.evaluate(&labels(&[("env", "staging")])));
    }

    #[test]
    fn evaluate_missing_key_returns_false() {
        let e = WhereExpr { clauses: vec![clause("env", "prod")] };
        assert!(!e.evaluate(&labels(&[("region", "us-east")])));
    }

    #[test]
    fn evaluate_all_clauses_must_match() {
        let e = WhereExpr { clauses: vec![clause("env", "prod"), clause("tier", "premium")] };
        assert!(e.evaluate(&labels(&[("env", "prod"), ("tier", "premium")])));
        assert!(!e.evaluate(&labels(&[("env", "prod"), ("tier", "free")])));
        assert!(!e.evaluate(&labels(&[("env", "prod")])));
    }
}
