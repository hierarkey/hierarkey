// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::Labels;
use serde::{Deserialize, Serialize};

/// Operator used in a [`WhereClause`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum WhereOperator {
    /// Exact equality: `key=value`. The default for backward-compatible deserialization.
    #[default]
    #[serde(rename = "eq")]
    Eq,
    /// Inequality: `key!=value`.
    #[serde(rename = "ne")]
    Ne,
    /// Membership: `key in [v1,v2,...]`.
    #[serde(rename = "in")]
    In,
    /// Presence: `key exists` — true if the label key is present, regardless of value.
    #[serde(rename = "exists")]
    Exists,
}

/// A single condition clause inside a [`WhereExpr`].
///
/// Serialized with `operator` defaulting to `"eq"` for backward compatibility:
/// old JSON `{"key":"env","value":"prod"}` deserializes as `Eq { value: "prod" }`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WhereClause {
    pub key: String,
    /// The comparison operator. Defaults to [`WhereOperator::Eq`].
    #[serde(default)]
    pub operator: WhereOperator,
    /// The comparison value. Used by `Eq` and `Ne`. Empty for `In` and `Exists`.
    #[serde(default)]
    pub value: String,
    /// The value list. Used by `In`. Empty for all other operators.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

impl WhereClause {
    /// Evaluate this clause against the provided label map.
    pub fn evaluate(&self, labels: &Labels) -> bool {
        match self.operator {
            WhereOperator::Eq => labels.get(&self.key).is_some_and(|v| v == &self.value),
            WhereOperator::Ne => labels.get(&self.key).is_some_and(|v| v != &self.value),
            WhereOperator::In => labels.get(&self.key).is_some_and(|v| self.values.contains(v)),
            WhereOperator::Exists => labels.contains_key(&self.key),
        }
    }
}

impl std::fmt::Display for WhereClause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.operator {
            WhereOperator::Eq => write!(f, "{}={}", self.key, self.value),
            WhereOperator::Ne => write!(f, "{}!={}", self.key, self.value),
            WhereOperator::In => write!(f, "{} in [{}]", self.key, self.values.join(",")),
            WhereOperator::Exists => write!(f, "{} exists", self.key),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhereExpr {
    pub clauses: Vec<WhereClause>,
}

impl WhereExpr {
    /// Returns `true` if all clauses match the provided label set (AND semantics).
    /// An empty clause list always evaluates to `true`.
    pub fn evaluate(&self, labels: &Labels) -> bool {
        self.clauses.iter().all(|c| c.evaluate(labels))
    }
}

impl std::fmt::Display for WhereExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let clauses_str = self.clauses.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(" and ");
        write!(f, "{clauses_str}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> Labels {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn eq(key: &str, value: &str) -> WhereClause {
        WhereClause { key: key.to_string(), value: value.to_string(), ..Default::default() }
    }

    fn ne(key: &str, value: &str) -> WhereClause {
        WhereClause {
            key: key.to_string(),
            operator: WhereOperator::Ne,
            value: value.to_string(),
            values: vec![],
        }
    }

    fn in_list(key: &str, values: &[&str]) -> WhereClause {
        WhereClause {
            key: key.to_string(),
            operator: WhereOperator::In,
            value: String::new(),
            values: values.iter().map(|v| v.to_string()).collect(),
        }
    }

    fn exists(key: &str) -> WhereClause {
        WhereClause { key: key.to_string(), operator: WhereOperator::Exists, ..Default::default() }
    }

    // ---- Display ----

    #[test]
    fn clause_display_eq() {
        assert_eq!(eq("mfa", "true").to_string(), "mfa=true");
    }

    #[test]
    fn clause_display_ne() {
        assert_eq!(ne("env", "dev").to_string(), "env!=dev");
    }

    #[test]
    fn clause_display_in() {
        assert_eq!(in_list("env", &["prod", "staging"]).to_string(), "env in [prod,staging]");
    }

    #[test]
    fn clause_display_exists() {
        assert_eq!(exists("mfa").to_string(), "mfa exists");
    }

    #[test]
    fn expr_display_single_clause() {
        let e = WhereExpr { clauses: vec![eq("env", "prod")] };
        assert_eq!(e.to_string(), "env=prod");
    }

    #[test]
    fn expr_display_multiple_clauses() {
        let e = WhereExpr { clauses: vec![eq("role", "admin"), eq("env", "prod")] };
        assert_eq!(e.to_string(), "role=admin and env=prod");
    }

    #[test]
    fn expr_display_empty_clauses() {
        let e = WhereExpr { clauses: vec![] };
        assert_eq!(e.to_string(), "");
    }

    // ---- evaluate: Eq ----

    #[test]
    fn evaluate_empty_expr_always_true() {
        let e = WhereExpr { clauses: vec![] };
        assert!(e.evaluate(&labels(&[])));
        assert!(e.evaluate(&labels(&[("env", "prod")])));
    }

    #[test]
    fn evaluate_eq_matches() {
        let e = WhereExpr { clauses: vec![eq("env", "prod")] };
        assert!(e.evaluate(&labels(&[("env", "prod")])));
    }

    #[test]
    fn evaluate_eq_wrong_value() {
        let e = WhereExpr { clauses: vec![eq("env", "prod")] };
        assert!(!e.evaluate(&labels(&[("env", "staging")])));
    }

    #[test]
    fn evaluate_eq_missing_key() {
        let e = WhereExpr { clauses: vec![eq("env", "prod")] };
        assert!(!e.evaluate(&labels(&[("region", "us-east")])));
    }

    #[test]
    fn evaluate_and_all_must_match() {
        let e = WhereExpr { clauses: vec![eq("env", "prod"), eq("tier", "premium")] };
        assert!(e.evaluate(&labels(&[("env", "prod"), ("tier", "premium")])));
        assert!(!e.evaluate(&labels(&[("env", "prod"), ("tier", "free")])));
        assert!(!e.evaluate(&labels(&[("env", "prod")])));
    }

    // ---- evaluate: Ne ----

    #[test]
    fn evaluate_ne_passes_when_value_differs() {
        let e = WhereExpr { clauses: vec![ne("env", "dev")] };
        assert!(e.evaluate(&labels(&[("env", "prod")])));
        assert!(e.evaluate(&labels(&[("env", "staging")])));
    }

    #[test]
    fn evaluate_ne_fails_when_value_matches() {
        let e = WhereExpr { clauses: vec![ne("env", "dev")] };
        assert!(!e.evaluate(&labels(&[("env", "dev")])));
    }

    #[test]
    fn evaluate_ne_missing_key_is_false() {
        // A missing label means we can't confirm it's not "dev"
        let e = WhereExpr { clauses: vec![ne("env", "dev")] };
        assert!(!e.evaluate(&labels(&[])));
    }

    // ---- evaluate: In ----

    #[test]
    fn evaluate_in_matches_one_of_list() {
        let e = WhereExpr { clauses: vec![in_list("env", &["prod", "staging"])] };
        assert!(e.evaluate(&labels(&[("env", "prod")])));
        assert!(e.evaluate(&labels(&[("env", "staging")])));
    }

    #[test]
    fn evaluate_in_rejects_unlisted_value() {
        let e = WhereExpr { clauses: vec![in_list("env", &["prod", "staging"])] };
        assert!(!e.evaluate(&labels(&[("env", "dev")])));
    }

    #[test]
    fn evaluate_in_missing_key_is_false() {
        let e = WhereExpr { clauses: vec![in_list("env", &["prod"])] };
        assert!(!e.evaluate(&labels(&[])));
    }

    // ---- evaluate: Exists ----

    #[test]
    fn evaluate_exists_true_when_key_present() {
        let e = WhereExpr { clauses: vec![exists("mfa")] };
        assert!(e.evaluate(&labels(&[("mfa", "true")])));
        assert!(e.evaluate(&labels(&[("mfa", "false")])));
        assert!(e.evaluate(&labels(&[("mfa", "anything")])));
    }

    #[test]
    fn evaluate_exists_false_when_key_absent() {
        let e = WhereExpr { clauses: vec![exists("mfa")] };
        assert!(!e.evaluate(&labels(&[("env", "prod")])));
        assert!(!e.evaluate(&labels(&[])));
    }

    // ---- serde backward compat ----

    #[test]
    fn old_eq_json_deserializes_correctly() {
        let json = r#"{"key":"env","value":"prod"}"#;
        let clause: WhereClause = serde_json::from_str(json).unwrap();
        assert_eq!(clause.key, "env");
        assert_eq!(clause.operator, WhereOperator::Eq);
        assert_eq!(clause.value, "prod");
        assert!(clause.values.is_empty());
    }
}
