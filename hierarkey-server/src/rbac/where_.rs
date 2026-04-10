// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhereExpr {
    pub clauses: Vec<WhereClause>,
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
}
