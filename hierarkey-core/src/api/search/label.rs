// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use std::str::FromStr;

/// Label selector:
///   - "key=value" means exact match
///   - "key" means existence
#[allow(unused)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelExpr {
    pub key: String,
    pub value: Option<String>,
}

impl std::fmt::Display for LabelExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.value {
            Some(v) => write!(f, "{}={}", self.key, v),
            None => write!(f, "{}", self.key),
        }
    }
}

impl FromStr for LabelExpr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err("Label cannot be empty".into());
        }

        // Split on first '=' only
        if let Some((k, v)) = s.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            if key.is_empty() {
                return Err(format!("Invalid label '{s}': missing key"));
            }
            if val.is_empty() {
                return Err(format!("Invalid label '{s}': missing value"));
            }
            Ok(LabelExpr {
                key: key.to_string(),
                value: Some(val.to_string()),
            })
        } else {
            // Existence
            let key = s;
            if key.is_empty() {
                return Err(format!("Invalid label '{s}': missing key"));
            }
            Ok(LabelExpr {
                key: key.to_string(),
                value: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_value() {
        let expr: LabelExpr = "env=prod".parse().unwrap();
        assert_eq!(expr.key, "env");
        assert_eq!(expr.value, Some("prod".to_string()));
    }

    #[test]
    fn parse_existence() {
        let expr: LabelExpr = "monitored".parse().unwrap();
        assert_eq!(expr.key, "monitored");
        assert_eq!(expr.value, None);
    }

    #[test]
    fn parse_trims_whitespace() {
        let expr: LabelExpr = "  env = prod  ".parse().unwrap();
        assert_eq!(expr.key, "env");
        assert_eq!(expr.value, Some("prod".to_string()));
    }

    #[test]
    fn parse_empty_string_is_error() {
        assert!("".parse::<LabelExpr>().is_err());
        assert!("   ".parse::<LabelExpr>().is_err());
    }

    #[test]
    fn parse_missing_key_is_error() {
        assert!("=value".parse::<LabelExpr>().is_err());
        assert!(" = value".parse::<LabelExpr>().is_err());
    }

    #[test]
    fn parse_missing_value_is_error() {
        assert!("key=".parse::<LabelExpr>().is_err());
        assert!("key= ".parse::<LabelExpr>().is_err());
    }

    #[test]
    fn parse_value_with_embedded_equals() {
        // Only the first '=' is used as separator; the rest becomes the value.
        let expr: LabelExpr = "key=a=b".parse().unwrap();
        assert_eq!(expr.key, "key");
        assert_eq!(expr.value, Some("a=b".to_string()));
    }

    #[test]
    fn display_key_value() {
        let expr = LabelExpr {
            key: "env".to_string(),
            value: Some("prod".to_string()),
        };
        assert_eq!(expr.to_string(), "env=prod");
    }

    #[test]
    fn display_existence() {
        let expr = LabelExpr {
            key: "monitored".to_string(),
            value: None,
        };
        assert_eq!(expr.to_string(), "monitored");
    }

    #[test]
    fn roundtrip_key_value() {
        let original = LabelExpr {
            key: "tier".to_string(),
            value: Some("backend".to_string()),
        };
        let parsed: LabelExpr = original.to_string().parse().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_existence() {
        let original = LabelExpr {
            key: "active".to_string(),
            value: None,
        };
        let parsed: LabelExpr = original.to_string().parse().unwrap();
        assert_eq!(original, parsed);
    }
}
