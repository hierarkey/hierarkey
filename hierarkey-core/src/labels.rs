// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::CkResult;
use crate::error::validation::ValidationError;
use std::collections::HashMap;

pub type Labels = HashMap<String, String>;

pub fn validate_labels(labels: &[String]) -> CkResult<()> {
    let field = "labels";
    let mut seen = std::collections::HashSet::new();

    for label in labels {
        let (key, _value) = label.split_once('=').ok_or_else(|| ValidationError::Field {
            field,
            code: "invalid_format",
            message: "Invalid label format. Expected key=value".into(),
        })?;

        if key.is_empty() {
            return Err(ValidationError::Field {
                field,
                code: "empty_key",
                message: "Label key cannot be empty".into(),
            }
            .into());
        }

        if !key
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(ValidationError::FieldWithParams {
                field,
                code: "invalid_key_chars",
                message: "Label key contains invalid characters",
                params: vec![("key", key.to_string()), ("allowed", "a-zA-Z0-9 _ - .".to_string())],
            }
            .into());
        }

        // Check for duplicates
        if !seen.insert(key) {
            return Err(ValidationError::FieldWithParams {
                field,
                code: "duplicate_key",
                message: "Duplicate label key found",
                params: vec![("key", key.to_string())],
            }
            .into());
        }
    }

    Ok(())
}

pub fn parse_labels(labels: &[String]) -> Labels {
    labels
        .iter()
        .filter_map(|label| {
            let parts: Vec<&str> = label.splitn(2, '=').collect();
            if parts.len() == 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_labels_success() {
        let labels = vec![
            "env=production".to_string(),
            "version=1.0.0".to_string(),
            "region=us-west".to_string(),
        ];
        assert!(validate_labels(&labels).is_ok());
    }

    #[test]
    fn test_validate_labels_invalid_format() {
        let labels = vec!["invalid".to_string()];
        assert!(validate_labels(&labels).is_err());
    }

    #[test]
    fn test_validate_labels_duplicate_key() {
        let labels = vec!["env=production".to_string(), "env=staging".to_string()];
        assert!(validate_labels(&labels).is_err());
    }

    #[test]
    fn test_validate_labels_empty_key() {
        let labels = vec!["=value".to_string()];
        assert!(validate_labels(&labels).is_err());
    }

    #[test]
    fn test_validate_labels_invalid_key_chars() {
        let labels = vec!["key@name=value".to_string()];
        assert!(validate_labels(&labels).is_err());
    }

    #[test]
    fn test_parse_labels_strings() {
        let labels = vec!["env=production".to_string(), "region=us-west".to_string()];
        let parsed = parse_labels(&labels);

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get("env"), Some(&"production".to_string()));
        assert_eq!(parsed.get("region"), Some(&"us-west".to_string()));
    }

    #[test]
    fn test_parse_labels_with_equals_in_value() {
        let labels = vec!["url=https://example.com?foo=bar".to_string()];
        let parsed = parse_labels(&labels);

        assert_eq!(parsed.get("url"), Some(&"https://example.com?foo=bar".to_string()));
    }

    #[test]
    fn test_parse_labels_empty_value() {
        let labels = vec!["key=".to_string()];
        let parsed = parse_labels(&labels);

        assert_eq!(parsed.get("key"), Some(&"".to_string()));
    }

    #[test]
    fn test_validate_labels_valid_special_chars() {
        let labels = vec![
            "env_name=prod".to_string(),
            "app-name=myapp".to_string(),
            "domain.name=example.com".to_string(),
        ];
        assert!(validate_labels(&labels).is_ok());
    }
}
