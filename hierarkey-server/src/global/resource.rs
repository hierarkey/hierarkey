// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::CkError;
use hierarkey_core::error::validation::ValidationError;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::str::FromStr;

/// Generic resource (namespace, account, secret, etc.) status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ResourceStatus {
    /// Resource is active and available (pending rbac)
    Active,
    /// Resource is disabled and unavailable
    Disabled,
    /// Resource is deleted and unavailable. Can be recycled into a new resource with the same name.
    Deleted,
}

impl ResourceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceStatus::Active => "active",
            ResourceStatus::Disabled => "disabled",
            ResourceStatus::Deleted => "deleted",
        }
    }
}

impl std::fmt::Display for ResourceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<String> for ResourceStatus {
    type Error = CkError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<&str> for ResourceStatus {
    type Error = CkError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "active" => Ok(ResourceStatus::Active),
            "disabled" => Ok(ResourceStatus::Disabled),
            "deleted" => Ok(ResourceStatus::Deleted),
            _ => Err(ValidationError::Field {
                field: "resource_status",
                code: "incorrect_value",
                message: "invalid resource status".into(),
            }
            .into()),
        }
    }
}

impl FromStr for ResourceStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "active" => Ok(ResourceStatus::Active),
            "disabled" => Ok(ResourceStatus::Disabled),
            "deleted" => Ok(ResourceStatus::Deleted),
            other => Err(format!("invalid status '{other}' (expected: active, disabled, deleted)")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_status_as_str() {
        assert_eq!(ResourceStatus::Active.as_str(), "active");
        assert_eq!(ResourceStatus::Disabled.as_str(), "disabled");
        assert_eq!(ResourceStatus::Deleted.as_str(), "deleted");
    }

    #[test]
    fn test_resource_status_display() {
        assert_eq!(ResourceStatus::Active.to_string(), "active");
        assert_eq!(ResourceStatus::Disabled.to_string(), "disabled");
        assert_eq!(ResourceStatus::Deleted.to_string(), "deleted");
    }

    #[test]
    fn test_resource_status_try_from_valid() {
        assert_eq!(ResourceStatus::try_from("active").unwrap(), ResourceStatus::Active);
        assert_eq!(ResourceStatus::try_from("disabled").unwrap(), ResourceStatus::Disabled);
        assert_eq!(ResourceStatus::try_from("deleted").unwrap(), ResourceStatus::Deleted);
    }

    #[test]
    fn test_resource_status_try_from_invalid() {
        let result = ResourceStatus::try_from("invalid");
        assert!(matches!(result, Err(CkError::Validation(_))));

        let result = ResourceStatus::try_from("ACTIVE");
        assert!(matches!(result, Err(CkError::Validation(_))));

        let result = ResourceStatus::try_from("");
        assert!(matches!(result, Err(CkError::Validation(_))));

        let result = ResourceStatus::try_from("pending");
        assert!(matches!(result, Err(CkError::Validation(_))));
    }

    #[test]
    fn test_resource_status_equality() {
        assert_eq!(ResourceStatus::Active, ResourceStatus::Active);
        assert_eq!(ResourceStatus::Disabled, ResourceStatus::Disabled);
        assert_eq!(ResourceStatus::Deleted, ResourceStatus::Deleted);

        assert_ne!(ResourceStatus::Active, ResourceStatus::Disabled);
        assert_ne!(ResourceStatus::Active, ResourceStatus::Deleted);
        assert_ne!(ResourceStatus::Disabled, ResourceStatus::Deleted);
    }

    #[test]
    fn test_resource_status_clone() {
        let status = ResourceStatus::Active;
        let cloned = status;
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_resource_status_copy() {
        let status = ResourceStatus::Active;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn test_resource_status_serialization() {
        let status = ResourceStatus::Active;
        let serialized = serde_json::to_string(&status).unwrap();
        assert_eq!(serialized, "\"active\"");

        let deserialized: ResourceStatus = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, status);
    }

    #[test]
    fn test_all_statuses_roundtrip() {
        let statuses = vec![
            ResourceStatus::Active,
            ResourceStatus::Disabled,
            ResourceStatus::Deleted,
        ];

        for status in statuses {
            let as_str = status.as_str();
            let parsed = ResourceStatus::try_from(as_str).unwrap();
            assert_eq!(status, parsed);
        }
    }

    #[test]
    fn test_resource_status_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(ResourceStatus::Active);
        set.insert(ResourceStatus::Disabled);
        set.insert(ResourceStatus::Deleted);
        set.insert(ResourceStatus::Active); // Duplicate

        assert_eq!(set.len(), 3);
        assert!(set.contains(&ResourceStatus::Active));
        assert!(set.contains(&ResourceStatus::Disabled));
        assert!(set.contains(&ResourceStatus::Deleted));
    }

    #[test]
    fn test_resource_status_debug() {
        let status = ResourceStatus::Active;
        let debug_str = format!("{status:?}");
        assert_eq!(debug_str, "Active");
    }

    #[test]
    fn test_resource_status_in_match() {
        let status = ResourceStatus::Active;
        let result = match status {
            ResourceStatus::Active => "is_active",
            ResourceStatus::Disabled => "is_disabled",
            ResourceStatus::Deleted => "is_deleted",
        };
        assert_eq!(result, "is_active");
    }
}
