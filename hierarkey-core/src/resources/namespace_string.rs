// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::error::validation::ValidationError;
use crate::{CkError, CkResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sqlx::{Database, Type};
use std::fmt;
use std::str::FromStr;

const MIN_NAMESPACE_LENGTH: usize = 2;
const MAX_NAMESPACE_LENGTH: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct NamespaceString(String);

impl NamespaceString {
    /// Create a new namespace, validating it
    pub fn new(s: impl Into<String>) -> CkResult<Self> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(NamespaceString(s))
    }

    /// Get the namespace as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate a namespace string
    fn validate(namespace: &str) -> CkResult<()> {
        let field = "namespace";

        // Check length
        if namespace.len() < MIN_NAMESPACE_LENGTH || namespace.len() > MAX_NAMESPACE_LENGTH {
            return Err(ValidationError::FieldWithParams {
                field,
                code: "length_out_of_range",
                message: "Namespace length is out of range",
                params: vec![
                    ("min", MIN_NAMESPACE_LENGTH.to_string()),
                    ("max", MAX_NAMESPACE_LENGTH.to_string()),
                ],
            }
            .into());
        }

        // Must start with /
        if !namespace.starts_with('/') {
            return Err(ValidationError::Field {
                field,
                code: "missing_leading_slash",
                message: "Namespace must start with '/'".into(),
            }
            .into());
        }

        // "/" is not valid - must have at least one segment
        if namespace == "/" {
            return Err(ValidationError::Field {
                field,
                code: "missing_segment",
                message: "Namespace must contain at least one segment after '/'".into(),
            }
            .into());
        }

        // Cannot end with /
        if namespace.ends_with('/') {
            return Err(ValidationError::Field {
                field,
                code: "trailing_slash",
                message: "Namespace cannot end with '/'".into(),
            }
            .into());
        }

        // Split by '/' and validate each segment
        let mut segments = namespace[1..].split('/').enumerate();
        for (idx, seg) in &mut segments {
            if seg.is_empty() {
                return Err(ValidationError::Field {
                    field,
                    code: "empty_segment",
                    message: "Namespace cannot contain consecutive slashes '//' ".into(),
                }
                .into());
            }

            // $ only allowed at start of first segment
            if let Some(rest) = seg.strip_prefix('$') {
                if idx != 0 {
                    return Err(ValidationError::Field {
                        field,
                        code: "dollar_not_first_segment",
                        message: "Symbol '$' is only allowed in the first segment after root '/'".into(),
                    }
                    .into());
                }
                if rest.is_empty() {
                    return Err(ValidationError::Field {
                        field,
                        code: "dollar_only",
                        message: "Segment cannot be just '$'".into(),
                    }
                    .into());
                }
                if !rest
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
                {
                    return Err(ValidationError::Field {
                        field,
                        code: "invalid_chars_after_dollar",
                        message: "After '$', only alphanumeric characters, underscores, hyphens, and dots are allowed"
                            .into(),
                    }
                    .into());
                }
            } else if !seg
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                return Err(ValidationError::Field {
                    field,
                    code: "invalid_chars",
                    message:
                        "Namespace segments can only contain alphanumeric characters, underscores, hyphens, and dots"
                            .into(),
                }
                .into());
            }
        }

        Ok(())
    }

    /// Get the segments of the namespace
    pub fn segments(&self) -> Vec<&str> {
        self.0[1..].split('/').collect()
    }

    /// Check if this namespace starts with another namespace (is a sub-namespace)
    pub fn is_sub_namespace_of(&self, parent: &NamespaceString) -> bool {
        self.0.starts_with(parent.as_str())
            && (self.0.len() == parent.0.len() || self.0.as_bytes()[parent.0.len()] == b'/')
    }

    /// Returns true if the namespace is reserved (starts with $ in the first segment)
    pub fn is_reserved(&self) -> bool {
        let segments = self.segments();
        if let Some(first_segment) = segments.first() {
            first_segment.starts_with('$')
        } else {
            false
        }
    }
}

impl fmt::Display for NamespaceString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for NamespaceString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for NamespaceString {
    type Err = CkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for NamespaceString {
    type Error = CkError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for NamespaceString {
    type Error = CkError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

// Serde support
impl Serialize for NamespaceString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NamespaceString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        NamespaceString::new(s).map_err(serde::de::Error::custom)
    }
}

impl Type<sqlx::Postgres> for NamespaceString {
    fn type_info() -> <sqlx::Postgres as Database>::TypeInfo {
        <String as Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &<sqlx::Postgres as Database>::TypeInfo) -> bool {
        <String as Type<sqlx::Postgres>>::compatible(ty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_namespaces() {
        assert!(NamespaceString::new("/users").is_ok());
        assert!(NamespaceString::new("/users/john").is_ok());
        assert!(NamespaceString::new("/$system").is_ok());
        assert!(NamespaceString::new("/$sys_tem").is_ok());
        assert!(NamespaceString::new("/$system/config").is_ok());
        assert!(NamespaceString::new("/org/team-1").is_ok());
        assert!(NamespaceString::new("/org/team.alpha").is_ok());
    }

    #[test]
    fn test_invalid_namespaces() {
        assert!(NamespaceString::new("users").is_err()); // No leading /
        assert!(NamespaceString::new("/users/").is_err()); // Trailing /
        assert!(NamespaceString::new("/").is_err()); // Too short
        assert!(NamespaceString::new("//users").is_err()); // Consecutive slashes
        assert!(NamespaceString::new("/users//john").is_err()); // Consecutive slashes
        assert!(NamespaceString::new("/$").is_err()); // Just $
        assert!(NamespaceString::new("/users/$system").is_err()); // $ not in first segment
        assert!(NamespaceString::new("/users/jo hn").is_err()); // Space not allowed
        assert!(NamespaceString::new("/users/john@").is_err()); // @ not allowed
    }

    #[test]
    fn test_sub_namespace() {
        let parent = NamespaceString::new("/users").unwrap();
        let child = NamespaceString::new("/users/john").unwrap();
        let other = NamespaceString::new("/groups").unwrap();

        assert!(child.is_sub_namespace_of(&parent));
        assert!(!other.is_sub_namespace_of(&parent));
        assert!(parent.is_sub_namespace_of(&parent)); // Self is sub-namespace
    }

    #[test]
    fn test_invalid_chars_after_dollar() {
        assert!(NamespaceString::new("/$abc!").is_err()); // invalid char after $
        assert!(NamespaceString::new("/$@sys").is_err()); // @ after $
        assert!(NamespaceString::new("/$sys tem").is_err()); // space after $
    }

    #[test]
    fn test_segments() {
        let ns = NamespaceString::new("/users/john/config").unwrap();
        assert_eq!(ns.segments(), vec!["users", "john", "config"]);

        let ns = NamespaceString::new("/users").unwrap();
        assert_eq!(ns.segments(), vec!["users"]);
    }

    #[test]
    fn test_is_reserved() {
        let reserved = NamespaceString::new("/$system").unwrap();
        assert!(reserved.is_reserved());

        let reserved2 = NamespaceString::new("/$system/config").unwrap();
        assert!(reserved2.is_reserved());

        let not_reserved = NamespaceString::new("/users").unwrap();
        assert!(!not_reserved.is_reserved());

        let not_reserved2 = NamespaceString::new("/org/team").unwrap();
        assert!(!not_reserved2.is_reserved());
    }

    #[test]
    fn test_as_ref() {
        let ns = NamespaceString::new("/users").unwrap();
        let s: &str = ns.as_ref();
        assert_eq!(s, "/users");
    }

    #[test]
    fn test_from_str_trait() {
        use std::str::FromStr;
        let ns = NamespaceString::from_str("/users").unwrap();
        assert_eq!(ns.as_str(), "/users");
        assert!(NamespaceString::from_str("no-leading-slash").is_err());
    }

    #[test]
    fn test_try_from_string() {
        let ns = NamespaceString::try_from(String::from("/users")).unwrap();
        assert_eq!(ns.as_str(), "/users");
        assert!(NamespaceString::try_from(String::from("bad")).is_err());
    }

    #[test]
    fn test_display() {
        let ns = NamespaceString::new("/org/team").unwrap();
        assert_eq!(format!("{ns}"), "/org/team");
        assert_eq!(ns.to_string(), "/org/team");
    }

    #[test]
    fn test_serde_serialize() {
        let ns = NamespaceString::new("/users").unwrap();
        let json = serde_json::to_string(&ns).unwrap();
        assert_eq!(json, "\"/users\"");
    }

    #[test]
    fn test_serde_deserialize() {
        let ns: NamespaceString = serde_json::from_str("\"/users\"").unwrap();
        assert_eq!(ns.as_str(), "/users");

        let result: Result<NamespaceString, _> = serde_json::from_str("\"invalid\"");
        assert!(result.is_err());
    }
}
