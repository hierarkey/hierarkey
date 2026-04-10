// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::error::validation::ValidationError;
use crate::{CkError, CkResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sqlx::{Database, Type};
use std::fmt;
use std::str::FromStr;

const MIN_KEY_LENGTH: usize = 1;
const MAX_KEY_LENGTH: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct KeyString(String);

impl KeyString {
    /// Create a new key path, validating it
    pub fn new(path: impl Into<String>) -> CkResult<Self> {
        let path = path.into();
        Self::validate(&path)?;
        Ok(KeyString(path))
    }

    /// Get the key path as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if the key path starts with the given prefix
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.0.starts_with(prefix)
    }

    /// Validate a key path string
    fn validate(path: &str) -> CkResult<()> {
        let field = "key_path";

        // Check length
        if path.len() < MIN_KEY_LENGTH || path.len() > MAX_KEY_LENGTH {
            return Err(ValidationError::FieldWithParams {
                field,
                code: "length_out_of_range",
                message: "Key path length is out of allowed range",
                params: vec![("min", MIN_KEY_LENGTH.to_string()), ("max", MAX_KEY_LENGTH.to_string())],
            }
            .into());
        }

        // Cannot start with /
        if path.starts_with('/') {
            return Err(ValidationError::Field {
                field,
                code: "starts_with_slash",
                message: "Key path cannot start with '/'".into(),
            }
            .into());
        }

        // Cannot end with /
        if path.ends_with('/') {
            return Err(ValidationError::Field {
                field,
                code: "ends_with_slash",
                message: "Key path cannot end with '/'".into(),
            }
            .into());
        }

        // Split by '/' and validate each segment
        let segments: Vec<&str> = path.split('/').collect();
        if segments.is_empty() {
            return Err(ValidationError::Field {
                field,
                code: "no_segments",
                message: "Key path must contain at least one segment".into(),
            }
            .into());
        }

        for segment in segments.iter() {
            // Check for empty segments (would indicate //)
            if segment.is_empty() {
                return Err(ValidationError::Field {
                    field,
                    code: "empty_segment",
                    message: "Key path cannot contain consecutive slashes '//' ".into(),
                }
                .into());
            }

            // Validate characters: only alphanumeric, underscore, hyphen, and dot
            if !segment
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                return Err(ValidationError::Field {
                    field,
                    code: "invalid_chars",
                    message:
                        "Key path segments may only contain alphanumeric characters, underscores, hyphens, and dots"
                            .into(),
                }
                .into());
            }
        }

        Ok(())
    }

    /// Get the segments of the key path
    pub fn segments(&self) -> Vec<&str> {
        self.0.split('/').collect()
    }

    /// Check if this key path starts with another key path (is a sub-path)
    pub fn is_sub_path_of(&self, parent: &KeyString) -> bool {
        self.0.starts_with(parent.as_str())
            && (self.0.len() == parent.0.len() || self.0.as_bytes()[parent.0.len()] == b'/')
    }
}

impl fmt::Display for KeyString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for KeyString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for KeyString {
    type Err = CkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for KeyString {
    type Error = CkError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for KeyString {
    type Error = CkError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

// Serde support
impl Serialize for KeyString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for KeyString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        KeyString::new(s).map_err(serde::de::Error::custom)
    }
}

impl Type<sqlx::Postgres> for KeyString {
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
    fn test_valid_key_paths() {
        assert!(KeyString::new("mykey").is_ok());
        assert!(KeyString::new("app_1").is_ok());
        assert!(KeyString::new("app.config").is_ok());
        assert!(KeyString::new("app-name").is_ok());
        assert!(KeyString::new("app1/webtoken").is_ok());
        assert!(KeyString::new("prod/app/db/password").is_ok());
        assert!(KeyString::new("level1/level2/level3").is_ok());
    }

    #[test]
    fn test_invalid_key_paths() {
        assert!(KeyString::new("").is_err()); // Empty
        assert!(KeyString::new("/mykey").is_err()); // Starts with /
        assert!(KeyString::new("mykey/").is_err()); // Ends with /
        assert!(KeyString::new("my//key").is_err()); // Consecutive slashes
        assert!(KeyString::new("my key").is_err()); // Space not allowed
        assert!(KeyString::new("my@key").is_err()); // @ not allowed
        assert!(KeyString::new("my$key").is_err()); // $ not allowed
        assert!(KeyString::new("my/ke y/test").is_err()); // Space in segment
    }

    #[test]
    fn test_sub_path() {
        let parent = KeyString::new("app").unwrap();
        let child = KeyString::new("app/config").unwrap();
        let other = KeyString::new("other").unwrap();

        assert!(child.is_sub_path_of(&parent));
        assert!(!other.is_sub_path_of(&parent));
        assert!(parent.is_sub_path_of(&parent)); // Self is sub-path
    }

    #[test]
    fn test_segments() {
        let path = KeyString::new("app/config/db").unwrap();
        let segments = path.segments();
        assert_eq!(segments, vec!["app", "config", "db"]);
    }

    #[test]
    fn test_starts_with() {
        let k = KeyString::new("app/config").unwrap();
        assert!(k.starts_with("app"));
        assert!(k.starts_with("app/"));
        assert!(!k.starts_with("other"));
    }

    #[test]
    fn test_as_ref() {
        let k = KeyString::new("my/key").unwrap();
        let s: &str = k.as_ref();
        assert_eq!(s, "my/key");
    }

    #[test]
    fn test_from_str_trait() {
        use std::str::FromStr;
        let k = KeyString::from_str("app/config").unwrap();
        assert_eq!(k.as_str(), "app/config");
        assert!(KeyString::from_str("").is_err());
    }

    #[test]
    fn test_try_from_string() {
        let k = KeyString::try_from(String::from("my/key")).unwrap();
        assert_eq!(k.as_str(), "my/key");
        assert!(KeyString::try_from(String::from("")).is_err());
    }

    #[test]
    fn test_display() {
        let k = KeyString::new("app/config/db").unwrap();
        assert_eq!(format!("{k}"), "app/config/db");
        assert_eq!(k.to_string(), "app/config/db");
    }

    #[test]
    fn test_serde_serialize() {
        let k = KeyString::new("app/config").unwrap();
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(json, "\"app/config\"");
    }

    #[test]
    fn test_serde_deserialize() {
        let k: KeyString = serde_json::from_str("\"app/config\"").unwrap();
        assert_eq!(k.as_str(), "app/config");

        let result: Result<KeyString, _> = serde_json::from_str("\"\"");
        assert!(result.is_err());

        let result: Result<KeyString, _> = serde_json::from_str("\"/starts-with-slash\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_max_length() {
        let long = "a".repeat(200);
        assert!(KeyString::new(long.as_str()).is_ok());
        let too_long = "a".repeat(201);
        assert!(KeyString::new(too_long.as_str()).is_err());
    }
}
