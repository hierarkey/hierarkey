// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::error::validation::ValidationError;
use crate::resources::KeyString;
use crate::resources::NamespaceString;
use crate::{CkResult, resources::Revision};
use serde::Serialize;

/// A reference to a secret, consisting of a namespace and key, and optionally a revision.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretRef {
    /// The namespace of the secret, e.g. "/prod" or "/dev/app1"
    pub namespace: NamespaceString,
    /// The key of the secret, e.g. "db/password" or "api/key"
    pub key: KeyString,
    /// An optional revision, which can be a specific version number, "active", or "latest"
    pub revision: Option<Revision>,
}

impl Serialize for SecretRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}:{}", self.namespace, self.key))
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.revision {
            Some(rev) => write!(f, "{}:{}@{}", self.namespace, self.key, rev),
            None => write!(f, "{}:{}", self.namespace, self.key),
        }
    }
}

impl SecretRef {
    pub fn new(namespace: NamespaceString, key: KeyString, revision: Option<Revision>) -> Self {
        SecretRef {
            namespace,
            key,
            revision,
        }
    }

    /// Creates a SecretRef from separate namespace and key strings, validating them according
    /// to the rules of NamespaceString and KeyString.
    pub fn from_parts(namespace: &str, key: &str, revision: Option<Revision>) -> CkResult<Self> {
        Ok(SecretRef {
            namespace: NamespaceString::try_from(namespace)?,
            key: KeyString::try_from(key)?,
            revision,
        })
    }

    /// Parses a SecretRef from a string in the format "/namespace:key" or "/namespace:key@revision".
    pub fn from_string(s: &str) -> CkResult<Self> {
        let s = s.trim();

        let (nskey, rev_opt) = match s.split_once('@') {
            Some((left, right)) => {
                let rev = Revision::try_from(right).map_err(|_| ValidationError::Field {
                    field: "secret_ref",
                    code: "invalid_format",
                    message: "Revision must be a non-negative integer, 'active', or 'latest'".into(),
                })?;

                (left.trim(), Some(rev))
            }
            None => (s, None),
        };

        let (ns, key) = nskey.split_once(':').ok_or_else(|| ValidationError::Field {
            field: "secret_ref",
            code: "invalid_format",
            message: "Expected secret ref in the form '/namespace:key' (optionally with @revision)".into(),
        })?;

        let ns = ns.trim();
        let key = key.trim();

        if ns.is_empty() {
            return Err(ValidationError::Field {
                field: "secret_ref",
                code: "invalid_format",
                message: "Namespace must not be empty (expected '/namespace:key')".into(),
            }
            .into());
        }
        if key.is_empty() {
            return Err(ValidationError::Field {
                field: "secret_ref",
                code: "invalid_format",
                message: "Key must not be empty (expected '/namespace:key')".into(),
            }
            .into());
        }

        let namespace = NamespaceString::try_from(ns)?;
        let key = KeyString::try_from(key)?;

        Ok(SecretRef {
            namespace,
            key,
            revision: rev_opt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_ref_new() -> CkResult<()> {
        let namespace = NamespaceString::try_from("/prod")?;
        let key = KeyString::try_from("api/database/password")?;
        let id = SecretRef::new(namespace.clone(), key.clone(), Some(Revision::Number(1)));

        assert_eq!(id.namespace, namespace);
        assert_eq!(id.key, key);
        assert_eq!(id.revision, Some(Revision::Number(1)));
        Ok(())
    }

    #[test]
    fn test_secret_ref_from_parts_valid() -> CkResult<()> {
        let id = SecretRef::from_parts("/prod", "api/database/password", None)?;
        assert_eq!(id.namespace.as_str(), "/prod");
        assert_eq!(id.key.as_str(), "api/database/password");
        assert_eq!(id.revision, None);
        Ok(())
    }

    #[test]
    fn test_secret_ref_from_parts_invalid() {
        assert!(SecretRef::from_parts("prod", "api/secret", None).is_err()); // no leading /
        assert!(SecretRef::from_parts("/prod", "/api/secret", None).is_err()); // key starts with /
        assert!(SecretRef::from_parts("/prod/", "api/secret", None).is_err()); // namespace ends with /
        assert!(SecretRef::from_parts("/prod", "api/secret/", None).is_err()); // key ends with /
    }

    #[test]
    fn test_to_string_drops_revision() -> CkResult<()> {
        let id = SecretRef::from_parts("/dev", "app/secret", Some(Revision::Number(7)))?;
        assert_eq!(id.to_string(), "/dev:app/secret@7");
        Ok(())
    }

    #[test]
    fn test_from_string_valid_no_revision() -> CkResult<()> {
        let id = SecretRef::from_string("/staging:config/api-key")?;
        assert_eq!(id.namespace.as_str(), "/staging");
        assert_eq!(id.key.as_str(), "config/api-key");
        assert_eq!(id.revision, None);
        Ok(())
    }

    #[test]
    fn test_from_string_valid_with_revision() -> CkResult<()> {
        let id = SecretRef::from_string("/staging:config/api-key@1")?;
        assert_eq!(id.namespace.as_str(), "/staging");
        assert_eq!(id.key.as_str(), "config/api-key");
        assert_eq!(id.revision, Some(Revision::Number(1)));
        Ok(())
    }

    #[test]
    fn test_from_string_trims_whitespace() -> CkResult<()> {
        let id = SecretRef::from_string("  /staging:config/api-key  @  12  ")?;
        assert_eq!(id.namespace.as_str(), "/staging");
        assert_eq!(id.key.as_str(), "config/api-key");
        assert_eq!(id.revision, Some(Revision::Number(12)));
        Ok(())
    }

    #[test]
    fn test_from_string_revision_missing_value_is_error() {
        assert!(SecretRef::from_string("/prod:key@").is_err());
        assert!(SecretRef::from_string("/prod:key@   ").is_err());
    }

    #[test]
    fn test_from_string_revision_invalid_is_error() {
        assert!(SecretRef::from_string("/prod:key@nope").is_err());
        assert!(SecretRef::from_string("/prod:key@-1").is_err());
    }

    #[test]
    fn test_from_string_no_colon_is_error() {
        let result = SecretRef::from_string("no-colon-here");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_string_empty_parts_is_error() {
        assert!(SecretRef::from_string(":key").is_err()); // empty namespace
        assert!(SecretRef::from_string("/namespace:").is_err()); // empty key
    }

    #[test]
    fn test_from_string_invalid_namespace_is_error() {
        assert!(SecretRef::from_string("invalid:key").is_err()); // no leading /
        assert!(SecretRef::from_string("/ns/:key").is_err()); // trailing /
    }

    #[test]
    fn test_from_string_invalid_key_is_error() {
        assert!(SecretRef::from_string("/prod:/no-leading-slash").is_err()); // key starts with /
        assert!(SecretRef::from_string("/prod:key/").is_err()); // key ends with /
    }

    #[test]
    fn test_roundtrip_display_parse_drops_revision() -> CkResult<()> {
        let with_rev = SecretRef::from_string("/prod:api/secret@3")?;
        assert_eq!(with_rev.revision, Some(Revision::Number(3)));

        // Display drops the revision
        let display = with_rev.to_string();
        assert_eq!(display, "/prod:api/secret@3");

        Ok(())
    }

    #[test]
    fn test_complex_paths() -> CkResult<()> {
        let id = SecretRef::from_parts("/prod/app1", "db/primary/password", None)?;
        assert_eq!(id.to_string(), "/prod/app1:db/primary/password");

        let parsed = SecretRef::from_string("/prod/app1:db/primary/password")?;
        assert_eq!(parsed.namespace.as_str(), "/prod/app1");
        assert_eq!(parsed.key.as_str(), "db/primary/password");
        assert_eq!(parsed.revision, None);

        let parsed2 = SecretRef::from_string("/prod/app1:db/primary/password@42")?;
        assert_eq!(parsed2.revision, Some(Revision::Number(42)));

        Ok(())
    }

    #[test]
    fn test_serialize_drops_revision() -> CkResult<()> {
        let id = SecretRef::from_parts("/test", "my/key", Some(Revision::Number(99)))?;
        let json = serde_json::to_string(&id)?;
        assert_eq!(json, "\"/test:my/key\"");
        Ok(())
    }

    #[test]
    fn test_multiple_at_is_error() {
        // split_once('@') means the right side would contain another '@' and Revision parsing should fail
        assert!(SecretRef::from_string("/prod:key@1@2").is_err());
    }
}
