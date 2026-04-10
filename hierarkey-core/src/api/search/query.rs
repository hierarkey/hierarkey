// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::{CkError, CkResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Search query for secrets, with various filters and pagination options.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretSearchRequest {
    #[serde(default)]
    pub scope: ScopeFilter,

    #[serde(default)]
    pub identity: IdentityFilter,

    #[serde(default)]
    pub labels: LabelFilter,

    #[serde(default)]
    pub time: TimeFilter,

    #[serde(default)]
    pub state: StateFilter,

    #[serde(default)]
    pub access: AccessFilter,

    #[serde(default)]
    pub r#type: TypeFilter,

    #[serde(default)]
    pub q: Option<String>,

    #[serde(default)]
    pub page: Page,
}

/// Scope on how to search for secrets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScopeFilter {
    #[serde(default)]
    pub namespaces: Vec<String>, // OR
    #[serde(default)]
    pub namespace_prefixes: Vec<String>, // OR
    #[serde(default)]
    pub all_namespaces: bool,
}

/// Identity filter for searching secrets by name or ID.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityFilter {
    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    pub name_match: Option<NameMatch>, // exact|contains|prefix

    #[serde(default)]
    pub id: Option<String>, // uuid/ulid/prefix
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameMatch {
    Exact,
    Contains,
    Prefix,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabelFilter {
    /// AND: all selectors must match
    #[serde(default)]
    pub all: Vec<String>, // "k=v" or "k" (exists)
    /// AND NOT: none may match
    #[serde(default)]
    pub none: Vec<String>, // "k=v" or "k"
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeFilter {
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    pub updated_after: Option<DateTime<Utc>>,
    pub updated_before: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateFilter {
    pub status: Option<ResourceStatus>,

    #[serde(default)]
    pub needs_rotation: bool,

    pub rotation_policy: Option<RotationPolicy>,

    /// stale means: updated_at < now - stale_seconds
    pub stale_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessFilter {
    pub accessed_after: Option<DateTime<Utc>>,
    pub accessed_before: Option<DateTime<Utc>>,

    #[serde(default)]
    pub never_accessed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeFilter {
    pub secret_type: Option<SecretType>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Page {
    pub sort: Option<SecretSortKey>,
    #[serde(default)]
    pub desc: bool,
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    50
}

// Enums
#[derive(Debug, Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RotationPolicy {
    Manual,
    Scheduled,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    Opaque,
    Password,
    CertificateChain,
    Certificate,
    CertificateKeyPair,
    Json,
    Yaml,
    Jwt,
    PrivateKey,
    PublicKey,
    SshPrivateKey,
    Uri,
    ConnectionString,
}

impl std::str::FromStr for SecretType {
    type Err = CkError;

    fn from_str(s: &str) -> CkResult<Self> {
        match s {
            "opaque" => Ok(SecretType::Opaque),
            "password" => Ok(SecretType::Password),
            "certificate" => Ok(SecretType::Certificate),
            "certificate_chain" => Ok(SecretType::CertificateChain),
            "certificate_key_pair" => Ok(SecretType::CertificateKeyPair),
            "json" => Ok(SecretType::Json),
            "yaml" => Ok(SecretType::Yaml),
            "jwt" => Ok(SecretType::Jwt),
            "private_key" => Ok(SecretType::PrivateKey),
            "public_key" => Ok(SecretType::PublicKey),
            "ssh_private_key" => Ok(SecretType::SshPrivateKey),
            "uri" => Ok(SecretType::Uri),
            "connection_string" => Ok(SecretType::ConnectionString),
            _ => Err(CkError::Custom("invalid secret type".into())),
        }
    }
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SecretType::Opaque => "opaque",
            SecretType::Password => "password",
            SecretType::Certificate => "certificate",
            SecretType::CertificateChain => "certificate_chain",
            SecretType::CertificateKeyPair => "certificate_key_pair",
            SecretType::Json => "json",
            SecretType::Yaml => "yaml",
            SecretType::Jwt => "jwt",
            SecretType::PrivateKey => "private_key",
            SecretType::PublicKey => "public_key",
            SecretType::SshPrivateKey => "ssh_private_key",
            SecretType::Uri => "uri",
            SecretType::ConnectionString => "connection_string",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum SecretSortKey {
    Name,
    Created,
    Updated,
    Accessed,
    RotationDue,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ResourceStatus {
    Active,
    Disabled,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_type_from_str_all_variants() {
        let cases = [
            ("opaque", SecretType::Opaque),
            ("password", SecretType::Password),
            ("certificate", SecretType::Certificate),
            ("certificate_chain", SecretType::CertificateChain),
            ("certificate_key_pair", SecretType::CertificateKeyPair),
            ("json", SecretType::Json),
            ("yaml", SecretType::Yaml),
            ("jwt", SecretType::Jwt),
            ("private_key", SecretType::PrivateKey),
            ("public_key", SecretType::PublicKey),
            ("ssh_private_key", SecretType::SshPrivateKey),
            ("uri", SecretType::Uri),
            ("connection_string", SecretType::ConnectionString),
        ];
        for (s, expected) in cases {
            let parsed: SecretType = s.parse().expect(s);
            assert_eq!(parsed, expected, "failed for '{s}'");
        }
    }

    #[test]
    fn secret_type_from_str_unknown_is_error() {
        assert!("unknown".parse::<SecretType>().is_err());
        assert!("OPAQUE".parse::<SecretType>().is_err());
        assert!("".parse::<SecretType>().is_err());
    }

    #[test]
    fn secret_type_display_all_variants() {
        let cases = [
            (SecretType::Opaque, "opaque"),
            (SecretType::Password, "password"),
            (SecretType::Certificate, "certificate"),
            (SecretType::CertificateChain, "certificate_chain"),
            (SecretType::CertificateKeyPair, "certificate_key_pair"),
            (SecretType::Json, "json"),
            (SecretType::Yaml, "yaml"),
            (SecretType::Jwt, "jwt"),
            (SecretType::PrivateKey, "private_key"),
            (SecretType::PublicKey, "public_key"),
            (SecretType::SshPrivateKey, "ssh_private_key"),
            (SecretType::Uri, "uri"),
            (SecretType::ConnectionString, "connection_string"),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.to_string(), expected);
        }
    }

    #[test]
    fn secret_type_roundtrip() {
        let variants = [
            SecretType::Opaque,
            SecretType::Password,
            SecretType::Certificate,
            SecretType::CertificateChain,
            SecretType::CertificateKeyPair,
            SecretType::Json,
            SecretType::Yaml,
            SecretType::Jwt,
            SecretType::PrivateKey,
            SecretType::PublicKey,
            SecretType::SshPrivateKey,
            SecretType::Uri,
            SecretType::ConnectionString,
        ];
        for variant in variants {
            let s = variant.to_string();
            let parsed: SecretType = s.parse().unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn resource_status_as_str() {
        assert_eq!(ResourceStatus::Active.as_str(), "active");
        assert_eq!(ResourceStatus::Disabled.as_str(), "disabled");
        assert_eq!(ResourceStatus::Deleted.as_str(), "deleted");
    }

    #[test]
    fn page_default_limit_is_50() {
        // #[serde(default = "default_limit")] only fires during JSON deserialization,
        // not when calling Page::default() directly (which gives u32's default of 0).
        let page = Page::default();
        assert_eq!(page.limit, 0);
        assert_eq!(page.offset, 0);
        assert!(!page.desc);
        assert!(page.sort.is_none());

        // Deserializing an empty JSON object applies the serde default -> 50.
        let page: Page = serde_json::from_str("{}").unwrap();
        assert_eq!(page.limit, 50);
    }

    #[test]
    fn secret_search_request_default_is_empty() {
        let req = SecretSearchRequest::default();
        assert!(req.scope.namespaces.is_empty());
        assert!(req.scope.namespace_prefixes.is_empty());
        assert!(!req.scope.all_namespaces);
        assert!(req.identity.name.is_none());
        assert!(req.identity.id.is_none());
        assert!(req.labels.all.is_empty());
        assert!(req.labels.none.is_empty());
        assert!(req.q.is_none());
        // Page::default() gives limit=0; serde default of 50 only applies on deserialization.
        assert_eq!(req.page.limit, 0);
    }

    #[test]
    fn secret_search_request_serde_roundtrip() {
        let req = SecretSearchRequest {
            scope: ScopeFilter {
                namespaces: vec!["ns1".to_string()],
                all_namespaces: true,
                ..Default::default()
            },
            identity: IdentityFilter {
                name: Some("my-secret".to_string()),
                name_match: Some(NameMatch::Prefix),
                ..Default::default()
            },
            labels: LabelFilter {
                all: vec!["env=prod".to_string()],
                none: vec!["deprecated".to_string()],
            },
            state: StateFilter {
                needs_rotation: true,
                ..Default::default()
            },
            page: Page {
                limit: 10,
                offset: 20,
                desc: true,
                sort: Some(SecretSortKey::Name),
            },
            ..Default::default()
        };

        let json = serde_json::to_string(&req).unwrap();
        let restored: SecretSearchRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.scope.namespaces, vec!["ns1"]);
        assert!(restored.scope.all_namespaces);
        assert_eq!(restored.identity.name.as_deref(), Some("my-secret"));
        assert!(matches!(restored.identity.name_match, Some(NameMatch::Prefix)));
        assert_eq!(restored.labels.all, vec!["env=prod"]);
        assert_eq!(restored.labels.none, vec!["deprecated"]);
        assert!(restored.state.needs_rotation);
        assert_eq!(restored.page.limit, 10);
        assert_eq!(restored.page.offset, 20);
        assert!(restored.page.desc);
    }

    #[test]
    fn secret_search_request_deserialize_minimal_json() {
        // Absent `page` key -> #[serde(default)] uses Page::default() -> limit=0.
        let req: SecretSearchRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(req.page.limit, 0);
        assert!(req.labels.all.is_empty());

        // Explicit empty `page` object -> per-field serde defaults fire -> limit=50.
        let req: SecretSearchRequest = serde_json::from_str(r#"{"page":{}}"#).unwrap();
        assert_eq!(req.page.limit, 50);
    }
}
