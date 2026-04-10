// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::error::validation::ValidationError;
use hierarkey_core::{CkError, CkResult};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SecretAlgorithm {
    AesGcm256, // We only support AESGCM256 as this is approved by NIST
}

impl SecretAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretAlgorithm::AesGcm256 => "AES-GCM-256",
        }
    }

    /// Returns all supported algorithms
    pub fn all() -> Vec<SecretAlgorithm> {
        vec![SecretAlgorithm::AesGcm256]
    }

    /// Returns all supported algorithm names as strings
    pub fn all_names() -> Vec<&'static str> {
        vec!["AES-GCM-256"]
    }

    /// Returns the key size in bytes for this algorithm
    pub fn key_size(&self) -> usize {
        match self {
            SecretAlgorithm::AesGcm256 => 32, // 256 bits = 32 bytes
        }
    }

    /// Returns the nonce/IV size in bytes for this algorithm
    pub fn nonce_size(&self) -> usize {
        match self {
            SecretAlgorithm::AesGcm256 => 12, // 96 bits = 12 bytes (standard for GCM)
        }
    }

    /// Returns the authentication tag size in bytes
    pub fn tag_size(&self) -> usize {
        match self {
            SecretAlgorithm::AesGcm256 => 16, // 128 bits = 16 bytes
        }
    }
}

impl FromStr for SecretAlgorithm {
    type Err = CkError;

    fn from_str(s: &str) -> CkResult<Self> {
        match s {
            "AES-GCM-256" => Ok(SecretAlgorithm::AesGcm256),
            _ => Err(ValidationError::FieldWithParams {
                field: "secret_alg",
                code: "unsupported_algorithm",
                message: "Unsupported secret algorithm",
                params: vec![("value", s.to_string()), ("allowed", Self::all_names().join(", "))],
            }
            .into()),
        }
    }
}

impl std::fmt::Display for SecretAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl sqlx::Type<sqlx::Postgres> for SecretAlgorithm {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for SecretAlgorithm {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        self.as_str().encode_by_ref(buf)
    }
}

impl sqlx::Decode<'_, sqlx::Postgres> for SecretAlgorithm {
    fn decode(value: sqlx::postgres::PgValueRef<'_>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        SecretAlgorithm::from_str(&s).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_str() {
        assert_eq!(SecretAlgorithm::AesGcm256.as_str(), "AES-GCM-256");
    }

    #[test]
    fn test_all() {
        let algorithms = SecretAlgorithm::all();
        assert_eq!(algorithms.len(), 1);
        assert_eq!(algorithms[0], SecretAlgorithm::AesGcm256);
    }

    #[test]
    fn test_all_names() {
        let names = SecretAlgorithm::all_names();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "AES-GCM-256");
    }

    #[test]
    fn test_key_size() {
        assert_eq!(SecretAlgorithm::AesGcm256.key_size(), 32);
    }

    #[test]
    fn test_nonce_size() {
        assert_eq!(SecretAlgorithm::AesGcm256.nonce_size(), 12);
    }

    #[test]
    fn test_tag_size() {
        assert_eq!(SecretAlgorithm::AesGcm256.tag_size(), 16);
    }

    #[test]
    fn test_from_str_valid() {
        let result = SecretAlgorithm::from_str("AES-GCM-256");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SecretAlgorithm::AesGcm256);
    }

    #[test]
    fn test_from_str_invalid() {
        let result = SecretAlgorithm::from_str("INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_case_sensitive() {
        let result = SecretAlgorithm::from_str("aes-gcm-256");
        assert!(result.is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", SecretAlgorithm::AesGcm256), "AES-GCM-256");
    }

    #[test]
    fn test_clone() {
        let alg = SecretAlgorithm::AesGcm256;
        let cloned = alg;
        assert_eq!(alg, cloned);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SecretAlgorithm::AesGcm256);
        assert!(set.contains(&SecretAlgorithm::AesGcm256));
    }

    #[test]
    fn test_serde_serialize() {
        let alg = SecretAlgorithm::AesGcm256;
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, r#""AesGcm256""#);
    }

    #[test]
    fn test_serde_deserialize() {
        let json = r#""AesGcm256""#;
        let alg: SecretAlgorithm = serde_json::from_str(json).unwrap();
        assert_eq!(alg, SecretAlgorithm::AesGcm256);
    }

    #[test]
    fn test_serde_roundtrip() {
        let original = SecretAlgorithm::AesGcm256;
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: SecretAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }
}
