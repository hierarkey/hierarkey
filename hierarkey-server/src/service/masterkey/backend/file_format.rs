// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64_standard;
use hierarkey_core::{CkError, CkResult};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::error;
use zeroize::Zeroizing;

#[cfg(test)]
use crate::global::short_id::ShortId;
use crate::manager::masterkey::{MasterKey, MasterKeyData};

pub const INSECURE_FILE_VERSION: u32 = 1;
pub const PASSPHRASE_FILE_VERSION: u32 = 1;

/// A discriminator for what payload type we expect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilePayloadKind {
    Insecure,
    Passphrase,
}

impl FilePayloadKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            FilePayloadKind::Insecure => "insecure",
            FilePayloadKind::Passphrase => "passphrase",
        }
    }
}

// ------------------------------------------------------------------------------------------
fn serialize_zeroizing_string<S>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.as_str())
}

fn deserialize_zeroizing_string<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Zeroizing::new(s))
}

// ------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2IdParams {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "algorithm", content = "params")]
pub enum KdfParams {
    #[serde(rename = "argon2id")]
    Argon2Id(Argon2IdParams),
}

impl KdfParams {
    /// A stable string used for checksum input
    pub fn fingerprint(&self) -> String {
        match self {
            KdfParams::Argon2Id(p) => format!("argon2id:m={};t={};p={}", p.memory_cost, p.time_cost, p.parallelism),
        }
    }
}

// ------------------------------------------------------------------------------------------
// File payloads (on disk)

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FilePayload {
    #[serde(rename = "insecure")]
    Insecure {
        #[allow(unused)]
        created_at: chrono::DateTime<chrono::Utc>,
        #[serde(
            deserialize_with = "deserialize_zeroizing_string",
            serialize_with = "serialize_zeroizing_string"
        )]
        key: Zeroizing<String>,
        version: u32,
    },

    #[serde(rename = "passphrase")]
    Passphrase {
        #[allow(unused)]
        created_at: chrono::DateTime<chrono::Utc>,
        kdf_params: KdfParams,
        // base64 of: salt(16) + nonce(12) + tag(16) + ciphertext(32)
        #[serde(
            deserialize_with = "deserialize_zeroizing_string",
            serialize_with = "serialize_zeroizing_string"
        )]
        b64_enc_key_data: Zeroizing<String>,
        version: u32,
    },
}

impl FilePayload {
    pub fn kind(&self) -> FilePayloadKind {
        match self {
            FilePayload::Insecure { .. } => FilePayloadKind::Insecure,
            FilePayload::Passphrase { .. } => FilePayloadKind::Passphrase,
        }
    }

    // pub fn version(&self) -> u32 {
    //     match self {
    //         FilePayload::Insecure { version, .. } => *version,
    //         FilePayload::Passphrase { version, .. } => *version,
    //     }
    // }
}

// ------------------------------------------------------------------------------------------
// Parsing + validation

/// Parse JSON file contents into a FilePayload enum.
pub fn parse_payload(raw_json: &str) -> CkResult<FilePayload> {
    let payload: FilePayload = serde_json::from_str(raw_json)?;
    Ok(payload)
}

/// Validate that payload matches expected kind and supported version.
pub fn validate_payload(payload: &FilePayload, expected: FilePayloadKind) -> CkResult<()> {
    let kind = payload.kind();
    if kind != expected {
        error!("invalid master key type in file: {}", kind.as_str());
        return Err(CkError::MasterKey("invalid master key type in file".into()));
    }

    match payload {
        FilePayload::Insecure { version, .. } => {
            if *version != INSECURE_FILE_VERSION {
                error!("unsupported insecure master key version in file: {}", version);
                return Err(CkError::MasterKey("unsupported insecure master key version in file".into()));
            }
        }
        FilePayload::Passphrase { version, .. } => {
            if *version != PASSPHRASE_FILE_VERSION {
                error!("unsupported passphrase master key version in file: {}", version);
                return Err(CkError::MasterKey("unsupported passphrase master key version in file".into()));
            }
        }
    }

    Ok(())
}

// ------------------------------------------------------------------------------------------
// Checksums

/// Create a "content checksum" for the on-disk payload.
pub fn create_content_checksum(payload: &FilePayload) -> String {
    // Hash the "secret-ish" blob and use only its hash as input to the canonical checksum.
    let data_hash = match payload {
        FilePayload::Insecure { key, .. } => sha256_hex(key.as_bytes()),
        FilePayload::Passphrase { b64_enc_key_data, .. } => sha256_hex(b64_enc_key_data.as_bytes()),
    };

    let mut hasher = Sha256::new();
    hasher.update(b"hkey_file:v1\0");

    match payload {
        FilePayload::Insecure {
            created_at, version, ..
        } => {
            hasher.update(created_at.to_rfc3339().as_bytes());
            hasher.update(b"\0");
            hasher.update(b"insecure");
            hasher.update(b"\0");
            hasher.update(version.to_string().as_bytes());
            hasher.update(b"\0");
            hasher.update(data_hash.as_bytes());
        }

        FilePayload::Passphrase {
            created_at,
            kdf_params,
            version,
            ..
        } => {
            hasher.update(created_at.to_rfc3339().as_bytes());
            hasher.update(b"\0");
            hasher.update(b"passphrase");
            hasher.update(b"\0");
            hasher.update(version.to_string().as_bytes());
            hasher.update(b"\0");
            hasher.update(kdf_params.fingerprint().as_bytes());
            hasher.update(b"\0");

            hasher.update(data_hash.as_bytes());
        }
    }

    hex::encode(hasher.finalize())
}

/// Create the master key checksum that ties file payload to MK and MKV.
pub fn create_masterkey_checksum(
    master_key: &MasterKey,
    content_checksum: &str,
    payload_kind: FilePayloadKind,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content_checksum.as_bytes());
    hasher.update(b"\0");
    hasher.update(master_key.id.as_bytes());
    hasher.update(b"\0");
    hasher.update(b"file");
    hasher.update(b"\0");
    hasher.update(payload_kind.as_str().as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time compare of stored checksum vs calculated checksum.
pub fn checksum_matches(calculated_hex: &str, stored_hex: &str) -> bool {
    calculated_hex.as_bytes().ct_eq(stored_hex.as_bytes()).into()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

// ------------------------------------------------------------------------------------------
// Payload helpers for providers

/// Decode base64 key material from an insecure payload.
pub fn decode_insecure_key(payload: &FilePayload) -> CkResult<MasterKeyData> {
    let FilePayload::Insecure { key, .. } = payload else {
        return Err(CkError::MasterKey("expected insecure payload".into()));
    };

    decode_b64_key_32(key.as_str())
}

/// Extract passphrase parameters + encrypted blob from a passphrase payload.
pub fn extract_passphrase_material(payload: &FilePayload) -> CkResult<(KdfParams, Zeroizing<String>)> {
    let FilePayload::Passphrase {
        kdf_params,
        b64_enc_key_data,
        ..
    } = payload
    else {
        return Err(CkError::MasterKey("expected passphrase payload".into()));
    };

    Ok((kdf_params.clone(), b64_enc_key_data.clone()))
}

fn decode_b64_key_32(b64: &str) -> CkResult<MasterKeyData> {
    let mut key_bytes = Zeroizing::new([0u8; 32]);

    // base64 of 32 bytes typically encodes to 44 chars (with padding)
    let decoded_len = base64_standard.decode_slice(b64, &mut *key_bytes).map_err(|e| {
        error!("failed to decode base64 master key: {}", e);
        CkError::MasterKey("failed to decode base64 master key".into())
    })?;

    if decoded_len != 32 {
        error!("invalid master key length after decoding: {}", decoded_len);
        return Err(CkError::MasterKey("invalid master key length after decoding".into()));
    }

    Ok(MasterKeyData::from(key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::masterkey::{MasterKeyBackend, MasterKeyStatus, MasterKeyUsage, MasterkeyId};
    use hierarkey_core::Metadata;

    fn make_passphrase_payload() -> FilePayload {
        FilePayload::Passphrase {
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            kdf_params: KdfParams::Argon2Id(Argon2IdParams {
                memory_cost: 65536,
                time_cost: 3,
                parallelism: 1,
            }),
            b64_enc_key_data: Zeroizing::new("dGVzdC1ibG9i".into()),
            version: PASSPHRASE_FILE_VERSION,
        }
    }

    fn make_insecure_payload() -> FilePayload {
        let key_b64 = base64_standard.encode([0u8; 32]);
        FilePayload::Insecure {
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            key: Zeroizing::new(key_b64),
            version: INSECURE_FILE_VERSION,
        }
    }

    fn make_test_masterkey() -> MasterKey {
        MasterKey {
            id: MasterkeyId::new(),
            short_id: ShortId::generate("mk_", 12),
            name: "test-key".into(),
            usage: MasterKeyUsage::WrapKek,
            status: MasterKeyStatus::Active,
            backend: MasterKeyBackend::File,
            file_type: None,
            file_path: None,
            file_sha256: None,
            pkcs11_ref: None,
            metadata: Metadata::new(),
            created_at: chrono::Utc::now(),
            created_by: None,
            updated_at: None,
            updated_by: None,
            retired_at: None,
            retired_by: None,
        }
    }

    #[test]
    fn parse_payload_valid_passphrase_json() {
        let json = r#"{
            "type": "passphrase",
            "created_at": "1970-01-01T00:00:00Z",
            "kdf_params": {"algorithm": "argon2id", "params": {"memory_cost": 65536, "time_cost": 3, "parallelism": 1}},
            "b64_enc_key_data": "dGVzdA==",
            "version": 1
        }"#;
        let payload = parse_payload(json).unwrap();
        assert_eq!(payload.kind(), FilePayloadKind::Passphrase);
    }

    #[test]
    fn parse_payload_valid_insecure_json() {
        let key_b64 = base64_standard.encode([0u8; 32]);
        let json =
            format!(r#"{{"type":"insecure","created_at":"1970-01-01T00:00:00Z","key":"{key_b64}","version":1}}"#);
        let payload = parse_payload(&json).unwrap();
        assert_eq!(payload.kind(), FilePayloadKind::Insecure);
    }

    #[test]
    fn parse_payload_invalid_json_fails() {
        assert!(parse_payload("not json at all").is_err());
    }

    #[test]
    fn parse_payload_unknown_type_fails() {
        let json = r#"{"type":"unknown","created_at":"1970-01-01T00:00:00Z","version":1}"#;
        assert!(parse_payload(json).is_err());
    }

    #[test]
    fn validate_payload_correct_passphrase_kind_passes() {
        let payload = make_passphrase_payload();
        assert!(validate_payload(&payload, FilePayloadKind::Passphrase).is_ok());
    }

    #[test]
    fn validate_payload_correct_insecure_kind_passes() {
        let payload = make_insecure_payload();
        assert!(validate_payload(&payload, FilePayloadKind::Insecure).is_ok());
    }

    #[test]
    fn validate_payload_wrong_kind_fails() {
        let payload = make_passphrase_payload();
        assert!(validate_payload(&payload, FilePayloadKind::Insecure).is_err());
    }

    #[test]
    fn validate_payload_wrong_version_fails() {
        let mut payload = make_passphrase_payload();
        if let FilePayload::Passphrase { ref mut version, .. } = payload {
            *version = 999;
        }
        assert!(validate_payload(&payload, FilePayloadKind::Passphrase).is_err());
    }

    #[test]
    fn create_content_checksum_is_deterministic() {
        let payload = make_passphrase_payload();
        let c1 = create_content_checksum(&payload);
        let c2 = create_content_checksum(&payload);
        assert_eq!(c1, c2);
    }

    #[test]
    fn create_content_checksum_differs_for_different_payloads() {
        let p1 = make_passphrase_payload();
        let p2 = make_insecure_payload();
        assert_ne!(create_content_checksum(&p1), create_content_checksum(&p2));
    }

    #[test]
    fn create_content_checksum_changes_when_blob_changes() {
        let mut p1 = make_passphrase_payload();
        let mut p2 = make_passphrase_payload();
        if let FilePayload::Passphrase {
            ref mut b64_enc_key_data,
            ..
        } = p1
        {
            *b64_enc_key_data = Zeroizing::new("blob-a".into());
        }
        if let FilePayload::Passphrase {
            ref mut b64_enc_key_data,
            ..
        } = p2
        {
            *b64_enc_key_data = Zeroizing::new("blob-b".into());
        }
        assert_ne!(create_content_checksum(&p1), create_content_checksum(&p2));
    }

    #[test]
    fn create_masterkey_checksum_is_deterministic() {
        let mk = make_test_masterkey();
        let c1 = create_masterkey_checksum(&mk, "content-hash", FilePayloadKind::Passphrase);
        let c2 = create_masterkey_checksum(&mk, "content-hash", FilePayloadKind::Passphrase);
        assert_eq!(c1, c2);
    }

    #[test]
    fn create_masterkey_checksum_differs_for_different_master_keys() {
        let mk1 = make_test_masterkey();
        let mk2 = make_test_masterkey();
        let c1 = create_masterkey_checksum(&mk1, "content", FilePayloadKind::Passphrase);
        let c2 = create_masterkey_checksum(&mk2, "content", FilePayloadKind::Passphrase);
        // Different MasterKey IDs (UUIDs) must produce different checksums
        assert_ne!(c1, c2);
    }

    #[test]
    fn create_masterkey_checksum_differs_for_different_payload_kinds() {
        let mk = make_test_masterkey();
        let c_pass = create_masterkey_checksum(&mk, "content", FilePayloadKind::Passphrase);
        let c_ins = create_masterkey_checksum(&mk, "content", FilePayloadKind::Insecure);
        assert_ne!(c_pass, c_ins);
    }

    #[test]
    fn checksum_matches_equal_strings() {
        assert!(checksum_matches("abcdef1234", "abcdef1234"));
    }

    #[test]
    fn checksum_matches_different_strings() {
        assert!(!checksum_matches("abcdef1234", "000000000000"));
    }

    #[test]
    fn checksum_matches_empty_strings() {
        assert!(checksum_matches("", ""));
    }

    #[test]
    fn extract_passphrase_material_from_passphrase_payload() {
        let payload = make_passphrase_payload();
        let result = extract_passphrase_material(&payload);
        assert!(result.is_ok());
        let (kdf, blob) = result.unwrap();
        let KdfParams::Argon2Id(p) = kdf;
        assert_eq!(p.memory_cost, 65536);
        assert_eq!(blob.as_str(), "dGVzdC1ibG9i");
    }

    #[test]
    fn extract_passphrase_material_from_insecure_payload_fails() {
        let payload = make_insecure_payload();
        assert!(extract_passphrase_material(&payload).is_err());
    }

    #[test]
    fn decode_insecure_key_from_insecure_payload() {
        let expected = [0xABu8; 32];
        let key_b64 = base64_standard.encode(expected);
        let payload = FilePayload::Insecure {
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            key: Zeroizing::new(key_b64),
            version: INSECURE_FILE_VERSION,
        };
        let result = decode_insecure_key(&payload).unwrap();
        assert_eq!(result.as_bytes(), &expected);
    }

    #[test]
    fn decode_insecure_key_from_passphrase_payload_fails() {
        let payload = make_passphrase_payload();
        assert!(decode_insecure_key(&payload).is_err());
    }
}
