// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::global::short_id::ShortId;
use crate::manager::kek::KekEncAlgo;
use crate::manager::masterkey::MasterkeyId;
use crate::manager::namespace::NamespaceId;
use crate::manager::secret::encrypted_data::EncryptedData;
use crate::uuid_id;
use hierarkey_core::error::crypto::CryptoError;
use hierarkey_core::{CkError, CkResult};
use rand::TryRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEK_AAD: &str = "hierarkey:kek-wrap:v1";
pub const SIGNING_KEY_AAD: &str = "hierarkey:signing-key-wrap:v1";

pub const DEK_SIZE: usize = 32;
pub const TAG_SIZE: usize = 16;
pub const KEK_SIZE: usize = 32;
pub const SIGNING_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;

// ======= Data Encryption Key (DEK) =======

/// Encrypted DEK. Safe to copy/clone around.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedDek {
    /// Nonce used for encryption
    pub nonce: [u8; NONCE_SIZE],
    /// Actual ciphertext + tag (always a 256-bit DEK)
    pub ciphertext: [u8; DEK_SIZE],
    /// Authentication tag
    pub tag: [u8; TAG_SIZE],
}

impl EncryptedDek {
    pub fn new(nonce: [u8; NONCE_SIZE], ciphertext: [u8; DEK_SIZE], tag: [u8; TAG_SIZE]) -> Self {
        Self { nonce, ciphertext, tag }
    }

    pub fn from(dek_bytes: Vec<u8>) -> CkResult<Self> {
        if dek_bytes.len() != NONCE_SIZE + DEK_SIZE + TAG_SIZE {
            Err(CryptoError::InvalidEncryptedData {
                field: "dek_bytes",
                message: "Invalid dek_bytes length".into(),
            })?
        }

        // split nonce 12, ciphertext 32, tag 16
        let nonce: [u8; NONCE_SIZE] =
            dek_bytes[0..NONCE_SIZE]
                .try_into()
                .map_err(|_| CryptoError::InvalidEncryptedData {
                    field: "none",
                    message: "Invalid nonce".into(),
                })?;
        let ciphertext: [u8; DEK_SIZE] = dek_bytes[NONCE_SIZE..(NONCE_SIZE + DEK_SIZE)].try_into().map_err(|_| {
            CryptoError::InvalidEncryptedData {
                field: "ciphertext",
                message: "Invalid ciphertext".into(),
            }
        })?;
        let tag: [u8; TAG_SIZE] = dek_bytes[(NONCE_SIZE + DEK_SIZE)..(NONCE_SIZE + DEK_SIZE + TAG_SIZE)]
            .try_into()
            .map_err(|_| CryptoError::InvalidEncryptedData {
                field: "tag",
                message: "Invalid tag".into(),
            })?;

        let enc_dek = Self::new(nonce, ciphertext, tag);
        enc_dek.validate()?;

        Ok(enc_dek)
    }

    pub fn validate(&self) -> CkResult<()> {
        if self.nonce.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidEncryptedData {
                field: "nonce",
                message: "Nonce is all zeros".to_string(),
            }
            .into());
        }
        if self.ciphertext.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidEncryptedData {
                field: "ciphertext",
                message: "Ciphertext is all zeros".to_string(),
            }
            .into());
        }
        if self.tag.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidEncryptedData {
                field: "tag",
                message: "Tag is all zeros".to_string(),
            }
            .into());
        }
        Ok(())
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NONCE_SIZE + DEK_SIZE + TAG_SIZE);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&self.tag);
        bytes
    }
}

impl TryFrom<Vec<u8>> for EncryptedDek {
    type Error = CkError;

    fn try_from(value: Vec<u8>) -> CkResult<Self> {
        EncryptedDek::from(value)
    }
}

/// Unencrypted DEK. Sensitive, should be zeroized on drop.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Dek {
    pub inner: Zeroizing<[u8; DEK_SIZE]>,
}

impl Dek {
    pub fn generate() -> CkResult<Self> {
        let mut key_bytes = Zeroizing::new([0u8; DEK_SIZE]);
        rand::rng()
            .try_fill_bytes(&mut key_bytes[..])
            .map_err(|e| CryptoError::RandomnessFailure(anyhow::anyhow!(e)))?;

        // Ensure we don't have an all-zeros key
        if key_bytes.iter().all(|&b| b == 0) {
            // Try again
            rand::rng()
                .try_fill_bytes(&mut key_bytes[..])
                .map_err(|e| CryptoError::RandomnessFailure(anyhow::anyhow!(e)))?;
        }

        Ok(Dek { inner: key_bytes })
    }

    pub fn as_slice(&self) -> &[u8; DEK_SIZE] {
        &self.inner
    }

    pub fn from_bytes(bytes: &[u8; DEK_SIZE]) -> CkResult<Self> {
        // Validate the key is not all zeros
        if bytes.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidEncryptedData {
                field: "dek",
                message: "Key cannot be all zeros".to_string(),
            }
            .into());
        }

        let mut key_bytes = Zeroizing::new([0u8; DEK_SIZE]);
        key_bytes.copy_from_slice(bytes);
        Ok(Dek { inner: key_bytes })
    }

    pub fn is_zero(&self) -> bool {
        self.inner.iter().all(|&b| b == 0)
    }
}

impl Clone for Dek {
    fn clone(&self) -> Self {
        let mut key_bytes = Zeroizing::new([0u8; DEK_SIZE]);
        key_bytes.copy_from_slice(&self.inner[..]);
        Dek { inner: key_bytes }
    }
}

// ======= Key Encryption Key (KEK) =======

use crate::global::uuid_id::Identifier;
uuid_id!(KekId, "kek_");

#[derive(sqlx::FromRow, Debug, Clone, Serialize, Deserialize)]
/// Encrypted KEK. Safe to copy/clone around.
pub struct EncryptedKek {
    /// Unique ID of the KEK
    pub id: KekId,
    /// Short human-friendly ID
    pub short_id: ShortId,
    /// Encryption algorithm used
    #[sqlx(try_from = "String", rename = "algorithm")]
    pub algo: KekEncAlgo,
    /// Actual encrypted data (+ nonce + tag)
    #[sqlx(try_from = "Vec<u8>")]
    pub ciphertext: EncryptedData,
    /// Master key used for encryption
    pub masterkey_id: MasterkeyId,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last rotation timestamp
    pub last_rotated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Scheduled rotation time
    pub rotate_by: Option<chrono::DateTime<chrono::Utc>>,
    /// Number of times this KEK has been rotated
    #[sqlx(try_from = "i32")]
    pub rotation_count: usize,
}

impl EncryptedKek {
    pub fn generate_aad(algo: KekEncAlgo, masterkey_id: MasterkeyId, namespace_id: NamespaceId) -> String {
        format!("{}|{}|{}|{}", KEK_AAD, algo.as_str(), masterkey_id, namespace_id,).to_string()
    }

    pub fn validate(&self) -> CkResult<()> {
        if self.ciphertext.nonce()?.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidEncryptedData {
                field: "nonce",
                message: "Nonce cannot be all zeros".to_string(),
            }
            .into());
        }
        if self.ciphertext.ciphertext()?.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidEncryptedData {
                field: "ciphertext",
                message: "Ciphertext cannot be all zeros".to_string(),
            }
            .into());
        }
        Ok(())
    }

    pub fn is_rotated(&self) -> bool {
        self.last_rotated_at.is_some()
    }

    pub fn needs_rotation(&self) -> bool {
        if let Some(rotate_by) = self.rotate_by {
            chrono::Utc::now() >= rotate_by
        } else {
            false
        }
    }

    pub fn mark_rotated(&mut self) {
        self.last_rotated_at = Some(chrono::Utc::now());
        self.rotation_count += 1;
    }
}

/// Unencrypted KEK. Sensitive, should be zeroized on drop.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Kek {
    pub inner: Zeroizing<[u8; KEK_SIZE]>,
}

impl Kek {
    pub fn generate() -> CkResult<Self> {
        let mut key_bytes = Zeroizing::new([0u8; KEK_SIZE]);
        rand::rng()
            .try_fill_bytes(&mut key_bytes[..])
            .map_err(|e| CryptoError::RandomnessFailure(anyhow::anyhow!(e)))?;

        // Ensure we don't have an all-zeros key
        if key_bytes.iter().all(|&b| b == 0) {
            // Try again
            rand::rng()
                .try_fill_bytes(&mut key_bytes[..])
                .map_err(|e| CryptoError::RandomnessFailure(anyhow::anyhow!(e)))?;
        }

        Ok(Kek { inner: key_bytes })
    }

    // pub fn as_slice(&self) -> &[u8; KEK_SIZE] {
    //     &self.inner
    // }
    pub fn as_bytes(&self) -> &[u8; KEK_SIZE] {
        &self.inner
    }

    pub fn from_bytes(bytes: &[u8; KEK_SIZE]) -> CkResult<Self> {
        // Validate the key is not all zeros
        if bytes.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidEncryptedData {
                field: "key",
                message: "Key cannot be all zeros".to_string(),
            }
            .into());
        }

        let mut key_bytes = Zeroizing::new([0u8; KEK_SIZE]);
        key_bytes.copy_from_slice(bytes);
        Ok(Kek { inner: key_bytes })
    }

    pub fn is_zero(&self) -> bool {
        self.inner.iter().all(|&b| b == 0)
    }
}

impl Clone for Kek {
    fn clone(&self) -> Self {
        let mut key_bytes = Zeroizing::new([0u8; KEK_SIZE]);
        key_bytes.copy_from_slice(&self.inner[..]);
        Kek { inner: key_bytes }
    }
}

// ======= Row Integrity Signing Key =======

uuid_id!(SigningKeyId, "sk_");

#[derive(sqlx::FromRow, Debug, Clone, Serialize, Deserialize)]
/// Encrypted signing key as stored in the database. Safe to copy/clone around.
pub struct EncryptedSigningKey {
    /// Unique ID of the signing key
    pub id: SigningKeyId,
    /// Short human-friendly ID
    pub short_id: ShortId,
    /// Wrapping algorithm (always AES-GCM-256 for now)
    #[sqlx(try_from = "String", rename = "algorithm")]
    pub algo: KekEncAlgo,
    /// Encrypted 32-byte key material: nonce (12) || ciphertext (32) || tag (16)
    #[sqlx(try_from = "Vec<u8>")]
    pub ciphertext: EncryptedData,
    /// Master key that wrapped this signing key
    pub masterkey_id: MasterkeyId,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl EncryptedSigningKey {
    /// Build the Additional Authenticated Data string used during wrap/unwrap.
    /// Includes the signing key's own ID to bind the ciphertext to this specific row.
    pub fn generate_aad(algo: KekEncAlgo, masterkey_id: MasterkeyId, signing_key_id: SigningKeyId) -> String {
        format!("{}|{}|{}|{}", SIGNING_KEY_AAD, algo.as_str(), masterkey_id, signing_key_id)
    }

    pub fn validate(&self) -> CkResult<()> {
        if self.ciphertext.nonce()?.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidEncryptedData {
                field: "nonce",
                message: "Nonce cannot be all zeros".to_string(),
            }
            .into());
        }
        if self.ciphertext.ciphertext()?.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidEncryptedData {
                field: "ciphertext",
                message: "Ciphertext cannot be all zeros".to_string(),
            }
            .into());
        }
        Ok(())
    }
}

/// Plaintext signing key held in memory after the master key is unlocked.
/// Sensitive — zeroed on drop.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey {
    pub inner: Zeroizing<[u8; SIGNING_KEY_SIZE]>,
}

impl SigningKey {
    pub fn generate() -> CkResult<Self> {
        let mut key_bytes = Zeroizing::new([0u8; SIGNING_KEY_SIZE]);
        rand::rng()
            .try_fill_bytes(&mut key_bytes[..])
            .map_err(|e| CryptoError::RandomnessFailure(anyhow::anyhow!(e)))?;

        if key_bytes.iter().all(|&b| b == 0) {
            // Astronomically unlikely, but try once more to be safe
            rand::rng()
                .try_fill_bytes(&mut key_bytes[..])
                .map_err(|e| CryptoError::RandomnessFailure(anyhow::anyhow!(e)))?;
        }

        Ok(SigningKey { inner: key_bytes })
    }

    pub fn as_bytes(&self) -> &[u8; SIGNING_KEY_SIZE] {
        &self.inner
    }

    pub fn from_bytes(bytes: &[u8; SIGNING_KEY_SIZE]) -> CkResult<Self> {
        if bytes.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidEncryptedData {
                field: "signing_key",
                message: "Key cannot be all zeros".to_string(),
            }
            .into());
        }

        let mut key_bytes = Zeroizing::new([0u8; SIGNING_KEY_SIZE]);
        key_bytes.copy_from_slice(bytes);
        Ok(SigningKey { inner: key_bytes })
    }

    pub fn is_zero(&self) -> bool {
        self.inner.iter().all(|&b| b == 0)
    }
}

impl Clone for SigningKey {
    fn clone(&self) -> Self {
        let mut key_bytes = Zeroizing::new([0u8; SIGNING_KEY_SIZE]);
        key_bytes.copy_from_slice(&self.inner[..]);
        SigningKey { inner: key_bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hierarkey_core::Metadata;

    fn get_enc_kek() -> EncryptedKek {
        let mut metadata = Metadata::new();
        metadata.insert("test-key", "test-value");
        metadata.add_description("Test EncryptedKek");
        metadata.add_label("foo", "bar");

        let masterkey_id = MasterkeyId::new();

        EncryptedKek {
            id: KekId::new(),
            short_id: ShortId::generate("kek_", 12),
            algo: KekEncAlgo::Aes256Gcm,
            ciphertext: EncryptedData::new(&[1u8; 12], &[2u8; 32], &[3u8; 16]),
            masterkey_id,
            created_at: chrono::Utc::now(),

            last_rotated_at: None,
            rotate_by: None,
            rotation_count: 0,
        }
    }

    #[test]
    fn test_dek_generate() {
        let dek = Dek::generate().unwrap();
        assert!(!dek.is_zero());
        assert_eq!(dek.as_slice().len(), DEK_SIZE);
    }

    #[test]
    fn test_dek_from_bytes() {
        let bytes = [42u8; DEK_SIZE];
        let dek = Dek::from_bytes(&bytes).unwrap();
        assert_eq!(dek.as_slice(), &bytes);
    }

    #[test]
    fn test_dek_from_bytes_rejects_zeros() {
        let bytes = [0u8; DEK_SIZE];
        let result = Dek::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_dek_clone() {
        let dek1 = Dek::generate().unwrap();
        let dek2 = dek1.clone();
        assert_eq!(dek1.as_slice(), dek2.as_slice());
    }

    #[test]
    fn test_dek_is_zero() {
        let mut bytes = Zeroizing::new([0u8; DEK_SIZE]);
        rand::rng().try_fill_bytes(&mut bytes[..]).unwrap();
        let dek = Dek { inner: bytes };
        assert!(!dek.is_zero());
    }

    #[test]
    fn test_kek_generate() {
        let kek = Kek::generate().unwrap();
        assert!(!kek.is_zero());
        assert_eq!(kek.as_bytes().len(), KEK_SIZE);
    }

    #[test]
    fn test_kek_from_bytes() {
        let bytes = [42u8; KEK_SIZE];
        let kek = Kek::from_bytes(&bytes).unwrap();
        assert_eq!(kek.as_bytes(), &bytes);
    }

    #[test]
    fn test_kek_from_bytes_rejects_zeros() {
        let bytes = [0u8; KEK_SIZE];
        let result = Kek::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_kek_clone() {
        let kek1 = Kek::generate().unwrap();
        let kek2 = kek1.clone();
        assert_eq!(kek1.as_bytes(), kek2.as_bytes());
    }

    #[test]
    fn test_encrypted_dek_new() {
        let nonce = [1u8; NONCE_SIZE];
        let ciphertext = [2u8; DEK_SIZE];
        let tag = [3u8; TAG_SIZE];

        let enc_dek = EncryptedDek::new(nonce, ciphertext, tag);

        assert_eq!(enc_dek.nonce, nonce);
        assert_eq!(enc_dek.ciphertext, ciphertext);
        assert_eq!(enc_dek.tag, tag);
    }

    #[test]
    fn test_encrypted_dek_validate() {
        let nonce = [1u8; NONCE_SIZE];
        let ciphertext = [2u8; DEK_SIZE];
        let tag = [3u8; TAG_SIZE];

        let enc_dek = EncryptedDek::new(nonce, ciphertext, tag);
        assert!(enc_dek.validate().is_ok());
    }

    #[test]
    fn test_encrypted_dek_validate_zero_nonce() {
        let nonce = [0u8; NONCE_SIZE];
        let ciphertext = [2u8; DEK_SIZE];
        let tag = [3u8; TAG_SIZE];

        let enc_dek = EncryptedDek::new(nonce, ciphertext, tag);
        assert!(enc_dek.validate().is_err());
    }

    #[test]
    fn test_encrypted_dek_validate_zero_ciphertext() {
        let nonce = [1u8; NONCE_SIZE];
        let ciphertext = [0u8; DEK_SIZE];
        let tag = [3u8; TAG_SIZE];

        let enc_dek = EncryptedDek::new(nonce, ciphertext, tag);
        assert!(enc_dek.validate().is_err());
    }

    #[test]
    fn test_encrypted_dek_validate_zero_tag() {
        let nonce = [1u8; NONCE_SIZE];
        let ciphertext = [2u8; DEK_SIZE];
        let tag = [0u8; TAG_SIZE];

        let enc_dek = EncryptedDek::new(nonce, ciphertext, tag);
        assert!(enc_dek.validate().is_err());
    }

    #[test]
    fn test_encrypted_dek_serialization() {
        let nonce = [1u8; NONCE_SIZE];
        let ciphertext = [2u8; DEK_SIZE];
        let tag = [3u8; TAG_SIZE];

        let enc_dek = EncryptedDek::new(nonce, ciphertext, tag);

        let json = serde_json::to_string(&enc_dek).unwrap();
        let deserialized: EncryptedDek = serde_json::from_str(&json).unwrap();

        assert_eq!(enc_dek.nonce, deserialized.nonce);
        assert_eq!(enc_dek.ciphertext, deserialized.ciphertext);
        assert_eq!(enc_dek.tag, deserialized.tag);
    }

    #[test]
    fn test_encrypted_kek_is_rotated() {
        let mut enc_kek = get_enc_kek();
        assert!(!enc_kek.is_rotated());

        enc_kek.last_rotated_at = Some(chrono::Utc::now());
        assert!(enc_kek.is_rotated());
    }

    #[test]
    fn test_encrypted_kek_serialization() {
        let enc_kek = get_enc_kek();

        let json = serde_json::to_string(&enc_kek).unwrap();
        let deserialized: EncryptedKek = serde_json::from_str(&json).unwrap();

        assert_eq!(enc_kek.id, deserialized.id);
        assert_eq!(enc_kek.ciphertext, deserialized.ciphertext);
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEK_SIZE, 32);
        assert_eq!(KEK_SIZE, 32);
        assert_eq!(NONCE_SIZE, 12);
    }
}
