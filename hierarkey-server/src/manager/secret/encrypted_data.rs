// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::global::keys::{NONCE_SIZE, TAG_SIZE};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64_standard;
use hierarkey_core::error::crypto::CryptoError;
use hierarkey_core::error::validation::ValidationError;
use hierarkey_core::{CkError, CkResult};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Structure that holds encrypted data. This structure contains the nonce, ciphertext and tag.
#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedData {
    inner: Vec<u8>,
}

impl EncryptedData {
    /// Minimum size: nonce + tag (no ciphertext)
    pub const MIN_SIZE: usize = NONCE_SIZE + TAG_SIZE;

    /// Creates an EncryptedData from a byte vector
    pub fn from(data: Vec<u8>) -> CkResult<Self> {
        if data.len() < Self::MIN_SIZE {
            return Err(CryptoError::InvalidEncryptedData {
                field: "data",
                message: format!(
                    "Invalid data length: expected at least {} bytes, got {}",
                    Self::MIN_SIZE,
                    data.len()
                ),
            }
            .into());
        }
        Ok(Self { inner: data })
    }

    /// Creates an EncryptedData by combining nonce, ciphertext, and tag
    pub fn new(nonce: &[u8; NONCE_SIZE], ciphertext: &[u8], tag: &[u8; TAG_SIZE]) -> Self {
        let mut data = Vec::with_capacity(NONCE_SIZE + ciphertext.len() + TAG_SIZE);
        data.extend_from_slice(nonce);
        data.extend_from_slice(ciphertext);
        data.extend_from_slice(tag);
        Self { inner: data }
    }

    /// Returns the entire encrypted data as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Returns the length of the entire encrypted data
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the encrypted data is empty (should never happen with valid data)
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the ciphertext length (excluding nonce and tag)
    pub fn ciphertext_len(&self) -> usize {
        self.inner.len().saturating_sub(Self::MIN_SIZE)
    }

    /// Extracts the nonce from the encrypted data
    pub fn nonce(&self) -> Result<&[u8; NONCE_SIZE], CkError> {
        self.inner
            .get(..NONCE_SIZE)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| {
                CryptoError::InvalidEncryptedData {
                    field: "nonce",
                    message: "Invalid nonce size".into(),
                }
                .into()
            })
    }

    /// Extracts the authentication tag from the encrypted data
    pub fn tag(&self) -> Result<&[u8; TAG_SIZE], CkError> {
        if self.inner.len() < TAG_SIZE {
            return Err(CryptoError::InvalidEncryptedData {
                field: "tag",
                message: "Invalid tag size".into(),
            }
            .into());
        }

        self.inner[self.inner.len() - TAG_SIZE..].try_into().map_err(|_| {
            CryptoError::InvalidEncryptedData {
                field: "tag",
                message: "Invalid tag size".into(),
            }
            .into()
        })
    }

    /// Extracts the ciphertext from the encrypted data
    pub fn ciphertext(&self) -> Result<&[u8], CkError> {
        if self.inner.len() < Self::MIN_SIZE {
            return Err(CryptoError::InvalidEncryptedData {
                field: "ciphertext",
                message: format!(
                    "Encrypted data too short: expected at least {} bytes, got {}",
                    Self::MIN_SIZE,
                    self.inner.len()
                ),
            }
            .into());
        }

        Ok(&self.inner[NONCE_SIZE..self.inner.len() - TAG_SIZE])
    }

    /// Extracts the combined ciphertext and tag from the encrypted data
    pub fn ciphertext_and_tag(&self) -> Result<&[u8], CkError> {
        if self.inner.len() < Self::MIN_SIZE {
            return Err(CryptoError::InvalidEncryptedData {
                field: "ciphertext_and_tag",
                message: format!(
                    "Encrypted data too short: expected at least {} bytes, got {}",
                    Self::MIN_SIZE,
                    self.inner.len()
                ),
            }
            .into());
        }

        Ok(&self.inner[NONCE_SIZE..])
    }

    /// Deconstructs the EncryptedData into its components
    #[allow(clippy::type_complexity)]
    pub fn into_parts(self) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), CkError> {
        if self.inner.len() < Self::MIN_SIZE {
            return Err(CryptoError::InvalidEncryptedData {
                field: "data",
                message: "Encrypted data too short".into(),
            }
            .into());
        }

        let nonce = self.inner[..NONCE_SIZE].to_vec();
        let ciphertext = self.inner[NONCE_SIZE..self.inner.len() - TAG_SIZE].to_vec();
        let tag = self.inner[self.inner.len() - TAG_SIZE..].to_vec();

        Ok((nonce, ciphertext, tag))
    }

    /// Converts the encrypted data to base64
    pub fn to_base64(&self) -> String {
        base64_standard.encode(&self.inner)
    }

    /// Creates EncryptedData from a base64 string
    pub fn from_base64(b64_str: &str) -> CkResult<Self> {
        let decoded = base64_standard.decode(b64_str).map_err(|_| ValidationError::Field {
            field: "encrypted_data",
            code: "invalid_base64",
            message: "Invalid base64 encoding".into(),
        })?;
        Self::from(decoded)
    }

    /// Validates the structure without extracting components
    pub fn validate(&self) -> CkResult<()> {
        if self.inner.len() < Self::MIN_SIZE {
            return Err(CryptoError::InvalidEncryptedData {
                field: "data",
                message: format!(
                    "Invalid data length: expected at least {} bytes, got {}",
                    Self::MIN_SIZE,
                    self.inner.len()
                ),
            }
            .into());
        }
        Ok(())
    }
}

impl From<EncryptedData> for Vec<u8> {
    fn from(data: EncryptedData) -> Self {
        data.inner.clone()
    }
}

impl AsRef<[u8]> for EncryptedData {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl TryFrom<Vec<u8>> for EncryptedData {
    type Error = CkError;

    fn try_from(data: Vec<u8>) -> CkResult<Self> {
        Self::from(data)
    }
}

impl TryFrom<&[u8]> for EncryptedData {
    type Error = CkError;

    fn try_from(data: &[u8]) -> CkResult<Self> {
        Self::from(data.to_vec())
    }
}

impl Serialize for EncryptedData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for EncryptedData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_base64(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NONCE: [u8; NONCE_SIZE] = [1u8; NONCE_SIZE];
    const TEST_TAG: [u8; TAG_SIZE] = [2u8; TAG_SIZE];
    const TEST_CIPHERTEXT: &[u8] = &[3, 4, 5, 6, 7];

    fn create_test_data() -> EncryptedData {
        EncryptedData::new(&TEST_NONCE, TEST_CIPHERTEXT, &TEST_TAG)
    }

    #[test]
    fn test_new() {
        let data = create_test_data();
        assert_eq!(data.len(), NONCE_SIZE + TEST_CIPHERTEXT.len() + TAG_SIZE);
    }

    #[test]
    fn test_from_valid() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TEST_NONCE);
        bytes.extend_from_slice(TEST_CIPHERTEXT);
        bytes.extend_from_slice(&TEST_TAG);

        let result = EncryptedData::from(bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_too_short() {
        let bytes = vec![1, 2, 3];
        let result = EncryptedData::from(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_minimum_size() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TEST_NONCE);
        bytes.extend_from_slice(&TEST_TAG);

        let result = EncryptedData::from(bytes);
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.ciphertext_len(), 0);
    }

    #[test]
    fn test_as_bytes() {
        let data = create_test_data();
        let bytes = data.as_bytes();
        assert_eq!(bytes.len(), NONCE_SIZE + TEST_CIPHERTEXT.len() + TAG_SIZE);
    }

    #[test]
    fn test_len() {
        let data = create_test_data();
        assert_eq!(data.len(), NONCE_SIZE + TEST_CIPHERTEXT.len() + TAG_SIZE);
    }

    #[test]
    fn test_is_empty() {
        let data = create_test_data();
        assert!(!data.is_empty());
    }

    #[test]
    fn test_ciphertext_len() {
        let data = create_test_data();
        assert_eq!(data.ciphertext_len(), TEST_CIPHERTEXT.len());
    }

    #[test]
    fn test_ciphertext_len_minimum() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TEST_NONCE);
        bytes.extend_from_slice(&TEST_TAG);
        let data = EncryptedData::from(bytes).unwrap();
        assert_eq!(data.ciphertext_len(), 0);
    }

    #[test]
    fn test_nonce() {
        let data = create_test_data();
        let nonce = data.nonce().unwrap();
        assert_eq!(nonce, &TEST_NONCE);
    }

    #[test]
    fn test_tag() {
        let data = create_test_data();
        let tag = data.tag().unwrap();
        assert_eq!(tag, &TEST_TAG);
    }

    #[test]
    fn test_ciphertext() {
        let data = create_test_data();
        let ciphertext = data.ciphertext().unwrap();
        assert_eq!(ciphertext, TEST_CIPHERTEXT);
    }

    #[test]
    fn test_ciphertext_empty() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TEST_NONCE);
        bytes.extend_from_slice(&TEST_TAG);
        let data = EncryptedData::from(bytes).unwrap();
        let ciphertext = data.ciphertext().unwrap();
        assert_eq!(ciphertext.len(), 0);
    }

    #[test]
    fn test_into_parts() {
        let data = create_test_data();
        let (nonce, ciphertext, tag) = data.into_parts().unwrap();
        assert_eq!(nonce, TEST_NONCE.to_vec());
        assert_eq!(ciphertext, TEST_CIPHERTEXT.to_vec());
        assert_eq!(tag, TEST_TAG.to_vec());
    }

    #[test]
    fn test_to_base64() {
        let data = create_test_data();
        let b64 = data.to_base64();
        assert!(!b64.is_empty());
    }

    #[test]
    fn test_from_base64_valid() {
        let data = create_test_data();
        let b64 = data.to_base64();
        let result = EncryptedData::from_base64(&b64);
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_base64_invalid() {
        let result = EncryptedData::from_base64("not-valid-base64!");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = create_test_data();
        let b64 = data.to_base64();
        let decoded = EncryptedData::from_base64(&b64).unwrap();
        assert_eq!(data.as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_validate_valid() {
        let data = create_test_data();
        assert!(data.validate().is_ok());
    }

    #[test]
    fn test_validate_too_short() {
        let bytes = vec![1, 2, 3];
        let result = EncryptedData::from(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_into_vec() {
        let data = create_test_data();
        let original_bytes = data.as_bytes().to_vec();
        let vec: Vec<u8> = data.into();
        assert_eq!(vec, original_bytes);
    }

    #[test]
    fn test_as_ref() {
        let data = create_test_data();
        let bytes: &[u8] = data.as_ref();
        assert_eq!(bytes, data.as_bytes());
    }

    #[test]
    fn test_try_from_vec() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TEST_NONCE);
        bytes.extend_from_slice(TEST_CIPHERTEXT);
        bytes.extend_from_slice(&TEST_TAG);

        let result = EncryptedData::try_from(bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_from_slice() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TEST_NONCE);
        bytes.extend_from_slice(TEST_CIPHERTEXT);
        bytes.extend_from_slice(&TEST_TAG);

        let result = EncryptedData::try_from(bytes.as_slice());
        assert!(result.is_ok());
    }

    #[test]
    fn test_serialize() {
        let data = create_test_data();
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains(&data.to_base64()));
    }

    #[test]
    fn test_deserialize() {
        let data = create_test_data();
        let b64 = data.to_base64();
        let json = format!("\"{b64}\"");
        let decoded: EncryptedData = serde_json::from_str(&json).unwrap();
        assert_eq!(data.as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_serde_roundtrip() {
        let original = create_test_data();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: EncryptedData = serde_json::from_str(&json).unwrap();
        assert_eq!(original.as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_clone() {
        let data = create_test_data();
        let cloned = data.clone();
        assert_eq!(data.as_bytes(), cloned.as_bytes());
    }

    #[test]
    fn test_min_size_constant() {
        assert_eq!(EncryptedData::MIN_SIZE, NONCE_SIZE + TAG_SIZE);
    }
}
