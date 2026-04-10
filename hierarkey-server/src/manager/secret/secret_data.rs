// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64_standard;
use hierarkey_core::error::crypto::CryptoError;
use hierarkey_core::error::validation::ValidationError;
use hierarkey_core::{CkError, CkResult};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret32(Zeroizing<[u8; 32]>);

impl Secret32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<SecretData> for Secret32 {
    type Error = CkError;

    fn try_from(s: SecretData) -> Result<Self, Self::Error> {
        let arr: [u8; 32] = s.expose_secret().try_into().map_err(|_| {
            CkError::from(CryptoError::InvalidEncryptedData {
                field: "plaintext",
                message: "expected 32-byte plaintext".into(),
            })
        })?;

        Ok(Secret32::new(arr))
    }
}

impl TryFrom<&SecretData> for Secret32 {
    type Error = CkError;

    fn try_from(s: &SecretData) -> Result<Self, Self::Error> {
        let arr: [u8; 32] = s
            .expose_secret()
            .try_into()
            .map_err(|_| CryptoError::InvalidEncryptedData {
                field: "plaintext",
                message: "expected 32-byte plaintext".into(),
            })?;

        Ok(Secret32::new(arr))
    }
}

impl core::fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret32(<redacted>)")
    }
}

// ----------------------------------------------------------------------------------------------

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretData(Zeroizing<Box<[u8]>>);

impl SecretData {
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self(Zeroizing::new(v.into_boxed_slice()))
    }

    pub fn from_array_32(bytes: [u8; 32]) -> Self {
        let boxed: Box<[u8; 32]> = Box::new(bytes);
        let boxed: Box<[u8]> = boxed;
        Self(Zeroizing::new(boxed))
    }

    pub fn from_slice_copy(s: &[u8]) -> Self {
        Self(Zeroizing::new(s.to_vec().into_boxed_slice()))
    }

    pub fn from_base64(b64: &str) -> CkResult<Self> {
        const MAX_B64_LEN: usize = 1_000_000;
        if b64.len() > MAX_B64_LEN {
            return Err(ValidationError::Field {
                field: "data",
                code: "base64_too_large",
                message: format!("Base64 data too large (max {MAX_B64_LEN} bytes)").into(),
            }
            .into());
        }

        let decoded = base64_standard.decode(b64).map_err(|_| ValidationError::Field {
            field: "data",
            code: "base64_invalid",
            message: "Invalid base64 encoding".into(),
        })?;

        Ok(Self::from_vec(decoded))
    }

    /// Returns the length of the secret data.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Checks if the secret data is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Exposes the secret data as a byte slice.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

// Prevent accidental secret logging.
impl core::fmt::Debug for SecretData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretData(<redacted>)")
    }
}

// ----------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{Secret32, SecretData};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as b64;

    #[test]
    fn from_vec_roundtrip_len_and_expose() {
        let s = SecretData::from_vec(vec![1, 2, 3, 4]);
        assert_eq!(s.len(), 4);
        assert!(!s.is_empty());
        assert_eq!(s.expose_secret(), &[1, 2, 3, 4]);
    }

    #[test]
    fn from_vec_empty() {
        let s = SecretData::from_vec(Vec::new());
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
        assert!(s.expose_secret().is_empty());
    }

    #[test]
    fn from_array_32_roundtrip() {
        let bytes = [7u8; 32];
        let s = SecretData::from_array_32(bytes);
        assert_eq!(s.len(), 32);
        assert_eq!(s.expose_secret(), &bytes);
    }

    #[test]
    fn from_slice_copy_roundtrip() {
        let input = [9u8, 8, 7, 6, 5];
        let s = SecretData::from_slice_copy(&input);
        assert_eq!(s.len(), input.len());
        assert_eq!(s.expose_secret(), &input);
    }

    #[test]
    fn from_base64_valid() {
        let input = b"hello hierarkey \x00\x01\xff";
        let encoded = b64.encode(input);

        let s = SecretData::from_base64(&encoded).expect("base64 decode should succeed");
        assert_eq!(s.expose_secret(), input);
    }

    #[test]
    fn from_base64_invalid() {
        // definitely not valid base64
        let err = SecretData::from_base64("!!!not_base64!!!").expect_err("expected base64 decoding to fail");

        let msg = err.to_string();
        // be resilient to your error plumbing; check either the code or message content
        assert!(
            msg.contains("base64_invalid") || msg.to_lowercase().contains("invalid base64"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn from_base64_too_large_rejected() {
        // Must be larger than MAX_B64_LEN (1_000_000 in implementation)
        let huge = "A".repeat(1_000_000 + 1);

        let err = SecretData::from_base64(&huge).expect_err("expected too-large input to fail");
        let msg = err.to_string();
        assert!(
            msg.contains("base64_too_large") || msg.to_lowercase().contains("too large"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn debug_is_redacted() {
        let s = SecretData::from_vec(vec![1, 2, 3]);
        assert_eq!(format!("{s:?}"), "SecretData(<redacted>)");
    }

    // ---------------- Secret32 ----------------

    #[test]
    fn secret32_new_and_expose() {
        let bytes = [0xABu8; 32];
        let s = Secret32::new(bytes);
        assert_eq!(s.expose_secret(), &bytes);
        assert_eq!(format!("{s:?}"), "Secret32(<redacted>)");
    }

    // ---------------- SecretData constructors ----------------

    #[test]
    fn secretdata_from_vec_roundtrip() {
        let s = SecretData::from_vec(vec![1, 2, 3, 4]);
        assert_eq!(s.len(), 4);
        assert!(!s.is_empty());
        assert_eq!(s.expose_secret(), &[1, 2, 3, 4]);
    }

    #[test]
    fn secretdata_from_vec_empty() {
        let s = SecretData::from_vec(Vec::new());
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
        assert!(s.expose_secret().is_empty());
    }

    #[test]
    fn secretdata_from_array_32_roundtrip() {
        let bytes = [7u8; 32];
        let s = SecretData::from_array_32(bytes);
        assert_eq!(s.len(), 32);
        assert_eq!(s.expose_secret(), &bytes);
    }

    #[test]
    fn secretdata_from_slice_copy_roundtrip() {
        let input = [9u8, 8, 7, 6, 5];
        let s = SecretData::from_slice_copy(&input);
        assert_eq!(s.len(), input.len());
        assert_eq!(s.expose_secret(), &input);
    }

    // ---------------- SecretData base64 ----------------

    #[test]
    fn secretdata_from_base64_valid() {
        let input = b"hello hierarkey \x00\x01\xff";
        let encoded = b64.encode(input);

        let s = SecretData::from_base64(&encoded).expect("base64 decode should succeed");
        assert_eq!(s.expose_secret(), input);
    }

    #[test]
    fn secretdata_from_base64_invalid() {
        let err = SecretData::from_base64("!!!not_base64!!!").expect_err("expected base64 decoding to fail");

        let msg = err.to_string();
        assert!(
            msg.contains("base64_invalid") || msg.to_lowercase().contains("invalid base64"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn secretdata_from_base64_too_large_rejected() {
        // MAX_B64_LEN is 1_000_000; exceed by 1.
        let huge = "A".repeat(1_000_000 + 1);

        let err = SecretData::from_base64(&huge).expect_err("expected too-large base64 input to be rejected");

        let msg = err.to_string();
        assert!(
            msg.contains("base64_too_large") || msg.to_lowercase().contains("too large"),
            "unexpected error: {msg}"
        );
    }

    // ---------------- Debug redaction ----------------

    #[test]
    fn secretdata_debug_is_redacted() {
        let s = SecretData::from_vec(vec![1, 2, 3]);
        assert_eq!(format!("{s:?}"), "SecretData(<redacted>)");
    }
}
