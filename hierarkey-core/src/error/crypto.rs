// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::CkError;

/// Errors related to cryptographic operations, including encryption, decryption, key management, and password hashing.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed(#[source] anyhow::Error),

    #[error("randomness failure")]
    RandomnessFailure(#[source] anyhow::Error),

    #[error("ciphertext invalid")]
    CiphertextInvalid,

    #[error("decryption failed")]
    DecryptionFailed(#[source] anyhow::Error),

    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("invalid key material")]
    InvalidKeyMaterial(#[source] anyhow::Error),

    #[error("password hash invalid")]
    PasswordHashInvalid,

    #[error("password hashing failed")]
    PasswordHashingFailed,

    #[error("encrypted data is invalid: {field}")]
    InvalidEncryptedData { field: &'static str, message: String },

    #[error("hsm error: {what}")]
    Hsm {
        what: &'static str,
        #[source]
        source: anyhow::Error,
    },

    #[error("unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },
}

impl From<CryptoError> for CkError {
    fn from(e: CryptoError) -> Self {
        CkError::Crypto(e)
    }
}
