// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

// Hierarkey - Cryptographic Key Management
//
// AES-256-GCM encryption/decryption module providing authenticated encryption
// with additional data (AEAD). Uses 256-bit keys, 96-bit nonces, and 128-bit
// authentication tags for secure data protection.

use crate::global::keys::{NONCE_SIZE, TAG_SIZE};
use crate::manager::secret::SecretData;
use crate::manager::secret::encrypted_data::EncryptedData;
use crate::manager::secret::secret_data::Secret32;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce};
use hierarkey_core::CkResult;
use hierarkey_core::error::crypto::CryptoError;
use std::fmt::Debug;

pub struct CryptoAesGcm {
    cipher: Aes256Gcm,
}

impl Debug for CryptoAesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoAesGcm").finish_non_exhaustive()
    }
}

impl CryptoAesGcm {
    pub fn new(key: &Secret32) -> CkResult<Self> {
        // we need to "transfer" the secret key to the Aes256GCM type, but this will internally
        // use zeroize as well.
        let cipher = Aes256Gcm::new_from_slice(key.expose_secret())
            .map_err(|e| CryptoError::InvalidKeyMaterial(anyhow::anyhow!(e)))?;

        Ok(Self { cipher })
    }

    pub fn encrypt32(&self, data: &Secret32, aad: &[u8]) -> CkResult<EncryptedData> {
        self.encrypt_bytes(data.expose_secret(), aad)
    }

    pub fn decrypt32(&self, enc: &EncryptedData, aad: &[u8]) -> CkResult<Secret32> {
        let secret_data = self.decrypt_bytes(enc, aad)?;
        Secret32::try_from(secret_data)
    }

    pub fn encrypt(&self, data: &SecretData, aad: &[u8]) -> CkResult<EncryptedData> {
        self.encrypt_bytes(data.expose_secret(), aad)
    }

    pub fn decrypt(&self, data: &EncryptedData, aad: &[u8]) -> CkResult<SecretData> {
        self.decrypt_bytes(data, aad)
    }

    fn encrypt_bytes(&self, msg: &[u8], aad: &[u8]) -> CkResult<EncryptedData> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Encrypt with AAD
        let ciphertext_with_tag = self
            .cipher
            .encrypt(&nonce, aes_gcm::aead::Payload { msg, aad })
            .map_err(|e| CryptoError::EncryptionFailed(anyhow::anyhow!(e)))?;

        // concat nonce || cipher
        let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext_with_tag.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ciphertext_with_tag);

        // nonce || ciphertext || tag
        EncryptedData::from(out)
    }

    fn decrypt_bytes(&self, enc_data: &EncryptedData, aad: &[u8]) -> CkResult<SecretData> {
        // nonce || ciphertext || tag
        let msg = enc_data.as_bytes();
        if msg.len() < NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::InvalidEncryptedData {
                field: "length",
                message: "Encrypted data too short".into(),
            }
            .into());
        }

        let nonce = Nonce::from_slice(&msg[..NONCE_SIZE]);
        let ciphertext_with_tag = &msg[NONCE_SIZE..];

        // Decrypt with AAD
        let pt = self
            .cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext_with_tag,
                    aad,
                },
            )
            .map_err(|_e| CryptoError::AuthenticationFailed)?; // No need for details

        Ok(SecretData::from_vec(pt))
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoAesGcm;
    use crate::manager::secret::SecretData;
    use crate::manager::secret::encrypted_data::EncryptedData;
    use crate::manager::secret::secret_data::Secret32;
    use aes_gcm::aead::OsRng;
    use aes_gcm::aead::rand_core::RngCore;
    use zeroize::Zeroizing;

    fn random_key() -> Secret32 {
        let mut k = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(k.as_mut());
        Secret32::new(*k)
    }

    #[test]
    fn roundtrip_secretdata() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();

        let pt = SecretData::from_vec(b"hello".to_vec());
        let aad = b"aad";

        let enc = crypto.encrypt(&pt, aad).unwrap();
        let dec = crypto.decrypt(&enc, aad).unwrap();

        assert_eq!(dec.expose_secret(), b"hello");
    }

    #[test]
    fn roundtrip_secret32() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();

        let pt = Secret32::new([0x42u8; 32]);
        let aad = b"kek-wrap-v1";

        let enc = crypto.encrypt32(&pt, aad).unwrap();
        let dec = crypto.decrypt32(&enc, aad).unwrap();

        assert_eq!(dec.expose_secret(), pt.expose_secret());
    }

    #[test]
    fn decrypt_fails_with_wrong_aad() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();

        let pt = SecretData::from_vec(b"secret".to_vec());
        let enc = crypto.encrypt(&pt, b"aad-1").unwrap();

        assert!(crypto.decrypt(&enc, b"aad-2").is_err());
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let key1 = random_key();
        let key2 = random_key();

        let c1 = CryptoAesGcm::new(&key1).unwrap();
        let c2 = CryptoAesGcm::new(&key2).unwrap();

        let pt = Secret32::new([1u8; 32]);
        let aad = b"aad";

        let enc = c1.encrypt32(&pt, aad).unwrap();
        assert!(c2.decrypt32(&enc, aad).is_err());
    }

    #[test]
    fn roundtrip_secretdata_various_lengths() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();
        let aad = b"aad";

        for len in [0usize, 1, 2, 15, 16, 31, 32, 33, 128, 1024] {
            let pt = vec![0xA5u8; len];
            let sd = SecretData::from_vec(pt.clone());

            let enc = crypto.encrypt(&sd, aad).unwrap();
            let dec = crypto.decrypt(&enc, aad).unwrap();

            assert_eq!(dec.expose_secret(), pt.as_slice(), "len={len}");
        }
    }

    #[test]
    fn encrypt_uses_random_nonce_produces_different_ciphertexts() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();
        let aad = b"aad";

        let pt = SecretData::from_vec(b"same plaintext".to_vec());

        let enc1 = crypto.encrypt(&pt, aad).unwrap();
        let enc2 = crypto.encrypt(&pt, aad).unwrap();

        // With random nonces, ciphertext blobs should differ.
        assert_ne!(enc1.as_bytes(), enc2.as_bytes());
    }

    #[test]
    fn decrypt_fails_with_wrong_aad_secretdata() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();

        let pt = SecretData::from_vec(b"secret".to_vec());
        let enc = crypto.encrypt(&pt, b"aad-1").unwrap();

        assert!(crypto.decrypt(&enc, b"aad-2").is_err());
    }

    #[test]
    fn decrypt_fails_with_wrong_aad_secret32() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();

        let pt = Secret32::new([7u8; 32]);
        let enc = crypto.encrypt32(&pt, b"aad-1").unwrap();

        assert!(crypto.decrypt32(&enc, b"aad-2").is_err());
    }

    #[test]
    fn decrypt_fails_with_wrong_key_secretdata() {
        let key1 = random_key();
        let key2 = random_key();

        let c1 = CryptoAesGcm::new(&key1).unwrap();
        let c2 = CryptoAesGcm::new(&key2).unwrap();

        let pt = SecretData::from_vec(b"secret".to_vec());
        let aad = b"aad";

        let enc = c1.encrypt(&pt, aad).unwrap();
        assert!(c2.decrypt(&enc, aad).is_err());
    }

    #[test]
    fn decrypt_fails_with_wrong_key_secret32() {
        let key1 = random_key();
        let key2 = random_key();

        let c1 = CryptoAesGcm::new(&key1).unwrap();
        let c2 = CryptoAesGcm::new(&key2).unwrap();

        let pt = Secret32::new([1u8; 32]);
        let aad = b"aad";

        let enc = c1.encrypt32(&pt, aad).unwrap();
        assert!(c2.decrypt32(&enc, aad).is_err());
    }

    #[test]
    fn tamper_ciphertext_byte_fails_auth() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();
        let aad = b"aad";

        let pt = SecretData::from_vec(b"hello".to_vec());
        let enc = crypto.encrypt(&pt, aad).unwrap();

        let mut bytes = enc.as_bytes().to_vec();
        let len = bytes.len();
        // Flip one byte somewhere after nonce (avoid only touching nonce to vary coverage)
        if len > 20 {
            bytes[20] ^= 0x01;
        } else {
            bytes[len - 1] ^= 0x01;
        }

        let tampered = EncryptedData::from(bytes).unwrap();
        assert!(crypto.decrypt(&tampered, aad).is_err());
    }

    #[test]
    fn tamper_nonce_byte_fails_auth() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();
        let aad = b"aad";

        let pt = SecretData::from_vec(b"hello".to_vec());
        let enc = crypto.encrypt(&pt, aad).unwrap();

        let mut bytes = enc.as_bytes().to_vec();
        // Flip a nonce byte (nonce is at start)
        bytes[0] ^= 0x80;

        let tampered = EncryptedData::from(bytes).unwrap();
        assert!(crypto.decrypt(&tampered, aad).is_err());
    }

    #[test]
    fn tamper_tag_byte_fails_auth() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();
        let aad = b"aad";

        let pt = SecretData::from_vec(b"hello".to_vec());
        let enc = crypto.encrypt(&pt, aad).unwrap();

        let mut bytes = enc.as_bytes().to_vec();
        // Flip last byte (tag is at end)
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;

        let tampered = EncryptedData::from(bytes).unwrap();
        assert!(crypto.decrypt(&tampered, aad).is_err());
    }

    #[test]
    fn decrypt_rejects_too_short_blob() {
        // let key = random_key();

        // Minimal invalid blob: shorter than NONCE_SIZE + TAG_SIZE
        // We don't hardcode sizes here; just make it clearly too small.
        let bytes = vec![0u8; 10];
        assert!(EncryptedData::from(bytes).is_err());
    }

    #[test]
    fn decrypt32_rejects_plaintext_not_32_bytes() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();
        let aad = b"aad";

        // Encrypt 31 bytes using the generic SecretData API
        let pt = SecretData::from_vec(vec![0x11u8; 31]);
        let enc = crypto.encrypt(&pt, aad).unwrap();

        // decrypt32 should reject because plaintext isn't exactly 32 bytes
        assert!(crypto.decrypt32(&enc, aad).is_err());
    }

    #[test]
    fn empty_aad_is_allowed_but_must_match() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();

        let pt = SecretData::from_vec(b"hello".to_vec());

        let enc = crypto.encrypt(&pt, b"").unwrap();
        let dec = crypto.decrypt(&enc, b"").unwrap();
        assert_eq!(dec.expose_secret(), b"hello");

        // Non-empty AAD should fail
        assert!(crypto.decrypt(&enc, b"not-empty").is_err());
    }

    #[test]
    fn different_aad_lengths_same_prefix_fail() {
        let key = random_key();
        let crypto = CryptoAesGcm::new(&key).unwrap();

        let pt = Secret32::new([9u8; 32]);
        let enc = crypto.encrypt32(&pt, b"prefix").unwrap();

        assert!(crypto.decrypt32(&enc, b"prefix\0").is_err());
    }
}
