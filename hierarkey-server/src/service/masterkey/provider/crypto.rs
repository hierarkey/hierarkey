// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use hierarkey_core::CkResult;

use crate::global::aes_gcm::CryptoAesGcm;
use crate::global::keys::{EncryptedKek, EncryptedSigningKey, SigningKeyId};
use crate::manager::kek::KekEncAlgo;
use crate::manager::masterkey::MasterkeyId;
use crate::manager::namespace::NamespaceId;
use crate::manager::secret::encrypted_data::EncryptedData;

pub trait MasterKeyCrypto: Send + Sync + Debug {
    /// Encrypt 32 bytes (a KEK) with associated data.
    fn wrap_kek_32(
        &self,
        plaintext: &[u8; 32],
        masterkey_id: MasterkeyId,
        namespace_id: NamespaceId,
    ) -> CkResult<EncryptedData>;

    /// Decrypt 32 bytes (a KEK) with associated data.
    fn unwrap_kek_32(
        &self,
        ciphertext: &EncryptedData,
        masterkey_id: MasterkeyId,
        namespace_id: NamespaceId,
    ) -> CkResult<[u8; 32]>;

    /// Encrypt 32 bytes of signing key material using `EncryptedSigningKey::generate_aad`.
    /// The `signing_key_id` must be pre-generated so it can be bound into the AAD.
    fn wrap_signing_key(
        &self,
        plaintext: &[u8; 32],
        masterkey_id: MasterkeyId,
        signing_key_id: SigningKeyId,
    ) -> CkResult<EncryptedData>;

    /// Decrypt the 32-byte signing key material from an `EncryptedSigningKey`.
    ///
    /// Uses `EncryptedSigningKey::generate_aad` (domain-separated from KEK AAD)
    /// so a ciphertext intended for a signing key cannot be confused with a KEK.
    fn unwrap_signing_key(&self, enc_key: &EncryptedSigningKey) -> CkResult<[u8; 32]>;

    fn algo(&self) -> KekEncAlgo;
}

/// Shared handle type you can store in the KeyRing.
pub type MasterKeyCryptoHandle = Arc<dyn MasterKeyCrypto>;

// ------------------------------------------------------------------------------------------
// In-memory implementation (AES-GCM) used by insecure + passphrase providers

pub struct AesGcmMasterKeyCrypto {
    crypto: CryptoAesGcm,
}

impl AesGcmMasterKeyCrypto {
    pub fn new(crypto: CryptoAesGcm) -> Self {
        Self { crypto }
    }

    pub fn inner(&self) -> &CryptoAesGcm {
        &self.crypto
    }
}

impl Debug for AesGcmMasterKeyCrypto {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcmMasterKeyCrypto").finish()
    }
}

impl MasterKeyCrypto for AesGcmMasterKeyCrypto {
    fn wrap_kek_32(
        &self,
        plaintext: &[u8; 32],
        masterkey_id: MasterkeyId,
        namespace_id: NamespaceId,
    ) -> CkResult<EncryptedData> {
        let aad = EncryptedKek::generate_aad(self.algo(), masterkey_id, namespace_id);

        let kek = crate::manager::secret::secret_data::Secret32::new(*plaintext);
        let enc = self.crypto.encrypt32(&kek, aad.as_bytes())?;
        Ok(enc)
    }

    fn unwrap_kek_32(
        &self,
        ciphertext: &EncryptedData,
        masterkey_id: MasterkeyId,
        namespace_id: NamespaceId,
    ) -> CkResult<[u8; 32]> {
        let aad = EncryptedKek::generate_aad(self.algo(), masterkey_id, namespace_id);

        let secret = self.crypto.decrypt32(ciphertext, aad.as_bytes())?;
        Ok(*secret.expose_secret())
    }

    fn wrap_signing_key(
        &self,
        plaintext: &[u8; 32],
        masterkey_id: MasterkeyId,
        signing_key_id: SigningKeyId,
    ) -> CkResult<EncryptedData> {
        let aad = EncryptedSigningKey::generate_aad(self.algo(), masterkey_id, signing_key_id);
        let secret = crate::manager::secret::secret_data::Secret32::new(*plaintext);
        self.crypto.encrypt32(&secret, aad.as_bytes())
    }

    fn unwrap_signing_key(&self, enc_key: &EncryptedSigningKey) -> CkResult<[u8; 32]> {
        let aad = EncryptedSigningKey::generate_aad(self.algo(), enc_key.masterkey_id, enc_key.id);
        let secret = self.crypto.decrypt32(&enc_key.ciphertext, aad.as_bytes())?;
        Ok(*secret.expose_secret())
    }

    fn algo(&self) -> KekEncAlgo {
        KekEncAlgo::Aes256Gcm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::aes_gcm::CryptoAesGcm;
    use crate::manager::masterkey::MasterkeyId;
    use crate::manager::namespace::NamespaceId;
    use crate::manager::secret::secret_data::Secret32;

    fn make_crypto() -> AesGcmMasterKeyCrypto {
        let key = Secret32::new([42u8; 32]);
        let aes = CryptoAesGcm::new(&key).unwrap();
        AesGcmMasterKeyCrypto::new(aes)
    }

    fn mk_id() -> MasterkeyId {
        MasterkeyId(uuid::Uuid::new_v4())
    }

    fn ns_id() -> NamespaceId {
        NamespaceId(uuid::Uuid::new_v4())
    }

    #[test]
    fn algo_returns_aes256gcm() {
        let c = make_crypto();
        assert_eq!(c.algo(), KekEncAlgo::Aes256Gcm);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let c = make_crypto();
        let mk = mk_id();
        let ns = ns_id();
        let plaintext = [0xABu8; 32];
        let enc = c.wrap_kek_32(&plaintext, mk, ns).unwrap();
        let dec = c.unwrap_kek_32(&enc, mk, ns).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn wrap_unwrap_different_masterkey_fails() {
        let c = make_crypto();
        let mk1 = mk_id();
        let mk2 = mk_id();
        let ns = ns_id();
        let plaintext = [0xCDu8; 32];
        let enc = c.wrap_kek_32(&plaintext, mk1, ns).unwrap();
        // Decrypt with wrong masterkey_id -> AAD mismatch -> error
        assert!(c.unwrap_kek_32(&enc, mk2, ns).is_err());
    }

    #[test]
    fn wrap_unwrap_different_namespace_fails() {
        let c = make_crypto();
        let mk = mk_id();
        let ns1 = ns_id();
        let ns2 = ns_id();
        let plaintext = [0xEFu8; 32];
        let enc = c.wrap_kek_32(&plaintext, mk, ns1).unwrap();
        // Decrypt with wrong namespace_id -> AAD mismatch -> error
        assert!(c.unwrap_kek_32(&enc, mk, ns2).is_err());
    }

    #[test]
    fn wrap_with_different_key_cannot_unwrap() {
        let c1 = make_crypto();
        let c2 = AesGcmMasterKeyCrypto::new(CryptoAesGcm::new(&Secret32::new([0u8; 32])).unwrap());
        let mk = mk_id();
        let ns = ns_id();
        let plaintext = [0x11u8; 32];
        let enc = c1.wrap_kek_32(&plaintext, mk, ns).unwrap();
        assert!(c2.unwrap_kek_32(&enc, mk, ns).is_err());
    }

    #[test]
    fn inner_returns_aes_gcm_ref() {
        let key = Secret32::new([1u8; 32]);
        let aes = CryptoAesGcm::new(&key).unwrap();
        let c = AesGcmMasterKeyCrypto::new(aes);
        // Just verify inner() compiles and returns without panic
        let _inner = c.inner();
    }
}
