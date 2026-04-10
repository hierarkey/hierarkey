// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

#![allow(unused)]
use crate::audit_context::CallContext;
use crate::global::keys::{Dek, EncryptedDek, EncryptedKek, Kek, KekId};
use crate::global::short_id::ShortId;
use crate::manager::KekManager;
use crate::manager::masterkey::{MasterKey, MasterKeyUsage, MasterkeyId};
use crate::manager::namespace::NamespaceId;
use crate::service::kek::cache::KekCache;
use crate::service::masterkey::provider::crypto::MasterKeyCryptoHandle;
use crate::service::namespace::KekEncryptable;
use crate::service::secret::DekDecryptor;
use crate::task_manager::BackgroundTaskManager;
use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use async_trait::async_trait;
use hierarkey_core::error::crypto::CryptoError;
use hierarkey_core::{CkError, CkResult};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, trace, warn};

mod cache;

/// Filter controlling which KEKs are rewrapped in a partial-rewrap operation.
#[derive(Debug, Clone)]
pub enum RewrapKekFilter {
    /// Rewrap every KEK currently wrapped under the source master key.
    All,
    /// Rewrap only KEKs assigned to the given namespace.
    Namespace(NamespaceId),
    /// Rewrap a single specific KEK.
    Kek(KekId),
}

#[async_trait]
pub trait MasterKeyRetrievable: Send + Sync {
    async fn find_active(&self, usage: MasterKeyUsage) -> CkResult<Option<MasterKey>>;
    async fn find_by_id(&self, id: MasterkeyId) -> CkResult<Option<MasterKey>>;
    fn crypto_for(&self, master_key: &MasterKey) -> CkResult<MasterKeyCryptoHandle>;
}

pub struct KekService {
    kek_manager: Arc<KekManager>,
    kek_cache: Arc<KekCache>,
    masterkey_retriever: Arc<dyn MasterKeyRetrievable>,
}

#[async_trait]
impl KekEncryptable for KekService {
    async fn generate_encrypted_kek(&self, namespace_id: NamespaceId) -> CkResult<(KekId, MasterkeyId)> {
        trace!("Generating new KEK for namespace {}", namespace_id);

        let Some(master_key) = self.masterkey_retriever.find_active(MasterKeyUsage::WrapKek).await? else {
            error!("No active master key for KEK wrapping");
            return Err(CkError::MasterKey("No active master key for KEK wrapping".to_string()));
        };

        let new_kek = Kek::generate()?;
        let crypto = self.masterkey_retriever.crypto_for(&master_key)?;
        let enc_data = crypto.wrap_kek_32(new_kek.as_bytes(), master_key.id, namespace_id)?;

        let ctx = CallContext::system();
        let enc_kek = self
            .kek_manager
            .create(&ctx, &enc_data, crypto.algo(), master_key.id)
            .await?;
        Ok((enc_kek.id, master_key.id))
    }
}

#[async_trait]
impl DekDecryptor for KekService {
    async fn decrypt_dek(
        &self,
        kek_id: KekId,
        encrypted_dek: &EncryptedDek,
        aad: &str,
        namespace_id: NamespaceId,
    ) -> CkResult<Dek> {
        // Make sure we decrypt a valid DEK
        encrypted_dek.validate()?;

        let Some(kek) = self.get_decrypted_kek(kek_id, namespace_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "kek",
                id: kek_id.to_string(),
            });
        };

        // We have an decrypted KEK, use it to decrypt the DEK
        use aes_gcm::{
            Aes256Gcm, Nonce,
            aead::{Aead, KeyInit},
        };

        let cipher = Aes256Gcm::new(kek.as_bytes().into());
        let nonce_gcm = Nonce::from_slice(&encrypted_dek.nonce);

        let mut ciphertext_with_tag = Vec::with_capacity(48);
        ciphertext_with_tag.extend_from_slice(&encrypted_dek.ciphertext);
        ciphertext_with_tag.extend_from_slice(&encrypted_dek.tag);

        let payload = aes_gcm::aead::Payload {
            msg: &ciphertext_with_tag,
            aad: aad.as_bytes(),
        };

        let decrypted = cipher
            .decrypt(nonce_gcm, payload)
            .map_err(|e| CryptoError::DecryptionFailed(anyhow::anyhow!(e)))?;

        if decrypted.len() != 32 {
            return Err(CryptoError::InvalidEncryptedData {
                field: "dek",
                message: format!("Invalid DEK size: expected 32 bytes, got {}", decrypted.len()),
            }
            .into());
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&decrypted);

        Dek::from_bytes(&key_bytes)
    }

    async fn encrypt_dek(
        &self,
        kek_id: KekId,
        dek: &Dek,
        aad: &str,
        namespace_id: NamespaceId,
    ) -> CkResult<EncryptedDek> {
        use aes_gcm::{
            Aes256Gcm, Nonce,
            aead::{Aead, KeyInit},
        };

        // Sanity check
        if dek.is_zero() {
            return Err(CryptoError::EncryptionFailed(anyhow::anyhow!("Dek cannot be all zeros")).into());
        }

        // Get the decrypted KEK (from cache or decrypt)
        let Some(kek) = self.get_decrypted_kek(kek_id, namespace_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "kek",
                id: kek_id.to_string(),
            });
        };

        let cipher = Aes256Gcm::new(kek.as_bytes().into());
        let mut nonce = [0u8; 12];
        OsRng.try_fill_bytes(&mut nonce).map_err(|e| {
            CryptoError::EncryptionFailed(anyhow::anyhow!("Failed to generate nonce for DEK encryption: {e}"))
        })?;
        let nonce_gcm = Nonce::from_slice(&nonce);

        let payload = aes_gcm::aead::Payload {
            msg: &dek.inner[..],
            aad: aad.as_bytes(),
        };

        let ciphertext_with_tag = cipher
            .encrypt(nonce_gcm, payload)
            .map_err(|e| CryptoError::EncryptionFailed(anyhow::anyhow!("Failed to encrypt DEK: {e}")))?;

        if ciphertext_with_tag.len() != 48 {
            return Err(CryptoError::EncryptionFailed(anyhow::anyhow!(format!(
                "Invalid encrypted DEK size: expected 48 bytes, got {}",
                ciphertext_with_tag.len()
            )))
            .into());
        }

        // Split ciphertext and tag
        let mut ciphertext = [0u8; 32];
        ciphertext.copy_from_slice(&ciphertext_with_tag[..32]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext_with_tag[32..48]);

        let enc_dek = EncryptedDek { nonce, ciphertext, tag };
        Ok(enc_dek)
    }
}

impl KekService {
    pub fn new(
        kek_manager: Arc<KekManager>,
        masterkey_retriever: Arc<dyn MasterKeyRetrievable>,
        cache_ttl: Duration,
        task_manager: Arc<BackgroundTaskManager>,
    ) -> Self {
        let kek_cache = KekCache::new(cache_ttl);

        // We spawn a background task to evict idle KEKs from the cache periodically.
        // Note that we rely on the background task manager to shut down when the server
        // is shutting down.
        let shutdown = task_manager.shutdown_token();
        task_manager.spawn("kek_cache_eviction", {
            let mut shutdown = shutdown.clone();
            let kek_cache = kek_cache.clone();

            async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => {
                            trace!("KEK cache eviction thread received shutdown signal, exiting");
                            break;
                        }
                        _ = tokio::time::sleep(cache_ttl) => {
                            trace!("Running KEK cache eviction");
                            kek_cache.evict_idle();
                        }
                    }
                }
            }
        });

        Self {
            kek_manager,
            kek_cache,
            masterkey_retriever,
        }
    }

    /// Rewrap KEKs currently protected by `old_mk` under `new_mk`.
    ///
    /// `filter` controls which KEKs are rewrapped:
    /// - `All`: every KEK wrapped under `old_mk`
    /// - `Namespace(id)`: only KEKs assigned to that namespace
    /// - `Kek(id)`: a single specific KEK
    ///
    /// Returns `(rewrapped, remaining)` — the number of KEKs rewrapped and the number
    /// still wrapped under `old_mk` after the operation.
    pub async fn rewrap_keks_to_new_masterkey(
        &self,
        old_mk: &MasterKey,
        new_mk: &MasterKey,
        filter: &RewrapKekFilter,
    ) -> CkResult<(usize, usize)> {
        let old_crypto = self.masterkey_retriever.crypto_for(old_mk)?;
        let new_crypto = self.masterkey_retriever.crypto_for(new_mk)?;

        let all_keks = self.kek_manager.list_by_masterkey_with_namespace(old_mk.id).await?;
        let total_before = all_keks.len();

        let to_rewrap: Vec<_> = match filter {
            RewrapKekFilter::All => all_keks,
            RewrapKekFilter::Namespace(ns_id) => all_keks.into_iter().filter(|(_, ns)| ns == ns_id).collect(),
            RewrapKekFilter::Kek(kek_id) => all_keks.into_iter().filter(|(k, _)| k.id == *kek_id).collect(),
        };

        let rewrapped_count = to_rewrap.len();

        for (enc_kek, namespace_id) in to_rewrap {
            // Decrypt (unwrap) using the old master key
            let kek_bytes = match old_crypto.unwrap_kek_32(&enc_kek.ciphertext, old_mk.id, namespace_id) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Failed to unwrap KEK '{}' during rewrap: {e}", enc_kek.id);
                    return Err(e);
                }
            };

            // Re-encrypt (wrap) using the new master key
            let new_ciphertext = new_crypto.wrap_kek_32(&kek_bytes, new_mk.id, namespace_id)?;

            // Persist the new ciphertext
            self.kek_manager
                .rewrap_kek(enc_kek.id, new_ciphertext, new_mk.id)
                .await?;

            // Evict the old cached plaintext so it is re-read from the new ciphertext
            self.kek_cache.evict(enc_kek.id);
        }

        let remaining = total_before - rewrapped_count;
        Ok((rewrapped_count, remaining))
    }

    /// Look up a KEK by its short ID (e.g. "kek_abc123").
    pub async fn find_kek_by_short_id(&self, short_id: &str) -> CkResult<Option<EncryptedKek>> {
        self.kek_manager.find_by_short_id(short_id).await
    }

    /// Count KEKs grouped by master key ID (single query).
    pub async fn count_keks_by_masterkey(
        &self,
    ) -> CkResult<std::collections::HashMap<crate::manager::masterkey::MasterkeyId, usize>> {
        self.kek_manager.count_all_by_masterkey().await
    }

    /// Get the decrypted KEK, either from cache or by decrypting it with a master key
    async fn get_decrypted_kek(&self, kek_id: KekId, namespace_id: NamespaceId) -> CkResult<Option<Kek>> {
        if let Some(kek) = self.kek_cache.find_entry(kek_id)? {
            trace!("KEK '{}' found in cache", kek_id);
            return Ok(Some(kek));
        };

        trace!("KEK '{}' not found in cache, decrypting", kek_id);

        let Some(enc_kek) = self.kek_manager.fetch(kek_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "kek",
                id: kek_id.to_string(),
            });
        };

        let master_key = self
            .masterkey_retriever
            .find_by_id(enc_kek.masterkey_id)
            .await?
            .ok_or_else(|| {
                CkError::MasterKey(format!("Master key '{}' not found for KEK unwrapping", enc_kek.masterkey_id))
            })?;

        let crypto = self.masterkey_retriever.crypto_for(&master_key)?;
        let kek_bytes = crypto.unwrap_kek_32(&enc_kek.ciphertext, master_key.id, namespace_id)?;
        let kek = Kek::from_bytes(&kek_bytes)?;

        self.kek_cache.insert(kek_id, &kek);
        Ok(Some(kek))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::aes_gcm::CryptoAesGcm;
    use crate::global::keys::{Dek, EncryptedDek, KekId, NONCE_SIZE, TAG_SIZE};
    use crate::manager::kek::{InMemoryKekStore, KekManager};
    use crate::manager::masterkey::{MasterKey, MasterKeyBackend, MasterKeyFileType, MasterKeyStatus, MasterkeyId};
    use crate::manager::namespace::NamespaceId;
    use crate::manager::secret::secret_data::Secret32;
    use crate::service::masterkey::provider::crypto::{AesGcmMasterKeyCrypto, MasterKeyCryptoHandle};
    use crate::task_manager::BackgroundTaskManager;
    use async_trait::async_trait;
    use hierarkey_core::{CkResult, Metadata};
    use std::sync::Arc;
    use std::time::Duration;

    struct MockMkRetriever {
        master_key: MasterKey,
        crypto: MasterKeyCryptoHandle,
    }

    #[async_trait]
    impl MasterKeyRetrievable for MockMkRetriever {
        async fn find_active(&self, _usage: MasterKeyUsage) -> CkResult<Option<MasterKey>> {
            Ok(Some(self.master_key.clone()))
        }
        async fn find_by_id(&self, id: MasterkeyId) -> CkResult<Option<MasterKey>> {
            if self.master_key.id == id {
                Ok(Some(self.master_key.clone()))
            } else {
                Ok(None)
            }
        }
        fn crypto_for(&self, _master_key: &MasterKey) -> CkResult<MasterKeyCryptoHandle> {
            Ok(self.crypto.clone())
        }
    }

    struct NoMkRetriever;

    #[async_trait]
    impl MasterKeyRetrievable for NoMkRetriever {
        async fn find_active(&self, _usage: MasterKeyUsage) -> CkResult<Option<MasterKey>> {
            Ok(None)
        }
        async fn find_by_id(&self, _id: MasterkeyId) -> CkResult<Option<MasterKey>> {
            Ok(None)
        }
        fn crypto_for(&self, _: &MasterKey) -> CkResult<MasterKeyCryptoHandle> {
            Err(hierarkey_core::CkError::MasterKey("no key".into()))
        }
    }

    fn make_test_mk_and_crypto() -> (MasterKey, MasterKeyCryptoHandle) {
        let key_bytes = [42u8; 32];
        let key = Secret32::new(key_bytes);
        let aes = CryptoAesGcm::new(&key).unwrap();
        let crypto: MasterKeyCryptoHandle = Arc::new(AesGcmMasterKeyCrypto::new(aes));
        let mk = MasterKey {
            id: MasterkeyId::new(),
            short_id: ShortId::generate("mk_", 12),
            name: "test-mk".into(),
            usage: MasterKeyUsage::WrapKek,
            status: MasterKeyStatus::Active,
            backend: MasterKeyBackend::File,
            file_type: Some(MasterKeyFileType::Insecure),
            file_path: None,
            file_sha256: None,
            pkcs11_ref: None,
            metadata: Metadata::default(),
            created_at: chrono::Utc::now(),
            created_by: None,
            updated_at: None,
            updated_by: None,
            retired_at: None,
            retired_by: None,
        };
        (mk, crypto)
    }

    fn make_svc() -> KekService {
        let (mk, crypto) = make_test_mk_and_crypto();
        let retriever = Arc::new(MockMkRetriever { master_key: mk, crypto });
        let kek_store = Arc::new(InMemoryKekStore::new());
        let kek_manager = Arc::new(KekManager::new(kek_store));
        let task_mgr = Arc::new(BackgroundTaskManager::new());
        KekService::new(kek_manager, retriever, Duration::from_secs(300), task_mgr)
    }

    fn make_svc_no_mk() -> KekService {
        let retriever = Arc::new(NoMkRetriever);
        let kek_store = Arc::new(InMemoryKekStore::new());
        let kek_manager = Arc::new(KekManager::new(kek_store));
        let task_mgr = Arc::new(BackgroundTaskManager::new());
        KekService::new(kek_manager, retriever, Duration::from_secs(300), task_mgr)
    }

    #[tokio::test]
    async fn generate_encrypted_kek_success() {
        let svc = make_svc();
        let ns = NamespaceId::new();
        let result = svc.generate_encrypted_kek(ns).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn generate_encrypted_kek_no_active_masterkey() {
        let svc = make_svc_no_mk();
        let result = svc.generate_encrypted_kek(NamespaceId::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn encrypt_dek_success() {
        let svc = make_svc();
        let ns = NamespaceId::new();
        let (kek_id, _) = svc.generate_encrypted_kek(ns).await.unwrap();
        let dek = Dek::from_bytes(&[1u8; 32]).unwrap();
        let result = svc.encrypt_dek(kek_id, &dek, "test-aad", ns).await;
        assert!(result.is_ok());
        result.unwrap().validate().unwrap();
    }

    #[tokio::test]
    async fn encrypt_dek_kek_not_found() {
        let svc = make_svc();
        let dek = Dek::from_bytes(&[1u8; 32]).unwrap();
        let result = svc.encrypt_dek(KekId::new(), &dek, "aad", NamespaceId::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn decrypt_dek_invalid_nonce_is_error() {
        let svc = make_svc();
        let ns = NamespaceId::new();
        let (kek_id, _) = svc.generate_encrypted_kek(ns).await.unwrap();
        let bad_enc = EncryptedDek {
            nonce: [0u8; NONCE_SIZE],
            ciphertext: [1u8; 32],
            tag: [1u8; TAG_SIZE],
        };
        let result = svc.decrypt_dek(kek_id, &bad_enc, "aad", ns).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn decrypt_dek_kek_not_found() {
        let svc = make_svc();
        let enc = EncryptedDek {
            nonce: [1u8; NONCE_SIZE],
            ciphertext: [1u8; 32],
            tag: [1u8; TAG_SIZE],
        };
        let result = svc.decrypt_dek(KekId::new(), &enc, "aad", NamespaceId::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let svc = make_svc();
        let ns = NamespaceId::new();
        let (kek_id, _) = svc.generate_encrypted_kek(ns).await.unwrap();
        let original = [7u8; 32];
        let dek = Dek::from_bytes(&original).unwrap();
        let enc = svc.encrypt_dek(kek_id, &dek, "my-aad", ns).await.unwrap();
        let decrypted = svc.decrypt_dek(kek_id, &enc, "my-aad", ns).await.unwrap();
        assert_eq!(decrypted.as_slice(), &original);
    }

    #[tokio::test]
    async fn encrypt_decrypt_wrong_aad_fails() {
        let svc = make_svc();
        let ns = NamespaceId::new();
        let (kek_id, _) = svc.generate_encrypted_kek(ns).await.unwrap();
        let dek = Dek::from_bytes(&[3u8; 32]).unwrap();
        let enc = svc.encrypt_dek(kek_id, &dek, "correct-aad", ns).await.unwrap();
        let result = svc.decrypt_dek(kek_id, &enc, "wrong-aad", ns).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn kek_cache_hit_on_second_decrypt() {
        let svc = make_svc();
        let ns = NamespaceId::new();
        let (kek_id, _) = svc.generate_encrypted_kek(ns).await.unwrap();
        let dek = Dek::from_bytes(&[5u8; 32]).unwrap();
        let enc = svc.encrypt_dek(kek_id, &dek, "aad", ns).await.unwrap();
        let r1 = svc.decrypt_dek(kek_id, &enc, "aad", ns).await.unwrap();
        let r2 = svc.decrypt_dek(kek_id, &enc, "aad", ns).await.unwrap();
        assert_eq!(r1.as_slice(), r2.as_slice());
    }

    #[tokio::test]
    async fn multiple_keks_independent() {
        let svc = make_svc();
        let ns1 = NamespaceId::new();
        let ns2 = NamespaceId::new();
        let (kek1, _) = svc.generate_encrypted_kek(ns1).await.unwrap();
        let (kek2, _) = svc.generate_encrypted_kek(ns2).await.unwrap();
        assert_ne!(kek1, kek2);

        let dek1 = Dek::from_bytes(&[0xAAu8; 32]).unwrap();
        let dek2 = Dek::from_bytes(&[0xBBu8; 32]).unwrap();
        let enc1 = svc.encrypt_dek(kek1, &dek1, "aad1", ns1).await.unwrap();
        let enc2 = svc.encrypt_dek(kek2, &dek2, "aad2", ns2).await.unwrap();
        let dec1 = svc.decrypt_dek(kek1, &enc1, "aad1", ns1).await.unwrap();
        let dec2 = svc.decrypt_dek(kek2, &enc2, "aad2", ns2).await.unwrap();
        assert_eq!(dec1.as_slice(), &[0xAAu8; 32]);
        assert_eq!(dec2.as_slice(), &[0xBBu8; 32]);
    }
}
