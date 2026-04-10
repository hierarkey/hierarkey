// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use base64::Engine;
use hierarkey_core::{CkError, CkResult};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::global::aes_gcm::CryptoAesGcm;
use crate::manager::account::AccountId;
use crate::manager::masterkey::{MasterKey, MasterKeyData};
use crate::manager::secret::secret_data::Secret32;

use crate::service::masterkey::backend::file_format::{
    FilePayload, FilePayloadKind, INSECURE_FILE_VERSION, checksum_matches, create_content_checksum,
    create_masterkey_checksum, decode_insecure_key, parse_payload, validate_payload,
};
use crate::service::masterkey::backend::memory_store::MemoryStore;

use crate::service::masterkey::ProviderCreateInput;
use crate::service::masterkey::keyring::UnlockMaterial;
use crate::service::masterkey::provider::UnlockArgs;
use crate::service::masterkey::provider::crypto::{AesGcmMasterKeyCrypto, MasterKeyCryptoHandle};
use crate::service::masterkey::provider::traits::{LoadedMaterial, MasterKeyProvider, StartupDisposition};

/// Test provider that behaves like the file-backed insecure provider,
/// but stores JSON blobs in-memory (MemoryStore) instead of writing to disk.
#[derive(Default)]
pub struct TestMasterKeyProvider {
    store: MemoryStore,
}

impl fmt::Debug for TestMasterKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestMasterKeyProvider").finish()
    }
}

impl TestMasterKeyProvider {
    pub fn new() -> Self {
        Self {
            store: MemoryStore::new(),
        }
    }

    fn derive_key_data(master_key: &MasterKey) -> MasterKeyData {
        let mut hasher = Sha256::new();
        hasher.update(b"hkey:test-provider:v1\0");
        hasher.update(master_key.id.as_bytes());
        hasher.update(b"\0");
        let digest = hasher.finalize();

        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&digest[..32]);
        MasterKeyData::from(out)
    }

    fn filename_for(master_key: &MasterKey) -> String {
        format!("test-masterkey-{}.json", master_key.id)
    }

    pub fn store(&self) -> &MemoryStore {
        &self.store
    }
}

impl MasterKeyProvider for TestMasterKeyProvider {
    fn create_masterkey_data(&self, master_key: &mut MasterKey, _input: &ProviderCreateInput) -> CkResult<()> {
        // Derive deterministic key bytes
        let key_data = Self::derive_key_data(master_key);
        let b64 = base64::engine::general_purpose::STANDARD.encode(key_data.as_slice());

        let payload = FilePayload::Insecure {
            created_at: chrono::Utc::now(),
            key: Zeroizing::new(b64),
            version: INSECURE_FILE_VERSION,
        };

        let content_checksum = create_content_checksum(&payload);
        let master_key_checksum = create_masterkey_checksum(master_key, &content_checksum, FilePayloadKind::Insecure);

        // Write payload into memory store under a “filename”
        let filename = Self::filename_for(master_key);
        let json = serde_json::to_value(&payload)?;
        self.store.write_json(&filename, &json)?;

        master_key.file_path = Some(filename.clone());
        master_key.file_sha256 = Some(master_key_checksum.clone());
        Ok(())
    }

    fn load_material(&self, master_key: &MasterKey, _actor: Option<AccountId>) -> CkResult<LoadedMaterial> {
        let Some(filename) = &master_key.file_path else {
            return Err(CkError::MasterKey("master key does not have a file path configured".into()));
        };

        // Read payload from MemoryStore
        let raw = self.store.read_to_string(filename)?;

        // Parse + validate payload
        let payload = parse_payload(&raw)?;
        validate_payload(&payload, FilePayloadKind::Insecure)?;

        // Validate checksum against mkv.file_sha256
        let Some(stored) = master_key.file_sha256.as_ref() else {
            return Err(CkError::MasterKey("master key does not have a file checksum configured".into()));
        };

        let content_checksum = create_content_checksum(&payload);
        let calculated = create_masterkey_checksum(master_key, &content_checksum, FilePayloadKind::Insecure);

        if !checksum_matches(&calculated, stored) {
            return Err(CkError::MasterKey("master key checksum mismatch".into()));
        }

        // Decode key data
        let key_data = decode_insecure_key(&payload)?;

        // Create crypto immediately (startup disposition: unlocked)
        let key = Secret32::new(*key_data.as_bytes());
        let aes = CryptoAesGcm::new(&key)?;
        let crypto: MasterKeyCryptoHandle = Arc::new(AesGcmMasterKeyCrypto::new(aes));

        Ok(LoadedMaterial {
            material: UnlockMaterial::Insecure {
                key_data: Arc::new(key_data),
            },
            startup: StartupDisposition::Unlocked,
            crypto_if_unlocked: Some(crypto),
        })
    }

    fn unlock_to_crypto(
        &self,
        _master_key: &MasterKey,
        material: &UnlockMaterial,
        args: &UnlockArgs,
        _actor: Option<AccountId>,
    ) -> CkResult<MasterKeyCryptoHandle> {
        match args {
            UnlockArgs::None => {}
            _ => return Err(CkError::MasterKey("invalid unlock arguments for test provider".into())),
        }

        let UnlockMaterial::Insecure { key_data } = material else {
            return Err(CkError::MasterKey("invalid unlock material for test provider".into()));
        };

        let key = Secret32::new(*key_data.as_bytes());
        let aes = CryptoAesGcm::new(&key)?;
        Ok(Arc::new(AesGcmMasterKeyCrypto::new(aes)))
    }
}
