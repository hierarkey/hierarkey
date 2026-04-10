// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::{CkError, CkResult};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::error;
use zeroize::Zeroizing;

#[cfg(test)]
use crate::global::short_id::ShortId;
use crate::manager::account::AccountId;
use crate::manager::masterkey::{MasterKey, MasterKeyData, MasterkeyId};
use crate::service::masterkey::backend::file_format::KdfParams;
use crate::service::masterkey::provider::crypto::MasterKeyCryptoHandle;

use super::MasterKeyProviderType;

/// Maximum number of entries in memory
pub const MAX_MASTERKEY_ENTRIES: usize = 1000;

#[derive(Debug, Clone)]
pub enum UnlockMaterial {
    /// Insecure: we keep the raw key bytes in memory so we can lock/unlock without disk.
    Insecure {
        key_data: Arc<MasterKeyData>, // Arc, because masterkeydata is not cloneable
    },
    /// Passphrase: keep KDF params and encrypted key blob (base64).
    Passphrase {
        kdf_params: KdfParams,
        b64_enc_key_data: Zeroizing<String>,
    },
    /// PKCS#11: keep reference JSON (label/slot/etc). Actual PIN is provided at unlock-time.
    Pkcs11 { pkcs11_ref: JsonValue },
}

#[derive(Debug)]
pub struct KeyEntry {
    pub provider: MasterKeyProviderType,

    pub locked: bool,
    pub crypto: Option<MasterKeyCryptoHandle>,
    pub material: UnlockMaterial,

    pub unlocked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub unlocked_by: Option<AccountId>,

    pub locked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub locked_by: Option<AccountId>,
    pub locked_reason: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyStatus {
    pub masterkey_id: MasterkeyId,
    pub provider: MasterKeyProviderType,
    pub locked: bool,

    pub unlocked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub unlocked_by_id: Option<AccountId>,
    pub unlocked_by_name: Option<String>,

    pub locked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub locked_by_id: Option<AccountId>,
    pub locked_by_name: Option<String>,
    pub locked_reason: Option<String>,
}

#[derive(Debug, Default)]
pub struct KeyRing {
    entries: RwLock<HashMap<MasterkeyId, KeyEntry>>,
}

impl KeyRing {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Returns `(locked_count, unlocked_count)` across all entries in the keyring.
    pub fn locked_unlocked_counts(&self) -> (usize, usize) {
        let guard = self.entries.read();
        let locked = guard.values().filter(|e| e.locked).count();
        let unlocked = guard.len() - locked;
        (locked, unlocked)
    }

    pub fn contains(&self, master_key: &MasterKey) -> bool {
        self.entries.read().contains_key(&master_key.id)
    }

    /// Inserts/overwrites an entry as "locked". No crypto handle is stored.
    pub fn insert_loaded_locked(
        &self,
        master_key: &MasterKey,
        provider: MasterKeyProviderType,
        material: UnlockMaterial,
        actor: Option<AccountId>,
        reason: Option<String>,
    ) -> CkResult<()> {
        self.ensure_capacity()?;

        let entry = KeyEntry {
            provider,
            locked: true,
            crypto: None,
            material,

            unlocked_at: None,
            unlocked_by: None,

            locked_at: Some(chrono::Utc::now()),
            locked_by: actor,
            locked_reason: reason.or_else(|| Some("Locked at load time".into())),
        };

        self.entries.write().insert(master_key.id, entry);
        Ok(())
    }

    // Inserts/overwrites an entry as "unlocked" with a crypto handle.
    pub fn insert_loaded_unlocked(
        &self,
        master_key: &MasterKey,
        provider: MasterKeyProviderType,
        material: UnlockMaterial,
        crypto: MasterKeyCryptoHandle,
        actor: Option<AccountId>,
    ) -> CkResult<()> {
        self.ensure_capacity()?;

        let entry = KeyEntry {
            provider,
            locked: false,
            crypto: Some(crypto),
            material,

            unlocked_at: Some(chrono::Utc::now()),
            unlocked_by: actor,

            locked_at: None,
            locked_by: None,
            locked_reason: None,
        };

        self.entries.write().insert(master_key.id, entry);
        Ok(())
    }

    pub fn remove(&self, master_key: &MasterKey) {
        self.entries.write().remove(&master_key.id);
    }

    pub fn clear(&self) {
        self.entries.write().clear();
    }

    pub fn is_locked(&self, master_key: &MasterKey) -> CkResult<bool> {
        let guard = self.entries.read();
        let entry = guard.get(&master_key.id).ok_or_else(|| CkError::ResourceNotFound {
            kind: "master_key",
            id: master_key.id.to_string(),
        })?;

        Ok(entry.locked)
    }

    pub fn provider_for(&self, master_key: &MasterKey) -> CkResult<MasterKeyProviderType> {
        let guard = self.entries.read();
        let entry = guard.get(&master_key.id).ok_or_else(|| CkError::ResourceNotFound {
            kind: "master_key",
            id: master_key.id.to_string(),
        })?;
        Ok(entry.provider)
    }

    pub fn clone_material(&self, master_key: &MasterKey) -> CkResult<UnlockMaterial> {
        let guard = self.entries.read();
        let entry = guard.get(&master_key.id).ok_or_else(|| CkError::ResourceNotFound {
            kind: "master_key",
            id: master_key.id.to_string(),
        })?;

        Ok(entry.material.clone())
    }

    // Called after the service/provider has produced a crypto handle.
    pub fn mark_unlocked(
        &self,
        master_key: &MasterKey,
        crypto: MasterKeyCryptoHandle,
        actor: Option<AccountId>,
    ) -> CkResult<()> {
        let mut guard = self.entries.write();
        let entry = guard.get_mut(&master_key.id).ok_or_else(|| CkError::ResourceNotFound {
            kind: "master_key",
            id: master_key.id.to_string(),
        })?;

        if !entry.locked {
            return Err(CkError::MasterKey("key is already unlocked".into()));
        }

        entry.crypto = Some(crypto);
        entry.locked = false;

        entry.unlocked_at = Some(chrono::Utc::now());
        entry.unlocked_by = actor;

        entry.locked_at = None;
        entry.locked_by = None;
        entry.locked_reason = None;

        Ok(())
    }

    // This wipes the crypto handle, but keeps unlock material so it can be unlocked later.
    pub fn mark_locked(
        &self,
        master_key: &MasterKey,
        actor: Option<AccountId>,
        reason: Option<String>,
    ) -> CkResult<()> {
        let mut guard = self.entries.write();
        let entry = guard.get_mut(&master_key.id).ok_or_else(|| CkError::ResourceNotFound {
            kind: "master_key",
            id: master_key.id.to_string(),
        })?;

        if entry.locked {
            return Err(CkError::MasterKey("key is already locked".into()));
        }

        entry.crypto = None;
        entry.locked = true;

        entry.locked_at = Some(chrono::Utc::now());
        entry.locked_by = actor;
        entry.locked_reason = reason;

        entry.unlocked_at = None;
        entry.unlocked_by = None;

        Ok(())
    }

    // Returns the crypto handle if unlocked (used by KEK wrap/unwrap paths).
    pub fn get_crypto(&self, master_key: &MasterKey) -> CkResult<MasterKeyCryptoHandle> {
        let guard = self.entries.read();
        let entry = guard.get(&master_key.id).ok_or_else(|| CkError::ResourceNotFound {
            kind: "master_key",
            id: master_key.id.to_string(),
        })?;

        if entry.locked {
            return Err(CkError::MasterKey("master key is locked".into()));
        }

        entry
            .crypto
            .clone()
            .ok_or_else(|| CkError::MasterKey("missing crypto handle for unlocked key".into()))
    }

    pub fn status(&self, master_key: &MasterKey) -> CkResult<KeyStatus> {
        let guard = self.entries.read();
        let entry = guard.get(&master_key.id).ok_or_else(|| CkError::ResourceNotFound {
            kind: "master_key",
            id: master_key.id.to_string(),
        })?;

        Ok(KeyStatus {
            masterkey_id: master_key.id,
            provider: entry.provider,
            locked: entry.locked,

            unlocked_at: entry.unlocked_at,
            unlocked_by_id: entry.unlocked_by,
            unlocked_by_name: None,

            locked_at: entry.locked_at,
            locked_by_id: entry.locked_by,
            locked_by_name: None,
            locked_reason: entry.locked_reason.clone(),
        })
    }

    fn ensure_capacity(&self) -> CkResult<()> {
        let len = self.entries.read().len();
        if len >= MAX_MASTERKEY_ENTRIES {
            error!("maximum number of loaded master keys exceeded ({})", MAX_MASTERKEY_ENTRIES);
            return Err(CkError::MasterKey("maximum number of loaded master keys exceeded".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::global::aes_gcm::CryptoAesGcm;
    use crate::manager::masterkey::{
        MasterKeyBackend, MasterKeyFileType, MasterKeyStatus, MasterKeyUsage, MasterkeyId,
    };
    use crate::manager::secret::secret_data::Secret32;
    use crate::service::masterkey::provider::crypto::AesGcmMasterKeyCrypto;
    use hierarkey_core::Metadata;

    fn make_mk() -> MasterKey {
        MasterKey {
            id: MasterkeyId(uuid::Uuid::new_v4()),
            short_id: ShortId::generate("mk_", 12),
            name: "test-key".into(),
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
        }
    }

    fn make_material() -> UnlockMaterial {
        let data = Arc::new(crate::manager::masterkey::MasterKeyData::from([42u8; 32]));
        UnlockMaterial::Insecure { key_data: data }
    }

    fn make_crypto() -> MasterKeyCryptoHandle {
        let key = Secret32::new([42u8; 32]);
        let aes = CryptoAesGcm::new(&key).unwrap();
        Arc::new(AesGcmMasterKeyCrypto::new(aes))
    }

    #[test]
    fn new_keyring_is_empty() {
        let ring = KeyRing::new();
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn insert_locked_and_contains() {
        let ring = KeyRing::new();
        let mk = make_mk();
        ring.insert_loaded_locked(&mk, MasterKeyProviderType::Insecure, make_material(), None, None)
            .unwrap();
        assert!(ring.contains(&mk));
        assert_eq!(ring.len(), 1);
        assert!(!ring.is_empty());
    }

    #[test]
    fn insert_locked_is_locked() {
        let ring = KeyRing::new();
        let mk = make_mk();
        ring.insert_loaded_locked(&mk, MasterKeyProviderType::Insecure, make_material(), None, None)
            .unwrap();
        assert!(ring.is_locked(&mk).unwrap());
    }

    #[test]
    fn insert_unlocked_is_not_locked() {
        let ring = KeyRing::new();
        let mk = make_mk();
        ring.insert_loaded_unlocked(&mk, MasterKeyProviderType::Insecure, make_material(), make_crypto(), None)
            .unwrap();
        assert!(!ring.is_locked(&mk).unwrap());
    }

    #[test]
    fn get_crypto_on_unlocked_succeeds() {
        let ring = KeyRing::new();
        let mk = make_mk();
        ring.insert_loaded_unlocked(&mk, MasterKeyProviderType::Insecure, make_material(), make_crypto(), None)
            .unwrap();
        assert!(ring.get_crypto(&mk).is_ok());
    }

    #[test]
    fn get_crypto_on_locked_fails() {
        let ring = KeyRing::new();
        let mk = make_mk();
        ring.insert_loaded_locked(&mk, MasterKeyProviderType::Insecure, make_material(), None, None)
            .unwrap();
        assert!(ring.get_crypto(&mk).is_err());
    }

    #[test]
    fn get_crypto_on_missing_fails() {
        let ring = KeyRing::new();
        let mk = make_mk();
        assert!(ring.get_crypto(&mk).is_err());
    }

    #[test]
    fn mark_unlocked_transitions_state() {
        let ring = KeyRing::new();
        let mk = make_mk();
        ring.insert_loaded_locked(&mk, MasterKeyProviderType::Insecure, make_material(), None, None)
            .unwrap();
        ring.mark_unlocked(&mk, make_crypto(), None).unwrap();
        assert!(!ring.is_locked(&mk).unwrap());
        assert!(ring.get_crypto(&mk).is_ok());
    }

    #[test]
    fn mark_unlocked_on_already_unlocked_fails() {
        let ring = KeyRing::new();
        let mk = make_mk();
        ring.insert_loaded_unlocked(&mk, MasterKeyProviderType::Insecure, make_material(), make_crypto(), None)
            .unwrap();
        assert!(ring.mark_unlocked(&mk, make_crypto(), None).is_err());
    }

    #[test]
    fn mark_locked_transitions_state() {
        let ring = KeyRing::new();
        let mk = make_mk();
        ring.insert_loaded_unlocked(&mk, MasterKeyProviderType::Insecure, make_material(), make_crypto(), None)
            .unwrap();
        ring.mark_locked(&mk, None, None).unwrap();
        assert!(ring.is_locked(&mk).unwrap());
        assert!(ring.get_crypto(&mk).is_err());
    }

    #[test]
    fn mark_locked_on_already_locked_fails() {
        let ring = KeyRing::new();
        let mk = make_mk();
        ring.insert_loaded_locked(&mk, MasterKeyProviderType::Insecure, make_material(), None, None)
            .unwrap();
        assert!(ring.mark_locked(&mk, None, None).is_err());
    }

    #[test]
    fn remove_entry() {
        let ring = KeyRing::new();
        let mk = make_mk();
        ring.insert_loaded_locked(&mk, MasterKeyProviderType::Insecure, make_material(), None, None)
            .unwrap();
        ring.remove(&mk);
        assert!(!ring.contains(&mk));
        assert!(ring.is_empty());
    }

    #[test]
    fn clear_empties_ring() {
        let ring = KeyRing::new();
        let mk1 = make_mk();
        let mk2 = make_mk();
        ring.insert_loaded_locked(&mk1, MasterKeyProviderType::Insecure, make_material(), None, None)
            .unwrap();
        ring.insert_loaded_locked(&mk2, MasterKeyProviderType::Insecure, make_material(), None, None)
            .unwrap();
        assert_eq!(ring.len(), 2);
        ring.clear();
        assert!(ring.is_empty());
    }

    #[test]
    fn provider_for_returns_correct_type() {
        let ring = KeyRing::new();
        let mk = make_mk();
        ring.insert_loaded_locked(&mk, MasterKeyProviderType::Insecure, make_material(), None, None)
            .unwrap();
        assert_eq!(ring.provider_for(&mk).unwrap(), MasterKeyProviderType::Insecure);
    }

    #[test]
    fn status_reflects_locked_state() {
        let ring = KeyRing::new();
        let mk = make_mk();
        ring.insert_loaded_locked(
            &mk,
            MasterKeyProviderType::Insecure,
            make_material(),
            None,
            Some("test reason".into()),
        )
        .unwrap();
        let status = ring.status(&mk).unwrap();
        assert!(status.locked);
        assert_eq!(status.masterkey_id, mk.id);
        assert!(status.locked_reason.is_some());
    }

    #[test]
    fn status_on_missing_key_fails() {
        let ring = KeyRing::new();
        let mk = make_mk();
        assert!(ring.status(&mk).is_err());
    }

    #[test]
    fn is_locked_on_missing_key_fails() {
        let ring = KeyRing::new();
        let mk = make_mk();
        assert!(ring.is_locked(&mk).is_err());
    }
}
