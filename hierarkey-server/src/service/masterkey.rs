// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::MasterKeyManager;
use crate::ResolveOne;
use crate::audit_context::CallContext;
use crate::global::short_id::ShortId;
use crate::manager::masterkey::{
    MasterKey, MasterKeyBackend, MasterKeyFileType, MasterKeyStatus, MasterKeyUsage, MasterkeyId,
};
use crate::service::kek::MasterKeyRetrievable;
use crate::service::masterkey::keyring::{KeyRing, UnlockMaterial};
use crate::service::masterkey::provider::crypto::MasterKeyCryptoHandle;
use crate::service::masterkey::provider::{MasterKeyProvider, Pkcs11TokenInfo, UnlockArgs};

pub use crate::service::masterkey::provider::Pkcs11TokenInfo as MasterKeyPkcs11TokenInfo;
use crate::service::masterkey::registry::ProviderRegistry;
use async_trait::async_trait;
use clap::ValueEnum;
use hierarkey_core::{CkError, CkResult, Metadata};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use zeroize::Zeroizing;

pub mod backend;
pub mod keyring;
pub mod provider;
mod registry;

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Debug, ValueEnum, Copy)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "kebab_case")]
pub enum MasterKeyProviderType {
    Insecure,
    Passphrase,
    Pkcs11,
}

impl std::fmt::Display for MasterKeyProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MasterKeyProviderType::Insecure => "insecure",
            MasterKeyProviderType::Passphrase => "passphrase",
            MasterKeyProviderType::Pkcs11 => "pkcs11",
        };
        write!(f, "{s}")
    }
}

pub enum MasterKeyActivateOutcome {
    // Key is successfully activated
    Activated,
    // Key was already activated
    AlreadyActivated,
}

#[derive(Error, Debug)]
pub enum MasterKeyActivateError {
    #[error("master key not loaded into keyring")]
    NotLoaded,
    #[error("master key is locked")]
    Locked,
    #[error("master key provider error: {0}")]
    CkError(#[from] CkError),
}

pub type ActivateResult = Result<MasterKeyActivateOutcome, MasterKeyActivateError>;

// --------------------------------------------------------------------------------------------

pub enum MasterKeyUnlockOutcome {
    // Key is successfully unlocked
    Unlocked,
    // Key was already unlocked
    AlreadyUnlocked,
}

#[derive(Error, Debug)]
pub enum MasterKeyUnlockError {
    #[error("invalid unlock data provided")]
    InvalidUnlockData, // HTTP status 400
    #[error("authentication failed")]
    AuthenticationFailed, // HTTP status 422
    #[error("master key not loaded into keyring")]
    NotLoaded,
    #[error("master key provider error: {0}")]
    CkError(#[from] CkError),
}

pub type UnlockResult = Result<MasterKeyUnlockOutcome, MasterKeyUnlockError>;

// --------------------------------------------------------------------------------------------

pub enum MasterKeyLockOutcome {
    // Key is successfully locked
    Locked,
    // Key was already locked
    AlreadyLocked,
}

#[derive(Error, Debug)]
pub enum MasterKeyLockError {
    #[error("master key not loaded into keyring")]
    NotLoaded,
    #[error("master key provider error: {0}")]
    CkError(#[from] CkError),
}

pub type LockResult = Result<MasterKeyLockOutcome, MasterKeyLockError>;

// --------------------------------------------------------------------------------------------
/// PKCS#11 options for creating/loading a master key
#[derive(Serialize, Deserialize)]
pub struct Pkcs11Options {
    pub slot: Option<u64>,
    pub token_label: Option<String>,
    pub key_label: String,
}

/// Input parameters for creating a master key with a specific provider
pub enum ProviderCreateInput {
    Insecure,
    Passphrase {
        passphrase: Zeroizing<String>,
    },
    Pkcs11 {
        options: Pkcs11Options,
        pin: Option<Zeroizing<String>>,
    },
}

/// Generic information needed to create a new master key, independent of provider
pub struct CreateMasterKeyRequest {
    pub name: String,
    pub usage: MasterKeyUsage,
    pub metadata: Metadata,
    pub backend: BackendCreate,
    pub status: MasterKeyStatus,
}

/// Backend-specific parameters for creating a new master key
pub enum BackendCreate {
    Insecure {
        file_type: MasterKeyFileType,
    },
    Passphrase {
        file_type: MasterKeyFileType,
        // Non-saved passphrase for encrypting masterkey
        passphrase: Zeroizing<String>,
    },
    Pkcs11 {
        slot: Option<u64>,
        token_label: Option<String>,
        key_label: String,
        // Non-saved PIN for accessing the HSM
        pin: Option<Zeroizing<String>>,
    },
}

impl BackendCreate {
    /// Returns the backend type of the different create options
    pub fn backend_type(&self) -> MasterKeyBackend {
        match self {
            BackendCreate::Insecure { .. } => MasterKeyBackend::File,
            BackendCreate::Passphrase { .. } => MasterKeyBackend::File,
            BackendCreate::Pkcs11 { .. } => MasterKeyBackend::Pkcs11,
        }
    }

    pub fn file_type(&self) -> Option<MasterKeyFileType> {
        match self {
            BackendCreate::Insecure { file_type, .. } => Some(*file_type),
            BackendCreate::Passphrase { file_type, .. } => Some(*file_type),
            _ => None,
        }
    }

    /// Returns the PKCS#11 reference JSON if applicable
    pub fn pkcs11_ref(&self) -> Option<serde_json::Value> {
        match self {
            BackendCreate::Pkcs11 {
                slot,
                key_label,
                token_label,
                ..
            } => {
                let options = Pkcs11Options {
                    slot: *slot,
                    token_label: token_label.clone(),
                    key_label: key_label.clone(),
                };
                Some(serde_json::json!(options))
            }
            _ => Some(serde_json::Value::Null),
        }
    }

    /// Convert to provider-specific create input
    pub fn into_provider_input(&self) -> ProviderCreateInput {
        match self {
            BackendCreate::Insecure { .. } => ProviderCreateInput::Insecure,
            BackendCreate::Passphrase { passphrase, .. } => {
                // Cloning Zeroizing<String> is safe: the clone is also Zeroizing and
                // will be wiped on drop independently of the original.
                ProviderCreateInput::Passphrase {
                    passphrase: passphrase.clone(),
                }
            }
            BackendCreate::Pkcs11 {
                slot,
                token_label,
                key_label,
                pin,
            } => {
                let options = Pkcs11Options {
                    slot: *slot,
                    token_label: token_label.clone(),
                    key_label: key_label.clone(),
                };
                // Cloning Zeroizing<String> is safe: the clone is also Zeroizing and
                // will be wiped on drop independently of the original.
                ProviderCreateInput::Pkcs11 {
                    options,
                    pin: pin.clone(),
                }
            }
        }
    }
}
// --------------------------------------------------------------------------------------------

pub struct MasterKeyService {
    mk_manager: Arc<MasterKeyManager>,
    registry: ProviderRegistry,
    keyring: Arc<KeyRing>,
}

impl MasterKeyService {
    pub fn new(mk_manager: Arc<MasterKeyManager>) -> Self {
        Self {
            mk_manager,
            registry: ProviderRegistry::new(),
            keyring: Arc::new(KeyRing::new()),
        }
    }

    pub fn keyring(&self) -> Arc<KeyRing> {
        self.keyring.clone()
    }

    pub fn add_provider(&mut self, name: MasterKeyProviderType, provider: Box<dyn MasterKeyProvider>) {
        self.registry.add_provider(name, provider);
    }

    /// List token slots available on the PKCS#11 backend's default module.
    pub fn list_pkcs11_tokens(&self) -> CkResult<Vec<Pkcs11TokenInfo>> {
        let provider = self.registry.get_provider(MasterKeyProviderType::Pkcs11)?;
        provider.list_tokens()
    }

    pub async fn find_all(&self, _ctx: &CallContext) -> CkResult<Vec<MasterKey>> {
        self.mk_manager.find_all().await
    }

    pub async fn find_by_name(&self, _ctx: &CallContext, name: &str) -> CkResult<Option<MasterKey>> {
        self.mk_manager.find_by_name(name).await
    }

    pub async fn find_masterkey_by_id(
        &self,
        _ctx: &CallContext,
        masterkey_id: MasterkeyId,
    ) -> CkResult<Option<MasterKey>> {
        self.mk_manager.find_masterkey_by_id(masterkey_id).await
    }

    pub async fn resolve_short_masterkey_id(&self, prefix: &str) -> CkResult<ResolveOne<MasterkeyId>> {
        self.mk_manager.resolve_short_masterkey_id(prefix).await
    }

    pub async fn create_master_key(&self, ctx: &CallContext, req: &CreateMasterKeyRequest) -> CkResult<MasterKey> {
        // Reject duplicate names
        if self.mk_manager.find_by_name(&req.name).await?.is_some() {
            return Err(CkError::Conflict {
                what: format!("A master key with the name '{}' already exists", req.name),
            });
        }

        // Get the provider input from the request
        let create_input = req.backend.into_provider_input();

        // Create our new master key structure
        let mut master_key = MasterKey {
            id: MasterkeyId::new(),
            short_id: ShortId::generate("mk_", 12),
            name: req.name.clone(),
            usage: req.usage,
            status: req.status,
            backend: req.backend.backend_type(),
            file_type: req.backend.file_type(),
            file_path: None,
            file_sha256: None,
            pkcs11_ref: req.backend.pkcs11_ref(),
            created_at: chrono::Utc::now(),
            created_by: None,
            updated_at: None,
            updated_by: None,
            retired_at: None,
            metadata: req.metadata.clone(),
            retired_by: None,
        };

        // Find the provider thatcan handle this master key
        let provider_type = self.registry.get_provider_type(&master_key)?;
        let provider = self.registry.get_provider(provider_type)?;

        // Create the actual masterkey data (if needed) via the provider, and update the
        // master key structure accordingly
        provider.create_masterkey_data(&mut master_key, &create_input)?;

        // Now we can store the master key version in the database
        self.mk_manager.create(ctx, &master_key).await?;
        Ok(master_key)
    }

    /// Load a master key version into the keyring (locked or unlocked depending on provider).
    pub async fn load_into_keyring(&self, ctx: &CallContext, master_key: &MasterKey) -> CkResult<()> {
        let actor = ctx.actor.account_id().copied();
        // Resolve provider deterministically from MKV metadata
        let provider_type = self.registry.get_provider_type(master_key)?;
        let provider = self.registry.get_provider(provider_type)?;

        // Ask provider to load backend material (file parse/validate/checksum etc)
        let loaded = provider.load_material(master_key, actor)?;

        // Store in keyring according to startup disposition
        match loaded.startup {
            provider::StartupDisposition::Locked { reason } => {
                println!(
                    "  [ WARN ]  {:<18}  {} ({}) loaded as LOCKED",
                    "Master key", master_key.name, master_key.short_id
                );
                self.keyring
                    .insert_loaded_locked(master_key, provider_type, loaded.material, actor, reason)?;
            }
            provider::StartupDisposition::Unlocked => {
                println!(
                    "  [  OK  ]  {:<18}  {} ({}) loaded",
                    "Master key", master_key.name, master_key.short_id
                );
                let crypto = loaded.crypto_if_unlocked.ok_or_else(|| {
                    CkError::MasterKey("provider requested Unlocked startup but returned no crypto handle".into())
                })?;

                self.keyring
                    .insert_loaded_unlocked(master_key, provider_type, loaded.material, crypto, actor)?;
            }
        }

        Ok(())
    }

    /// Check locked status
    pub fn is_locked(&self, _ctx: &CallContext, master_key: &MasterKey) -> CkResult<bool> {
        self.keyring.is_locked(master_key)
    }

    pub async fn activate(&self, ctx: &CallContext, master_key: &MasterKey) -> ActivateResult {
        if !self.keyring.contains(master_key) {
            return Err(MasterKeyActivateError::NotLoaded);
        }

        if self.keyring.is_locked(master_key)? {
            return Err(MasterKeyActivateError::Locked);
        }

        // If already activated
        if master_key.status == MasterKeyStatus::Active {
            return Ok(MasterKeyActivateOutcome::AlreadyActivated);
        }

        self.mk_manager.set_active(ctx, master_key.id).await?;
        Ok(MasterKeyActivateOutcome::Activated)
    }

    /// Transition a master key to Retired status. The key must be Draining (or Pending).
    /// The caller is responsible for ensuring no KEKs remain wrapped under it.
    pub async fn retire(&self, ctx: &CallContext, master_key: &MasterKey) -> CkResult<()> {
        self.mk_manager.retire(ctx, master_key.id).await
    }

    /// Permanently delete a master key. Only Retired keys may be deleted.
    pub async fn delete(&self, ctx: &CallContext, master_key: &MasterKey) -> CkResult<()> {
        if master_key.status != MasterKeyStatus::Retired {
            return Err(CkError::Conflict {
                what: format!(
                    "Master key '{}' is not retired (status: {}). Only retired master keys can be deleted.",
                    master_key.name, master_key.status
                ),
            });
        }
        self.mk_manager.delete(ctx, master_key.id).await
    }

    /// Lock a loaded key version
    pub fn lock(&self, ctx: &CallContext, master_key: &MasterKey, reason: Option<String>) -> LockResult {
        let actor = ctx.actor.account_id().copied();
        if !self.keyring.contains(master_key) {
            return Err(MasterKeyLockError::NotLoaded);
        }

        // If already locked
        if self.keyring.is_locked(master_key)? {
            return Ok(MasterKeyLockOutcome::AlreadyLocked);
        }

        self.keyring.mark_locked(master_key, actor, reason)?;
        Ok(MasterKeyLockOutcome::Locked)
    }

    /// Unlock a loaded key version.
    pub fn unlock(&self, ctx: &CallContext, master_key: &MasterKey, args: &UnlockArgs) -> UnlockResult {
        let actor = ctx.actor.account_id().copied();
        if !self.keyring.contains(master_key) {
            return Err(MasterKeyUnlockError::NotLoaded);
        }

        // If already unlocked
        if !self.keyring.is_locked(master_key)? {
            return Ok(MasterKeyUnlockOutcome::AlreadyUnlocked);
        }

        // Determine provider for this loaded entry
        let provider_type = self.registry.get_provider_type(master_key)?;
        let provider = self.registry.get_provider(provider_type)?;

        // Clone unlock material for this MKV
        let material: UnlockMaterial = self.keyring.clone_material(master_key)?;

        // Provider produces crypto handle (KDF, decrypt, PKCS11 login, etc.)
        let crypto = provider
            .unlock_to_crypto(master_key, &material, args, actor)
            .map_err(|e| match e {
                CkError::InvalidCredentials => MasterKeyUnlockError::AuthenticationFailed,
                other => MasterKeyUnlockError::CkError(other),
            })?;

        // Transition keyring state
        self.keyring.mark_unlocked(master_key, crypto, actor)?;

        Ok(MasterKeyUnlockOutcome::Unlocked)
    }

    pub async fn load_masterkeys_into_keyring(&self) -> CkResult<()> {
        let ctx = CallContext::system();
        let master_keys: Vec<MasterKey> = self.find_all(&ctx).await?;
        for master_key in master_keys {
            // Retired keys are fully decommissioned — no KEKs reference them, so they
            // don't need to be in the keyring. Active, Draining, and Pending keys must
            // be loaded (Pending keys are loaded so they can be activated without restart).
            if master_key.status == MasterKeyStatus::Retired {
                continue;
            }
            if self.keyring.contains(&master_key) {
                continue;
            }
            self.load_into_keyring(&ctx, &master_key).await?;
        }

        Ok(())
    }

    pub async fn has_active_masterkey(&self, ctx: &CallContext) -> CkResult<bool> {
        let master_keys: Vec<MasterKey> = self.find_all(ctx).await?;
        let active_mk = master_keys.iter().find(|k| k.status == MasterKeyStatus::Active);

        Ok(active_mk.is_some())
    }

    pub async fn is_active_masterkey_locked(&self, ctx: &CallContext) -> CkResult<bool> {
        let master_keys: Vec<MasterKey> = self.find_all(ctx).await?;
        let active_mk = master_keys.iter().find(|k| k.status == MasterKeyStatus::Active);

        match active_mk {
            None => Err(CkError::MasterKey("no active master key found".into())),
            Some(mk) => self.is_locked(ctx, mk),
        }
    }

    /// Returns true if any Draining key is locked. A locked draining key means its
    /// KEKs cannot be decrypted, making some secrets temporarily unreadable.
    pub async fn any_draining_key_locked(&self, ctx: &CallContext) -> CkResult<bool> {
        let master_keys: Vec<MasterKey> = self.find_all(ctx).await?;
        for mk in master_keys.iter().filter(|k| k.status == MasterKeyStatus::Draining) {
            if self.is_locked(ctx, mk)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[async_trait]
impl MasterKeyRetrievable for MasterKeyService {
    async fn find_active(&self, usage: MasterKeyUsage) -> CkResult<Option<MasterKey>> {
        self.mk_manager.find_active_masterkey(usage).await
    }

    async fn find_by_id(&self, id: MasterkeyId) -> CkResult<Option<MasterKey>> {
        self.mk_manager.find_masterkey_by_id(id).await
    }

    fn crypto_for(&self, master_key: &MasterKey) -> CkResult<MasterKeyCryptoHandle> {
        // Ensure loaded
        if !self.keyring.contains(master_key) {
            return Err(CkError::MasterKey("master key not loaded".into()));
        }

        // Ensure unlocked
        if self.keyring.is_locked(master_key)? {
            return Err(CkError::MasterKey("master key is locked".into()));
        }

        self.keyring.get_crypto(master_key)
    }
}

impl MasterKeyService {
    /// Get the decrypted crypto handle for a master key (must be loaded and unlocked).
    /// Exposed for the CLI recovery path.
    pub fn get_crypto_handle(&self, master_key: &MasterKey) -> CkResult<MasterKeyCryptoHandle> {
        self.crypto_for(master_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::manager::masterkey::{
        InMemoryMasterKeyStore, MasterKeyBackend, MasterKeyFileType, MasterKeyManager, MasterKeyStatus, MasterKeyUsage,
    };
    use crate::service::masterkey::provider::{TestMasterKeyProvider, UnlockArgs};
    use hierarkey_core::Metadata;
    use std::sync::Arc;

    fn make_svc() -> MasterKeyService {
        let mk_store = Arc::new(InMemoryMasterKeyStore::new());
        let mk_manager = Arc::new(MasterKeyManager::new(mk_store).unwrap());
        let mut svc = MasterKeyService::new(mk_manager);
        svc.add_provider(MasterKeyProviderType::Insecure, Box::new(TestMasterKeyProvider::new()));
        svc
    }

    fn insecure_req(name: &str, status: MasterKeyStatus) -> CreateMasterKeyRequest {
        CreateMasterKeyRequest {
            name: name.into(),
            usage: MasterKeyUsage::WrapKek,
            metadata: Metadata::default(),
            backend: BackendCreate::Insecure {
                file_type: MasterKeyFileType::Insecure,
            },
            status,
        }
    }

    async fn create_mk(svc: &MasterKeyService, name: &str, status: MasterKeyStatus) -> MasterKey {
        let req = insecure_req(name, status);
        svc.create_master_key(&CallContext::system(), &req).await.unwrap()
    }

    // ---- find_all / find_by_name ----

    #[tokio::test]
    async fn find_all_empty() {
        let svc = make_svc();
        let all = svc.find_all(&CallContext::system()).await.unwrap();
        assert!(all.is_empty());
    }

    #[tokio::test]
    async fn find_all_after_create() {
        let svc = make_svc();
        create_mk(&svc, "mk1", MasterKeyStatus::Active).await;
        create_mk(&svc, "mk2", MasterKeyStatus::Retired).await;
        let all = svc.find_all(&CallContext::system()).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn find_by_name_not_found() {
        let svc = make_svc();
        let found = svc.find_by_name(&CallContext::system(), "ghost").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn find_by_name_found() {
        let svc = make_svc();
        create_mk(&svc, "named-mk", MasterKeyStatus::Active).await;
        let found = svc.find_by_name(&CallContext::system(), "named-mk").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "named-mk");
    }

    // ---- create_master_key ----

    #[tokio::test]
    async fn create_master_key_success() {
        let svc = make_svc();
        let mk = create_mk(&svc, "new-mk", MasterKeyStatus::Active).await;
        assert_eq!(mk.name, "new-mk");
        assert_eq!(mk.usage, MasterKeyUsage::WrapKek);
        assert!(mk.file_path.is_some());
        assert!(mk.file_sha256.is_some());
    }

    #[tokio::test]
    async fn create_master_key_duplicate_name_fails() {
        let svc = make_svc();
        create_mk(&svc, "duplicate", MasterKeyStatus::Active).await;
        let req = insecure_req("duplicate", MasterKeyStatus::Active);
        let result = svc.create_master_key(&CallContext::system(), &req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CkError::Conflict { .. }), "expected Conflict, got: {err:?}");
    }

    // ---- load_into_keyring / is_locked ----

    #[tokio::test]
    async fn load_into_keyring_unlocked_for_active_key() {
        let svc = make_svc();
        let mk = create_mk(&svc, "active-load", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        assert!(!svc.is_locked(&CallContext::system(), &mk).unwrap());
    }

    #[tokio::test]
    async fn load_into_keyring_and_lock() {
        let svc = make_svc();
        let mk = create_mk(&svc, "load-then-lock", MasterKeyStatus::Retired).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        svc.lock(&CallContext::system(), &mk, Some("test".into())).unwrap();
        assert!(svc.is_locked(&CallContext::system(), &mk).unwrap());
    }

    #[tokio::test]
    async fn load_into_keyring_idempotent() {
        let svc = make_svc();
        let mk = create_mk(&svc, "idempotent-load", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        assert!(!svc.is_locked(&CallContext::system(), &mk).unwrap());
    }

    // ---- activate ----

    #[tokio::test]
    async fn activate_not_loaded() {
        let svc = make_svc();
        let mk = create_mk(&svc, "unloaded", MasterKeyStatus::Retired).await;
        let result = svc.activate(&CallContext::system(), &mk).await;
        assert!(matches!(result, Err(MasterKeyActivateError::NotLoaded)));
    }

    #[tokio::test]
    async fn activate_locked() {
        let svc = make_svc();
        let mk = create_mk(&svc, "locked-activate", MasterKeyStatus::Retired).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        svc.lock(&CallContext::system(), &mk, None).unwrap();
        let result = svc.activate(&CallContext::system(), &mk).await;
        assert!(matches!(result, Err(MasterKeyActivateError::Locked)));
    }

    #[tokio::test]
    async fn activate_already_active() {
        let svc = make_svc();
        let mk = create_mk(&svc, "already-active", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        let result = svc.activate(&CallContext::system(), &mk).await;
        assert!(matches!(result, Ok(MasterKeyActivateOutcome::AlreadyActivated)));
    }

    #[tokio::test]
    async fn activate_success() {
        let svc = make_svc();
        let mk = create_mk(&svc, "to-activate", MasterKeyStatus::Retired).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        let result = svc.activate(&CallContext::system(), &mk).await;
        assert!(matches!(result, Ok(MasterKeyActivateOutcome::Activated)));
    }

    // ---- lock ----

    #[tokio::test]
    async fn lock_not_loaded() {
        let svc = make_svc();
        let mk = create_mk(&svc, "unloaded-lock", MasterKeyStatus::Active).await;
        let result = svc.lock(&CallContext::system(), &mk, None);
        assert!(matches!(result, Err(MasterKeyLockError::NotLoaded)));
    }

    #[tokio::test]
    async fn lock_already_locked() {
        let svc = make_svc();
        let mk = create_mk(&svc, "already-locked", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        svc.lock(&CallContext::system(), &mk, None).unwrap();
        let result = svc.lock(&CallContext::system(), &mk, None);
        assert!(matches!(result, Ok(MasterKeyLockOutcome::AlreadyLocked)));
    }

    #[tokio::test]
    async fn lock_success() {
        let svc = make_svc();
        let mk = create_mk(&svc, "to-lock", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        let result = svc.lock(&CallContext::system(), &mk, Some("test reason".into()));
        assert!(matches!(result, Ok(MasterKeyLockOutcome::Locked)));
        assert!(svc.is_locked(&CallContext::system(), &mk).unwrap());
    }

    // ---- unlock ----

    #[tokio::test]
    async fn unlock_not_loaded() {
        let svc = make_svc();
        let mk = create_mk(&svc, "unloaded-unlock", MasterKeyStatus::Active).await;
        let result = svc.unlock(&CallContext::system(), &mk, &UnlockArgs::None);
        assert!(matches!(result, Err(MasterKeyUnlockError::NotLoaded)));
    }

    #[tokio::test]
    async fn unlock_already_unlocked() {
        let svc = make_svc();
        let mk = create_mk(&svc, "already-unlocked", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        let result = svc.unlock(&CallContext::system(), &mk, &UnlockArgs::None);
        assert!(matches!(result, Ok(MasterKeyUnlockOutcome::AlreadyUnlocked)));
    }

    #[tokio::test]
    async fn unlock_success() {
        let svc = make_svc();
        let mk = create_mk(&svc, "to-unlock", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        svc.lock(&CallContext::system(), &mk, None).unwrap();
        assert!(svc.is_locked(&CallContext::system(), &mk).unwrap());
        let result = svc.unlock(&CallContext::system(), &mk, &UnlockArgs::None);
        assert!(matches!(result, Ok(MasterKeyUnlockOutcome::Unlocked)));
        assert!(!svc.is_locked(&CallContext::system(), &mk).unwrap());
    }

    // ---- load_masterkeys_into_keyring ----

    #[tokio::test]
    async fn load_masterkeys_into_keyring_loads_active_and_draining() {
        let svc = make_svc();
        create_mk(&svc, "bulk-active", MasterKeyStatus::Active).await;
        create_mk(&svc, "bulk-draining", MasterKeyStatus::Draining).await;
        create_mk(&svc, "bulk-pending", MasterKeyStatus::Pending).await;
        create_mk(&svc, "bulk-retired", MasterKeyStatus::Retired).await;
        svc.load_masterkeys_into_keyring().await.unwrap();
        // Active, Draining, and Pending are loaded; Retired is skipped
        assert_eq!(svc.keyring().len(), 3);
    }

    #[tokio::test]
    async fn load_masterkeys_into_keyring_skips_already_loaded() {
        let svc = make_svc();
        let mk = create_mk(&svc, "skip-reload", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        // Calling again should not error
        svc.load_masterkeys_into_keyring().await.unwrap();
        assert_eq!(svc.keyring().len(), 1);
    }

    // ---- has_active_masterkey ----

    #[tokio::test]
    async fn has_active_masterkey_none() {
        let svc = make_svc();
        assert!(!svc.has_active_masterkey(&CallContext::system()).await.unwrap());
    }

    #[tokio::test]
    async fn has_active_masterkey_yes() {
        let svc = make_svc();
        create_mk(&svc, "active-check", MasterKeyStatus::Active).await;
        assert!(svc.has_active_masterkey(&CallContext::system()).await.unwrap());
    }

    #[tokio::test]
    async fn has_active_masterkey_only_retired() {
        let svc = make_svc();
        create_mk(&svc, "retired-only", MasterKeyStatus::Retired).await;
        assert!(!svc.has_active_masterkey(&CallContext::system()).await.unwrap());
    }

    // ---- is_active_masterkey_locked ----

    #[tokio::test]
    async fn is_active_masterkey_locked_no_active_key() {
        let svc = make_svc();
        let result = svc.is_active_masterkey_locked(&CallContext::system()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn is_active_masterkey_locked_false() {
        let svc = make_svc();
        let mk = create_mk(&svc, "active-unlocked", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        let locked = svc.is_active_masterkey_locked(&CallContext::system()).await.unwrap();
        assert!(!locked);
    }

    #[tokio::test]
    async fn is_active_masterkey_locked_true() {
        let svc = make_svc();
        let mk = create_mk(&svc, "active-to-lock", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        svc.lock(&CallContext::system(), &mk, None).unwrap();
        let locked = svc.is_active_masterkey_locked(&CallContext::system()).await.unwrap();
        assert!(locked);
    }

    // ---- any_draining_key_locked ----

    #[tokio::test]
    async fn any_draining_key_locked_no_draining_keys() {
        let svc = make_svc();
        let mk = create_mk(&svc, "active-no-draining", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        assert!(!svc.any_draining_key_locked(&CallContext::system()).await.unwrap());
    }

    #[tokio::test]
    async fn any_draining_key_locked_unlocked() {
        let svc = make_svc();
        let mk = create_mk(&svc, "draining-unlocked", MasterKeyStatus::Draining).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        assert!(!svc.any_draining_key_locked(&CallContext::system()).await.unwrap());
    }

    #[tokio::test]
    async fn any_draining_key_locked_one_locked() {
        let svc = make_svc();
        let mk = create_mk(&svc, "draining-locked", MasterKeyStatus::Draining).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        svc.lock(&CallContext::system(), &mk, None).unwrap();
        assert!(svc.any_draining_key_locked(&CallContext::system()).await.unwrap());
    }

    // ---- MasterKeyRetrievable impl ----

    #[tokio::test]
    async fn find_active_returns_none_when_empty() {
        let svc = make_svc();
        let result = svc.find_active(MasterKeyUsage::WrapKek).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn find_active_returns_active_key() {
        let svc = make_svc();
        create_mk(&svc, "retrieval-active", MasterKeyStatus::Active).await;
        let result = svc.find_active(MasterKeyUsage::WrapKek).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status, MasterKeyStatus::Active);
    }

    #[tokio::test]
    async fn crypto_for_not_loaded_returns_error() {
        let svc = make_svc();
        let mk = create_mk(&svc, "crypto-not-loaded", MasterKeyStatus::Active).await;
        let result = svc.crypto_for(&mk);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn crypto_for_locked_returns_error() {
        let svc = make_svc();
        let mk = create_mk(&svc, "crypto-locked", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        svc.lock(&CallContext::system(), &mk, None).unwrap();
        let result = svc.crypto_for(&mk);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn crypto_for_unlocked_returns_handle() {
        let svc = make_svc();
        let mk = create_mk(&svc, "crypto-unlocked", MasterKeyStatus::Active).await;
        svc.load_into_keyring(&CallContext::system(), &mk).await.unwrap();
        let result = svc.crypto_for(&mk);
        assert!(result.is_ok());
    }

    // ---- BackendCreate methods ----

    #[test]
    fn backend_create_insecure_type() {
        let bc = BackendCreate::Insecure {
            file_type: MasterKeyFileType::Insecure,
        };
        assert_eq!(bc.backend_type(), MasterKeyBackend::File);
        assert_eq!(bc.file_type(), Some(MasterKeyFileType::Insecure));
        assert!(bc.pkcs11_ref().is_some());
    }

    #[test]
    fn backend_create_passphrase_type() {
        let bc = BackendCreate::Passphrase {
            file_type: MasterKeyFileType::Passphrase,
            passphrase: zeroize::Zeroizing::new("secret".into()),
        };
        assert_eq!(bc.backend_type(), MasterKeyBackend::File);
        assert_eq!(bc.file_type(), Some(MasterKeyFileType::Passphrase));
    }

    #[test]
    fn backend_create_pkcs11_type() {
        let bc = BackendCreate::Pkcs11 {
            slot: Some(0),
            token_label: Some("label".into()),
            key_label: "key".into(),
            pin: None,
        };
        assert_eq!(bc.backend_type(), MasterKeyBackend::Pkcs11);
        assert_eq!(bc.file_type(), None);
        let ref_json = bc.pkcs11_ref().unwrap();
        assert!(ref_json.is_object());
    }

    #[test]
    fn backend_create_into_provider_input() {
        let bc_insecure = BackendCreate::Insecure {
            file_type: MasterKeyFileType::Insecure,
        };
        assert!(matches!(bc_insecure.into_provider_input(), ProviderCreateInput::Insecure));

        let bc_pass = BackendCreate::Passphrase {
            file_type: MasterKeyFileType::Passphrase,
            passphrase: zeroize::Zeroizing::new("pw".into()),
        };
        assert!(matches!(bc_pass.into_provider_input(), ProviderCreateInput::Passphrase { .. }));
    }

    // ---- Display impls ----

    #[test]
    fn provider_type_display() {
        assert_eq!(MasterKeyProviderType::Insecure.to_string(), "insecure");
        assert_eq!(MasterKeyProviderType::Passphrase.to_string(), "passphrase");
        assert_eq!(MasterKeyProviderType::Pkcs11.to_string(), "pkcs11");
    }

    #[test]
    fn error_types_display() {
        assert!(!MasterKeyActivateError::NotLoaded.to_string().is_empty());
        assert!(!MasterKeyActivateError::Locked.to_string().is_empty());
        assert!(!MasterKeyLockError::NotLoaded.to_string().is_empty());
        assert!(!MasterKeyUnlockError::NotLoaded.to_string().is_empty());
        assert!(!MasterKeyUnlockError::InvalidUnlockData.to_string().is_empty());
        assert!(!MasterKeyUnlockError::AuthenticationFailed.to_string().is_empty());
    }
}
