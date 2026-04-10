// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use std::fmt::Debug;

use hierarkey_core::{CkError, CkResult};
use serde::{Deserialize, Serialize};

use crate::manager::account::AccountId;
use crate::manager::masterkey::MasterKey;

use super::UnlockArgs;
use super::crypto::MasterKeyCryptoHandle;
use crate::service::masterkey::ProviderCreateInput;
use crate::service::masterkey::keyring::UnlockMaterial;

/// Information about a single token slot returned by `list_tokens()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pkcs11TokenInfo {
    pub slot_id: u64,
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
}

/// Provider startup behavior: should a loaded key be locked or unlocked initially?
#[derive(Debug, Clone)]
pub enum StartupDisposition {
    /// Insert as locked entry in the KeyRing.
    Locked {
        /// Optional reason shown in status / audit.
        reason: Option<String>,
    },
    /// Insert as unlocked entry in the KeyRing (requires provider to produce crypto at load-time).
    Unlocked,
}

/// Result of loading a master key version “material” from its backend.
#[derive(Debug, Clone)]
pub struct LoadedMaterial {
    /// Provider-specific unlockable material that can be cached in memory.
    pub material: UnlockMaterial,

    /// Whether this should be inserted as locked or unlocked at load time.
    pub startup: StartupDisposition,

    /// If `startup == Unlocked`, provider may provide an already-usable crypto handle.
    pub crypto_if_unlocked: Option<MasterKeyCryptoHandle>,
}

/// Lock/unlock state machine + audit + caching is handled by KeyRing / MasterKeyService.
pub trait MasterKeyProvider: Send + Sync + Debug {
    fn create_masterkey_data(&self, master_key: &mut MasterKey, input: &ProviderCreateInput) -> CkResult<()>;

    /// Load backend data for a master key version and return unlockable material.
    fn load_material(&self, master_key: &MasterKey, actor: Option<AccountId>) -> CkResult<LoadedMaterial>;

    /// Unlock: convert cached unlock material + user-provided args into a crypto handle.
    fn unlock_to_crypto(
        &self,
        master_key: &MasterKey,
        material: &UnlockMaterial,
        args: &UnlockArgs,
        actor: Option<AccountId>,
    ) -> CkResult<MasterKeyCryptoHandle>;

    /// List all token slots available on the default module. Only meaningful for PKCS#11 providers.
    fn list_tokens(&self) -> CkResult<Vec<Pkcs11TokenInfo>> {
        Err(CkError::NotImplemented("list_tokens is not supported by this provider".into()))
    }
}
