// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

/// PKCS#11 / HSM master key provider — available in the Commercial Edition only.
///
/// This stub is always compiled into the community binary so that the provider type
/// is recognised when deserialising database records created by a commercial instance,
/// but all operations return a clear error directing users to the commercial edition.
use crate::manager::account::AccountId;
use crate::manager::masterkey::MasterKey;
use crate::service::masterkey::ProviderCreateInput;
use crate::service::masterkey::keyring::UnlockMaterial;
use crate::service::masterkey::provider::UnlockArgs;
use crate::service::masterkey::provider::crypto::MasterKeyCryptoHandle;
use crate::service::masterkey::provider::traits::{LoadedMaterial, MasterKeyProvider};
use hierarkey_core::{CkError, CkResult};

const MSG: &str = "HSM / PKCS#11 support requires the Hierarkey Commercial Edition.";

#[derive(Debug)]
pub struct Pkcs11MasterKeyProvider;

impl MasterKeyProvider for Pkcs11MasterKeyProvider {
    fn create_masterkey_data(&self, _master_key: &mut MasterKey, _input: &ProviderCreateInput) -> CkResult<()> {
        Err(CkError::MasterKey(MSG.into()))
    }

    fn load_material(&self, _master_key: &MasterKey, _actor: Option<AccountId>) -> CkResult<LoadedMaterial> {
        Err(CkError::MasterKey(MSG.into()))
    }

    fn unlock_to_crypto(
        &self,
        _master_key: &MasterKey,
        _material: &UnlockMaterial,
        _args: &UnlockArgs,
        _actor: Option<AccountId>,
    ) -> CkResult<MasterKeyCryptoHandle> {
        Err(CkError::MasterKey(MSG.into()))
    }
}
