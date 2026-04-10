// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use std::collections::HashMap;

use hierarkey_core::{CkError, CkResult};

#[cfg(test)]
use crate::global::short_id::ShortId;
use crate::manager::masterkey::{MasterKey, MasterKeyBackend, MasterKeyFileType};
use crate::service::masterkey::MasterKeyProviderType;
use crate::service::masterkey::provider::MasterKeyProvider;

/// Registry of master key providers + deterministic provider resolution.
#[derive(Default)]
pub struct ProviderRegistry {
    providers: HashMap<MasterKeyProviderType, Box<dyn MasterKeyProvider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    pub fn add_provider(&mut self, provider_type: MasterKeyProviderType, provider: Box<dyn MasterKeyProvider>) {
        self.providers.insert(provider_type, provider);
    }

    pub fn get_provider(&self, provider_type: MasterKeyProviderType) -> CkResult<&dyn MasterKeyProvider> {
        self.providers
            .get(&provider_type)
            .map(|b| b.as_ref())
            .ok_or_else(|| CkError::Custom(format!("provider not registered: {provider_type:?}")))
    }

    /// Resolve which provider type should handle this MasterKey.
    pub fn get_provider_type(&self, master_key: &MasterKey) -> CkResult<MasterKeyProviderType> {
        match master_key.backend {
            MasterKeyBackend::File => {
                let Some(file_type) = master_key.file_type else {
                    return Err(CkError::MasterKey("master key backend=file but file_type is missing".into()));
                };

                match file_type {
                    MasterKeyFileType::Insecure => Ok(MasterKeyProviderType::Insecure),
                    MasterKeyFileType::Passphrase => Ok(MasterKeyProviderType::Passphrase),
                    // _ => Err(CkError::MasterKey(format!(
                    //     "unsupported file_type for backend=file: {file_type:?}"
                    // ))),
                }
            }

            MasterKeyBackend::Pkcs11 => Ok(MasterKeyProviderType::Pkcs11),
            // _ => Err(CkError::MasterKey(format!(
            //     "unsupported master key backend: {:?}",
            //     mkv.backend
            // ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::masterkey::{MasterKeyStatus, MasterKeyUsage, MasterkeyId};
    use crate::service::masterkey::provider::TestMasterKeyProvider;
    use hierarkey_core::Metadata;

    fn make_mk(backend: MasterKeyBackend, file_type: Option<MasterKeyFileType>) -> MasterKey {
        MasterKey {
            id: MasterkeyId(uuid::Uuid::new_v4()),
            short_id: ShortId::generate("mk_", 12),
            name: "test".into(),
            usage: MasterKeyUsage::WrapKek,
            status: MasterKeyStatus::Active,
            backend,
            file_type,
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

    #[test]
    fn add_and_get_provider() {
        let mut reg = ProviderRegistry::new();
        reg.add_provider(MasterKeyProviderType::Insecure, Box::new(TestMasterKeyProvider::new()));
        assert!(reg.get_provider(MasterKeyProviderType::Insecure).is_ok());
    }

    #[test]
    fn get_unregistered_provider_fails() {
        let reg = ProviderRegistry::new();
        assert!(reg.get_provider(MasterKeyProviderType::Insecure).is_err());
    }

    #[test]
    fn get_provider_type_insecure() {
        let reg = ProviderRegistry::new();
        let mk = make_mk(MasterKeyBackend::File, Some(MasterKeyFileType::Insecure));
        assert_eq!(reg.get_provider_type(&mk).unwrap(), MasterKeyProviderType::Insecure);
    }

    #[test]
    fn get_provider_type_passphrase() {
        let reg = ProviderRegistry::new();
        let mk = make_mk(MasterKeyBackend::File, Some(MasterKeyFileType::Passphrase));
        assert_eq!(reg.get_provider_type(&mk).unwrap(), MasterKeyProviderType::Passphrase);
    }

    #[test]
    fn get_provider_type_pkcs11() {
        let reg = ProviderRegistry::new();
        let mk = make_mk(MasterKeyBackend::Pkcs11, None);
        assert_eq!(reg.get_provider_type(&mk).unwrap(), MasterKeyProviderType::Pkcs11);
    }

    #[test]
    fn get_provider_type_file_without_file_type_fails() {
        let reg = ProviderRegistry::new();
        let mk = make_mk(MasterKeyBackend::File, None);
        assert!(reg.get_provider_type(&mk).is_err());
    }
}
