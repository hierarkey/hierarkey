// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use base64::Engine;
use hierarkey_core::{CkError, CkResult};
use std::fmt;
use std::sync::Arc;
use tracing::warn;
use zeroize::Zeroizing;

use crate::global::aes_gcm::CryptoAesGcm;
use crate::global::config::MasterKeyFileConfig;
#[cfg(test)]
use crate::global::short_id::ShortId;
use crate::manager::account::AccountId;
use crate::manager::masterkey::{MasterKey, MasterKeyData};
use crate::manager::secret::secret_data::Secret32;

use crate::service::masterkey::backend::file_format::{
    FilePayload, FilePayloadKind, INSECURE_FILE_VERSION, checksum_matches, create_content_checksum,
    create_masterkey_checksum, decode_insecure_key, parse_payload, validate_payload,
};
use crate::service::masterkey::backend::file_store::FileStore;

use crate::service::masterkey::ProviderCreateInput;
use crate::service::masterkey::keyring::UnlockMaterial;
use crate::service::masterkey::provider::UnlockArgs;
use crate::service::masterkey::provider::crypto::{AesGcmMasterKeyCrypto, MasterKeyCryptoHandle};
use crate::service::masterkey::provider::traits::{LoadedMaterial, MasterKeyProvider, StartupDisposition};

fn display_warning_banner() {
    eprintln!();
    eprintln!("  [ WARN ]  hierarkey is running in DEVELOPMENT master key mode.");
    eprintln!();
    eprintln!("   - Master key is stored UNENCRYPTED on disk.");
    eprintln!("   - Anyone with filesystem access can decrypt all secrets.");
    eprintln!("   - DO NOT use this mode in production or shared systems.");
    eprintln!();
}

// -----------------------------------------------------------------------------

pub struct InsecureMasterKeyProvider {
    store: FileStore,
    already_warned: std::sync::atomic::AtomicBool,
}

impl fmt::Debug for InsecureMasterKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InsecureMasterKeyProvider")
            .field("base_dir", &self.store.base_dir())
            .finish()
    }
}

impl InsecureMasterKeyProvider {
    pub fn new(config: &MasterKeyFileConfig) -> CkResult<Self> {
        let Some(path) = &config.path else {
            return Err(CkError::MasterKey("no path configured for insecure master key provider".into()));
        };

        let store = FileStore::new(path)?;
        Ok(Self {
            store,
            already_warned: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn maybe_warn(&self) {
        if !self.already_warned.swap(true, std::sync::atomic::Ordering::SeqCst) {
            warn!(
                "Running in INSECURE master key mode. Fine for development and local testing, but NOT for production!"
            );
            display_warning_banner();
        }
    }

    fn default_filename(master_key: &MasterKey) -> String {
        let base = if !master_key.name.is_empty() {
            master_key.name.clone()
        } else {
            master_key.id.to_string()
        };

        format!("hkey-master-{}-{}.json", base, master_key.id)
    }
}

impl MasterKeyProvider for InsecureMasterKeyProvider {
    fn create_masterkey_data(&self, master_key: &mut MasterKey, _input: &ProviderCreateInput) -> CkResult<()> {
        // Warn on insecure provider usage if not done so already
        self.maybe_warn();

        let key_data = MasterKeyData::generate();
        let b64 = base64::engine::general_purpose::STANDARD.encode(key_data.as_slice());

        let payload = FilePayload::Insecure {
            created_at: chrono::Utc::now(),
            key: Zeroizing::new(b64),
            version: INSECURE_FILE_VERSION,
        };

        let content_checksum = create_content_checksum(&payload);
        let master_key_checksum = create_masterkey_checksum(master_key, &content_checksum, FilePayloadKind::Insecure);

        let filename = Self::default_filename(master_key);
        let json = serde_json::to_value(&payload)?;
        self.store.write_json_atomic(&filename, &json)?;

        master_key.file_path = Some(filename);
        master_key.file_sha256 = Some(master_key_checksum);

        Ok(())
    }

    fn load_material(&self, master_key: &MasterKey, _actor: Option<AccountId>) -> CkResult<LoadedMaterial> {
        self.maybe_warn();

        let Some(filename) = &master_key.file_path else {
            return Err(CkError::MasterKey("master key does not have a file path configured".into()));
        };

        let raw = self.store.read_to_string(filename)?;

        let payload = parse_payload(&raw)?;
        validate_payload(&payload, FilePayloadKind::Insecure)?;

        let Some(stored) = master_key.file_sha256.as_ref() else {
            return Err(CkError::MasterKey("master key does not have a file checksum configured".into()));
        };

        let content_checksum = create_content_checksum(&payload);
        let calculated = create_masterkey_checksum(master_key, &content_checksum, FilePayloadKind::Insecure);

        if !checksum_matches(&calculated, stored) {
            return Err(CkError::MasterKey("master key file checksum validation failed".into()));
        }

        let key_data = decode_insecure_key(&payload)?;

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
            _ => return Err(CkError::MasterKey("invalid unlock arguments for insecure provider".into())),
        }

        let UnlockMaterial::Insecure { key_data } = material else {
            return Err(CkError::MasterKey("invalid unlock material for insecure provider".into()));
        };

        let key = Secret32::new(*key_data.as_bytes());
        let aes = CryptoAesGcm::new(&key)?;
        Ok(Arc::new(AesGcmMasterKeyCrypto::new(aes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::config::MasterKeyFileConfig;
    use crate::manager::masterkey::{
        MasterKeyBackend, MasterKeyFileType, MasterKeyStatus, MasterKeyUsage, MasterkeyId,
    };
    use crate::service::masterkey::ProviderCreateInput;
    use crate::service::masterkey::provider::UnlockArgs;
    use hierarkey_core::Metadata;

    fn make_config(path: Option<&str>) -> MasterKeyFileConfig {
        MasterKeyFileConfig {
            path: path.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    fn make_mk() -> MasterKey {
        MasterKey {
            id: MasterkeyId(uuid::Uuid::new_v4()),
            short_id: ShortId::generate("mk_", 12),
            name: "test-insecure-key".into(),
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

    fn tmp_dir() -> String {
        std::env::temp_dir()
            .join(format!("hkey-insecure-test-{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn new_with_no_path_fails() {
        assert!(InsecureMasterKeyProvider::new(&make_config(None)).is_err());
    }

    #[test]
    fn new_with_valid_path_succeeds() {
        let dir = tmp_dir();
        assert!(InsecureMasterKeyProvider::new(&make_config(Some(&dir))).is_ok());
    }

    #[test]
    fn create_and_load_material_succeeds() {
        let dir = tmp_dir();
        let provider = InsecureMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        provider
            .create_masterkey_data(&mut mk, &ProviderCreateInput::Insecure)
            .unwrap();
        assert!(mk.file_path.is_some());
        assert!(mk.file_sha256.is_some());

        let loaded = provider.load_material(&mk, None).unwrap();
        assert!(matches!(loaded.startup, StartupDisposition::Unlocked));
        assert!(loaded.crypto_if_unlocked.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlock_to_crypto_succeeds() {
        let dir = tmp_dir();
        let provider = InsecureMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        provider
            .create_masterkey_data(&mut mk, &ProviderCreateInput::Insecure)
            .unwrap();
        let loaded = provider.load_material(&mk, None).unwrap();

        let crypto = provider
            .unlock_to_crypto(&mk, &loaded.material, &UnlockArgs::None, None)
            .unwrap();
        // Verify it's usable — just check it's a valid handle
        let _ = crypto;

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlock_to_crypto_wrong_args_fails() {
        let dir = tmp_dir();
        let provider = InsecureMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        provider
            .create_masterkey_data(&mut mk, &ProviderCreateInput::Insecure)
            .unwrap();
        let loaded = provider.load_material(&mk, None).unwrap();

        let result = provider.unlock_to_crypto(
            &mk,
            &loaded.material,
            &UnlockArgs::Passphrase(zeroize::Zeroizing::new("oops".into())),
            None,
        );
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlock_to_crypto_wrong_material_fails() {
        let dir = tmp_dir();
        let provider = InsecureMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mk = make_mk();
        let kdf_params = crate::service::masterkey::backend::file_format::KdfParams::Argon2Id(
            crate::service::masterkey::backend::file_format::Argon2IdParams {
                memory_cost: 8,
                time_cost: 1,
                parallelism: 1,
            },
        );
        let wrong_material = UnlockMaterial::Passphrase {
            kdf_params,
            b64_enc_key_data: zeroize::Zeroizing::new("dummydata".into()),
        };

        let result = provider.unlock_to_crypto(&mk, &wrong_material, &UnlockArgs::None, None);
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_material_missing_file_path_fails() {
        let dir = tmp_dir();
        let provider = InsecureMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mk = make_mk(); // file_path = None
        assert!(provider.load_material(&mk, None).is_err());
    }

    #[test]
    fn load_material_missing_file_sha256_fails() {
        let dir = tmp_dir();
        let provider = InsecureMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        provider
            .create_masterkey_data(&mut mk, &ProviderCreateInput::Insecure)
            .unwrap();
        // Wipe checksum
        mk.file_sha256 = None;
        assert!(provider.load_material(&mk, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_material_tampered_checksum_fails() {
        let dir = tmp_dir();
        let provider = InsecureMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        provider
            .create_masterkey_data(&mut mk, &ProviderCreateInput::Insecure)
            .unwrap();
        mk.file_sha256 = Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        assert!(provider.load_material(&mk, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
