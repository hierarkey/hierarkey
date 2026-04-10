// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use std::fmt;

use aes_gcm::{
    Aes256Gcm, Key, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use anyhow::anyhow;
use argon2::{Algorithm, Argon2, Params, ParamsBuilder, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64_standard;
use rand::TryRng;
use tracing::info;
use zeroize::Zeroizing;

use crate::global::aes_gcm::CryptoAesGcm;
use crate::global::config::MasterKeyFileConfig;
#[cfg(test)]
use crate::global::short_id::ShortId;
use crate::manager::account::AccountId;
use crate::manager::masterkey::{MasterKey, MasterKeyData};
use crate::manager::secret::secret_data::Secret32;
use hierarkey_core::error::crypto::CryptoError;
use hierarkey_core::{CkError, CkResult};

use crate::service::masterkey::backend::file_format::{
    Argon2IdParams, FilePayload, FilePayloadKind, KdfParams, PASSPHRASE_FILE_VERSION, checksum_matches,
    create_content_checksum, create_masterkey_checksum, extract_passphrase_material, parse_payload, validate_payload,
};
use crate::service::masterkey::backend::file_store::FileStore;

use crate::service::masterkey::ProviderCreateInput;
use crate::service::masterkey::keyring::UnlockMaterial;
use crate::service::masterkey::provider::UnlockArgs;
use crate::service::masterkey::provider::crypto::{AesGcmMasterKeyCrypto, MasterKeyCryptoHandle};
use crate::service::masterkey::provider::traits::{LoadedMaterial, MasterKeyProvider, StartupDisposition};

pub struct PassphraseMasterKeyProvider {
    store: FileStore,
    /// KDF parameters used when creating new passphrase-backed master keys.
    /// Stored in the key file at creation time; existing keys always use the
    /// parameters embedded in their own file.
    kdf_params: KdfParams,
}

impl fmt::Debug for PassphraseMasterKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassphraseMasterKeyProvider")
            .field("base_dir", &self.store.base_dir())
            .finish()
    }
}

impl PassphraseMasterKeyProvider {
    pub fn new(config: &MasterKeyFileConfig) -> CkResult<Self> {
        let Some(path) = &config.path else {
            return Err(CkError::MasterKey(
                "no path configured for passphrase master key provider".into(),
            ));
        };

        let kdf_params = KdfParams::Argon2Id(Argon2IdParams {
            memory_cost: config.kdf_memory_kib,
            time_cost: config.kdf_time_cost,
            parallelism: config.kdf_parallelism,
        });

        Ok(Self {
            store: FileStore::new(path)?,
            kdf_params,
        })
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

// -----------------------------------------------------------------------------

impl MasterKeyProvider for PassphraseMasterKeyProvider {
    fn create_masterkey_data(&self, master_key: &mut MasterKey, input: &ProviderCreateInput) -> CkResult<()> {
        info!(
            master_key_id = %master_key.id,
            "Creating passphrase-backed master key file"
        );

        let passphrase = match input {
            ProviderCreateInput::Passphrase { passphrase } => passphrase,
            _ => {
                return Err(CkError::MasterKey(
                    "invalid provider create input for passphrase master key provider".into(),
                ));
            }
        };

        let key_data = MasterKeyData::generate();

        let kdf_params = self.kdf_params.clone();
        let b64_enc_key_data = encrypt_key_with_passphrase(&key_data, passphrase, &kdf_params)?;

        let payload = FilePayload::Passphrase {
            created_at: chrono::Utc::now(),
            kdf_params: kdf_params.clone(),
            b64_enc_key_data,
            version: PASSPHRASE_FILE_VERSION,
        };

        let content_checksum = create_content_checksum(&payload);
        let master_key_checksum = create_masterkey_checksum(master_key, &content_checksum, FilePayloadKind::Passphrase);

        let filename = Self::default_filename(master_key);
        let json = serde_json::to_value(&payload)?;
        self.store.write_json_atomic(&filename, &json)?;

        master_key.file_path = Some(filename.clone());
        master_key.file_sha256 = Some(master_key_checksum);
        Ok(())
    }

    fn load_material(&self, master_key: &MasterKey, _actor: Option<AccountId>) -> CkResult<LoadedMaterial> {
        info!(
            master_key_id = %master_key.id,
            "Loading passphrase master key material (locked)"
        );

        let Some(filename) = &master_key.file_path else {
            return Err(CkError::MasterKey("master key does not have a file path configured".into()));
        };

        let raw = self.store.read_to_string(filename)?;

        let payload = parse_payload(&raw)?;
        validate_payload(&payload, FilePayloadKind::Passphrase)?;

        let Some(stored) = master_key.file_sha256.as_ref() else {
            return Err(CkError::MasterKey("master key does not have a file checksum configured".into()));
        };

        let content_checksum = create_content_checksum(&payload);
        let calculated = create_masterkey_checksum(master_key, &content_checksum, FilePayloadKind::Passphrase);

        if !checksum_matches(&calculated, stored) {
            return Err(CkError::MasterKey("master key file checksum validation failed".into()));
        }

        let (kdf_params, b64_enc_key_data) = extract_passphrase_material(&payload)?;

        Ok(LoadedMaterial {
            material: UnlockMaterial::Passphrase {
                kdf_params,
                b64_enc_key_data,
            },
            startup: StartupDisposition::Locked {
                reason: Some("Locked by default at startup".into()),
            },
            crypto_if_unlocked: None,
        })
    }

    fn unlock_to_crypto(
        &self,
        _master_key: &MasterKey,
        material: &UnlockMaterial,
        args: &UnlockArgs,
        _actor: Option<AccountId>,
    ) -> CkResult<MasterKeyCryptoHandle> {
        let UnlockArgs::Passphrase(passphrase) = args else {
            return Err(CkError::MasterKey("invalid unlock arguments for passphrase provider".into()));
        };

        let UnlockMaterial::Passphrase {
            kdf_params,
            b64_enc_key_data,
        } = material
        else {
            return Err(CkError::MasterKey("invalid unlock material for passphrase provider".into()));
        };

        let key_data = decrypt_key_with_passphrase(b64_enc_key_data.as_str(), passphrase.as_str(), kdf_params)
            .map_err(|_| CkError::InvalidCredentials)?;

        let key = Secret32::new(*key_data.as_bytes());
        let aes = CryptoAesGcm::new(&key)?;
        Ok(std::sync::Arc::new(AesGcmMasterKeyCrypto::new(aes)))
    }
}

// -----------------------------------------------------------------------------

/// Encrypt 32-byte master key with passphrase-derived key (Argon2id) + AES-256-GCM.
fn encrypt_key_with_passphrase(
    key_data: &MasterKeyData,
    passphrase: &str,
    params: &KdfParams,
) -> CkResult<Zeroizing<String>> {
    let mut salt = [0u8; 16];
    let _ = rand::rng().try_fill_bytes(&mut salt);

    let derived_key = derive_key(passphrase, &salt, params)?;
    if derived_key.len() != 32 {
        return Err(CkError::Custom("derived key has invalid length".into()));
    }

    // 12-byte nonce (GCM standard)
    let mut nonce_bytes = [0u8; 12];
    let _ = rand::rng().try_fill_bytes(&mut nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(derived_key.as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut buf = key_data.as_bytes().to_vec();

    let aad = b"ckp-v1";
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut buf)
        .map_err(|e| CryptoError::EncryptionFailed(anyhow!(e.to_string())))?;

    let mut out = Vec::with_capacity(16 + 12 + 16 + buf.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(tag.as_slice());
    out.extend_from_slice(&buf);

    Ok(Zeroizing::new(base64_standard.encode(out)))
}

fn decrypt_key_with_passphrase(blob_b64: &str, passphrase: &str, params: &KdfParams) -> CkResult<MasterKeyData> {
    let raw = base64_standard
        .decode(blob_b64)
        .map_err(|e| CkError::Custom(format!("base64 decode failed: {e}")))?;

    // salt(16) + nonce(12) + tag(16) + ciphertext(>= 1; expected 32)
    if raw.len() < 16 + 12 + 16 {
        return Err(CkError::Custom("encrypted data too short".into()));
    }

    let salt = &raw[0..16];
    let nonce_bytes = &raw[16..28];
    let tag_bytes = &raw[28..44];
    let ciphertext = &raw[44..];

    let derived_key = derive_key(passphrase, salt, params)?;
    if derived_key.len() != 32 {
        return Err(CkError::Custom("derived key has invalid length".into()));
    }

    let key = Key::<Aes256Gcm>::from_slice(derived_key.as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let tag = Tag::from_slice(tag_bytes);

    let mut buf = ciphertext.to_vec();

    cipher
        .decrypt_in_place_detached(nonce, b"ckp-v1", &mut buf, tag)
        .map_err(|e| CkError::Custom(format!("decryption failed: {e}")))?;

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&buf);
    Ok(MasterKeyData::from(out))
}

fn derive_key(passphrase: &str, salt: &[u8], params: &KdfParams) -> CkResult<Zeroizing<[u8; 32]>> {
    match params {
        KdfParams::Argon2Id(p) => {
            let mut out = Zeroizing::new([0u8; 32]);

            let argon2_params = create_argon2_params(p)?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

            argon2
                .hash_password_into(passphrase.as_bytes(), salt, &mut *out)
                .map_err(|_| CkError::Custom("key derivation failed".into()))?;

            Ok(out)
        }
    }
}

fn create_argon2_params(p: &Argon2IdParams) -> CkResult<Params> {
    ParamsBuilder::new()
        .m_cost(p.memory_cost)
        .t_cost(p.time_cost)
        .p_cost(p.parallelism)
        .build()
        .map_err(|_| CkError::Custom("invalid Argon2 parameters".into()))
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
            kdf_memory_kib: 8,
            kdf_time_cost: 1,
            kdf_parallelism: 1,
            ..Default::default()
        }
    }

    fn make_mk() -> MasterKey {
        MasterKey {
            id: MasterkeyId(uuid::Uuid::new_v4()),
            short_id: ShortId::generate("mk_", 12),
            name: "test-passphrase-key".into(),
            usage: MasterKeyUsage::WrapKek,
            status: MasterKeyStatus::Active,
            backend: MasterKeyBackend::File,
            file_type: Some(MasterKeyFileType::Passphrase),
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
            .join(format!("hkey-passphrase-test-{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn new_with_no_path_fails() {
        assert!(PassphraseMasterKeyProvider::new(&make_config(None)).is_err());
    }

    #[test]
    fn new_with_valid_path_succeeds() {
        let dir = tmp_dir();
        assert!(PassphraseMasterKeyProvider::new(&make_config(Some(&dir))).is_ok());
    }

    #[test]
    fn create_masterkey_data_wrong_input_type_fails() {
        let dir = tmp_dir();
        let provider = PassphraseMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        assert!(
            provider
                .create_masterkey_data(&mut mk, &ProviderCreateInput::Insecure)
                .is_err()
        );
    }

    #[test]
    fn create_masterkey_data_sets_file_path_and_checksum() {
        let dir = tmp_dir();
        let provider = PassphraseMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        let input = ProviderCreateInput::Passphrase {
            passphrase: zeroize::Zeroizing::new("my-test-passphrase".into()),
        };
        provider.create_masterkey_data(&mut mk, &input).unwrap();
        assert!(mk.file_path.is_some());
        assert!(mk.file_sha256.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_material_starts_locked() {
        let dir = tmp_dir();
        let provider = PassphraseMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        let input = ProviderCreateInput::Passphrase {
            passphrase: zeroize::Zeroizing::new("passphrase123".into()),
        };
        provider.create_masterkey_data(&mut mk, &input).unwrap();

        let loaded = provider.load_material(&mk, None).unwrap();
        assert!(matches!(loaded.startup, StartupDisposition::Locked { .. }));
        assert!(loaded.crypto_if_unlocked.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_material_missing_file_path_fails() {
        let dir = tmp_dir();
        let provider = PassphraseMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mk = make_mk(); // file_path = None
        assert!(provider.load_material(&mk, None).is_err());
    }

    #[test]
    fn load_material_missing_checksum_fails() {
        let dir = tmp_dir();
        let provider = PassphraseMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        let input = ProviderCreateInput::Passphrase {
            passphrase: zeroize::Zeroizing::new("pass".into()),
        };
        provider.create_masterkey_data(&mut mk, &input).unwrap();
        mk.file_sha256 = None;
        assert!(provider.load_material(&mk, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_material_tampered_checksum_fails() {
        let dir = tmp_dir();
        let provider = PassphraseMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        let input = ProviderCreateInput::Passphrase {
            passphrase: zeroize::Zeroizing::new("pass".into()),
        };
        provider.create_masterkey_data(&mut mk, &input).unwrap();
        mk.file_sha256 = Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        assert!(provider.load_material(&mk, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlock_to_crypto_correct_passphrase_succeeds() {
        let dir = tmp_dir();
        let provider = PassphraseMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        let passphrase = "correct-passphrase";
        let input = ProviderCreateInput::Passphrase {
            passphrase: zeroize::Zeroizing::new(passphrase.into()),
        };
        provider.create_masterkey_data(&mut mk, &input).unwrap();
        let loaded = provider.load_material(&mk, None).unwrap();

        let result = provider.unlock_to_crypto(
            &mk,
            &loaded.material,
            &UnlockArgs::Passphrase(zeroize::Zeroizing::new(passphrase.into())),
            None,
        );
        assert!(result.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlock_to_crypto_wrong_passphrase_fails() {
        let dir = tmp_dir();
        let provider = PassphraseMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        let input = ProviderCreateInput::Passphrase {
            passphrase: zeroize::Zeroizing::new("correct".into()),
        };
        provider.create_masterkey_data(&mut mk, &input).unwrap();
        let loaded = provider.load_material(&mk, None).unwrap();

        let result = provider.unlock_to_crypto(
            &mk,
            &loaded.material,
            &UnlockArgs::Passphrase(zeroize::Zeroizing::new("wrong".into())),
            None,
        );
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlock_to_crypto_wrong_args_type_fails() {
        let dir = tmp_dir();
        let provider = PassphraseMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mut mk = make_mk();
        let input = ProviderCreateInput::Passphrase {
            passphrase: zeroize::Zeroizing::new("pass".into()),
        };
        provider.create_masterkey_data(&mut mk, &input).unwrap();
        let loaded = provider.load_material(&mk, None).unwrap();

        let result = provider.unlock_to_crypto(&mk, &loaded.material, &UnlockArgs::None, None);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlock_to_crypto_wrong_material_type_fails() {
        let dir = tmp_dir();
        let provider = PassphraseMasterKeyProvider::new(&make_config(Some(&dir))).unwrap();
        let mk = make_mk();
        let wrong_material = UnlockMaterial::Insecure {
            key_data: std::sync::Arc::new(MasterKeyData::generate()),
        };
        let result = provider.unlock_to_crypto(
            &mk,
            &wrong_material,
            &UnlockArgs::Passphrase(zeroize::Zeroizing::new("pass".into())),
            None,
        );
        assert!(result.is_err());
    }

    /// Minimal Argon2id parameters for fast tests (not for production use).
    fn test_kdf_params() -> KdfParams {
        KdfParams::Argon2Id(Argon2IdParams {
            memory_cost: 8, // 8 KiB — argon2 minimum
            time_cost: 1,
            parallelism: 1,
        })
    }

    #[test]
    fn encrypt_decrypt_roundtrip_recovers_original_key() {
        let key_data = MasterKeyData::generate();
        let params = test_kdf_params();
        let blob = encrypt_key_with_passphrase(&key_data, "correct-passphrase", &params).unwrap();
        let recovered = decrypt_key_with_passphrase(blob.as_str(), "correct-passphrase", &params).unwrap();
        assert_eq!(key_data.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn encrypt_produces_different_blobs_for_same_key() {
        // salt and nonce are random, so two encryptions of the same key must differ
        let key_data = MasterKeyData::generate();
        let params = test_kdf_params();
        let blob1 = encrypt_key_with_passphrase(&key_data, "passphrase", &params).unwrap();
        let blob2 = encrypt_key_with_passphrase(&key_data, "passphrase", &params).unwrap();
        assert_ne!(blob1.as_str(), blob2.as_str());
    }

    #[test]
    fn wrong_passphrase_fails_decryption() {
        let key_data = MasterKeyData::generate();
        let params = test_kdf_params();
        let blob = encrypt_key_with_passphrase(&key_data, "correct-passphrase", &params).unwrap();
        let result = decrypt_key_with_passphrase(blob.as_str(), "wrong-passphrase", &params);
        assert!(result.is_err(), "decryption with wrong passphrase must fail");
    }

    #[test]
    fn empty_passphrase_fails_when_non_empty_was_used() {
        let key_data = MasterKeyData::generate();
        let params = test_kdf_params();
        let blob = encrypt_key_with_passphrase(&key_data, "my-passphrase", &params).unwrap();
        let result = decrypt_key_with_passphrase(blob.as_str(), "", &params);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_blob_fails_decryption() {
        // Fewer than 44 bytes (16 salt + 12 nonce + 16 tag) must be rejected
        let short = base64_standard.encode([0u8; 10]);
        let result = decrypt_key_with_passphrase(&short, "passphrase", &test_kdf_params());
        assert!(result.is_err());
    }

    #[test]
    fn corrupted_ciphertext_fails_decryption() {
        let key_data = MasterKeyData::generate();
        let params = test_kdf_params();
        let blob = encrypt_key_with_passphrase(&key_data, "passphrase", &params).unwrap();

        let mut raw = base64_standard.decode(blob.as_str()).unwrap();
        // Flip the last byte of the ciphertext (after salt[16] + nonce[12] + tag[16])
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        let corrupted = base64_standard.encode(&raw);

        let result = decrypt_key_with_passphrase(&corrupted, "passphrase", &params);
        assert!(result.is_err(), "corrupted ciphertext must fail AEAD verification");
    }

    #[test]
    fn corrupted_auth_tag_fails_decryption() {
        let key_data = MasterKeyData::generate();
        let params = test_kdf_params();
        let blob = encrypt_key_with_passphrase(&key_data, "passphrase", &params).unwrap();

        let mut raw = base64_standard.decode(blob.as_str()).unwrap();
        // Flip the first byte of the tag (bytes 28..44)
        raw[28] ^= 0xFF;
        let corrupted = base64_standard.encode(&raw);

        let result = decrypt_key_with_passphrase(&corrupted, "passphrase", &params);
        assert!(result.is_err(), "corrupted auth tag must fail AEAD verification");
    }

    #[test]
    fn invalid_base64_fails_decryption() {
        let result = decrypt_key_with_passphrase("not-valid-base64!!!", "passphrase", &test_kdf_params());
        assert!(result.is_err());
    }

    #[test]
    fn derive_key_is_deterministic() {
        let params = test_kdf_params();
        let salt = [0x42u8; 16];
        let k1 = derive_key("test-passphrase", &salt, &params).unwrap();
        let k2 = derive_key("test-passphrase", &salt, &params).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_key_output_is_32_bytes() {
        let key = derive_key("passphrase", &[0u8; 16], &test_kdf_params()).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_key_differs_with_different_salt() {
        let params = test_kdf_params();
        let k1 = derive_key("passphrase", &[0x11u8; 16], &params).unwrap();
        let k2 = derive_key("passphrase", &[0x22u8; 16], &params).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_key_differs_with_different_passphrase() {
        let params = test_kdf_params();
        let salt = [0x42u8; 16];
        let k1 = derive_key("passphrase-one", &salt, &params).unwrap();
        let k2 = derive_key("passphrase-two", &salt, &params).unwrap();
        assert_ne!(*k1, *k2);
    }
}
