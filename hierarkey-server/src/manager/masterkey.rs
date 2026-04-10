// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::global::short_id::ShortId;
use crate::global::utils::sql::escape_ilike;
use crate::manager::account::AccountId;
use crate::{ResolveOne, one_line_sql, uuid_id};
use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use clap::ValueEnum;
#[cfg(test)]
use hierarkey_core::CkError;
use hierarkey_core::{CkResult, Metadata};
#[cfg(test)]
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
#[cfg(test)]
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::global::uuid_id::Identifier;
uuid_id!(MasterkeyId, "mk_");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ValueEnum)]
#[clap(rename_all = "snake_case")]
#[sqlx(type_name = "masterkey_usage", rename_all = "snake_case")]
pub enum MasterKeyUsage {
    WrapKek,
}

impl Display for MasterKeyUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MasterKeyUsage::WrapKek => "wrap_kek",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "masterkey_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MasterKeyStatus {
    /// Key is active and used to wrap new KEKs.
    Active,
    /// Key was just created and has never been activated. No KEKs exist under it yet.
    /// Loaded at startup so it can be activated without a restart.
    Pending,
    /// Key has been superseded by a new active key. No new KEKs will be wrapped under it,
    /// but existing KEKs still reference it. Must stay loaded in the keyring until all
    /// KEKs are rewrapped away from it, at which point it transitions to Retired.
    Draining,
    /// Key is fully decommissioned. No KEKs reference it. Not loaded at startup.
    Retired,
    /// Key material is unavailable (file missing, HSM unreachable, etc.).
    Unavailable,
}

impl Display for MasterKeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MasterKeyStatus::Active => "active",
            MasterKeyStatus::Pending => "pending",
            MasterKeyStatus::Draining => "draining",
            MasterKeyStatus::Retired => "retired",
            MasterKeyStatus::Unavailable => "unavailable",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "masterkey_backend", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MasterKeyBackend {
    File,
    Pkcs11,
}

impl Display for MasterKeyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MasterKeyBackend::File => "file",
            MasterKeyBackend::Pkcs11 => "pkcs11",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "masterkey_file_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MasterKeyFileType {
    Insecure,
    Passphrase,
}

impl Display for MasterKeyFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MasterKeyFileType::Insecure => "insecure",
            MasterKeyFileType::Passphrase => "passphrase",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------------------------

#[derive(sqlx::FromRow, Debug, Serialize, Clone)]
pub struct MasterKey {
    pub id: MasterkeyId,
    pub short_id: ShortId,
    pub name: String,
    pub usage: MasterKeyUsage,
    pub status: MasterKeyStatus,
    pub backend: MasterKeyBackend,
    pub file_type: Option<MasterKeyFileType>,
    pub file_path: Option<String>,
    pub file_sha256: Option<String>,
    pub pkcs11_ref: Option<serde_json::Value>,
    pub metadata: Metadata,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Option<AccountId>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_by: Option<AccountId>,
    pub retired_at: Option<chrono::DateTime<chrono::Utc>>,
    pub retired_by: Option<AccountId>,
}

// ---------------------------------------------------------------------------------------------

#[async_trait::async_trait]
pub trait MasterKeyStore: Send + Sync {
    async fn find_by_id(&self, masterkey_id: MasterkeyId) -> CkResult<Option<MasterKey>>;
    async fn find_by_name(&self, name: &str) -> CkResult<Option<MasterKey>>;
    async fn find_all(&self) -> CkResult<Vec<MasterKey>>;

    async fn get_count(&self, usage: MasterKeyUsage) -> CkResult<i64>;

    async fn create(&self, master_key: &MasterKey) -> CkResult<()>;
    async fn set_active(&self, masterkey_id: MasterkeyId, updated_by: Option<AccountId>) -> CkResult<()>;
    async fn retire(&self, masterkey_id: MasterkeyId, retired_by: Option<AccountId>) -> CkResult<()>;
    async fn delete(&self, masterkey_id: MasterkeyId) -> CkResult<()>;

    async fn resolve_short_masterkey_id(&self, prefix: &str) -> CkResult<ResolveOne<MasterkeyId>>;
}

// ---------------------------------------------------------------------------------------------

pub struct SqlMasterKeyStore {
    pool: PgPool,
}

impl SqlMasterKeyStore {
    pub fn new(pool: PgPool) -> CkResult<Self> {
        Ok(Self { pool })
    }
}

#[async_trait::async_trait]
impl MasterKeyStore for SqlMasterKeyStore {
    async fn find_by_id(&self, masterkey_id: MasterkeyId) -> CkResult<Option<MasterKey>> {
        let masterkey = sqlx::query_as::<_, MasterKey>(&one_line_sql(
            r#"
            SELECT
                id, short_id, name, usage, status, backend,
                file_type, file_path, file_sha256, pkcs11_ref,
                metadata, created_at, created_by, updated_at,
                updated_by, retired_at, retired_by
            FROM
                masterkeys
            WHERE
                id = $1
            "#,
        ))
        .bind(masterkey_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(masterkey)
    }

    async fn get_count(&self, usage: MasterKeyUsage) -> CkResult<i64> {
        let count: i64 = sqlx::query_scalar(&one_line_sql(
            r#"
            SELECT
                COUNT(*)
            FROM
                masterkeys
            WHERE
                usage = $1
            "#,
        ))
        .bind(usage)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    async fn find_all(&self) -> CkResult<Vec<MasterKey>> {
        let masterkeys = sqlx::query_as::<_, MasterKey>(&one_line_sql(
            r#"
            SELECT
                id, short_id, name, usage, status, backend,
                file_type, file_path, file_sha256, pkcs11_ref,
                metadata, created_at, created_by, updated_at,
                updated_by, retired_at, retired_by
            FROM
                masterkeys
            ORDER BY
                created_at ASC
            "#,
        ))
        .fetch_all(&self.pool)
        .await?;

        Ok(masterkeys)
    }

    async fn find_by_name(&self, name: &str) -> CkResult<Option<MasterKey>> {
        let masterkey = sqlx::query_as::<_, MasterKey>(&one_line_sql(
            r#"
            SELECT
                id, short_id, name, usage, status, backend,
                file_type, file_path, file_sha256, pkcs11_ref,
                metadata, created_at, created_by, updated_at,
                updated_by, retired_at, retired_by
            FROM
                masterkeys
            WHERE
                name = $1
            "#,
        ))
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(masterkey)
    }

    async fn create(&self, master_key: &MasterKey) -> CkResult<()> {
        let _ = sqlx::query_as::<_, MasterKey>(&one_line_sql(
            r#"
            INSERT INTO masterkeys (
                id, short_id, name, usage, status, backend,
                file_type, pkcs11_ref, metadata, created_at,
                file_path, file_sha256
            ) VALUES (
                $1, $11, $2, $3, $10, $4,
                $5, $6, $7, NOW(), $8, $9
            )
            RETURNING
                id, short_id, name, usage, status, backend,
                file_type, file_path, file_sha256, pkcs11_ref,
                metadata, created_at, created_by, updated_at,
                updated_by, retired_at, retired_by
            "#,
        ))
        .bind(master_key.id)
        .bind(master_key.name.clone())
        .bind(master_key.usage)
        .bind(master_key.backend)
        .bind(master_key.file_type)
        // .bind(master_key.pkcs11_ref.unwrap_or(&serde_json::Value::Null))
        .bind(master_key.pkcs11_ref.clone())
        .bind(master_key.metadata.clone())
        .bind(master_key.file_path.clone())
        .bind(master_key.file_sha256.clone())
        .bind(master_key.status)
        .bind(master_key.short_id.to_string())
        .fetch_one(&self.pool)
        .await?;

        Ok(())
    }

    async fn set_active(&self, masterkey_id: MasterkeyId, updated_by: Option<AccountId>) -> CkResult<()> {
        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Transition the currently-active key (same usage) to 'draining'. It keeps its
        // existing KEKs and must stay loaded until those are all rewrapped away.
        sqlx::query(&one_line_sql(
            r#"
            UPDATE
                masterkeys
            SET
                status = 'draining',
                updated_at = NOW(),
                updated_by = $2
            WHERE
                usage = (
                    SELECT usage FROM masterkeys WHERE id = $1
                )
                AND status = 'active'
            "#,
        ))
        .bind(masterkey_id)
        .bind(updated_by)
        .execute(&mut *tx)
        .await?;

        // now set the specified masterkey to active
        sqlx::query(&one_line_sql(
            r#"
            UPDATE
                masterkeys
            SET
                status = 'active',
                updated_at = NOW(),
                updated_by = $2
            WHERE
                id = $1
            "#,
        ))
        .bind(masterkey_id)
        .bind(updated_by)
        .execute(&mut *tx)
        .await?;

        // Commit transaction
        tx.commit().await?;

        Ok(())
    }

    async fn retire(&self, masterkey_id: MasterkeyId, retired_by: Option<AccountId>) -> CkResult<()> {
        sqlx::query(&one_line_sql(
            r#"
            UPDATE masterkeys
            SET status = 'retired',
                retired_at = NOW(),
                retired_by = $2,
                updated_at = NOW()
            WHERE id = $1
            "#,
        ))
        .bind(masterkey_id)
        .bind(retired_by)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, masterkey_id: MasterkeyId) -> CkResult<()> {
        sqlx::query(&one_line_sql(
            r#"
            DELETE FROM masterkeys WHERE id = $1
            "#,
        ))
        .bind(masterkey_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn resolve_short_masterkey_id(&self, prefix: &str) -> CkResult<ResolveOne<MasterkeyId>> {
        let sql = one_line_sql(
            r#"
            SELECT id FROM masterkeys WHERE short_id ILIKE $1
        "#,
        );

        let rows = sqlx::query_as::<_, (MasterkeyId,)>(&sql)
            .bind(format!("{}%", escape_ilike(prefix)))
            .fetch_all(&self.pool)
            .await?;

        match rows.len() {
            0 => Ok(ResolveOne::None),
            1 => Ok(ResolveOne::One(rows[0].0)),
            n => Ok(ResolveOne::Many(Some(n))),
        }
    }
}

// ---------------------------------------------------------------------------------------------
#[cfg(test)]
pub struct InMemoryMasterKeyStore {
    masterkeys: Mutex<HashMap<MasterkeyId, MasterKey>>,
}

#[cfg(test)]
impl Default for InMemoryMasterKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl InMemoryMasterKeyStore {
    pub fn new() -> Self {
        Self {
            masterkeys: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl MasterKeyStore for InMemoryMasterKeyStore {
    async fn find_by_id(&self, masterkey_id: MasterkeyId) -> CkResult<Option<MasterKey>> {
        let masterkeys = self.masterkeys.lock();
        Ok(masterkeys.get(&masterkey_id).cloned())
    }

    async fn get_count(&self, usage: MasterKeyUsage) -> CkResult<i64> {
        let masterkeys = self.masterkeys.lock();
        let count = masterkeys.values().filter(|mk| mk.usage == usage).count() as i64;
        Ok(count)
    }

    async fn find_all(&self) -> CkResult<Vec<MasterKey>> {
        let masterkeys = self.masterkeys.lock();
        Ok(masterkeys.values().cloned().collect())
    }

    async fn find_by_name(&self, name: &str) -> CkResult<Option<MasterKey>> {
        let masterkeys = self.masterkeys.lock();
        for mk in masterkeys.values() {
            if mk.name == name {
                return Ok(Some(mk.clone()));
            }
        }
        Ok(None)
    }

    async fn create(&self, master_key: &MasterKey) -> CkResult<()> {
        let mut masterkeys = self.masterkeys.lock();
        masterkeys.insert(master_key.id, master_key.clone());

        Ok(())
    }

    async fn set_active(&self, masterkey_id: MasterkeyId, _updated_by: Option<AccountId>) -> CkResult<()> {
        let mut masterkeys = self.masterkeys.lock();

        // First, retire any currently active masterkey with the same usage
        let usage = if let Some(mk) = masterkeys.get(&masterkey_id) {
            mk.usage
        } else {
            return Err(CkError::ResourceNotFound {
                kind: "masterkey",
                id: masterkey_id.to_string(),
            });
        };

        for mk in masterkeys.values_mut() {
            if mk.usage == usage && mk.status == MasterKeyStatus::Active {
                mk.status = MasterKeyStatus::Draining;
                mk.updated_at = Some(chrono::Utc::now());
            }
        }

        // Now set the specified masterkey to active
        if let Some(mk) = masterkeys.get_mut(&masterkey_id) {
            mk.status = MasterKeyStatus::Active;
            mk.updated_at = Some(chrono::Utc::now());
            mk.retired_at = None;
            mk.retired_by = None;
            Ok(())
        } else {
            Err(CkError::ResourceNotFound {
                kind: "masterkey",
                id: masterkey_id.to_string(),
            })
        }
    }

    async fn retire(&self, masterkey_id: MasterkeyId, retired_by: Option<AccountId>) -> CkResult<()> {
        let mut masterkeys = self.masterkeys.lock();
        let mk = masterkeys.get_mut(&masterkey_id).ok_or(CkError::ResourceNotFound {
            kind: "masterkey",
            id: masterkey_id.to_string(),
        })?;
        mk.status = MasterKeyStatus::Retired;
        mk.retired_at = Some(chrono::Utc::now());
        mk.retired_by = retired_by;
        mk.updated_at = Some(chrono::Utc::now());
        Ok(())
    }

    async fn delete(&self, masterkey_id: MasterkeyId) -> CkResult<()> {
        let mut masterkeys = self.masterkeys.lock();
        masterkeys.remove(&masterkey_id);
        Ok(())
    }

    async fn resolve_short_masterkey_id(&self, prefix: &str) -> CkResult<ResolveOne<MasterkeyId>> {
        let masterkeys = self.masterkeys.lock();
        let prefix_lower = prefix.to_lowercase();
        let matches: Vec<MasterkeyId> = masterkeys
            .values()
            .filter(|mk| mk.short_id.to_string().to_lowercase().starts_with(&prefix_lower))
            .map(|mk| mk.id)
            .collect();
        match matches.len() {
            0 => Ok(ResolveOne::None),
            1 => Ok(ResolveOne::One(matches[0])),
            n => Ok(ResolveOne::Many(Some(n))),
        }
    }
}

// ---------------------------------------------------------------------------------------------

pub struct MasterKeyManager {
    store: Arc<dyn MasterKeyStore>,
}

impl MasterKeyManager {
    pub fn new(store: Arc<dyn MasterKeyStore>) -> CkResult<Self> {
        Ok(Self { store })
    }

    pub async fn find_masterkey_by_id(&self, masterkey_id: MasterkeyId) -> CkResult<Option<MasterKey>> {
        self.store.find_by_id(masterkey_id).await
    }

    pub async fn find_by_name(&self, name: &str) -> CkResult<Option<MasterKey>> {
        self.store.find_by_name(name).await
    }

    pub async fn find_all(&self) -> CkResult<Vec<MasterKey>> {
        self.store.find_all().await
    }

    pub async fn count_keys(&self, usage: MasterKeyUsage) -> CkResult<i64> {
        self.store.get_count(usage).await
    }

    pub async fn set_active(&self, _ctx: &CallContext, masterkey_id: MasterkeyId) -> CkResult<()> {
        self.store.set_active(masterkey_id, None).await
    }

    pub async fn retire(&self, _ctx: &CallContext, masterkey_id: MasterkeyId) -> CkResult<()> {
        self.store.retire(masterkey_id, None).await
    }

    pub async fn delete(&self, _ctx: &CallContext, masterkey_id: MasterkeyId) -> CkResult<()> {
        self.store.delete(masterkey_id).await
    }

    pub async fn find_active_masterkey(&self, usage: MasterKeyUsage) -> CkResult<Option<MasterKey>> {
        let all_keys = self.store.find_all().await?;
        for mk in all_keys {
            if mk.usage == usage && mk.status == MasterKeyStatus::Active {
                return Ok(Some(mk));
            }
        }
        Ok(None)
    }

    pub async fn create(&self, _ctx: &CallContext, master_key: &MasterKey) -> CkResult<()> {
        self.store.create(master_key).await
    }

    pub async fn resolve_short_masterkey_id(&self, prefix: &str) -> CkResult<ResolveOne<MasterkeyId>> {
        self.store.resolve_short_masterkey_id(prefix).await
    }
}

// ---------------------------------------------------------------------------------------------

/// Master keys (if stored in memory) are zeroized on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKeyData(Zeroizing<[u8; 32]>);

impl From<[u8; 32]> for MasterKeyData {
    fn from(bytes: [u8; 32]) -> Self {
        MasterKeyData(Zeroizing::new(bytes))
    }
}

impl From<Zeroizing<[u8; 32]>> for MasterKeyData {
    fn from(bytes: Zeroizing<[u8; 32]>) -> Self {
        MasterKeyData(bytes)
    }
}

impl MasterKeyData {
    pub fn generate() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *key);
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Display for MasterKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKeyData<Redacted>")
    }
}

impl std::fmt::Debug for MasterKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKeyData<Redacted>").finish()
    }
}
