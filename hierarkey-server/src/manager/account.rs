// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
#[cfg(test)]
use crate::global::DEFAULT_OFFSET_VALUE;
use crate::global::short_id::ShortId;
use crate::global::uuid_id::Identifier;
use crate::global::{DEFAULT_LIMIT_VALUE, MAX_LIMIT_VALUE};
use crate::manager::secret::sql_store::escape_like;
use crate::service::account::{
    AccountData, AccountSearchQuery, AccountSortBy, CustomAccountData, CustomServiceAccountData,
};
use crate::{one_line_sql, uuid_id};
use clap::ValueEnum;
use hierarkey_core::error::auth::{AuthError, AuthFailReason};
use hierarkey_core::error::crypto::CryptoError;
use hierarkey_core::error::validation::ValidationError;
use hierarkey_core::resources::AccountName;
use hierarkey_core::{CkError, CkResult, Metadata};
#[cfg(test)]
use parking_lot::Mutex;
use password_hash::phc::PasswordHash;
use password_hash::{PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, QueryBuilder};
#[cfg(test)]
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::sync::{Arc, LazyLock};
use tracing::{error, trace};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use {chrono::DateTime, chrono::Utc};

uuid_id!(AccountId, "acc_");

// ----------------------------------------------------------------------------------------

const ADMIN_ROLE_NAME: &str = "platform:admin";

// ----------------------------------------------------------------------------------------

pub const DEFAULT_ADMIN_PASSWORD_LENGTH: usize = 24;
const MIN_PASSWORD_LENGTH: usize = 12;

// Argon2id parameters for account password hashing.
// These are intentionally stronger than the argon2 crate defaults (19 MiB / 2 iterations)
// because this is a key management system where password compromise is high-impact.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

static ARGON2_PARAMS: LazyLock<argon2::Params> = LazyLock::new(|| {
    argon2::Params::new(ARGON2_MEMORY_KIB, ARGON2_TIME_COST, ARGON2_PARALLELISM, None)
        .expect("Argon2 parameters are valid compile-time constants")
});

/// Returns an Argon2id instance configured with the server's standard password-hashing parameters.
/// Use this for both hashing new passwords and generating dummy hashes for timing-attack mitigation.
pub fn account_argon2() -> argon2::Argon2<'static> {
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, ARGON2_PARAMS.clone())
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Password {
    inner: Zeroizing<String>,
}

impl Deref for Password {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Password {
    pub fn new(password: &str) -> Self {
        Self {
            inner: Zeroizing::new(password.to_string()),
        }
    }
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, PartialEq, sqlx::Type, Default, ValueEnum)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "account_type", rename_all = "snake_case")]
pub enum AccountType {
    #[default]
    User,
    Service,
    System,
}

impl std::fmt::Display for AccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountType::User => write!(f, "user"),
            AccountType::Service => write!(f, "service"),
            AccountType::System => write!(f, "system"),
        }
    }
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, PartialEq, sqlx::Type, Default)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "account_status", rename_all = "snake_case")]
pub enum AccountStatus {
    #[default]
    Active,
    Locked,
    Disabled,
    Deleted,
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountStatus::Active => write!(f, "active"),
            AccountStatus::Locked => write!(f, "locked"),
            AccountStatus::Disabled => write!(f, "disabled"),
            AccountStatus::Deleted => write!(f, "deleted"),
        }
    }
}

// Internal working object for accounts
#[derive(sqlx::FromRow, Debug, Clone)]
pub struct Account {
    pub id: AccountId,
    pub short_id: ShortId,
    pub name: AccountName,
    pub account_type: AccountType,

    pub status: AccountStatus,
    pub status_reason: Option<String>,
    pub locked_until: Option<DateTime<Utc>>,

    pub status_changed_at: Option<DateTime<Utc>>,
    pub status_changed_by: Option<AccountId>,

    pub password_hash: Option<String>,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    #[sqlx(default)]
    pub mfa_backup_codes: Option<String>,

    #[sqlx(default)]
    pub client_cert_fingerprint: Option<String>,
    #[sqlx(default)]
    pub client_cert_subject: Option<String>,

    pub last_login_at: Option<DateTime<Utc>>,
    pub failed_login_attempts: i32,

    pub password_changed_at: Option<DateTime<Utc>>,
    pub must_change_password: bool,

    pub full_name: Option<String>,
    pub email: Option<String>,
    pub metadata: Metadata,

    /// Service accounts have a separate passphrase field
    pub passphrase_hash: Option<String>,
    /// Service accounts with ed25519 keys have a separate public key field
    pub public_key: Option<String>,

    pub created_by: Option<AccountId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<AccountId>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub deleted_by: Option<AccountId>,
}

/// A resolved reference to another account, carrying both the display ID and human-readable name.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountRef {
    pub id: ShortId,
    pub name: AccountName,
}

/// Public information from accounts. Keeps sensitive fields hidden.
#[derive(sqlx::FromRow, Debug, Serialize, Deserialize, Clone)]
pub struct AccountDto {
    pub id: ShortId,
    pub account_name: AccountName,
    pub account_type: AccountType,

    pub status: AccountStatus,
    pub status_reason: Option<String>,
    pub locked_until: Option<DateTime<Utc>>,
    pub status_changed_at: Option<DateTime<Utc>>,
    /// Resolved only by the describe endpoint; None in list results.
    #[sqlx(skip)]
    pub status_changed_by: Option<AccountRef>,

    pub mfa_enabled: bool,

    pub last_login_at: Option<DateTime<Utc>>,
    pub failed_login_attempts: i32,
    pub password_changed_at: Option<DateTime<Utc>>,
    pub must_change_password: bool,

    pub full_name: Option<String>,
    pub email: Option<String>,
    pub metadata: Metadata,

    /// Subject DN of the registered mTLS client cert (Commercial Edition only)
    pub client_cert_subject: Option<String>,

    pub created_at: DateTime<Utc>,
    /// Resolved only by the describe endpoint; None in list results.
    #[sqlx(skip)]
    pub created_by: Option<AccountRef>,
    pub updated_at: Option<DateTime<Utc>>,
    /// Resolved only by the describe endpoint; None in list results.
    #[sqlx(skip)]
    pub updated_by: Option<AccountRef>,
    pub deleted_at: Option<DateTime<Utc>>,
    /// Resolved only by the describe endpoint; None in list results.
    #[sqlx(skip)]
    pub deleted_by: Option<AccountRef>,
}

impl From<&Account> for AccountDto {
    fn from(u: &Account) -> Self {
        Self {
            id: u.short_id.clone(),
            account_name: u.name.clone(),
            account_type: u.account_type,

            status: u.status,
            status_reason: u.status_reason.clone(),
            locked_until: u.locked_until,
            status_changed_at: u.status_changed_at,
            status_changed_by: None,

            mfa_enabled: u.mfa_enabled,

            last_login_at: u.last_login_at,
            failed_login_attempts: u.failed_login_attempts,
            password_changed_at: u.password_changed_at,
            must_change_password: u.must_change_password,

            full_name: u.full_name.clone(),
            email: u.email.clone(),
            metadata: u.metadata.clone(),
            client_cert_subject: u.client_cert_subject.clone(),

            created_at: u.created_at,
            created_by: None,
            updated_at: u.updated_at,
            updated_by: None,
            deleted_at: u.deleted_at,
            deleted_by: None,
        }
    }
}

#[async_trait::async_trait]
pub trait AccountStore: Send + Sync {
    async fn find_by_id(&self, account_id: AccountId) -> CkResult<Option<Account>>;
    async fn find_by_name(&self, account_name: &AccountName) -> CkResult<Option<Account>>;

    // async fn create_system_account(&self, account: &Account) -> CkResult<()>;
    async fn create_account(&self, ctx: &CallContext, account: &Account) -> CkResult<()>;
    async fn update_account(&self, ctx: &CallContext, account: &Account) -> CkResult<()>;

    async fn set_status(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        status: AccountStatus,
        reason: Option<String>,
    ) -> CkResult<bool>;

    async fn get_admin_count(&self) -> CkResult<usize>;
    async fn count_user_service_accounts(&self) -> CkResult<i64>;
    async fn is_admin(&self, account_id: AccountId) -> CkResult<bool>;
    async fn grant_admin(&self, ctx: &CallContext, target_account_id: AccountId) -> CkResult<()>;
    async fn revoke_admin(&self, ctx: &CallContext, target_account_id: AccountId) -> CkResult<()>;

    async fn delete_account(&self, ctx: &CallContext, account_id: AccountId) -> CkResult<()>;

    async fn search(&self, query: &AccountSearchQuery) -> CkResult<(Vec<AccountDto>, usize)>;

    /// Look up a service account by the SHA-256 fingerprint of its registered client certificate.
    async fn find_by_cert_fingerprint(&self, fingerprint: &str) -> CkResult<Option<Account>>;

    /// Register (or clear) a client certificate on an account.
    /// Pass `None` for both to remove the cert.
    async fn set_client_cert(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        fingerprint: Option<String>,
        subject: Option<String>,
    ) -> CkResult<()>;

    async fn set_mfa_backup_codes(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        codes_json: Option<String>,
    ) -> CkResult<()>;

    async fn set_mfa_enabled(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        enabled: bool,
        secret: Option<String>,
    ) -> CkResult<()>;
}

pub struct SqlAccountStore {
    pool: PgPool,
}

impl SqlAccountStore {
    pub fn new(pool: PgPool) -> CkResult<Self> {
        Ok(Self { pool })
    }
}

#[async_trait::async_trait]
impl AccountStore for SqlAccountStore {
    async fn find_by_id(&self, account_id: AccountId) -> CkResult<Option<Account>> {
        let row = sqlx::query_as::<_, Account>(&one_line_sql(
            r#"
        SELECT
            id, short_id, name, account_type,
            status, status_reason, locked_until,
            status_changed_at, status_changed_by,
            password_hash, mfa_enabled, mfa_secret, mfa_backup_codes,
            last_login_at, failed_login_attempts, password_changed_at, must_change_password,
            full_name, email, metadata, passphrase_hash, public_key,
            client_cert_fingerprint, client_cert_subject,
            created_at, created_by, updated_at, updated_by, deleted_at, deleted_by
        FROM accounts
        WHERE id = $1 AND deleted_at IS NULL
        LIMIT 1
        "#,
        ))
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn find_by_name(&self, name: &AccountName) -> CkResult<Option<Account>> {
        // let name = canonicalize(name);
        let row = sqlx::query_as::<_, Account>(&one_line_sql(
            r#"
        SELECT
            id, short_id, name, account_type,
            status, status_reason, locked_until,
            status_changed_at, status_changed_by,
            password_hash, mfa_enabled, mfa_secret, mfa_backup_codes,
            last_login_at, failed_login_attempts, password_changed_at, must_change_password,
            full_name, email, metadata, passphrase_hash, public_key,
            client_cert_fingerprint, client_cert_subject,
            created_at, created_by, updated_at, updated_by, deleted_at, deleted_by
        FROM accounts
        WHERE lower(name) = lower($1) AND deleted_at IS NULL
        LIMIT 1
        "#,
        ))
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .inspect_err(|e| error!("Error in find_by_name: {}", e))?;

        Ok(row)
    }

    async fn create_account(&self, ctx: &CallContext, account: &Account) -> CkResult<()> {
        let mut account = account.clone();
        account.created_by = Some(*ctx.actor.require_account_id()?);
        account.created_at = Utc::now();

        sqlx::query(&one_line_sql(
            r#"
        INSERT INTO accounts (
            id, name, account_type,
            status, status_reason, locked_until,
            status_changed_by, status_changed_at,
            password_hash, mfa_enabled, mfa_secret,
            last_login_at, failed_login_attempts, password_changed_at, must_change_password,
            full_name, email, metadata,
            deleted_at, passphrase_hash, public_key,
            created_by
        )
        VALUES (
            $1,$2,$3,
            $4,$5,$6,
            $7,$8,
            $9,$10,$11,
            $12,$13,$14,$15,
            $16,$17,$18,
            $19,$20,$21,
            $22
        )
    "#,
        ))
        .bind(account.id)
        .bind(&account.name)
        .bind(account.account_type)
        .bind(account.status)
        .bind(&account.status_reason)
        .bind(account.locked_until)
        .bind(account.status_changed_by)
        .bind(account.status_changed_at)
        .bind(&account.password_hash)
        .bind(account.mfa_enabled)
        .bind(&account.mfa_secret)
        .bind(account.last_login_at)
        .bind(account.failed_login_attempts)
        .bind(account.password_changed_at)
        .bind(account.must_change_password)
        .bind(&account.full_name)
        .bind(&account.email)
        .bind(&account.metadata)
        .bind(account.deleted_at)
        .bind(&account.passphrase_hash)
        .bind(&account.public_key)
        .bind(account.created_by)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn update_account(&self, ctx: &CallContext, account: &Account) -> CkResult<()> {
        let mut account = account.clone();
        account.updated_at = Some(Utc::now());
        account.updated_by = ctx.actor.account_id().copied();

        sqlx::query(&one_line_sql(
            r#"
        UPDATE accounts
        SET
            name = $2,
            account_type = $3,

            status = $4,
            status_reason = $5,
            locked_until = $6,
            status_changed_at = $7,
            status_changed_by = $8,

            password_hash = COALESCE($9, password_hash),
            mfa_enabled = $10,
            mfa_secret = COALESCE($11, mfa_secret),

            last_login_at = $12,
            failed_login_attempts = $13,
            password_changed_at = $14,
            must_change_password = $15,

            full_name = $16,
            email = $17,
            metadata = $18,

            deleted_at = $19,
            updated_at = now(),
            updated_by = $22,

            passphrase_hash = COALESCE($20, passphrase_hash),
            public_key = COALESCE($21, public_key)
        WHERE id = $1
        "#,
        ))
        .bind(account.id)
        .bind(&account.name)
        .bind(account.account_type)
        .bind(account.status)
        .bind(&account.status_reason)
        .bind(account.locked_until)
        .bind(account.status_changed_at)
        .bind(account.status_changed_by)
        .bind(&account.password_hash)
        .bind(account.mfa_enabled)
        .bind(&account.mfa_secret)
        .bind(account.last_login_at)
        .bind(account.failed_login_attempts)
        .bind(account.password_changed_at)
        .bind(account.must_change_password)
        .bind(&account.full_name)
        .bind(&account.email)
        .bind(&account.metadata)
        .bind(account.deleted_at)
        .bind(&account.passphrase_hash)
        .bind(&account.public_key)
        .bind(account.updated_by)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn find_by_cert_fingerprint(&self, fingerprint: &str) -> CkResult<Option<Account>> {
        let row = sqlx::query_as::<_, Account>(&one_line_sql(
            r#"
        SELECT
            id, short_id, name, account_type,
            status, status_reason, locked_until,
            status_changed_at, status_changed_by,
            password_hash, mfa_enabled, mfa_secret, mfa_backup_codes,
            client_cert_fingerprint, client_cert_subject,
            last_login_at, failed_login_attempts, password_changed_at, must_change_password,
            full_name, email, metadata, passphrase_hash, public_key,
            client_cert_fingerprint, client_cert_subject,
            created_at, created_by, updated_at, updated_by, deleted_at, deleted_by
        FROM accounts
        WHERE client_cert_fingerprint = $1 AND deleted_at IS NULL
        LIMIT 1
        "#,
        ))
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn set_client_cert(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        fingerprint: Option<String>,
        subject: Option<String>,
    ) -> CkResult<()> {
        sqlx::query(
            r#"
        UPDATE accounts
        SET client_cert_fingerprint = $2,
            client_cert_subject     = $3,
            updated_at              = now(),
            updated_by              = $4
        WHERE id = $1
          AND deleted_at IS NULL
        "#,
        )
        .bind(account_id)
        .bind(&fingerprint)
        .bind(&subject)
        .bind(ctx.actor.account_id())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Sets account status (+ optional reason) and maintains consistency rules:
    /// - If status != Locked -> locked_until is cleared (matches DB CHECK constraint).
    /// - status_changed_at is always updated.
    /// - status_changed_by is set to actor (or NULL if not provided).
    ///
    /// Returns `true` if an account row was updated.
    async fn set_status(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        status: AccountStatus,
        reason: Option<String>,
    ) -> CkResult<bool> {
        let locked_until: Option<DateTime<Utc>> = match status {
            AccountStatus::Locked => None,
            _ => None,
        };

        let res = sqlx::query(
            r#"
        UPDATE accounts
        SET
            status = $2,
            status_reason = $3,
            locked_until = $4,
            status_changed_at = now(),
            status_changed_by = $5,
            updated_at = now()
        WHERE id = $1
          AND deleted_at IS NULL
        "#,
        )
        .bind(account_id)
        .bind(status)
        .bind(reason)
        .bind(locked_until)
        .bind(ctx.actor.account_id())
        .execute(&self.pool)
        .await?;

        Ok(res.rows_affected() == 1)
    }

    /// Returns the number of non-deleted accounts that have the `platform:admin` role.
    async fn get_admin_count(&self) -> CkResult<usize> {
        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)::bigint
            FROM rbac_account_roles ar
            JOIN rbac_roles r ON r.id = ar.role_id
            JOIN accounts a ON a.id = ar.account_id
            WHERE r.name = $1
              AND a.deleted_at IS NULL
              AND (ar.valid_from  IS NULL OR ar.valid_from  <= now())
              AND (ar.valid_until IS NULL OR ar.valid_until >  now())
            "#,
        )
        .bind(ADMIN_ROLE_NAME)
        .fetch_one(&self.pool)
        .await?;

        Ok(total as usize)
    }

    /// Returns the number of non-deleted user and service accounts (excludes system accounts).
    /// Used for license enforcement.
    async fn count_user_service_accounts(&self) -> CkResult<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM accounts WHERE deleted_at IS NULL AND account_type IN ('user', 'service')",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    /// Returns true if the given account currently has the `platform:admin` role.
    async fn is_admin(&self, account_id: AccountId) -> CkResult<bool> {
        let exists: Option<bool> = sqlx::query_scalar(
            r#"
            SELECT TRUE
            FROM rbac_account_roles ar
            JOIN rbac_roles r ON r.id = ar.role_id
            JOIN accounts a ON a.id = ar.account_id
            WHERE r.name = $1
              AND ar.account_id = $2
              AND a.deleted_at IS NULL
              AND (ar.valid_from  IS NULL OR ar.valid_from  <= now())
              AND (ar.valid_until IS NULL OR ar.valid_until >  now())
            LIMIT 1
            "#,
        )
        .bind(ADMIN_ROLE_NAME)
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(exists.is_some())
    }

    /// Grants `platform:admin` to `target_account_id` (idempotent).
    ///
    /// `actor` is recorded in `created_by` (can be None for system/bootstrap actions).
    async fn grant_admin(&self, ctx: &CallContext, target_account_id: AccountId) -> CkResult<()> {
        sqlx::query(
            r#"
            INSERT INTO rbac_account_roles (account_id, role_id, created_by)
            SELECT $2, r.id, $3
            FROM rbac_roles r
            WHERE r.name = $1
            ON CONFLICT (account_id, role_id) DO NOTHING
            "#,
        )
        .bind(ADMIN_ROLE_NAME)
        .bind(target_account_id)
        .bind(ctx.actor.account_id().copied())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Revokes `platform:admin` from `target_account_id`.
    ///
    /// Safety:
    /// - Prevents removing the last remaining admin (non-deleted).
    /// - Uses a transaction + `FOR UPDATE` lock on the admin role row to avoid races.
    async fn revoke_admin(&self, _ctx: &CallContext, target_account_id: AccountId) -> CkResult<()> {
        let mut tx = self.pool.begin().await?;

        // Serialize admin changes by locking the role row.
        // If the role does not exist, this is a configuration error.
        let role_id: uuid::Uuid = sqlx::query_scalar(
            r#"
            SELECT id
            FROM rbac_roles
            WHERE name = $1
            FOR UPDATE
            "#,
        )
        .bind(ADMIN_ROLE_NAME)
        .fetch_one(&mut *tx)
        .await?;

        // Is target currently an admin? If not, we are done (idempotent).
        let target_is_admin: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM rbac_account_roles ar
                JOIN accounts a ON a.id = ar.account_id
                WHERE ar.role_id = $1
                  AND ar.account_id = $2
                  AND a.deleted_at IS NULL
                  AND (ar.valid_from  IS NULL OR ar.valid_from  <= now())
                  AND (ar.valid_until IS NULL OR ar.valid_until >  now())
            )
            "#,
        )
        .bind(role_id)
        .bind(target_account_id)
        .fetch_one(&mut *tx)
        .await?;

        if !target_is_admin {
            tx.commit().await?;
            return Ok(());
        }

        // Count current admins (excluding deleted accounts and expired assignments).
        let admin_count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)::bigint
            FROM rbac_account_roles ar
            JOIN accounts a ON a.id = ar.account_id
            WHERE ar.role_id = $1
              AND a.deleted_at IS NULL
              AND (ar.valid_from  IS NULL OR ar.valid_from  <= now())
              AND (ar.valid_until IS NULL OR ar.valid_until >  now())
            "#,
        )
        .bind(role_id)
        .fetch_one(&mut *tx)
        .await?;

        if admin_count <= 1 {
            return Err(ValidationError::InvalidOperation {
                message: "cannot revoke admin: this is the last remaining admin account".into(),
            }
            .into());
        }

        // Remove the role assignment
        sqlx::query(
            r#"
            DELETE FROM rbac_account_roles
            WHERE role_id = $1
              AND account_id = $2
            "#,
        )
        .bind(role_id)
        .bind(target_account_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn delete_account(&self, ctx: &CallContext, account_id: AccountId) -> CkResult<()> {
        let actor_id = ctx.actor.account_id().copied();
        sqlx::query(&one_line_sql(
            r#"
        UPDATE accounts
        SET deleted_at = now(), deleted_by = $2, status = 'disabled'
        WHERE id = $1 AND deleted_at IS NULL
        "#,
        ))
        .bind(account_id)
        .bind(actor_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn search(&self, query: &AccountSearchQuery) -> CkResult<(Vec<AccountDto>, usize)> {
        let limit: i64 = query.limit.unwrap_or(DEFAULT_LIMIT_VALUE).clamp(1, MAX_LIMIT_VALUE) as i64;
        let offset: i64 = query.offset.unwrap_or(0) as i64;

        // --------- Helper closure: build WHERE once (works for both SELECT and COUNT) ----------
        let apply_where = |qb: &mut QueryBuilder<Postgres>| {
            qb.push(" WHERE deleted_at IS NULL");

            // Prefix search on name
            if let Some(prefix) = query.prefix.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
                let like_prefix = format!("{prefix}%");
                qb.push(" AND name ILIKE ");
                qb.push_bind(like_prefix);
            }

            // Prefix search on short_id
            if let Some(id_prefix) = query.id_prefix.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
                qb.push(" AND short_id ILIKE ");
                qb.push_bind(format!("{}%", escape_like(id_prefix)));
            }

            // Like search on many fields
            let like: Option<String> = query
                .q
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| format!("%{}%", s.to_lowercase()));

            if let Some(like) = like.as_ref() {
                qb.push(" AND (");
                qb.push("name ILIKE ");
                qb.push_bind(like.clone());
                qb.push(" OR email ILIKE ");
                qb.push_bind(like.clone());
                qb.push(" OR full_name ILIKE ");
                qb.push_bind(like.clone());

                qb.push(" OR (metadata->'labels')::text ILIKE ");
                qb.push_bind(like.clone());

                qb.push(")");
            }

            if !query.account_type.is_empty() {
                qb.push(" AND account_type IN (");
                let mut sep = qb.separated(", ");
                for t in &query.account_type {
                    sep.push_bind(*t);
                }
                sep.push_unseparated(")");
            }

            if !query.status.is_empty() {
                qb.push(" AND status IN (");
                let mut sep = qb.separated(", ");
                for s in &query.status {
                    sep.push_bind(*s);
                }
                sep.push_unseparated(")");
            }

            // Label key existence filters (AND semantics)
            for k in &query.label_key {
                qb.push(" AND (metadata->'labels') ? ");
                qb.push_bind(k.clone());
            }

            // Label key=value filters (AND semantics)
            for (k, v) in &query.label {
                qb.push(" AND (metadata->'labels'->>"); // ->> needs the key as text
                qb.push_bind(k.clone());
                qb.push(") = ");
                qb.push_bind(v.clone());
            }

            // query before
            if let Some(created_before) = query.created_before {
                qb.push(" AND created_at < ");
                qb.push_bind(created_before);
            }
            // query after
            if let Some(created_after) = query.created_after {
                qb.push(" AND created_at > ");
                qb.push_bind(created_after);
            }
        };

        // ------------------ 1) Fetch rows ------------------
        let mut qb = QueryBuilder::<Postgres>::new(&one_line_sql(
            r#"
                SELECT
                    short_id AS id, name AS account_name, account_type,
                    status, status_reason, locked_until,
                    status_changed_at, status_changed_by,
                    mfa_enabled,
                    last_login_at, failed_login_attempts, password_changed_at, must_change_password,
                    full_name, email, metadata, passphrase_hash, public_key,
                    client_cert_fingerprint, client_cert_subject,
                    created_at, updated_at, deleted_at
                FROM accounts
            "#,
        ));

        apply_where(&mut qb);

        let o = query.order.to_string();
        match query.sort_by {
            AccountSortBy::Name => qb.push(format!(" ORDER BY lower(name) {o}, created_at {o}")),
            AccountSortBy::CreatedAt => qb.push(format!(" ORDER BY created_at {o}")),
            AccountSortBy::StatusChangedAt => {
                qb.push(format!(" ORDER BY status_changed_at {o} NULLS LAST, created_at {o}"))
            }
            AccountSortBy::Type => qb.push(format!(" ORDER BY account_type {o}, created_at {o}")),
            AccountSortBy::Status => qb.push(format!(" ORDER BY status {o}, created_at {o}")),
        };

        qb.push(" LIMIT ");
        qb.push_bind(limit);
        qb.push(" OFFSET ");
        qb.push_bind(offset);

        let rows: Vec<AccountDto> = qb.build_query_as().fetch_all(&self.pool).await?;

        // ------------------ 2) Fetch count ------------------
        let mut qb = QueryBuilder::<Postgres>::new("SELECT COUNT(*)::bigint FROM accounts");
        apply_where(&mut qb);

        let total: i64 = qb.build_query_scalar().fetch_one(&self.pool).await?;

        Ok((rows, total as usize))
    }

    async fn set_mfa_backup_codes(
        &self,
        _ctx: &CallContext,
        account_id: AccountId,
        codes_json: Option<String>,
    ) -> CkResult<()> {
        sqlx::query("UPDATE accounts SET mfa_backup_codes = $2, updated_at = now() WHERE id = $1")
            .bind(account_id)
            .bind(&codes_json)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_mfa_enabled(
        &self,
        _ctx: &CallContext,
        account_id: AccountId,
        enabled: bool,
        secret: Option<String>,
    ) -> CkResult<()> {
        sqlx::query("UPDATE accounts SET mfa_enabled = $2, mfa_secret = $3, updated_at = now() WHERE id = $1")
            .bind(account_id)
            .bind(enabled)
            .bind(&secret)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
pub struct InMemoryAccountStore {
    accounts: Mutex<HashMap<AccountId, Account>>,
    account_index: Mutex<HashMap<String, AccountId>>,

    role_bindings: Mutex<HashMap<String, HashSet<AccountId>>>,
}

#[cfg(test)]
impl Default for InMemoryAccountStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl InMemoryAccountStore {
    pub fn new() -> Self {
        Self {
            accounts: Mutex::new(HashMap::new()),
            account_index: Mutex::new(HashMap::new()),
            role_bindings: Mutex::new(HashMap::new()),
        }
    }

    /// Directly seed an account as a platform admin, bypassing the async account manager.
    /// Used in test fixtures so that `create_mock_app_state()` can pre-register
    /// `system_account_id` as an admin without needing an async runtime or an existing actor.
    pub fn seed_admin(&self, account_id: AccountId) {
        let account = Account {
            id: account_id,
            short_id: ShortId::generate("acc_", 8),
            name: AccountName::try_from("system").expect("valid account name"),
            account_type: AccountType::System,
            status: AccountStatus::Active,
            status_reason: None,
            locked_until: None,
            status_changed_at: None,
            status_changed_by: None,
            password_hash: None,
            mfa_enabled: false,
            mfa_secret: None,
            mfa_backup_codes: None,
            client_cert_fingerprint: None,
            client_cert_subject: None,
            last_login_at: None,
            failed_login_attempts: 0,
            password_changed_at: None,
            must_change_password: false,
            full_name: None,
            email: None,
            metadata: Default::default(),
            passphrase_hash: None,
            public_key: None,
            created_by: Some(account_id),
            created_at: chrono::Utc::now(),
            updated_at: None,
            updated_by: None,
            deleted_at: None,
            deleted_by: None,
        };

        self.accounts.lock().insert(account_id, account);
        self.account_index.lock().insert("system".to_string(), account_id);
        self.role_bindings
            .lock()
            .entry(ADMIN_ROLE_NAME.to_string())
            .or_default()
            .insert(account_id);
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl AccountStore for InMemoryAccountStore {
    async fn find_by_id(&self, account_id: AccountId) -> CkResult<Option<Account>> {
        let accounts = self.accounts.lock();
        Ok(accounts.get(&account_id).filter(|a| a.deleted_at.is_none()).cloned())
    }

    async fn find_by_name(&self, account_name: &AccountName) -> CkResult<Option<Account>> {
        let name_index = self.account_index.lock();
        if let Some(account_id) = name_index.get(&account_name.to_string()) {
            let accounts = self.accounts.lock();
            Ok(accounts.get(account_id).filter(|a| a.deleted_at.is_none()).cloned())
        } else {
            Ok(None)
        }
    }

    async fn create_account(&self, _ctx: &CallContext, account: &Account) -> CkResult<()> {
        let mut accounts = self.accounts.lock();
        let mut name_index = self.account_index.lock();

        accounts.insert(account.id, account.clone());
        name_index.insert(account.name.to_string(), account.id);
        Ok(())
    }

    async fn update_account(&self, _ctx: &CallContext, account: &Account) -> CkResult<()> {
        let mut accounts = self.accounts.lock();
        accounts.insert(account.id, account.clone());
        Ok(())
    }

    async fn set_status(
        &self,
        _ctx: &CallContext,
        account_id: AccountId,
        status: AccountStatus,
        reason: Option<String>,
    ) -> CkResult<bool> {
        let mut accounts = self.accounts.lock();

        let Some(account) = accounts.get_mut(&account_id) else {
            return Ok(false);
        };

        if account.status == status && account.status_reason == reason {
            return Ok(false);
        }

        account.status = status;
        account.status_reason = reason;
        account.status_changed_at = Some(Utc::now());
        // account.status_changed_by = actor; // not tracked in in-memory store
        Ok(true)
    }

    async fn get_admin_count(&self) -> CkResult<usize> {
        let accounts = self.accounts.lock();
        let bindings = self.role_bindings.lock();

        let admins = bindings.get(ADMIN_ROLE_NAME);
        let count = admins
            .map(|set| {
                set.iter()
                    .filter(|id| accounts.get(id).is_some_and(|u| u.deleted_at.is_none()))
                    .count()
            })
            .unwrap_or(0);

        Ok(count)
    }

    async fn count_user_service_accounts(&self) -> CkResult<i64> {
        let accounts = self.accounts.lock();
        let count = accounts
            .values()
            .filter(|a| {
                a.deleted_at.is_none()
                    && (a.account_type == AccountType::User || a.account_type == AccountType::Service)
            })
            .count();
        Ok(count as i64)
    }

    async fn is_admin(&self, account_id: AccountId) -> CkResult<bool> {
        let accounts = self.accounts.lock();
        let bindings = self.role_bindings.lock();

        // not found or deleted => not admin (matches DB semantics)
        let Some(u) = accounts.get(&account_id) else {
            return Ok(false);
        };
        if u.deleted_at.is_some() {
            return Ok(false);
        }

        Ok(bindings
            .get(ADMIN_ROLE_NAME)
            .map(|set| set.contains(&account_id))
            .unwrap_or(false))
    }

    async fn grant_admin(&self, _ctx: &CallContext, target_account_id: AccountId) -> CkResult<()> {
        // If account doesn't exist (or is deleted), decide your policy:
        // Here: error if missing, ignore if deleted.
        let accounts = self.accounts.lock();
        let Some(u) = accounts.get(&target_account_id) else {
            return Err(CkError::ResourceNotFound {
                kind: "account",
                id: target_account_id.to_string(),
            });
        };
        if u.deleted_at.is_some() {
            return Err(ValidationError::InvalidOperation {
                message: "cannot grant admin to a deleted account".into(),
            }
            .into());
        }
        drop(accounts);

        let mut bindings = self.role_bindings.lock();
        let set = bindings.entry(ADMIN_ROLE_NAME.to_string()).or_default();
        set.insert(target_account_id);

        Ok(())
    }

    async fn revoke_admin(&self, _ctx: &CallContext, target_account_id: AccountId) -> CkResult<()> {
        // Acquire locks in a consistent order to avoid deadlocks:
        let accounts = self.accounts.lock();
        let mut bindings = self.role_bindings.lock();

        let Some(admins) = bindings.get_mut(ADMIN_ROLE_NAME) else {
            // no admins at all => idempotent
            return Ok(());
        };

        // If target isn't an admin => idempotent
        if !admins.contains(&target_account_id) {
            return Ok(());
        }

        // Count current *valid* admins (non-deleted existing accounts)
        let current_admin_count = admins
            .iter()
            .filter(|id| accounts.get(id).is_some_and(|u| u.deleted_at.is_none()))
            .count();

        if current_admin_count <= 1 {
            return Err(ValidationError::InvalidOperation {
                message: "cannot revoke admin: this is the last remaining admin account".into(),
            }
            .into());
        }

        // Remove it
        admins.remove(&target_account_id);

        // Optional cleanup: if empty, remove role entry
        if admins.is_empty() {
            bindings.remove(ADMIN_ROLE_NAME);
        }

        Ok(())
    }

    async fn delete_account(&self, ctx: &CallContext, account_id: AccountId) -> CkResult<()> {
        let actor_id = ctx.actor.account_id().copied();
        let mut accounts = self.accounts.lock();
        if let Some(account) = accounts.get_mut(&account_id)
            && account.deleted_at.is_none()
        {
            account.deleted_at = Some(Utc::now());
            account.deleted_by = actor_id;
            account.status = AccountStatus::Disabled;
        }
        Ok(())
    }

    async fn search(&self, query: &AccountSearchQuery) -> CkResult<(Vec<AccountDto>, usize)> {
        let accounts = self.accounts.lock();

        let mut matched: Vec<Account> = accounts
            .values()
            .filter(|u| u.deleted_at.is_none())
            .filter(|u| {
                if let Some(term) = &query.q {
                    let t = term.to_lowercase();
                    u.name.to_string().contains(&t)
                        || u.email.as_deref().unwrap_or("").to_lowercase().contains(&t)
                        || u.full_name.as_deref().unwrap_or("").to_lowercase().contains(&t)
                } else {
                    true
                }
            })
            // .filter(|u| match query.account_type {
            //     QueryAccountType::All => true,
            //     QueryAccountType::User => u.account_type == AccountType::User,
            //     QueryAccountType::Service => u.account_type == AccountType::Service,
            //     QueryAccountType::System => u.account_type == AccountType::System,
            // })
            // .filter(|u| match query.status {
            //     QueryAccountStatus::All => true,
            //     QueryAccountStatus::Active => u.status == AccountStatus::Active,
            //     QueryAccountStatus::Disabled => u.status == AccountStatus::Disabled,
            //     QueryAccountStatus::Locked => u.status == AccountStatus::Locked,
            //     // QueryAccountStatus::Destroyed => u.deleted_at.is_some(),
            // })
            .cloned()
            .collect();

        matched.sort_by(|a, b| a.name.cmp(&b.name));

        let total = matched.len();
        let entries = matched
            .into_iter()
            .skip(query.offset.unwrap_or(DEFAULT_OFFSET_VALUE))
            .take(query.limit.unwrap_or(DEFAULT_LIMIT_VALUE).min(MAX_LIMIT_VALUE))
            .map(|u| AccountDto::from(&u))
            .collect();

        Ok((entries, total))
    }

    async fn find_by_cert_fingerprint(&self, fingerprint: &str) -> CkResult<Option<Account>> {
        let accounts = self.accounts.lock();
        Ok(accounts
            .values()
            .find(|a| a.deleted_at.is_none() && a.client_cert_fingerprint.as_deref() == Some(fingerprint))
            .cloned())
    }

    async fn set_client_cert(
        &self,
        _ctx: &CallContext,
        account_id: AccountId,
        fingerprint: Option<String>,
        subject: Option<String>,
    ) -> CkResult<()> {
        let mut accounts = self.accounts.lock();
        if let Some(acc) = accounts.get_mut(&account_id) {
            acc.client_cert_fingerprint = fingerprint;
            acc.client_cert_subject = subject;
        }
        Ok(())
    }

    async fn set_mfa_backup_codes(
        &self,
        _ctx: &CallContext,
        account_id: AccountId,
        codes_json: Option<String>,
    ) -> CkResult<()> {
        let mut accounts = self.accounts.lock();
        if let Some(acc) = accounts.get_mut(&account_id) {
            acc.mfa_backup_codes = codes_json;
        }
        Ok(())
    }

    async fn set_mfa_enabled(
        &self,
        _ctx: &CallContext,
        account_id: AccountId,
        enabled: bool,
        secret: Option<String>,
    ) -> CkResult<()> {
        let mut accounts = self.accounts.lock();
        if let Some(acc) = accounts.get_mut(&account_id) {
            acc.mfa_enabled = enabled;
            if secret.is_some() {
                acc.mfa_secret = secret;
            }
            if !enabled {
                acc.mfa_secret = None;
                acc.mfa_backup_codes = None;
            }
        }
        Ok(())
    }
}

pub struct AccountManager {
    store: Arc<dyn AccountStore>,
}

impl AccountManager {
    pub fn new(store: Arc<dyn AccountStore>) -> Self {
        Self { store }
    }

    pub async fn find_account_by_id(&self, account_id: AccountId) -> CkResult<Option<Account>> {
        self.store.find_by_id(account_id).await
    }

    pub async fn find_account_by_name(&self, name: &AccountName) -> CkResult<Option<Account>> {
        self.store.find_by_name(name).await
    }

    pub async fn find_account_by_cert_fingerprint(&self, fingerprint: &str) -> CkResult<Option<Account>> {
        self.store.find_by_cert_fingerprint(fingerprint).await
    }

    pub async fn set_client_cert(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        fingerprint: Option<String>,
        subject: Option<String>,
    ) -> CkResult<()> {
        self.store.set_client_cert(ctx, account_id, fingerprint, subject).await
    }

    pub async fn revoke_admin(&self, ctx: &CallContext, account_id: AccountId) -> CkResult<()> {
        self.store.revoke_admin(ctx, account_id).await
    }

    pub async fn grant_admin(&self, ctx: &CallContext, account_id: AccountId) -> CkResult<()> {
        self.store.grant_admin(ctx, account_id).await
    }

    pub async fn set_last_login(&self, ctx: &CallContext, account_id: AccountId) -> CkResult<()> {
        let mut account = self.try_get_account(account_id).await?;

        account.last_login_at = Some(Utc::now());
        account.failed_login_attempts = 0;
        account.locked_until = None;

        self.store.update_account(ctx, &account).await?;
        Ok(())
    }

    /// Increment the failed-login counter for an account.
    /// After `max_attempts` consecutive failures the account is temporarily
    /// locked for `lockout_minutes` minutes.
    pub async fn record_failed_login(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        max_attempts: u32,
        lockout_minutes: u64,
    ) -> CkResult<()> {
        let mut account = self.try_get_account(account_id).await?;

        account.failed_login_attempts += 1;

        if account.failed_login_attempts >= max_attempts as i32 {
            account.locked_until = Some(Utc::now() + chrono::Duration::minutes(lockout_minutes as i64));
            account.failed_login_attempts = 0;
            trace!(
                "Account '{}' locked for {} minutes after {} failed login attempts",
                account.name, lockout_minutes, max_attempts
            );
        }

        self.store.update_account(ctx, &account).await?;
        Ok(())
    }

    pub async fn update_password(&self, ctx: &CallContext, account: &Account, new_password: &Password) -> CkResult<()> {
        self.validate_password(new_password)?;

        let hash = account_argon2()
            .hash_password(new_password.as_bytes())
            .map_err(|_| CryptoError::PasswordHashingFailed)?
            .to_string();

        let mut updated_account = account.clone();
        updated_account.password_hash = Some(hash);
        updated_account.password_changed_at = Some(Utc::now());
        updated_account.must_change_password = false;
        updated_account.updated_at = Some(Utc::now());

        self.store.update_account(ctx, &updated_account).await?;
        Ok(())
    }

    fn validate_password(&self, password: &Password) -> CkResult<()> {
        if password.to_string().len() < MIN_PASSWORD_LENGTH {
            return Err(ValidationError::TooShort {
                field: "password",
                min: MIN_PASSWORD_LENGTH,
            }
            .into());
        }
        Ok(())
    }

    async fn create_impl(&self, ctx: &CallContext, data: &AccountData) -> CkResult<Account> {
        let mut password_hash = None;
        let mut must_change_password = false;
        let mut account_type = AccountType::User;
        let mut email = None;
        let mut full_name = None;

        let mut passphrase_hash = None;
        let mut public_key = None;

        match data.custom {
            CustomAccountData::User(ref user_data) => {
                if user_data.password.is_empty() {
                    return Err(ValidationError::MissingField { field: "password" }.into());
                }

                password_hash = Some(self.create_password_hash(&user_data.password)?);
                must_change_password = user_data.must_change_password;
                email = user_data.email.clone();
                full_name = user_data.full_name.clone();
            }
            CustomAccountData::Service(ref service_data) => {
                account_type = AccountType::Service;

                match service_data {
                    CustomServiceAccountData::Passphrase { passphrase } => {
                        passphrase_hash = Some(self.create_password_hash(passphrase)?);
                    }
                    CustomServiceAccountData::Ed25519 { public_key: pk } => {
                        public_key = Some(pk.clone());
                    }
                }
            }
        }

        let mut metadata = Metadata::default();
        if let Some(desc) = &data.description {
            metadata.add_description(desc);
        }
        metadata.add_labels(data.labels.clone());

        Ok(Account {
            id: AccountId::new(),
            short_id: ShortId::generate("acc_", 12),
            name: data.account_name.clone(),
            email,
            password_hash,
            account_type,
            status: if data.is_active {
                AccountStatus::Active
            } else {
                AccountStatus::Disabled
            },
            mfa_enabled: false,
            mfa_secret: None,
            last_login_at: None,
            failed_login_attempts: 0,
            locked_until: None,
            password_changed_at: None,
            must_change_password,
            full_name,
            metadata,
            created_at: Utc::now(),
            created_by: Some(*ctx.actor.require_account_id()?),
            updated_at: None,
            updated_by: None,
            deleted_at: None,
            deleted_by: None,
            status_changed_at: Some(Utc::now()),
            status_changed_by: Some(*ctx.actor.require_account_id()?),
            status_reason: None,
            passphrase_hash,
            public_key,
            mfa_backup_codes: None,
            client_cert_fingerprint: None,
            client_cert_subject: None,
        })
    }

    pub async fn get_admin_count(&self) -> CkResult<usize> {
        let result = self.store.get_admin_count().await?;
        Ok(result)
    }

    pub async fn count_user_service_accounts(&self) -> CkResult<i64> {
        self.store.count_user_service_accounts().await
    }

    pub async fn is_admin(&self, account_id: AccountId) -> CkResult<bool> {
        let result = self.store.is_admin(account_id).await?;
        Ok(result)
    }

    pub async fn create(&self, ctx: &CallContext, data: &AccountData) -> CkResult<Account> {
        trace!("Creating account '{}'", data.account_name);

        let account = self.store.find_by_name(&data.account_name).await?;
        if account.is_some() {
            return Err(ValidationError::AlreadyExists {
                field: "name",
                message: data.account_name.to_string(),
            }
            .into());
        }
        let account = self.create_impl(ctx, data).await?;

        self.store.create_account(ctx, &account).await?;
        Ok(account)
    }

    pub async fn authenticate(&self, password_hash: &str, password: &Password) -> CkResult<()> {
        let parsed_hash = PasswordHash::new(password_hash).map_err(|_| CryptoError::PasswordHashInvalid)?;

        if account_argon2()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            trace!("Password verified successfully");
            return Ok(());
        }

        trace!("Password not verified");
        Err(AuthError::Unauthenticated {
            reason: AuthFailReason::InvalidCredentials,
        }
        .into())
    }

    /// Generate a random plaintext password of the specified length.
    /// Uses the full 94-character printable ASCII charset for maximum entropy.
    pub fn generate_plaintext_password(len: usize) -> CkResult<Zeroizing<String>> {
        Ok(crate::global::utils::password::generate_strong_passphrase(len))
    }

    pub async fn search(&self, query: &AccountSearchQuery) -> CkResult<(Vec<AccountDto>, usize)> {
        self.store.search(query).await
    }

    pub async fn update_account(&self, ctx: &CallContext, account: &Account) -> CkResult<()> {
        self.store.update_account(ctx, account).await
    }

    pub async fn delete_account(&self, ctx: &CallContext, account_id: AccountId) -> CkResult<()> {
        self.store.delete_account(ctx, account_id).await
    }

    pub async fn set_mfa_backup_codes(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        codes_json: Option<String>,
    ) -> CkResult<()> {
        self.store.set_mfa_backup_codes(ctx, account_id, codes_json).await
    }

    pub async fn set_mfa_enabled(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        enabled: bool,
        secret: Option<String>,
    ) -> CkResult<()> {
        self.store.set_mfa_enabled(ctx, account_id, enabled, secret).await
    }

    fn create_password_hash(&self, password: &Password) -> CkResult<String> {
        self.validate_password(password)?;

        Ok(account_argon2()
            .hash_password(password.as_bytes())
            .map_err(|_| CryptoError::PasswordHashingFailed)?
            .to_string())
    }

    pub async fn set_change_password(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        must_change_pwd: bool,
    ) -> CkResult<()> {
        let mut account = match self.store.find_by_id(account_id).await? {
            Some(u) => u,
            None => {
                return Err(CkError::ResourceNotFound {
                    kind: "User",
                    id: account_id.to_string(),
                });
            }
        };

        account.must_change_password = must_change_pwd;
        account.updated_at = Some(Utc::now());

        self.store.update_account(ctx, &account).await?;
        Ok(())
    }

    async fn try_get_account(&self, account_id: AccountId) -> CkResult<Account> {
        match self.store.find_by_id(account_id).await? {
            Some(u) => Ok(u),
            None => Err(CkError::ResourceNotFound {
                kind: "user",
                id: account_id.to_string(),
            }),
        }
    }

    pub async fn disable_account(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        reason: Option<String>,
    ) -> CkResult<()> {
        let mut account = self.try_get_account(account_id).await?;

        if account.status == AccountStatus::Disabled {
            return Err(ValidationError::InvalidOperation {
                message: "account is already disabled".into(),
            }
            .into());
        }

        account.locked_until = None;
        if let Some(reason) = reason {
            account.status_reason = Some(reason);
        }
        account.status = AccountStatus::Disabled;
        account.status_changed_at = Some(Utc::now());

        self.store.update_account(ctx, &account).await?;
        Ok(())
    }

    pub async fn enable_account(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        reason: Option<String>,
    ) -> CkResult<()> {
        let mut account = self.try_get_account(account_id).await?;

        if account.status == AccountStatus::Active {
            return Err(ValidationError::InvalidOperation {
                message: "account is already active".into(),
            }
            .into());
        }

        account.locked_until = None;
        if let Some(reason) = reason {
            account.status_reason = Some(reason);
        }
        account.status = AccountStatus::Active;
        account.status_changed_at = Some(Utc::now());

        self.store.update_account(ctx, &account).await?;
        Ok(())
    }

    pub async fn lock_account(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        reason: Option<String>,
        locked_until: Option<DateTime<Utc>>,
    ) -> CkResult<()> {
        let mut account = self.try_get_account(account_id).await?;

        if account.status == AccountStatus::Locked {
            return Ok(());
        }

        if account.status == AccountStatus::Disabled {
            return Err(ValidationError::InvalidOperation {
                message: "cannot lock a disabled account".into(),
            }
            .into());
        }

        if let Some(until) = locked_until {
            account.locked_until = Some(until);
        }
        if let Some(reason) = reason {
            account.status_reason = Some(reason);
        }
        account.status = AccountStatus::Locked;
        account.status_changed_at = Some(Utc::now());
        account.status_changed_by = ctx.actor.account_id().copied();

        self.store.update_account(ctx, &account).await?;
        Ok(())
    }

    pub async fn unlock_account(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        reason: Option<String>,
    ) -> CkResult<()> {
        let mut account = self.try_get_account(account_id).await?;

        if account.status != AccountStatus::Locked {
            return Err(ValidationError::InvalidOperation {
                message: "account is not locked".into(),
            }
            .into());
        }

        account.locked_until = None;
        if let Some(reason) = reason {
            account.status_reason = Some(reason);
        }
        account.status = AccountStatus::Active;
        account.status_changed_at = Some(Utc::now());
        account.status_changed_by = ctx.actor.account_id().copied();

        self.store.update_account(ctx, &account).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::service::account::{AccountData, AccountSearchQuery, CustomAccountData, CustomUserAccountData};
    use hierarkey_core::Labels;
    use password_hash::PasswordHasher;

    fn make_manager() -> AccountManager {
        AccountManager::new(Arc::new(InMemoryAccountStore::new()))
    }

    fn sys_ctx() -> CallContext {
        // create_account requires require_account_id(), so we need an Account actor, not System.
        CallContext::for_account(AccountId::new())
    }

    fn user_data(name: &str) -> AccountData {
        AccountData {
            account_name: name.parse().unwrap(),
            is_active: true,
            description: None,
            labels: Labels::default(),
            custom: CustomAccountData::User(CustomUserAccountData {
                full_name: None,
                email: None,
                password: Password::new("correct-password-123"),
                must_change_password: false,
            }),
        }
    }

    async fn create_user(manager: &AccountManager, name: &str) -> Account {
        manager.create(&sys_ctx(), &user_data(name)).await.unwrap()
    }

    #[tokio::test]
    async fn create_user_success() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;
        assert_eq!(account.name.to_string(), "alice");
        assert_eq!(account.status, AccountStatus::Active);
        assert_eq!(account.account_type, AccountType::User);
        assert!(account.deleted_at.is_none());
    }

    #[tokio::test]
    async fn create_user_findable_by_id_and_name() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;

        let by_id = manager.find_account_by_id(account.id).await.unwrap();
        assert!(by_id.is_some(), "should find by id");

        let by_name = manager.find_account_by_name(&"alice".parse().unwrap()).await.unwrap();
        assert!(by_name.is_some(), "should find by name");
    }

    #[tokio::test]
    async fn create_duplicate_user_fails() {
        let manager = make_manager();
        create_user(&manager, "alice").await;
        let result = manager.create(&sys_ctx(), &user_data("alice")).await;
        assert!(result.is_err(), "duplicate create should fail");
    }

    #[tokio::test]
    async fn create_name_collision_is_case_insensitive() {
        let manager = make_manager();
        create_user(&manager, "Alice").await;
        let result = manager.create(&sys_ctx(), &user_data("alice")).await;
        assert!(result.is_err(), "case-insensitive name collision should fail");
    }

    #[tokio::test]
    async fn lock_account_sets_status_locked() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;

        manager
            .lock_account(&sys_ctx(), account.id, Some("testing".into()), None)
            .await
            .unwrap();

        let found = manager.find_account_by_id(account.id).await.unwrap().unwrap();
        assert_eq!(found.status, AccountStatus::Locked);
        assert_eq!(found.status_reason.as_deref(), Some("testing"));
    }

    #[tokio::test]
    async fn unlock_account_restores_active_status() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;
        manager.lock_account(&sys_ctx(), account.id, None, None).await.unwrap();

        manager.unlock_account(&sys_ctx(), account.id, None).await.unwrap();

        let found = manager.find_account_by_id(account.id).await.unwrap().unwrap();
        assert_eq!(found.status, AccountStatus::Active);
    }

    #[tokio::test]
    async fn unlock_active_account_fails() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;
        let result = manager.unlock_account(&sys_ctx(), account.id, None).await;
        assert!(result.is_err(), "unlocking an active account should fail");
    }

    #[tokio::test]
    async fn lock_sets_status_changed_at() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;
        let created_changed_at = account.status_changed_at;

        // Small sleep so the timestamp actually advances
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        manager.lock_account(&sys_ctx(), account.id, None, None).await.unwrap();

        let found = manager.find_account_by_id(account.id).await.unwrap().unwrap();
        assert!(found.status_changed_at.is_some(), "status_changed_at should be set after lock");
        assert_ne!(
            found.status_changed_at, created_changed_at,
            "status_changed_at should update after lock"
        );
    }

    #[tokio::test]
    async fn disable_sets_status_changed_at() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;

        manager.disable_account(&sys_ctx(), account.id, None).await.unwrap();

        let found = manager.find_account_by_id(account.id).await.unwrap().unwrap();
        assert_eq!(found.status, AccountStatus::Disabled);
        assert!(
            found.status_changed_at.is_some(),
            "status_changed_at should be set after disable"
        );
    }

    #[tokio::test]
    async fn enable_restores_active_and_sets_status_changed_at() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;
        manager.disable_account(&sys_ctx(), account.id, None).await.unwrap();

        manager.enable_account(&sys_ctx(), account.id, None).await.unwrap();

        let found = manager.find_account_by_id(account.id).await.unwrap().unwrap();
        assert_eq!(found.status, AccountStatus::Active);
        assert!(found.status_changed_at.is_some());
    }

    #[tokio::test]
    async fn grant_admin_makes_account_admin() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;
        assert!(!manager.is_admin(account.id).await.unwrap());

        manager.grant_admin(&sys_ctx(), account.id).await.unwrap();

        assert!(manager.is_admin(account.id).await.unwrap());
        assert_eq!(manager.get_admin_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn revoke_admin_removes_admin_role() {
        let manager = make_manager();
        let alice = create_user(&manager, "alice").await;
        let bob = create_user(&manager, "bob").await;
        manager.grant_admin(&sys_ctx(), alice.id).await.unwrap();
        manager.grant_admin(&sys_ctx(), bob.id).await.unwrap();

        manager.revoke_admin(&sys_ctx(), alice.id).await.unwrap();

        assert!(!manager.is_admin(alice.id).await.unwrap());
        assert!(manager.is_admin(bob.id).await.unwrap());
        assert_eq!(manager.get_admin_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn revoke_last_admin_fails() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;
        manager.grant_admin(&sys_ctx(), account.id).await.unwrap();

        let result = manager.revoke_admin(&sys_ctx(), account.id).await;
        assert!(result.is_err(), "revoking the last admin should fail");
    }

    #[tokio::test]
    async fn deleted_account_not_found_by_id() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;

        manager.delete_account(&sys_ctx(), account.id).await.unwrap();

        let found = manager.find_account_by_id(account.id).await.unwrap();
        assert!(found.is_none(), "deleted account should not be found by id");
    }

    #[tokio::test]
    async fn deleted_account_not_found_by_name() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;

        manager.delete_account(&sys_ctx(), account.id).await.unwrap();

        let found = manager.find_account_by_name(&account.name).await.unwrap();
        assert!(found.is_none(), "deleted account should not be found by name");
    }

    #[tokio::test]
    async fn deleted_account_name_can_be_reused() {
        let manager = make_manager();
        let account = create_user(&manager, "alice").await;
        manager.delete_account(&sys_ctx(), account.id).await.unwrap();

        let result = manager.create(&sys_ctx(), &user_data("alice")).await;
        assert!(result.is_ok(), "name should be reusable after soft delete");
    }

    #[tokio::test]
    async fn search_returns_all_active_accounts() {
        let manager = make_manager();
        create_user(&manager, "alice").await;
        create_user(&manager, "bob").await;
        create_user(&manager, "carol").await;

        let (entries, total) = manager.search(&AccountSearchQuery::default()).await.unwrap();
        assert_eq!(total, 3);
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn search_excludes_deleted_accounts() {
        let manager = make_manager();
        let alice = create_user(&manager, "alice").await;
        create_user(&manager, "bob").await;
        manager.delete_account(&sys_ctx(), alice.id).await.unwrap();

        let (_, total) = manager.search(&AccountSearchQuery::default()).await.unwrap();
        assert_eq!(total, 1, "deleted accounts should be excluded from search");
    }

    #[tokio::test]
    async fn search_by_query_filters_by_name() {
        let manager = make_manager();
        create_user(&manager, "alice").await;
        create_user(&manager, "bob").await;

        let query = AccountSearchQuery {
            q: Some("ali".into()),
            ..Default::default()
        };
        let (entries, total) = manager.search(&query).await.unwrap();
        assert_eq!(total, 1);
        assert_eq!(entries[0].account_name.to_string(), "alice");
    }

    #[tokio::test]
    async fn search_pagination_limit_and_offset() {
        let manager = make_manager();
        for name in ["alice", "bob", "carol", "dave", "eve"] {
            create_user(&manager, name).await;
        }

        let page1 = AccountSearchQuery {
            limit: Some(2),
            offset: Some(0),
            ..Default::default()
        };
        let (entries, total) = manager.search(&page1).await.unwrap();
        assert_eq!(total, 5, "total should reflect full count");
        assert_eq!(entries.len(), 2, "limit should be respected");

        let page2 = AccountSearchQuery {
            limit: Some(2),
            offset: Some(2),
            ..Default::default()
        };
        let (entries2, _) = manager.search(&page2).await.unwrap();
        assert_eq!(entries2.len(), 2);
        assert_ne!(entries[0].account_name, entries2[0].account_name, "pages should not overlap");
    }

    #[tokio::test]
    async fn search_total_reflects_unpaginated_count() {
        let manager = make_manager();
        for name in ["alice", "bob", "carol"] {
            create_user(&manager, name).await;
        }

        let query = AccountSearchQuery {
            limit: Some(1),
            ..Default::default()
        };
        let (entries, total) = manager.search(&query).await.unwrap();
        assert_eq!(entries.len(), 1, "only 1 entry returned due to limit");
        assert_eq!(total, 3, "total should be full count, not just page size");
    }

    // Argon2's algorithm and version fields are pub(crate), so we verify them
    // indirectly by checking the PHC hash string produced by account_argon2().
    // A hash of "$argon2id$v=19$..." confirms Argon2id + Version::V0x13 (0x13 = 19).
    #[test]
    fn account_argon2_produces_argon2id_v19_hashes() {
        let hash = account_argon2().hash_password(b"test").unwrap().to_string();
        assert!(hash.starts_with("$argon2id$v=19$"), "expected argon2id v19 hash, got: {hash}");
    }

    #[test]
    fn account_argon2_has_correct_memory_cost() {
        let a = account_argon2();
        assert_eq!(a.params().m_cost(), ARGON2_MEMORY_KIB);
    }

    #[test]
    fn account_argon2_has_correct_time_cost() {
        let a = account_argon2();
        assert_eq!(a.params().t_cost(), ARGON2_TIME_COST);
    }

    #[test]
    fn account_argon2_has_correct_parallelism() {
        let a = account_argon2();
        assert_eq!(a.params().p_cost(), ARGON2_PARALLELISM);
    }

    #[test]
    fn generate_plaintext_password_returns_correct_length() {
        for len in [1, 12, 24, 64, 128] {
            let pw = AccountManager::generate_plaintext_password(len).unwrap();
            assert_eq!(pw.len(), len, "expected length {len}");
        }
    }

    #[test]
    fn generate_plaintext_password_only_printable_ascii() {
        let pw = AccountManager::generate_plaintext_password(256).unwrap();
        assert!(
            pw.chars().all(|c| c.is_ascii_graphic()),
            "password contains non-printable char: {:?}",
            pw.as_str()
        );
    }

    #[test]
    fn generate_plaintext_password_contains_symbols() {
        // With a 94-char charset over 256 chars the probability that no symbol
        // appears is astronomically small.
        let pw = AccountManager::generate_plaintext_password(256).unwrap();
        assert!(
            pw.chars().any(|c| !c.is_ascii_alphanumeric()),
            "expected at least one symbol in a 256-char password"
        );
    }

    #[test]
    fn generate_plaintext_password_is_random() {
        let p1 = AccountManager::generate_plaintext_password(24).unwrap();
        let p2 = AccountManager::generate_plaintext_password(24).unwrap();
        assert_ne!(p1.as_str(), p2.as_str(), "two generated passwords should differ");
    }

    fn hash_password(password: &str) -> String {
        account_argon2().hash_password(password.as_bytes()).unwrap().to_string()
    }

    #[tokio::test]
    async fn authenticate_correct_password_succeeds() {
        let manager = make_manager();
        let hash = hash_password("correct-password");
        let result = manager.authenticate(&hash, &Password::new("correct-password")).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn authenticate_wrong_password_fails() {
        let manager = make_manager();
        let hash = hash_password("correct-password");
        let result = manager.authenticate(&hash, &Password::new("wrong-password")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticate_invalid_hash_format_fails() {
        let manager = make_manager();
        let result = manager
            .authenticate("not-a-valid-phc-hash", &Password::new("password"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticate_empty_password_against_non_empty_hash_fails() {
        let manager = make_manager();
        let hash = hash_password("non-empty");
        let result = manager.authenticate(&hash, &Password::new("")).await;
        assert!(result.is_err());
    }
}
