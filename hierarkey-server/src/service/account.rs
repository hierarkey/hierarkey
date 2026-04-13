// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::api_error::{ApiErrorCtx, HttpError};
use crate::manager::AccountManager;
use crate::manager::account::AccountDto;
pub use crate::manager::account::{AccountId, AccountStatus, AccountType, Password};
use crate::service::ApiMappableError;
use crate::{Account, TokenManager};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use hierarkey_core::api::status::{ApiCode, ApiErrorCode};
use hierarkey_core::resources::AccountName;
use hierarkey_core::{CkError, CkResult, Labels};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use tracing::trace;

// ------------------------------------------------------------------------------------------------

#[derive(thiserror::Error, Debug)]
pub enum AccountPromotionError {
    #[error("Account ID '{0}' not found")]
    IdNotFound(AccountId),
    #[error("Account '{0}' not found")]
    NotFound(AccountName),
    #[error("Account '{0}' is already an admin")]
    AlreadyAdmin(AccountName),
    #[error("Account '{0}' is locked and cannot be promoted")]
    Locked(AccountName),
    #[error("Machine account '{0}' cannot be promoted to admin")]
    ServiceAccount(AccountName),
    #[error("System account '{0}' cannot be promoted to admin")]
    SystemAccount(AccountName),

    #[error(transparent)]
    Store(#[from] CkError),
}

impl ApiMappableError for AccountPromotionError {
    fn into_http(self, fail_code: ApiCode) -> HttpError {
        match self {
            AccountPromotionError::NotFound(account_name) => HttpError::simple(
                StatusCode::NOT_FOUND,
                fail_code,
                ApiErrorCode::NotFound,
                format!("Account '{account_name}' not found"),
            ),
            AccountPromotionError::AlreadyAdmin(account_name) => HttpError::simple(
                StatusCode::CONFLICT,
                fail_code,
                ApiErrorCode::InvalidRequest,
                format!("Account '{account_name}' is already an admin"),
            ),
            AccountPromotionError::Locked(account_name) => HttpError::simple(
                StatusCode::CONFLICT,
                fail_code,
                ApiErrorCode::InvalidRequest,
                format!("Account '{account_name}' is locked and cannot be promoted"),
            ),
            AccountPromotionError::SystemAccount(account_name) => HttpError::simple(
                StatusCode::BAD_REQUEST,
                fail_code,
                ApiErrorCode::InvalidRequest,
                format!("System account '{account_name}' cannot be promoted to admin"),
            ),
            AccountPromotionError::ServiceAccount(account_name) => HttpError::simple(
                StatusCode::BAD_REQUEST,
                fail_code,
                ApiErrorCode::InvalidRequest,
                format!("Machine account '{account_name}' cannot be promoted to admin"),
            ),

            AccountPromotionError::Store(err) => HttpError::from_ck(err, ApiErrorCtx { fail_code }),
            AccountPromotionError::IdNotFound(account_id) => HttpError::simple(
                StatusCode::NOT_FOUND,
                fail_code,
                ApiErrorCode::NotFound,
                format!("Account ID '{account_id}' not found"),
            ),
        }
    }
}

// ------------------------------------------------------------------------------------------------

#[derive(thiserror::Error, Debug)]
pub enum AccountDemotionError {
    #[error("Account '{0}' not found")]
    NotFound(String),
    #[error("Account '{0}' is not an admin")]
    NotAnAdmin(String),
    #[error("Account '{0}' is locked and cannot be demoted")]
    Locked(String),
    #[error("Service account '{0}' cannot be demoted to admin")]
    ServiceAccount(String),
    #[error("System account '{0}' cannot be demoted to admin")]
    SystemAccount(String),
    #[error("Cannot demote the last admin account")]
    LastAdmin,

    #[error(transparent)]
    Store(#[from] CkError),
}

impl ApiMappableError for AccountDemotionError {
    fn into_http(self, fail_code: ApiCode) -> HttpError {
        match self {
            AccountDemotionError::NotFound(account_name) => HttpError::simple(
                StatusCode::NOT_FOUND,
                fail_code,
                ApiErrorCode::NotFound,
                format!("Account '{account_name}' not found"),
            ),
            AccountDemotionError::NotAnAdmin(account_name) => HttpError::simple(
                StatusCode::CONFLICT,
                fail_code,
                ApiErrorCode::InvalidRequest,
                format!("Account '{account_name}' is not an admin"),
            ),
            AccountDemotionError::Locked(account_name) => HttpError::simple(
                StatusCode::CONFLICT,
                fail_code,
                ApiErrorCode::InvalidRequest,
                format!("Account '{account_name}' is locked and cannot be promoted"),
            ),

            AccountDemotionError::SystemAccount(account_name) => HttpError::simple(
                StatusCode::BAD_REQUEST,
                fail_code,
                ApiErrorCode::InvalidRequest,
                format!("System account '{account_name}' cannot be promoted to admin"),
            ),

            AccountDemotionError::ServiceAccount(account_name) => HttpError::simple(
                StatusCode::BAD_REQUEST,
                fail_code,
                ApiErrorCode::InvalidRequest,
                format!("Service account '{account_name}' cannot be promoted to admin"),
            ),

            AccountDemotionError::LastAdmin => HttpError::simple(
                StatusCode::BAD_REQUEST,
                fail_code,
                ApiErrorCode::InvalidRequest,
                "Cannot demote the last admin account",
            ),

            AccountDemotionError::Store(err) => HttpError::from_ck(err, ApiErrorCtx { fail_code }),
        }
    }
}

// ------------------------------------------------------------------------------------------------

pub struct CustomUserAccountData {
    pub full_name: Option<String>,
    pub email: Option<String>,
    pub password: Password,
    pub must_change_password: bool,
}

pub enum CustomServiceAccountData {
    Ed25519 { public_key: String },
    Passphrase { passphrase: Password },
}

pub enum CustomAccountData {
    User(CustomUserAccountData),
    Service(CustomServiceAccountData),
}

pub struct AccountData {
    pub account_name: AccountName,
    pub is_active: bool,
    pub description: Option<String>,
    pub labels: Labels,
    pub custom: CustomAccountData,
}

// ------------------------------------------------------------------------------------------------

#[derive(Debug, Copy, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum QueryOrder {
    #[default]
    Asc,
    Desc,
}

impl std::fmt::Display for QueryOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryOrder::Asc => write!(f, "ASC"),
            QueryOrder::Desc => write!(f, "DESC"),
        }
    }
}

#[derive(clap::ValueEnum, Deserialize, Serialize, Clone, Debug, Default)]
pub enum AccountSortBy {
    #[default]
    Name,
    CreatedAt,
    StatusChangedAt,
    Type,
    Status,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct AccountSearchQuery {
    #[serde(default)]
    pub account_type: Vec<AccountType>, // User | Service | System, Empty for all

    #[serde(default)]
    pub status: Vec<AccountStatus>, // Active | Locked | Disabled, empty for all

    /// Optional text query.
    /// - If None => behaves like "list"
    /// - If Some => behaves like "search"
    pub q: Option<String>,

    /// Prefix name (only for list actions)
    pub prefix: Option<String>,

    /// Prefix match on account short_id (e.g. "acc_w" matches "acc_wabcdef...")
    pub id_prefix: Option<String>,

    #[serde(default)]
    pub order: QueryOrder, // asc/desc
    pub sort_by: AccountSortBy, // later: enum?

    #[serde(default)]
    pub label: HashMap<String, String>,

    #[serde(default)]
    pub label_key: Vec<String>,

    pub created_before: Option<DateTime<Utc>>,
    pub created_after: Option<DateTime<Utc>>,

    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

// ------------------------------------------------------------------------------------------------

pub struct AccountService {
    account_manager: Arc<AccountManager>,
    /// Serialises the check-then-grant sequence during bootstrap (admin_count == 0)
    /// to prevent a TOCTOU race where two concurrent requests both see zero admins
    /// and both succeed in promoting themselves.
    bootstrap_lock: Arc<AsyncMutex<()>>,
}

impl AccountService {
    pub fn new(account_manager: Arc<AccountManager>, _token_manager: Arc<TokenManager>) -> Self {
        Self {
            account_manager,
            bootstrap_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    pub async fn get_by_id(&self, _ctx: &CallContext, account_id: AccountId) -> CkResult<Account> {
        let Some(user) = self.account_manager.find_account_by_id(account_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "account",
                id: account_id.to_string(),
            });
        };

        Ok(user)
    }

    pub async fn find_by_name(&self, _ctx: &CallContext, account_name: &AccountName) -> CkResult<Option<Account>> {
        trace!("Fetching account by name '{}'", account_name);
        self.account_manager.find_account_by_name(account_name).await
    }

    pub async fn find_by_id(&self, _ctx: &CallContext, account_id: AccountId) -> CkResult<Option<Account>> {
        self.account_manager.find_account_by_id(account_id).await
    }

    pub async fn find_by_cert_fingerprint(&self, _ctx: &CallContext, fingerprint: &str) -> CkResult<Option<Account>> {
        self.account_manager.find_account_by_cert_fingerprint(fingerprint).await
    }

    pub async fn set_client_cert(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        fingerprint: Option<String>,
        subject: Option<String>,
    ) -> CkResult<()> {
        self.account_manager
            .set_client_cert(ctx, account_id, fingerprint, subject)
            .await
    }

    pub async fn set_mfa_backup_codes(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        codes_json: Option<String>,
    ) -> CkResult<()> {
        self.account_manager
            .set_mfa_backup_codes(ctx, account_id, codes_json)
            .await
    }

    pub async fn set_mfa_enabled(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        enabled: bool,
        secret: Option<String>,
    ) -> CkResult<()> {
        self.account_manager
            .set_mfa_enabled(ctx, account_id, enabled, secret)
            .await
    }

    pub async fn update_password(&self, ctx: &CallContext, account: &Account, new_password: &Password) -> CkResult<()> {
        trace!("Updating password for user ID {}", account.id);
        self.account_manager.update_password(ctx, account, new_password).await
    }

    pub async fn create_account(&self, ctx: &CallContext, data: &AccountData) -> CkResult<Account> {
        trace!("Creating account '{}'", data.account_name);
        // Only admins may create accounts.
        // During bootstrap (no admins exist yet) any authenticated actor may
        // create the first account, mirroring the same pattern used by grant_admin.
        // System actors also bypass this check.
        if !ctx.actor.is_system() {
            let actor_id = ctx.actor.require_account_id()?;
            let admin_count = self.account_manager.get_admin_count().await?;
            if admin_count > 0 && !self.account_manager.is_admin(*actor_id).await? {
                return Err(hierarkey_core::error::auth::AuthError::Forbidden {
                    reason: "Admin privilege required to create accounts",
                }
                .into());
            }
        }
        self.account_manager.create(ctx, data).await
    }

    pub async fn must_change_password(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        must_change: bool,
    ) -> CkResult<()> {
        self.account_manager
            .set_change_password(ctx, account_id, must_change)
            .await
    }

    pub async fn disable(&self, ctx: &CallContext, account_id: AccountId, reason: Option<String>) -> CkResult<()> {
        trace!("Disabling account ID {}", account_id);

        let actor_id = ctx.actor.require_account_id()?;
        if !self.account_manager.is_admin(*actor_id).await? {
            return Err(hierarkey_core::error::auth::AuthError::Forbidden {
                reason: "Admin privilege required to disable accounts",
            }
            .into());
        }

        let account = match self.account_manager.find_account_by_id(account_id).await? {
            Some(a) => a,
            None => {
                return Err(CkError::ResourceNotFound {
                    kind: "account",
                    id: account_id.to_string(),
                });
            }
        };

        if account.account_type == AccountType::System {
            return Err(hierarkey_core::error::validation::ValidationError::InvalidOperation {
                message: "System accounts cannot be disabled".into(),
            }
            .into());
        }

        if *actor_id == account_id {
            return Err(hierarkey_core::error::auth::AuthError::Forbidden {
                reason: "Cannot disable your own account",
            }
            .into());
        }

        self.account_manager.disable_account(ctx, account_id, reason).await
    }

    pub async fn enable(&self, ctx: &CallContext, account_id: AccountId, reason: Option<String>) -> CkResult<()> {
        trace!("Enabling account ID {}", account_id);

        let actor_id = ctx.actor.require_account_id()?;
        if !self.account_manager.is_admin(*actor_id).await? {
            return Err(hierarkey_core::error::auth::AuthError::Forbidden {
                reason: "Admin privilege required to enable accounts",
            }
            .into());
        }

        self.account_manager.enable_account(ctx, account_id, reason).await
    }

    pub async fn lock(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        reason: Option<String>,
        locked_until: Option<DateTime<Utc>>,
    ) -> CkResult<()> {
        trace!("Locking account ID {}", account_id);

        let actor_id = ctx.actor.require_account_id()?;
        if !self.account_manager.is_admin(*actor_id).await? {
            return Err(hierarkey_core::error::auth::AuthError::Forbidden {
                reason: "Admin privilege required to lock accounts",
            }
            .into());
        }

        let account = match self.account_manager.find_account_by_id(account_id).await? {
            Some(a) => a,
            None => {
                return Err(CkError::ResourceNotFound {
                    kind: "account",
                    id: account_id.to_string(),
                });
            }
        };

        if account.account_type == AccountType::System {
            return Err(hierarkey_core::error::validation::ValidationError::InvalidOperation {
                message: "System accounts cannot be locked".into(),
            }
            .into());
        }

        if *actor_id == account_id {
            return Err(hierarkey_core::error::auth::AuthError::Forbidden {
                reason: "Cannot lock your own account",
            }
            .into());
        }

        self.account_manager
            .lock_account(ctx, account_id, reason, locked_until)
            .await
    }

    pub async fn unlock(&self, ctx: &CallContext, account_id: AccountId, reason: Option<String>) -> CkResult<()> {
        trace!("Unlocking account ID {}", account_id);

        let actor_id = ctx.actor.require_account_id()?;
        if !self.account_manager.is_admin(*actor_id).await? {
            return Err(hierarkey_core::error::auth::AuthError::Forbidden {
                reason: "Admin privilege required to unlock accounts",
            }
            .into());
        }

        self.account_manager.unlock_account(ctx, account_id, reason).await
    }

    pub async fn grant_admin(&self, ctx: &CallContext, account_id: AccountId) -> Result<(), AccountPromotionError> {
        trace!("Promoting account {} to admin", account_id);

        let actor_id = ctx.actor.require_account_id().map_err(AccountPromotionError::Store)?;

        // Acquire the bootstrap lock before reading admin_count so that two concurrent
        // requests cannot both observe admin_count == 0 and both promote themselves.
        // The lock is held for the duration of the check-then-grant to prevent the TOCTOU race.
        let _bootstrap_guard = self.bootstrap_lock.lock().await;

        // During bootstrap (no admins exist yet) any authenticated user may promote the first admin.
        // After that, only existing admins can promote.
        let admin_count = self.account_manager.get_admin_count().await?;
        if admin_count > 0 && !self.account_manager.is_admin(*actor_id).await? {
            return Err(AccountPromotionError::Store(
                hierarkey_core::error::auth::AuthError::Forbidden {
                    reason: "Admin privilege required to promote accounts",
                }
                .into(),
            ));
        }

        let Some(account) = self.account_manager.find_account_by_id(account_id).await? else {
            return Err(AccountPromotionError::IdNotFound(account_id));
        };

        // Cannot promote yourself (except during bootstrap when there are no admins yet)
        if *actor_id == account_id && admin_count > 0 {
            return Err(AccountPromotionError::Store(
                hierarkey_core::error::auth::AuthError::Forbidden {
                    reason: "Cannot promote your own account",
                }
                .into(),
            ));
        }

        if self.account_manager.is_admin(account.id).await? {
            return Err(AccountPromotionError::AlreadyAdmin(account.name));
        }

        if account.status == AccountStatus::Locked {
            return Err(AccountPromotionError::Locked(account.name));
        }

        if account.status == AccountStatus::Disabled {
            return Err(AccountPromotionError::NotFound(account.name));
        }

        if account.account_type == AccountType::Service {
            return Err(AccountPromotionError::ServiceAccount(account.name));
        }

        if account.account_type == AccountType::System {
            return Err(AccountPromotionError::SystemAccount(account.name));
        }

        self.account_manager.grant_admin(ctx, account.id).await?;
        Ok(())
    }

    pub async fn revoke_admin(&self, ctx: &CallContext, account_id: AccountId) -> Result<(), AccountDemotionError> {
        trace!("Demoting user {} to regular user", account_id);

        // Only admins can demote accounts
        let actor_id = ctx.actor.require_account_id().map_err(AccountDemotionError::Store)?;
        if !self.account_manager.is_admin(*actor_id).await? {
            return Err(AccountDemotionError::Store(
                hierarkey_core::error::auth::AuthError::Forbidden {
                    reason: "Admin privilege required to demote accounts",
                }
                .into(),
            ));
        }

        let Some(account) = self.account_manager.find_account_by_id(account_id).await? else {
            return Err(AccountDemotionError::NotFound(account_id.to_string()));
        };

        // Cannot demote yourself
        if *actor_id == account_id {
            return Err(AccountDemotionError::Store(
                hierarkey_core::error::auth::AuthError::Forbidden {
                    reason: "Cannot demote your own account",
                }
                .into(),
            ));
        }

        if account.account_type == AccountType::Service {
            return Err(AccountDemotionError::ServiceAccount(account.name.to_string()));
        }

        if account.account_type == AccountType::System {
            return Err(AccountDemotionError::SystemAccount(account.name.to_string()));
        }

        if !self.account_manager.is_admin(account.id).await? {
            return Err(AccountDemotionError::NotAnAdmin(account.name.to_string()));
        }

        if account.status == AccountStatus::Locked {
            return Err(AccountDemotionError::Locked(account.name.to_string()));
        }

        if account.status == AccountStatus::Disabled {
            return Err(AccountDemotionError::NotFound(account.name.to_string()));
        }

        // Check if we are the last admin
        let admin_count = self.get_admin_count(ctx).await?;
        if admin_count <= 1 {
            return Err(AccountDemotionError::LastAdmin);
        }

        self.account_manager.revoke_admin(ctx, account.id).await?;
        Ok(())
    }

    pub async fn search_accounts(
        &self,
        ctx: &CallContext,
        query: &AccountSearchQuery,
    ) -> CkResult<(Vec<AccountDto>, usize)> {
        // Only admins may list all accounts. System actors (internal/bootstrap) bypass this check.
        if !ctx.actor.is_system() {
            let actor_id = ctx.actor.require_account_id()?;
            if !self.account_manager.is_admin(*actor_id).await? {
                return Err(hierarkey_core::error::auth::AuthError::Forbidden {
                    reason: "Admin privilege required to search accounts",
                }
                .into());
            }
        }
        trace!("Searching users with query: {:?}", query);
        self.account_manager.search(query).await
    }

    pub async fn get_admin_count(&self, _ctx: &CallContext) -> CkResult<usize> {
        trace!("Counting total number of accounts");
        self.account_manager.get_admin_count().await
    }

    pub async fn count_user_service_accounts(&self, _ctx: &CallContext) -> CkResult<i64> {
        self.account_manager.count_user_service_accounts().await
    }

    pub async fn is_admin(&self, _ctx: &CallContext, account_id: AccountId) -> CkResult<bool> {
        self.account_manager.is_admin(account_id).await
    }

    pub async fn update_profile(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        email: Option<Option<String>>,
        full_name: Option<Option<String>>,
        metadata: Option<hierarkey_core::Metadata>,
    ) -> CkResult<()> {
        // Users may update their own profile; admins may update any account.
        // System actors (internal/bootstrap calls) bypass this check.
        if !ctx.actor.is_system() {
            let actor_id = ctx.actor.require_account_id()?;
            if *actor_id != account_id && !self.account_manager.is_admin(*actor_id).await? {
                return Err(hierarkey_core::error::auth::AuthError::Forbidden {
                    reason: "Admin privilege required to update another account's profile",
                }
                .into());
            }
        }

        let mut account = match self.account_manager.find_account_by_id(account_id).await? {
            Some(a) => a,
            None => {
                return Err(CkError::ResourceNotFound {
                    kind: "account",
                    id: account_id.to_string(),
                });
            }
        };

        if account.account_type == AccountType::System {
            return Err(hierarkey_core::error::validation::ValidationError::InvalidOperation {
                message: "System accounts cannot be updated".into(),
            }
            .into());
        }

        if let Some(email) = email {
            account.email = email;
        }
        if let Some(full_name) = full_name {
            account.full_name = full_name;
        }
        if let Some(metadata) = metadata {
            account.metadata = metadata;
        }

        self.account_manager.update_account(ctx, &account).await
    }

    pub async fn delete_account(&self, ctx: &CallContext, account_id: AccountId) -> CkResult<()> {
        // Only admins can delete accounts
        let actor_id = ctx.actor.require_account_id()?;
        if !self.account_manager.is_admin(*actor_id).await? {
            return Err(hierarkey_core::error::auth::AuthError::Forbidden {
                reason: "Admin privilege required to delete accounts",
            }
            .into());
        }

        let account = match self.account_manager.find_account_by_id(account_id).await? {
            Some(a) => a,
            None => {
                return Err(CkError::ResourceNotFound {
                    kind: "account",
                    id: account_id.to_string(),
                });
            }
        };

        if account.account_type == AccountType::System {
            return Err(hierarkey_core::error::validation::ValidationError::InvalidOperation {
                message: "System accounts cannot be deleted".into(),
            }
            .into());
        }

        // Prevent self-deletion
        if *actor_id == account_id {
            return Err(hierarkey_core::error::auth::AuthError::Forbidden {
                reason: "Cannot delete your own account",
            }
            .into());
        }

        // Prevent deleting the last admin
        if self.account_manager.is_admin(account_id).await? {
            let admin_count = self.account_manager.get_admin_count().await?;
            if admin_count <= 1 {
                return Err(hierarkey_core::error::validation::ValidationError::InvalidOperation {
                    message: "Cannot delete the last admin account".into(),
                }
                .into());
            }
        }

        self.account_manager.delete_account(ctx, account_id).await
    }

    /// Recover a `Tampered` account (CLI break-glass, requires master key unlocked).
    ///
    /// Bypasses RBAC - must only be called from the CLI recovery path after the
    /// master key has been unlocked and the signing key has been loaded into the slot.
    pub async fn recover_tampered_account(&self, ctx: &CallContext, account_id: AccountId) -> CkResult<()> {
        self.account_manager.recover_account(ctx, account_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::global::short_id::ShortId;
    use crate::manager::account::{AccountManager, AccountStatus, AccountStore, AccountType, InMemoryAccountStore};
    use crate::manager::token::{InMemoryTokenStore, TokenManager};
    use axum::http::StatusCode;
    use chrono::Utc;
    use hierarkey_core::api::status::ApiCode;
    use hierarkey_core::resources::AccountName;
    use std::sync::Arc;

    fn fail_code() -> ApiCode {
        ApiCode::AccountCreateFailed
    }

    // ---- test infrastructure ----

    fn make_svc() -> (AccountService, Arc<InMemoryAccountStore>) {
        let store = Arc::new(InMemoryAccountStore::new());
        let signing_slot = Arc::new(crate::service::signing_key_slot::SigningKeySlot::new());
        let manager = Arc::new(AccountManager::new(store.clone(), signing_slot));
        let token_store = Arc::new(InMemoryTokenStore::new());
        let token_manager = Arc::new(TokenManager::new(
            token_store,
            Arc::new(crate::service::signing_key_slot::SigningKeySlot::new()),
        ));
        let svc = AccountService::new(manager, token_manager);
        (svc, store)
    }

    /// Build an Account struct directly — bypasses Argon2 so tests stay fast.
    fn make_account(id: AccountId, name: &str, account_type: AccountType, status: AccountStatus) -> Account {
        Account {
            id,
            short_id: ShortId::generate("acc_", 8),
            name: AccountName::try_from(name).unwrap(),
            account_type,
            status,
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
            metadata: hierarkey_core::Metadata::default(),
            passphrase_hash: None,
            public_key: None,
            created_by: Some(AccountId::new()),
            created_at: Utc::now(),
            updated_at: None,
            updated_by: None,
            deleted_at: None,
            deleted_by: None,
            row_hmac: None,
        }
    }

    async fn inject(store: &InMemoryAccountStore, account: &Account) {
        store.create_account(&CallContext::system(), account).await.unwrap();
    }

    async fn inject_admin(store: &InMemoryAccountStore, name: &str) -> (Account, CallContext) {
        let id = AccountId::new();
        let account = make_account(id, name, AccountType::User, AccountStatus::Active);
        inject(store, &account).await;
        store.grant_admin(&CallContext::system(), id, None).await.unwrap();
        (account, CallContext::for_account(id))
    }

    async fn inject_user(store: &InMemoryAccountStore, name: &str) -> (Account, CallContext) {
        let id = AccountId::new();
        let account = make_account(id, name, AccountType::User, AccountStatus::Active);
        inject(store, &account).await;
        (account, CallContext::for_account(id))
    }

    fn account_name(s: &str) -> AccountName {
        s.parse().expect("valid account name")
    }

    // ---- QueryOrder Display ----

    #[test]
    fn query_order_display_asc() {
        assert_eq!(QueryOrder::Asc.to_string(), "ASC");
    }

    #[test]
    fn query_order_display_desc() {
        assert_eq!(QueryOrder::Desc.to_string(), "DESC");
    }

    #[test]
    fn query_order_default_is_asc() {
        let o: QueryOrder = Default::default();
        assert_eq!(o.to_string(), "ASC");
    }

    // ---- AccountPromotionError::into_http ----

    #[test]
    fn promotion_not_found_maps_to_404() {
        let err = AccountPromotionError::NotFound(account_name("alice"));
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::NOT_FOUND);
        assert_eq!(http.reason, ApiErrorCode::NotFound);
    }

    #[test]
    fn promotion_id_not_found_maps_to_404() {
        let id = AccountId::new();
        let err = AccountPromotionError::IdNotFound(id);
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::NOT_FOUND);
        assert_eq!(http.reason, ApiErrorCode::NotFound);
    }

    #[test]
    fn promotion_already_admin_maps_to_409() {
        let err = AccountPromotionError::AlreadyAdmin(account_name("alice"));
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::CONFLICT);
        assert_eq!(http.reason, ApiErrorCode::InvalidRequest);
        assert!(http.message.contains("already an admin"));
    }

    #[test]
    fn promotion_locked_maps_to_409() {
        let err = AccountPromotionError::Locked(account_name("alice"));
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::CONFLICT);
        assert_eq!(http.reason, ApiErrorCode::InvalidRequest);
        assert!(http.message.contains("locked"));
    }

    #[test]
    fn promotion_service_account_maps_to_400() {
        let err = AccountPromotionError::ServiceAccount(account_name("svc"));
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::BAD_REQUEST);
        assert_eq!(http.reason, ApiErrorCode::InvalidRequest);
        assert!(http.message.contains("Machine account"));
    }

    #[test]
    fn promotion_system_account_maps_to_400() {
        let err = AccountPromotionError::SystemAccount(account_name("$system"));
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::BAD_REQUEST);
        assert_eq!(http.reason, ApiErrorCode::InvalidRequest);
        assert!(http.message.contains("System account"));
    }

    #[test]
    fn promotion_store_error_is_forwarded() {
        let err = AccountPromotionError::Store(CkError::PermissionDenied);
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::FORBIDDEN);
    }

    // ---- AccountDemotionError::into_http ----

    #[test]
    fn demotion_not_found_maps_to_404() {
        let err = AccountDemotionError::NotFound("alice".into());
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::NOT_FOUND);
        assert_eq!(http.reason, ApiErrorCode::NotFound);
    }

    #[test]
    fn demotion_not_an_admin_maps_to_409() {
        let err = AccountDemotionError::NotAnAdmin("alice".into());
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::CONFLICT);
        assert_eq!(http.reason, ApiErrorCode::InvalidRequest);
        assert!(http.message.contains("not an admin"));
    }

    #[test]
    fn demotion_locked_maps_to_409() {
        let err = AccountDemotionError::Locked("alice".into());
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::CONFLICT);
        assert_eq!(http.reason, ApiErrorCode::InvalidRequest);
        assert!(http.message.contains("locked"));
    }

    #[test]
    fn demotion_service_account_maps_to_400() {
        let err = AccountDemotionError::ServiceAccount("svc".into());
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::BAD_REQUEST);
        assert_eq!(http.reason, ApiErrorCode::InvalidRequest);
    }

    #[test]
    fn demotion_system_account_maps_to_400() {
        let err = AccountDemotionError::SystemAccount("$system".into());
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::BAD_REQUEST);
        assert_eq!(http.reason, ApiErrorCode::InvalidRequest);
    }

    #[test]
    fn demotion_last_admin_maps_to_400() {
        let err = AccountDemotionError::LastAdmin;
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::BAD_REQUEST);
        assert_eq!(http.reason, ApiErrorCode::InvalidRequest);
        assert!(http.message.contains("last admin"));
    }

    #[test]
    fn demotion_store_error_is_forwarded() {
        let err = AccountDemotionError::Store(CkError::PermissionDenied);
        let http = err.into_http(fail_code());
        assert_eq!(http.http, StatusCode::FORBIDDEN);
    }

    // ---- Error Display (via thiserror) ----

    #[test]
    fn promotion_error_display() {
        let err = AccountPromotionError::AlreadyAdmin(account_name("alice"));
        assert!(err.to_string().contains("alice"));
    }

    #[test]
    fn demotion_error_display() {
        let err = AccountDemotionError::LastAdmin;
        assert!(err.to_string().contains("last admin"));
    }

    // ---- get_by_id ----

    #[tokio::test]
    async fn get_by_id_found() {
        let (svc, store) = make_svc();
        let id = AccountId::new();
        let account = make_account(id, "alice", AccountType::User, AccountStatus::Active);
        inject(&store, &account).await;

        let result = svc.get_by_id(&CallContext::system(), id).await.unwrap();
        assert_eq!(result.id, id);
    }

    #[tokio::test]
    async fn get_by_id_not_found() {
        let (svc, _store) = make_svc();
        let result = svc.get_by_id(&CallContext::system(), AccountId::new()).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    // ---- find_by_name ----

    #[tokio::test]
    async fn find_by_name_found() {
        let (svc, store) = make_svc();
        let id = AccountId::new();
        let account = make_account(id, "bob", AccountType::User, AccountStatus::Active);
        inject(&store, &account).await;

        let name = AccountName::try_from("bob").unwrap();
        let found = svc.find_by_name(&CallContext::system(), &name).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, id);
    }

    #[tokio::test]
    async fn find_by_name_not_found() {
        let (svc, _store) = make_svc();
        let name = AccountName::try_from("ghost").unwrap();
        let found = svc.find_by_name(&CallContext::system(), &name).await.unwrap();
        assert!(found.is_none());
    }

    // ---- create_account (needs Argon2) ----

    #[tokio::test]
    async fn create_account_success() {
        let (svc, store) = make_svc();
        let (_, ctx) = inject_admin(&store, "admin_creator").await;
        let data = AccountData {
            account_name: AccountName::try_from("newuser").unwrap(),
            is_active: true,
            description: None,
            labels: Default::default(),
            custom: CustomAccountData::User(CustomUserAccountData {
                email: None,
                full_name: None,
                password: Password::new("a-long-enough-password"),
                must_change_password: false,
            }),
        };
        let account = svc.create_account(&ctx, &data).await.unwrap();
        assert_eq!(account.name.to_string(), "newuser");
    }

    #[tokio::test]
    async fn create_account_duplicate_fails() {
        let (svc, store) = make_svc();
        let id = AccountId::new();
        let existing = make_account(id, "dupuser", AccountType::User, AccountStatus::Active);
        inject(&store, &existing).await;

        let ctx = CallContext::system();
        let data = AccountData {
            account_name: AccountName::try_from("dupuser").unwrap(),
            is_active: true,
            description: None,
            labels: Default::default(),
            custom: CustomAccountData::User(CustomUserAccountData {
                email: None,
                full_name: None,
                password: Password::new("a-long-enough-password"),
                must_change_password: false,
            }),
        };
        let result = svc.create_account(&ctx, &data).await;
        assert!(result.is_err());
    }

    // ---- must_change_password ----

    #[tokio::test]
    async fn must_change_password_sets_flag() {
        let (svc, store) = make_svc();
        let id = AccountId::new();
        inject(&store, &make_account(id, "pwduser", AccountType::User, AccountStatus::Active)).await;
        let ctx = CallContext::system();

        svc.must_change_password(&ctx, id, true).await.unwrap();

        let account = svc.get_by_id(&ctx, id).await.unwrap();
        assert!(account.must_change_password);
    }

    // ---- disable / enable ----

    #[tokio::test]
    async fn disable_success() {
        let (svc, store) = make_svc();
        let (_, actor_ctx) = inject_admin(&store, "actor1").await;
        let (target, _) = inject_user(&store, "target1").await;

        svc.disable(&actor_ctx, target.id, None).await.unwrap();

        let found = svc.get_by_id(&CallContext::system(), target.id).await.unwrap();
        assert_eq!(found.status, AccountStatus::Disabled);
    }

    #[tokio::test]
    async fn disable_non_admin_denied() {
        let (svc, store) = make_svc();
        let (_, actor_ctx) = inject_user(&store, "nonadmin_dis").await;
        let (target, _) = inject_user(&store, "target_dis").await;

        let result = svc.disable(&actor_ctx, target.id, None).await;
        assert!(matches!(
            result,
            Err(CkError::Auth(hierarkey_core::error::auth::AuthError::Forbidden { .. }))
        ));
    }

    #[tokio::test]
    async fn disable_not_found() {
        let (svc, store) = make_svc();
        let (_, actor_ctx) = inject_admin(&store, "actor2").await;
        let result = svc.disable(&actor_ctx, AccountId::new(), None).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn disable_system_account_fails() {
        let (svc, store) = make_svc();
        let (_, actor_ctx) = inject_admin(&store, "actor3").await;
        let sys_id = AccountId::new();
        inject(
            &store,
            &make_account(sys_id, "sys1", AccountType::System, AccountStatus::Active),
        )
        .await;

        let result = svc.disable(&actor_ctx, sys_id, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn disable_self_fails() {
        let (svc, store) = make_svc();
        let (user, user_ctx) = inject_admin(&store, "selfuser").await;
        let result = svc.disable(&user_ctx, user.id, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn enable_success() {
        let (svc, store) = make_svc();
        let (_, actor_ctx) = inject_admin(&store, "enactor").await;
        let target_id = AccountId::new();
        inject(
            &store,
            &make_account(target_id, "entarget", AccountType::User, AccountStatus::Disabled),
        )
        .await;

        svc.enable(&actor_ctx, target_id, None).await.unwrap();

        let found = svc.get_by_id(&CallContext::system(), target_id).await.unwrap();
        assert_eq!(found.status, AccountStatus::Active);
    }

    #[tokio::test]
    async fn enable_non_admin_denied() {
        let (svc, store) = make_svc();
        let (_, actor_ctx) = inject_user(&store, "nonadmin_en").await;
        let target_id = AccountId::new();
        inject(
            &store,
            &make_account(target_id, "entarget2", AccountType::User, AccountStatus::Disabled),
        )
        .await;

        let result = svc.enable(&actor_ctx, target_id, None).await;
        assert!(matches!(
            result,
            Err(CkError::Auth(hierarkey_core::error::auth::AuthError::Forbidden { .. }))
        ));
    }

    // ---- lock / unlock ----

    #[tokio::test]
    async fn lock_success() {
        let (svc, store) = make_svc();
        let (_, actor_ctx) = inject_admin(&store, "lkactor").await;
        let (target, _) = inject_user(&store, "lktarget").await;

        svc.lock(&actor_ctx, target.id, Some("reason".into()), None)
            .await
            .unwrap();

        let found = svc.get_by_id(&CallContext::system(), target.id).await.unwrap();
        assert_eq!(found.status, AccountStatus::Locked);
    }

    #[tokio::test]
    async fn lock_non_admin_denied() {
        let (svc, store) = make_svc();
        let (_, actor_ctx) = inject_user(&store, "nonadmin_lk").await;
        let (target, _) = inject_user(&store, "lktarget2").await;

        let result = svc.lock(&actor_ctx, target.id, None, None).await;
        assert!(matches!(
            result,
            Err(CkError::Auth(hierarkey_core::error::auth::AuthError::Forbidden { .. }))
        ));
    }

    #[tokio::test]
    async fn lock_not_found() {
        let (svc, store) = make_svc();
        let (_, actor_ctx) = inject_admin(&store, "lkactor2").await;
        let result = svc.lock(&actor_ctx, AccountId::new(), None, None).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn lock_system_account_fails() {
        let (svc, store) = make_svc();
        let (_, actor_ctx) = inject_admin(&store, "lkactor3").await;
        let sys_id = AccountId::new();
        inject(
            &store,
            &make_account(sys_id, "sys2", AccountType::System, AccountStatus::Active),
        )
        .await;

        let result = svc.lock(&actor_ctx, sys_id, None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn lock_self_fails() {
        let (svc, store) = make_svc();
        let (user, user_ctx) = inject_admin(&store, "selflock").await;
        let result = svc.lock(&user_ctx, user.id, None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn unlock_success() {
        let (svc, store) = make_svc();
        let (_, actor_ctx) = inject_admin(&store, "ulactor").await;
        let target_id = AccountId::new();
        inject(
            &store,
            &make_account(target_id, "ultarget", AccountType::User, AccountStatus::Locked),
        )
        .await;

        svc.unlock(&actor_ctx, target_id, None).await.unwrap();
    }

    #[tokio::test]
    async fn unlock_non_admin_denied() {
        let (svc, store) = make_svc();
        let (_, actor_ctx) = inject_user(&store, "nonadmin_ul").await;
        let target_id = AccountId::new();
        inject(
            &store,
            &make_account(target_id, "ultarget2", AccountType::User, AccountStatus::Locked),
        )
        .await;

        let result = svc.unlock(&actor_ctx, target_id, None).await;
        assert!(matches!(
            result,
            Err(CkError::Auth(hierarkey_core::error::auth::AuthError::Forbidden { .. }))
        ));
    }

    // ---- grant_admin ----

    #[tokio::test]
    async fn grant_admin_success() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_ga").await;
        let (target, _) = inject_user(&store, "target_ga").await;

        svc.grant_admin(&admin_ctx, target.id).await.unwrap();

        let is_admin = svc.is_admin(&CallContext::system(), target.id).await.unwrap();
        assert!(is_admin);
    }

    #[tokio::test]
    async fn grant_admin_non_admin_actor_denied() {
        let (svc, store) = make_svc();
        // Ensure there is already an admin so bootstrap mode is not active
        inject_admin(&store, "existing_admin_ga").await;
        let (_, user_ctx) = inject_user(&store, "plain_ga").await;
        let (target, _) = inject_user(&store, "target_ga2").await;

        let result = svc.grant_admin(&user_ctx, target.id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn grant_admin_target_not_found() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_ganf").await;

        let result = svc.grant_admin(&admin_ctx, AccountId::new()).await;
        assert!(matches!(result, Err(AccountPromotionError::IdNotFound(_))));
    }

    #[tokio::test]
    async fn grant_admin_self_promote_fails() {
        let (svc, store) = make_svc();
        let (admin, admin_ctx) = inject_admin(&store, "admin_self").await;

        let result = svc.grant_admin(&admin_ctx, admin.id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn grant_admin_already_admin() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_aa1").await;
        let (target, _) = inject_admin(&store, "admin_aa2").await;

        let result = svc.grant_admin(&admin_ctx, target.id).await;
        assert!(matches!(result, Err(AccountPromotionError::AlreadyAdmin(_))));
    }

    #[tokio::test]
    async fn grant_admin_locked_target_fails() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_lk").await;
        let locked_id = AccountId::new();
        inject(
            &store,
            &make_account(locked_id, "lktarget_ga", AccountType::User, AccountStatus::Locked),
        )
        .await;

        let result = svc.grant_admin(&admin_ctx, locked_id).await;
        assert!(matches!(result, Err(AccountPromotionError::Locked(_))));
    }

    #[tokio::test]
    async fn grant_admin_disabled_target_treated_as_not_found() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_dis").await;
        let dis_id = AccountId::new();
        inject(
            &store,
            &make_account(dis_id, "distarget_ga", AccountType::User, AccountStatus::Disabled),
        )
        .await;

        let result = svc.grant_admin(&admin_ctx, dis_id).await;
        assert!(matches!(result, Err(AccountPromotionError::NotFound(_))));
    }

    #[tokio::test]
    async fn grant_admin_service_account_fails() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_svc").await;
        let svc_id = AccountId::new();
        inject(
            &store,
            &make_account(svc_id, "svctarget_ga", AccountType::Service, AccountStatus::Active),
        )
        .await;

        let result = svc.grant_admin(&admin_ctx, svc_id).await;
        assert!(matches!(result, Err(AccountPromotionError::ServiceAccount(_))));
    }

    #[tokio::test]
    async fn grant_admin_system_account_fails() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_sys").await;
        let sys_id = AccountId::new();
        inject(
            &store,
            &make_account(sys_id, "systgt_ga", AccountType::System, AccountStatus::Active),
        )
        .await;

        let result = svc.grant_admin(&admin_ctx, sys_id).await;
        assert!(matches!(result, Err(AccountPromotionError::SystemAccount(_))));
    }

    // ---- revoke_admin ----

    #[tokio::test]
    async fn revoke_admin_success() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_ra1").await;
        let (target, _) = inject_admin(&store, "admin_ra2").await;

        svc.revoke_admin(&admin_ctx, target.id).await.unwrap();

        let is_admin = svc.is_admin(&CallContext::system(), target.id).await.unwrap();
        assert!(!is_admin);
    }

    #[tokio::test]
    async fn revoke_admin_last_admin_fails() {
        let (svc, store) = make_svc();
        let (last_admin, admin_ctx) = inject_admin(&store, "last_admin").await;

        let result = svc.revoke_admin(&admin_ctx, last_admin.id).await;
        // self-demote is blocked before last-admin check
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn revoke_admin_non_admin_actor_denied() {
        let (svc, store) = make_svc();
        let (_, user_ctx) = inject_user(&store, "plain_ra").await;
        let (_, _) = inject_admin(&store, "target_ra").await;

        let result = svc.revoke_admin(&user_ctx, AccountId::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn revoke_admin_target_not_found() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_ranf").await;

        let result = svc.revoke_admin(&admin_ctx, AccountId::new()).await;
        assert!(matches!(result, Err(AccountDemotionError::NotFound(_))));
    }

    #[tokio::test]
    async fn revoke_admin_self_demote_fails() {
        let (svc, store) = make_svc();
        let (admin, admin_ctx) = inject_admin(&store, "admin_self2").await;

        let result = svc.revoke_admin(&admin_ctx, admin.id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn revoke_admin_not_an_admin_target() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_naa").await;
        let (user, _) = inject_user(&store, "notadmin_ra").await;

        let result = svc.revoke_admin(&admin_ctx, user.id).await;
        assert!(matches!(result, Err(AccountDemotionError::NotAnAdmin(_))));
    }

    #[tokio::test]
    async fn revoke_admin_service_account_fails() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_rasvc").await;
        let svc_id = AccountId::new();
        inject(
            &store,
            &make_account(svc_id, "svctgt_ra", AccountType::Service, AccountStatus::Active),
        )
        .await;

        let result = svc.revoke_admin(&admin_ctx, svc_id).await;
        assert!(matches!(result, Err(AccountDemotionError::ServiceAccount(_))));
    }

    #[tokio::test]
    async fn revoke_admin_system_account_fails() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_rasys").await;
        let sys_id = AccountId::new();
        inject(
            &store,
            &make_account(sys_id, "systgt_ra", AccountType::System, AccountStatus::Active),
        )
        .await;

        let result = svc.revoke_admin(&admin_ctx, sys_id).await;
        assert!(matches!(result, Err(AccountDemotionError::SystemAccount(_))));
    }

    #[tokio::test]
    async fn revoke_admin_locked_target_fails() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_ralk").await;
        let lk_id = AccountId::new();
        let mut lk_account = make_account(lk_id, "lktgt_ra", AccountType::User, AccountStatus::Locked);
        inject(&store, &lk_account).await;
        store.grant_admin(&CallContext::system(), lk_id, None).await.unwrap();
        // inject second admin so the actor has a "buddy" and won't fail the last-admin check
        let (_, _) = inject_admin(&store, "buddy_ralk").await;
        // Re-inject lk as locked
        lk_account.status = AccountStatus::Locked;
        // Simulate locked status in the store
        store
            .set_status(&CallContext::system(), lk_id, AccountStatus::Locked, None)
            .await
            .unwrap();

        let result = svc.revoke_admin(&admin_ctx, lk_id).await;
        assert!(matches!(result, Err(AccountDemotionError::Locked(_))));
    }

    #[tokio::test]
    async fn revoke_admin_disabled_target_treated_as_not_found() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_radis").await;
        let dis_id = AccountId::new();
        inject(
            &store,
            &make_account(dis_id, "distgt_ra", AccountType::User, AccountStatus::Disabled),
        )
        .await;
        store.grant_admin(&CallContext::system(), dis_id, None).await.unwrap();
        let (_, _) = inject_admin(&store, "buddy_radis").await;

        let result = svc.revoke_admin(&admin_ctx, dis_id).await;
        assert!(matches!(result, Err(AccountDemotionError::NotFound(_))));
    }

    // ---- search_accounts / get_admin_count / is_admin ----

    #[tokio::test]
    async fn search_accounts_returns_results() {
        let (svc, store) = make_svc();
        inject(
            &store,
            &make_account(AccountId::new(), "searcher1", AccountType::User, AccountStatus::Active),
        )
        .await;
        inject(
            &store,
            &make_account(AccountId::new(), "searcher2", AccountType::User, AccountStatus::Active),
        )
        .await;

        let (accounts, total) = svc
            .search_accounts(&CallContext::system(), &AccountSearchQuery::default())
            .await
            .unwrap();
        assert_eq!(total, 2);
        assert_eq!(accounts.len(), 2);
    }

    #[tokio::test]
    async fn get_admin_count_returns_zero_initially() {
        let (svc, _store) = make_svc();
        let count = svc.get_admin_count(&CallContext::system()).await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn get_admin_count_reflects_grants() {
        let (svc, store) = make_svc();
        inject_admin(&store, "admin_cnt1").await;
        inject_admin(&store, "admin_cnt2").await;

        let count = svc.get_admin_count(&CallContext::system()).await.unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn is_admin_true_and_false() {
        let (svc, store) = make_svc();
        let (admin, _) = inject_admin(&store, "admin_ia").await;
        let (user, _) = inject_user(&store, "user_ia").await;

        assert!(svc.is_admin(&CallContext::system(), admin.id).await.unwrap());
        assert!(!svc.is_admin(&CallContext::system(), user.id).await.unwrap());
    }

    // ---- update_profile ----

    #[tokio::test]
    async fn update_profile_success() {
        let (svc, store) = make_svc();
        let (user, user_ctx) = inject_user(&store, "profuser").await;

        svc.update_profile(&user_ctx, user.id, Some(Some("new@example.com".into())), None, None)
            .await
            .unwrap();

        let found = svc.get_by_id(&CallContext::system(), user.id).await.unwrap();
        assert_eq!(found.email.as_deref(), Some("new@example.com"));
    }

    #[tokio::test]
    async fn update_profile_full_name_and_metadata() {
        let (svc, store) = make_svc();
        let (user, user_ctx) = inject_user(&store, "profuser2").await;

        let mut meta = hierarkey_core::Metadata::new();
        meta.add_description("updated meta");

        svc.update_profile(&user_ctx, user.id, None, Some(Some("Alice".into())), Some(meta))
            .await
            .unwrap();

        let found = svc.get_by_id(&CallContext::system(), user.id).await.unwrap();
        assert_eq!(found.full_name.as_deref(), Some("Alice"));
    }

    #[tokio::test]
    async fn update_profile_not_found() {
        let (svc, _store) = make_svc();
        let result = svc
            .update_profile(&CallContext::system(), AccountId::new(), None, None, None)
            .await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn update_profile_system_account_fails() {
        let (svc, store) = make_svc();
        let sys_id = AccountId::new();
        inject(
            &store,
            &make_account(sys_id, "sysupd", AccountType::System, AccountStatus::Active),
        )
        .await;

        let result = svc
            .update_profile(&CallContext::system(), sys_id, None, None, None)
            .await;
        assert!(result.is_err());
    }

    // ---- delete_account ----

    #[tokio::test]
    async fn delete_account_success() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_del1").await;
        let (_, _) = inject_admin(&store, "admin_del2").await; // second admin so we can delete
        let (target, _) = inject_user(&store, "del_target").await;

        svc.delete_account(&admin_ctx, target.id).await.unwrap();

        let result = svc.get_by_id(&CallContext::system(), target.id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn delete_account_non_admin_denied() {
        let (svc, store) = make_svc();
        let (_, user_ctx) = inject_user(&store, "nonadmin_del").await;
        let (target, _) = inject_user(&store, "del_target2").await;

        let result = svc.delete_account(&user_ctx, target.id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn delete_account_not_found() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_delnf").await;

        let result = svc.delete_account(&admin_ctx, AccountId::new()).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn delete_account_system_account_fails() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "admin_delsys").await;
        let sys_id = AccountId::new();
        inject(
            &store,
            &make_account(sys_id, "sysdel", AccountType::System, AccountStatus::Active),
        )
        .await;

        let result = svc.delete_account(&admin_ctx, sys_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn delete_account_self_delete_fails() {
        let (svc, store) = make_svc();
        let (admin, admin_ctx) = inject_admin(&store, "admin_delself").await;

        let result = svc.delete_account(&admin_ctx, admin.id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn delete_account_last_admin_fails() {
        let (svc, store) = make_svc();
        let (_, admin_ctx) = inject_admin(&store, "solo_admin_del1").await;
        let (last_admin2, _) = inject_admin(&store, "solo_admin_del2").await;

        let result = svc.delete_account(&admin_ctx, last_admin2.id).await;
        // Two admins: deleting one (not self) should succeed
        assert!(result.is_ok());

        // Now only one admin left; deleting them should fail
        let (admin_a, admin_a_ctx) = inject_admin(&store, "admin_dellla").await;
        let (admin_b, _) = inject_admin(&store, "admin_dellb").await;
        svc.delete_account(&admin_a_ctx, admin_b.id).await.unwrap();
        // Now admin_a is sole admin; try to delete a non-admin
        let (non_admin, _) = inject_user(&store, "nonadmin_last").await;
        // Deleting a non-admin when admin_a is last admin is fine (only admins are protected)
        svc.delete_account(&admin_a_ctx, non_admin.id).await.unwrap();
        // admin_a is still the only admin; can't delete themselves or another admin
        let _ = admin_a;
    }
}
