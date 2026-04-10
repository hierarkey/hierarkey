// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::global::config::AuthConfig;
use crate::http_server::handlers::auth_response::AuthScope;
use crate::manager::AccountManager;
use crate::manager::account::account_argon2;
use crate::manager::account::{AccountId, AccountStatus, AccountType, Password};
use crate::manager::token::PatId;
use crate::{Account, PersonalAccessToken, TokenManager};
use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use hierarkey_core::CkResult;
use hierarkey_core::error::auth::{AuthError, AuthFailReason};
use hierarkey_core::error::crypto::CryptoError;
use hierarkey_core::resources::AccountName;
use password_hash::{PasswordHasher, SaltString};
use std::sync::{Arc, OnceLock};
use tracing::trace;
// ------------------------------------------------------------------------------------------------

/// The dummy user hash used for mitigating timing attacks.
static DUMMY_USER_HASH: OnceLock<String> = OnceLock::new();

pub fn get_dummy_account_hash() -> Result<String, password_hash::Error> {
    if let Some(hash) = DUMMY_USER_HASH.get() {
        return Ok(hash.clone());
    }

    let salt = SaltString::generate(&mut OsRng);

    let mut pwd_bytes = vec![0u8; 64];
    OsRng
        .try_fill_bytes(&mut pwd_bytes)
        .map_err(|_| password_hash::Error::Crypto)?;

    let hash = account_argon2().hash_password(&pwd_bytes, &salt)?.to_string();

    Ok(DUMMY_USER_HASH.get_or_init(|| hash).clone())
}

// ------------------------------------------------------------------------------------------------

pub enum PasswordOrPassphrase {
    Password(Password),
    Passphrase(Password),
}

pub struct AuthService {
    account_manager: Arc<AccountManager>,
    token_manager: Arc<TokenManager>,
    max_failed_login_attempts: u32,
    lockout_duration_minutes: u64,
    pub access_token_ttl_minutes: i64,
    pub refresh_token_ttl_minutes: i64,
}

impl AuthService {
    pub fn new(
        account_manager: Arc<AccountManager>,
        token_manager: Arc<TokenManager>,
        auth_config: &AuthConfig,
    ) -> CkResult<Self> {
        // Generate first dummy hash at startup to avoid latency on first use.
        let _ = get_dummy_account_hash().map_err(|e| {
            trace!("Failed to generate dummy hash at startup: {}", e);
            CryptoError::PasswordHashingFailed
        });

        Ok(Self {
            account_manager,
            token_manager,
            max_failed_login_attempts: auth_config.max_failed_login_attempts,
            lockout_duration_minutes: auth_config.lockout_duration_minutes,
            access_token_ttl_minutes: (auth_config.access_token_ttl_seconds / 60).max(1) as i64,
            refresh_token_ttl_minutes: (auth_config.refresh_token_ttl_seconds / 60).max(1) as i64,
        })
    }

    /// Authenticate an account by their token. Returns the account and token expiration if successful.
    pub async fn authenticate(&self, ctx: &CallContext, token: &str) -> CkResult<(Account, PersonalAccessToken)> {
        trace!("Authenticating token");
        let pat = self.token_manager.authenticate_token(token).await?;

        let Some(account) = self.account_manager.find_account_by_id(pat.account_id).await? else {
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::AccountNotFound,
            }
            .into());
        };

        if account.deleted_at.is_some() {
            trace!("Account ID {} has been deleted", pat.account_id);
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::AccountDisabled,
            }
            .into());
        }

        if account.status != AccountStatus::Active {
            trace!("Account ID {} is not active", pat.account_id);
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::AccountDisabled,
            }
            .into());
        }

        self.account_manager.set_last_login(ctx, account.id).await?;

        trace!("Authenticated account ID {}", pat.account_id);
        Ok((account, pat))
    }

    async fn dummy_auth(&self) -> CkResult<()> {
        // We already have generated the dummy hash at startup
        let dummy_hash = get_dummy_account_hash().map_err(|e| {
            trace!("Failed to generate dummy hash: {}", e);
            CryptoError::PasswordHashingFailed
        })?;

        // To mitigate timing attacks, perform a dummy authentication, otherwise the time taken to
        // respond could reveal whether the account exists or not.
        self.account_manager
            .authenticate(&dummy_hash, &Password::new("<dummy hash>"))
            .await?;

        Err(AuthError::Unauthenticated {
            reason: AuthFailReason::InvalidCredentials,
        }
        .into())
    }

    async fn real_auth(&self, ctx: &CallContext, account: &Account, secret: &PasswordOrPassphrase) -> CkResult<()> {
        // System accounts are not authenticatable via password/passphrase.
        if account.account_type == AccountType::System {
            trace!("Rejected password auth attempt for system account '{}'", account.name);
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::InvalidCredentials,
            }
            .into());
        }

        // Reject deleted accounts before any other check.
        if account.deleted_at.is_some() {
            trace!("Account '{}' has been deleted", account.name);
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::AccountDisabled,
            }
            .into());
        }

        // Reject before any crypto work if the account is temporarily locked.
        if let Some(locked_until) = account.locked_until
            && locked_until > chrono::Utc::now()
        {
            trace!("Account '{}' is temporarily locked until {}", account.name, locked_until);
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::AccountLocked,
            }
            .into());
        }

        // Reject permanently disabled/deleted accounts.
        if account.status != AccountStatus::Active && account.status != AccountStatus::Locked {
            trace!("Account '{}' is not active", account.name);
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::AccountDisabled,
            }
            .into());
        }

        // Reject admin-locked accounts (no locked_until means indefinitely locked).
        if account.status == AccountStatus::Locked {
            trace!("Account '{}' is locked", account.name);
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::AccountDisabled,
            }
            .into());
        }

        // Figure out if we need to check password or passphrase.
        let (secret_hash, secret) = match secret {
            PasswordOrPassphrase::Password(pw) => (account.password_hash.as_ref(), pw),
            PasswordOrPassphrase::Passphrase(pp) => (account.passphrase_hash.as_ref(), pp),
        };

        // Make sure we actually have found a hash to check against.
        let Some(secret_hash) = secret_hash else {
            trace!("Account '{}' has no password/passphrase hash set", account.name);
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::InvalidCredentials,
            }
            .into());
        };

        match self.account_manager.authenticate(secret_hash, secret).await {
            Ok(()) => {
                trace!("Authenticated account '{}'", account.name);
                self.account_manager.set_last_login(ctx, account.id).await?;
                Ok(())
            }
            Err(e) => {
                // Increment the failed-login counter; this may lock the account.
                if let Err(lock_err) = self
                    .account_manager
                    .record_failed_login(ctx, account.id, self.max_failed_login_attempts, self.lockout_duration_minutes)
                    .await
                {
                    tracing::warn!("Failed to record failed login for account {}: {lock_err}", account.id);
                }
                Err(e)
            }
        }
    }

    pub async fn authenticate_with_id_secret(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
        secret: &PasswordOrPassphrase,
    ) -> CkResult<Account> {
        trace!("Authenticating account by id and secret");
        match self.account_manager.find_account_by_id(account_id).await? {
            Some(account) => {
                self.real_auth(ctx, &account, secret).await?;
                Ok(account)
            }
            None => {
                // Execute dummy authentication to mitigate timing attacks, otherwise the time taken to respond could reveal whether the account exists or not.
                self.dummy_auth().await?;
                Err(AuthError::Unauthenticated {
                    reason: AuthFailReason::AccountNotFound,
                }
                .into())
            }
        }
    }

    pub async fn authenticate_with_name_secret(
        &self,
        ctx: &CallContext,
        account_name: &AccountName,
        secret: &PasswordOrPassphrase,
    ) -> CkResult<Account> {
        trace!("Authenticating account by name and secret");
        match self.account_manager.find_account_by_name(account_name).await? {
            Some(account) => {
                self.real_auth(ctx, &account, secret).await?;
                Ok(account)
            }
            None => {
                // Execute dummy authentication to mitigate timing attacks, otherwise the time taken to respond could reveal whether the account exists or not.
                let _ = self.dummy_auth().await;
                Err(AuthError::Unauthenticated {
                    reason: AuthFailReason::AccountNotFound,
                }
                .into())
            }
        }
    }

    pub async fn create_pat(
        &self,
        ctx: &CallContext,
        account: &Account,
        description: &str,
        duration_minutes: i64,
        scope: AuthScope,
    ) -> CkResult<(String, PersonalAccessToken)> {
        // Defence-in-depth: system accounts must not receive tokens even if they
        // somehow bypass the earlier real_auth guard.
        if account.account_type == AccountType::System {
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::AccountDisabled,
            }
            .into());
        }

        // Bind refresh tokens to the requesting client's IP so they cannot be
        // replayed from a different network location.
        let client_ip = if scope == AuthScope::Refresh {
            ctx.client_ip
        } else {
            None
        };

        self.token_manager
            .create_token(account.id, description, duration_minutes, scope.into(), client_ip)
            .await
    }

    pub async fn list_pat(
        &self,
        _ctx: &CallContext,
        account_id: AccountId,
        limit: usize,
        offset: usize,
    ) -> CkResult<(Vec<PersonalAccessToken>, usize)> {
        trace!("Listing tokens for account ID {}", account_id);
        self.token_manager.list_user_tokens(account_id, limit, offset).await
    }

    pub async fn pat_info(&self, _ctx: &CallContext, pat_id: PatId) -> CkResult<Option<PersonalAccessToken>> {
        trace!("Fetching token info for token ID {}", pat_id);
        self.token_manager.find_token_info(pat_id).await
    }

    pub async fn pat_revoke(&self, ctx: &CallContext, pat_id: PatId) -> CkResult<bool> {
        trace!("Revoking token ID {}", pat_id);
        self.token_manager.revoke_token(ctx, pat_id).await
    }

    /// Validate a refresh token and exchange it for a new access + refresh token pair.
    /// The old refresh token is revoked atomically after the new tokens are created.
    /// If the token was originally bound to a client IP, the caller's IP must match.
    pub async fn exchange_refresh_token(
        &self,
        ctx: &CallContext,
        refresh_token_str: &str,
    ) -> CkResult<(Account, String, PersonalAccessToken, String, PersonalAccessToken)> {
        let old_pat = self.token_manager.authenticate_token(refresh_token_str).await?;

        if old_pat.purpose != crate::manager::token::TokenPurpose::Refresh {
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::InvalidToken,
            }
            .into());
        }

        // Enforce IP binding: if the refresh token was issued to a specific IP,
        // the presenting client must come from the same address.
        if let Some(bound_ip) = old_pat.created_from_ip {
            match ctx.client_ip {
                Some(current_ip) if bound_ip == current_ip => {
                    // IP matches — allow
                }
                Some(current_ip) => {
                    tracing::warn!(
                        bound_ip = %bound_ip,
                        current_ip = %current_ip,
                        token_id = %old_pat.id,
                        "Refresh token presented from different IP — rejecting"
                    );
                    return Err(AuthError::Unauthenticated {
                        reason: AuthFailReason::InvalidToken,
                    }
                    .into());
                }
                None => {
                    // ConnectInfo is absent: we cannot verify the client IP, so we must
                    // reject to avoid silently bypassing the IP-binding security control.
                    tracing::warn!(
                        token_id = %old_pat.id,
                        bound_ip = %bound_ip,
                        "Refresh token is IP-bound but server has no ConnectInfo — rejecting to enforce IP binding"
                    );
                    return Err(AuthError::Unauthenticated {
                        reason: AuthFailReason::InvalidToken,
                    }
                    .into());
                }
            }
        }

        let Some(account) = self.account_manager.find_account_by_id(old_pat.account_id).await? else {
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::AccountNotFound,
            }
            .into());
        };

        if account.deleted_at.is_some() || account.status != AccountStatus::Active {
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::AccountDisabled,
            }
            .into());
        }

        let (access_str, access_pat) = self
            .token_manager
            .create_token(
                account.id,
                "Refreshed access token",
                self.access_token_ttl_minutes,
                crate::manager::token::TokenPurpose::Auth,
                None,
            )
            .await?;

        let (refresh_str, refresh_pat) = self
            .token_manager
            .create_token(
                account.id,
                "Refreshed refresh token",
                self.refresh_token_ttl_minutes,
                crate::manager::token::TokenPurpose::Refresh,
                ctx.client_ip,
            )
            .await?;

        // Revoke old refresh token after new tokens are created.
        let _ = self.token_manager.revoke_token(ctx, old_pat.id).await;

        Ok((account, access_str, access_pat, refresh_str, refresh_pat))
    }

    /// Record a failed login attempt. If the threshold is reached the account is temporarily locked.
    pub async fn record_failed_login(&self, ctx: &CallContext, account_id: AccountId) -> CkResult<()> {
        self.account_manager
            .record_failed_login(ctx, account_id, self.max_failed_login_attempts, self.lockout_duration_minutes)
            .await
    }

    /// Record a successful login: resets the failed-attempt counter and updates last_login_at.
    pub async fn record_successful_login(&self, ctx: &CallContext, account_id: AccountId) -> CkResult<()> {
        self.account_manager.set_last_login(ctx, account_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::global::config::AuthConfig;
    use crate::global::short_id::ShortId;
    use crate::http_server::handlers::auth_response::AuthScope;
    use crate::manager::account::{AccountManager, AccountStatus, AccountStore, AccountType, InMemoryAccountStore};
    use crate::manager::token::{InMemoryTokenStore, TokenManager, TokenPurpose};
    use chrono::Utc;
    use hierarkey_core::Metadata;
    use hierarkey_core::resources::AccountName;
    use std::sync::Arc;

    fn make_svc() -> (AuthService, Arc<InMemoryAccountStore>, Arc<InMemoryTokenStore>) {
        let account_store = Arc::new(InMemoryAccountStore::new());
        let account_manager = Arc::new(AccountManager::new(account_store.clone()));
        let token_store = Arc::new(InMemoryTokenStore::new());
        let token_manager = Arc::new(TokenManager::new(token_store.clone()));
        let config = AuthConfig::default();
        let svc = AuthService::new(account_manager, token_manager, &config).unwrap();
        (svc, account_store, token_store)
    }

    fn make_account(id: AccountId, name: &str, at: AccountType, status: AccountStatus) -> crate::Account {
        crate::Account {
            id,
            short_id: ShortId::generate("acc_", 8),
            name: AccountName::try_from(name).unwrap(),
            account_type: at,
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
            metadata: Metadata::default(),
            passphrase_hash: None,
            public_key: None,
            created_by: Some(AccountId::new()),
            created_at: Utc::now(),
            updated_at: None,
            updated_by: None,
            deleted_at: None,
            deleted_by: None,
        }
    }

    async fn inject(store: &InMemoryAccountStore, account: &crate::Account) {
        store.create_account(&CallContext::system(), account).await.unwrap();
    }

    async fn make_active_account(store: &InMemoryAccountStore, name: &str) -> (crate::Account, AccountId) {
        let id = AccountId::new();
        let account = make_account(id, name, AccountType::User, AccountStatus::Active);
        inject(store, &account).await;
        (account, id)
    }

    // ---- authenticate (token-based) ----

    #[tokio::test]
    async fn authenticate_token_not_found() {
        let (svc, _, _) = make_svc();
        let ctx = CallContext::system();
        let result = svc.authenticate(&ctx, "hkat_bogus.bogus").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticate_token_success() {
        let (svc, store, _) = make_svc();
        let (account, _) = make_active_account(&store, "tokenuser").await;
        let ctx = CallContext::system();
        let (token_str, _) = svc
            .create_pat(&ctx, &account, "test token", 60, AuthScope::Auth)
            .await
            .unwrap();
        let result = svc.authenticate(&ctx, &token_str).await;
        assert!(result.is_ok());
        let (returned_account, _pat) = result.unwrap();
        assert_eq!(returned_account.id, account.id);
    }

    #[tokio::test]
    async fn authenticate_token_account_deleted() {
        let (svc, store, _) = make_svc();
        let id = AccountId::new();
        let mut account = make_account(id, "deleteduser", AccountType::User, AccountStatus::Active);
        inject(&store, &account).await;

        // Create the token before marking as deleted
        let ctx = CallContext::system();
        let (token_str, _) = svc.create_pat(&ctx, &account, "t", 60, AuthScope::Auth).await.unwrap();

        // Now mark deleted in store
        account.deleted_at = Some(Utc::now());
        store.update_account(&ctx, &account).await.unwrap();

        let result = svc.authenticate(&ctx, &token_str).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticate_token_account_not_active() {
        let (svc, store, _) = make_svc();
        let id = AccountId::new();
        let account = make_account(id, "disableduser", AccountType::User, AccountStatus::Active);
        inject(&store, &account).await;

        let ctx = CallContext::system();
        let (token_str, _) = svc.create_pat(&ctx, &account, "t", 60, AuthScope::Auth).await.unwrap();

        // Disable account
        store.set_status(&ctx, id, AccountStatus::Disabled, None).await.unwrap();

        let result = svc.authenticate(&ctx, &token_str).await;
        assert!(result.is_err());
    }

    // ---- create_pat ----

    #[tokio::test]
    async fn create_pat_success() {
        let (svc, store, _) = make_svc();
        let (account, _) = make_active_account(&store, "patuser").await;
        let ctx = CallContext::system();
        let result = svc.create_pat(&ctx, &account, "my token", 60, AuthScope::Auth).await;
        assert!(result.is_ok());
        let (token_str, pat) = result.unwrap();
        assert!(token_str.starts_with("hkat_"));
        assert_eq!(pat.account_id, account.id);
        assert_eq!(pat.purpose, TokenPurpose::Auth);
    }

    #[tokio::test]
    async fn create_pat_refresh_scope() {
        let (svc, store, _) = make_svc();
        let (account, _) = make_active_account(&store, "refreshuser").await;
        let ctx = CallContext::system();
        let (_, pat) = svc
            .create_pat(&ctx, &account, "refresh", 60, AuthScope::Refresh)
            .await
            .unwrap();
        assert_eq!(pat.purpose, TokenPurpose::Refresh);
    }

    #[tokio::test]
    async fn create_pat_system_account_rejected() {
        let (svc, store, _) = make_svc();
        let id = AccountId::new();
        let system_account = make_account(id, "sysuser", AccountType::System, AccountStatus::Active);
        inject(&store, &system_account).await;
        let ctx = CallContext::system();
        let result = svc.create_pat(&ctx, &system_account, "t", 60, AuthScope::Auth).await;
        assert!(result.is_err());
    }

    // ---- list_pat / pat_info / pat_revoke ----

    #[tokio::test]
    async fn list_pat_empty() {
        let (svc, _, _) = make_svc();
        let ctx = CallContext::system();
        let id = AccountId::new();
        let (result, total) = svc.list_pat(&ctx, id, 20, 0).await.unwrap();
        assert!(result.is_empty());
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn list_pat_returns_created_tokens() {
        let (svc, store, _) = make_svc();
        let (account, _) = make_active_account(&store, "listpatuser").await;
        let ctx = CallContext::system();
        svc.create_pat(&ctx, &account, "t1", 60, AuthScope::Auth).await.unwrap();
        svc.create_pat(&ctx, &account, "t2", 60, AuthScope::Auth).await.unwrap();
        let (tokens, total) = svc.list_pat(&ctx, account.id, 20, 0).await.unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(total, 2);
    }

    #[tokio::test]
    async fn pat_info_not_found() {
        let (svc, _, _) = make_svc();
        use crate::manager::token::PatId;
        let ctx = CallContext::system();
        let result = svc.pat_info(&ctx, PatId::new()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn pat_info_found() {
        let (svc, store, _) = make_svc();
        let (account, _) = make_active_account(&store, "patinfouser").await;
        let ctx = CallContext::system();
        let (_str, pat) = svc
            .create_pat(&ctx, &account, "info test", 60, AuthScope::Auth)
            .await
            .unwrap();
        let found = svc.pat_info(&ctx, pat.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, pat.id);
    }

    #[tokio::test]
    async fn pat_revoke_success() {
        let (svc, store, _) = make_svc();
        let (account, _) = make_active_account(&store, "revokeuser").await;
        let ctx = CallContext::system();
        let (_str, pat) = svc
            .create_pat(&ctx, &account, "to revoke", 60, AuthScope::Auth)
            .await
            .unwrap();
        let revoked = svc.pat_revoke(&ctx, pat.id).await.unwrap();
        assert!(revoked);
    }

    // ---- exchange_refresh_token ----

    #[tokio::test]
    async fn exchange_refresh_token_wrong_scope() {
        let (svc, store, _) = make_svc();
        let (account, _) = make_active_account(&store, "exchangeuser").await;
        let ctx = CallContext::system();
        // Create an Auth-scoped token (not Refresh)
        let (token_str, _) = svc.create_pat(&ctx, &account, "t", 60, AuthScope::Auth).await.unwrap();
        let result = svc.exchange_refresh_token(&ctx, &token_str).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn exchange_refresh_token_success() {
        let (svc, store, _) = make_svc();
        let (account, _) = make_active_account(&store, "refreshexchangeuser").await;
        let ctx = CallContext::system();
        let (refresh_str, _) = svc
            .create_pat(&ctx, &account, "refresh token", 60, AuthScope::Refresh)
            .await
            .unwrap();
        let result = svc.exchange_refresh_token(&ctx, &refresh_str).await;
        assert!(result.is_ok());
        let (returned_account, access_str, _access_pat, refresh_str2, _refresh_pat2) = result.unwrap();
        assert_eq!(returned_account.id, account.id);
        assert!(access_str.starts_with("hkat_"));
        assert!(refresh_str2.starts_with("hkrt_"));
    }

    #[tokio::test]
    async fn exchange_refresh_token_account_disabled() {
        let (svc, store, _) = make_svc();
        let (account, id) = make_active_account(&store, "disabledrefreshuser").await;
        let ctx = CallContext::system();
        let (refresh_str, _) = svc
            .create_pat(&ctx, &account, "r", 60, AuthScope::Refresh)
            .await
            .unwrap();

        store.set_status(&ctx, id, AccountStatus::Disabled, None).await.unwrap();

        let result = svc.exchange_refresh_token(&ctx, &refresh_str).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn exchange_refresh_token_ip_mismatch() {
        let (svc, store, _) = make_svc();
        let (account, _) = make_active_account(&store, "ipmismatchuser").await;

        // Create token with bound IP
        let mut ctx_with_ip = CallContext::for_account(account.id);
        ctx_with_ip.client_ip = Some("1.2.3.4".parse().unwrap());
        let (refresh_str, _) = svc
            .create_pat(&ctx_with_ip, &account, "r", 60, AuthScope::Refresh)
            .await
            .unwrap();

        // Exchange with different IP
        let mut ctx_other_ip = CallContext::system();
        ctx_other_ip.client_ip = Some("9.9.9.9".parse().unwrap());
        let result = svc.exchange_refresh_token(&ctx_other_ip, &refresh_str).await;
        assert!(result.is_err());
    }

    // ---- authenticate_with_id_secret / authenticate_with_name_secret error paths ----

    #[tokio::test]
    async fn authenticate_with_id_system_account_rejected() {
        let (svc, store, _) = make_svc();
        let id = AccountId::new();
        let sys_account = make_account(id, "sysaccount", AccountType::System, AccountStatus::Active);
        inject(&store, &sys_account).await;
        let ctx = CallContext::system();
        let result = svc
            .authenticate_with_id_secret(&ctx, id, &PasswordOrPassphrase::Password(Password::new("pw")))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticate_with_id_deleted_account_rejected() {
        let (svc, store, _) = make_svc();
        let id = AccountId::new();
        let mut account = make_account(id, "deletedauth", AccountType::User, AccountStatus::Active);
        account.deleted_at = Some(Utc::now());
        inject(&store, &account).await;
        let ctx = CallContext::system();
        let result = svc
            .authenticate_with_id_secret(&ctx, id, &PasswordOrPassphrase::Password(Password::new("pw")))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticate_with_id_locked_until_future_rejected() {
        let (svc, store, _) = make_svc();
        let id = AccountId::new();
        let mut account = make_account(id, "timelocked", AccountType::User, AccountStatus::Active);
        account.locked_until = Some(Utc::now() + chrono::Duration::hours(1));
        inject(&store, &account).await;
        let ctx = CallContext::system();
        let result = svc
            .authenticate_with_id_secret(&ctx, id, &PasswordOrPassphrase::Password(Password::new("pw")))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticate_with_id_disabled_status_rejected() {
        let (svc, store, _) = make_svc();
        let id = AccountId::new();
        let account = make_account(id, "disabledstatus", AccountType::User, AccountStatus::Disabled);
        inject(&store, &account).await;
        let ctx = CallContext::system();
        let result = svc
            .authenticate_with_id_secret(&ctx, id, &PasswordOrPassphrase::Password(Password::new("pw")))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticate_with_id_admin_locked_rejected() {
        let (svc, store, _) = make_svc();
        let id = AccountId::new();
        let account = make_account(id, "adminlocked", AccountType::User, AccountStatus::Locked);
        inject(&store, &account).await;
        let ctx = CallContext::system();
        let result = svc
            .authenticate_with_id_secret(&ctx, id, &PasswordOrPassphrase::Password(Password::new("pw")))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticate_with_id_no_password_hash_rejected() {
        let (svc, store, _) = make_svc();
        let id = AccountId::new();
        let account = make_account(id, "nohashuser", AccountType::User, AccountStatus::Active);
        // password_hash is None by default in make_account
        inject(&store, &account).await;
        let ctx = CallContext::system();
        let result = svc
            .authenticate_with_id_secret(&ctx, id, &PasswordOrPassphrase::Password(Password::new("pw")))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticate_with_name_system_account_rejected() {
        let (svc, store, _) = make_svc();
        let id = AccountId::new();
        let sys_account = make_account(id, "sysbyname", AccountType::System, AccountStatus::Active);
        inject(&store, &sys_account).await;
        let ctx = CallContext::system();
        let name = AccountName::try_from("sysbyname").unwrap();
        let result = svc
            .authenticate_with_name_secret(&ctx, &name, &PasswordOrPassphrase::Password(Password::new("pw")))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticate_with_name_no_hash_rejected() {
        let (svc, store, _) = make_svc();
        let id = AccountId::new();
        let account = make_account(id, "nohashbyname", AccountType::User, AccountStatus::Active);
        inject(&store, &account).await;
        let ctx = CallContext::system();
        let name = AccountName::try_from("nohashbyname").unwrap();
        let result = svc
            .authenticate_with_name_secret(&ctx, &name, &PasswordOrPassphrase::Password(Password::new("pw")))
            .await;
        assert!(result.is_err());
    }

    // ---- record_failed_login / record_successful_login ----

    #[tokio::test]
    async fn record_failed_login_success() {
        let (svc, store, _) = make_svc();
        let (_, id) = make_active_account(&store, "failedloginuser").await;
        let ctx = CallContext::system();
        let result = svc.record_failed_login(&ctx, id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn record_successful_login_success() {
        let (svc, store, _) = make_svc();
        let (_, id) = make_active_account(&store, "successloginuser").await;
        let ctx = CallContext::system();
        let result = svc.record_successful_login(&ctx, id).await;
        assert!(result.is_ok());
    }

    #[test]
    fn get_dummy_account_hash_returns_valid_argon2_hash() {
        let hash = get_dummy_account_hash().expect("hash generation should succeed");
        // Argon2 PHC hashes start with "$argon2"
        assert!(hash.starts_with("$argon2"), "expected argon2 hash, got: {hash}");
    }

    #[test]
    fn get_dummy_account_hash_is_idempotent() {
        let h1 = get_dummy_account_hash().unwrap();
        let h2 = get_dummy_account_hash().unwrap();
        // OnceLock — same value on every call
        assert_eq!(h1, h2);
    }

    #[test]
    fn get_dummy_account_hash_is_non_empty() {
        let hash = get_dummy_account_hash().unwrap();
        assert!(!hash.is_empty());
    }
}
