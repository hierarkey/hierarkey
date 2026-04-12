// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::global::row_hmac::{RowHmac, sign_pat, verify_pat};
use crate::global::short_id::ShortId;
use crate::global::uuid_id::Identifier;
use crate::http_server::handlers::auth_response::AuthScope;
use crate::manager::account::AccountId;
use crate::service::signing_key_slot::SigningKeySlot;
use crate::{one_line_sql, uuid_id};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use hierarkey_core::error::auth::{AuthError, AuthFailReason};
use hierarkey_core::error::validation::ValidationError;
use hierarkey_core::{CkError, CkResult};
#[cfg(test)]
use parking_lot::Mutex;
use rand::TryRng;
use sqlx::{PgPool, Row};
#[cfg(test)]
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use uuid::Uuid;

uuid_id!(PatId, "pat_");

const TOKEN_PREFIX_AUTH: &str = "hkat_";
const TOKEN_PREFIX_REFRESH: &str = "hkrt_";
const TOKEN_PREFIX_CHANGE_PWD: &str = "hkcp_";
const TOKEN_PREFIX_MFA_CHALLENGE: &str = "hkmf_";
const ALL_TOKEN_PREFIXES: &[&str] = &[
    TOKEN_PREFIX_AUTH,
    TOKEN_PREFIX_REFRESH,
    TOKEN_PREFIX_CHANGE_PWD,
    TOKEN_PREFIX_MFA_CHALLENGE,
];
const MIN_DESCRIPTION_LENGTH: usize = 1;
const MAX_DESCRIPTION_LENGTH: usize = 200;
pub const MIN_TTL_MINUTES: i64 = 1;
pub const MAX_TTL_MINUTES: i64 = 24 * 60 * 7; // 7 days max

/// Purpose of a token — controls which endpoints it may be used on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "token_purpose", rename_all = "snake_case")]
pub enum TokenPurpose {
    /// Token can be used for changing password only
    ChangePwd,
    /// Token can be used for general API authentication
    Auth,
    /// Long-lived token used only to obtain a new access token
    Refresh,
    /// Short-lived token used only to submit an MFA verification code
    MfaChallenge,
}

impl From<AuthScope> for TokenPurpose {
    fn from(scope: AuthScope) -> Self {
        match scope {
            AuthScope::ChangePassword => TokenPurpose::ChangePwd,
            AuthScope::Auth => TokenPurpose::Auth,
            AuthScope::Refresh => TokenPurpose::Refresh,
            AuthScope::MfaChallenge => TokenPurpose::MfaChallenge,
        }
    }
}

impl std::fmt::Display for TokenPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenPurpose::ChangePwd => write!(f, "change_password"),
            TokenPurpose::Auth => write!(f, "auth"),
            TokenPurpose::Refresh => write!(f, "refresh"),
            TokenPurpose::MfaChallenge => write!(f, "mfa_challenge"),
        }
    }
}

#[async_trait::async_trait]
pub trait TokenStore: Send + Sync {
    async fn save_token(&self, pat: &PersonalAccessToken) -> CkResult<()>;
    async fn find_token(&self, token_id: PatId) -> CkResult<Option<PersonalAccessToken>>;
    async fn update_last_used(&self, token_id: PatId, when: DateTime<Utc>) -> CkResult<()>;
    async fn revoke_token(&self, token_id: PatId) -> CkResult<bool>;
    async fn list_user_tokens(
        &self,
        account_id: AccountId,
        limit: usize,
        offset: usize,
    ) -> CkResult<(Vec<PersonalAccessToken>, usize)>;
    /// Update only the `row_hmac` column for a PAT (used after revocation re-signing).
    async fn update_pat_hmac(&self, token_id: PatId, hmac_hex: &str) -> CkResult<()>;
}

#[derive(Debug, Clone)]
pub struct PersonalAccessToken {
    pub id: PatId,
    pub short_id: ShortId,
    pub account_id: AccountId,
    pub description: String,
    token_hash: [u8; 32],
    pub token_suffix: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub purpose: TokenPurpose,
    /// Client IP address recorded at token creation. Only set for Refresh-scoped tokens.
    pub created_from_ip: Option<IpAddr>,
    /// Row-level HMAC covering id, account_id, expires_at, purpose, revoked_at.
    pub row_hmac: Option<String>,
}

impl PersonalAccessToken {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_revoked()
    }
}

// #[derive(Debug, Clone, Serialize)]
// pub struct TokenInfo {
//     pub id: PatId,
//     pub account_id: AccountId,
//     pub name: String,
//     pub description: String,
//     pub token_suffix: String,
//     pub created_at: DateTime<Utc>,
//     pub expires_at: DateTime<Utc>,
//     pub last_used_at: Option<DateTime<Utc>>,
//     pub revoked_at: Option<DateTime<Utc>>,
// }

// impl From<PersonalAccessToken> for TokenInfo {
//     fn from(pat: PersonalAccessToken) -> Self {
//         Self {
//             id: pat.id,
//             account_id: pat.account_id,
//             name: String::new(), // This should be filled in by the caller
//             description: pat.description,
//             token_suffix: pat.token_suffix,
//             created_at: pat.created_at,
//             expires_at: pat.expires_at,
//             last_used_at: pat.last_used_at,
//             revoked_at: pat.revoked_at,
//         }
//     }
// }

pub struct SqlTokenStore {
    pool: PgPool,
}

impl SqlTokenStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl TokenStore for SqlTokenStore {
    async fn save_token(&self, pat: &PersonalAccessToken) -> CkResult<()> {
        sqlx::query(&one_line_sql(
            r#"
            INSERT INTO pats
                (id, account_id, description, token_hash, token_suffix, created_at, expires_at, last_used_at, revoked_at, purpose, created_from_ip, row_hmac)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        ))
        .bind(pat.id)
        .bind(pat.account_id)
        .bind(&pat.description)
        .bind(pat.token_hash)
        .bind(&pat.token_suffix)
        .bind(pat.created_at)
        .bind(pat.expires_at)
        .bind(pat.last_used_at)
        .bind(pat.revoked_at)
        .bind(pat.purpose)
        .bind(pat.created_from_ip.map(|ip| ip.to_string()))
        .bind(&pat.row_hmac)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn find_token(&self, token_id: PatId) -> CkResult<Option<PersonalAccessToken>> {
        let rec = sqlx::query(&one_line_sql(
            r#"
            SELECT
                id, short_id, account_id, description, token_hash, token_suffix, purpose,
                created_at, expires_at, last_used_at, revoked_at, revoked_by, usage_count, metadata,
                created_from_ip, row_hmac
            FROM pats
            WHERE id = $1
            "#,
        ))
        .bind(token_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(rec) = rec {
            let pat = PersonalAccessToken {
                id: rec.get("id"),
                short_id: rec.get("short_id"),
                account_id: rec.get("account_id"),
                description: rec.get("description"),
                token_hash: rec.get("token_hash"),
                token_suffix: rec.get("token_suffix"),
                created_at: rec.get("created_at"),
                expires_at: rec.get("expires_at"),
                last_used_at: rec.get("last_used_at"),
                revoked_at: rec.get("revoked_at"),
                purpose: rec.get("purpose"),
                created_from_ip: rec
                    .get::<Option<String>, _>("created_from_ip")
                    .and_then(|s| s.parse::<IpAddr>().ok()),
                row_hmac: rec.get("row_hmac"),
            };
            Ok(Some(pat))
        } else {
            Ok(None)
        }
    }

    async fn update_last_used(&self, token_id: PatId, when: DateTime<Utc>) -> CkResult<()> {
        sqlx::query(&one_line_sql(
            r#"
            UPDATE pats
            SET last_used_at = $2, usage_count = usage_count + 1
            WHERE id = $1
            "#,
        ))
        .bind(token_id)
        .bind(when)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn revoke_token(&self, token_id: PatId) -> CkResult<bool> {
        let result = sqlx::query(&one_line_sql(
            r#"
            UPDATE pats
            SET revoked_at = $2
            WHERE id = $1 AND revoked_at IS NULL
            "#,
        ))
        .bind(token_id)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_user_tokens(
        &self,
        account_id: AccountId,
        limit: usize,
        offset: usize,
    ) -> CkResult<(Vec<PersonalAccessToken>, usize)> {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pats WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&self.pool)
            .await?;

        let rows = sqlx::query(&one_line_sql(
            r#"
            SELECT
                id, short_id, account_id, description, token_hash, token_suffix, purpose,
                created_at, expires_at, last_used_at, revoked_at,
                revoked_by, usage_count, metadata, created_from_ip, row_hmac
            FROM pats
            WHERE account_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        ))
        .bind(account_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;

        let tokens = rows
            .iter()
            .map(|rec| PersonalAccessToken {
                id: rec.get("id"),
                short_id: rec.get("short_id"),
                account_id: rec.get("account_id"),
                description: rec.get("description"),
                token_hash: rec.get("token_hash"),
                token_suffix: rec.get("token_suffix"),
                created_at: rec.get("created_at"),
                expires_at: rec.get("expires_at"),
                last_used_at: rec.get("last_used_at"),
                revoked_at: rec.get("revoked_at"),
                purpose: rec.get("purpose"),
                created_from_ip: rec
                    .get::<Option<String>, _>("created_from_ip")
                    .and_then(|s| s.parse::<IpAddr>().ok()),
                row_hmac: rec.get("row_hmac"),
            })
            .collect();

        Ok((tokens, total as usize))
    }

    async fn update_pat_hmac(&self, token_id: PatId, hmac_hex: &str) -> CkResult<()> {
        sqlx::query("UPDATE pats SET row_hmac = $2 WHERE id = $1")
            .bind(token_id)
            .bind(hmac_hex)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
pub struct InMemoryTokenStore {
    tokens: Mutex<HashMap<PatId, PersonalAccessToken>>,
}

#[cfg(test)]
impl Default for InMemoryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl InMemoryTokenStore {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl TokenStore for InMemoryTokenStore {
    async fn save_token(&self, pat: &PersonalAccessToken) -> CkResult<()> {
        self.tokens.lock().insert(pat.id, pat.clone());
        Ok(())
    }

    async fn find_token(&self, token_id: PatId) -> CkResult<Option<PersonalAccessToken>> {
        Ok(self.tokens.lock().get(&token_id).cloned())
    }

    async fn update_last_used(&self, token_id: PatId, when: DateTime<Utc>) -> CkResult<()> {
        if let Some(pat) = self.tokens.lock().get_mut(&token_id) {
            pat.last_used_at = Some(when);
        }
        Ok(())
    }

    async fn revoke_token(&self, token_id: PatId) -> CkResult<bool> {
        let mut tokens = self.tokens.lock();
        if let Some(pat) = tokens.get_mut(&token_id) {
            if pat.revoked_at.is_some() {
                return Ok(false);
            }
            pat.revoked_at = Some(Utc::now());
            return Ok(true);
        }

        Err(CkError::ResourceNotFound {
            kind: "pat",
            id: token_id.to_string(),
        })
    }

    async fn update_pat_hmac(&self, token_id: PatId, hmac_hex: &str) -> CkResult<()> {
        let mut tokens = self.tokens.lock();
        if let Some(pat) = tokens.get_mut(&token_id) {
            pat.row_hmac = Some(hmac_hex.to_string());
        }
        Ok(())
    }

    async fn list_user_tokens(
        &self,
        account_id: AccountId,
        limit: usize,
        offset: usize,
    ) -> CkResult<(Vec<PersonalAccessToken>, usize)> {
        let tokens = self.tokens.lock();
        let mut user_tokens: Vec<_> = tokens
            .values()
            .filter(|pat| pat.account_id == account_id)
            .cloned()
            .collect();

        user_tokens.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        let total = user_tokens.len();
        let page = user_tokens.into_iter().skip(offset).take(limit).collect();
        Ok((page, total))
    }
}

pub struct TokenManager {
    store: Arc<dyn TokenStore>,
    signing_slot: Arc<SigningKeySlot>,
}

impl TokenManager {
    pub fn new(store: Arc<dyn TokenStore>, signing_slot: Arc<SigningKeySlot>) -> Self {
        Self { store, signing_slot }
    }

    fn validate_description(&self, description: &str) -> CkResult<()> {
        let field = "description";

        if description.len() < MIN_DESCRIPTION_LENGTH {
            return Err(ValidationError::TooShort {
                field,
                min: MIN_DESCRIPTION_LENGTH,
            }
            .into());
        }
        if description.len() > MAX_DESCRIPTION_LENGTH {
            return Err(ValidationError::TooLong {
                field,
                max: MAX_DESCRIPTION_LENGTH,
            }
            .into());
        }

        Ok(())
    }

    fn validate_ttl(&self, ttl_minutes: i64) -> CkResult<()> {
        if ttl_minutes < MIN_TTL_MINUTES {
            return Err(ValidationError::Custom(format!("TTL must be at least {MIN_TTL_MINUTES} minute(s)")).into());
        }

        if ttl_minutes > MAX_TTL_MINUTES {
            return Err(ValidationError::Custom("TTL must be at most 7 days".into()).into());
        }

        Ok(())
    }

    pub async fn create_token(
        &self,
        account_id: AccountId,
        description: &str,
        ttl_minutes: i64,
        purpose: TokenPurpose,
        client_ip: Option<IpAddr>,
    ) -> CkResult<(String, PersonalAccessToken)> {
        self.validate_description(description)?;
        self.validate_ttl(ttl_minutes)?;

        let token_id = PatId::new();
        let token_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_id.as_bytes());

        let mut token_bytes = [0u8; 32];
        rand::rng()
            .try_fill_bytes(&mut token_bytes)
            .map_err(|e| CkError::Custom(format!("Failed to generate token: {e}")))?;

        let secret_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
        let prefix = match purpose {
            TokenPurpose::Auth => TOKEN_PREFIX_AUTH,
            TokenPurpose::Refresh => TOKEN_PREFIX_REFRESH,
            TokenPurpose::ChangePwd => TOKEN_PREFIX_CHANGE_PWD,
            TokenPurpose::MfaChallenge => TOKEN_PREFIX_MFA_CHALLENGE,
        };
        let raw_token = format!("{prefix}{token_id_b64}.{secret_b64}");

        let token_hash = blake3::hash(secret_b64.as_bytes());

        let now = Utc::now();
        let expires_at = now + Duration::minutes(ttl_minutes);

        let row_hmac = self
            .signing_slot
            .peek()
            .map(|key| sign_pat(&key, token_id.0, account_id, expires_at, &purpose.to_string(), None).to_hex());

        let pat = PersonalAccessToken {
            id: token_id,
            short_id: ShortId::generate("tok_", 12),
            account_id,
            description: description.to_string(),
            token_hash: *token_hash.as_bytes(),
            token_suffix: secret_b64[secret_b64.len().saturating_sub(4)..].to_string(),
            created_at: now,
            expires_at,
            last_used_at: None,
            revoked_at: None,
            purpose,
            created_from_ip: client_ip,
            row_hmac,
        };

        self.store.save_token(&pat).await?;

        Ok((raw_token, pat))
    }

    pub async fn authenticate_token(&self, token: &str) -> CkResult<PersonalAccessToken> {
        let token =
            ALL_TOKEN_PREFIXES
                .iter()
                .find_map(|p| token.strip_prefix(p))
                .ok_or(AuthError::Unauthenticated {
                    reason: AuthFailReason::InvalidToken,
                })?;

        let (id_str, token_secret_b64) = token.split_once('.').ok_or(AuthError::Unauthenticated {
            reason: AuthFailReason::InvalidToken,
        })?;

        let id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(id_str)
            .map_err(|_| AuthError::Unauthenticated {
                reason: AuthFailReason::InvalidToken,
            })?;

        if id_bytes.len() != 16 {
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::InvalidToken,
            }
            .into());
        }

        let token_id_uuid = Uuid::from_slice(&id_bytes).map_err(|_| AuthError::Unauthenticated {
            reason: AuthFailReason::InvalidToken,
        })?;
        let token_id = PatId(token_id_uuid);

        let pat = self
            .store
            .find_token(token_id)
            .await?
            .ok_or(AuthError::Unauthenticated {
                reason: AuthFailReason::MissingToken,
            })?;

        if !pat.is_valid() {
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::InvalidToken,
            }
            .into());
        }

        // Make sure we check in constant time here
        let provided = blake3::hash(token_secret_b64.as_bytes());
        let hash_match = provided.as_bytes().ct_eq(pat.token_hash.as_slice());
        if !bool::from(hash_match) {
            return Err(AuthError::Unauthenticated {
                reason: AuthFailReason::InvalidToken,
            }
            .into());
        }

        // Verify row HMAC if signing key is loaded — fail closed on NULL or mismatch
        if let Some(key) = self.signing_slot.peek() {
            let hmac_hex = pat.row_hmac.as_deref().ok_or(AuthError::Unauthenticated {
                reason: AuthFailReason::InvalidToken,
            })?;
            let expected = RowHmac::from_hex(hmac_hex).map_err(|_| {
                CkError::from(AuthError::Unauthenticated {
                    reason: AuthFailReason::InvalidToken,
                })
            })?;
            if !verify_pat(
                &key,
                pat.id.0,
                pat.account_id,
                pat.expires_at,
                &pat.purpose.to_string(),
                pat.revoked_at,
                &expected,
            ) {
                return Err(AuthError::Unauthenticated {
                    reason: AuthFailReason::InvalidToken,
                }
                .into());
            }
        }

        let now = Utc::now();
        self.store.update_last_used(pat.id, now).await?;

        Ok(pat)
    }

    pub async fn revoke_token(&self, _ctx: &CallContext, token_id: PatId) -> CkResult<bool> {
        let revoked = self.store.revoke_token(token_id).await?;
        if revoked {
            // Re-sign the PAT now that revoked_at has changed
            if let Some(key) = self.signing_slot.peek()
                && let Ok(Some(pat)) = self.store.find_token(token_id).await
            {
                let hmac_hex = sign_pat(
                    &key,
                    pat.id.0,
                    pat.account_id,
                    pat.expires_at,
                    &pat.purpose.to_string(),
                    pat.revoked_at,
                )
                .to_hex();
                if let Err(e) = self.store.update_pat_hmac(token_id, &hmac_hex).await {
                    tracing::warn!(token_id = %token_id, err = %e, "failed to re-sign PAT after revocation");
                }
            }
        }
        Ok(revoked)
    }

    pub async fn list_user_tokens(
        &self,
        account_id: AccountId,
        limit: usize,
        offset: usize,
    ) -> CkResult<(Vec<PersonalAccessToken>, usize)> {
        self.store.list_user_tokens(account_id, limit, offset).await
    }

    pub async fn find_token_info(&self, token_id: PatId) -> CkResult<Option<PersonalAccessToken>> {
        self.store.find_token(token_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::global::short_id::ShortId;
    use crate::manager::account::Account;
    use crate::service::account::{AccountStatus, AccountType};
    use crate::service::signing_key_slot::SigningKeySlot;
    use hierarkey_core::Metadata;
    use hierarkey_core::resources::AccountName;

    fn create_test_user() -> Account {
        Account {
            id: AccountId::new(),
            short_id: ShortId::generate("acc_", 12),
            name: AccountName::try_from("testuser").unwrap(),
            email: None,
            password_hash: Some("hash".to_string()),
            account_type: AccountType::User,
            status: AccountStatus::Active,
            mfa_enabled: false,
            mfa_secret: None,
            last_login_at: None,
            failed_login_attempts: 0,
            locked_until: None,
            status_changed_at: None,
            password_changed_at: None,
            must_change_password: false,
            full_name: None,
            metadata: Metadata::default(),
            created_at: Utc::now(),
            created_by: Some(AccountId::new()),
            updated_at: None,
            updated_by: None,
            deleted_at: None,
            deleted_by: None,
            status_reason: None,
            status_changed_by: None,
            passphrase_hash: None,
            public_key: None,
            mfa_backup_codes: None,
            client_cert_fingerprint: None,
            client_cert_subject: None,
            row_hmac: None,
        }
    }

    #[tokio::test]
    async fn test_create_token() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store.clone(), Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let (token, pat) = manager
            .create_token(user.id, "My API Token", 24, TokenPurpose::Auth, None)
            .await
            .unwrap();

        assert!(token.starts_with(TOKEN_PREFIX_AUTH));
        assert_eq!(pat.account_id, user.id);
        assert_eq!(pat.description, "My API Token");
    }

    #[tokio::test]
    async fn test_create_token_no_expiry() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let (token, _pat) = manager
            .create_token(user.id, "Permanent Token", 24, TokenPurpose::Auth, None)
            .await
            .unwrap();

        assert!(token.starts_with(TOKEN_PREFIX_AUTH));
    }

    #[tokio::test]
    async fn test_validate_description_too_short() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let result = manager.create_token(user.id, "", 24, TokenPurpose::Auth, None).await;
        assert!(result.is_err());

        match result {
            Err(CkError::Validation(ValidationError::TooShort { field, min })) => {
                assert_eq!(field, "description");
                assert_eq!(min, MIN_DESCRIPTION_LENGTH);
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[tokio::test]
    async fn test_validate_description_too_long() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let long_desc = "a".repeat(201);
        let result = manager
            .create_token(user.id, &long_desc, 24, TokenPurpose::Auth, None)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_ttl_too_short() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let result = manager
            .create_token(user.id, "Token", 0, TokenPurpose::Auth, None)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_ttl_too_long() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let result = manager
            .create_token(user.id, "Token", 100000, TokenPurpose::Auth, None)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_token_success() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let (token, _) = manager
            .create_token(user.id, "Test Token", 24, TokenPurpose::Auth, None)
            .await
            .unwrap();

        let pat = manager.authenticate_token(&token).await.unwrap();

        assert_eq!(user.id, pat.account_id);
    }

    #[tokio::test]
    async fn test_authenticate_token_invalid_prefix() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));

        let result = manager.authenticate_token("invalid_token").await;
        assert!(result.is_err());

        match result {
            Err(CkError::Auth(AuthError::Unauthenticated { reason })) => {
                assert_eq!(reason, AuthFailReason::InvalidToken);
            }
            _ => panic!("Expected InvalidCredentials"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_token_wrong_secret() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let (token, _) = manager
            .create_token(user.id, "Test Token", 24, TokenPurpose::Auth, None)
            .await
            .unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        let tampered_token = format!("{}.wrongsecret", parts[0]);

        let result = manager.authenticate_token(&tampered_token).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_expired_token() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store.clone(), Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let (token, mut pat) = manager
            .create_token(user.id, "Test Token", 24, TokenPurpose::Auth, None)
            .await
            .unwrap();

        pat.expires_at = Utc::now() - Duration::hours(1);
        store.save_token(&pat).await.unwrap();

        let result = manager.authenticate_token(&token).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_revoke_token() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let (token, pat) = manager
            .create_token(user.id, "Test Token", 24, TokenPurpose::Auth, None)
            .await
            .unwrap();

        manager.revoke_token(&ctx, pat.id).await.unwrap();

        let result = manager.authenticate_token(&token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_revoke_token_twice() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let (_, pat) = manager
            .create_token(user.id, "Test Token", 24, TokenPurpose::Auth, None)
            .await
            .unwrap();

        let result = manager.revoke_token(&ctx, pat.id).await.unwrap();
        assert!(result);
        let result = manager.revoke_token(&ctx, pat.id).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_list_user_tokens() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        manager
            .create_token(user.id, "Token 1", 24, TokenPurpose::Auth, None)
            .await
            .unwrap();
        manager
            .create_token(user.id, "Token 2", 1, TokenPurpose::Auth, None)
            .await
            .unwrap();

        let (tokens, total) = manager.list_user_tokens(user.id, 20, 0).await.unwrap();

        assert_eq!(total, 2);
        assert!(tokens.iter().any(|t| t.description == "Token 1"));
        assert!(tokens.iter().any(|t| t.description == "Token 2"));
    }

    #[tokio::test]
    async fn test_list_user_tokens_sorted() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        manager
            .create_token(user.id, "Old", 24, TokenPurpose::Auth, None)
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        manager
            .create_token(user.id, "New", 24, TokenPurpose::Auth, None)
            .await
            .unwrap();

        let (tokens, _) = manager.list_user_tokens(user.id, 20, 0).await.unwrap();

        assert_eq!(tokens[0].description, "New");
        assert_eq!(tokens[1].description, "Old");
    }

    #[tokio::test]
    async fn test_get_token_info() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store, Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let (_, pat) = manager
            .create_token(user.id, "Test Token", 24, TokenPurpose::Auth, None)
            .await
            .unwrap();

        let info = manager.find_token_info(pat.id).await.unwrap().unwrap();

        assert_eq!(info.id, pat.id);
        assert_eq!(info.description, "Test Token");
    }

    #[tokio::test]
    async fn test_update_last_used() {
        let store = Arc::new(InMemoryTokenStore::new());
        let manager = TokenManager::new(store.clone(), Arc::new(SigningKeySlot::new()));
        let user = create_test_user();

        let (token, pat) = manager
            .create_token(user.id, "Test Token", 24, TokenPurpose::Auth, None)
            .await
            .unwrap();

        assert!(pat.last_used_at.is_none());

        manager.authenticate_token(&token).await.unwrap();

        let updated = store.find_token(pat.id).await.unwrap().unwrap();
        assert!(updated.last_used_at.is_some());
    }

    #[tokio::test]
    async fn test_is_expired() {
        let mut pat = PersonalAccessToken {
            id: PatId::new(),
            short_id: ShortId::generate("tok_", 12),
            account_id: AccountId::new(),
            description: "Test".to_string(),
            token_hash: *blake3::hash("hash".as_bytes()).as_bytes(),
            token_suffix: "prefix".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            last_used_at: None,
            revoked_at: None,
            purpose: TokenPurpose::ChangePwd,
            created_from_ip: None,
            row_hmac: None,
        };

        assert!(!pat.is_expired());

        pat.expires_at = Utc::now() + Duration::hours(1);
        assert!(!pat.is_expired());

        pat.expires_at = Utc::now() - Duration::hours(1);
        assert!(pat.is_expired());
    }

    #[tokio::test]
    async fn test_is_revoked() {
        let mut pat = PersonalAccessToken {
            id: PatId::new(),
            short_id: ShortId::generate("tok_", 12),
            account_id: AccountId::new(),
            description: "Test".to_string(),
            token_hash: *blake3::hash("hash".as_bytes()).as_bytes(),
            token_suffix: "prefix".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            last_used_at: None,
            revoked_at: None,
            purpose: TokenPurpose::ChangePwd,
            created_from_ip: None,
            row_hmac: None,
        };

        assert!(!pat.is_revoked());

        pat.revoked_at = Some(Utc::now());
        assert!(pat.is_revoked());
    }

    #[tokio::test]
    async fn test_is_valid() {
        let mut pat = PersonalAccessToken {
            id: PatId::new(),
            short_id: ShortId::generate("tok_", 12),
            account_id: AccountId::new(),
            description: "Test".to_string(),
            token_hash: *blake3::hash("hash".as_bytes()).as_bytes(),
            token_suffix: "prefix".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            last_used_at: None,
            revoked_at: None,
            purpose: TokenPurpose::ChangePwd,
            created_from_ip: None,
            row_hmac: None,
        };

        assert!(pat.is_valid());

        pat.expires_at = Utc::now() - Duration::hours(1);
        assert!(!pat.is_valid());

        pat.expires_at = Utc::now() + Duration::hours(1);
        pat.revoked_at = Some(Utc::now());
        assert!(!pat.is_valid());
    }
}
