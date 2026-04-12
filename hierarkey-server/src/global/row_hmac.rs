// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

//! Row-level HMAC integrity for security-critical database rows.
//!
//! Each protected row carries a 32-byte BLAKE3-keyed MAC over a canonical, versioned
//! encoding of its security-critical fields.  The MAC key lives only in memory after
//! the active master key has been unlocked; an attacker with raw database write access
//! cannot forge a valid MAC without also compromising the running server process.
//!
//! ## Protected row types
//!
//! | Row type                  | Covered fields                                                                    |
//! |---------------------------|-----------------------------------------------------------------------------------|
//! | `accounts`                | id, name, account_type, status, password_hash, mfa_enabled, mfa_secret, public_key, passphrase_hash, deleted_at |
//! | `rbac_rules`              | id, effect, permission, target_kind, pattern_raw, condition                       |
//! | `rbac_account_rules`      | account_id, rule_id, valid_from, valid_until                                      |
//! | `rbac_account_roles`      | account_id, role_id, valid_from, valid_until                                      |
//! | `rbac_role_rules`         | role_id, rule_id                                                                  |
//! | `pats`                    | id, account_id, expires_at, purpose, revoked_at                                   |
//!
//! ## Canonical encoding
//!
//! Every signer hashes a context string first (providing type-level domain separation),
//! then each field using deterministic length-prefixed encoding for variable-length
//! data and fixed-width encoding for fixed-size types.  Optional fields are preceded
//! by a presence byte (`0x00` = absent, `0x01` = present).
//!
//! ## Versioning
//!
//! Each row type has a context string of the form `"hierarkey:<type>:v<N>"`.  Changing
//! the canonical field set requires bumping the version in the context string.  A
//! database migration must then re-sign all existing rows.

use crate::global::keys::SigningKey;
use crate::manager::account::{Account, AccountId};
use crate::manager::rbac::rule::RuleRow;
use crate::rbac::{RoleId, RuleId, TargetKind};
use chrono::{DateTime, Utc};
use hierarkey_core::error::crypto::CryptoError;
use hierarkey_core::CkResult;
use uuid::Uuid;

// -- Context strings (domain separators) --
// Each row type uses a distinct string hashed at the start of every MAC computation.
// This guarantees that two rows of different types with identical field values
// produce different MACs, even when the signing key is the same.
// Bump the ":vN" suffix whenever the canonical field set for that row type changes.

// v2: added deleted_at to account HMAC coverage (closes gap 1.6)
pub const ACCOUNT_HMAC_CTX: &str = "hierarkey:account:v2";
pub const RULE_HMAC_CTX: &str = "hierarkey:rbac-rule:v1";
pub const ACCOUNT_RULE_BINDING_HMAC_CTX: &str = "hierarkey:rbac-account-rule:v1";
pub const ACCOUNT_ROLE_BINDING_HMAC_CTX: &str = "hierarkey:rbac-account-role:v1";
pub const ROLE_RULE_HMAC_CTX: &str = "hierarkey:rbac-role-rule:v1";
pub const PAT_HMAC_CTX: &str = "hierarkey:pat:v1";

// -- Output type --

/// A 32-byte BLAKE3-keyed MAC over a canonical row encoding.
///
/// Stored in the database as a 64-character lowercase hex string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowHmac(pub [u8; 32]);

impl RowHmac {
    /// Encode as a lowercase hex string for storage in the database.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Decode a lowercase hex string retrieved from the database.
    pub fn from_hex(s: &str) -> CkResult<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::InvalidEncryptedData {
            field: "row_hmac",
            message: format!("invalid hex: {e}"),
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidEncryptedData {
            field: "row_hmac",
            message: "expected exactly 32 bytes (64 hex chars)".into(),
        })?;
        Ok(RowHmac(arr))
    }
}

// -- Incremental hasher --

/// Wraps a BLAKE3 keyed `Hasher` with helpers for canonical field encoding.
///
/// The context string is hashed first to provide type-level domain separation.
struct RowHasher {
    hasher: blake3::Hasher,
}

impl RowHasher {
    /// Create a new hasher for a specific row type.
    ///
    /// `ctx` must be one of the `*_HMAC_CTX` constants.  It is hashed before any
    /// field data so that MACs for different row types can never collide even if
    /// their field bytes happen to be identical.
    fn new(key: &[u8; 32], ctx: &str) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(key);
        // Prefix the context so it cannot be confused with field data: write its
        // length first so a context that is a prefix of another produces a different hash.
        let ctx_len = ctx.len() as u32;
        hasher.update(&ctx_len.to_le_bytes());
        hasher.update(ctx.as_bytes());
        Self { hasher }
    }

    /// Push a UUID as its 16 raw bytes (RFC 4122 byte order).
    fn uuid(&mut self, id: uuid::Uuid) -> &mut Self {
        self.hasher.update(id.as_bytes());
        self
    }

    /// Push a required string as `[4-byte LE length][UTF-8 bytes]`.
    fn str_req(&mut self, s: &str) -> &mut Self {
        let len = s.len() as u32;
        self.hasher.update(&len.to_le_bytes());
        self.hasher.update(s.as_bytes());
        self
    }

    /// Push an optional string.
    ///
    /// Encoding: `0x00` if absent; `0x01 [4-byte LE length] [UTF-8 bytes]` if present.
    fn str_opt(&mut self, s: Option<&str>) -> &mut Self {
        match s {
            None => {
                self.hasher.update(&[0x00]);
            }
            Some(v) => {
                self.hasher.update(&[0x01]);
                let len = v.len() as u32;
                self.hasher.update(&len.to_le_bytes());
                self.hasher.update(v.as_bytes());
            }
        }
        self
    }

    /// Push a boolean as a single byte (`0x00` = false, `0x01` = true).
    fn bool_field(&mut self, b: bool) -> &mut Self {
        self.hasher.update(&[b as u8]);
        self
    }

    /// Push a required timestamp as `[8-byte i64 LE Unix seconds]`.
    fn datetime_req(&mut self, dt: DateTime<Utc>) -> &mut Self {
        self.hasher.update(&dt.timestamp().to_le_bytes());
        self
    }

    /// Push an optional timestamp.
    ///
    /// Encoding: `0x00` if absent; `0x01 [8-byte i64 LE Unix seconds]` if present.
    /// Second precision is sufficient; sub-second differences in `valid_from` /
    /// `valid_until` are not meaningful for RBAC window enforcement.
    fn datetime_opt(&mut self, dt: Option<DateTime<Utc>>) -> &mut Self {
        match dt {
            None => {
                self.hasher.update(&[0x00]);
            }
            Some(t) => {
                self.hasher.update(&[0x01]);
                self.hasher.update(&t.timestamp().to_le_bytes());
            }
        }
        self
    }

    fn finalize(&self) -> RowHmac {
        RowHmac(*self.hasher.finalize().as_bytes())
    }
}

// -- TargetKind canonical string --

fn target_kind_str(k: TargetKind) -> &'static str {
    match k {
        TargetKind::All => "all",
        TargetKind::Platform => "platform",
        TargetKind::Namespace => "namespace",
        TargetKind::Secret => "secret",
        TargetKind::Account => "account",
    }
}

// -- Account --

/// Compute the HMAC for an `accounts` row (v2).
///
/// Covers the fields whose tampering could elevate privileges or bypass
/// authentication: identity (`id`, `name`, `account_type`), access-control state
/// (`status`, `deleted_at`), and all credential material
/// (`password_hash`, `passphrase_hash`, `public_key`, `mfa_enabled`, `mfa_secret`).
///
/// Including `deleted_at` means that clearing it (resurrecting a soft-deleted account)
/// invalidates the HMAC and is detected on the next authentication attempt.
///
/// Intentionally excludes non-security fields: `full_name`, `email`, `metadata`,
/// `last_login_at`, `failed_login_attempts`, `locked_until`, `updated_at`, etc.
pub fn sign_account(key: &SigningKey, account: &Account) -> RowHmac {
    let mut h = RowHasher::new(key.as_bytes(), ACCOUNT_HMAC_CTX);
    h.uuid(account.id.0)
        .str_req(account.name.as_ref())
        .str_req(&account.account_type.to_string())
        .str_req(&account.status.to_string())
        .str_opt(account.password_hash.as_deref())
        .bool_field(account.mfa_enabled)
        .str_opt(account.mfa_secret.as_deref())
        .str_opt(account.public_key.as_deref())
        .str_opt(account.passphrase_hash.as_deref())
        .datetime_opt(account.deleted_at)
        .finalize()
}

/// Verify the HMAC for an `accounts` row.
///
/// Returns `true` if the MAC matches; `false` if the row has been tampered with
/// or was signed with a different key.
pub fn verify_account(key: &SigningKey, account: &Account, expected: &RowHmac) -> bool {
    sign_account(key, account) == *expected
}

// -- RBAC rule --

/// Compute the HMAC for an `rbac_rules` row.
///
/// Covers the policy-defining fields: `id`, `effect`, `permission`, `target_kind`,
/// `pattern_raw`, and `condition`.
/// Excludes display/audit fields: `metadata`, `created_at`, `created_by`, etc.
pub fn sign_rule(key: &SigningKey, rule: &RuleRow) -> RowHmac {
    let condition_json = rule.condition.as_ref().map(|v| v.to_string());

    let mut h = RowHasher::new(key.as_bytes(), RULE_HMAC_CTX);
    h.uuid(rule.id.0)
        .str_req(&rule.effect.to_string())
        .str_req(&rule.permission)
        .str_req(target_kind_str(rule.target_kind))
        .str_opt(rule.pattern_raw.as_deref())
        .str_opt(condition_json.as_deref())
        .finalize()
}

/// Verify the HMAC for an `rbac_rules` row.
pub fn verify_rule(key: &SigningKey, rule: &RuleRow, expected: &RowHmac) -> bool {
    sign_rule(key, rule) == *expected
}

// -- RBAC account -> rule binding --

/// Compute the HMAC for an `rbac_account_rules` row.
///
/// The binding has a composite PK (`account_id`, `rule_id`).  Both are included
/// along with the time-window fields so that no grant, revoke, or window-shift
/// operation goes undetected.
pub fn sign_account_rule_binding(
    key: &SigningKey,
    account_id: AccountId,
    rule_id: RuleId,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
) -> RowHmac {
    let mut h = RowHasher::new(key.as_bytes(), ACCOUNT_RULE_BINDING_HMAC_CTX);
    h.uuid(account_id.0)
        .uuid(rule_id.0)
        .datetime_opt(valid_from)
        .datetime_opt(valid_until)
        .finalize()
}

/// Verify the HMAC for an `rbac_account_rules` row.
pub fn verify_account_rule_binding(
    key: &SigningKey,
    account_id: AccountId,
    rule_id: RuleId,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
    expected: &RowHmac,
) -> bool {
    sign_account_rule_binding(key, account_id, rule_id, valid_from, valid_until) == *expected
}

// -- RBAC account -> role binding --

/// Compute the HMAC for an `rbac_account_roles` row.
pub fn sign_account_role_binding(
    key: &SigningKey,
    account_id: AccountId,
    role_id: RoleId,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
) -> RowHmac {
    let mut h = RowHasher::new(key.as_bytes(), ACCOUNT_ROLE_BINDING_HMAC_CTX);
    h.uuid(account_id.0)
        .uuid(role_id.0)
        .datetime_opt(valid_from)
        .datetime_opt(valid_until)
        .finalize()
}

/// Verify the HMAC for an `rbac_account_roles` row.
pub fn verify_account_role_binding(
    key: &SigningKey,
    account_id: AccountId,
    role_id: RoleId,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
    expected: &RowHmac,
) -> bool {
    sign_account_role_binding(key, account_id, role_id, valid_from, valid_until) == *expected
}

// -- RBAC role -> rule association --

/// Compute the HMAC for an `rbac_role_rules` row.
///
/// The PK is (`role_id`, `rule_id`); both are included so that neither can be
/// substituted without invalidating the MAC.
pub fn sign_role_rule(key: &SigningKey, role_id: RoleId, rule_id: RuleId) -> RowHmac {
    let mut h = RowHasher::new(key.as_bytes(), ROLE_RULE_HMAC_CTX);
    h.uuid(role_id.0).uuid(rule_id.0).finalize()
}

/// Verify the HMAC for an `rbac_role_rules` row.
pub fn verify_role_rule(key: &SigningKey, role_id: RoleId, rule_id: RuleId, expected: &RowHmac) -> bool {
    sign_role_rule(key, role_id, rule_id) == *expected
}

// -- Personal Access Token --

/// Compute the HMAC for a `pats` row.
///
/// Covers the fields that control whether and until when the token is valid:
/// `id`, `account_id`, `expires_at`, `purpose`, and `revoked_at`.
/// Extending `expires_at` or clearing `revoked_at` in the DB invalidates the MAC.
pub fn sign_pat(
    key: &SigningKey,
    id: Uuid,
    account_id: AccountId,
    expires_at: DateTime<Utc>,
    purpose: &str,
    revoked_at: Option<DateTime<Utc>>,
) -> RowHmac {
    let mut h = RowHasher::new(key.as_bytes(), PAT_HMAC_CTX);
    h.uuid(id)
        .uuid(account_id.0)
        .datetime_req(expires_at)
        .str_req(purpose)
        .datetime_opt(revoked_at)
        .finalize()
}

/// Verify the HMAC for a `pats` row.
pub fn verify_pat(
    key: &SigningKey,
    id: Uuid,
    account_id: AccountId,
    expires_at: DateTime<Utc>,
    purpose: &str,
    revoked_at: Option<DateTime<Utc>>,
    expected: &RowHmac,
) -> bool {
    sign_pat(key, id, account_id, expires_at, purpose, revoked_at) == *expected
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::keys::SigningKey;
    use crate::global::short_id::ShortId;
    use crate::manager::account::{Account, AccountId, AccountStatus, AccountType};
    use crate::manager::rbac::rule::RuleRow;
    use crate::rbac::{PolicyEffect, RoleId, RuleId, TargetKind};
    use chrono::Utc;
    use hierarkey_core::resources::AccountName;
    use hierarkey_core::Metadata;
    use std::str::FromStr;
    use uuid::Uuid;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32]).unwrap()
    }

    fn other_key() -> SigningKey {
        SigningKey::from_bytes(&[0x99u8; 32]).unwrap()
    }

    fn make_account() -> Account {
        Account {
            id: AccountId(Uuid::now_v7()),
            short_id: ShortId::generate("acc_", 12),
            name: AccountName::from_str("alice").unwrap(),
            account_type: AccountType::User,
            status: AccountStatus::Active,
            status_reason: None,
            locked_until: None,
            status_changed_at: None,
            status_changed_by: None,
            password_hash: Some("$argon2id$v=19$...".to_string()),
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
            metadata: Metadata::new(),
            passphrase_hash: None,
            public_key: None,
            created_by: None,
            created_at: Utc::now(),
            updated_at: None,
            updated_by: None,
            deleted_at: None,
            deleted_by: None,
            row_hmac: None,
        }
    }

    fn make_rule() -> RuleRow {
        let creator = AccountId(Uuid::now_v7());
        RuleRow {
            id: RuleId(Uuid::now_v7()),
            short_id: ShortId::generate("rul_", 12),
            raw_spec: None,
            spec_version: 1,
            effect: PolicyEffect::Allow,
            permission: "secret:reveal".to_string(),
            target_kind: TargetKind::Secret,
            pattern_raw: Some("/prod/**".to_string()),
            condition: None,
            metadata: Metadata::new(),
            created_at: Utc::now(),
            created_by: creator,
            updated_at: None,
            updated_by: None,
            row_hmac: None,
        }
    }

    // -- RowHmac helpers --

    #[test]
    fn row_hmac_hex_roundtrip() {
        let mac = RowHmac([0xABu8; 32]);
        let hex = mac.to_hex();
        assert_eq!(hex.len(), 64);
        let decoded = RowHmac::from_hex(&hex).unwrap();
        assert_eq!(mac, decoded);
    }

    #[test]
    fn row_hmac_from_hex_rejects_bad_length() {
        assert!(RowHmac::from_hex("deadbeef").is_err());
        assert!(RowHmac::from_hex(&"aa".repeat(33)).is_err());
    }

    #[test]
    fn row_hmac_from_hex_rejects_non_hex() {
        assert!(RowHmac::from_hex(&"zz".repeat(32)).is_err());
    }

    // -- Account signing --

    #[test]
    fn account_sign_is_deterministic() {
        let key = test_key();
        let account = make_account();
        assert_eq!(sign_account(&key, &account), sign_account(&key, &account));
    }

    #[test]
    fn account_verify_valid() {
        let key = test_key();
        let account = make_account();
        let mac = sign_account(&key, &account);
        assert!(verify_account(&key, &account, &mac));
    }

    #[test]
    fn account_verify_rejects_wrong_key() {
        let key1 = test_key();
        let key2 = other_key();
        let account = make_account();
        let mac = sign_account(&key1, &account);
        assert!(!verify_account(&key2, &account, &mac));
    }

    #[test]
    fn account_verify_detects_name_change() {
        let key = test_key();
        let mut account = make_account();
        let mac = sign_account(&key, &account);
        account.name = AccountName::from_str("eve").unwrap();
        assert!(!verify_account(&key, &account, &mac));
    }

    #[test]
    fn account_verify_detects_status_change() {
        let key = test_key();
        let mut account = make_account();
        let mac = sign_account(&key, &account);
        account.status = AccountStatus::Disabled;
        assert!(!verify_account(&key, &account, &mac));
    }

    #[test]
    fn account_verify_detects_type_change() {
        let key = test_key();
        let mut account = make_account();
        let mac = sign_account(&key, &account);
        account.account_type = AccountType::System;
        assert!(!verify_account(&key, &account, &mac));
    }

    #[test]
    fn account_verify_detects_password_hash_change() {
        let key = test_key();
        let mut account = make_account();
        let mac = sign_account(&key, &account);
        account.password_hash = Some("$argon2id$changed$...".to_string());
        assert!(!verify_account(&key, &account, &mac));
    }

    #[test]
    fn account_verify_detects_mfa_enable() {
        let key = test_key();
        let mut account = make_account();
        let mac = sign_account(&key, &account);
        account.mfa_enabled = true;
        assert!(!verify_account(&key, &account, &mac));
    }

    #[test]
    fn account_verify_detects_public_key_change() {
        let key = test_key();
        let mut account = make_account();
        let mac = sign_account(&key, &account);
        account.public_key = Some("ed25519:AAAA...".to_string());
        assert!(!verify_account(&key, &account, &mac));
    }

    #[test]
    fn account_different_ids_produce_different_macs() {
        let key = test_key();
        let a1 = make_account();
        let mut a2 = make_account();
        a2.id = AccountId(Uuid::now_v7());
        assert_ne!(sign_account(&key, &a1), sign_account(&key, &a2));
    }

    // -- Rule signing --

    #[test]
    fn rule_sign_is_deterministic() {
        let key = test_key();
        let rule = make_rule();
        assert_eq!(sign_rule(&key, &rule), sign_rule(&key, &rule));
    }

    #[test]
    fn rule_verify_valid() {
        let key = test_key();
        let rule = make_rule();
        let mac = sign_rule(&key, &rule);
        assert!(verify_rule(&key, &rule, &mac));
    }

    #[test]
    fn rule_verify_rejects_wrong_key() {
        let key1 = test_key();
        let key2 = other_key();
        let rule = make_rule();
        let mac = sign_rule(&key1, &rule);
        assert!(!verify_rule(&key2, &rule, &mac));
    }

    #[test]
    fn rule_verify_detects_effect_change() {
        let key = test_key();
        let mut rule = make_rule();
        let mac = sign_rule(&key, &rule);
        rule.effect = PolicyEffect::Deny;
        assert!(!verify_rule(&key, &rule, &mac));
    }

    #[test]
    fn rule_verify_detects_permission_change() {
        let key = test_key();
        let mut rule = make_rule();
        let mac = sign_rule(&key, &rule);
        rule.permission = "platform:admin".to_string();
        assert!(!verify_rule(&key, &rule, &mac));
    }

    #[test]
    fn rule_verify_detects_pattern_change() {
        let key = test_key();
        let mut rule = make_rule();
        let mac = sign_rule(&key, &rule);
        rule.pattern_raw = Some("/prod/secrets/**".to_string());
        assert!(!verify_rule(&key, &rule, &mac));
    }

    #[test]
    fn rule_verify_detects_target_kind_change() {
        let key = test_key();
        let mut rule = make_rule();
        let mac = sign_rule(&key, &rule);
        rule.target_kind = TargetKind::All;
        assert!(!verify_rule(&key, &rule, &mac));
    }

    // -- Binding signing --

    #[test]
    fn account_rule_binding_sign_is_deterministic() {
        let key = test_key();
        let account_id = AccountId(Uuid::now_v7());
        let rule_id = RuleId(Uuid::now_v7());
        let mac1 = sign_account_rule_binding(&key, account_id, rule_id, None, None);
        let mac2 = sign_account_rule_binding(&key, account_id, rule_id, None, None);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn account_rule_binding_verify_valid() {
        let key = test_key();
        let account_id = AccountId(Uuid::now_v7());
        let rule_id = RuleId(Uuid::now_v7());
        let mac = sign_account_rule_binding(&key, account_id, rule_id, None, None);
        assert!(verify_account_rule_binding(&key, account_id, rule_id, None, None, &mac));
    }

    #[test]
    fn account_rule_binding_detects_account_swap() {
        let key = test_key();
        let account_id = AccountId(Uuid::now_v7());
        let other_account = AccountId(Uuid::now_v7());
        let rule_id = RuleId(Uuid::now_v7());
        let mac = sign_account_rule_binding(&key, account_id, rule_id, None, None);
        assert!(!verify_account_rule_binding(&key, other_account, rule_id, None, None, &mac));
    }

    #[test]
    fn account_rule_binding_detects_valid_until_change() {
        let key = test_key();
        let account_id = AccountId(Uuid::now_v7());
        let rule_id = RuleId(Uuid::now_v7());
        let ts = Utc::now();
        let mac = sign_account_rule_binding(&key, account_id, rule_id, None, None);
        assert!(!verify_account_rule_binding(&key, account_id, rule_id, None, Some(ts), &mac));
    }

    #[test]
    fn account_role_binding_sign_is_deterministic() {
        let key = test_key();
        let account_id = AccountId(Uuid::now_v7());
        let role_id = RoleId(Uuid::now_v7());
        let mac1 = sign_account_role_binding(&key, account_id, role_id, None, None);
        let mac2 = sign_account_role_binding(&key, account_id, role_id, None, None);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn account_role_binding_verify_valid() {
        let key = test_key();
        let account_id = AccountId(Uuid::now_v7());
        let role_id = RoleId(Uuid::now_v7());
        let mac = sign_account_role_binding(&key, account_id, role_id, None, None);
        assert!(verify_account_role_binding(&key, account_id, role_id, None, None, &mac));
    }

    #[test]
    fn account_role_binding_detects_role_swap() {
        let key = test_key();
        let account_id = AccountId(Uuid::now_v7());
        let role_id = RoleId(Uuid::now_v7());
        let other_role = RoleId(Uuid::now_v7());
        let mac = sign_account_role_binding(&key, account_id, role_id, None, None);
        assert!(!verify_account_role_binding(&key, account_id, other_role, None, None, &mac));
    }

    // -- Cross-type isolation --
    // Different row types with identical UUIDs must produce different MACs because
    // each type uses a distinct context string.

    #[test]
    fn rule_and_role_binding_with_same_uuids_differ() {
        let key = test_key();
        let shared = Uuid::now_v7();
        let account_id = AccountId(shared);
        let rule_id = RuleId(shared);
        let role_id = RoleId(shared);

        let rule_mac = sign_account_rule_binding(&key, account_id, rule_id, None, None);
        let role_mac = sign_account_role_binding(&key, account_id, role_id, None, None);

        // Distinct context strings guarantee distinct MACs even with identical UUIDs.
        assert_ne!(rule_mac, role_mac);
    }
}
