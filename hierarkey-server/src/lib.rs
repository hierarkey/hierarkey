// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

#![forbid(unsafe_code)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::dbg_macro)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::panic))]

/// The version of the hierarkey-server crate, derived from Cargo.toml at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod http_server;
pub mod migrations;
pub mod startup;

pub mod audit_context;
pub mod global;
pub(crate) mod manager;
pub mod service;

pub mod api;
pub mod auth;
pub mod federated;
pub mod preview;
pub mod rbac;
pub mod task_manager;

pub use crate::manager::masterkey::MasterKeyManager;
pub use crate::manager::rbac::RbacManager;
// mod rbac {
//     pub use crate::manager::rbac::{Permission, Resource};
// }
pub use crate::manager::account::{Account, AccountStore};
pub use crate::manager::secret::SecretManager;
pub use crate::manager::token::{PersonalAccessToken, TokenManager};

pub use crate::manager::account::{
    AccountDto, AccountId, AccountManager, AccountRef, AccountStatus, AccountType, DEFAULT_ADMIN_PASSWORD_LENGTH,
    Password,
};
pub use crate::manager::kek::KekEncAlgo;
pub use crate::manager::masterkey::{
    MasterKey, MasterKeyBackend, MasterKeyFileType, MasterKeyStatus, MasterKeyUsage, MasterkeyId,
};
pub use crate::manager::namespace::NamespaceId;
pub use crate::manager::secret::SecretId;
pub use crate::manager::secret::encrypted_data::EncryptedData;
pub use crate::manager::token::PatId;
pub use config::Config;
pub use global::db::create_pool;
pub use global::short_id::ResolveOne;

// Re-exports for the commercial crate to implement provider extensions.
pub use crate::global::keys::{EncryptedKek, NONCE_SIZE, TAG_SIZE};
pub use crate::service::masterkey::ProviderCreateInput;
pub use crate::service::masterkey::backend::pkcs11_store::{Pkcs11Ref, pin_from_unlock_args};
pub use crate::service::masterkey::keyring::UnlockMaterial;
pub use crate::service::masterkey::provider::crypto::{MasterKeyCrypto, MasterKeyCryptoHandle};
pub use crate::service::masterkey::provider::{
    LoadedMaterial, MasterKeyProvider, Pkcs11TokenInfo, StartupDisposition, UnlockArgs,
};

// Utility function to convert a multi-line SQL string into a single line, removing extra whitespace. It makes
// it easier to log or display SQL queries without unnecessary line breaks and indentation.
fn one_line_sql(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
