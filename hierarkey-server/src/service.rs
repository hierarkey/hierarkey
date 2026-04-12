// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

//! Services that combine the different managers into higher-level functionality. For instance,
//! "delete_namespace" will use the namespace manager, and secret manager to delete both the namespace
//! itself and the secrets within the namespace.

pub mod account;
pub mod audit;
pub mod auth;
pub mod kek;
pub mod license;
pub mod masterkey;
pub mod namespace;
pub mod rbac;
mod secret;
pub mod signing_key_slot;
mod token;

use crate::http_server::api_error::HttpError;
use hierarkey_core::api::status::ApiCode;

pub use account::AccountService;
pub use audit::AuditService;
pub use auth::AuthService;
pub use kek::KekService;
pub use license::LicenseService;
pub use masterkey::MasterKeyService;
pub use namespace::NamespaceService;
pub use rbac::RbacService;
pub use secret::SecretService;
pub use token::TokenService;

/// A trait for errors that can be mapped to HTTP responses in the API layer. This allows us to convert
/// internal errors from the service layer into standardized HTTP error responses with appropriate
/// status codes and messages.
pub trait ApiMappableError: std::error::Error + Send + Sync + 'static {
    fn into_http(self, fail_code: ApiCode) -> HttpError;
}

pub trait ApiMapErr<T> {
    fn api_err(self, fail_code: ApiCode) -> Result<T, HttpError>;
}

impl<T, E> ApiMapErr<T> for Result<T, E>
where
    E: ApiMappableError,
{
    fn api_err(self, fail_code: ApiCode) -> Result<T, HttpError> {
        self.map_err(|e| e.into_http(fail_code))
    }
}
