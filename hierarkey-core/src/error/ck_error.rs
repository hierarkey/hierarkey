// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::error::auth::AuthError;
use crate::error::crypto::CryptoError;
use crate::error::rbac::RbacError;
use crate::error::validation::ValidationError;
use thiserror::Error;

/// The main error type for the application, encompassing various error categories.
#[derive(Debug, Error)]
pub enum CkError {
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("db error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("db: {0}")]
    Database(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("config error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("custom error: {0}")]
    Custom(String),

    #[error("file permission error: {0}")]
    FilePermissions(String),

    #[error("permission denied")]
    PermissionDenied,

    /// Indicates that a resource already exists.
    #[error("resource exists: {kind}: {id}")]
    ResourceExists { kind: &'static str, id: String },

    /// Indicates that a resource was not found.
    #[error("resource does not exists: {kind}: {id}")]
    ResourceNotFound { kind: &'static str, id: String },

    #[error("revision mismatch")]
    RevisionMismatch,

    // --------------------------------------------------------
    #[error("authentication error: {0}")]
    Auth(AuthError),

    #[error("validation error: {0}")]
    Validation(ValidationError),

    #[error("rbac error: {0}")]
    Rbac(RbacError),

    #[error("crypto error: {0}")]
    Crypto(CryptoError),

    #[error("conflict: {what}")]
    Conflict { what: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invariant violated: {what}")]
    InvariantViolation { what: String },

    #[error("masterkey error: {0}")]
    MasterKey(String),

    /// Credentials supplied to unlock/authenticate were incorrect (wrong passphrase, wrong PIN, etc.).
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("file not found: {0}")]
    FileNotFound(String),

    /// Row-level HMAC check failed: the stored MAC does not match the computed one.
    /// This indicates the database row was modified outside the application.
    #[error("row integrity violation: {kind} {id}")]
    RowIntegrityViolation { kind: &'static str, id: String },
}
