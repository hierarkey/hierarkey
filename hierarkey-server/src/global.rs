// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

pub mod aes_gcm;
pub mod config;
pub mod db;
pub mod keys;
pub mod resource;
pub mod short_id;
pub mod utils;
pub mod uuid_id;

#[cfg(test)]
pub mod test_utils;

/// Timeout settings in seconds
pub const HTTP_REQUEST_BODY_TIMEOUT: u64 = 30;
pub const HTTP_RESPONSE_BODY_TIMEOUT: u64 = 30;
pub const HTTP_GLOBAL_TIMEOUT: u64 = 30;

/// Maximum allowed incoming requests at once
pub const HTTP_CONCURRENCY_LIMIT: usize = 1000;

/// Maximum allowed size for incoming request bodies (5 MB)
pub const HTTP_MAX_BODY_SIZE: usize = 5 * 1024 * 1024;

/// Pagination defaults and limits
pub const DEFAULT_OFFSET_VALUE: usize = 0;
pub const DEFAULT_LIMIT_VALUE: usize = 20;
pub const MAX_LIMIT_VALUE: usize = 500;

/// Minimum password length for account passwords.
pub const MIN_PASSWORD_LEN: usize = 12;

/// Default and minimum passphrase length for master keys.
pub const DEFAULT_PASSPHRASE_LEN: usize = 48;
pub const MIN_PASSPHRASE_LEN: usize = 16;
