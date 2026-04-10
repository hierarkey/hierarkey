// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

#![forbid(unsafe_code)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::dbg_macro)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![cfg_attr(not(test), deny(warnings))]

pub mod api;
pub mod error;
mod labels;
pub mod license;
mod metadata;
pub mod resources;

pub use error::CkError;
pub type CkResult<T> = Result<T, CkError>;

/// Maximum size of a secret (in bytes)
pub const MAX_SECRET_SIZE: usize = 2 * 1024 * 1024; // 2 MiB

pub use labels::Labels;
pub use labels::parse_labels;
pub use labels::validate_labels;
pub use metadata::Metadata;
