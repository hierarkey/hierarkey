// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::error::{CliError, CliResult};
use hierarkey_core::resources::SecretRef;

pub mod formatting;
pub mod tabled;

/// Validate that a string is a valid secret reference and return the parsed SecretRef object.
pub fn validate_secret_ref(s: &str) -> CliResult<SecretRef> {
    let sec_ref =
        SecretRef::from_string(s).map_err(|e| CliError::InvalidInput(format!("Invalid key format '{s}': {e}")))?;

    Ok(sec_ref)
}
