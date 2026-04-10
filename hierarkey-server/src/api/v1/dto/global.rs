// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::resources::AccountName;
use serde::{Deserialize, Serialize};

/// Data Transfer Object (DTO) for representing a reference to an Account in the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRefDto {
    /// (Short) Id of the user
    pub account_id: String,
    /// Name of the user
    pub account_name: AccountName,
}
