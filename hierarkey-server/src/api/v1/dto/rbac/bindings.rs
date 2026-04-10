// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::api::v1::dto::rbac::role::RoleWithRulesDto;
use crate::api::v1::dto::rbac::rule::RuleDto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AccountBindingsDto {
    /// The account for which the bindings are defined.
    pub account: String,
    /// The roles assigned to the account, along with their associated rules.
    pub roles: Vec<RoleWithRulesDto>,
    /// The rules directly assigned to the account, independent of any roles.
    pub rules: Vec<RuleDto>,
}

#[derive(Serialize, Deserialize)]
pub struct AllBindingsDto {
    /// Bindings for every account, in alphabetical order.
    pub entries: Vec<AccountBindingsDto>,
}
