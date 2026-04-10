// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::RoleDeleteArgs;
use crate::error::CliResult;

pub(crate) fn rbac_role_delete(_client: &ApiClient, _cli_args: &CliArgs, args: &RoleDeleteArgs) -> CliResult<()> {
    println!("We're calling the api to delete a role with the following parameters:");
    println!("Name: {}", args.name.clone());
    Ok(())
}
