// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::role::add::rbac_role_add;
use crate::commands::rbac::role::create::rbac_role_create;
use crate::commands::rbac::role::delete::rbac_role_delete;
use crate::commands::rbac::role::describe::rbac_role_describe;
use crate::commands::rbac::role::list::rbac_role_list;
use crate::commands::rbac::role::update::rbac_role_update;
use crate::commands::rbac::{RoleCmd, RoleSubcommand};
use crate::error::CliResult;

mod add;
mod create;
mod delete;
mod describe;
mod list;
mod update;

pub fn rbac_role(client: &ApiClient, cli_args: &CliArgs, cmd: &RoleCmd) -> CliResult<()> {
    match &cmd.cmd {
        RoleSubcommand::Create(args) => rbac_role_create(client, cli_args, args)?,
        RoleSubcommand::Update(args) => rbac_role_update(client, cli_args, args)?,
        RoleSubcommand::Delete(args) => rbac_role_delete(client, cli_args, args)?,
        RoleSubcommand::List(args) => rbac_role_list(client, cli_args, args)?,
        RoleSubcommand::Describe(args) => rbac_role_describe(client, cli_args, args)?,
        RoleSubcommand::Add(args) => rbac_role_add(client, cli_args, args)?,
    }

    Ok(())
}
