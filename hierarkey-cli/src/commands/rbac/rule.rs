// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::rule::create::rbac_rule_create;
use crate::commands::rbac::rule::delete::rbac_rule_delete;
use crate::commands::rbac::rule::describe::rbac_rule_describe;
use crate::commands::rbac::rule::list::rbac_rule_list;
use crate::commands::rbac::{RuleCmd, RuleSubcommand};
use crate::error::CliResult;

mod create;
mod delete;
mod describe;
mod list;

pub fn rbac_rule(client: &ApiClient, cli_args: &CliArgs, cmd: &RuleCmd) -> CliResult<()> {
    match &cmd.cmd {
        RuleSubcommand::Create(args) => rbac_rule_create(client, cli_args, args)?,
        RuleSubcommand::Delete(args) => rbac_rule_delete(client, cli_args, args)?,
        RuleSubcommand::List(args) => rbac_rule_list(client, cli_args, args)?,
        RuleSubcommand::Describe(args) => rbac_rule_describe(client, cli_args, args)?,
    }

    Ok(())
}
