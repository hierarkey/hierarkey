// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::RoleDescribeArgs;
use crate::commands::rbac::role::create::print_role_with_rules_describe;
use crate::error::CliResult;
use hierarkey_server::api::v1::dto::rbac::role::RoleWithRulesDto;

pub(crate) fn rbac_role_describe(client: &ApiClient, cli_args: &CliArgs, args: &RoleDescribeArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client
        .get(&format!("/v1/rbac/role/{}", &args.name))
        .bearer_auth(token.as_str())
        .send()?;
    let data = client.handle_response::<RoleWithRulesDto>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        print_role_with_rules_describe(&data);
    }

    Ok(())
}
