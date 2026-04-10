// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::RuleDescribeArgs;
use crate::commands::rbac::rule::create::print_rule_describe;
use crate::error::CliResult;
use hierarkey_server::api::v1::dto::rbac::rule::RuleDto;

pub(crate) fn rbac_rule_describe(client: &ApiClient, cli_args: &CliArgs, args: &RuleDescribeArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client
        .get(&format!("/v1/rbac/rule/{}", &args.id))
        .bearer_auth(token.as_str())
        .send()?;
    let data = client.handle_response::<RuleDto>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        print_rule_describe(&data);
    }

    Ok(())
}
