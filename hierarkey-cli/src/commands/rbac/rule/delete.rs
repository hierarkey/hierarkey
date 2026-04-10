// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::RuleDeleteArgs;
use crate::error::CliResult;

pub(crate) fn rbac_rule_delete(client: &ApiClient, cli_args: &CliArgs, args: &RuleDeleteArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client
        .delete(&format!("/v1/rbac/rule/{}", args.id))
        .bearer_auth(token.as_str())
        .send()?;

    client.handle_response_unit(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::json!({ "deleted": true, "id": args.id }));
    } else {
        println!("Rule '{}' deleted.", args.id);
    }

    Ok(())
}
