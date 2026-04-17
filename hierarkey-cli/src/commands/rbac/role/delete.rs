// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::RoleDeleteArgs;
use crate::error::CliResult;

pub(crate) fn rbac_role_delete(client: &ApiClient, cli_args: &CliArgs, args: &RoleDeleteArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client
        .delete(&format!("/v1/rbac/role/{}", args.name))
        .bearer_auth(token)
        .send()?;
    client.handle_response_unit(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::json!({ "deleted": true, "name": args.name }));
    } else {
        println!("Role '{}' deleted successfully.", args.name);
    }

    Ok(())
}
