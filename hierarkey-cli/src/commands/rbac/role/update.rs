// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::RoleUpdateArgs;
use crate::commands::rbac::role::create::print_role_describe;
use crate::error::CliResult;
use hierarkey_server::api::v1::dto::rbac::role::RoleDto;
use hierarkey_server::http_server::handlers::rbac::role::update::UpdateRoleRequest;

pub(crate) fn rbac_role_update(client: &ApiClient, cli_args: &CliArgs, args: &RoleUpdateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let payload = UpdateRoleRequest {
        name: None,
        description: args.description.clone(),
    };

    let resp = client
        .patch(&format!("/v1/rbac/role/{}", args.name))
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;
    let resp_body = client.handle_full_response::<RoleDto>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else {
        println!("Rbac role updated successfully.");
        println!();
        if let Some(role) = resp_body.data {
            print_role_describe(&role);
        }
    }

    Ok(())
}
