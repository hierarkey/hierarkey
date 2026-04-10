// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::RoleAddArgs;
use crate::commands::rbac::role::create::print_role_with_rules_describe;
use crate::error::CliResult;
use hierarkey_core::api::status::Outcome;
use hierarkey_server::api::v1::dto::rbac::role::RoleWithRulesDto;
use hierarkey_server::http_server::handlers::rbac::role::add::AddRuleToRoleRequest;

pub(crate) fn rbac_role_add(client: &ApiClient, cli_args: &CliArgs, args: &RoleAddArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let payload = AddRuleToRoleRequest {
        rule_id: args.rule_id.clone(),
        spec: args.spec.as_ref().map(|s| s.to_string()),
    };

    let resp = client
        .post(&format!("/v1/rbac/role/{}/rules", args.name))
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;
    let resp_body = client.handle_full_response::<RoleWithRulesDto>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else {
        if resp_body.status.outcome != Outcome::Success {
            println!("Failed to add rule to role: {}", resp_body.status);
            return Ok(());
        }
        if let Some(data) = &resp_body.data {
            println!("Rbac rule added successfully.");
            println!();
            print_role_with_rules_describe(data);
        }
    }

    Ok(())
}
