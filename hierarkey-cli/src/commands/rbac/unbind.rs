// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::UnbindCmd;
use crate::error::{CliError, CliResult};
use hierarkey_server::http_server::handlers::rbac::unbind::UnbindRequest;

pub fn rbac_unbind(client: &ApiClient, cli_args: &CliArgs, args: &UnbindCmd) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let label = match args.label {
        Some(ref label) => {
            if let Some((k, v)) = label.split_once('=') {
                Some((k.to_string(), v.to_string()))
            } else {
                return Err(CliError::InvalidInput("Invalid label format. Use key=value.".into()));
            }
        }
        None => None,
    };

    let payload = UnbindRequest {
        account_name: args.name.clone(),
        account_label: label,
        role: args.role.clone(),
        rule_id: args.rule_id.clone(),
    };

    let resp = client
        .post("/v1/rbac/unbind")
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;

    let resp_body = client.handle_response_unit(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else {
        let subject = if let Some(ref label) = args.label {
            format!("Label selector '{label}'")
        } else if let Some(ref name) = args.name {
            format!("Account '{name}'")
        } else {
            "Subject".to_string()
        };

        let target = if let Some(ref role) = args.role {
            format!("role '{role}'")
        } else if let Some(ref rule_id) = args.rule_id {
            format!("rule '{rule_id}'")
        } else {
            "target".to_string()
        };

        println!("{subject} unbound from {target} successfully.");
    }

    Ok(())
}
