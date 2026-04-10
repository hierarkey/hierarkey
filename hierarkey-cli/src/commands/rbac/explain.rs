// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::ExplainCmd;
use crate::error::{CliError, CliResult};
use hierarkey_core::resources::AccountName;
use hierarkey_server::http_server::handlers::rbac::explain::{ExplainRequest, ExplainResponseDto};

pub fn rbac_explain(client: &ApiClient, cli_args: &CliArgs, args: &ExplainCmd) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let account = AccountName::try_from(args.account.as_str())
        .map_err(|e| CliError::InvalidInput(format!("Invalid account name: {e}")))?;

    if args.namespace.is_none() && args.secret.is_none() {
        return Err(CliError::InvalidInput(
            "Either --namespace or --secret must be specified".into(),
        ));
    }

    let payload = ExplainRequest {
        account,
        permission: args.permission.to_string(),
        namespace: args.namespace.clone(),
        secret: args.secret.clone(),
        verbose: args.near_misses,
    };

    let resp = client
        .post("/v1/rbac/explain")
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;

    let data = client.handle_response::<ExplainResponseDto>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    // Human-readable output
    let resource_desc = args
        .namespace
        .as_deref()
        .map(|ns| format!("namespace {ns}"))
        .or_else(|| args.secret.as_deref().map(|s| format!("secret {s}")))
        .unwrap_or_default();

    let verdict = if data.allowed { "ALLOWED" } else { "DENIED" };
    println!("{:<9} {} on {}", verdict, args.permission, resource_desc);

    if let Some(rule) = &data.matched_rule {
        println!(
            "Matched rule: {}  {} {} to {}",
            rule.id, rule.effect, rule.permission, rule.target
        );
    } else {
        println!("Matched rule: (none)");
    }

    if args.near_misses && !data.near_misses.is_empty() {
        println!("\nNear misses ({}):", data.near_misses.len());
        for nm in &data.near_misses {
            println!(
                "  {}  {} {:<20} to {}  [{}]",
                nm.rule.id, nm.rule.effect, nm.rule.permission, nm.rule.target, nm.reason
            );
        }
    }

    Ok(())
}
