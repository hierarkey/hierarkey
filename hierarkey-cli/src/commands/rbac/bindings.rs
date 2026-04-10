// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::BindingsCmd;
use crate::error::{CliError, CliResult};
use hierarkey_core::resources::AccountName;
use hierarkey_server::api::v1::dto::rbac::bindings::{AccountBindingsDto, AllBindingsDto};
use hierarkey_server::http_server::handlers::rbac::bindings::BindingsRequest;

pub fn rbac_bindings(client: &ApiClient, cli_args: &CliArgs, args: &BindingsCmd) -> CliResult<()> {
    let token = cli_args.require_token()?;

    if args.all {
        return rbac_bindings_all(client, cli_args, token.as_str());
    }

    let account = match &args.account {
        None => None,
        Some(name) => {
            let account_name = AccountName::try_from(name.as_str())
                .map_err(|e| CliError::InvalidInput(format!("Invalid account name: {e}")))?;
            Some(account_name)
        }
    };

    let payload = BindingsRequest { account };

    let resp = client
        .post("/v1/rbac/bindings")
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;

    let data = client.handle_response::<AccountBindingsDto>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    println!("BINDINGS FOR {}", data.account);
    println!();

    println!("ROLES ({}):", data.roles.len());
    if data.roles.is_empty() {
        println!("  (none)");
    } else {
        for rwr in &data.roles {
            println!("  {:<20} {}", rwr.role.name, rwr.role.id);
            for rule in &rwr.rules {
                println!("    {} {:<28} to {}", rule.effect, rule.permission, rule.target);
            }
            println!();
        }
    }

    println!("DIRECT RULES ({}):", data.rules.len());
    if data.rules.is_empty() {
        println!("  (none)");
    } else {
        for rule in &data.rules {
            println!("  {}  {} {}  to {}", rule.id, rule.effect, rule.permission, rule.target);
        }
    }

    println!();
    println!("Tip: To check a specific permission, run:");
    println!("  hkey rbac explain --account <name>");
    println!("    --permission <perm> --namespace <ns>");

    Ok(())
}

fn rbac_bindings_all(client: &ApiClient, cli_args: &CliArgs, token: &str) -> CliResult<()> {
    let resp = client.post("/v1/rbac/bindings/all").bearer_auth(token).send()?;

    let data = client.handle_response::<AllBindingsDto>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    let col_w = [20usize, 16, 24, 8, 22, 30];
    println!(
        "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}  TARGET",
        "ACCOUNT",
        "ID",
        "DESCRIPTION",
        "EFFECT",
        "PERMISSION",
        w0 = col_w[0],
        w1 = col_w[1],
        w2 = col_w[2],
        w3 = col_w[3],
        w4 = col_w[4],
    );
    println!("{}", "-".repeat(col_w.iter().sum::<usize>() + (col_w.len() - 1) * 2));

    for entry in &data.entries {
        // Rows from role-bound rules
        for rwr in &entry.roles {
            let raw_desc = rwr.role.description.as_deref().unwrap_or(&rwr.role.name);
            let desc = truncate(raw_desc, col_w[2]);
            for rule in &rwr.rules {
                println!(
                    "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}  {}",
                    entry.account,
                    rwr.role.id,
                    desc,
                    rule.effect,
                    rule.permission,
                    rule.target,
                    w0 = col_w[0],
                    w1 = col_w[1],
                    w2 = col_w[2],
                    w3 = col_w[3],
                    w4 = col_w[4],
                );
            }
        }
        // Rows from directly-bound rules
        for rule in &entry.rules {
            let raw_desc = rule.description.as_deref().unwrap_or("-");
            let desc = truncate(raw_desc, col_w[2]);
            println!(
                "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}  {}",
                entry.account,
                rule.id,
                desc,
                rule.effect,
                rule.permission,
                rule.target,
                w0 = col_w[0],
                w1 = col_w[1],
                w2 = col_w[2],
                w3 = col_w[3],
                w4 = col_w[4],
            );
        }
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}
