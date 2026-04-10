// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::RoleCreateArgs;
use crate::error::CliResult;
use crate::utils::formatting::{clip, fmt_bool, fmt_date, fmt_opt_date, fmt_user_ref};
use hierarkey_core::api::status::Outcome;
use hierarkey_server::api::v1::dto::rbac::role::{RoleDto, RoleWithRulesDto};
use hierarkey_server::http_server::handlers::rbac::role::create::CreateRoleRequest;

pub(crate) fn rbac_role_create(client: &ApiClient, cli_args: &CliArgs, args: &RoleCreateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let payload = CreateRoleRequest {
        name: args.name.clone(),
        description: args.description.clone(),
    };

    let resp = client
        .post("/v1/rbac/role")
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;
    let resp_body = client.handle_full_response::<RoleDto>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else {
        if resp_body.status.outcome != Outcome::Success {
            println!("Failed to create role: {}", resp_body.status);
            return Ok(());
        }
        if let Some(data) = &resp_body.data {
            println!("Role created successfully.");
            println!();
            print_role_describe(data);
        }
    }

    Ok(())
}

pub fn print_role_describe(role: &RoleDto) {
    // Identity section (no header)
    println!("  {:<20} {}", "Identifier:", role.id);
    println!("  {:<20} {}", "Name:", role.name);
    println!("  {:<20} {}", "System role:", fmt_bool(role.is_system, "YES", "NO"));

    println!();
    println!("METADATA:");
    println!("  {:<20} {}", "Description:", role.description.as_deref().unwrap_or("-"));
    println!("  {:<20} {}", "Created at:", fmt_date(role.created_at));
    println!("  {:<20} {}", "Created by:", fmt_user_ref(&role.created_by));
    println!("  {:<20} {}", "Updated at:", fmt_opt_date(role.updated_at, "-"));
    if let Some(u) = &role.updated_by {
        println!("  {:<20} {}", "Updated by:", fmt_user_ref(u));
    } else {
        println!("  {:<20} -", "Updated by:");
    }
}

pub fn print_role_with_rules_describe(rwr: &RoleWithRulesDto) {
    // Identity section (no header)
    println!("  {:<20} {}", "Identifier:", &rwr.role.id.to_string());
    println!("  {:<20} {}", "Name:", rwr.role.name);
    println!("  {:<20} {}", "System role:", fmt_bool(rwr.role.is_system, "YES", "NO"));

    println!();
    println!("METADATA:");
    println!("  {:<20} {}", "Description:", rwr.role.description.as_deref().unwrap_or("-"));
    println!("  {:<20} {}", "Created at:", fmt_date(rwr.role.created_at));
    println!("  {:<20} {}", "Created by:", fmt_user_ref(&rwr.role.created_by));
    println!("  {:<20} {}", "Updated at:", fmt_opt_date(rwr.role.updated_at, "-"));
    if let Some(u) = &rwr.role.updated_by {
        println!("  {:<20} {}", "Updated by:", fmt_user_ref(u));
    } else {
        println!("  {:<20} -", "Updated by:");
    }

    // Rules
    println!();
    println!("RULES:            {}", rwr.rules.len());

    if rwr.rules.is_empty() {
        println!("  (none)");
        return;
    }

    // Optional: stable, friendly order
    let mut rules = rwr.rules.clone();
    rules.sort_by(|a, b| {
        a.permission
            .cmp(&b.permission)
            .then(a.effect.cmp(&b.effect))
            .then(a.target.to_string().cmp(&b.target.to_string()))
    });

    println!();
    println!("{:<12}  {:<4}  {:<14}  {:<42}", "ID", "EFF", "PERMISSION", "TARGET");
    println!("{}", "-".repeat(78));

    for r in rules.iter() {
        println!(
            "{:<12}  {:<4}  {:<14}  {:<42}",
            r.id,
            clip(&r.effect.to_uppercase(), 4),
            clip(&r.permission, 14),
            clip(&r.target.to_string(), 42),
        );
    }
}
