// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::RuleCreateArgs;
use crate::error::CliResult;
use crate::utils::formatting::{fmt_date, fmt_opt_date, fmt_user_ref};
use hierarkey_core::api::status::Outcome;
use hierarkey_server::api::v1::dto::rbac::rule::RuleDto;
use hierarkey_server::http_server::handlers::rbac::rule::create::CreateRuleRequest;

pub(crate) fn rbac_rule_create(client: &ApiClient, cli_args: &CliArgs, args: &RuleCreateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let payload = CreateRuleRequest {
        spec: args.spec.to_string(),
    };

    let resp = client
        .post("/v1/rbac/rule")
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;
    let resp_body = client.handle_full_response::<RuleDto>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else {
        if resp_body.status.outcome != Outcome::Success {
            println!("Failed to create rbac rule: {}", resp_body.status);
            return Ok(());
        }
        if let Some(data) = &resp_body.data {
            println!("Rule created successfully.");
            println!();
            print_rule_describe(data);
        }
    }

    Ok(())
}

pub fn print_rule_describe(rule: &RuleDto) {
    // Identity section (no header)
    println!("  {:<20} {}", "Identifier:", &rule.id);
    println!("  {:<20} {}", "Effect:", rule.effect.to_uppercase());
    println!("  {:<20} {}", "Permission:", rule.permission);
    println!("  {:<20} {}", "Target:", rule.target);
    println!("  {:<20} {}", "Where:", rule.condition.as_deref().unwrap_or("-"));

    println!();
    println!("METADATA:");
    println!("  {:<20} {}", "Created at:", fmt_date(rule.created_at));
    println!("  {:<20} {}", "Created by:", fmt_user_ref(&rule.created_by));
    println!("  {:<20} {}", "Updated at:", fmt_opt_date(rule.updated_at, "-"));
    if let Some(u) = &rule.updated_by {
        println!("  {:<20} {}", "Updated by:", fmt_user_ref(u));
    } else {
        println!("  {:<20} -", "Updated by:");
    }
}
