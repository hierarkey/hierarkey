// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::RuleListArgs;
use crate::error::CliResult;
use crate::utils::formatting::clip;
use hierarkey_server::api::v1::dto::rbac::rule::RuleListItemDto;
use hierarkey_server::http_server::handlers::rbac::rule::search::{SearchRuleRequest, SearchRuleResponse};
use tabled::settings::Style;
use tabled::{Table, Tabled};

#[derive(Tabled)]
struct RuleTableEntry {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "EFFECT")]
    effect: String,
    #[tabled(rename = "PERMISSION")]
    permission: String,
    #[tabled(rename = "TARGET")]
    target: String,
    #[tabled(rename = "ROLES")]
    roles: u32,
    #[tabled(rename = "ACCOUNTS")]
    accounts: u32,
}

impl From<RuleListItemDto> for RuleTableEntry {
    fn from(r: RuleListItemDto) -> Self {
        RuleTableEntry {
            id: r.id.to_string(),
            effect: r.effect.to_uppercase(),
            permission: r.permission,
            target: r.target.to_string(),
            roles: r.role_count,
            accounts: r.account_count,
        }
    }
}

pub(crate) fn rbac_rule_list(client: &ApiClient, cli_args: &CliArgs, _args: &RuleListArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let payload = SearchRuleRequest {};

    let resp = client
        .post("/v1/rbac/rule/search")
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;
    let response = client.handle_response::<SearchRuleResponse>(resp)?;
    let data = response.entries;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else if cli_args.output_table {
        let entries = data.into_iter().map(RuleTableEntry::from).collect::<Vec<_>>();
        let mut table = Table::new(&entries);
        table.with(Style::markdown());
        println!("\n{table}\n");
    } else {
        if data.is_empty() {
            println!("No rbac rules found.");
        } else {
            println!(
                "{:<12}  {:<4}  {:<14}  {:<28}  {:>4}  {:>4}",
                "ID", "EFF", "PERMISSION", "TARGET", "ROLE", "ACCT"
            );

            for r in data {
                println!(
                    "{:<12}  {:<4}  {:<14}  {:<28}  {:>4}  {:>4}",
                    clip(&r.id.to_string(), 12),
                    clip(&r.effect.to_uppercase(), 4),
                    clip(&r.permission, 14),
                    clip(&r.target.to_string(), 28),
                    r.role_count,
                    r.account_count
                );
            }
            println!();
        }
        println!("Tip: Use `--table` for more columns, or:");
        println!("  hkey rbac rule describe --id <id>");
    }

    Ok(())
}
