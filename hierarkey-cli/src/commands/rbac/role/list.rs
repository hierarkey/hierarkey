// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::commands::rbac::RoleListArgs;
use crate::error::CliResult;
use crate::utils::formatting::{clip, fmt_bool};
use crate::utils::tabled::display_option;
use hierarkey_server::api::v1::dto::rbac::role::RoleListItemDto;
use hierarkey_server::http_server::handlers::rbac::role::search::{SearchRoleRequest, SearchRoleResponse};
use tabled::settings::Style;
use tabled::{Table, Tabled};

#[derive(Tabled)]
struct RoleTableEntry {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "SYSTEM")]
    system: String,
    #[tabled(rename = "RULES")]
    rules: u32,
    #[tabled(rename = "DESCRIPTION", display = "display_option")]
    desc: Option<String>,
}

impl From<RoleListItemDto> for RoleTableEntry {
    fn from(role: RoleListItemDto) -> Self {
        RoleTableEntry {
            id: role.id.to_string(),
            name: role.name,
            system: fmt_bool(role.is_system, "YES", "NO"),
            rules: role.role_count,
            desc: role.description,
        }
    }
}

pub(crate) fn rbac_role_list(client: &ApiClient, cli_args: &CliArgs, _args: &RoleListArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let payload = SearchRoleRequest {};

    let resp = client
        .post("/v1/rbac/role/search")
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;
    let response = client.handle_response::<SearchRoleResponse>(resp)?;
    let data = response.entries;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else if cli_args.output_table {
        let entries = data.into_iter().map(RoleTableEntry::from).collect::<Vec<_>>();
        let mut table = Table::new(&entries);
        table.with(Style::markdown());
        println!("\n{table}\n");
    } else {
        if data.is_empty() {
            println!("No rbac roles found.");
        } else {
            println!(
                "{:<12}  {:<18}  {:<3}  {:>5}  {:<28}",
                "ID", "NAME", "SYS", "RULES", "DESCRIPTION"
            );
            for role in data {
                println!(
                    "{:<12}  {:<18}  {:<3}  {:>5}  {:<28}",
                    clip(&role.id.to_string(), 12),
                    clip(&role.name, 18),
                    fmt_bool(role.is_system, "YES", "NO"),
                    role.role_count,
                    clip(&role.description.unwrap_or_default(), 28)
                );
            }
            println!();
        }
        println!("Tip: Use `--table` for more columns, or:");
        println!("  hkey rbac role describe --name <name>");
    }

    Ok(())
}
