// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::pat::PatListArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use crate::utils::formatting::{clip, fmt_date};
use crate::utils::tabled::display_opt_date;
use hierarkey_server::PatId;
use serde::{Deserialize, Serialize};
use tabled::settings::Style;
use tabled::{Table, Tabled};

#[derive(Deserialize, Serialize)]
struct PatListResponse {
    tokens: Vec<PatItem>,
}

#[derive(Deserialize, Serialize)]
struct PatItem {
    id: PatId,
    short_id: String,
    description: String,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Tabled)]
struct PatTableEntry {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "DESCRIPTION")]
    description: String,
    #[tabled(rename = "EXPIRES")]
    expires: String,
    #[tabled(rename = "LAST USED", display = "display_opt_date")]
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<PatItem> for PatTableEntry {
    fn from(pat: PatItem) -> Self {
        PatTableEntry {
            id: pat.short_id.clone(),
            description: pat.description,
            expires: fmt_date(pat.expires_at),
            last_used_at: pat.last_used_at,
        }
    }
}

pub fn pat_list(client: &ApiClient, cli_args: &CliArgs, _args: &PatListArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client.get("/v1/pat").bearer_auth(token.as_str()).send()?;

    let body: PatListResponse = client.handle_response(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&body.tokens)?);
    } else if cli_args.output_table {
        let entries = body.tokens.into_iter().map(PatTableEntry::from).collect::<Vec<_>>();
        let mut table = Table::new(&entries);
        table.with(Style::markdown());
        println!("\n{table}\n");
    } else {
        if body.tokens.is_empty() {
            println!("No PATs found.");
        } else {
            println!("{:<14}  {:<37}  {:<23}", "ID", "DESCRIPTION", "EXPIRES");

            for pat in body.tokens {
                println!(
                    "{:<14}  {:<37}  {:<23}",
                    clip(&pat.short_id, 14),
                    clip(&pat.description, 37),
                    fmt_date(pat.expires_at),
                );
            }
            println!();
        }
        println!("Tip: Use `--table` for more columns, or:");
        println!("  hkey pat show --id <id>");
    }

    Ok(())
}
