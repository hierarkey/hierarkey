// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::namespace::NamespaceSearchArgs;
use crate::commands::namespace::list::NamespaceTableEntry;
use crate::error::CliResult;
use crate::http::ApiClient;
use crate::utils::formatting::{clip, fmt_age, fmt_labels};
use hierarkey_server::http_server::handlers::namespace_response::NamespaceSearchResponse;
use std::collections::HashMap;
use tabled::Table;
use tabled::settings::Style;

pub fn namespace_search(client: &ApiClient, cli_args: &CliArgs, args: &NamespaceSearchArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let mut q: HashMap<&str, String> = HashMap::new();
    if let Some(query) = &args.query {
        q.insert("q", query.clone());
    }
    if let Some(limit) = args.limit {
        q.insert("limit", limit.to_string());
    }
    if let Some(offset) = args.offset {
        q.insert("offset", offset.to_string());
    }

    let resp = client
        .get("/v1/namespaces/search")
        .bearer_auth(token)
        .query(&q)
        .send()?;
    let data: NamespaceSearchResponse = client.handle_response(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else if cli_args.output_table {
        let entries = data
            .entries
            .into_iter()
            .map(NamespaceTableEntry::from)
            .collect::<Vec<_>>();

        let mut table = Table::new(&entries);
        table.with(Style::markdown());
        println!("\n{table}\n");
    } else {
        if data.entries.is_empty() {
            println!("No namespaces found matching the criteria.");
        } else {
            println!("{:<16}  {:<20}  {:<8}  {:<12}  AGE", "ID", "NAMESPACE", "STATUS", "LABELS");

            for ns in data.entries {
                println!(
                    "{:<16}  {:<20}  {:<8}  {:<12}  {}",
                    clip(&ns.short_id, 16),
                    clip(ns.namespace.as_str(), 20),
                    clip(&ns.status.to_uppercase(), 8),
                    clip(&fmt_labels(&ns.labels), 12),
                    fmt_age(ns.created_at),
                );
            }
            println!();
        }
        println!("Tip: Use `--table` for more columns, or:");
        println!("  hkey namespace describe --namespace <path>");
    }

    Ok(())
}
