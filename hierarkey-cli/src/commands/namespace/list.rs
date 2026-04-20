// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::namespace::NamespaceListArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use crate::utils::formatting::{clip, fmt_age, fmt_date, fmt_labels};
use crate::utils::tabled::display_labels;
use crate::utils::tabled::display_opt_date;
use crate::utils::tabled::display_option;
use hierarkey_core::{Labels, resources::Revision};
use hierarkey_server::http_server::handlers::namespace_response::{NamespaceResponse, NamespaceSearchResponse};
use serde_json::json;
use tabled::settings::Style;
use tabled::{Table, Tabled};

#[derive(Tabled)]
#[tabled(rename_all = "PascalCase")]
pub struct NamespaceTableEntry {
    namespace: String,
    status: String,
    #[tabled(rename = "Secrets")]
    secrets_total: usize,
    #[tabled(display = "display_option")]
    description: Option<String>,
    #[tabled(display = "display_labels")]
    labels: Labels,
    #[tabled(rename = "Created At")]
    created_at: String,
    #[tabled(rename = "Updated At", display = "display_opt_date")]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
    #[tabled(skip)]
    active_kek_revision: Option<Revision>,
    #[tabled(skip)]
    latest_kek_revision: Revision,
    #[tabled(display("display_revisions", self), rename = "KEK Act/Lat")]
    kek_revisions: String,
}

fn display_revisions(_: &String, entry: &NamespaceTableEntry) -> String {
    format!(
        "{}/{}",
        entry
            .active_kek_revision
            .as_ref()
            .map(|r| r.to_string())
            .unwrap_or("-".to_string()),
        entry.latest_kek_revision
    )
}

impl From<NamespaceResponse> for NamespaceTableEntry {
    fn from(ns: NamespaceResponse) -> Self {
        NamespaceTableEntry {
            namespace: ns.namespace,
            status: ns.status.to_uppercase(),
            secrets_total: ns.secret_summary.map_or(0, |s| s.total),
            description: ns.description,
            labels: ns.labels,
            created_at: fmt_date(ns.created_at),
            updated_at: ns.updated_at,
            active_kek_revision: ns.active_kek_revision,
            latest_kek_revision: ns.latest_kek_revision,
            kek_revisions: String::new(), // Will be set by display_revisions
        }
    }
}

pub fn namespace_list(client: &ApiClient, cli_args: &CliArgs, args: &NamespaceListArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let mut body = json!({
        "status": args.effective_statuses(),
    });
    if let Some(prefix) = &args.prefix {
        body["q"] = json!(prefix);
    }
    if let Some(limit) = args.limit {
        body["limit"] = json!(limit);
    }
    if let Some(offset) = args.offset {
        body["offset"] = json!(offset);
    }

    let resp = client
        .post("/v1/namespaces/search")
        .bearer_auth(token)
        .json(&body)
        .send()?;
    let data = client.handle_response::<NamespaceSearchResponse>(resp)?;

    if cli_args.output_json {
        // Json output
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else if cli_args.output_table {
        // Table output
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
