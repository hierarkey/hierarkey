// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::secret::SecretListArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use crate::utils::formatting::{clip, fmt_age, fmt_date, fmt_size};
use crate::utils::tabled::display_labels;
use crate::utils::tabled::display_option;
use hierarkey_core::api::search::query::SecretSearchRequest;
use hierarkey_core::{Labels, resources::Revision};
use hierarkey_server::NamespaceId;
use hierarkey_server::SecretId;
use hierarkey_server::http_server::handlers::secret_response::{SecretResponse, SecretSearchResponse};
use serde_json::json;
use tabled::settings::Style;
use tabled::{Table, Tabled};

#[derive(Tabled)]
#[tabled(rename_all = "PascalCase")]
struct SecretItemEntry {
    #[tabled(skip)]
    _id: SecretId,
    #[tabled(skip)]
    _namespace_id: NamespaceId,
    #[tabled(skip)]
    ref_key: String,
    #[tabled(format("{}:{}", self.ref_ns, self.ref_key), rename = "Reference")]
    ref_ns: String,
    #[tabled(display = "display_uppercase")]
    status: String,
    #[tabled(display = "display_option")]
    description: Option<String>,
    #[tabled(display = "display_labels")]
    labels: Labels,
    secret_type: String,
    #[tabled(rename = "Created At")]
    created_at: String,
    #[tabled(rename = "Updated At", display = "display_option")]
    updated_at: Option<String>,
    #[tabled(skip)]
    active_revision: Option<Revision>,
    #[tabled(skip)]
    latest_revision: Revision,
    #[tabled(display("display_revisions", self), rename = "Act/Lat")]
    revisions: String,
}

impl From<SecretResponse> for SecretItemEntry {
    fn from(secret: SecretResponse) -> Self {
        SecretItemEntry {
            _id: secret.id,
            _namespace_id: secret.namespace_id,
            ref_key: secret.ref_key.clone(),
            ref_ns: secret.ref_ns,
            status: secret.status,
            description: secret.description,
            labels: secret.labels,
            secret_type: secret.secret_type.to_string(),
            created_at: fmt_date(secret.created_at),
            updated_at: secret.updated_at.map(fmt_date),
            active_revision: Some(secret.active_revision),
            latest_revision: secret.latest_revision,
            revisions: String::new(), // Placeholder, will be filled by display_revisions
        }
    }
}

fn display_uppercase(status: &str) -> String {
    status.to_uppercase()
}

fn display_revisions(_: &String, entry: &SecretItemEntry) -> String {
    format!(
        "{}/{}",
        entry
            .active_revision
            .as_ref()
            .map(|r| r.to_string())
            .unwrap_or("-".to_string()),
        entry.latest_revision
    )
}

pub fn secret_list(client: &ApiClient, cli_args: &CliArgs, args: &SecretListArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let mut sr = SecretSearchRequest::default();
    if let Some(namespace) = &args.namespace {
        sr.scope.namespace_prefixes = vec![namespace.to_string()];
    }
    if let Some(limit) = args.limit {
        sr.page.limit = limit as u32;
    }
    if let Some(offset) = args.offset {
        sr.page.offset = offset as u32;
    }

    let resp = client
        .post("/v1/secrets/search")
        .bearer_auth(token.as_str())
        .json(&json!(&sr))
        .send()?;

    let data: SecretSearchResponse = client.handle_response(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else if cli_args.output_table {
        let entries = data
            .entries
            .into_iter()
            .map(SecretItemEntry::from)
            .collect::<Vec<SecretItemEntry>>();

        let mut table = Table::new(&entries);
        table.with(Style::markdown());
        println!("\n{table}\n");
    } else {
        if data.entries.is_empty() {
            println!("No secrets found matching the criteria.");
        } else {
            println!(
                "{:<16}  {:<14}  {:<16}  {:<12}  {:>7}  {:<6}  {:>3}  {:<8}",
                "ID", "NAMESPACE", "REFERENCE", "TYPE", "LEN", "STATUS", "A/L", "AGE",
            );

            for secret in data.entries {
                let len = secret
                    .active_revision_length
                    .map(fmt_size)
                    .unwrap_or_else(|| "-".to_string());

                println!(
                    "{:<16}  {:<14}  {:<16}  {:<12}  {:>7}  {:<6}  {:>3}  {:<8}",
                    clip(&secret.short_id, 16),
                    clip(&secret.ref_ns, 14),
                    clip(&secret.ref_key, 16),
                    clip(&secret.secret_type.to_string(), 12),
                    len,
                    clip(&secret.status.to_uppercase(), 6),
                    format!("{}/{}", secret.active_revision, secret.latest_revision),
                    fmt_age(secret.created_at),
                );
            }
            println!();
        }
        println!("Tip: Use `--table` for more columns, or:");
        println!("  hkey secret describe --ref <ref>");
    }

    Ok(())
}
