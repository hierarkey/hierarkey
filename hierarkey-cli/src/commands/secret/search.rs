// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::secret::SecretSearchArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use chrono::Utc;
use hierarkey_core::api::search::query::{
    AccessFilter, IdentityFilter, LabelFilter, Page, ScopeFilter, SecretSearchRequest, StateFilter, TimeFilter,
    TypeFilter,
};
use hierarkey_server::http_server::handlers::secret_response::{SecretResponse, SecretSearchResponse};
use serde_json::json;
use tabled::settings::Style;
use tabled::{Table, Tabled};

#[derive(Tabled)]
#[tabled(rename_all = "PascalCase")]
pub struct SecretTableEntry {
    sec_ref: String,
    created_at: String,
    length: usize,
    active_revision: String,
    latest_revision: String,
}

impl From<SecretResponse> for SecretTableEntry {
    fn from(secret: SecretResponse) -> Self {
        SecretTableEntry {
            sec_ref: format!("{}:{}", secret.ref_ns, secret.ref_key),
            created_at: secret.created_at.to_rfc3339(),
            length: secret.revisions.last().map_or(0, |r| r.length),
            active_revision: secret.active_revision.to_string(),
            latest_revision: secret.latest_revision.to_string(),
        }
    }
}

pub fn secret_search(client: &ApiClient, cli_args: &CliArgs, args: &SecretSearchArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let secret_search_request = from_args(args);

    let resp = client
        .post("/v1/secrets/search")
        .bearer_auth(token.as_str())
        .json(&json!(secret_search_request))
        .send()?;
    let data = client.handle_response::<SecretSearchResponse>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else if cli_args.output_table {
        // Table output
        let entries = data.entries.into_iter().map(SecretTableEntry::from).collect::<Vec<_>>();

        let mut table = Table::new(&entries);
        table.with(Style::markdown());
        println!("\n{table}\n");
    } else {
        for secret in data.entries {
            println!("{}", secret.ref_ns + ":" + &secret.ref_key);
            println!("  ID: {}", secret.short_id);
            println!("  Status: {}", secret.status);
            println!("  Created At: {}", secret.created_at);
            if let Some(updated_at) = secret.updated_at {
                println!("  Updated At: {updated_at}");
            }
            println!("  Description: {}", secret.description.as_deref().unwrap_or("-"));
            println!("  Labels: {:?}", secret.labels);
            println!("  Active Revision: {}", secret.active_revision);
            println!("  Latest Revision: {}", secret.latest_revision);
            println!("  Revisions:");
            for rev in &secret.revisions {
                let star = if rev.revision == secret.active_revision {
                    "*"
                } else {
                    " "
                };
                println!("    -{} Revision: {}", star, rev.revision);
                println!("      Created At: {}", rev.created_at);
                println!("      Description: {}", rev.description.as_deref().unwrap_or("-"));
                println!("      KEK ID: {}", rev.kek_id);
                println!("      DEK Algorithm: {}", rev.dek_alg);
                println!("      Secret Algorithm: {}", rev.secret_alg);
                println!("      Labels: {:?}", rev.labels);
                println!("      Length: {}", rev.length);
            }
            println!();
        }
    }

    Ok(())
}

fn from_args(args: &SecretSearchArgs) -> SecretSearchRequest {
    let now = Utc::now();

    // --- Scope --------------------------------------------------------------
    let scope = ScopeFilter {
        namespaces: args.namespace.clone(),
        namespace_prefixes: args.namespace_prefix.clone(),
        all_namespaces: args.all_namespaces,
    };

    // --- Identity -----------------------------------------------------------
    let identity = IdentityFilter {
        name: args.name.clone(),
        name_match: None, // CLI currently implies "contains"; keep server default
        id: args.id.clone(),
    };

    // --- Labels -------------------------------------------------------------
    let labels = LabelFilter {
        all: args.label.iter().map(|l| l.to_string()).collect(),
        none: args.label_not.iter().map(|l| l.to_string()).collect(),
    };

    // --- Time filters -------------------------------------------------------
    let time = TimeFilter {
        created_after: args.created_after.as_ref().map(|t| t.resolve(now)),
        created_before: args.created_before.as_ref().map(|t| t.resolve(now)),
        updated_after: args.updated_after.as_ref().map(|t| t.resolve(now)),
        updated_before: args.updated_before.as_ref().map(|t| t.resolve(now)),
    };

    // --- State / hygiene ----------------------------------------------------
    let state = StateFilter {
        status: args.status,
        needs_rotation: args.needs_rotation,
        rotation_policy: args.rotation_policy,
        stale_seconds: args.stale.map(|d| d.as_secs()),
    };

    // --- Access -------------------------------------------------------------
    let access = AccessFilter {
        accessed_after: args.accessed_after.as_ref().map(|t| t.resolve(now)),
        accessed_before: args.accessed_before.as_ref().map(|t| t.resolve(now)),
        never_accessed: args.never_accessed,
    };

    // --- Type ---------------------------------------------------------------
    let r#type = TypeFilter {
        secret_type: args.secret_type,
    };

    // --- Pagination / sorting ----------------------------------------------
    let page = Page {
        sort: args.sort,
        desc: args.desc,
        offset: args.offset.unwrap_or(0) as u32,
        limit: args.limit as u32,
    };

    SecretSearchRequest {
        scope,
        identity,
        labels,
        time,
        state,
        access,
        r#type,
        q: args.q.clone(),
        page,
    }
}
