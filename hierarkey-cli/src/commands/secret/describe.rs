// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::secret::SecretDescribeArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use crate::utils::formatting::{fmt_date, fmt_labels, fmt_opt_date, fmt_size};
use hierarkey_core::resources::SecretRef;
use hierarkey_server::http_server::handlers::secret_response::SecretResponse;

pub fn secret_describe(client: &ApiClient, cli_args: &CliArgs, args: &SecretDescribeArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let param = if args.id.is_some() {
        // Short ID — send directly
        args.sec_ref_value().to_string()
    } else {
        // Parse and validate the ref, then URL-encode
        let sec_ref =
            SecretRef::from_string(args.sec_ref_value()).map_err(|e| CliError::InvalidInput(e.to_string()))?;
        urlencoding::encode(&sec_ref.to_string()[1..]).into_owned()
    };

    let resp = client
        .get(&format!("/v1/secrets/{param}"))
        .bearer_auth(token.as_str())
        .send()?;
    let data = client.handle_response::<SecretResponse>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        print_secret_describe(&data);
    }

    Ok(())
}

pub fn print_secret_describe(data: &SecretResponse) {
    // Identity section (no header)
    println!("  {:<20} {}", "Identifier:", data.short_id);
    println!("  {:<20} {}:{}", "Reference:", data.ref_ns, data.ref_key);
    println!("  {:<20} {}", "Status:", data.status.to_uppercase());
    println!("  {:<20} {}", "Latest revision:", data.latest_revision);
    println!("  {:<20} {}", "Active revision:", data.active_revision);

    println!();
    println!("METADATA:");
    println!("  {:<20} {}", "Description:", data.description.as_deref().unwrap_or("-"));
    println!("  {:<20} {}", "Labels:", fmt_labels(&data.labels));
    println!("  {:<20} {}", "Created at:", fmt_date(data.created_at));
    println!("  {:<20} {}", "Created by:", data.created_by.as_deref().unwrap_or("-"));
    println!("  {:<20} {}", "Updated at:", fmt_opt_date(data.updated_at, "-"));
    println!("  {:<20} {}", "Updated by:", data.updated_by.as_deref().unwrap_or("-"));

    // Revision history
    if !data.revisions.is_empty() {
        println!();
        println!("SECRET REVISIONS:");
        println!("  Rev  Created                  Size        Description");

        let mut sorted_revs: Vec<_> = data.revisions.iter().collect();
        sorted_revs.sort_by_key(|r| std::cmp::Reverse(r.revision)); // newest first

        for rev in sorted_revs {
            let star = if rev.revision == data.active_revision { "*" } else { " " };
            let date = fmt_date(rev.created_at);
            let size = fmt_size(rev.length);
            let desc = rev.description.as_deref().unwrap_or("-");

            println!("  {:>3}{} {:<23.23} {:>10}   {}", rev.revision, star, date, size, desc);
        }
    }
}
