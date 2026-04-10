// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::pat::PatCreateArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use crate::utils::formatting::{fmt_date, parse_ttl};
use hierarkey_server::PatId;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct CreatePatRequest {
    description: String,
    ttl_minutes: u32,
}

#[derive(Deserialize, Serialize)]
struct CreatePatResponse {
    id: PatId,
    short_id: String,
    token: String,
    description: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

pub fn pat_create(client: &ApiClient, cli_args: &CliArgs, args: &PatCreateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;
    let ttl_minutes = parse_ttl(&args.ttl).map_err(CliError::InvalidInput)?;

    let payload = CreatePatRequest {
        description: args.description.clone(),
        ttl_minutes,
    };

    let resp = client
        .post("/v1/pat")
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;

    let body: CreatePatResponse = client.handle_response(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else {
        println!("PAT created successfully.");
        println!();
        println!("  {:<20} {}", "ID:", body.short_id);
        println!("  {:<20} {}", "Description:", body.description);
        println!("  {:<20} {}", "Expires:", fmt_date(body.expires_at));
        println!();
        println!("----------------------------------------");
        println!("Generated token:");
        println!();
        println!("{}", body.token);
        println!();
        println!("This token will not be shown again.");
        println!("Store it securely before continuing.");
        println!("----------------------------------------");
    }

    Ok(())
}
