// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::pat::PatDescribeArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use crate::utils::tabled::{OptionalUtcDate, UtcDate};
use hierarkey_server::PatId;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct PatDescribeResponse {
    id: PatId,
    short_id: String,
    description: String,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    created_by: String,
}

pub fn pat_describe(client: &ApiClient, cli_args: &CliArgs, args: &PatDescribeArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client
        .get(&format!("/v1/pat/{}", urlencoding::encode(&args.id)))
        .bearer_auth(token.as_str())
        .send()?;

    let body: PatDescribeResponse = client.handle_response(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else {
        println!("Personal Access Token details:");
        println!("  ID: {}", body.short_id);
        println!("  Description: {}", body.description);
        println!("  Created by: {}", body.created_by);
        println!("  Created at: {}", UtcDate::from(body.created_at));
        println!("  Expires at: {}", UtcDate::from(body.expires_at));
        println!("  Last used: {}", OptionalUtcDate::from(body.last_used_at));
    }

    Ok(())
}
