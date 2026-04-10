// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::rekey::RekeyKekArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use serde::Deserialize;

#[derive(Deserialize)]
struct KekAssignmentResponse {
    revision: serde_json::Value,
    kek_short_id: String,
    masterkey_short_id: String,
    is_active: bool,
}

pub fn rekey_kek(client: &ApiClient, cli_args: &CliArgs, args: &RekeyKekArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    // Strip leading slash for URL construction (API path param is without leading slash)
    let ns = args.namespace.trim_start_matches('/');

    let resp = client
        .post(&format!("/v1/namespaces/{ns}/rotate-kek"))
        .bearer_auth(token)
        .send()?;

    let data: KekAssignmentResponse = client.handle_response(resp)?;

    println!("New KEK created for namespace '{}'.", args.namespace);
    println!("  KEK ID:     {}", data.kek_short_id);
    println!("  MasterKey:  {}", data.masterkey_short_id);
    println!("  Revision:   {}", data.revision);
    println!("  Active:     {}", if data.is_active { "yes" } else { "no" });

    Ok(())
}
