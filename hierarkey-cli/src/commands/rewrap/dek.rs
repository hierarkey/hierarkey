// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::rewrap::RewrapDekArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use serde::Deserialize;

#[derive(Deserialize)]
struct RewrapDeksResponse {
    rewrapped: usize,
    skipped: usize,
}

pub fn rewrap_dek(client: &ApiClient, cli_args: &CliArgs, args: &RewrapDekArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let namespace = args
        .namespace
        .as_deref()
        .ok_or_else(|| CliError::ConfigError("--namespace <NS> is required (e.g. --namespace /prod)".into()))?;

    // Strip leading slash for URL path parameter
    let ns = namespace.trim_start_matches('/');

    let resp = client
        .post(&format!("/v1/namespaces/{ns}/rewrap-deks"))
        .bearer_auth(token)
        .send()?;

    let data: RewrapDeksResponse = client.handle_response(resp)?;

    if data.rewrapped == 0 && data.skipped == 0 {
        println!("All DEKs in '{namespace}' are already using the active KEK.");
    } else {
        println!("Rewrapped {} DEK revision(s) in '{}'.", data.rewrapped, namespace);
        if data.skipped > 0 {
            println!(
                "Skipped {} revision(s) due to decryption errors (check server logs).",
                data.skipped
            );
        }
    }

    Ok(())
}
