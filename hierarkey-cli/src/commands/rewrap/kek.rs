// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::rewrap::RewrapKekArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct RewrapKeksRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kek_id: Option<&'a str>,
}

#[derive(Deserialize)]
struct RewrapKeksResponse {
    rewrapped: usize,
    remaining: usize,
    retired: bool,
}

pub fn rewrap_kek(client: &ApiClient, cli_args: &CliArgs, args: &RewrapKekArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    if args.namespace.is_some() && args.kek_id.is_some() {
        return Err(CliError::ConfigError(
            "Specify at most one of --namespace or --kek-id, not both".into(),
        ));
    }

    let from = args.from.as_deref().ok_or_else(|| {
        CliError::ConfigError("--from <masterkey> is required to specify the draining key to rewrap from".into())
    })?;

    let body = RewrapKeksRequest {
        namespace: args.namespace.as_deref(),
        kek_id: args.kek_id.as_deref(),
    };

    let resp = client
        .post(&format!("/v1/masterkeys/{from}/rewrap-keks"))
        .bearer_auth(token)
        .json(&body)
        .send()?;

    let data: RewrapKeksResponse = client.handle_response(resp)?;

    let scope = match (&args.namespace, &args.kek_id) {
        (Some(ns), _) => format!(" (namespace '{ns}')"),
        (_, Some(id)) => format!(" (kek '{id}')"),
        _ => String::new(),
    };

    if data.rewrapped == 0 {
        println!("No KEKs were wrapped under '{from}'{scope}.");
    } else {
        println!("Rewrapped {} KEK(s) from '{from}'{scope}.", data.rewrapped);
    }

    if data.retired {
        println!("'{from}' has no remaining KEKs and is now retired.");
    } else {
        println!(
            "{} KEK(s) still remain under '{}'. Run again to continue.",
            data.remaining, from
        );
    }

    Ok(())
}
