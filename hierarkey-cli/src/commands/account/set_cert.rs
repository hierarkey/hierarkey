// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::account::AccountSetCertArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use std::io::Read;

pub fn account_set_cert(client: &ApiClient, cli_args: &CliArgs, args: &AccountSetCertArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let cert_pem = if args.remove {
        None
    } else {
        let path = args
            .cert
            .as_ref()
            .ok_or_else(|| CliError::InvalidInput("--cert <path> is required unless --remove is specified".into()))?;

        let file =
            std::fs::File::open(path).map_err(|e| CliError::InvalidInput(format!("failed to open cert file: {e}")))?;
        let mut pem = String::new();
        // 64 KiB is more than enough for any X.509 certificate
        file.take(64 * 1024)
            .read_to_string(&mut pem)
            .map_err(|e| CliError::InvalidInput(format!("failed to read cert file: {e}")))?;
        Some(pem)
    };

    let account = args.account.value();
    let resp = client
        .post(&format!("/v1/accounts/{account}/cert"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "cert_pem": cert_pem }))
        .send()?;
    client.handle_response_unit(resp)?;

    if args.remove {
        println!("Client certificate removed from account '{account}'.");
    } else {
        println!("Client certificate registered on account '{account}'.");
    }

    Ok(())
}
