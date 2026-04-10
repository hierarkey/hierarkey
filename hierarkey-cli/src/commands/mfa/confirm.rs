// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::mfa::MfaConfirmArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ConfirmResponse {
    backup_codes: Vec<String>,
}

pub fn mfa_confirm(client: &ApiClient, cli_args: &CliArgs, args: &MfaConfirmArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let body = serde_json::json!({ "code": args.code });
    let resp = client
        .post("/v1/auth/mfa/confirm")
        .bearer_auth(token.as_str())
        .json(&body)
        .send()?;
    let data: ConfirmResponse = client.handle_response(resp)?;

    if cli_args.output_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "backup_codes": data.backup_codes,
            }))?
        );
    } else {
        println!("MFA is now enabled.");
        println!();
        println!("Save these backup codes somewhere safe. They will not be shown again.");
        println!();
        for code in &data.backup_codes {
            println!("  {code}");
        }
    }

    Ok(())
}
