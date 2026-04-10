// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct EnrollResponse {
    secret: String,
    otpauth_url: String,
}

pub fn mfa_enroll(client: &ApiClient, cli_args: &CliArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client.post("/v1/auth/mfa/enroll").bearer_auth(token.as_str()).send()?;
    let data: EnrollResponse = client.handle_response(resp)?;

    if cli_args.output_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "secret": data.secret,
                "otpauth_url": data.otpauth_url,
            }))?
        );
    } else {
        println!("MFA enrollment started.");
        println!();
        println!("  {:<20} {}", "Secret:", data.secret);
        println!("  {:<20} {}", "OTPAuth URL:", data.otpauth_url);
        println!();
        println!("Scan the OTPAuth URL with your authenticator app, then confirm with:");
        println!("  hkey mfa confirm --code <TOTP-CODE>");
    }

    Ok(())
}
