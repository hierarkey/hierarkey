// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct BackupCodesResponse {
    backup_codes: Vec<String>,
}

pub fn mfa_backup_codes(client: &ApiClient, cli_args: &CliArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    if !cli_args.output_json {
        use std::io::{self, Write};
        print!("Regenerating backup codes will invalidate all previous codes. Continue? (y/N): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let resp = client
        .post("/v1/auth/mfa/backup-codes")
        .bearer_auth(token.as_str())
        .send()?;
    let data: BackupCodesResponse = client.handle_response(resp)?;

    if cli_args.output_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "backup_codes": data.backup_codes,
            }))?
        );
    } else {
        println!("New backup codes generated. Previous codes are now invalid.");
        println!();
        println!("Save these backup codes somewhere safe. They will not be shown again.");
        println!();
        for code in &data.backup_codes {
            println!("  {code}");
        }
    }

    Ok(())
}
