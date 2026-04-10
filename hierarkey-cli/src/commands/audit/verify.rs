// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::audit::AuditVerifyArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize, Serialize)]
struct ChainVerifyResult {
    valid: bool,
    total_checked: i64,
    first_broken_seq: Option<i64>,
}

pub fn audit_verify(client: &ApiClient, cli_args: &CliArgs, args: &AuditVerifyArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let body = json!({
        "from_seq": args.from_seq,
        "limit": args.limit,
    });

    let resp = client.post("/v1/audit/verify").bearer_auth(token).json(&body).send()?;
    let data: ChainVerifyResult = client.handle_response(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    println!("AUDIT CHAIN VERIFICATION");
    println!(
        "  {:<20} {}",
        "Result:",
        if data.valid {
            "OK - chain intact"
        } else {
            "FAILED - chain broken!"
        }
    );
    println!("  {:<20} {}", "Events checked:", data.total_checked);
    if let Some(seq) = data.first_broken_seq {
        println!("  {:<20} {} (first broken event)", "Broken at seq:", seq);
    }
    println!();

    if !data.valid {
        return Err(crate::error::CliError::Other(
            "Audit chain integrity check FAILED. The log may have been tampered with.".into(),
        ));
    }

    Ok(())
}
