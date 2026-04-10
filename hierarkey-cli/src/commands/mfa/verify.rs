// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::mfa::MfaVerifyArgs;
use crate::config::SecureToken;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use crate::utils::formatting::{fmt_date, parse_ttl};

pub fn mfa_verify(client: &ApiClient, cli_args: &CliArgs, args: &MfaVerifyArgs) -> CliResult<()> {
    let ttl_minutes = args
        .ttl
        .as_deref()
        .map(parse_ttl)
        .transpose()
        .map_err(CliError::InvalidInput)?;
    let body = client.mfa_verify(&args.challenge_token, &args.code, ttl_minutes)?;

    if cli_args.output_json {
        let json_output = serde_json::to_string_pretty(&body)?;
        println!("{json_output}");
    } else {
        let now = chrono::Utc::now();
        let duration = body.expires_at.signed_duration_since(now);

        let time_remaining = if duration.num_seconds() > 0 {
            let hours = duration.num_hours();
            let minutes = (duration.num_minutes() % 60).abs();
            let seconds = (duration.num_seconds() % 60).abs();
            if hours > 0 {
                format!("{hours:02}h{minutes:02}m{seconds:02}s")
            } else if minutes > 0 {
                format!("{minutes:02}m{seconds:02}s")
            } else {
                format!("{seconds:02}s")
            }
        } else {
            "expired".to_string()
        };

        println!("Id       : {}", body.account_short_id);
        println!("Name     : {}", body.account_name);
        println!("Scope    : {}", body.scope);
        println!("Expires  : {} ({})", fmt_date(body.expires_at), time_remaining);
        println!("Access Token  : {}", SecureToken::new(body.access_token.to_string()).as_str());
        println!("Refresh Token : {}", SecureToken::new(body.refresh_token.to_string()).as_str());
    }

    Ok(())
}
