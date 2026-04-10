// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::auth::AuthLoginArgs;
use crate::config::SecureToken;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use crate::utils::formatting::{fmt_date, parse_ttl};
use hierarkey_server::global::utils::password::read_password_from_tty;
use hierarkey_server::http_server::handlers::auth_response::AuthScope;
use std::io::Write;
use zeroize::Zeroizing;

pub fn auth_login(client: &ApiClient, cli_args: &CliArgs, args: &AuthLoginArgs) -> CliResult<()> {
    let ttl_minutes = parse_ttl(&args.ttl).map_err(CliError::InvalidInput)?;
    let password = match &args.insecure_password {
        Some(pwd) => {
            eprintln!(
                "WARNING: --insecure-password supplies the password on the command line. \
                 It may be visible in shell history and process listings. \
                 Omit the flag to be prompted securely instead."
            );
            Zeroizing::new(pwd.clone())
        }
        None => read_password_from_tty("Please enter your password (hidden):")?,
    };

    let mut body = client.get_auth_token(&args.name, &password, AuthScope::Auth, "CLI login token", ttl_minutes)?;

    if body.mfa_required {
        let code = if let Some(c) = &args.mfa_code {
            c.clone()
        } else if cli_args.output_json {
            // In JSON mode we can't prompt — output the partial response so the caller can
            // complete the flow with `hkey mfa verify --challenge-token <token> --code <code>`.
            let json_output = serde_json::to_string_pretty(&body)?;
            println!("{json_output}");
            return Err(CliError::Other(
                "MFA required. Complete login with: hkey mfa verify --challenge-token <token> --code <code>".into(),
            ));
        } else {
            eprint!("MFA code: ");
            std::io::stderr().flush().ok();
            let mut code = String::new();
            std::io::stdin()
                .read_line(&mut code)
                .map_err(|e| CliError::Other(format!("Failed to read MFA code: {e}")))?;
            code.trim().to_string()
        };

        body = client.mfa_verify(body.access_token.as_str(), &code, Some(ttl_minutes))?;
    }

    if args.env {
        println!("export HKEY_ACCESS_TOKEN={}", body.access_token.as_str());
        return Ok(());
    }

    if cli_args.output_json {
        let json_output = serde_json::to_string_pretty(&body)?;
        println!("{json_output}");
    } else {
        let now = chrono::Utc::now();
        let duration = body.expires_at.signed_duration_since(now);

        let time_remaining = if duration.num_seconds() > 0 {
            let days = duration.num_days();
            let hours = (duration.num_hours() % 24).abs();
            let minutes = (duration.num_minutes() % 60).abs();
            let seconds = (duration.num_seconds() % 60).abs();

            if days > 0 {
                format!("{days:02}d{hours:02}h{minutes:02}m{seconds:02}s")
            } else if hours > 0 {
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
