// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::auth::AuthRefreshArgs;
use crate::config::SecureToken;
use crate::error::CliResult;
use crate::http::ApiClient;
use crate::utils::formatting::fmt_date;
use hierarkey_server::http_server::handlers::auth_response::AuthResponse;

pub fn auth_refresh(client: &ApiClient, cli_args: &CliArgs, args: &AuthRefreshArgs) -> CliResult<()> {
    let resp = client
        .post("/v1/auth/refresh")
        .bearer_auth(&args.refresh_token)
        .send()?;

    let body = client.handle_response::<AuthResponse>(resp)?;

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
