// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::account::AccountChangePwArgs;
use crate::commands::account::create::{ApiResponseWithGeneratedSecret, DEFAULT_PASSWORD_LENGTH};
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use hierarkey_core::CkResult;
use hierarkey_core::error::validation::ValidationError;
use hierarkey_server::global::utils::password::{generate_strong_passphrase, read_password_from_tty};
use hierarkey_server::http_server::handlers::auth_response::AuthScope;
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Serialize)]
struct AccountChangePwRequest {
    password: Zeroizing<String>,
}

pub fn account_change_password(client: &ApiClient, cli_args: &CliArgs, args: &AccountChangePwArgs) -> CliResult<()> {
    let mut current_password = None;
    if !cli_args.has_token() {
        // We don't have a token, so we need to ask for the user's password
        current_password = Some(Zeroizing::new(read_password_from_tty("Enter current password (hidden):")?));
    }

    let mut generated = false;
    let new_password = if args.generate_password {
        generated = true;
        generate_strong_passphrase(DEFAULT_PASSWORD_LENGTH)
    } else {
        fetch_password(args.insecure_new_password.clone())?
    };

    // If we have a current password, we need to authenticate and get a token
    let token = if let Some(current_password) = current_password {
        let data = client.get_auth_token(&args.name, &current_password, AuthScope::ChangePassword, "", 60)?;
        if data.access_token.is_empty() {
            return Err(CliError::Unauthenticated("Failed to authenticate with current password".into()));
        }
        data.access_token
    } else {
        Zeroizing::new(cli_args.require_token()?)
    };

    let payload = AccountChangePwRequest {
        password: new_password.clone(),
    };

    let u = urlencoding::encode(args.name.as_str());
    let resp = client
        .post(&format!("/v1/accounts/{u}/password"))
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;
    let resp_body = client.handle_response_unit(resp)?;

    if cli_args.output_json {
        let data = ApiResponseWithGeneratedSecret {
            status: resp_body.status,
            error: resp_body.error,
            data: resp_body.data,
            generated_secret: if generated { Some(new_password) } else { None },
        };
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        println!("Password changed successfully for user '{}'.", args.name);

        if generated {
            println!();
            println!("Generated password: {}", new_password.as_str());
            println!("Please store this password securely, as it will not be shown again.");
        }
    }

    Ok(())
}

fn fetch_password(password: Option<String>) -> CkResult<Zeroizing<String>> {
    let pwd = match password {
        Some(pwd) => Zeroizing::new(pwd),
        None => {
            let password = read_password_from_tty("Enter new password (hidden):")?;
            let password_confirm = read_password_from_tty("Confirm new password (hidden):")?;

            if *password != *password_confirm {
                return Err(ValidationError::Custom("Passwords do not match".into()).into());
            }

            password
        }
    };

    Ok(pwd)
}
