// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::auth::{AuthMethod, AuthTokenArgs, OutputFormat, PrintField};
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use crate::utils::formatting::parse_ttl;
use base64::Engine;
use hierarkey_core::resources::AccountName;
use hierarkey_core::{CkError, CkResult};
use hierarkey_server::auth::ed25519::{Ed25519Crypto, Ed25519PrivateKey};
use hierarkey_server::global::utils::password::read_password_from_tty;
use hierarkey_server::http_server::handlers::auth::token::{AuthTokenRequest, KeySigAlgo, SaAuthRequest};
use hierarkey_server::http_server::handlers::auth_response::AuthResponse;
use rand::Rng;
use std::io::Read;
use zeroize::Zeroizing;

pub fn account_sa_token(client: &ApiClient, _cli_args: &CliArgs, args: &AuthTokenArgs) -> CliResult<()> {
    let auth_response = match args.method {
        AuthMethod::Passphrase => auth_passphrase(client, args)?,
        AuthMethod::Keysig => auth_keysig(client, args)?,
        AuthMethod::Mtls => {
            return Err(CliError::Other(
                "mTLS authentication is only available in the Hierarkey Commercial Edition".into(),
            ));
        }
    };

    // Generate the output based on format and optional field selection
    let output = match args.format {
        OutputFormat::Json => match args.print {
            Some(field) => match field {
                PrintField::AccessToken => {
                    serde_json::json!({ "access_token": auth_response.access_token }).to_string()
                }
                PrintField::RefreshToken => {
                    serde_json::json!({ "refresh_token": auth_response.refresh_token }).to_string()
                }
                PrintField::ExpiresIn => serde_json::json!({ "expires_at": auth_response.expires_at }).to_string(),
            },
            None => serde_json::to_string_pretty(&auth_response)?,
        },
        OutputFormat::Env => match args.print {
            Some(field) => match field {
                PrintField::AccessToken => format!("export HKEY_ACCESS_TOKEN={}", auth_response.access_token.as_str()),
                PrintField::RefreshToken => {
                    format!("export HKEY_REFRESH_TOKEN={}", auth_response.refresh_token.as_str())
                }
                PrintField::ExpiresIn => format!("export HKEY_EXPIRES_AT=\"{}\"", auth_response.expires_at),
            },
            None => {
                format!(
                    "export HKEY_ACCESS_TOKEN={}\nexport HKEY_REFRESH_TOKEN={}\nexport HKEY_EXPIRES_AT=\"{}\"",
                    auth_response.access_token.as_str(),
                    auth_response.refresh_token.as_str(),
                    auth_response.expires_at
                )
            }
        },
    };

    // Write to file if requested, otherwise print to stdout
    if let Some(path) = &args.write {
        std::fs::write(path, &output)?;
    } else {
        println!("{output}");
    }

    Ok(())
}

fn read_passphrase_from_stdin() -> CkResult<Zeroizing<String>> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;

    // strip trailing newlines (common with echo/printf)
    while buf.ends_with('\n') || buf.ends_with('\r') {
        buf.pop();
        if buf.ends_with('\r') {
            // in case of \r\n, pop again next loop
        }
    }

    if buf.is_empty() {
        return Err(CkError::Custom("passphrase from stdin was empty".into()));
    }

    Ok(Zeroizing::new(buf))
}

fn auth_passphrase(client: &ApiClient, args: &AuthTokenArgs) -> CliResult<AuthResponse> {
    let Some(ref account_name) = args.name else {
        return Err(CliError::InvalidInput("--name is required for the passphrase method".into()));
    };
    let account = AccountName::try_from(account_name.as_str())
        .map_err(|_| CliError::InvalidInput("invalid account name".into()))?;

    // Check how we want to specify the passphrase
    let mut passphrase = None;
    if let Some(pass) = &args.auth.passphrase.passphrase {
        // Directly from the command line arguments (insecure)
        passphrase = Some(Zeroizing::new(pass.to_string()));
    } else if args.auth.passphrase.passphrase_stdin {
        // Read passphrase from stdin (e.g. echo "mypassword" | hkey auth sa token --method passphrase --account app1 --passphrase-stdin)
        let pass = read_passphrase_from_stdin()?;
        passphrase = Some(Zeroizing::new(pass.to_string()));
    } else if args.auth.passphrase.prompt_passphrase {
        // Prompt for passphrase interactively (input will be hidden)
        let pass = read_password_from_tty("Please enter your passphrase (hidden):")?;
        passphrase = Some(Zeroizing::new(pass.to_string()));
    }

    // If passphrase is still None, it means the user didn't provide it in any way, which is an error.
    let Some(passphrase) = passphrase else {
        return Err(CliError::InvalidInput(
            "No passphrase provided for the passphrase method".into(),
        ));
    };

    let ttl_minutes = args
        .ttl
        .as_deref()
        .map(parse_ttl)
        .transpose()
        .map_err(CliError::InvalidInput)?;

    // Create the actual auth request we send to the server
    let data = AuthTokenRequest {
        auth: SaAuthRequest::Passphrase {
            account_name: account.clone(),
            passphrase: passphrase.clone(),
        },
        scope: None,
        audience: None,
        ttl_minutes,
    };

    let resp = client.post("/v1/auth/service-account/token").json(&data).send()?;

    client.handle_response::<AuthResponse>(resp)
}

fn auth_keysig(client: &ApiClient, args: &AuthTokenArgs) -> CliResult<AuthResponse> {
    let Some(ref account) = args.name else {
        return Err(CliError::InvalidInput("--name is required for the keysig method".into()));
    };
    let account_name = AccountName::try_from(account)?;

    let Some(ref priv_key_path) = args.auth.keysig.private_key else {
        return Err(CliError::InvalidInput("--private-key is required for the keysig method".into()));
    };

    if args.auth.keysig.alg != "ed25519" {
        return Err(CliError::InvalidInput("--alg must be ed25519 for the keysig method".into()));
    }

    // Read key file. Make sure the file is not too large to prevent DoS (e.g. accidentally
    // pointing to a big file); 10KB should be more than enough for an ed25519 key.
    let key_file = std::fs::File::open(priv_key_path)?;
    let mut key_data = Vec::new();
    key_file.take(10 * 1024).read_to_end(&mut key_data)?;
    let key_str =
        String::from_utf8(key_data).map_err(|_| CkError::Custom("private key file is not valid UTF-8".into()))?;

    // Convert it to an ed25519 private key struct.
    let priv_key = Ed25519PrivateKey::from_pem(&key_str)
        .map_err(|e| CkError::Custom(format!("failed to parse private key: {e}")))?;

    let ts_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CkError::Custom("system time is before UNIX_EPOCH".into()))?
        .as_secs();

    let mut bytes = [0u8; 32]; // 256-bit nonce
    rand::rng().fill_bytes(&mut bytes);
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    // Note: account_name is user input, but we sanitized it into an AccountName, meaning it cannot contain any special characters that would allow for injection attacks. Still
    let msg = format!(
        "hierarkey.sa_auth.v1|purpose:{}|method:{}|audience:{}|account:{}|ts:{}|nonce:{}",
        "auth_token", "POST", "hierarkey-server", account_name, ts_epoch, nonce,
    );

    // Sign the msg with the private key
    let signature = Ed25519Crypto::sign(&priv_key, msg.as_bytes());
    let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);

    let ttl_minutes = args
        .ttl
        .as_deref()
        .map(parse_ttl)
        .transpose()
        .map_err(CliError::InvalidInput)?;

    let data = AuthTokenRequest {
        auth: SaAuthRequest::KeySig {
            account_name: account_name.clone(),
            key_id: args.auth.keysig.key_id.clone().unwrap_or_else(|| "default".to_string()),
            alg: KeySigAlgo::Ed25519,
            nonce,
            ts: ts_epoch,
            sig: signature_b64,
        },
        scope: None,
        audience: None,
        ttl_minutes,
    };

    let resp = client.post("/v1/auth/service-account/token").json(&data).send()?;
    client.handle_response::<AuthResponse>(resp)
}
