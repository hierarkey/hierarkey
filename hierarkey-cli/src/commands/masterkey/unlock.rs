// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::masterkey::MasterkeyUnlockArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use hierarkey_core::api::status::{ApiCode, Outcome};
use hierarkey_server::global::utils::password::read_password_from_tty;
use hierarkey_server::http_server::handlers::masterkey_response::MasterKeyStatusResponse;
use hierarkey_server::service::masterkey::MasterKeyProviderType;
use std::collections::HashMap;

pub fn masterkey_unlock(client: &ApiClient, cli_args: &CliArgs, args: &MasterkeyUnlockArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    // First, fetch the info from the key.
    let resp = client
        .get(&format!("/v1/masterkeys/{}", args.selector.value()))
        .bearer_auth(token.clone())
        .send()?;
    let mk_entry: MasterKeyStatusResponse = client.handle_response(resp)?;

    if !mk_entry.keyring.locked {
        println!("Masterkey '{}' is already unlocked.", args.selector.value());
        return Ok(());
    }

    let mut data: HashMap<String, String> = HashMap::new();
    match mk_entry.keyring.provider {
        MasterKeyProviderType::Passphrase => {
            match args.passphrase.clone() {
                Some(p) => {
                    data.insert("passphrase".to_string(), p);
                }
                None => {
                    // Check if we need to read the passphrase from stdin
                    if args.passphrase_stdin {
                        use std::io::{self, Read};
                        let mut buffer = String::new();
                        io::stdin().read_to_string(&mut buffer)?;
                        let passphrase = buffer.trim_end().to_string();
                        data.insert("passphrase".to_string(), passphrase);
                    } else {
                        // Otherwise, prompt for it
                        let passphrase = read_password_from_tty(&format!(
                            "Enter passphrase for master key {} ({}) (hidden):",
                            mk_entry.master_key.short_id, mk_entry.master_key.name
                        ))?;
                        // Here the passphrase is outside a Zeroizing, but it's short-lived
                        data.insert("passphrase".to_string(), passphrase.as_str().to_string());
                    }
                }
            }
        }
        MasterKeyProviderType::Insecure => {
            // No need to add additional data
        }
        MasterKeyProviderType::Pkcs11 => {
            let pin = if let Ok(p) = std::env::var("HIERARKEY_HSM_PIN") {
                p
            } else {
                let pin = read_password_from_tty(&format!(
                    "Enter PIN for HSM key {} ({}) (hidden):",
                    mk_entry.master_key.short_id, mk_entry.master_key.name
                ))?;
                pin.as_str().to_string()
            };
            data.insert("pin".to_string(), pin);
        }
    }

    let resp = client
        .post(&format!("/v1/masterkeys/{}/unlock", args.selector.value()))
        .json(&data)
        .bearer_auth(&token)
        .send()?;
    let resp_body = client.handle_response_unit(resp)?;

    if resp_body.status.outcome != Outcome::Success {
        println!(
            "Failed to unlock master key '{}': {}",
            args.selector.value(),
            resp_body.status.message
        );
        return Ok(());
    }

    if resp_body.status.code == ApiCode::MasterKeyAlreadyUnlocked {
        println!("Master key '{}' is already unlocked.", args.selector.value());
        return Ok(());
    }

    println!("Master key '{}' unlocked successfully.", args.selector.value());
    Ok(())
}
