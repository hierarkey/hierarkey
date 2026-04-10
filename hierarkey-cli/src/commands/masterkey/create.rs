// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

#![allow(unused)]
use crate::cli::CliArgs;
use crate::commands::masterkey::{MasterkeyCreateArgs, print_describe_masterkey};
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use hierarkey_core::{Labels, parse_labels, validate_labels};
use hierarkey_server::MasterKeyUsage;
use hierarkey_server::global::utils::password::{
    generate_strong_passphrase, read_passphrase_from_user, read_password_from_tty,
};
use hierarkey_server::global::{DEFAULT_PASSPHRASE_LEN, MIN_PASSPHRASE_LEN};
use hierarkey_server::http_server::handlers::masterkey_response::MasterKeyStatusResponse;
use hierarkey_server::service::masterkey::MasterKeyProviderType;
use rand::Rng;
use rand::distr::Alphanumeric;
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Serialize)]
struct ApiRequest {
    name: String,
    description: Option<String>,
    labels: Labels,
    usage: MasterKeyUsage,
    provider: MasterKeyProviderType,
    passphrase: Option<String>,
    pkcs11_key_label: Option<String>,
    pkcs11_slot: Option<u64>,
    pkcs11_token_label: Option<String>,
    pkcs11_pin: Option<String>, // sent to server, never stored in shell history
}

pub fn masterkey_create(client: &ApiClient, cli_args: &CliArgs, args: &MasterkeyCreateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let passphrase = match args.provider {
        MasterKeyProviderType::Passphrase => {
            let passphrase = if let Some(passphrase) = args.passphrase.clone() {
                println!("WARNING: Using insecure passphrase from command line argument.");
                println!("This is not recommended for production use.");
                Zeroizing::from(passphrase)
            } else if args.generate_passphrase {
                let passphrase = generate_strong_passphrase(DEFAULT_PASSPHRASE_LEN);
                println!("----------------------------------------");
                println!("Generated passphrase:");
                println!();
                println!("{}", passphrase.as_str());
                println!();
                println!("This passphrase will not be shown again.");
                println!("Store it securely before continuing.");
                println!("----------------------------------------");
                println!();
                passphrase
            } else {
                read_passphrase_from_user(MIN_PASSPHRASE_LEN).map_err(|e| CliError::InvalidInput(e.to_string()))?
            };

            Some(passphrase)
        }
        _ => None,
    };

    let pkcs11_pin = match args.provider {
        MasterKeyProviderType::Pkcs11 => {
            let pin = if let Ok(p) = std::env::var("HIERARKEY_HSM_PIN") {
                p
            } else {
                let pin = read_password_from_tty("Enter HSM PIN (hidden): ")?;
                pin.as_str().to_string()
            };
            Some(pin)
        }
        _ => None,
    };

    // Parse labels
    validate_labels(&args.labels).map_err(|e| CliError::InvalidInput(e.to_string()))?;

    let data = ApiRequest {
        name: args.name.clone(),
        description: args.description.clone(),
        labels: parse_labels(&args.labels),
        usage: args.key_usage,
        provider: args.provider,
        passphrase: passphrase.map(|p| p.as_str().to_string()),
        pkcs11_key_label: args.pkcs11_key_label.clone(),
        pkcs11_slot: args.pkcs11_slot,
        pkcs11_token_label: args.pkcs11_token_label.clone(),
        pkcs11_pin,
    };

    let resp = client.post("/v1/masterkeys").bearer_auth(token).json(&data).send()?;
    let data: MasterKeyStatusResponse = client.handle_response(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        println!("Masterkey '{}' created successfully.\n", args.name);
        print_describe_masterkey(data);
    }

    Ok(())
}
