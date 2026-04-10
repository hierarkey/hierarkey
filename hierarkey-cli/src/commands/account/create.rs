// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::account::describe::print_account_describe;
use crate::commands::account::{AccountCreateArgs, ClapAccountType, ServiceAuthMethod, ServiceEd25519Args};
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use base64::Engine;
use hierarkey_core::api::status::{ApiErrorBody, ApiStatus, Outcome};
use hierarkey_core::error::validation::ValidationError;
use hierarkey_core::parse_labels;
use hierarkey_server::AccountDto;
use hierarkey_server::auth::ed25519::{Ed25519Crypto, Ed25519PrivateKey, Ed25519PublicKey};
use hierarkey_server::global::utils::password::{generate_strong_passphrase, read_password_from_tty};
use hierarkey_server::http_server::handlers::account_response::{CreateAccountRequest, ServiceBootstrap};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const PASSPHRASE_SECTION_TEXT: &str = r#"
----------------------------------------
Generated Service Passphrase:

{passphrase}

This passphrase will not be shown again.
Store it securely before continuing.
----------------------------------------
"#;

const PRIVKEY_SECTION_TEXT: &str = r#"
----------------------------------------
Generated Service Private Key:

{private_key}

This key will not be shown again.
Store it securely before continuing.
----------------------------------------
"#;

pub(crate) const DEFAULT_PASSWORD_LENGTH: usize = 16;
pub(crate) const DEFAULT_PASSPHRASE_LENGTH: usize = 24;

#[derive(Serialize, Deserialize)]
pub struct AccountDtoWithSecret {
    pub account: AccountDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>, // For ed25519 bootstrap
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>, // For passphrase bootstrap
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiResponseWithGeneratedSecret<T> {
    pub status: ApiStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiErrorBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,

    // only present if CLI generated something
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_secret: Option<Zeroizing<String>>,
}

pub fn account_create(client: &ApiClient, cli_args: &CliArgs, args: &AccountCreateArgs) -> CliResult<()> {
    if let Err(e) = args.validate() {
        return Err(CliError::InvalidInput(e));
    }

    match args.r#type {
        ClapAccountType::User => account_create_user(client, cli_args, args),
        ClapAccountType::Service => account_create_service(client, cli_args, args),
    }
}

fn account_create_user(client: &ApiClient, cli_args: &CliArgs, args: &AccountCreateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;
    let labels = parse_labels(args.labels.as_slice());

    let mut generated_secret: Option<Zeroizing<String>> = None;

    let password = if args.generate_password {
        let p = generate_strong_passphrase(DEFAULT_PASSWORD_LENGTH);
        generated_secret = Some(p.clone());
        p
    } else if let Some(s) = args.insecure_password.as_ref() {
        eprintln!(
            "WARNING: --insecure-password supplies the password on the command line. \
             It may be visible in shell history and process listings. \
             Omit the flag to be prompted securely instead."
        );
        Zeroizing::new(s.clone())
    } else {
        let s = read_password_from_tty("Enter password for new user account (hidden):")?;
        let c = read_password_from_tty("Confirm password (hidden):")?;
        if *s != *c {
            return Err(ValidationError::Custom("Passwords do not match".into()).into());
        }
        s
    };

    let req = CreateAccountRequest::User {
        name: args.name.clone(),
        email: args.email.clone(),
        full_name: args.full_name.clone(),
        is_active: args.is_active,
        must_change_password: args.must_change_password,
        description: args.description.clone(),
        labels,
        password,
    };

    let resp = client
        .post("/v1/accounts")
        .bearer_auth(token.as_str())
        .json(&req)
        .send()?;

    let resp_body = client.handle_full_response::<AccountDto>(resp)?;

    if cli_args.output_json {
        if let Some(secret) = generated_secret {
            let data = ApiResponseWithGeneratedSecret {
                status: resp_body.status,
                error: resp_body.error,
                data: resp_body.data,
                generated_secret: Some(secret),
            };
            println!("{}", serde_json::to_string_pretty(&data)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&resp_body)?);
        }
    } else {
        println!("User account created successfully.");
        println!();
        if let Some(account) = resp_body.data {
            print_account_describe(&account);
        }

        if let Some(secret) = generated_secret {
            println!();
            println!("Generated password: {}", *secret);
            println!("Please store this password securely, as it will not be shown again.");
        }
    }

    Ok(())
}

enum GeneratedSecret {
    None,
    Passphrase(Zeroizing<String>),
    PrivKey(Zeroizing<String>),
}

fn account_create_service(client: &ApiClient, cli_args: &CliArgs, args: &AccountCreateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;
    let labels = parse_labels(args.labels.as_slice());

    let mut generated_secret: GeneratedSecret = GeneratedSecret::None;
    let mut print_generated_secret = false;

    let auth = args
        .auth
        .ok_or_else(|| ValidationError::Custom("Service account creation requires --auth option".into()))?;

    let bootstrap = match auth {
        ServiceAuthMethod::Passphrase => {
            if args.passphrase.generate_passphrase && (!cli_args.output_json && !args.passphrase.print_secret_once) {
                return Err(ValidationError::Custom("When using --generate-passphrase for service accounts, provide --print-secret-once or use JSON output to see the generated passphrase".into()).into());
            }

            let passphrase = if args.passphrase.generate_passphrase {
                let s = generate_strong_passphrase(DEFAULT_PASSPHRASE_LENGTH);
                generated_secret = GeneratedSecret::Passphrase(s.clone());
                print_generated_secret = true;
                s
            } else if let Some(s) = args.passphrase.insecure_passphrase.as_ref() {
                Zeroizing::new(s.clone())
            } else {
                // interactive prompt (recommended default)
                let s = read_password_from_tty("Enter passphrase for new service account (hidden):")?;
                let c = read_password_from_tty("Confirm passphrase (hidden):")?;
                if *s != *c {
                    return Err(ValidationError::Custom("Passphrases do not match".into()).into());
                }
                s
            };

            ServiceBootstrap::Passphrase { passphrase }
        }
        ServiceAuthMethod::Ed25519 => {
            let public_key = if args.ed25519.generate_keypair {
                let (priv_key, pub_key) = generate_ed25519_keypair()?;

                let priv_key_pem = priv_key.to_pem().map_err(|_| {
                    CliError::ValidationError(ValidationError::Custom("Failed to encode private key as PEM".into()))
                })?;
                let pub_key_pem = pub_key.to_pem().map_err(|_| {
                    CliError::ValidationError(ValidationError::Custom("Failed to encode public key as PEM".into()))
                })?;

                maybe_persist_private_key(&args.ed25519, &priv_key_pem)?;
                if let Some(path) = args.ed25519.out_public_key.as_ref() {
                    write_file_0600(path, pub_key_pem.as_bytes())?;
                }
                if args.ed25519.print_private_key_once {
                    generated_secret = GeneratedSecret::PrivKey(Zeroizing::new(priv_key_pem));
                    print_generated_secret = true;
                }

                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.to_bytes())
            } else if let Some(pk) = args.ed25519.public_key.as_ref() {
                pk.clone()
            } else if let Some(path) = args.ed25519.public_key_file.as_ref() {
                read_to_string_trimmed(path)?
            } else {
                return Err(ValidationError::Custom(
                    "For ed25519 bootstrap, provide --public-key, --public-key-file, or use --generate-keypair".into(),
                )
                .into());
            };

            ServiceBootstrap::Ed25519 { public_key }
        }
    };

    if args.email.is_some()
        || args.full_name.is_some()
        || args.insecure_password.is_some()
        || args.generate_password
        || args.must_change_password
    {
        return Err(ValidationError::Custom("The options --email, --full-name, --password, --generate-password, and --must-change-password are not valid for service accounts".into()).into());
    }

    let req = CreateAccountRequest::Service {
        name: args.name.clone(),
        is_active: args.is_active,
        description: args.description.clone(),
        labels,
        bootstrap,
    };

    let resp = client
        .post("/v1/accounts")
        .bearer_auth(token.as_str())
        .json(&req)
        .send()?;
    let resp_body = client.handle_full_response::<AccountDto>(resp)?;

    let dto = if resp_body.status.outcome == Outcome::Failure {
        None
    } else {
        resp_body.data.as_ref()
    };

    let Some(dto) = dto else {
        if cli_args.output_json {
            println!("{}", serde_json::to_string_pretty(&resp_body)?);
        } else {
            println!("Failed to create account: {}", resp_body.status.message);
        }
        return Ok(());
    };

    if cli_args.output_json {
        let combined_dto = AccountDtoWithSecret {
            account: dto.clone(),
            passphrase: match generated_secret {
                GeneratedSecret::Passphrase(ref s) => Some(s.to_string()),
                _ => None,
            },
            private_key: match generated_secret {
                GeneratedSecret::PrivKey(ref k) => Some(k.to_string()),
                _ => None,
            },
        };
        println!("{}", serde_json::to_string_pretty(&combined_dto)?);
        return Ok(());
    }

    println!("Service account created successfully.\n");
    print_account_describe(dto);

    if print_generated_secret {
        match generated_secret {
            GeneratedSecret::None => {}
            GeneratedSecret::Passphrase(s) => {
                println!("{}", PASSPHRASE_SECTION_TEXT.replace("{passphrase}", &s));
            }
            GeneratedSecret::PrivKey(s) => {
                println!("{}", PRIVKEY_SECTION_TEXT.replace("{private_key}", &s));
            }
        }
    }
    Ok(())
}

fn read_to_string_trimmed(path: &std::path::Path) -> CliResult<String> {
    let s = std::fs::read_to_string(path)?;
    Ok(s.trim().to_string())
}

fn write_file_0600(path: &std::path::Path, bytes: &[u8]) -> CliResult<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;

    use std::io::Write;
    f.write_all(bytes)?;
    Ok(())
}

fn maybe_persist_private_key(args: &ServiceEd25519Args, priv_key: &str) -> CliResult<()> {
    if let Some(path) = args.out_private_key.as_ref() {
        write_file_0600(path, priv_key.as_bytes())?;
        Ok(())
    } else if args.print_private_key_once {
        // handled by caller for stdout
        Ok(())
    } else {
        Err(ValidationError::Custom(
            "When using ed25519 --generate-keypair, provide --out-private-key or --print-private-key-once".into(),
        )
        .into())
    }
}

fn generate_ed25519_keypair() -> CliResult<(Ed25519PrivateKey, Ed25519PublicKey)> {
    let mut rng = rand::rng();
    Ok(Ed25519Crypto::generate_keypair(&mut rng))
}
