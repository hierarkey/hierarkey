// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use clap::{Args, Parser, Subcommand, ValueEnum};
use hierarkey_core::resources::AccountName;
use serde::{Deserialize, Serialize};

pub mod federated;
pub mod list_providers;
pub mod login;
pub mod refresh;
pub mod sa_token;
pub mod whoami;

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Authenticate with name and password to create a session
    Login(AuthLoginArgs),

    /// Refresh an access token using a refresh token
    Refresh(AuthRefreshArgs),

    /// Display information about the current authenticated user
    Whoami,

    /// Service account operations (e.g. generating tokens with bootstrap auth methods).
    #[command(subcommand)]
    Sa(Box<SaCommand>),

    /// Exchange a federated credential (OIDC JWT / k8s service account token) for a hierarkey token
    Federated(AuthFederatedArgs),

    /// List the federated authentication providers configured on this server
    #[command(name = "list-providers")]
    ListProviders,
}

#[derive(Subcommand, Debug)]
pub enum SaCommand {
    /// Get a service-account access/refresh token using a bootstrap auth method.
    Token(AuthTokenArgs),
}

#[derive(Parser, Debug)]
pub struct AuthLoginArgs {
    /// Account name for login
    #[arg(long)]
    pub name: AccountName,

    /// Pass a password via arguments (insecure)
    #[arg(
        long,
        help = "INSECURE: Password on command line (visible in process list)",
        allow_hyphen_values = true
    )]
    pub insecure_password: Option<String>,

    /// Time-to-live for the authentication token (e.g. 60s, 30m, 2h, 7d)
    #[arg(long, default_value = "1h")]
    pub ttl: String,

    /// MFA TOTP or backup code (if not provided and MFA is required, you will be prompted)
    #[arg(long)]
    pub mfa_code: Option<String>,

    /// Output as an exportable shell variable (eval $(hkey auth login --name admin --env))
    #[arg(long)]
    pub env: bool,
}

#[derive(Parser, Debug)]
pub struct AuthRefreshArgs {
    /// Refresh token (from a previous login or refresh)
    #[arg(long)]
    pub refresh_token: String,
}

/// Get a service-account access/refresh token using a bootstrap auth method.
///
/// Examples:
///   hkey auth sa token --method password --name app1 --password-stdin
///   hkey auth sa token --method mtls --mtls-cert client.crt --mtls-key client.key --mtls-ca ca.crt
///   hkey auth sa token --method keysig --name app1 --key-id sak_... --private-key ./app1_ed25519
#[derive(Parser, Debug)]
pub struct AuthTokenArgs {
    /// Bootstrap authentication method.
    #[arg(long, value_enum)]
    pub method: AuthMethod,

    /// Service account name (e.g. "app1").
    #[arg(long)]
    pub name: Option<String>,

    // /// Optional: request a reduced scope (server will clamp to allowed).
    // #[arg(long)]
    // pub scope: Option<String>,
    //
    // /// Optional: token audience (if your server supports it).
    // #[arg(long)]
    // pub audience: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,

    /// Write token response to a file (permissions should be 0600).
    #[arg(long)]
    pub write: Option<std::path::PathBuf>,

    /// Print only a single field (useful for scripts).
    #[arg(long, value_enum)]
    pub print: Option<PrintField>,

    /// Requested token lifetime (e.g. 60s, 30m, 2h, 7d). Capped to the server-configured maximum.
    #[arg(long)]
    pub ttl: Option<String>,

    /// Method-specific options.
    #[command(flatten)]
    pub auth: AuthMethodArgs,
}

#[derive(Copy, Clone, Debug, ValueEnum, Serialize, Deserialize)]
pub enum AuthMethod {
    Passphrase,
    Mtls,
    Keysig,
}

/// Method-specific argument groups.
///
/// We keep these as optional groups and validate at runtime that the group matches `--method`,
/// because clap doesn't natively "switch" on an enum field without subcommands.
#[derive(Args, Debug, Default)]
pub struct AuthMethodArgs {
    #[command(flatten)]
    pub passphrase: PassphraseArgs,

    #[command(flatten)]
    pub mtls: MtlsArgs,

    #[command(flatten)]
    pub keysig: KeySigArgs,
}

#[derive(Args, Debug, Default)]
pub struct PassphraseArgs {
    /// passphrase
    #[arg(long, help_heading = "Passphrase method options")]
    pub passphrase: Option<String>,

    /// Read passphrase from stdin.
    #[arg(long, conflicts_with_all = ["passphrase", "prompt_passphrase"], help_heading="Passphrase method options")]
    pub passphrase_stdin: bool,

    /// Prompt for passphrase interactively (no echo).
    #[arg(long, conflicts_with_all = ["passphrase", "passphrase_stdin"], help_heading="Passphrase method options")]
    pub prompt_passphrase: bool,
}

#[derive(Args, Debug, Default)]
pub struct MtlsArgs {
    /// Client certificate (PEM).
    #[arg(long, help_heading = "mTLS method options")]
    pub mtls_cert: Option<std::path::PathBuf>,

    /// Client private key (PEM).
    #[arg(long, help_heading = "mTLS method options")]
    pub mtls_key: Option<std::path::PathBuf>,

    /// CA bundle to trust for the server
    #[arg(long, help_heading = "mTLS method options")]
    pub mtls_ca: Option<std::path::PathBuf>,
}

#[derive(Args, Debug, Default)]
pub struct KeySigArgs {
    /// Registered key identifier on the server (e.g. "sak_...").
    #[arg(long, help_heading = "Key signature method options")]
    pub key_id: Option<String>,

    /// Private key path (PEM/ed25519).
    #[arg(long, help_heading = "Key signature method options")]
    pub private_key: Option<std::path::PathBuf>,

    /// Algorithm (default: ed25519).
    #[arg(long, default_value = "ed25519", help_heading = "Key signature method options")]
    pub alg: String,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    Json,
    Env,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum PrintField {
    AccessToken,
    RefreshToken,
    ExpiresIn,
}

#[derive(Parser, Debug)]
pub struct AuthFederatedArgs {
    /// Provider ID (must match an `[[auth.federated]]` id in the server config, e.g. "k8s")
    #[arg(long)]
    pub provider_id: String,

    /// Path to a file containing the credential (e.g. a projected service account token).
    /// Mutually exclusive with --credential.
    #[arg(long, conflicts_with = "credential", value_name = "PATH")]
    pub credential_file: Option<std::path::PathBuf>,

    /// Credential string (e.g. a JWT). Mutually exclusive with --credential-file.
    #[arg(long, conflicts_with = "credential_file")]
    pub credential: Option<String>,

    /// Requested token lifetime (e.g. 60s, 30m, 2h, 7d). Capped to the server-configured maximum.
    #[arg(long)]
    pub ttl: Option<String>,

    /// Output as an exportable shell variable
    #[arg(long)]
    pub env: bool,

    /// Print only a single field (useful for scripts)
    #[arg(long, value_enum)]
    pub print: Option<PrintField>,
}

impl AuthTokenArgs {
    /// Validate that the correct argument group is present for the selected method.
    /// Call this early in your command handler.
    pub fn validate(&self) -> Result<(), String> {
        match self.method {
            AuthMethod::Passphrase => {
                let a = &self.auth.passphrase;
                if self.name.as_deref().unwrap_or("").is_empty() {
                    return Err("--name is required for --method passphrase".into());
                }
                let has_pw = a.passphrase.is_some() || a.passphrase_stdin || a.prompt_passphrase;
                if !has_pw {
                    return Err(
                        "passphrase required: use --passphrase, --passphrase-stdin, or --prompt-passphrase".into(),
                    );
                }
                Ok(())
            }
            AuthMethod::Mtls => {
                // Account optional; cert/key/ca may be optional if using OS store.
                // If user provides any of cert/key/ca, require a consistent set.
                let m = &self.auth.mtls;
                let any = m.mtls_cert.is_some() || m.mtls_key.is_some() || m.mtls_ca.is_some();
                if any && (m.mtls_cert.is_none() || m.mtls_key.is_none()) {
                    return Err("--mtls-cert and --mtls-key are required when using custom mTLS files".into());
                }
                Ok(())
            }
            AuthMethod::Keysig => {
                let k = &self.auth.keysig;
                if self.name.as_deref().unwrap_or("").is_empty() {
                    return Err("--name is required for --method keysig".into());
                }
                if k.key_id.as_deref().unwrap_or("").is_empty() {
                    return Err("--key-id is required for --method keysig".into());
                }
                if k.private_key.is_none() {
                    return Err("--private-key is required for --method keysig".into());
                }
                Ok(())
            }
        }
    }
}
