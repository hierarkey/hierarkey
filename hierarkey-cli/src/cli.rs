// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::commands::account::AccountCommand;
use crate::commands::audit::AuditCommand;
use crate::commands::auth::AuthCommand;
use crate::commands::license::LicenseCommand;
use crate::commands::masterkey::MasterkeyCommand;
use crate::commands::mfa::MfaCommand;
use crate::commands::namespace::NamespaceCommand;
use crate::commands::pat::PatCommand;
use crate::commands::rbac::RbacCommand;
use crate::commands::rekey::RekeyCommand;
use crate::commands::rewrap::RewrapCommand;
use crate::commands::secret::SecretCommand;
use crate::commands::template::TemplateCommand;
use crate::error::{CliError, CliResult};
use clap::{Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser)]
#[command(
    name = "Hierarkey CLI",
    version,
    about = "Secure command-line interface for Hierarkey secret management platform",
    arg_required_else_help = true
)]
pub struct CliArgs {
    /// URL to the Hierarkey API server
    #[arg(long, global = true, env = "HKEY_SERVER_URL", help_heading = "Connection Options")]
    pub server: Option<String>,

    /// API token for authentication
    #[arg(
        long,
        global = true,
        env = "HKEY_ACCESS_TOKEN",
        required = false,
        help_heading = "Connection Options",
        hide_env_values = true
    )]
    pub token: Option<String>,

    /// Accept self-signed TLS certificates
    #[arg(long = "self-signed", global = true, help_heading = "Connection Options")]
    pub self_signed: bool,

    /// Output in JSON format
    #[arg(
        long = "json",
        global = true,
        conflicts_with = "output_table",
        help_heading = "Output Options"
    )]
    pub output_json: bool,

    /// Output in table format (if supported by the command)
    #[arg(
        long = "table",
        global = true,
        conflicts_with = "output_json",
        help_heading = "Output Options"
    )]
    pub output_table: bool,

    /// Enable verbose logging
    #[arg(short = 'v', long = "verbose", global = true, help_heading = "Global Options")]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

impl CliArgs {
    /// Retrieve the API token, returning an error if it's not provided
    pub fn require_token(&self) -> CliResult<String> {
        self.token.clone().ok_or_else(|| {
            CliError::Unauthenticated("API token is required. Provide it via --token or HKEY_ACCESS_TOKEN.".into())
        })
    }

    /// Check if an API token is available
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate shell completion scripts
    Shell {
        #[arg(value_enum)]
        shell: Option<Shell>,
    },

    /// Manage account settings
    #[command(subcommand, alias = "acc", hide_possible_values = true)]
    Account(AccountCommand),

    /// Query and verify the audit log (requires Commercial license)
    #[command(subcommand)]
    Audit(AuditCommand),

    /// Authenticate and manage sessions
    #[command(subcommand)]
    Auth(AuthCommand),

    /// Manage multi-factor authentication (MFA) for your account
    #[command(subcommand)]
    Mfa(MfaCommand),

    /// Create, manage, and retrieve secrets
    #[command(subcommand, alias = "sc", hide_possible_values = true)]
    Secret(Box<SecretCommand>),

    /// Manage namespaces and access controls
    #[command(subcommand, alias = "ns", hide_possible_values = true)]
    Namespace(NamespaceCommand),

    /// Manage personal access tokens
    #[command(subcommand)]
    Pat(PatCommand),

    /// Rotate key encryption keys (KEKs) and re-encrypt data encryption keys
    #[command(subcommand)]
    Rekey(RekeyCommand),

    /// Re-encrypt secrets with new data encryption keys
    #[command(subcommand)]
    Rewrap(RewrapCommand),

    /// Manage master encryption keys
    #[command(subcommand, alias = "mk", hide_possible_values = true)]
    Masterkey(MasterkeyCommand),

    /// Display hierarkey status
    Status,

    /// Show license information and account limits
    #[command(subcommand)]
    License(LicenseCommand),

    /// Manage role-based access control (RBAC) policies and permissions
    #[command(subcommand, hide_possible_values = true)]
    Rbac(RbacCommand),

    /// Render templates by substituting secret references
    #[command(subcommand, alias = "tmpl")]
    Template(TemplateCommand),
}
