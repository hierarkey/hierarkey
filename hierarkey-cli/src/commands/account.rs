// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use clap::{Args, Parser, Subcommand, ValueEnum};
use hierarkey_core::api::search::time::TimeExpr;
use hierarkey_core::resources::AccountName;
use hierarkey_server::service::account::AccountSortBy;
use hierarkey_server::{AccountStatus, AccountType};
use serde::Serialize;

/// Shared account identifier: supply exactly one of --name or --id.
#[derive(Args, Debug)]
pub struct AccountSelector {
    /// Account name
    #[arg(long, conflicts_with = "id", required_unless_present = "id")]
    pub name: Option<String>,

    /// Account ID (e.g. acc_01JXXXXXXXXXXXXXXXXXXXXXXX)
    #[arg(long, conflicts_with = "name", required_unless_present = "name")]
    pub id: Option<String>,
}

impl AccountSelector {
    /// Returns whichever of --name or --id was supplied.
    pub fn value(&self) -> &str {
        self.name
            .as_deref()
            .or(self.id.as_deref())
            .unwrap_or_else(|| unreachable!("clap requires --name or --id"))
    }
}

pub mod change_password;
pub mod create;
pub mod delete;
pub mod demote;
pub mod describe;
pub mod disable;
pub mod enable;
pub mod federated_identity;
pub mod list_search;
pub mod lock;
pub mod promote;
pub mod set_cert;
pub mod unlock;
pub mod update;

#[derive(Subcommand)]
pub enum AccountCommand {
    /// Create a new user or service account
    Create(AccountCreateArgs),
    /// List all user accounts
    List(AccountListArgs),
    /// Search user accounts
    Search(AccountSearchArgs),
    /// Change password
    #[command(name = "change-password")]
    ChangePw(AccountChangePwArgs),
    /// Show account details and metadata
    Describe(AccountDescribeArgs),
    /// Promote a user account to admin status
    Promote(AccountPromoteArgs),
    /// Demote an admin account to regular user status
    Demote(AccountDemoteArgs),
    /// Lock an account
    Lock(AccountLockArgs),
    /// Unlock an account
    Unlock(AccountUnlockArgs),
    /// Enable account
    Enable(AccountEnableArgs),
    /// Disable account
    Disable(AccountDisableArgs),
    /// Register or remove an mTLS client certificate on a service account (Commercial Edition)
    #[command(name = "set-cert")]
    SetCert(AccountSetCertArgs),
    /// Link a federated identity (OIDC/k8s) to a service account
    #[command(name = "link-federated-identity")]
    LinkFederatedIdentity(AccountLinkFederatedIdentityArgs),
    /// Show the federated identity linked to a service account
    #[command(name = "describe-federated-identity")]
    DescribeFederatedIdentity(AccountDescribeFederatedIdentityArgs),
    /// Remove the federated identity link from a service account
    #[command(name = "unlink-federated-identity")]
    UnlinkFederatedIdentity(AccountUnlinkFederatedIdentityArgs),
    /// Update account profile (email, full name, description, labels)
    Update(AccountUpdateArgs),
    /// Delete an account permanently
    Delete(AccountDeleteArgs),
}

#[derive(Parser, Debug)]
pub struct AccountChangePwArgs {
    /// Account name
    #[arg(long)]
    pub name: AccountName,

    /// Pass a password via arguments (insecure)
    #[arg(
        long,
        help = "INSECURE: Password on command line (visible in process list)",
        conflicts_with = "generate_password",
        allow_hyphen_values = true
    )]
    pub insecure_new_password: Option<String>,

    #[arg(
        long,
        help = "Generate a random password for the new user",
        conflicts_with = "insecure_new_password"
    )]
    pub generate_password: bool,

    /// Require the user to change password at next login
    #[arg(long)]
    pub must_change_password: bool,
}

#[derive(Parser, Debug)]
pub struct AccountDescribeArgs {
    #[command(flatten)]
    pub account: AccountSelector,
}

#[derive(Parser, Debug)]
pub struct AccountPromoteArgs {
    #[command(flatten)]
    pub account: AccountSelector,
}

#[derive(Parser, Debug)]
pub struct AccountDemoteArgs {
    #[command(flatten)]
    pub account: AccountSelector,
}

#[derive(Parser, Debug)]
pub struct AccountLockArgs {
    #[command(flatten)]
    pub account: AccountSelector,

    /// Reason for locking the account
    #[arg(long)]
    pub reason: Option<String>,

    /// Optional unlock date
    #[arg(long)]
    pub locked_until: Option<String>,
}

#[derive(Parser, Debug)]
pub struct AccountUnlockArgs {
    #[command(flatten)]
    pub account: AccountSelector,

    /// Reason for unlocking the account
    #[arg(long)]
    pub reason: Option<String>,
}

#[derive(Debug, Copy, Clone, ValueEnum)]
#[clap(rename_all = "snake_case")]
pub enum ClapAccountType {
    User,
    // System,
    Service,
}

impl std::fmt::Display for ClapAccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c: AccountType = (*self).into();
        write!(f, "{c}")
    }
}

impl From<ClapAccountType> for AccountType {
    fn from(value: ClapAccountType) -> Self {
        match value {
            ClapAccountType::User => AccountType::User,
            ClapAccountType::Service => AccountType::Service,
        }
    }
}

#[derive(Debug, Copy, Clone, ValueEnum)]
#[clap(rename_all = "snake_case")]
pub enum ClapAccountStatus {
    Active,
    Locked,
    Disabled,
    Deleted,
}

impl std::fmt::Display for ClapAccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c: AccountStatus = (*self).into();
        write!(f, "{c}")
    }
}

impl From<ClapAccountStatus> for AccountStatus {
    fn from(value: ClapAccountStatus) -> Self {
        match value {
            ClapAccountStatus::Active => AccountStatus::Active,
            ClapAccountStatus::Locked => AccountStatus::Locked,
            ClapAccountStatus::Disabled => AccountStatus::Disabled,
            ClapAccountStatus::Deleted => AccountStatus::Deleted,
        }
    }
}

#[derive(Parser, Debug)]
pub struct AccountSearchArgs {
    /// Free-text query (matches name, description, etc.)
    ///
    /// Examples:
    ///   --query "build bot"
    ///   --query "svc-"
    #[arg(short = 'q', long)]
    pub query: Option<String>,

    /// Filter by one or more labels (repeatable) in key=value form
    ///
    /// Example:
    ///   --label env=prod --label team=security
    #[arg(long, value_name = "KEY=VALUE", action = clap::ArgAction::Append)]
    pub label: Vec<String>,

    /// Filter by one or more label keys that must exist (repeatable)
    ///
    /// Example:
    ///   --has-label env --has-label team
    #[arg(long, value_name = "KEY", action = clap::ArgAction::Append)]
    pub has_label: Vec<String>,

    /// Filter by one or more types (repeatable)
    ///
    /// Example: --type user --type service
    #[arg(long = "type", value_enum, action = clap::ArgAction::Append)]
    pub account_type: Vec<ClapAccountType>,

    /// Filter by one or more statuses (repeatable)
    ///
    /// Example: --status active --status disabled
    #[arg(long, value_enum, action = clap::ArgAction::Append)]
    pub status: Vec<ClapAccountStatus>,

    /// Include all types (user + admin + service)
    ///
    /// Ignored if --type is provided.
    #[arg(long, conflicts_with_all = ["account_type"])]
    pub all: bool,

    /// Only return accounts created after this timestamp (RFC3339)
    ///
    /// Example: --created-after 2026-01-01T00:00:00Z
    #[arg(long, value_name = "RFC3339")]
    pub created_after: Option<TimeExpr>,

    /// Only return accounts created before this timestamp (RFC3339)
    ///
    /// Example: --created-before 2026-02-01T00:00:00Z
    #[arg(long, value_name = "RFC3339")]
    pub created_before: Option<TimeExpr>,

    /// Sort field
    #[arg(long, value_enum, default_value_t = AccountSortBy::CreatedAt)]
    pub sort_by: AccountSortBy,

    /// Sort descending
    #[arg(long)]
    pub desc: bool,

    /// Limit number of results
    #[arg(short = 'l', long)]
    pub limit: Option<usize>,

    /// Offset for results
    #[arg(short = 'o', long)]
    pub offset: Option<usize>,
}

#[derive(Parser, Debug)]
pub struct AccountListArgs {
    /// Prefix filter for account names
    #[arg(short = 'p', long)]
    pub prefix: Option<String>,

    /// Filter by one or more types (repeatable)
    ///
    /// Example: --type user --type service
    #[arg(long="type", value_enum, action = clap::ArgAction::Append)]
    pub account_type: Vec<ClapAccountType>,

    /// Filter by one or more statuses (repeatable)
    ///
    /// Example: --status active --status disabled
    #[arg(long, value_enum, action = clap::ArgAction::Append)]
    pub status: Vec<ClapAccountStatus>,

    /// Limit number of results
    #[arg(short = 'l', long)]
    pub limit: Option<usize>,

    /// Offset for results
    #[arg(short = 'o', long)]
    pub offset: Option<usize>,

    /// Include all types (user + admin + Service)
    ///
    /// Ignored if --type / --Service / --admin is provided.
    #[arg(long, conflicts_with_all = ["account_type"])]
    pub all: bool,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AccountStatusArg {
    Active,
    Disabled,
    Deleted,
}

impl std::fmt::Display for AccountStatusArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AccountStatusArg::Active => "active",
            AccountStatusArg::Disabled => "disabled",
            AccountStatusArg::Deleted => "deleted",
        };
        write!(f, "{s}")
    }
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AccountTypeArg {
    User,
    System,
    Admin,
    Service,
}

impl std::fmt::Display for AccountTypeArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AccountTypeArg::User => "user",
            AccountTypeArg::System => "system",
            AccountTypeArg::Admin => "admin",
            AccountTypeArg::Service => "service",
        };
        write!(f, "{s}")
    }
}

impl AccountListArgs {
    /// Resolve the effective type filter for the API.
    /// - default => [User]
    /// - --all => [User, Admin, Service, System]
    /// - --type / --admin / --service / --system => exactly those
    pub fn effective_types(&self) -> Vec<String> {
        if self.all {
            return vec![
                AccountTypeArg::User.to_string(),
                AccountTypeArg::Admin.to_string(),
                AccountTypeArg::System.to_string(),
                AccountTypeArg::Service.to_string(),
            ];
        }

        if self.account_type.is_empty() {
            return vec![AccountTypeArg::User.to_string()];
        }

        self.account_type.iter().map(|s| s.to_string()).collect()
    }

    /// Resolve the effective status filter for the API.
    /// - default => [Active]
    /// - --all => [Active, Disabled, Deleted]
    /// - --status / --disabled / --deleted => exactly those
    pub fn effective_statuses(&self) -> Vec<String> {
        if self.all {
            return vec![
                AccountStatusArg::Active.to_string(),
                AccountStatusArg::Disabled.to_string(),
                AccountStatusArg::Deleted.to_string(),
            ];
        }

        if self.status.is_empty() {
            return vec![AccountStatusArg::Active.to_string()];
        }

        self.status.iter().map(|s| s.to_string()).collect()
    }
}

#[derive(Parser, Debug)]
pub struct AccountDisableArgs {
    #[command(flatten)]
    pub account: AccountSelector,

    /// Reason for disabling the account
    #[arg(long)]
    pub reason: Option<String>,
}

#[derive(Parser, Debug)]
pub struct AccountEnableArgs {
    #[command(flatten)]
    pub account: AccountSelector,

    /// Reason for enabling the account
    #[arg(long)]
    pub reason: Option<String>,
}

#[derive(Parser, Debug)]
pub struct AccountCreateArgs {
    /// Account type
    #[arg(long, value_enum)]
    pub r#type: ClapAccountType,

    /// Account name
    #[arg(long)]
    pub name: AccountName,

    /// Activate the account immediately (default: false)
    #[arg(long = "activate")]
    pub is_active: bool,

    /// Optional description for the account
    #[arg(long)]
    pub description: Option<String>,

    /// Labels for the account in key=value form (repeatable)
    #[arg(short = 'l', long = "label")]
    pub labels: Vec<String>,

    // ---- user-only ----
    /// Email address for the account
    #[arg(long, help_heading = "User options")]
    pub email: Option<String>,
    /// Full name for the account
    #[arg(long, help_heading = "User options")]
    pub full_name: Option<String>,
    /// Pass a password via arguments (insecure)
    #[arg(
        long,
        conflicts_with = "generate_password",
        help_heading = "User options",
        allow_hyphen_values = true
    )]
    pub insecure_password: Option<String>,
    /// Generate a random password for the new user
    #[arg(long, conflicts_with = "insecure_password", help_heading = "User options")]
    pub generate_password: bool,
    /// Require the user to change password at next login
    #[arg(long, help_heading = "User options")]
    pub must_change_password: bool,

    // ---- service-only ----
    /// Bootstrap authentication method (service accounts only)
    #[arg(long, value_enum, help_heading = "Service options")]
    pub auth: Option<ServiceAuthMethod>,

    #[command(flatten)]
    pub passphrase: ServicePassphraseArgs,

    #[command(flatten)]
    pub ed25519: ServiceEd25519Args,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum ServiceAuthMethod {
    Passphrase,
    Ed25519,
}

#[derive(Parser, Debug, Clone)]
pub struct ServicePassphraseArgs {
    /// Pass passphrase via args (insecure)
    #[arg(
        long,
        conflicts_with = "generate_passphrase",
        help_heading = "Service passphrase options",
        allow_hyphen_values = true
    )]
    pub insecure_passphrase: Option<String>,

    /// Generate a random passphrase
    #[arg(
        long,
        conflicts_with = "insecure_passphrase",
        help_heading = "Service passphrase options"
    )]
    pub generate_passphrase: bool,

    /// Print the generated passphrase once (stdout)
    #[arg(long, help_heading = "Service passphrase options")]
    pub print_secret_once: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct ServiceEd25519Args {
    /// Provide an existing public key (e.g. base64 or PEM)
    #[arg(long, conflicts_with_all=["public_key_file", "generate_keypair"], help_heading="Service ed25519 options")]
    pub public_key: Option<String>,

    /// Provide an existing public key from file
    #[arg(long, value_name="PATH", conflicts_with_all=["public_key", "generate_keypair"], help_heading="Service ed25519 options")]
    pub public_key_file: Option<std::path::PathBuf>,

    /// Generate a new keypair locally and register the public key
    #[arg(long, conflicts_with_all=["public_key", "public_key_file"], help_heading="Service ed25519 options")]
    pub generate_keypair: bool,

    /// Where to write the private key (required when generating)
    #[arg(long, value_name = "PATH", help_heading = "Service ed25519 options")]
    pub out_private_key: Option<std::path::PathBuf>,

    /// Optional: write public key too
    #[arg(long, value_name = "PATH", help_heading = "Service ed25519 options")]
    pub out_public_key: Option<std::path::PathBuf>,

    /// Print private key once (discouraged; useful for CI bootstrap)
    #[arg(long, help_heading = "Service ed25519 options")]
    pub print_private_key_once: bool,
}

#[derive(Parser, Debug)]
pub struct AccountDeleteArgs {
    #[command(flatten)]
    pub account: AccountSelector,
}

#[derive(Parser, Debug)]
pub struct AccountUpdateArgs {
    #[command(flatten)]
    pub account: AccountSelector,

    /// Email address for the account
    #[arg(long, conflicts_with = "clear_email")]
    pub email: Option<String>,

    /// Clear the email address
    #[arg(long, conflicts_with = "email")]
    pub clear_email: bool,

    /// Full name for the account
    #[arg(long, conflicts_with = "clear_full_name")]
    pub full_name: Option<String>,

    /// Clear the full name
    #[arg(long, conflicts_with = "full_name")]
    pub clear_full_name: bool,

    /// Description in account metadata
    #[arg(long, conflicts_with = "clear_description")]
    pub description: Option<String>,

    /// Clear the description
    #[arg(long, conflicts_with = "description")]
    pub clear_description: bool,

    /// Add or update a label in key=value form (repeatable)
    #[arg(long = "label", value_name = "KEY=VALUE", action = clap::ArgAction::Append)]
    pub label: Vec<String>,

    /// Remove a label by key (repeatable)
    #[arg(long = "remove-label", value_name = "KEY", action = clap::ArgAction::Append)]
    pub remove_label: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct AccountSetCertArgs {
    #[command(flatten)]
    pub account: AccountSelector,

    /// Path to a PEM-encoded X.509 client certificate to register.
    /// Required unless --remove is specified.
    #[arg(long, value_name = "PATH", conflicts_with = "remove")]
    pub cert: Option<std::path::PathBuf>,

    /// Remove the currently registered client certificate from the account.
    #[arg(long, conflicts_with = "cert")]
    pub remove: bool,
}

#[derive(Parser, Debug)]
pub struct AccountLinkFederatedIdentityArgs {
    #[command(flatten)]
    pub account: AccountSelector,

    /// Provider ID (must match an `[[auth.federated]]` id in the server config)
    #[arg(long)]
    pub provider_id: String,

    /// External issuer (e.g. OIDC issuer URL or k8s API server URL)
    #[arg(long)]
    pub external_issuer: String,

    /// External subject (e.g. OIDC `sub` claim or k8s service account name)
    #[arg(long)]
    pub external_subject: String,
}

#[derive(Parser, Debug)]
pub struct AccountDescribeFederatedIdentityArgs {
    #[command(flatten)]
    pub account: AccountSelector,
}

#[derive(Parser, Debug)]
pub struct AccountUnlinkFederatedIdentityArgs {
    #[command(flatten)]
    pub account: AccountSelector,
}

impl AccountCreateArgs {
    // Validate that the combination of flags is consistent with the account type.
    pub fn validate(&self) -> Result<(), String> {
        match self.r#type {
            ClapAccountType::Service => {
                // Service accounts cannot not have these flags
                if self.email.is_some()
                    || self.full_name.is_some()
                    || self.generate_password
                    || self.insecure_password.is_some()
                    || self.must_change_password
                {
                    return Err("User-only flags (--email/--full-name/--generate-password/--insecure-password/--must-change-password) are not allowed with --type service".into());
                }

                let Some(auth) = self.auth else {
                    return Err("Service accounts require --auth <passphrase|ed25519>.".into());
                };

                let used_passphrase_flags = self.passphrase.generate_passphrase
                    || self.passphrase.insecure_passphrase.is_some()
                    || self.passphrase.print_secret_once;

                let used_ed25519_flags = self.ed25519.public_key.is_some()
                    || self.ed25519.public_key_file.is_some()
                    || self.ed25519.generate_keypair
                    || self.ed25519.out_private_key.is_some()
                    || self.ed25519.out_public_key.is_some()
                    || self.ed25519.print_private_key_once;

                match auth {
                    ServiceAuthMethod::Passphrase => {
                        if used_ed25519_flags {
                            return Err("ed25519 flags are not allowed with --auth passphrase.".into());
                        }
                        Ok(())
                    }
                    ServiceAuthMethod::Ed25519 => {
                        if used_passphrase_flags {
                            return Err("passphrase flags are not allowed with --auth ed25519.".into());
                        }

                        // Must either provide an existing public key or generate one.
                        if !self.ed25519.generate_keypair
                            && self.ed25519.public_key.is_none()
                            && self.ed25519.public_key_file.is_none()
                        {
                            return Err("With --auth ed25519, provide --public-key/--public-key-file or use --generate-keypair.".into());
                        }

                        // If generating keypair, require private key output or explicit print-once.
                        if self.ed25519.generate_keypair
                            && self.ed25519.out_private_key.is_none()
                            && !self.ed25519.print_private_key_once
                        {
                            return Err("When using ed25519 --generate-keypair, provide --out-private-key or --print-private-key-once.".into());
                        }

                        Ok(())
                    }
                }
            }

            _ => {
                if self.auth.is_some() {
                    return Err("--auth is only valid with --type service.".into());
                }

                let used_passphrase_flags = self.passphrase.generate_passphrase
                    || self.passphrase.insecure_passphrase.is_some()
                    || self.passphrase.print_secret_once;

                let used_ed25519_flags = self.ed25519.public_key.is_some()
                    || self.ed25519.public_key_file.is_some()
                    || self.ed25519.generate_keypair
                    || self.ed25519.out_private_key.is_some()
                    || self.ed25519.out_public_key.is_some()
                    || self.ed25519.print_private_key_once;

                if used_passphrase_flags || used_ed25519_flags {
                    return Err("Service-only flags are only valid with --type service.".into());
                }

                Ok(())
            }
        }
    }
}
