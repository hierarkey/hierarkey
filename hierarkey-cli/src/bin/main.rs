// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use clap::{CommandFactory, Parser};
use clap_complete::{Shell, generate};
use hkey::ApiClient;
use hkey::cli::{CliArgs, Commands};
use hkey::commands::account::{
    AccountCommand,
    change_password::account_change_password,
    create::account_create,
    delete::account_delete,
    demote::account_demote,
    describe::account_describe,
    disable::account_disable,
    enable::account_enable,
    federated_identity::{
        account_describe_federated_identity, account_link_federated_identity, account_unlink_federated_identity,
    },
    list_search::{account_list, account_search},
    lock::account_lock,
    promote::account_promote,
    set_cert::account_set_cert,
    unlock::account_unlock,
    update::account_update,
};
use hkey::commands::audit::{AuditCommand, events::audit_events, verify::audit_verify};
use hkey::commands::auth::{
    AuthCommand, SaCommand, federated::auth_federated, list_providers::auth_list_providers, login::auth_login,
    refresh::auth_refresh, sa_token::account_sa_token, whoami::auth_whoami,
};
use hkey::commands::license::{LicenseCommand, license_remove, license_set, license_status};
use hkey::commands::masterkey::{
    MasterkeyCommand, activate::masterkey_activate, create::masterkey_create, delete::masterkey_delete,
    describe::masterkey_describe, lock::masterkey_lock, pkcs11_tokens::masterkey_pkcs11_tokens,
    status::masterkey_status, unlock::masterkey_unlock,
};
use hkey::commands::mfa::{
    MfaCommand, backup_codes::mfa_backup_codes, confirm::mfa_confirm, disable::mfa_disable, enroll::mfa_enroll,
    verify::mfa_verify,
};
use hkey::commands::namespace::{
    NamespaceCommand, create::namespace_create, delete::namespace_delete, describe::namespace_describe,
    disable::namespace_disable, enable::namespace_enable, list::namespace_list, search::namespace_search,
    update::namespace_update,
};
use hkey::commands::pat::{PatCommand, create::pat_create, list::pat_list, revoke::pat_revoke, show::pat_describe};
use hkey::commands::rbac::{
    RbacCommand, bind::rbac_bind, bindings::rbac_bindings, explain::rbac_explain, role::rbac_role, rule::rbac_rule,
    unbind::rbac_unbind,
};
use hkey::commands::rekey::{RekeyCommand, kek::rekey_kek};
use hkey::commands::rewrap::{RewrapCommand, dek::rewrap_dek, kek::rewrap_kek};
use hkey::commands::secret::{
    SecretCommand, activate::secret_activate, annotate::secret_annotate, create::secret_create, delete::secret_delete,
    describe::secret_describe, disable::secret_disable, enable::secret_enable, list::secret_list,
    restore::secret_restore, reveal::secret_reveal, revise::secret_revise, search::secret_search,
    update::secret_update,
};
use hkey::commands::status::status;
use hkey::commands::template::{TemplateCommand, render::template_render};
use hkey::error::{CliError, CliResult};
use tracing_subscriber::EnvFilter;

fn main() {
    // Parse args manually: help/version go to stdout, errors go to stderr.
    let cli_args = CliArgs::try_parse().unwrap_or_else(|e| {
        use clap::error::ErrorKind;
        match e.kind() {
            ErrorKind::DisplayHelp
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            | ErrorKind::DisplayVersion => {
                print!("{e}");
            }
            _ => {
                eprint!("{e}");
            }
        }
        std::process::exit(e.exit_code());
    });

    if let Err(e) = run(cli_args) {
        eprintln!("{}", e.user_message());
        std::process::exit(e.exit_code());
    }
}

fn run(cli_args: CliArgs) -> CliResult<()> {
    let filter = if cli_args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();

    // Process local commands that do not need any server interaction
    if let Commands::Shell { shell } = &cli_args.command {
        let mut cmd = CliArgs::command();
        let shell = shell.unwrap_or(Shell::Bash);
        generate(shell, &mut cmd, "hkey", &mut std::io::stdout());
        return Ok(());
    }

    let server = get_server_url(&cli_args)?;
    let client = ApiClient::new(server, cli_args.self_signed)?;

    match &cli_args.command {
        Commands::Status => status(&client, &cli_args)?,
        Commands::Audit(cmd) => match cmd {
            AuditCommand::Events(args) => audit_events(&client, &cli_args, args)?,
            AuditCommand::Verify(args) => audit_verify(&client, &cli_args, args)?,
        },
        Commands::License(cmd) => match cmd {
            LicenseCommand::Status => license_status(&client, &cli_args)?,
            LicenseCommand::Set { from_file } => license_set(&client, &cli_args, from_file)?,
            LicenseCommand::Remove => license_remove(&client, &cli_args)?,
        },
        Commands::Account(cmd) => match cmd {
            AccountCommand::Create(args) => account_create(&client, &cli_args, args)?,
            AccountCommand::Describe(args) => account_describe(&client, &cli_args, args)?,
            AccountCommand::List(args) => account_list(&client, &cli_args, args)?,
            AccountCommand::Search(args) => account_search(&client, &cli_args, args)?,
            AccountCommand::ChangePw(args) => account_change_password(&client, &cli_args, args)?,
            AccountCommand::Promote(args) => account_promote(&client, &cli_args, args)?,
            AccountCommand::Demote(args) => account_demote(&client, &cli_args, args)?,
            AccountCommand::Lock(args) => account_lock(&client, &cli_args, args)?,
            AccountCommand::Unlock(args) => account_unlock(&client, &cli_args, args)?,
            AccountCommand::Enable(args) => account_enable(&client, &cli_args, args)?,
            AccountCommand::Disable(args) => account_disable(&client, &cli_args, args)?,
            AccountCommand::SetCert(args) => account_set_cert(&client, &cli_args, args)?,
            AccountCommand::LinkFederatedIdentity(args) => account_link_federated_identity(&client, &cli_args, args)?,
            AccountCommand::DescribeFederatedIdentity(args) => {
                account_describe_federated_identity(&client, &cli_args, args)?
            }
            AccountCommand::UnlinkFederatedIdentity(args) => {
                account_unlink_federated_identity(&client, &cli_args, args)?
            }
            AccountCommand::Update(args) => account_update(&client, &cli_args, args)?,
            AccountCommand::Delete(args) => account_delete(&client, &cli_args, args)?,
        },
        Commands::Auth(cmd) => match cmd {
            AuthCommand::Login(args) => auth_login(&client, &cli_args, args)?,
            AuthCommand::Refresh(args) => auth_refresh(&client, &cli_args, args)?,
            AuthCommand::Whoami => auth_whoami(&client, &cli_args)?,
            AuthCommand::Sa(cmd) => match &**cmd {
                SaCommand::Token(args) => account_sa_token(&client, &cli_args, args)?,
            },
            AuthCommand::Federated(args) => auth_federated(&client, &cli_args, args)?,
            AuthCommand::ListProviders => auth_list_providers(&client, &cli_args)?,
        },
        Commands::Mfa(cmd) => match cmd {
            MfaCommand::Enroll => mfa_enroll(&client, &cli_args)?,
            MfaCommand::Confirm(args) => mfa_confirm(&client, &cli_args, args)?,
            MfaCommand::Disable => mfa_disable(&client, &cli_args)?,
            MfaCommand::BackupCodes => mfa_backup_codes(&client, &cli_args)?,
            MfaCommand::Verify(args) => mfa_verify(&client, &cli_args, args)?,
        },
        Commands::Secret(cmd) => match &**cmd {
            SecretCommand::Create(args) => secret_create(&client, &cli_args, args)?,
            SecretCommand::Reveal(args) => secret_reveal(&client, &cli_args, args)?,
            SecretCommand::Update(args) => secret_update(&client, &cli_args, args)?,
            SecretCommand::Delete(args) => secret_delete(&client, &cli_args, args)?,
            SecretCommand::List(args) => secret_list(&client, &cli_args, args)?,
            SecretCommand::Describe(args) => secret_describe(&client, &cli_args, args)?,
            SecretCommand::Search(args) => secret_search(&client, &cli_args, args)?,
            SecretCommand::Revise(args) => secret_revise(&client, &cli_args, args)?,
            SecretCommand::Annotate(args) => secret_annotate(&client, &cli_args, args)?,
            SecretCommand::Activate(args) => secret_activate(&client, &cli_args, args)?,
            SecretCommand::Enable(args) => secret_enable(&client, &cli_args, args)?,
            SecretCommand::Disable(args) => secret_disable(&client, &cli_args, args)?,
            SecretCommand::Restore(args) => secret_restore(&client, &cli_args, args)?,
        },
        Commands::Namespace(cmd) => match cmd {
            NamespaceCommand::Create(args) => namespace_create(&client, &cli_args, args)?,
            NamespaceCommand::Describe(args) => namespace_describe(&client, &cli_args, args)?,
            NamespaceCommand::Update(args) => namespace_update(&client, &cli_args, args)?,
            NamespaceCommand::Delete(args) => namespace_delete(&client, &cli_args, args)?,
            NamespaceCommand::Disable(args) => namespace_disable(&client, &cli_args, args)?,
            NamespaceCommand::Enable(args) => namespace_enable(&client, &cli_args, args)?,
            NamespaceCommand::List(args) => namespace_list(&client, &cli_args, args)?,
            NamespaceCommand::Search(args) => namespace_search(&client, &cli_args, args)?,
        },
        Commands::Pat(cmd) => match cmd {
            PatCommand::Create(args) => pat_create(&client, &cli_args, args)?,
            PatCommand::List(args) => pat_list(&client, &cli_args, args)?,
            PatCommand::Describe(args) => pat_describe(&client, &cli_args, args)?,
            PatCommand::Revoke(args) => pat_revoke(&client, &cli_args, args)?,
        },
        Commands::Rekey(cmd) => match cmd {
            RekeyCommand::Kek(args) => rekey_kek(&client, &cli_args, args)?,
        },
        Commands::Rewrap(cmd) => match cmd {
            RewrapCommand::Kek(args) => rewrap_kek(&client, &cli_args, args)?,
            RewrapCommand::Dek(args) => rewrap_dek(&client, &cli_args, args)?,
        },
        Commands::Masterkey(cmd) => match cmd {
            MasterkeyCommand::Status(args) => masterkey_status(&client, &cli_args, args)?,
            MasterkeyCommand::Lock(args) => masterkey_lock(&client, &cli_args, args)?,
            MasterkeyCommand::Unlock(args) => masterkey_unlock(&client, &cli_args, args)?,
            MasterkeyCommand::Describe(args) => masterkey_describe(&client, &cli_args, args)?,
            MasterkeyCommand::Create(args) => masterkey_create(&client, &cli_args, args)?,
            MasterkeyCommand::Activate(args) => masterkey_activate(&client, &cli_args, args)?,
            MasterkeyCommand::Delete(args) => masterkey_delete(&client, &cli_args, args)?,
            MasterkeyCommand::Pkcs11Tokens(args) => masterkey_pkcs11_tokens(&client, &cli_args, args)?,
        },
        Commands::Rbac(cmd) => match cmd {
            RbacCommand::Rule(cmd) => rbac_rule(&client, &cli_args, cmd)?,
            RbacCommand::Role(cmd) => rbac_role(&client, &cli_args, cmd)?,
            RbacCommand::Bind(cmd) => rbac_bind(&client, &cli_args, cmd)?,
            RbacCommand::Unbind(cmd) => rbac_unbind(&client, &cli_args, cmd)?,
            RbacCommand::Explain(cmd) => rbac_explain(&client, &cli_args, cmd)?,
            RbacCommand::Bindings(cmd) => rbac_bindings(&client, &cli_args, cmd)?,
        },
        Commands::Template(cmd) => match cmd {
            TemplateCommand::Render(args) => template_render(&client, &cli_args, args)?,
        },
        _ => {}
    }

    Ok(())
}

/// Determine the server URL to connect to, based on CLI arguments and environment variables.
fn get_server_url(cli_args: &CliArgs) -> CliResult<String> {
    // Cli arguments take precedence over environment variables
    if let Some(server) = &cli_args.server {
        return Ok(server.clone());
    }

    // Next, check the environment variable HKEY_SERVER_URL
    if let Some(v) = std::env::var_os("HKEY_SERVER_URL") {
        return Ok(v.to_string_lossy().into_owned());
    }

    Err(CliError::ConfigError(
        "No server URL configured. Set HKEY_SERVER_URL or use --server".into(),
    ))
}
