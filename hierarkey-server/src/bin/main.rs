// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use clap::{Parser, Subcommand};
use config::ConfigError;
use hierarkey_core::{CkError, CkResult, Metadata, resources::AccountName};
use hierarkey_server::{
    AccountManager, AccountStatus, DEFAULT_ADMIN_PASSWORD_LENGTH, MasterKeyFileType, MasterKeyStatus, MasterKeyUsage,
    Password,
    audit_context::CallContext,
    global::{
        DEFAULT_PASSPHRASE_LEN, MIN_PASSPHRASE_LEN,
        config::Config,
        keys::SigningKey,
        utils::password::{generate_strong_passphrase, read_passphrase_from_user},
    },
    http_server::AppState,
    migrations::{check_migrations as check_migrations_impl, run_migrations},
    preview::{preview_enabled, preview_expired, preview_expiry_date},
    service::{
        account::{AccountData, CustomAccountData, CustomUserAccountData},
        masterkey::provider::UnlockArgs,
        masterkey::{BackendCreate, CreateMasterKeyRequest, MasterKeyProviderType},
    },
    startup::{
        StartupChecks, build_app_state, install_crypto_provider, load_master_keys, load_signing_key, setup_logging,
        start_server,
    },
};
use std::{io::Write, process::exit};
use tracing::{error, info};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "hierarkey", about = "Hierarkey Secret Management Server — Community Edition")]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), " (Community Edition)"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the server
    Serve {
        /// Configuration file path
        #[arg(short, long, default_value = "hierarkey-config.toml")]
        config: String,
    },
    /// Generate a default configuration file
    GenerateConfig {
        /// Output file path
        #[arg(short, long, default_value = "hierarkey-config.toml")]
        output: String,
    },
    /// Upgrade the database schema
    UpdateMigrations {
        /// Configuration file path
        #[arg(short, long, default_value = "hierarkey-config.toml")]
        config: String,

        /// Force upgrade without confirmation
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
    /// Check database schema
    CheckMigrations {
        /// Configuration file path
        #[arg(short, long, default_value = "hierarkey-config.toml")]
        config: String,

        /// Show missing SQL for pending migrations
        #[arg(long, default_value_t = false)]
        sql: bool,
    },
    /// Bootstrap the first admin account (fails if one already exists)
    BootstrapAdminAccount {
        /// Configuration file path
        #[arg(short, long, default_value = "hierarkey-config.toml")]
        config: String,

        /// Name for the admin account
        #[arg(long = "name", default_value = "admin")]
        account_name: AccountName,

        /// Insecure: specify password on command line (not recommended)
        #[arg(long)]
        insecure_password: Option<String>,

        /// Do not require password change on first login
        #[arg(long = "no-pwd-change")]
        no_pwd_change: bool,
    },
    /// Recover a tampered account (requires master key passphrase)
    RecoverAccount {
        /// Configuration file path
        #[arg(short, long, default_value = "hierarkey-config.toml")]
        config: String,

        /// Name of the account to recover
        #[arg(long = "name")]
        account_name: AccountName,
    },
    /// Bootstrap the row-integrity signing key (fails if one already exists)
    BootstrapSigningKey {
        /// Configuration file path
        #[arg(short, long, default_value = "hierarkey-config.toml")]
        config: String,
    },
    /// Bootstrap the first master key (fails if one already exists)
    BootstrapMasterKey {
        /// Configuration file path
        #[arg(short, long, default_value = "hierarkey-config.toml")]
        config: String,

        /// Type of master key: 'wrap_kek'
        #[arg(long = "usage", value_enum)]
        key_usage: MasterKeyUsage,

        /// Provider of master key: 'insecure' or 'passphrase', 'pkcs11'
        #[arg(long = "provider", value_enum)]
        provider: MasterKeyProviderType,

        /// Name of the masterkey
        #[arg(long, default_value = "root")]
        name: Option<String>,

        /// Description for the masterkey
        #[arg(long)]
        description: Option<String>,

        /// Passphrase for encrypted key (if applicable, will prompt if not provided)
        #[arg(long = "insecure-passphrase")]
        passphrase: Option<String>,

        /// Generate a random passphrase
        #[arg(long, conflicts_with = "passphrase")]
        generate_passphrase: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Serve { config } => run_server(&config).await,
        Commands::GenerateConfig { output } => exitcode(generate_config(&output).await),
        Commands::UpdateMigrations { config, yes } => exitcode(upgrade_migrations(&config, yes).await),
        Commands::CheckMigrations { config, sql } => exitcode(check_migrations(&config, sql).await),
        Commands::BootstrapMasterKey {
            config,
            key_usage,
            provider,
            name,
            description,
            passphrase,
            generate_passphrase,
        } => exitcode(
            bootstrap_masterkey(
                &config,
                key_usage,
                provider,
                name,
                description,
                passphrase.map(Zeroizing::new),
                generate_passphrase,
            )
            .await,
        ),
        Commands::BootstrapAdminAccount {
            config,
            account_name,
            insecure_password,
            no_pwd_change,
        } => exitcode(
            bootstrap_admin_account(&config, account_name, insecure_password.map(Zeroizing::new), !no_pwd_change).await,
        ),
        Commands::RecoverAccount { config, account_name } => exitcode(recover_account(&config, account_name).await),
        Commands::BootstrapSigningKey { config } => exitcode(bootstrap_signing_key(&config).await),
    };

    exit(exit_code);
}

/// Convert CkResult to a CLI exit code
fn exitcode(result: CkResult<()>) -> i32 {
    match result {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Error: {e}");
            match e {
                CkError::Validation(_) => 2,
                CkError::Auth(_) => 3,
                CkError::ResourceNotFound { .. } => 4,
                CkError::Conflict { .. } | CkError::RevisionMismatch => 5,
                CkError::PermissionDenied => 7,
                _ => 1,
            }
        }
    }
}

/// Resolve the $system account and return a CallContext acting as it.
/// CLI commands that write to the DB (create account, create masterkey, etc.) need a real
/// AccountId for the `created_by` field — Actor::System alone is not enough.
async fn system_ctx(state: &AppState) -> CkResult<CallContext> {
    let system_name = AccountName::try_from("$system")?;
    let system_id = state
        .account_service
        .find_by_name(&CallContext::system(), &system_name)
        .await?
        .ok_or_else(|| CkError::Custom("$system account not found — have migrations been applied?".to_string()))?
        .id;
    Ok(CallContext::for_account(system_id))
}

/// Generate a default configuration file
async fn generate_config(output_path: &str) -> CkResult<()> {
    Config::generate_template(output_path)
}

/// Upgrade the database schema
async fn upgrade_migrations(config_path: &str, confirmed: bool) -> CkResult<()> {
    let cfg = Config::load_from_file(config_path)?;
    let state = build_app_state(cfg, &[]).await?;

    if !confirmed {
        println!("WARNING: Upgrading the database schema may result in data loss if something goes wrong.");
        println!("Make sure you have a backup of your database before proceeding.");
        print!("Do you want to continue? (yes/no): ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();

        if input != "yes" && input != "y" {
            println!("Database upgrade cancelled.");
            return Ok(());
        }
    }

    run_migrations(&state.pool).await?;

    info!("Database schema upgraded successfully");
    Ok(())
}

/// Check database schema
async fn check_migrations(config_path: &str, show_missing_sql: bool) -> CkResult<()> {
    let cfg = Config::load_from_file(config_path)?;
    let state = build_app_state(cfg, &[]).await?;

    let pending = check_migrations_impl(&state.pool).await?;

    if pending.is_empty() {
        println!("Database is up to date. No pending migrations.");
        return Ok(());
    }

    eprintln!("There are {} pending migrations:", pending.len());
    for mig in &pending {
        eprintln!(" - {mig}");
    }

    if show_missing_sql {
        eprintln!("\nSQL for pending migrations:");
        for (name, sql) in hierarkey_server::migrations::MIGRATIONS {
            if pending.iter().any(|p| p == name) {
                eprintln!("\n-- Migration: {name}\n{sql}");
            }
        }

        eprintln!("Make sure you update the _migrations table after applying the above SQL statements.");
    }

    Err(CkError::Conflict {
        what: "database schema is not up to date".into(),
    })
}

/// Bootstrap the first admin account (fails if one already exists)
async fn bootstrap_admin_account(
    config_path: &str,
    account_name: AccountName,
    password: Option<Zeroizing<String>>,
    must_change_pwd: bool,
) -> CkResult<()> {
    let cfg = Config::load_from_file(config_path)?;
    let state = build_app_state(cfg, &[]).await?;
    // system_ctx must be called before the signing key is loaded: the $system account
    // is created by migrations and has no row_hmac; loading the key first would cause
    // the HMAC check to fail on lookup.
    let ctx = system_ctx(&state).await?;

    if state.account_service.get_admin_count(&ctx).await? != 0 {
        return Err(CkError::Conflict {
            what: "an admin account already exists".into(),
        });
    }

    // Load master keys and signing key AFTER the system account lookup so the new
    // admin account gets a signed row_hmac on creation.
    let _ = load_master_keys(&state).await;
    let _ = load_signing_key(&state).await;

    let password = match password {
        Some(pw) => {
            eprintln!(
                "WARNING: Password supplied on the command line. \
                 It may be visible in shell history and process listings. \
                 Use this only in non-interactive scripts with a secrets manager."
            );
            Password::new(&pw)
        }
        None => Password::new(&AccountManager::generate_plaintext_password(DEFAULT_ADMIN_PASSWORD_LENGTH)?),
    };

    let data = AccountData {
        account_name: account_name.clone(),
        is_active: true,
        description: Some("Built-in administrator account".into()),
        labels: Default::default(),
        custom: CustomAccountData::User(CustomUserAccountData {
            email: None,
            full_name: Some("Hierarkey Administrator".into()),
            password: password.clone(),
            must_change_password: must_change_pwd,
        }),
    };
    let account = state.account_service.create_account(&ctx, &data).await?;

    state
        .account_service
        .grant_admin(&ctx, account.id)
        .await
        .inspect_err(|e| eprintln!("{e}"))
        .map_err(|_| CkError::Custom("Could not grant admin permissions".into()))?;

    let printable_password = password.to_string();
    println!(
        r#"
Admin account created successfully.

Name     : {account_name}
Password : {printable_password}

Please change the password after first login!"#
    );

    Ok(())
}

/// Bootstrap the row-integrity signing key.
///
/// Generates a 32-byte random signing key, wraps it with the active master key,
/// and stores the encrypted key in the `signing_keys` table.  Fails if a signing
/// key already exists (use key rotation if you need to replace it).
async fn bootstrap_signing_key(config_path: &str) -> CkResult<()> {
    let cfg = Config::load_from_file(config_path)?;
    let state = build_app_state(cfg, &[]).await?;
    let ctx = CallContext::system();

    if state.signing_key_manager.fetch_active().await?.is_some() {
        return Err(CkError::Conflict {
            what: "a signing key already exists".into(),
        });
    }

    state.masterkey_service.load_masterkeys_into_keyring().await?;

    let master_keys = state.masterkey_service.find_all(&ctx).await?;
    let active_mk = master_keys
        .iter()
        .find(|k| k.status == MasterKeyStatus::Active)
        .ok_or_else(|| CkError::MasterKey("no active master key found".into()))?;

    if state.masterkey_service.is_locked(&ctx, active_mk)? {
        return Err(CkError::MasterKey("active master key is locked; unlock it first".into()));
    }

    let crypto = state.masterkey_service.get_crypto_handle(active_mk)?;
    let (_, enc_key) = state
        .signing_key_manager
        .bootstrap_new(crypto.as_ref(), active_mk.id)
        .await?;

    println!(
        "Signing key '{}' created and encrypted under master key '{}'.",
        enc_key.short_id, active_mk.name
    );
    println!("Row-level HMAC integrity protection is now active on the next server start.");

    Ok(())
}

/// Recover a `Tampered` account (break-glass path).
///
/// # Security model
///
/// Recovery requires the master key passphrase.  DB write access alone is not
/// sufficient; the attacker would also need the passphrase to decrypt the
/// signing key and produce a valid HMAC.
///
/// Flow:
///  1. Load master keys into the keyring (reads from DB, but key material is
///     still encrypted at this point).
///  2. Prompt for the active master key passphrase, unlock, decrypt the signing
///     key, and load it into the shared `SigningKeySlot`.
///  3. Load the tampered account directly from the store (bypasses HMAC check).
///  4. Reset `status` to `active` and call `update_account`, which re-signs the
///     row with the now-loaded signing key.
///  5. The account's `row_hmac` in the DB now reflects the recovered state and
///     will pass verification on the next server start.
async fn recover_account(config_path: &str, account_name: AccountName) -> CkResult<()> {
    let cfg = Config::load_from_file(config_path)?;
    let state = build_app_state(cfg, &[]).await?;
    let ctx = CallContext::system();

    // Step 1: find the account (signing slot empty, so no HMAC check yet)
    let account = state
        .account_service
        .find_by_name(&ctx, &account_name)
        .await?
        .ok_or_else(|| CkError::ResourceNotFound {
            kind: "account",
            id: account_name.to_string(),
        })?;

    if account.status != AccountStatus::Tampered {
        eprintln!(
            "Account '{}' has status '{}'; only accounts with status 'tampered' can be recovered.",
            account_name, account.status
        );
        return Err(hierarkey_core::error::validation::ValidationError::InvalidOperation {
            message: format!("account status is '{}', expected 'tampered'", account.status),
        }
        .into());
    }

    // Step 2: load signing key (requires master key passphrase)
    state.masterkey_service.load_masterkeys_into_keyring().await?;

    let master_keys = state.masterkey_service.find_all(&ctx).await?;
    let active_mk = master_keys
        .iter()
        .find(|k| k.status == MasterKeyStatus::Active)
        .ok_or_else(|| CkError::MasterKey("no active master key found".into()))?;

    // Check whether a signing key has been provisioned.
    let enc_signing_key = state.signing_key_manager.fetch_active().await?.ok_or_else(|| {
        CkError::Custom(
            "no signing key found; row integrity is not yet provisioned \
             (run 'bootstrap-signing-key' first)"
                .into(),
        )
    })?;

    // Prompt for passphrase and unlock the master key (only if locked).
    if state
        .masterkey_service
        .is_locked(&ctx, active_mk)
        .map_err(|e| CkError::Custom(format!("could not check master key status: {e}")))?
    {
        eprintln!("Enter the master key passphrase to authenticate this recovery:");
        let passphrase = read_passphrase_from_user(0)?;
        state
            .masterkey_service
            .unlock(&ctx, active_mk, &UnlockArgs::Passphrase(passphrase))
            .map_err(|e| CkError::Custom(format!("master key unlock failed: {e}")))?;
    } else {
        eprintln!("Master key is already unlocked (insecure/auto-unlock provider).");
    }

    // Decrypt the signing key and load it into the slot.
    let crypto = state
        .masterkey_service
        .get_crypto_handle(active_mk)
        .map_err(|e| CkError::Custom(format!("could not get crypto handle: {e}")))?;
    let key_bytes = crypto.unwrap_signing_key(&enc_signing_key)?;
    let signing_key = SigningKey::from_bytes(&key_bytes)?;
    state.signing_slot.load(signing_key);

    // Step 3-4: recover and re-sign
    state.account_service.recover_tampered_account(&ctx, account.id).await?;

    println!("Account '{account_name}' has been recovered and re-signed with the current signing key.");
    println!("IMPORTANT: change the account password before putting it back into service,");
    println!("in case the tamper included a password hash substitution.");

    Ok(())
}

async fn run_server(config_path: &str) -> i32 {
    print_banner();

    let checks = StartupChecks::new(config_path.to_string());
    let cfg = match checks.run_all().await {
        Ok(cfg) => cfg,
        Err(e) => {
            e.display(config_path);
            return e.exit_code();
        }
    };

    let log_dest = match setup_logging(&cfg) {
        Ok(dest) => dest,
        Err(e) => {
            eprintln!("Failed to initialize logging: {e}\n");
            return 1;
        }
    };
    println!("  [  OK  ]  {:<18}  level: {} ({})", "Logging", cfg.logging.level, log_dest);
    println!();
    println!("  ── Server ──────────────────────────────────────────────────");

    if let Err(e) = install_crypto_provider() {
        error!("Failed to install TLS crypto provider: {}", e);
        eprintln!("Failed to initialize TLS crypto provider: {e}\n");
        return 1;
    }

    match start_server(cfg, &[]).await {
        Ok(_) => {
            println!("- Server stopped gracefully");
            0
        }
        Err(e) => {
            error!("Fatal error while running server: {}", e);
            eprintln!("Fatal error while running server: {e}\n");
            1
        }
    }
}

fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    let version_line = format!("Community Edition  ·  v{version}");

    println!();
    println!("  ╔════════════════════════════════════════════════════════╗");
    println!("  ║{:^56}║", "Hierarkey  Secret Management Server");
    println!("  ║{version_line:^56}║");
    if preview_enabled() {
        println!("  ║{:^56}║", "[ Preview mode enabled ]");
    }
    println!("  ╚════════════════════════════════════════════════════════╝");
    println!();
    println!("  Started  :  {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Notice   :  This software is NOT production ready");
    if preview_enabled() {
        println!(
            "  Preview  :  Expires {}",
            preview_expiry_date().format("%Y-%m-%d %H:%M:%S UTC")
        );
        if preview_expired() {
            println!();
            eprintln!("  [ FAIL ]  Preview mode has expired. Thank you for testing Hierarkey!");
            exit(1);
        }
    }
    println!();
    println!("  ── Startup checks ──────────────────────────────────────────");
}

async fn bootstrap_masterkey(
    config_path: &str,
    key_usage: MasterKeyUsage,
    provider: MasterKeyProviderType,
    name: Option<String>,
    description: Option<String>,
    passphrase: Option<Zeroizing<String>>,
    generate_passphrase: bool,
) -> CkResult<()> {
    let cfg = Config::load_from_file(config_path)?;
    let state = build_app_state(cfg, &[]).await?;

    let ctx = system_ctx(&state).await?;

    if state
        .masterkey_service
        .find_all(&ctx)
        .await?
        .iter()
        .any(|mk| mk.usage == key_usage)
    {
        return Err(CkError::Conflict {
            what: format!("a master key for usage '{key_usage}' already exists"),
        });
    }

    let name = name.unwrap_or("root".into());
    let description = description.unwrap_or("Root Master Key".into());
    let mut metadata = Metadata::new();
    metadata.add_description(&description);
    metadata.add_label("key-usage", &key_usage.to_string());
    metadata.add_label("name", &name);

    if provider == MasterKeyProviderType::Insecure && !state.config.masterkey.allow_insecure_masterkey {
        return Err(CkError::Config(ConfigError::Message(
            "Insecure master key provider is not allowed. \
             Set masterkey.allow_insecure_masterkey = true in the config to enable it (dev/test only)."
                .into(),
        )));
    }

    // Based on the type, create the appropriate masterkey version config and actual data (if needed)
    let req = match provider {
        MasterKeyProviderType::Insecure => CreateMasterKeyRequest {
            name: name.clone(),
            usage: key_usage,
            metadata,
            backend: BackendCreate::Insecure {
                file_type: MasterKeyFileType::Insecure,
            },
            status: MasterKeyStatus::Active,
        },
        MasterKeyProviderType::Passphrase => {
            let passphrase = if generate_passphrase {
                let passphrase = generate_strong_passphrase(DEFAULT_PASSPHRASE_LEN);
                println!("Generated passphrase: {}", passphrase.as_str());
                println!("Please store this passphrase securely. It will not be shown again and cannot be recovered.");
                passphrase
            } else if let Some(p) = passphrase {
                p
            } else {
                read_passphrase_from_user(MIN_PASSPHRASE_LEN)?
            };

            CreateMasterKeyRequest {
                name: name.clone(),
                usage: key_usage,
                metadata,
                backend: BackendCreate::Passphrase {
                    file_type: MasterKeyFileType::Passphrase,
                    passphrase,
                },
                status: MasterKeyStatus::Active,
            }
        }
        _ => {
            return Err(CkError::Config(ConfigError::Message(format!(
                "Master key provider '{provider:?}' is not supported yet"
            ))));
        }
    };

    state.masterkey_service.create_master_key(&ctx, &req).await?;
    println!("- Master key '{name}' created successfully.");

    Ok(())
}
