// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::global::keys::SigningKey;
use crate::global::row_hmac::{sign_account, sign_account_role_binding, sign_role_rule, sign_rule};
use crate::manager::account::AccountId;
use crate::manager::masterkey::MasterKeyStatus;
use crate::manager::rbac::rule::RuleRow;
use crate::rbac::{RoleId, RuleId};
use crate::global::config::{Config, ServerMode};
use crate::http_server::federated_auth_provider::FederatedAuthProvider;
use crate::http_server::mfa_provider::MfaProvider;
use crate::http_server::mtls_provider::MtlsAuthProvider;
use crate::http_server::nonce_cache::NonceCache;
use crate::http_server::{AppState, ServerExtension, build_router, start_http_server, start_tls_server};
use crate::manager::account::{AccountManager, SqlAccountStore};
use crate::manager::federated_identity::FederatedIdentityManager;
use crate::manager::kek::{KekManager, SqlKekStore};
use crate::manager::masterkey::{MasterKeyUsage, SqlMasterKeyStore};
use crate::manager::namespace::{NamespaceManager, SqlNamespaceStore};
use crate::manager::rbac::SqlRbacStore;
use crate::manager::secret::sql_store::SqlSecretStore;
use crate::manager::signing_key::{SigningKeyManager, SqlSigningKeyStore};
use crate::manager::token::SqlTokenStore;
use crate::service::masterkey::MasterKeyProviderType;
use crate::service::masterkey::provider::insecure::InsecureMasterKeyProvider;
use crate::service::masterkey::provider::passphrase::PassphraseMasterKeyProvider;
use crate::service::{
    AccountService, AuditService, AuthService, KekService, LicenseService, MasterKeyService, NamespaceService,
    RbacService, SecretService, TokenService,
};
use crate::task_manager::BackgroundTaskManager;
use crate::{MasterKeyManager, RbacManager, SecretManager, TokenManager};
use hierarkey_core::{CkError, CkResult};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{trace, warn};
use tracing_appender::rolling;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, reload};

// ---------------------------------------------------------------------------
// StateBuilder — passed to extensions during configure()
// ---------------------------------------------------------------------------

/// Passed to `ServerExtension::configure` before `AppState` is frozen.
/// Extensions use this to register providers and inspect the server config.
pub struct StateBuilder<'a> {
    pub masterkey_service: &'a mut MasterKeyService,
    pub config: &'a Config,
    pub mtls_auth_provider: Option<Arc<dyn MtlsAuthProvider>>,
    pub mfa_provider: Option<Arc<dyn MfaProvider>>,
    pub federated_providers: Vec<Arc<dyn FederatedAuthProvider>>,
}

impl<'a> StateBuilder<'a> {
    pub fn register_mtls_provider(&mut self, provider: Arc<dyn MtlsAuthProvider>) {
        self.mtls_auth_provider = Some(provider);
    }

    pub fn register_mfa_provider(&mut self, provider: Arc<dyn MfaProvider>) {
        self.mfa_provider = Some(provider);
    }

    pub fn register_federated_provider(&mut self, provider: Arc<dyn FederatedAuthProvider>) {
        self.federated_providers.push(provider);
    }
}

/// Errors that can occur during startup checks. Each variant corresponds to a specific check that failed.
pub enum StartupError {
    ConfigMissing(String),
    ConfigInvalid(String),
    DatabaseNotMigrated,
    NoMasterKey,
    NoAdminAccount,
    SystemAccountMissing,
    Other(CkError),
    DatabaseConnectionFailed(CkError),
}

impl StartupError {
    /// We map each error variant to a specific exit code so that scripts or users can understand the reason for failure without parsing the error message.
    pub fn exit_code(&self) -> i32 {
        match self {
            StartupError::ConfigMissing(_) => 2,
            StartupError::ConfigInvalid(_) => 3,
            StartupError::DatabaseNotMigrated => 4,
            StartupError::NoAdminAccount => 5,
            StartupError::NoMasterKey => 6,
            StartupError::SystemAccountMissing => 7,
            StartupError::Other(_) => 1,
            StartupError::DatabaseConnectionFailed(_) => 1,
        }
    }

    pub fn display(&self, config_path: &str) {
        match self {
            StartupError::ConfigMissing(_) => {
                // FAIL line already printed by load_config()
                eprintln!();
                eprintln!("  To generate a default configuration file, run:");
                eprintln!();
                eprintln!("    hierarkey generate-config --output {config_path}");
                eprintln!();
                eprintln!("  Then edit the file to configure your database connection and other settings.");
            }
            StartupError::ConfigInvalid(_) => {
                // FAIL line (with the error reason) already printed by load_config()
                eprintln!();
                eprintln!("  Please check your configuration file at: {config_path}");
            }
            StartupError::DatabaseNotMigrated => {
                eprintln!("  [ FAIL ]  {:<18}  schema not up to date", "Schema");
                eprintln!();
                eprintln!("  To upgrade the database schema, run:");
                eprintln!();
                eprintln!("    hierarkey update-migrations --config {config_path}");
            }
            StartupError::NoMasterKey => {
                eprintln!("  [ FAIL ]  {:<18}  no master keys found", "Master keys");
                eprintln!();
                eprintln!("  To create an initial master key, run:");
                eprintln!();
                eprintln!("    hierarkey bootstrap-master-key --usage wrap_kek --provider <type>");
                eprintln!();
                eprintln!("  Supported provider types: 'passphrase', 'insecure' (dev/test only).");
            }
            StartupError::NoAdminAccount => {
                eprintln!("  [ FAIL ]  {:<18}  no administrator account found", "Admin accounts");
                eprintln!();
                eprintln!("  To create an initial administrator account, run:");
                eprintln!();
                eprintln!("    hierarkey bootstrap-admin-account --config {config_path} --name admin");
            }
            StartupError::SystemAccountMissing => {
                eprintln!("  [ FAIL ]  {:<18}  $system account missing", "System account");
                eprintln!();
                eprintln!("  The built-in $system account should be created by the initial migration.");
                eprintln!("  To re-apply migrations, run:");
                eprintln!();
                eprintln!("    hierarkey update-migrations --config {config_path}");
            }
            StartupError::Other(err) => {
                eprintln!("  [ FAIL ]  {:<18}  {}", "Startup", err);
            }
            StartupError::DatabaseConnectionFailed(_) => {
                eprintln!("  [ FAIL ]  {:<18}  connection failed", "Database");
                eprintln!();
                eprintln!("  Please check your database connection settings in: {config_path}");
            }
        }
        eprintln!();
    }
}

impl From<CkError> for StartupError {
    fn from(err: CkError) -> Self {
        match &err {
            CkError::ResourceNotFound { kind, .. } if *kind == "config" => StartupError::ConfigMissing(err.to_string()),
            _ => StartupError::Other(err),
        }
    }
}

pub struct StartupChecks {
    config_path: String,
}

impl StartupChecks {
    pub fn new(config_path: String) -> Self {
        Self { config_path }
    }

    pub async fn run_all(&self) -> Result<Config, StartupError> {
        self.check_config_exists()?;
        let config = self.load_config()?;
        self.check_database_migrated(&config).await?;
        self.check_system_account_exists(&config).await?;
        self.check_masterkeys(&config).await?;
        self.check_admin_exists(&config).await?;
        Ok(config)
    }

    fn check_config_exists(&self) -> Result<(), StartupError> {
        if !Path::new(&self.config_path).exists() {
            return Err(StartupError::ConfigMissing(self.config_path.clone()));
        }
        Ok(())
    }

    fn load_config(&self) -> Result<Config, StartupError> {
        let config = Config::load_from_file(&self.config_path).map_err(|e| match e {
            CkError::ResourceNotFound { .. } => {
                println!("  [ FAIL ]  {:<18}  file not found", "Configuration");
                StartupError::ConfigMissing(self.config_path.clone())
            }
            _ => {
                let err_str = e.to_string();
                println!("  [ FAIL ]  {:<18}  {}", "Configuration", strip_validation_prefix(&err_str));
                StartupError::ConfigInvalid(err_str)
            }
        })?;
        println!("  [  OK  ]  {:<18}  {}", "Configuration", self.config_path);
        Ok(config)
    }

    async fn check_database_migrated(&self, config: &Config) -> Result<(), StartupError> {
        let pool = crate::create_pool(config)
            .await
            .map_err(StartupError::DatabaseConnectionFailed)?;

        if !config.database.tls.enabled {
            println!("  [ WARN ]  {:<18}  connected, TLS disabled (unencrypted)", "Database");
        } else {
            println!("  [  OK  ]  {:<18}  connected (TLS: enabled)", "Database");
        }

        let pending = crate::migrations::check_migrations(&pool)
            .await
            .map_err(StartupError::Other)?;

        if !pending.is_empty() {
            eprintln!("  [ FAIL ]  {:<18}  {} pending migration(s):", "Schema", pending.len());
            for name in &pending {
                eprintln!("              - {name}");
            }
            return Err(StartupError::DatabaseNotMigrated);
        }

        println!("  [  OK  ]  {:<18}  up to date", "Schema");
        Ok(())
    }

    async fn check_system_account_exists(&self, config: &Config) -> Result<(), StartupError> {
        use crate::manager::account::{AccountManager, SqlAccountStore};
        use hierarkey_core::resources::AccountName;
        use std::sync::Arc;

        let pool = crate::global::db::create_pool(config)
            .await
            .map_err(StartupError::Other)?;
        let store = Arc::new(SqlAccountStore::new(pool.clone()).map_err(StartupError::Other)?);
        let signing_slot = Arc::new(crate::service::signing_key_slot::SigningKeySlot::new());
        let account_manager = AccountManager::new(store, signing_slot);

        let system_name = AccountName::try_from("$system").map_err(StartupError::Other)?;
        let system_account = account_manager
            .find_account_by_name(&system_name)
            .await
            .map_err(StartupError::Other)?;

        if system_account.is_none() {
            return Err(StartupError::SystemAccountMissing);
        }

        println!("  [  OK  ]  {:<18}  $system present", "System account");
        Ok(())
    }

    async fn check_admin_exists(&self, config: &Config) -> Result<(), StartupError> {
        use crate::manager::account::{AccountManager, SqlAccountStore};
        use std::sync::Arc;

        let pool = crate::global::db::create_pool(config)
            .await
            .map_err(StartupError::Other)?;
        let store = Arc::new(SqlAccountStore::new(pool.clone()).map_err(StartupError::Other)?);
        let signing_slot = Arc::new(crate::service::signing_key_slot::SigningKeySlot::new());
        let account_manager = AccountManager::new(store, signing_slot);

        let admin_count = account_manager.get_admin_count().await.map_err(StartupError::Other)?;
        if admin_count == 0 {
            return Err(StartupError::NoAdminAccount);
        }

        println!("  [  OK  ]  {:<18}  {} account(s)", "Admin accounts", admin_count);
        Ok(())
    }

    async fn check_masterkeys(&self, config: &Config) -> Result<(), StartupError> {
        use crate::manager::masterkey::{MasterKeyManager, SqlMasterKeyStore};
        use std::sync::Arc;

        let pool = crate::global::db::create_pool(config)
            .await
            .map_err(StartupError::Other)?;
        let store = Arc::new(SqlMasterKeyStore::new(pool.clone()).map_err(StartupError::Other)?);
        let masterkey_manager = MasterKeyManager::new(store)?;

        // Make sure we have at least one WrapKek master key
        let mk_count = masterkey_manager
            .count_keys(MasterKeyUsage::WrapKek)
            .await
            .map_err(StartupError::Other)?;
        if mk_count == 0 {
            return Err(StartupError::NoMasterKey);
        }

        println!("  [  OK  ]  {:<18}  {} active key(s)", "Master keys", mk_count);
        Ok(())
    }
}

/// Strip the verbose error-chain prefixes that `CkError::Validation` and
/// `ValidationError::Custom` add, so the user sees just the plain message.
fn strip_validation_prefix(s: &str) -> &str {
    let s = s.strip_prefix("validation error: ").unwrap_or(s);
    s.strip_prefix("general validation error: ").unwrap_or(s)
}

/// Create a service container with all services and managers configured.
///
/// `extensions` are called during construction so they can register providers
/// via `StateBuilder` before `AppState` is frozen into an `Arc`.
pub async fn build_app_state(cfg: Config, extensions: &[Box<dyn ServerExtension>]) -> CkResult<AppState> {
    let task_manager = Arc::new(BackgroundTaskManager::new());

    let pool = crate::create_pool(&cfg).await?;

    let store = Arc::new(SqlMasterKeyStore::new(pool.clone())?);
    let mk_manager = Arc::new(MasterKeyManager::new(store)?);

    let store = Arc::new(SqlAccountStore::new(pool.clone())?);
    let signing_slot = Arc::new(crate::service::signing_key_slot::SigningKeySlot::new());
    let account_manager = Arc::new(AccountManager::new(store, signing_slot.clone()));

    let store = Arc::new(SqlNamespaceStore::new(pool.clone()));
    let ns_manager = Arc::new(NamespaceManager::new(store));

    let store = Arc::new(SqlSecretStore::new(pool.clone()));
    let secret_manager = Arc::new(SecretManager::new(store));

    let store = Arc::new(SqlTokenStore::new(pool.clone()));
    let token_manager = Arc::new(TokenManager::new(store, signing_slot.clone()));

    let token_service = Arc::new(TokenService::new(token_manager.clone()));

    let mut masterkey_service = MasterKeyService::new(mk_manager.clone());
    if cfg.masterkey.allow_insecure_masterkey {
        masterkey_service.add_provider(
            MasterKeyProviderType::Insecure,
            Box::new(InsecureMasterKeyProvider::new(&cfg.masterkey.file)?),
        );
    }
    masterkey_service.add_provider(
        MasterKeyProviderType::Passphrase,
        Box::new(PassphraseMasterKeyProvider::new(&cfg.masterkey.file)?),
    );

    // Build federated providers from config before freezing the state.
    let config_federated_providers = crate::federated::build_providers(&cfg.auth.federated).await?;

    // Run extension configure() hooks while masterkey_service is still mutable.
    let (mtls_auth_provider, mfa_provider, federated_providers) = {
        let mut builder = StateBuilder {
            masterkey_service: &mut masterkey_service,
            config: &cfg,
            mtls_auth_provider: None,
            mfa_provider: None,
            federated_providers: config_federated_providers,
        };
        for ext in extensions {
            ext.configure(&mut builder)?;
        }
        (builder.mtls_auth_provider, builder.mfa_provider, builder.federated_providers)
    };

    let masterkey_service = Arc::new(masterkey_service);

    let store = Arc::new(SqlKekStore::new(pool.clone()));
    let kek_manager = Arc::new(KekManager::new(store));

    let signing_key_store = Arc::new(SqlSigningKeyStore::new(pool.clone()));
    let signing_key_manager = Arc::new(SigningKeyManager::new(signing_key_store));

    let rbac_store = Arc::new(SqlRbacStore::new(pool.clone()));
    let rbac_manager = Arc::new(RbacManager::new(rbac_store, signing_slot.clone()));

    let kek_service = Arc::new(KekService::new(
        kek_manager,
        masterkey_service.clone(),
        Duration::from_secs(15 * 60),
        task_manager.clone(),
    ));

    let rbac_service = Arc::new(RbacService::new(rbac_manager.clone()));

    let secret_service = Arc::new(SecretService::new(
        ns_manager.clone(),
        secret_manager.clone(),
        kek_service.clone(),
        rbac_service.clone(),
    ));
    let auth_service = AuthService::new(account_manager.clone(), token_manager.clone(), &cfg.auth)?;
    let auth_service = Arc::new(auth_service);
    let account_service = Arc::new(AccountService::new(account_manager.clone(), token_manager.clone()));
    let namespace_service = Arc::new(NamespaceService::new(
        ns_manager.clone(),
        kek_service.clone(),
        rbac_service.clone(),
    ));

    // Nonce TTL is 2x the timestamp acceptance window so every valid nonce is
    // tracked for at least as long as it could legitimately be replayed.
    let sa_nonce_cache = Arc::new(NonceCache::new(Duration::from_secs(120)));

    let license_service = Arc::new(LicenseService::new());
    let audit_service = Arc::new(AuditService::new(pool.clone(), license_service.clone()));
    let federated_identity_manager = Arc::new(FederatedIdentityManager::new(pool.clone()));

    let auth_rate_limiter = if cfg.rate_limit.enabled {
        use std::num::NonZeroU32;
        // .max(1) guarantees both values are >= 1, so NonZeroU32::new returns Some; fall back to MIN (1) to satisfy the type system.
        let nz_rpm = NonZeroU32::new(cfg.rate_limit.auth_requests_per_minute.max(1)).unwrap_or(NonZeroU32::MIN);
        let nz_burst = NonZeroU32::new(cfg.rate_limit.auth_burst_size.max(1)).unwrap_or(NonZeroU32::MIN);
        let quota = governor::Quota::per_minute(nz_rpm).allow_burst(nz_burst);
        Some(Arc::new(governor::RateLimiter::keyed(quota)))
    } else {
        None
    };

    Ok(AppState {
        masterkey_service,
        secret_service,
        auth_service,
        namespace_service,
        account_service,
        kek_service,
        token_service,
        rbac_service,
        license_service,
        audit_service,
        pool,
        auth_rate_limiter,
        mtls_auth_provider,
        mfa_provider,
        federated_providers,
        federated_identity_manager,
        system_account_id: None,
        task_manager,
        config: cfg,
        sa_nonce_cache,
        signing_slot,
        signing_key_manager,
    })
}

// ---------------------------------------------------------------------------
// Shared server startup helpers — used by both community and commercial binaries
// ---------------------------------------------------------------------------

/// Install the ring TLS crypto provider. Must be called before any TLS server is started.
pub fn install_crypto_provider() -> CkResult<()> {
    trace!("Using ring as TLS crypto provider");
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| CkError::Custom("failed to install TLS crypto provider".into()))
}

/// Configure the global tracing subscriber from `cfg`.
///
/// Returns a human-readable description of the log destination (e.g. `"stdout"` or
/// `"file: /var/log/hierarkey.log"`) so the caller can print it in the startup banner.
pub fn setup_logging(cfg: &Config) -> CkResult<String> {
    let filter = EnvFilter::try_new(&cfg.logging.level).unwrap_or_else(|_| EnvFilter::new("info"));
    let (filter, _handle) = reload::Layer::new(filter);

    let log_dest = match cfg.logging.log_file.as_deref().filter(|p| !p.is_empty()) {
        Some(path) => {
            setup_file_logging(filter, path)?;
            format!("file: {path}")
        }
        None => {
            setup_stdout_logging(filter);
            "stdout".to_string()
        }
    };

    Ok(log_dest)
}

fn setup_file_logging(
    filter: reload::Layer<EnvFilter, tracing_subscriber::Registry>,
    log_file_path: &str,
) -> CkResult<()> {
    let log_path = Path::new(log_file_path);

    let directory = log_path
        .parent()
        .ok_or_else(|| CkError::Config(config::ConfigError::Message("Invalid log file path".into())))?;
    let filename = log_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| CkError::Config(config::ConfigError::Message("Invalid log filename".into())))?;

    std::fs::create_dir_all(directory)?;

    let file_appender = rolling::never(directory, filename);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(non_blocking).with_ansi(false));

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set global subscriber");

    // CRITICAL: keep guard alive for the program lifetime — dropping it stops file logging.
    std::mem::forget(guard);

    Ok(())
}

fn setup_stdout_logging(filter: reload::Layer<EnvFilter, tracing_subscriber::Registry>) {
    let subscriber = tracing_subscriber::registry().with(filter).with(fmt::layer());
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set global subscriber");
}

/// Decrypt and load the active signing key into the in-process slot.
///
/// Called after master keys are loaded.  If no signing key has been provisioned,
/// or the active master key is still locked, HMAC checks are silently skipped
/// (the server runs in degraded mode rather than refusing to start).
pub async fn load_signing_key(state: &AppState) -> CkResult<()> {
    let Some(enc_sk) = state.signing_key_manager.fetch_active().await? else {
        return Ok(());
    };

    let ctx = CallContext::system();
    let master_keys = state.masterkey_service.find_all(&ctx).await?;
    let Some(active_mk) = master_keys.iter().find(|k| k.status == MasterKeyStatus::Active) else {
        return Ok(());
    };

    if state.masterkey_service.is_locked(&ctx, active_mk)? {
        return Ok(());
    }

    let crypto = state.masterkey_service.get_crypto_handle(active_mk)?;
    let key_bytes = crypto.unwrap_signing_key(&enc_sk)?;
    let signing_key = SigningKey::from_bytes(&key_bytes)?;
    state.signing_slot.load(signing_key.clone());

    // Sign any rows created before the signing key was provisioned (migrations, bootstrap).
    // This is idempotent: rows already signed are unchanged.
    if let Err(e) = backfill_row_hmacs(&state.pool, &signing_key).await {
        warn!(err = %e, "backfill of NULL row HMACs failed (non-fatal)");
    }

    Ok(())
}

/// Sign all rows with NULL `row_hmac` in tables that can have pre-signing-key content
/// (accounts created by migrations, role-rule associations from initial population, etc.).
///
/// Called once after the signing key is loaded.  Idempotent — rows already signed are skipped.
async fn backfill_row_hmacs(pool: &sqlx::PgPool, key: &SigningKey) -> CkResult<()> {
    use sqlx::Row;

    // ── rbac_rules ────────────────────────────────────────────────────────────
    let rule_rows = sqlx::query_as::<_, RuleRow>(
        "SELECT * FROM rbac_rules WHERE row_hmac IS NULL AND deleted_at IS NULL",
    )
    .fetch_all(pool)
    .await?;

    for rule_row in &rule_rows {
        let hmac_hex = sign_rule(key, rule_row).to_hex();
        sqlx::query("UPDATE rbac_rules SET row_hmac = $2 WHERE id = $1")
            .bind(rule_row.id.0)
            .bind(&hmac_hex)
            .execute(pool)
            .await?;
    }

    if !rule_rows.is_empty() {
        tracing::info!(count = rule_rows.len(), "backfilled row_hmac for rbac_rules");
    }

    // ── rbac_role_rules ───────────────────────────────────────────────────────
    let rows = sqlx::query(
        "SELECT role_id, rule_id FROM rbac_role_rules WHERE row_hmac IS NULL AND removed_at IS NULL",
    )
    .fetch_all(pool)
    .await?;

    for row in &rows {
        let role_id = RoleId(row.get::<uuid::Uuid, _>("role_id"));
        let rule_id = RuleId(row.get::<uuid::Uuid, _>("rule_id"));
        let hmac_hex = sign_role_rule(key, role_id, rule_id).to_hex();
        sqlx::query("UPDATE rbac_role_rules SET row_hmac = $3 WHERE role_id = $1 AND rule_id = $2")
            .bind(role_id.0)
            .bind(rule_id.0)
            .bind(&hmac_hex)
            .execute(pool)
            .await?;
    }

    if !rows.is_empty() {
        tracing::info!(count = rows.len(), "backfilled row_hmac for rbac_role_rules");
    }

    // ── rbac_account_roles ────────────────────────────────────────────────────
    let rows = sqlx::query(
        "SELECT account_id, role_id, valid_from, valid_until FROM rbac_account_roles WHERE row_hmac IS NULL",
    )
    .fetch_all(pool)
    .await?;

    for row in &rows {
        let account_id = AccountId(row.get::<uuid::Uuid, _>("account_id"));
        let role_id = RoleId(row.get::<uuid::Uuid, _>("role_id"));
        let valid_from: Option<chrono::DateTime<chrono::Utc>> = row.get("valid_from");
        let valid_until: Option<chrono::DateTime<chrono::Utc>> = row.get("valid_until");
        let hmac_hex = sign_account_role_binding(key, account_id, role_id, valid_from, valid_until).to_hex();
        sqlx::query(
            "UPDATE rbac_account_roles SET row_hmac = $3 WHERE account_id = $1 AND role_id = $2",
        )
        .bind(account_id.0)
        .bind(role_id.0)
        .bind(&hmac_hex)
        .execute(pool)
        .await?;
    }

    if !rows.is_empty() {
        tracing::info!(count = rows.len(), "backfilled row_hmac for rbac_account_roles");
    }

    // ── accounts (system accounts created by migrations) ───────────────────
    // We fetch full account rows so sign_account can cover all fields.
    let accounts = sqlx::query_as::<_, crate::manager::account::Account>(
        "SELECT * FROM accounts WHERE row_hmac IS NULL",
    )
    .fetch_all(pool)
    .await?;

    for account in &accounts {
        let hmac_hex = sign_account(key, account).to_hex();
        sqlx::query("UPDATE accounts SET row_hmac = $2 WHERE id = $1")
            .bind(account.id.0)
            .bind(&hmac_hex)
            .execute(pool)
            .await?;
    }

    if !accounts.is_empty() {
        tracing::info!(count = accounts.len(), "backfilled row_hmac for accounts");
    }

    Ok(())
}

/// Load all master keys from the database into the in-memory keyring.
pub async fn load_master_keys(state: &AppState) -> CkResult<()> {
    let ctx = CallContext::system();
    let masterkeys = state.masterkey_service.find_all(&ctx).await?;
    for master_key in masterkeys {
        if state.masterkey_service.keyring().contains(&master_key) {
            continue;
        }
        state.masterkey_service.load_into_keyring(&ctx, &master_key).await?;
    }
    Ok(())
}

/// Build the app state + router, load master keys, call extension init hooks, print the
/// "Server ready" banner, and run the HTTP/TLS server until shutdown.
///
/// `extensions` is empty for the Community Edition and populated for the Commercial Edition.
pub async fn start_server(cfg: Config, extensions: &[Box<dyn ServerExtension>]) -> CkResult<()> {
    let mut state = build_app_state(cfg.clone(), extensions).await?;

    let system_name = hierarkey_core::resources::AccountName::try_from("$system")?;
    state.system_account_id = state
        .account_service
        .find_by_name(&CallContext::system(), &system_name)
        .await?
        .map(|acc| acc.id);

    let app = build_router(state.clone(), extensions);

    load_master_keys(&state).await.map_err(|e| {
        eprintln!("  [ FAIL ]  {:<18}  {e}", "Master key");
        e
    })?;

    match load_signing_key(&state).await {
        Ok(()) if state.signing_slot.peek().is_some() => {
            println!("  [  OK  ]  {:<18}  active (row HMAC checks enabled)", "Signing key");
        }
        Ok(()) => {
            println!(
                "  [ WARN ]  {:<18}  not provisioned - run 'hierarkey bootstrap-signing-key'",
                "Signing key"
            );
        }
        Err(e) => {
            eprintln!("  [ FAIL ]  {:<18}  {e}", "Signing key");
            return Err(e);
        }
    }

    if cfg.masterkey.allow_insecure_masterkey {
        warn!(
            "Insecure master key provider is enabled — master key is stored unencrypted on disk. Not for production use."
        );
        println!(
            "  [ WARN ]  {:<18}  insecure provider active (not for production use)",
            "Master key"
        );
    }

    if cfg.database.tls.allow_insecure_tls {
        warn!(
            "Insecure database TLS mode is enabled — certificate/hostname validation may be bypassed. Not for production use."
        );
        if cfg.database.tls.accept_invalid_certs {
            println!("  [ WARN ]  {:<18}  cert validation disabled (unsafe)", "Database TLS");
        }
        if cfg.database.tls.accept_invalid_hostnames {
            println!("  [ WARN ]  {:<18}  hostname validation disabled (unsafe)", "Database TLS");
        }
    }

    let ctx = CallContext::system();
    if state.masterkey_service.is_active_masterkey_locked(&ctx).await? {
        println!("  [ WARN ]  {:<18}  active key locked — decryption unavailable", "Master key");
        println!("  [ INFO ]  {:<18}  run 'hkey masterkey unlock' to unlock", "Master key");
    }
    if state.masterkey_service.any_draining_key_locked(&ctx).await? {
        println!(
            "  [ WARN ]  {:<18}  draining key(s) locked — secrets wrapped under them are unreadable",
            "Master key"
        );
        println!("  [ INFO ]  {:<18}  run 'hkey masterkey status' to inspect", "Master key");
    }

    for ext in extensions {
        ext.init(&state).await?;
    }
    state.audit_service.init().await;

    match cfg.server.mode {
        ServerMode::Tls => {
            println!("  [  OK  ]  {:<18}  TLS", "API mode");
            println!();
            println!("  ────────────────────────────────────────────────────────────");
            println!("  Server ready.  Listening on https://{}", cfg.server.bind_address);
            println!("  ────────────────────────────────────────────────────────────");
            println!();
            start_tls_server(&cfg.server, app).await?;
        }
        ServerMode::Http => {
            if !cfg.server.allow_insecure_http {
                return Err(CkError::Config(config::ConfigError::Message(
                    "Insecure HTTP mode is not allowed. Set allow_insecure_http to true to enable.".into(),
                )));
            }
            warn!("Server is running in HTTP mode — all traffic is unencrypted. Not for production use.");
            println!("  [ WARN ]  {:<18}  HTTP (unencrypted — not for production use)", "API mode");
            println!();
            println!("  ────────────────────────────────────────────────────────────");
            println!("  Server ready.  Listening on http://{}", cfg.server.bind_address);
            println!("  ────────────────────────────────────────────────────────────");
            println!();
            start_http_server(&cfg.server, app).await?;
        }
    }

    state.task_manager.shutdown(Duration::from_secs(5)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hierarkey_core::CkError;

    #[test]
    fn strip_validation_prefix_removes_full_chain() {
        let input = "validation error: general validation error: some message";
        assert_eq!(strip_validation_prefix(input), "some message");
    }

    #[test]
    fn strip_validation_prefix_removes_outer_prefix_only() {
        let input = "validation error: something else";
        assert_eq!(strip_validation_prefix(input), "something else");
    }

    #[test]
    fn strip_validation_prefix_removes_inner_prefix_only() {
        let input = "general validation error: some message";
        assert_eq!(strip_validation_prefix(input), "some message");
    }

    #[test]
    fn strip_validation_prefix_returns_original_when_no_prefix() {
        let input = "some message without a prefix";
        assert_eq!(strip_validation_prefix(input), input);
    }

    #[test]
    fn strip_validation_prefix_empty_string() {
        assert_eq!(strip_validation_prefix(""), "");
    }

    #[test]
    fn exit_code_config_missing_is_2() {
        assert_eq!(StartupError::ConfigMissing("x".into()).exit_code(), 2);
    }

    #[test]
    fn exit_code_config_invalid_is_3() {
        assert_eq!(StartupError::ConfigInvalid("x".into()).exit_code(), 3);
    }

    #[test]
    fn exit_code_database_not_migrated_is_4() {
        assert_eq!(StartupError::DatabaseNotMigrated.exit_code(), 4);
    }

    #[test]
    fn exit_code_no_admin_account_is_5() {
        assert_eq!(StartupError::NoAdminAccount.exit_code(), 5);
    }

    #[test]
    fn exit_code_no_master_key_is_6() {
        assert_eq!(StartupError::NoMasterKey.exit_code(), 6);
    }

    #[test]
    fn exit_code_system_account_missing_is_7() {
        assert_eq!(StartupError::SystemAccountMissing.exit_code(), 7);
    }

    #[test]
    fn exit_code_other_is_1() {
        assert_eq!(StartupError::Other(CkError::Custom("x".into())).exit_code(), 1);
    }

    #[test]
    fn exit_code_database_connection_failed_is_1() {
        assert_eq!(
            StartupError::DatabaseConnectionFailed(CkError::Custom("x".into())).exit_code(),
            1
        );
    }

    #[test]
    fn display_config_missing_does_not_panic() {
        StartupError::ConfigMissing("test.toml".into()).display("test.toml");
    }

    #[test]
    fn display_config_invalid_does_not_panic() {
        StartupError::ConfigInvalid("bad value".into()).display("test.toml");
    }

    #[test]
    fn display_database_not_migrated_does_not_panic() {
        StartupError::DatabaseNotMigrated.display("test.toml");
    }

    #[test]
    fn display_no_master_key_does_not_panic() {
        StartupError::NoMasterKey.display("test.toml");
    }

    #[test]
    fn display_no_admin_account_does_not_panic() {
        StartupError::NoAdminAccount.display("test.toml");
    }

    #[test]
    fn display_system_account_missing_does_not_panic() {
        StartupError::SystemAccountMissing.display("test.toml");
    }

    #[test]
    fn display_other_does_not_panic() {
        StartupError::Other(CkError::Custom("oops".into())).display("test.toml");
    }

    #[test]
    fn display_database_connection_failed_does_not_panic() {
        StartupError::DatabaseConnectionFailed(CkError::Custom("oops".into())).display("test.toml");
    }
}
