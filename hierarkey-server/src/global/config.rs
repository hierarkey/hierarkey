// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::error::validation::ValidationError;
use hierarkey_core::{CkError, CkResult};
use ipnet::IpNet;
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::Write;

const CONFIG_TEMPLATE: &str = include_str!("../../../hierarkey-config.toml.example");

macro_rules! default_fn {
    ($name:ident, $type:ty, $value:expr) => {
        fn $name() -> $type {
            $value
        }
    };
}

default_fn!(default_max_connections, u32, 10);
default_fn!(default_min_connections, u32, 2);
default_fn!(default_idle_timeout, u64, 600);
default_fn!(default_max_lifetime, u64, 1800);
default_fn!(default_acquire_timeout, u64, 30);
default_fn!(default_mk_kdf_memory_kib, u32, 128 * 1024); // 128 MiB
default_fn!(default_mk_kdf_time_cost, u32, 3);
default_fn!(default_mk_kdf_parallelism, u32, 1);

#[derive(Default, Debug, Deserialize, Clone)]
pub struct Config {
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
    pub server: ServerConfig,
    pub masterkey: MasterKeyConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default)]
    pub security_headers: SecurityHeadersConfig,
    /// CIDR ranges of trusted reverse proxies.
    ///
    /// When the real TCP peer address falls within one of these ranges, the server
    /// will accept `X-Forwarded-For` as the authoritative client IP for rate
    /// limiting, and will accept `X-Client-Cert` as the peer certificate for
    /// mTLS authentication. When this list is empty (the default), both headers
    /// are ignored regardless of the peer address.
    ///
    /// Example: `trusted_proxy_cidrs = ["10.0.0.0/8", "172.16.0.0/12"]`
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<IpNet>,
}

impl Config {
    pub fn generate_template(output_path: &str) -> CkResult<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true) // <-- atomic "fail if exists"
            .open(output_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    CkError::Conflict {
                        what: format!("config file '{output_path}' already exists"),
                    }
                } else {
                    CkError::from(e) // relies on From<std::io::Error> for CkError
                }
            })?;

        file.write_all(CONFIG_TEMPLATE.as_bytes())?;
        Ok(())
    }
}

default_fn!(default_false, bool, false);
default_fn!(default_true, bool, true);
default_fn!(default_audience, String, "auth://hierarkey".into());
default_fn!(default_access_token, u64, 900);
default_fn!(default_refresh_token, u64, 86400);
default_fn!(default_max_failed_login_attempts, u32, 10);
default_fn!(default_lockout_duration_minutes, u64, 15);
default_fn!(default_auth_rpm, u32, 20);
default_fn!(default_cors_max_age, u64, 3600);
default_fn!(default_auth_burst, u32, 5);
default_fn!(default_hsts_max_age, u64, 31_536_000); // 1 year

// ----------------------------------------------------------------------------------

/// Configuration for a single `[[auth.federated]]` entry.
#[derive(Debug, Deserialize, Clone)]
pub struct FederatedProviderConfig {
    /// Provider type: `"oidc"` or `"k8s-tokenreview"`.
    pub provider: String,

    /// Unique identifier for this provider entry.
    /// Used as the URL path segment in `POST /v1/auth/federated/{id}` and
    /// stored in the `federated_identities` table.
    pub id: String,

    // --- OIDC-specific fields ---
    /// OIDC issuer URL (e.g. `https://keycloak.example.com/realms/myrealm`).
    /// Required for `provider = "oidc"`.
    pub issuer: Option<String>,

    /// Expected `aud` claim value in OIDC tokens.
    /// Required for `provider = "oidc"`.
    pub audience: Option<String>,

    /// Override the JWKS endpoint URL.
    /// When absent, the URL is discovered via `{issuer}/.well-known/openid-configuration`.
    pub jwks_url: Option<String>,

    /// Path to a file containing a bearer token used to authenticate JWKS/discovery requests.
    /// Useful when the JWKS endpoint requires authentication (e.g. Kubernetes API server).
    /// The file is read on each JWKS fetch so rotated tokens are automatically picked up.
    pub bearer_token_path: Option<String>,

    // --- Kubernetes TokenReview-specific fields ---
    /// Kubernetes API server URL (e.g. `https://k8s.example.com`).
    /// Required for `provider = "k8s-tokenreview"`.
    /// Also used as `external_issuer` when storing the linked identity.
    pub api_server: Option<String>,

    /// Path to the PEM-encoded CA certificate for the Kubernetes API server.
    /// Optional; when absent the system CA bundle is used.
    pub ca_cert_path: Option<String>,

    /// Path to a file containing the bearer token used to authenticate the
    /// `TokenReview` request.  The file is read on each request so rotated
    /// projected tokens are automatically picked up.
    /// Optional; when absent the request is sent without authentication
    /// (only works if the cluster allows anonymous `tokenreviews`).
    pub reviewer_token_path: Option<String>,
}

// ----------------------------------------------------------------------------------
#[derive(Default, Debug, Deserialize, Clone)]
pub struct AuthConfig {
    #[serde(default = "default_false")]
    pub allow_passphrase_auth: bool,
    #[serde(default = "default_true")]
    pub allow_ed25519_auth: bool,
    /// mTLS client-certificate authentication. Requires the Commercial Edition.
    #[serde(default = "default_false")]
    pub allow_mtls_auth: bool,
    #[serde(default = "default_audience")]
    pub audience: String,
    #[serde(default = "default_access_token")]
    pub access_token_ttl_seconds: u64,
    #[serde(default = "default_refresh_token")]
    pub refresh_token_ttl_seconds: u64,
    /// Number of consecutive failed logins before the account is temporarily locked.
    #[serde(default = "default_max_failed_login_attempts")]
    pub max_failed_login_attempts: u32,
    /// How long (in minutes) the account stays locked after hitting the threshold.
    #[serde(default = "default_lockout_duration_minutes")]
    pub lockout_duration_minutes: u64,
    /// Federated authentication providers (`[[auth.federated]]` array of tables).
    #[serde(default)]
    pub federated: Vec<FederatedProviderConfig>,
}

// ----------------------------------------------------------------------------------

#[derive(Default, Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,
    #[serde(default = "default_idle_timeout", rename = "idle_timeout")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_max_lifetime", rename = "max_lifetime")]
    pub max_lifetime_seconds: u64,
    #[serde(default = "default_acquire_timeout", rename = "acquire_timeout")]
    pub acquire_timeout_seconds: u64,

    #[serde(default)]
    pub tls: DatabaseTlsConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct DatabaseTlsConfig {
    pub enabled: bool,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    #[serde(default)]
    pub client_cert_path: Option<String>,
    #[serde(default)]
    pub client_key_path: Option<String>,
    #[serde(default)]
    pub verify_server: bool,
    #[serde(default)]
    pub accept_invalid_certs: bool,
    #[serde(default)]
    pub accept_invalid_hostnames: bool,
    /// Explicit opt-in required before `accept_invalid_certs` or
    /// `accept_invalid_hostnames` are honoured.  Must be `true` to use
    /// either of those flags.  Never set this in production.
    #[serde(default)]
    pub allow_insecure_tls: bool,
}

impl DatabaseTlsConfig {
    pub fn validate(&self) -> CkResult<()> {
        if self.accept_invalid_certs && !self.allow_insecure_tls {
            return Err(ValidationError::Custom(
                "database.tls.accept_invalid_certs = true requires \
                 database.tls.allow_insecure_tls = true (dev/test only, never use in production)"
                    .into(),
            )
            .into());
        }
        if self.accept_invalid_hostnames && !self.allow_insecure_tls {
            return Err(ValidationError::Custom(
                "database.tls.accept_invalid_hostnames = true requires \
                 database.tls.allow_insecure_tls = true (dev/test only, never use in production)"
                    .into(),
            )
            .into());
        }
        Ok(())
    }
}

// ----------------------------------------------------------------------------------

#[derive(Default, Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
    #[serde(default)]
    pub log_file: Option<String>,
}

// ----------------------------------------------------------------------------------

#[derive(Debug, Copy, Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ServerMode {
    #[default]
    Tls,
    Http,
}

impl std::fmt::Display for ServerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerMode::Tls => write!(f, "tls"),
            ServerMode::Http => write!(f, "http"),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ServerConfig {
    pub mode: ServerMode,
    pub bind_address: String,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub allow_insecure_http: bool,
}

// ----------------------------------------------------------------------------------
#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    /// Enable IP-based rate limiting on auth endpoints (default: false).
    #[serde(default)]
    pub enabled: bool,
    /// Maximum sustained requests per minute per IP on auth endpoints.
    #[serde(default = "default_auth_rpm")]
    pub auth_requests_per_minute: u32,
    /// Initial burst size for auth endpoints — how many requests are allowed immediately.
    #[serde(default = "default_auth_burst")]
    pub auth_burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auth_requests_per_minute: default_auth_rpm(),
            auth_burst_size: default_auth_burst(),
        }
    }
}

// ----------------------------------------------------------------------------------
#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    /// Enable CORS headers (default: false). When disabled no CORS headers are emitted.
    #[serde(default)]
    pub enabled: bool,
    /// Explicit list of allowed origins, e.g. ["https://admin.example.com"].
    /// Ignored when allow_any_origin is true.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Emit `Access-Control-Allow-Origin: *` — allows any origin.
    /// Dangerous for a secrets manager; requires explicit opt-in.
    #[serde(default)]
    pub allow_any_origin: bool,
    /// How long (seconds) browsers may cache preflight responses.
    #[serde(default = "default_cors_max_age")]
    pub max_age_seconds: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_origins: vec![],
            allow_any_origin: false,
            max_age_seconds: default_cors_max_age(),
        }
    }
}

// ----------------------------------------------------------------------------------
#[derive(Debug, Deserialize, Clone)]
pub struct SecurityHeadersConfig {
    /// Emit security headers on every response (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Emit the Strict-Transport-Security header (default: true).
    /// Automatically suppressed when the server runs in HTTP mode.
    #[serde(default = "default_true")]
    pub hsts_enabled: bool,
    /// HSTS max-age in seconds (default: 31536000 = 1 year).
    #[serde(default = "default_hsts_max_age")]
    pub hsts_max_age_seconds: u64,
    /// Add `includeSubDomains` to the HSTS header (default: true).
    #[serde(default = "default_true")]
    pub hsts_include_subdomains: bool,
    /// Add `preload` to the HSTS header (default: false).
    /// Only set this if you intend to submit to the HSTS preload list.
    #[serde(default)]
    pub hsts_preload: bool,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hsts_enabled: true,
            hsts_max_age_seconds: default_hsts_max_age(),
            hsts_include_subdomains: true,
            hsts_preload: false,
        }
    }
}

// ----------------------------------------------------------------------------------
#[derive(Debug, Clone, Default)]
pub enum MasterkeyBackend {
    #[default]
    File,
    Pkcs11,
}

impl<'de> serde::Deserialize<'de> for MasterkeyBackend {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "file" => Ok(MasterkeyBackend::File),
            "pkcs11" => Ok(MasterkeyBackend::Pkcs11),
            _ => Err(serde::de::Error::unknown_variant(&s, &["file", "pkcs11"])),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum MasterkeyFileType {
    Insecure,
    #[default]
    Passphrase,
}

impl<'de> serde::Deserialize<'de> for MasterkeyFileType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "insecure" => Ok(MasterkeyFileType::Insecure),
            "passphrase" => Ok(MasterkeyFileType::Passphrase),
            _ => Err(serde::de::Error::unknown_variant(&s, &["insecure", "passphrase"])),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct MasterKeyConfig {
    pub default_backend: MasterkeyBackend,
    pub default_file_type: MasterkeyFileType,
    pub file: MasterKeyFileConfig,
    /// Explicitly permit the insecure (unencrypted) master key provider.
    /// Must be set to `true` to create or load insecure master keys.
    /// Never enable this in production.
    #[serde(default)]
    pub allow_insecure_masterkey: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MasterKeyFileConfig {
    pub enabled: bool,
    pub allowed_types: Vec<MasterkeyFileType>,
    pub path: Option<String>,
    pub file_mode: Option<String>,
    pub dir_mode: Option<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
    /// Argon2id memory cost in KiB for passphrase-derived master key encryption.
    /// Applies only when creating new passphrase-backed master keys.
    /// Existing keys always use the parameters stored in their key file.
    /// Default: 131072 (128 MiB). Minimum: 32768 (32 MiB).
    #[serde(default = "default_mk_kdf_memory_kib")]
    pub kdf_memory_kib: u32,
    /// Argon2id iteration count for passphrase-derived master key encryption.
    /// Default: 3. Minimum: 1.
    #[serde(default = "default_mk_kdf_time_cost")]
    pub kdf_time_cost: u32,
    /// Argon2id parallelism for passphrase-derived master key encryption.
    /// Default: 1. Minimum: 1.
    #[serde(default = "default_mk_kdf_parallelism")]
    pub kdf_parallelism: u32,
}

impl Default for MasterKeyFileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_types: Vec::new(),
            path: None,
            file_mode: None,
            dir_mode: None,
            owner: None,
            group: None,
            kdf_memory_kib: default_mk_kdf_memory_kib(),
            kdf_time_cost: default_mk_kdf_time_cost(),
            kdf_parallelism: default_mk_kdf_parallelism(),
        }
    }
}

impl MasterKeyFileConfig {
    pub fn validate(&self, default_file_type: &MasterkeyFileType) -> CkResult<()> {
        if !self.enabled {
            return Ok(());
        }

        if self.allowed_types.is_empty() {
            return Err(
                ValidationError::Custom("masterkey.file.allowed_types must have at least one entry".into()).into(),
            );
        }

        if !self.allowed_types.contains(default_file_type) {
            return Err(ValidationError::Custom(
                "masterkey.file.allowed_types must include the default_file_type".into(),
            )
            .into());
        }

        let Some(path) = &self.path else {
            return Err(
                ValidationError::Custom("masterkey.file.path must be set when file backend is enabled".into()).into(),
            );
        };

        if path.trim().is_empty() {
            return Err(ValidationError::Custom("masterkey.file.path must be a non-empty string".into()).into());
        }

        if let Some(ref mode_str) = self.file_mode {
            parse_octal_mode(mode_str, "masterkey.file.file_mode")?;
        }
        if let Some(ref mode_str) = self.dir_mode {
            parse_octal_mode(mode_str, "masterkey.file.dir_mode")?;
        }

        if let Some(owner) = self.owner.as_deref()
            && owner.trim().is_empty()
        {
            return Err(ValidationError::Custom("masterkey.file.owner cannot be an empty string".into()).into());
        }
        if let Some(group) = self.group.as_deref()
            && group.trim().is_empty()
        {
            return Err(ValidationError::Custom("masterkey.file.group cannot be an empty string".into()).into());
        }

        // KDF parameters must meet minimum security thresholds
        if self.kdf_memory_kib < 32 * 1024 {
            return Err(ValidationError::Custom(
                "masterkey.file.kdf_memory_kib must be at least 32768 (32 MiB)".into(),
            )
            .into());
        }
        if self.kdf_time_cost < 1 {
            return Err(ValidationError::Custom("masterkey.file.kdf_time_cost must be at least 1".into()).into());
        }
        if self.kdf_parallelism < 1 {
            return Err(ValidationError::Custom("masterkey.file.kdf_parallelism must be at least 1".into()).into());
        }

        Ok(())
    }
}

impl Config {
    pub fn load_from_file(config_path: &str) -> CkResult<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name(config_path).required(true))
            .add_source(config::Environment::with_prefix("HIERARKEY").separator("__"))
            .build()?;

        let cfg: Config = cfg.try_deserialize()?;

        cfg.validate()?;

        // // Validate master key versions are unique
        // cfg.validate_master_key_versions()?;

        Ok(cfg)
    }

    fn validate(&self) -> CkResult<()> {
        self.database.tls.validate()?;

        if !self.masterkey.file.enabled {
            return Err(ValidationError::Custom(
                "The file master key backend must be enabled. \
                 HSM/PKCS#11 backend is available in the Hierarkey Commercial Edition."
                    .into(),
            )
            .into());
        }

        match self.masterkey.default_backend {
            MasterkeyBackend::File if !self.masterkey.file.enabled => {
                return Err(ValidationError::Custom(
                    "Default master key backend is set to 'file', but file backend is not enabled".into(),
                )
                .into());
            }
            _ => {}
        }

        if self.masterkey.file.enabled {
            self.masterkey.file.validate(&self.masterkey.default_file_type)?
        }

        if !self.masterkey.allow_insecure_masterkey {
            if self.masterkey.default_file_type == MasterkeyFileType::Insecure {
                return Err(ValidationError::Custom(
                    "masterkey.default_file_type is 'insecure' but masterkey.allow_insecure_masterkey is false; \
                     set allow_insecure_masterkey = true to permit the insecure provider (dev/test only)"
                        .into(),
                )
                .into());
            }
            if self.masterkey.file.allowed_types.contains(&MasterkeyFileType::Insecure) {
                return Err(ValidationError::Custom(
                    "masterkey.file.allowed_types contains 'insecure' but masterkey.allow_insecure_masterkey is false; \
                     set allow_insecure_masterkey = true to permit the insecure provider (dev/test only)"
                        .into(),
                )
                .into());
            }
        }

        Ok(())
    }
}

fn parse_octal_mode(s: &str, field: &'static str) -> CkResult<u32> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ValidationError::Custom(format!(" {field}: empty mode")).into());
    }

    // allow "0600" or "600" (treat as octal either way)
    if !s.chars().all(|c| c.is_ascii_digit()) {
        return Err(ValidationError::Custom(format!("{field}: mode must be digits only (octal), got '{s}'")).into());
    }

    // parse as octal
    let mode =
        u32::from_str_radix(s, 8).map_err(|_| ValidationError::Custom(format!("{field}: invalid octal mode '{s}'")))?;

    // only permission bits allowed (0..=0o7777)
    if mode > 0o7777 {
        return Err(ValidationError::Custom(format!("{field}: mode '{s}' out of range (max 07777)")).into());
    }

    Ok(mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_config(content: &str, temp_dir: &TempDir) -> String {
        let config_path = temp_dir.path().join("test_config.toml");
        fs::write(&config_path, content).unwrap();
        config_path.to_str().unwrap().to_string()
    }

    const BASE_CONFIG: &str = r#"
[database]
url = "postgresql://localhost/test"
max_connections = 10
min_connections = 2

[logging]
level = "info"

[server]
mode = "http"
bind_address = "127.0.0.1:8080"
allow_insecure_http = true

[masterkey]
default_backend = "file"
default_file_type = "insecure"
allow_insecure_masterkey = true

[masterkey.file]
enabled = true
allowed_types = ["insecure", "passphrase"]
path = "data/master-keys"
file_mode = "0600"
dir_mode = "0700"
owner = "hierarkey"
group = "hierarkey"
# Argon2id KDF parameters for passphrase-backed master key encryption.
# These apply only when CREATING new keys; existing keys use the parameters
# stored in their key file. Increase for stronger protection at the cost of
# slower unlock time. Minimum: kdf_memory_kib=32768, kdf_time_cost=1, kdf_parallelism=1.
kdf_memory_kib = 131072   # 128 MiB (default)
kdf_time_cost = 3         # iterations (default)
kdf_parallelism = 1       # threads (default)

[masterkey.pkcs11]
enabled = false

[auth]
allow_passphrase_auth = true
allow_ed25519_auth = true
audience = "hierarkey-server"
access_token_ttl_seconds = 900
refresh_token_ttl_seconds = 604800
"#;

    struct ConfigModifier {
        base: String,
    }

    impl ConfigModifier {
        fn new() -> Self {
            Self {
                base: BASE_CONFIG.to_string(),
            }
        }

        fn set(&mut self, path: &str, value: &str) -> &mut Self {
            let parts: Vec<&str> = path.split('.').collect();

            match parts.len() {
                2 => {
                    let section = parts[0];
                    let key = parts[1];
                    self.replace_in_section(section, key, value);
                }
                3 => {
                    let section = format!("{}.{}", parts[0], parts[1]);
                    let key = parts[2];
                    self.replace_in_section(&section, key, value);
                }
                _ => panic!("Invalid path: {path}"),
            }
            self
        }

        fn replace_in_section(&mut self, section: &str, key: &str, value: &str) {
            let section_header = format!("[{section}]");
            let lines: Vec<String> = self.base.lines().map(|s| s.to_string()).collect();
            let mut result = Vec::new();
            let mut in_section = false;
            let mut replaced = false;

            for line in lines {
                if line.trim() == section_header {
                    in_section = true;
                    result.push(line);
                } else if in_section && line.starts_with('[') {
                    if !replaced {
                        result.push(format!("{key} = {value}"));
                        replaced = true;
                    }
                    in_section = false;
                    result.push(line);
                } else if in_section && line.trim().starts_with(key) {
                    result.push(format!("{key} = {value}"));
                    replaced = true;
                } else {
                    result.push(line);
                }
            }

            if in_section && !replaced {
                result.push(format!("{key} = {value}"));
            }

            self.base = result.join("\n");
        }

        fn build(&self, temp_dir: &TempDir) -> String {
            create_test_config(&self.base, temp_dir)
        }
    }

    #[test]
    fn test_generate_template_creates_file() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("config.toml");
        let path_str = path.to_str().unwrap();

        let result = Config::generate_template(path_str);
        assert!(result.is_ok());
        assert!(path.exists());
    }

    #[test]
    fn test_generate_template_fails_if_exists() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("config.toml");
        let path_str = path.to_str().unwrap();

        Config::generate_template(path_str).unwrap();
        let result = Config::generate_template(path_str);

        assert!(result.is_err());
        match result.unwrap_err() {
            CkError::Conflict { what } => assert!(what.contains("already exists")),
            _ => panic!("Expected Conflict error"),
        }
    }

    #[test]
    fn test_load_valid_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_content = r#"
            [database]
            url = "postgresql://localhost/test"

            [logging]
            level = "info"

            [server]
            mode = "http"
            bind_address = "127.0.0.1:8080"
            allow_insecure_http = true

            [masterkey]
            default_backend = "file"
            default_file_type = "passphrase"

            [masterkey.file]
            enabled = true
            allowed_types = ["passphrase"]
            path = "/tmp/masterkey"

            [masterkey.pkcs11]
            enabled = false

            [auth]
            allow_passphrase_auth = true
            allow_ed25519_auth = true
                        audience = "hierarkey-server"
            access_token_ttl_seconds = 900      # 15 minutes
            refresh_token_ttl_seconds = 604800  # 7 days
        "#;

        let config_path = create_test_config(config_content, &temp_dir);
        let result = Config::load_from_file(&config_path);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.database.url, "postgresql://localhost/test");
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn test_default_database_values() {
        let temp_dir = TempDir::new().unwrap();
        let config_content = r#"
            [database]
            url = "postgresql://localhost/test"

            [logging]
            level = "info"

            [server]
            mode = "http"
            bind_address = "127.0.0.1:8080"
            allow_insecure_http = true

            [masterkey]
            default_backend = "file"
            default_file_type = "passphrase"

            [masterkey.file]
            enabled = true
            allowed_types = ["passphrase"]
            path = "/tmp/masterkey"

            [masterkey.pkcs11]
            enabled = false

            [auth]
            allow_passphrase_auth = true
            allow_ed25519_auth = true
                        audience = "hierarkey-server"
            access_token_ttl_seconds = 900      # 15 minutes
            refresh_token_ttl_seconds = 604800  # 7 days
        "#;

        let config_path = create_test_config(config_content, &temp_dir);
        let config = Config::load_from_file(&config_path).unwrap();

        assert_eq!(config.database.max_connections, 10);
        assert_eq!(config.database.min_connections, 2);
        assert_eq!(config.database.idle_timeout_seconds, 600);
        assert_eq!(config.database.max_lifetime_seconds, 1800);
        assert_eq!(config.database.acquire_timeout_seconds, 30);
    }

    #[test]
    fn test_no_backend_enabled_fails() {
        let temp_dir = TempDir::new().unwrap();
        let config_content = r#"
            [database]
            url = "postgresql://localhost/test"

            [logging]
            level = "info"

            [server]
            mode = "http"
            bind_address = "127.0.0.1:8080"
            allow_insecure_http = true

            [masterkey]
            default_backend = "File"
            default_file_type = "Passphrase"

            [masterkey.file]
            enabled = false
            allowed_types = []
            path = ""

            [masterkey.pkcs11]
            enabled = false
        "#;

        let config_path = create_test_config(config_content, &temp_dir);
        let result = Config::load_from_file(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_backend_mismatch_fails() {
        let temp_dir = TempDir::new().unwrap();
        let config_content = r#"
            [database]
            url = "postgresql://localhost/test"

            [logging]
            level = "info"

            [server]
            mode = "http"
            bind_address = "127.0.0.1:8080"
            allow_insecure_http = true

            [masterkey]
            default_backend = "File"
            default_file_type = "Passphrase"

            [masterkey.file]
            enabled = false
            allowed_types = []
            path = ""

            [masterkey.pkcs11]
            enabled = true
            default_module = "/lib/pkcs11.so"
            default_token_label = "token"
        "#;

        let config_path = create_test_config(config_content, &temp_dir);
        let result = Config::load_from_file(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_backend_empty_allowed_types_fails() {
        let config = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![],
            path: Some("/tmp/key".to_string()),
            file_mode: None,
            dir_mode: None,
            owner: None,
            group: None,
            ..Default::default()
        };

        let result = config.validate(&MasterkeyFileType::Passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_backend_default_not_in_allowed_fails() {
        let config = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![MasterkeyFileType::Insecure],
            path: Some("/tmp/key".to_string()),
            file_mode: None,
            dir_mode: None,
            owner: None,
            group: None,
            ..Default::default()
        };

        let result = config.validate(&MasterkeyFileType::Passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_backend_empty_path_fails() {
        let config = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![MasterkeyFileType::Passphrase],
            path: Some("".to_string()),
            file_mode: None,
            dir_mode: None,
            owner: None,
            group: None,
            ..Default::default()
        };

        let result = config.validate(&MasterkeyFileType::Passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_octal_mode_valid() {
        assert_eq!(parse_octal_mode("0600", "test").unwrap(), 0o600);
        assert_eq!(parse_octal_mode("600", "test").unwrap(), 0o600);
        assert_eq!(parse_octal_mode("0755", "test").unwrap(), 0o755);
        assert_eq!(parse_octal_mode("7777", "test").unwrap(), 0o7777);
    }

    #[test]
    fn test_parse_octal_mode_invalid() {
        assert!(parse_octal_mode("", "test").is_err());
        assert!(parse_octal_mode("abc", "test").is_err());
        assert!(parse_octal_mode("999", "test").is_err());
        assert!(parse_octal_mode("10000", "test").is_err());
    }

    #[test]
    fn test_file_mode_validation() {
        let config = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![MasterkeyFileType::Passphrase],
            path: Some("/tmp/key".to_string()),
            file_mode: Some("0600".to_string()),
            dir_mode: Some("0700".to_string()),
            owner: None,
            group: None,
            ..Default::default()
        };

        assert!(config.validate(&MasterkeyFileType::Passphrase).is_ok());
    }

    #[test]
    fn test_file_mode_invalid_fails() {
        let config = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![MasterkeyFileType::Passphrase],
            path: Some("/tmp/key".to_string()),
            file_mode: Some("invalid".to_string()),
            dir_mode: None,
            owner: None,
            group: None,
            ..Default::default()
        };

        assert!(config.validate(&MasterkeyFileType::Passphrase).is_err());
    }

    #[test]
    fn test_empty_owner_group_fails() {
        let config = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![MasterkeyFileType::Passphrase],
            path: Some("/tmp/key".to_string()),
            file_mode: None,
            dir_mode: None,
            owner: Some("".to_string()),
            group: None,
            ..Default::default()
        };

        assert!(config.validate(&MasterkeyFileType::Passphrase).is_err());

        let config = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![MasterkeyFileType::Passphrase],
            path: Some("/tmp/key".to_string()),
            file_mode: None,
            dir_mode: None,
            owner: None,
            group: Some("".to_string()),
            ..Default::default()
        };

        assert!(config.validate(&MasterkeyFileType::Passphrase).is_err());
    }

    #[test]
    fn test_server_mode_display() {
        assert_eq!(ServerMode::Tls.to_string(), "tls");
        assert_eq!(ServerMode::Http.to_string(), "http");
    }

    #[test]
    fn test_database_tls_defaults() {
        let tls_config = DatabaseTlsConfig::default();
        assert!(!tls_config.enabled);
        assert!(!tls_config.verify_server);
        assert!(!tls_config.accept_invalid_certs);
        assert!(!tls_config.accept_invalid_hostnames);
        assert!(!tls_config.allow_insecure_tls);
    }

    #[test]
    fn test_database_tls_accept_invalid_certs_requires_allow_insecure_tls() {
        let tls = DatabaseTlsConfig {
            accept_invalid_certs: true,
            allow_insecure_tls: false,
            ..Default::default()
        };
        assert!(tls.validate().is_err());
    }

    #[test]
    fn test_database_tls_accept_invalid_hostnames_requires_allow_insecure_tls() {
        let tls = DatabaseTlsConfig {
            accept_invalid_hostnames: true,
            allow_insecure_tls: false,
            ..Default::default()
        };
        assert!(tls.validate().is_err());
    }

    #[test]
    fn test_database_tls_accept_invalid_certs_allowed_with_gate() {
        let tls = DatabaseTlsConfig {
            accept_invalid_certs: true,
            allow_insecure_tls: true,
            ..Default::default()
        };
        assert!(tls.validate().is_ok());
    }

    #[test]
    fn test_database_tls_accept_invalid_hostnames_allowed_with_gate() {
        let tls = DatabaseTlsConfig {
            accept_invalid_hostnames: true,
            allow_insecure_tls: true,
            ..Default::default()
        };
        assert!(tls.validate().is_ok());
    }

    #[test]
    fn test_database_tls_safe_defaults_validate_ok() {
        assert!(DatabaseTlsConfig::default().validate().is_ok());
    }

    #[test]
    fn test_base_config_loads() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(BASE_CONFIG, &temp_dir);
        let result = Config::load_from_file(&config_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_file_backend_disabled_fails() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("masterkey.file.enabled", "false")
            .build(&temp_dir);

        let result = Config::load_from_file(&config_path);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("The file master key backend must be enabled"));
    }

    #[test]
    fn test_file_empty_allowed_types_fails() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("masterkey.file.allowed_types", "[]")
            .build(&temp_dir);

        let result = Config::load_from_file(&config_path);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("allowed_types must have at least one entry"));
    }

    #[test]
    fn test_file_default_type_not_in_allowed_fails() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("masterkey.default_file_type", r#""passphrase""#)
            .set("masterkey.file.allowed_types", r#"["insecure"]"#)
            .build(&temp_dir);

        let result = Config::load_from_file(&config_path);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("must include the default_file_type"));
    }

    #[test]
    fn test_file_empty_path_fails() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("masterkey.file.path", r#""""#)
            .build(&temp_dir);

        let result = Config::load_from_file(&config_path);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("path must be a non-empty string"));
    }

    #[test]
    fn test_file_invalid_file_mode_fails() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("masterkey.file.file_mode", r#""invalid""#)
            .build(&temp_dir);

        let result = Config::load_from_file(&config_path);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("mode must be digits only"));
    }

    #[test]
    fn test_file_invalid_dir_mode_fails() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("masterkey.file.dir_mode", r#""9999""#)
            .build(&temp_dir);

        let result = Config::load_from_file(&config_path);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("invalid octal mode"));
    }

    #[test]
    fn test_file_mode_out_of_range_fails() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("masterkey.file.file_mode", r#""10000""#)
            .build(&temp_dir);

        let result = Config::load_from_file(&config_path);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("out of range"));
    }

    #[test]
    fn test_file_empty_owner_fails() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("masterkey.file.owner", r#""""#)
            .build(&temp_dir);

        let result = Config::load_from_file(&config_path);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("owner cannot be an empty string"));
    }

    #[test]
    fn test_file_empty_group_fails() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("masterkey.file.group", r#""""#)
            .build(&temp_dir);

        let result = Config::load_from_file(&config_path);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("group cannot be an empty string"));
    }

    #[test]
    fn test_file_valid_modes_succeed() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("masterkey.file.file_mode", r#""0600""#)
            .set("masterkey.file.dir_mode", r#""0700""#)
            .build(&temp_dir);

        let result = Config::load_from_file(&config_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_database_custom_values() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("database.max_connections", "20")
            .set("database.min_connections", "5")
            .set("database.idle_timeout", "300")
            .set("database.max_lifetime", "900")
            .set("database.acquire_timeout", "60")
            .build(&temp_dir);

        let config = Config::load_from_file(&config_path).unwrap();
        assert_eq!(config.database.max_connections, 20);
        assert_eq!(config.database.min_connections, 5);
        assert_eq!(config.database.idle_timeout_seconds, 300);
        assert_eq!(config.database.max_lifetime_seconds, 900);
        assert_eq!(config.database.acquire_timeout_seconds, 60);
    }

    #[test]
    fn test_server_mode_tls() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("server.mode", r#""tls""#)
            .set("server.cert_path", r#""/path/to/cert.pem""#)
            .set("server.key_path", r#""/path/to/key.pem""#)
            .build(&temp_dir);

        let config = Config::load_from_file(&config_path).unwrap();
        assert!(matches!(config.server.mode, ServerMode::Tls));
    }

    #[test]
    fn test_logging_with_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = ConfigModifier::new()
            .set("logging.log_file", r#""/var/log/app.log""#)
            .build(&temp_dir);

        let config = Config::load_from_file(&config_path).unwrap();
        assert_eq!(config.logging.log_file, Some("/var/log/app.log".to_string()));
    }

    #[test]
    fn test_masterkey_kdf_defaults_are_secure() {
        let cfg = MasterKeyFileConfig::default();
        assert_eq!(cfg.kdf_memory_kib, 128 * 1024, "default memory should be 128 MiB");
        assert_eq!(cfg.kdf_time_cost, 3, "default time cost should be 3");
        assert_eq!(cfg.kdf_parallelism, 1, "default parallelism should be 1");
    }

    #[test]
    fn test_masterkey_kdf_memory_too_low_fails() {
        let cfg = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![MasterkeyFileType::Passphrase],
            path: Some("/tmp/key".into()),
            kdf_memory_kib: 32 * 1024 - 1, // just below minimum
            ..Default::default()
        };
        assert!(cfg.validate(&MasterkeyFileType::Passphrase).is_err());
    }

    #[test]
    fn test_masterkey_kdf_memory_minimum_passes() {
        let cfg = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![MasterkeyFileType::Passphrase],
            path: Some("/tmp/key".into()),
            kdf_memory_kib: 32 * 1024,
            ..Default::default()
        };
        assert!(cfg.validate(&MasterkeyFileType::Passphrase).is_ok());
    }

    #[test]
    fn test_masterkey_kdf_time_cost_zero_fails() {
        let cfg = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![MasterkeyFileType::Passphrase],
            path: Some("/tmp/key".into()),
            kdf_time_cost: 0,
            ..Default::default()
        };
        assert!(cfg.validate(&MasterkeyFileType::Passphrase).is_err());
    }

    #[test]
    fn test_masterkey_kdf_time_cost_minimum_passes() {
        let cfg = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![MasterkeyFileType::Passphrase],
            path: Some("/tmp/key".into()),
            kdf_time_cost: 1,
            ..Default::default()
        };
        assert!(cfg.validate(&MasterkeyFileType::Passphrase).is_ok());
    }

    #[test]
    fn test_masterkey_kdf_parallelism_zero_fails() {
        let cfg = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![MasterkeyFileType::Passphrase],
            path: Some("/tmp/key".into()),
            kdf_parallelism: 0,
            ..Default::default()
        };
        assert!(cfg.validate(&MasterkeyFileType::Passphrase).is_err());
    }

    #[test]
    fn test_masterkey_kdf_parallelism_minimum_passes() {
        let cfg = MasterKeyFileConfig {
            enabled: true,
            allowed_types: vec![MasterkeyFileType::Passphrase],
            path: Some("/tmp/key".into()),
            kdf_parallelism: 1,
            ..Default::default()
        };
        assert!(cfg.validate(&MasterkeyFileType::Passphrase).is_ok());
    }

    #[test]
    fn test_masterkey_kdf_disabled_backend_skips_kdf_validation() {
        // When enabled = false, validation returns Ok regardless of KDF params
        let cfg = MasterKeyFileConfig {
            enabled: false,
            kdf_memory_kib: 0,
            kdf_time_cost: 0,
            kdf_parallelism: 0,
            ..Default::default()
        };
        assert!(cfg.validate(&MasterkeyFileType::Passphrase).is_ok());
    }

    #[test]
    fn test_masterkey_backend_case_insensitive() {
        let temp_dir = TempDir::new().unwrap();
        for value in &["file", "File", "FILE"] {
            let config_path = ConfigModifier::new()
                .set("masterkey.default_backend", &format!(r#""{value}""#))
                .build(&temp_dir);
            let result = Config::load_from_file(&config_path);
            assert!(result.is_ok(), "expected '{value}' to be accepted, got: {:?}", result.err());
        }
    }

    #[test]
    fn test_masterkey_file_type_case_insensitive() {
        let temp_dir = TempDir::new().unwrap();
        for value in &["passphrase", "Passphrase", "PASSPHRASE"] {
            let config_path = ConfigModifier::new()
                .set("masterkey.default_file_type", &format!(r#""{value}""#))
                .build(&temp_dir);
            let result = Config::load_from_file(&config_path);
            assert!(result.is_ok(), "expected '{value}' to be accepted, got: {:?}", result.err());
        }
    }
}
