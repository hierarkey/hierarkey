// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::global::config::Config;
use crate::global::utils::file::check_file_permissions;
use hierarkey_core::{CkError, CkResult};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::str::FromStr;
use tracing::warn;

/// Create a PgPool and run migrations on startup.
pub async fn create_pool(cfg: &Config) -> CkResult<PgPool> {
    let mut connect_opts = PgConnectOptions::from_str(&cfg.database.url)?;

    if cfg.database.tls.enabled {
        // Belt-and-suspenders: config validation should have caught this, but
        // guard again in case create_pool is ever called with an unvalidated config.
        let insecure_certs = cfg.database.tls.accept_invalid_certs && cfg.database.tls.allow_insecure_tls;
        let insecure_hostnames = cfg.database.tls.accept_invalid_hostnames && cfg.database.tls.allow_insecure_tls;

        if insecure_certs {
            warn!(
                "SECURITY WARNING: Database TLS certificate validation is DISABLED (accept_invalid_certs = true). \
                   The server will accept any certificate, including self-signed or expired ones. \
                   This must NOT be used in production."
            );
        }
        if insecure_hostnames {
            warn!(
                "SECURITY WARNING: Database TLS hostname validation is DISABLED (accept_invalid_hostnames = true). \
                   The server will not verify that the certificate matches the database hostname. \
                   This must NOT be used in production."
            );
        }

        let tls_mode = if insecure_certs {
            PgSslMode::Require // skip cert + hostname validation
        } else if insecure_hostnames {
            PgSslMode::VerifyCa // verify cert, skip hostname check
        } else if cfg.database.tls.verify_server {
            PgSslMode::VerifyFull // verify cert + hostname (recommended)
        } else {
            // TLS is enabled but verify_server = false: require TLS encryption
            // but skip certificate/hostname validation.  Emit a warning so
            // operators know they are not getting full protection.
            warn!(
                "SECURITY WARNING: Database TLS is enabled but verify_server = false. \
                 The connection is encrypted but the server certificate is NOT verified. \
                 Set verify_server = true and supply a CA certificate for full protection."
            );
            PgSslMode::Require
        };

        connect_opts = connect_opts.application_name("hierarkey").ssl_mode(tls_mode);

        if let Some(ca_cert) = &cfg.database.tls.ca_cert_path {
            connect_opts = connect_opts.ssl_root_cert(ca_cert);
        };
        if let Some(client_cert) = &cfg.database.tls.client_cert_path {
            connect_opts = connect_opts.ssl_client_cert(client_cert);
        };
        if let Some(client_key) = &cfg.database.tls.client_key_path {
            // Open the key file and check permissions on the open fd (fstat, not stat)
            // to avoid a TOCTOU race between the check and sqlx re-opening the file.
            let key_file = std::fs::File::open(client_key)
                .map_err(|e| CkError::FilePermissions(format!("Cannot open client key file '{client_key}': {e}")))?;
            if !check_file_permissions(&key_file)? {
                warn!(
                    "Client key file '{}' has insecure permissions. It is mandatory to set the file permissions to be readable only by the owner.",
                    client_key
                );
                return Err(CkError::FilePermissions("Insecure client key file permissions".to_string()));
            }

            connect_opts = connect_opts.ssl_client_key(client_key);
        };
    } else {
        connect_opts = connect_opts.ssl_mode(PgSslMode::Disable);
    }

    let pool = PgPoolOptions::new()
        .max_connections(cfg.database.max_connections)
        .min_connections(cfg.database.min_connections)
        .acquire_timeout(std::time::Duration::from_secs(cfg.database.acquire_timeout_seconds))
        .idle_timeout(std::time::Duration::from_secs(cfg.database.idle_timeout_seconds))
        .max_lifetime(std::time::Duration::from_secs(cfg.database.max_lifetime_seconds))
        .connect_with(connect_opts)
        .await?;

    Ok(pool)
}
