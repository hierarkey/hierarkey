// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::Actor;
use crate::global::config::{Config, ServerConfig};
use crate::global::utils::file::check_file_permissions;
use crate::global::{
    HTTP_CONCURRENCY_LIMIT, HTTP_GLOBAL_TIMEOUT, HTTP_MAX_BODY_SIZE, HTTP_REQUEST_BODY_TIMEOUT,
    HTTP_RESPONSE_BODY_TIMEOUT,
};
use crate::http_server::api_error::HttpError;
use crate::http_server::middleware::{
    audit_ctx_middleware, auth_middleware, logging_middleware, require_auth_purpose, require_change_password_purpose,
    security_headers_middleware,
};
use crate::http_server::nonce_cache::NonceCache;
use crate::manager::account::AccountId;
use crate::manager::federated_identity::FederatedIdentityManager;
use crate::service::{
    AccountService, AuditService, AuthService, KekService, LicenseService, MasterKeyService, NamespaceService,
    RbacService, SecretService, TokenService,
};
use crate::task_manager::BackgroundTaskManager;
use axum::error_handling::HandleErrorLayer;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware as axum_middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{BoxError, Router};
use axum_server::tls_rustls::RustlsConfig;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode};
use hierarkey_core::{CkError, CkResult};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceBuilder;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::{RequestBodyTimeoutLayer, ResponseBodyTimeoutLayer};
use tracing::{debug, info};

pub mod api_error;
pub mod auth_user;
pub mod extractors;
pub mod federated_auth_provider;
pub mod handlers;
pub mod mfa_provider;
pub mod middleware;
pub mod mtls_provider;
pub mod nonce_cache;

/// Extension point for commercial modules to plug into the server lifecycle.
///
/// - `configure` is called in `build_app_state` before the state is frozen into `Arc`s —
///   use it to register providers (e.g. HSM) with the masterkey service.
/// - `extend_routes` is called before `with_state`, so routes added here have full access
///   to `State<AppState>` extractors.
/// - `extend_layers` is called after all community layers are applied, making it the
///   outermost layer (first to process incoming requests). The `state` parameter gives
///   access to services (e.g. `LicenseService`) for constructing state-aware middleware.
#[async_trait::async_trait]
pub trait ServerExtension: Send + Sync {
    fn configure(&self, _builder: &mut crate::startup::StateBuilder<'_>) -> hierarkey_core::CkResult<()> {
        Ok(())
    }
    fn extend_routes(&self, router: Router<AppState>) -> Router<AppState>;
    fn extend_layers(&self, state: &AppState, router: Router) -> Router;
    async fn init(&self, _state: &AppState) -> hierarkey_core::CkResult<()> {
        Ok(())
    }
}

/// Our global application state that is shared across all request handlers and middleware. It contains
/// references to services, database connection pool, configuration, and other shared resources. We wrap
/// services in Arc to allow cloning the AppState for each request without cloning the underlying
/// services themselves.
#[derive(Clone)]
pub struct AppState {
    /// Default services
    pub masterkey_service: Arc<MasterKeyService>,
    pub secret_service: Arc<SecretService>,
    pub auth_service: Arc<AuthService>,
    pub account_service: Arc<AccountService>,
    pub namespace_service: Arc<NamespaceService>,
    pub kek_service: Arc<KekService>,
    pub token_service: Arc<TokenService>,
    pub rbac_service: Arc<RbacService>,
    pub license_service: Arc<LicenseService>,
    pub audit_service: Arc<AuditService>,

    /// Preloaded system account ID for the "$system" actor
    pub system_account_id: Option<AccountId>,

    /// Database connection pool
    pub pool: PgPool,
    /// Background task manager for managing long-running tasks and graceful shutdown
    pub task_manager: Arc<BackgroundTaskManager>,
    /// Nonce cache for Ed25519 service-account authentication replay prevention
    pub sa_nonce_cache: Arc<NonceCache>,

    /// Per-IP rate limiter for auth endpoints — `None` when rate limiting is disabled
    pub auth_rate_limiter: Option<std::sync::Arc<governor::DefaultKeyedRateLimiter<std::net::IpAddr>>>,

    /// mTLS authentication provider — `None` in community edition (returns 501).
    /// Registered by `MtlsExtension::configure()` in the Commercial Edition.
    pub mtls_auth_provider: Option<std::sync::Arc<dyn mtls_provider::MtlsAuthProvider>>,

    /// Optional MFA provider (commercial only).
    pub mfa_provider: Option<std::sync::Arc<dyn mfa_provider::MfaProvider>>,

    /// Federated authentication providers built from `[[auth.federated]]` config entries.
    /// Empty when no federated providers are configured.
    pub federated_providers: Vec<std::sync::Arc<dyn federated_auth_provider::FederatedAuthProvider>>,

    /// Manager for the `federated_identities` table.
    pub federated_identity_manager: std::sync::Arc<FederatedIdentityManager>,

    /// Global configuration available for reading (preferably not needed)
    pub config: Config,
}

impl AppState {
    /// Returns the AccountId for a given Actor, resolving the "$system" actor to the preloaded
    /// system account ID.
    pub fn actor_account_id(&self, actor: &Actor) -> CkResult<AccountId> {
        match actor {
            Actor::Account(id) => Ok(*id),
            Actor::System => match self.system_account_id {
                Some(id) => Ok(id),
                None => Err(CkError::Custom(
                    "System actor requested but no '$system' found in the database".to_string(),
                )),
            },
        }
    }
}

/// Handle timeout errors from the TimeoutLayer and convert them into HttpError
async fn handle_timeout_error(err: BoxError) -> Response {
    if err.is::<tower::timeout::error::Elapsed>() {
        HttpError {
            http: StatusCode::REQUEST_TIMEOUT,
            fail_code: ApiCode::RequestTimedOut,
            reason: ApiErrorCode::ValidationFailed,
            message: "Request timed out".to_string(),
            details: None,
        }
        .into_response()
    } else {
        HttpError {
            http: StatusCode::INTERNAL_SERVER_ERROR,
            fail_code: ApiCode::InternalError,
            reason: ApiErrorCode::InternalError,
            message: format!("Middleware error: {err}"),
            details: None,
        }
        .into_response()
    }
}

pub fn build_router(state: AppState, extensions: &[Box<dyn ServerExtension>]) -> Router {
    // Build an optional CORS layer from config.
    let cors_layer = build_cors_layer(&state.config.cors);

    let secrets_router = Router::new()
        .route("/", post(handlers::secret::create))
        .route("/search", post(handlers::secret::search))
        // Reveal POSTs the actual secret ref in the body so it won't get logged in URL
        .route("/reveal", post(handlers::secret::reveal))
        .route(
            "/{sec_ref}",
            get(handlers::secret::describe)
                .patch(handlers::secret::update)
                .delete(handlers::secret::delete),
        )
        .route("/{sec_ref}/annotate", patch(handlers::secret::annotate))
        .route("/{sec_ref}/activate", post(handlers::secret::activate))
        .route("/{sec_ref}/revise", post(handlers::secret::revise))
        .route("/{sec_ref}/enable", post(handlers::secret::enable))
        .route("/{sec_ref}/disable", post(handlers::secret::disable))
        .route("/{sec_id}/restore", post(handlers::secret::restore))
        .layer(axum_middleware::from_fn(require_auth_purpose));

    let namespaces_router = Router::new()
        .route("/", post(handlers::namespace::create))
        .route("/search", get(handlers::namespace::search))
        .route("/id/{id}", get(handlers::namespace::describe_by_id))
        .route(
            "/{ns}",
            get(handlers::namespace::describe)
                .patch(handlers::namespace::update)
                .delete(handlers::namespace::delete),
        )
        .route("/{ns}/disable", post(handlers::namespace::disable))
        .route("/{ns}/enable", post(handlers::namespace::enable))
        .route("/{ns}/rotate-kek", post(handlers::namespace::rotate_kek))
        .route("/{ns}/rewrap-deks", post(handlers::namespace::rewrap_deks))
        .layer(axum_middleware::from_fn(require_auth_purpose));

    let accounts_router = Router::new()
        .merge(
            Router::new()
                .route("/", post(handlers::account::create))
                .route("/search", post(handlers::account::search))
                .route("/{account}", get(handlers::account::describe))
                .route("/{account}", patch(handlers::account::update))
                .route("/{account}", delete(handlers::account::delete))
                .route("/{account}/promote", post(handlers::account::promote))
                .route("/{account}/demote", post(handlers::account::demote))
                .route("/{account}/lock", post(handlers::account::lock))
                .route("/{account}/unlock", post(handlers::account::unlock))
                .route("/{account}/disable", post(handlers::account::disable))
                .route("/{account}/enable", post(handlers::account::enable))
                .route("/{account}/cert", post(handlers::account::set_cert))
                .route(
                    "/{account}/federated-identity",
                    post(handlers::account::federated_identity_link),
                )
                .route(
                    "/{account}/federated-identity",
                    get(handlers::account::federated_identity_describe),
                )
                .route(
                    "/{account}/federated-identity",
                    delete(handlers::account::federated_identity_unlink),
                )
                .route_layer(axum_middleware::from_fn(require_auth_purpose)),
        )
        .merge(
            Router::new()
                .route("/{account}/password", post(handlers::account::change_password))
                .route_layer(axum_middleware::from_fn(require_change_password_purpose)),
        );

    let auth_router = Router::new()
        .route("/login", post(handlers::auth::login))
        .route("/refresh", post(handlers::auth::refresh))
        .route("/service-account/token", post(handlers::auth::token))
        .route("/mfa/verify", post(handlers::auth::mfa_verify))
        .route("/federated", get(handlers::auth::list_providers))
        .route("/federated/{provider_id}", post(handlers::auth::federated))
        .route("/whoami", get(handlers::auth::whoami))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_rate_limit_middleware,
        ));

    let pat_router = Router::new()
        .route("/", post(handlers::pat::create).get(handlers::pat::list))
        .route("/{id}", delete(handlers::pat::revoke))
        .layer(axum_middleware::from_fn(require_auth_purpose));

    let rbac_router = Router::new()
        .route("/role", post(handlers::rbac::role::create))
        .route("/role/search", post(handlers::rbac::role::search))
        .route(
            "/role/{name}",
            get(handlers::rbac::role::describe).patch(handlers::rbac::role::update),
        )
        .route("/role/{name}/rules", post(handlers::rbac::role::add))
        .route("/rule", post(handlers::rbac::rule::create))
        .route("/rule/search", post(handlers::rbac::rule::search))
        .route(
            "/rule/{id}",
            get(handlers::rbac::rule::describe).delete(handlers::rbac::rule::delete),
        )
        .route("/bind", post(handlers::rbac::bind::bind))
        .route("/unbind", post(handlers::rbac::unbind::unbind))
        .route("/bindings", post(handlers::rbac::bindings::bindings))
        .route("/bindings/all", post(handlers::rbac::bindings::bindings_all))
        .route("/explain", post(handlers::rbac::explain::explain))
        .layer(axum_middleware::from_fn(require_auth_purpose));

    let masterkeys_router = Router::new()
        .route("/", post(handlers::masterkey::create).get(handlers::masterkey::status))
        .route(
            "/{name}",
            get(handlers::masterkey::describe).delete(handlers::masterkey::delete),
        )
        .route("/{name}/lock", post(handlers::masterkey::lock))
        .route("/{name}/unlock", post(handlers::masterkey::unlock))
        .route("/{name}/activate", post(handlers::masterkey::activate))
        .route("/{name}/rewrap-keks", post(handlers::masterkey::rewrap_keks))
        .layer(axum_middleware::from_fn(require_auth_purpose));

    let system_router = Router::new()
        .route("/about", get(handlers::system::about_admin))
        .route("/status", get(handlers::system::system_status))
        .layer(axum_middleware::from_fn(require_auth_purpose));

    let audit_router = Router::new()
        .route("/events", post(handlers::audit::events::events))
        .route("/verify", post(handlers::audit::verify::verify))
        .layer(axum_middleware::from_fn(require_auth_purpose));

    // All /v1 routes are protected with auth middleware. Extensions may add
    // additional routes before state is bound.
    let mut v1_typed: Router<AppState> = Router::new()
        .nest("/pat", pat_router)
        .nest("/accounts", accounts_router)
        .nest("/secrets", secrets_router)
        .nest("/rbac", rbac_router)
        .nest("/namespaces", namespaces_router)
        .nest("/masterkeys", masterkeys_router)
        .nest("/system", system_router)
        .nest("/audit", audit_router);

    for ext in extensions {
        v1_typed = ext.extend_routes(v1_typed);
    }

    let v1 = v1_typed
        .with_state(state.clone())
        .layer(axum_middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Clone before .with_state(state) consumes it — needed for state-aware middleware layers.
    let state_for_security_headers = state.clone();
    let state_for_extensions = state.clone();

    // Build base router before consuming state — extensions may add state-aware routes here.
    let mut base = Router::new()
        .route("/", get(handlers::index))
        .route("/about", get(handlers::system::about_public))
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .nest("/v1", v1)
        .nest("/v1/auth", auth_router);

    for ext in extensions {
        base = ext.extend_routes(base);
    }

    let mut router = base
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(HTTP_MAX_BODY_SIZE))
        .layer(DefaultBodyLimit::max(HTTP_MAX_BODY_SIZE))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_timeout_error))
                .timeout(Duration::from_secs(HTTP_GLOBAL_TIMEOUT)),
        )
        .layer(
            ServiceBuilder::new()
                .layer(RequestBodyTimeoutLayer::new(Duration::from_secs(HTTP_REQUEST_BODY_TIMEOUT)))
                .layer(ResponseBodyTimeoutLayer::new(Duration::from_secs(HTTP_RESPONSE_BODY_TIMEOUT))),
        )
        .layer(ConcurrencyLimitLayer::new(HTTP_CONCURRENCY_LIMIT))
        .layer(axum_middleware::from_fn(logging_middleware))
        // AuditCTX will run before logging, so logging can use trace/request id
        .layer(axum_middleware::from_fn(audit_ctx_middleware))
        .layer(axum_middleware::from_fn_with_state(
            state_for_security_headers,
            security_headers_middleware,
        ));
    // Note: last layer in axum runs first

    if let Some(layer) = cors_layer {
        router = router.layer(layer);
    }

    // Extensions add their outermost layers last (e.g. PrometheusMetricLayer).
    for ext in extensions {
        router = ext.extend_layers(&state_for_extensions, router);
    }

    router
}

fn build_cors_layer(cfg: &crate::global::config::CorsConfig) -> Option<CorsLayer> {
    if !cfg.enabled {
        return None;
    }

    let origin = if cfg.allow_any_origin {
        tracing::warn!("CORS: allow_any_origin is enabled — any origin is permitted (dangerous for a secrets manager)");
        AllowOrigin::any()
    } else {
        let origins: Vec<HeaderValue> = cfg
            .allowed_origins
            .iter()
            .filter_map(|o| {
                HeaderValue::from_str(o)
                    .inspect_err(|_| tracing::warn!("CORS: invalid origin '{}' — skipping", o))
                    .ok()
            })
            .collect();

        if origins.is_empty() {
            tracing::warn!("CORS: enabled but no valid origins configured — CORS headers will not be sent");
            return None;
        }

        AllowOrigin::list(origins)
    };

    Some(
        CorsLayer::new()
            .allow_origin(origin)
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
            .max_age(Duration::from_secs(cfg.max_age_seconds)),
    )
}

pub async fn start_http_server(server_cfg: &ServerConfig, app: Router) -> CkResult<()> {
    let listener = tokio::net::TcpListener::bind(&server_cfg.bind_address).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            if let Err(e) = shutdown_signal().await {
                tracing::error!("shutdown signal listener failed: {e}");
            }
        })
        .await
        .map_err(|e| CkError::Custom(format!("HTTP server error: {e}")))?;

    Ok(())
}

pub async fn start_tls_server(server_cfg: &ServerConfig, app: Router) -> CkResult<()> {
    let bind_address = &server_cfg.bind_address;
    let cert_path = server_cfg
        .cert_path
        .as_ref()
        .ok_or_else(|| CkError::Custom("TLS mode requires cert_path".into()))?;
    debug!("Using TLS cert at {}", cert_path);
    let key_path = server_cfg
        .key_path
        .as_ref()
        .ok_or_else(|| CkError::Custom("TLS mode requires key_path".into()))?;
    debug!("Using TLS key at {}", key_path);

    // We will first check if the key_path is a file and 0600 permissions
    // This is a TOCTOU race condition but better than nothing. It's a sanity-check for users
    // who might accidentally set insecure permissions on the key file.
    let path = &PathBuf::from_str(key_path).map_err(|e| CkError::Custom(e.to_string()))?;
    if !path.exists() {
        return Err(CkError::FileNotFound(format!("TLS key file {key_path} does not exist")));
    }
    if !check_file_permissions(path)? {
        return Err(CkError::FilePermissions(format!(
            "TLS key file {key_path} has insecure permissions (must be 0600)"
        )));
    }

    let tls_config = RustlsConfig::from_pem_file(cert_path.as_str(), key_path.as_str())
        .await
        .map_err(|e| CkError::Custom(format!("failed to load TLS config: {e}")))?;

    info!("Starting TLS server on {}", bind_address);

    let addr = SocketAddr::from_str(bind_address)
        .map_err(|e| CkError::Custom(format!("invalid bind address {bind_address}: {e}")))?;

    let handle = axum_server::Handle::new();

    // Spawn signal listener that triggers shutdown on the handle.
    tokio::spawn({
        let handle = handle.clone();
        async move {
            if let Err(e) = shutdown_signal().await {
                tracing::error!("shutdown signal listener failed: {e}");
            }
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
        }
    });

    axum_server::bind_rustls(addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| CkError::Custom(format!("TLS server error: {e}")))?;

    Ok(())
}

async fn shutdown_signal() -> CkResult<()> {
    // Ctrl-C (SIGINT)
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| CkError::Custom(format!("failed to install Ctrl-C handler: {e}")))?;
        Ok::<(), CkError>(())
    };

    // SIGTERM
    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{SignalKind, signal as unix_signal};
        let mut sig = unix_signal(SignalKind::terminate())
            .map_err(|e| CkError::Custom(format!("failed to install SIGTERM handler: {e}")))?;
        sig.recv().await;
        Ok::<(), CkError>(())
    };

    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }

    println!("- Shutdown signal received. Shutting down...");
    tracing::info!("Shutdown signal received. Shutting down.");

    Ok(())
}
