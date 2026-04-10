// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::global::config::Config;
use crate::http_server::AppState;
use crate::http_server::nonce_cache::NonceCache;
use crate::manager::account::{AccountId, AccountManager, InMemoryAccountStore};
use crate::manager::kek::{InMemoryKekStore, KekManager};
use crate::manager::masterkey::InMemoryMasterKeyStore;
use crate::manager::namespace::{InMemoryNamespaceStore, NamespaceManager};
use crate::manager::rbac::InMemoryRbacStore;
use crate::manager::secret::memory_store::InMemorySecretStore;
use crate::manager::token::InMemoryTokenStore;
use crate::service::masterkey::MasterKeyProviderType;
use crate::service::masterkey::provider::TestMasterKeyProvider;
use crate::service::{
    AccountService, AuditService, AuthService, KekService, LicenseService, MasterKeyService, NamespaceService,
    RbacService, SecretService, TokenService,
};
use crate::task_manager::BackgroundTaskManager;
use crate::{MasterKeyManager, RbacManager, SecretManager, TokenManager};
use sqlx::PgPool;
use std::sync::Arc;

// Helper function to create a mock AppState for testing
pub fn create_mock_app_state() -> AppState {
    let task_manager = Arc::new(BackgroundTaskManager::new());

    let store = Arc::new(InMemoryMasterKeyStore::new());
    let manager = Arc::new(MasterKeyManager::new(store).unwrap());

    let provider = TestMasterKeyProvider::new();
    let mut masterkey_service = MasterKeyService::new(manager.clone());
    masterkey_service.add_provider(MasterKeyProviderType::Insecure, Box::new(provider));
    let masterkey_service = Arc::new(masterkey_service);

    let store = Arc::new(InMemoryKekStore::new());
    let kek_manager = Arc::new(KekManager::new(store));

    let store = Arc::new(InMemoryNamespaceStore::new());
    let ns_manager = Arc::new(NamespaceManager::new(store));

    let store = Arc::new(InMemorySecretStore::new());
    let secret_manager = Arc::new(SecretManager::new(store));

    let store = Arc::new(InMemoryTokenStore::new());
    let token_manager = Arc::new(TokenManager::new(store));
    let token_service = Arc::new(TokenService::new(token_manager.clone()));

    let system_account_id = AccountId::new();
    let account_store = Arc::new(InMemoryAccountStore::new());
    account_store.seed_admin(system_account_id);
    let store = account_store;
    let account_manager = Arc::new(AccountManager::new(store));

    let store = Arc::new(InMemoryRbacStore::new());
    let rbac_manager = Arc::new(RbacManager::new(store));

    let kek_service = Arc::new(KekService::new(
        kek_manager.clone(),
        masterkey_service.clone(),
        std::time::Duration::from_secs(15 * 60),
        task_manager.clone(),
    ));
    let rbac_service = Arc::new(RbacService::new(rbac_manager.clone()));

    let secret_service = Arc::new(SecretService::new(
        ns_manager.clone(),
        secret_manager.clone(),
        kek_service.clone(),
        rbac_service.clone(),
    ));

    let auth_service = AuthService::new(account_manager.clone(), token_manager.clone(), &Default::default())
        .expect("Failed to create AuthService");
    let auth_service = Arc::new(auth_service);
    let account_service = Arc::new(AccountService::new(account_manager.clone(), token_manager.clone()));
    let namespace_service = Arc::new(NamespaceService::new(
        ns_manager.clone(),
        kek_service.clone(),
        rbac_service.clone(),
    ));

    let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();

    let sa_nonce_cache = Arc::new(NonceCache::new(std::time::Duration::from_secs(120)));

    let license_service = Arc::new(LicenseService::new());
    let audit_service = Arc::new(AuditService::new(pool.clone(), license_service.clone()));

    let pool_for_fi = pool.clone();
    AppState {
        pool,
        secret_service,
        account_service,
        auth_service,
        namespace_service,
        masterkey_service,
        kek_service,
        token_service,
        rbac_service,
        license_service,
        audit_service,
        system_account_id: Some(system_account_id),
        auth_rate_limiter: None,
        mtls_auth_provider: None,
        task_manager,
        config: Config::default(),
        sa_nonce_cache,
        mfa_provider: None,
        federated_providers: vec![],
        federated_identity_manager: std::sync::Arc::new(
            crate::manager::federated_identity::FederatedIdentityManager::new(pool_for_fi),
        ),
    }
}
