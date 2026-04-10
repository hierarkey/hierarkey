// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use serde::{Deserialize, Serialize};

/// ResourceKind represents the type of resource involved in an API operation, such as secrets, namespaces, authentication, etc.
/// This allows API responses to include structured metadata about what kind of resource was affected by the operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Secret,
    Namespace,
    Kek,
    Auth,
    Account,
    Rbac,
    Mfa,
    Enrollment,
    AccountPassword,
    RbacRole,
    RbacBinding,
    RbacPermission,
    Global,
    Masterkey,
    RbacRule,
    Audit,
}

impl std::fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ResourceKind::Secret => "secret",
            ResourceKind::Namespace => "namespace",
            ResourceKind::Kek => "kek",
            ResourceKind::Auth => "auth",
            ResourceKind::Account => "account",
            ResourceKind::Rbac => "rbac",
            ResourceKind::Mfa => "mfa",
            ResourceKind::Enrollment => "enrollment",
            ResourceKind::AccountPassword => "account_password",
            ResourceKind::RbacRole => "rbac_role",
            ResourceKind::RbacRule => "rbac_rule",
            ResourceKind::Audit => "audit",
            ResourceKind::RbacBinding => "rbac_binding",
            ResourceKind::RbacPermission => "rbac_permission",
            ResourceKind::Global => "global",
            ResourceKind::Masterkey => "masterkey",
        };

        write!(f, "{s}")
    }
}

/// Operation represents the type of action performed in an API operation, such as creating, updating, deleting, etc.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Create,
    Update,
    Delete,
    Rotate,         // e.g. rotate KEK
    CreateRevision, // for secrets
    Activate,
    Deactivate,
    Fetch,
    List,
    Disable,
    Enable,
    Destroy,
    Rewrap,
    Rekey,
    Login,
    Enrollment,
    Complete,
    ChallengeRequired,
    Grant,
    Revoke,
    Reveal,
    Global,
    PwdChangeRequired,
    Promote,
    Demote,
    Lock,
    Unlock,
    Restore,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Operation::Create => "create",
            Operation::Update => "update",
            Operation::Delete => "delete",
            Operation::Rotate => "rotate",
            Operation::CreateRevision => "create_revision",
            Operation::Activate => "activate",
            Operation::Deactivate => "deactivate",
            Operation::Fetch => "fetch",
            Operation::List => "list",
            Operation::Disable => "disable",
            Operation::Enable => "enable",
            Operation::Destroy => "destroy",
            Operation::Rewrap => "rewrap",
            Operation::Rekey => "rekey",
            Operation::Login => "login",
            Operation::Enrollment => "enrollment",
            Operation::Complete => "complete",
            Operation::ChallengeRequired => "challenge_required",
            Operation::Grant => "grant",
            Operation::Revoke => "revoke",
            Operation::Reveal => "reveal",
            Operation::Global => "global",
            Operation::PwdChangeRequired => "pwd_change_required",
            Operation::Promote => "promote",
            Operation::Demote => "demote",
            Operation::Lock => "lock",
            Operation::Unlock => "unlock",
            Operation::Restore => "restore",
        };
        write!(f, "{s}")
    }
}

/// Outcome represents whether an API operation succeeded or failed. This allows API responses to include structured metadata about the result of the operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
        };
        write!(f, "{s}")
    }
}

/// ApiErrorBody represents the structure of error details included in API responses when an operation fails. It includes a machine-readable error code,
/// a human-readable message, and optional additional details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: ApiErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// ApiStatus represents the status of an API operation, including the resource kind, operation type, outcome, and a specific API code.
/// This structured metadata allows clients to understand the context of the response and handle it appropriately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiStatus {
    pub resource: ResourceKind,
    pub operation: Operation,
    pub outcome: Outcome,
    pub code: ApiCode,
    /// Human readable message describing the status.
    pub message: String,
}

impl std::fmt::Display for ApiStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}: {}",
            self.operation.to_string().to_uppercase(),
            self.resource.to_string().to_uppercase(),
            self.outcome.to_string().to_uppercase(),
            self.message
        )
    }
}

impl ApiStatus {
    /// From an API code, we can derive the resource kind, operation, and outcome. This allows us to construct a
    /// consistent ApiStatus for any given API code, ensuring that all responses include structured metadata about
    /// the operation performed.
    fn derive(code: ApiCode) -> (ResourceKind, Operation, Outcome) {
        match code {
            ApiCode::SecretCreated => (ResourceKind::Secret, Operation::Create, Outcome::Success),
            ApiCode::SecretCreateFailed => (ResourceKind::Secret, Operation::Create, Outcome::Failure),
            ApiCode::SecretUpdated => (ResourceKind::Secret, Operation::Update, Outcome::Success),
            ApiCode::SecretUpdateFailed => (ResourceKind::Secret, Operation::Update, Outcome::Failure),
            ApiCode::SecretDeleted => (ResourceKind::Secret, Operation::Delete, Outcome::Success),
            ApiCode::SecretDeleteFailed => (ResourceKind::Secret, Operation::Delete, Outcome::Failure),
            ApiCode::SecretRevisionCreated => (ResourceKind::Secret, Operation::CreateRevision, Outcome::Success),
            ApiCode::SecretRevisionCreateFailed => (ResourceKind::Secret, Operation::CreateRevision, Outcome::Failure),
            ApiCode::SecretRevisionActivated => (ResourceKind::Secret, Operation::Activate, Outcome::Success),
            ApiCode::SecretRevisionActivateFailed => (ResourceKind::Secret, Operation::Activate, Outcome::Failure),
            ApiCode::SecretRevisionDeactivated => (ResourceKind::Secret, Operation::Deactivate, Outcome::Success),
            ApiCode::SecretRevisionDeactivateFailed => (ResourceKind::Secret, Operation::Deactivate, Outcome::Failure),
            ApiCode::SecretAnnotated => (ResourceKind::Secret, Operation::Update, Outcome::Success),
            ApiCode::SecretAnnotateFailed => (ResourceKind::Secret, Operation::Update, Outcome::Failure),
            ApiCode::SecretFetched => (ResourceKind::Secret, Operation::Fetch, Outcome::Success),
            ApiCode::SecretFetchFailed => (ResourceKind::Secret, Operation::Fetch, Outcome::Failure),
            ApiCode::SecretListed => (ResourceKind::Secret, Operation::List, Outcome::Success),
            ApiCode::SecretRevisionFetched => (ResourceKind::Secret, Operation::Fetch, Outcome::Success),
            ApiCode::SecretDisabled => (ResourceKind::Secret, Operation::Disable, Outcome::Success),
            ApiCode::SecretDisableFailed => (ResourceKind::Secret, Operation::Disable, Outcome::Failure),
            ApiCode::SecretEnabled => (ResourceKind::Secret, Operation::Enable, Outcome::Success),
            ApiCode::SecretEnableFailed => (ResourceKind::Secret, Operation::Enable, Outcome::Failure),
            ApiCode::SecretDestroyed => (ResourceKind::Secret, Operation::Destroy, Outcome::Success),
            ApiCode::SecretDestroyFailed => (ResourceKind::Secret, Operation::Destroy, Outcome::Failure),
            ApiCode::SecretRewrapped => (ResourceKind::Secret, Operation::Rewrap, Outcome::Success),
            ApiCode::SecretRewrapFailed => (ResourceKind::Secret, Operation::Rewrap, Outcome::Failure),
            ApiCode::SecretRekeyed => (ResourceKind::Secret, Operation::Rekey, Outcome::Success),
            ApiCode::SecretRekeyFailed => (ResourceKind::Secret, Operation::Rekey, Outcome::Failure),
            ApiCode::SecretRestored => (ResourceKind::Secret, Operation::Restore, Outcome::Success),
            ApiCode::SecretRestoreFailed => (ResourceKind::Secret, Operation::Restore, Outcome::Failure),

            ApiCode::NamespaceCreated => (ResourceKind::Namespace, Operation::Create, Outcome::Success),
            ApiCode::NamespaceCreateFailed => (ResourceKind::Namespace, Operation::Create, Outcome::Failure),
            ApiCode::NamespaceUpdated => (ResourceKind::Namespace, Operation::Update, Outcome::Success),
            ApiCode::NamespaceUpdateFailed => (ResourceKind::Namespace, Operation::Update, Outcome::Failure),
            ApiCode::NamespaceDeleted => (ResourceKind::Namespace, Operation::Delete, Outcome::Success),
            ApiCode::NamespaceDeleteFailed => (ResourceKind::Namespace, Operation::Delete, Outcome::Failure),
            ApiCode::NamespaceDisabled => (ResourceKind::Namespace, Operation::Disable, Outcome::Success),
            ApiCode::NamespaceDisableFailed => (ResourceKind::Namespace, Operation::Disable, Outcome::Failure),
            ApiCode::NamespaceEnabled => (ResourceKind::Namespace, Operation::Enable, Outcome::Success),
            ApiCode::NamespaceEnableFailed => (ResourceKind::Namespace, Operation::Enable, Outcome::Failure),
            ApiCode::NamespaceDestroyed => (ResourceKind::Namespace, Operation::Destroy, Outcome::Success),
            ApiCode::NamespaceDestroyFailed => (ResourceKind::Namespace, Operation::Destroy, Outcome::Failure),
            ApiCode::NamespaceFetched => (ResourceKind::Namespace, Operation::Fetch, Outcome::Success),
            ApiCode::NamespaceFetchFailed => (ResourceKind::Namespace, Operation::Fetch, Outcome::Failure),
            ApiCode::NamespaceListed => (ResourceKind::Namespace, Operation::List, Outcome::Success),
            ApiCode::KekCreated => (ResourceKind::Kek, Operation::Create, Outcome::Success),
            ApiCode::KekCreateFailed => (ResourceKind::Kek, Operation::Create, Outcome::Failure),
            ApiCode::KekRotated => (ResourceKind::Kek, Operation::Rotate, Outcome::Success),
            ApiCode::KekRotateFailed => (ResourceKind::Kek, Operation::Rotate, Outcome::Failure),
            ApiCode::KekDisabled => (ResourceKind::Kek, Operation::Disable, Outcome::Success),
            ApiCode::KekDisableFailed => (ResourceKind::Kek, Operation::Disable, Outcome::Failure),
            ApiCode::KekEnabled => (ResourceKind::Kek, Operation::Enable, Outcome::Success),
            ApiCode::KekEnableFailed => (ResourceKind::Kek, Operation::Enable, Outcome::Failure),
            ApiCode::AuthLoginSucceeded => (ResourceKind::Auth, Operation::Login, Outcome::Success),
            ApiCode::AuthLoginFailed => (ResourceKind::Auth, Operation::Login, Outcome::Failure),
            ApiCode::AuthTokenIssued => (ResourceKind::Auth, Operation::Create, Outcome::Success),
            ApiCode::AuthTokenIssueFailed => (ResourceKind::Auth, Operation::Create, Outcome::Failure),
            ApiCode::AuthWhoamiSucceeded => (ResourceKind::Auth, Operation::Fetch, Outcome::Success),
            ApiCode::MfaEnrollmentStarted => (ResourceKind::Enrollment, Operation::Create, Outcome::Success),
            ApiCode::MfaEnrollmentStartFailed => (ResourceKind::Enrollment, Operation::Create, Outcome::Failure),
            ApiCode::MfaEnrollmentCompleted => (ResourceKind::Enrollment, Operation::Complete, Outcome::Success),
            ApiCode::MfaEnrollmentCompleteFailed => (ResourceKind::Enrollment, Operation::Complete, Outcome::Failure),
            ApiCode::MfaChallengeRequired => (ResourceKind::Mfa, Operation::ChallengeRequired, Outcome::Success),
            ApiCode::MfaChallengeFailed => (ResourceKind::Mfa, Operation::ChallengeRequired, Outcome::Failure),
            ApiCode::MfaDisabled => (ResourceKind::Mfa, Operation::Disable, Outcome::Success),
            ApiCode::MfaDisableFailed => (ResourceKind::Mfa, Operation::Disable, Outcome::Failure),
            ApiCode::AccountCreated => (ResourceKind::Account, Operation::Create, Outcome::Success),
            ApiCode::AccountCreateFailed => (ResourceKind::Account, Operation::Create, Outcome::Failure),
            ApiCode::AccountUpdated => (ResourceKind::Account, Operation::Update, Outcome::Success),
            ApiCode::AccountUpdateFailed => (ResourceKind::Account, Operation::Update, Outcome::Failure),
            ApiCode::AccountDeleted => (ResourceKind::Account, Operation::Delete, Outcome::Success),
            ApiCode::AccountDeleteFailed => (ResourceKind::Account, Operation::Delete, Outcome::Failure),
            ApiCode::AccountDisabled => (ResourceKind::Account, Operation::Disable, Outcome::Success),
            ApiCode::AccountDisableFailed => (ResourceKind::Account, Operation::Disable, Outcome::Failure),
            ApiCode::AccountEnabled => (ResourceKind::Account, Operation::Enable, Outcome::Success),
            ApiCode::AccountEnableFailed => (ResourceKind::Account, Operation::Enable, Outcome::Failure),
            ApiCode::AccountPasswordRotated => (ResourceKind::AccountPassword, Operation::Rotate, Outcome::Success),
            ApiCode::AccountPasswordRotateFailed => {
                (ResourceKind::AccountPassword, Operation::Rotate, Outcome::Failure)
            }
            ApiCode::RbacRoleCreated => (ResourceKind::RbacRole, Operation::Create, Outcome::Success),
            ApiCode::RbacRoleCreateFailed => (ResourceKind::RbacRole, Operation::Create, Outcome::Failure),
            ApiCode::RbacRoleUpdated => (ResourceKind::RbacRole, Operation::Update, Outcome::Success),
            ApiCode::RbacRoleUpdateFailed => (ResourceKind::RbacRole, Operation::Update, Outcome::Failure),
            ApiCode::RbacRoleDeleted => (ResourceKind::RbacRole, Operation::Delete, Outcome::Success),
            ApiCode::RbacRoleDeleteFailed => (ResourceKind::RbacRole, Operation::Delete, Outcome::Failure),
            ApiCode::RbacBindingCreated => (ResourceKind::RbacBinding, Operation::Create, Outcome::Success),
            ApiCode::RbacBindingCreateFailed => (ResourceKind::RbacBinding, Operation::Create, Outcome::Failure),
            ApiCode::RbacBindingDeleted => (ResourceKind::RbacBinding, Operation::Delete, Outcome::Success),
            ApiCode::RbacBindingDeleteFailed => (ResourceKind::RbacBinding, Operation::Delete, Outcome::Failure),
            ApiCode::RbacPermissionGranted => (ResourceKind::RbacPermission, Operation::Grant, Outcome::Success),
            ApiCode::RbacPermissionGrantFailed => (ResourceKind::RbacPermission, Operation::Grant, Outcome::Failure),
            ApiCode::RbacPermissionRevoked => (ResourceKind::RbacPermission, Operation::Revoke, Outcome::Success),
            ApiCode::RbacPermissionRevokeFailed => (ResourceKind::RbacPermission, Operation::Revoke, Outcome::Failure),
            ApiCode::SecretRevealFailed => (ResourceKind::Secret, Operation::Reveal, Outcome::Failure),
            ApiCode::SecretRevealed => (ResourceKind::Secret, Operation::Reveal, Outcome::Success),
            ApiCode::AccountListFailed => (ResourceKind::Account, Operation::List, Outcome::Failure),
            ApiCode::AccountListSucceeded => (ResourceKind::Account, Operation::List, Outcome::Success),
            ApiCode::AccountRetrieve => (ResourceKind::Account, Operation::Fetch, Outcome::Success),
            ApiCode::AccountRetrievalFailed => (ResourceKind::Account, Operation::Fetch, Outcome::Failure),
            ApiCode::AuthTokenListFailed => (ResourceKind::Auth, Operation::List, Outcome::Failure),
            ApiCode::AuthTokenListSucceeded => (ResourceKind::Auth, Operation::List, Outcome::Success),
            ApiCode::AuthTokenRevoked => (ResourceKind::Auth, Operation::Revoke, Outcome::Success),
            ApiCode::AuthTokenRevokeFailed => (ResourceKind::Auth, Operation::Revoke, Outcome::Failure),
            ApiCode::AuthPasswordChangeRequired => (ResourceKind::Auth, Operation::PwdChangeRequired, Outcome::Success),

            ApiCode::AccountPromotionFailed => (ResourceKind::Account, Operation::Promote, Outcome::Failure),
            ApiCode::AccountPromotion => (ResourceKind::Account, Operation::Promote, Outcome::Success),
            ApiCode::AccountDemotionFailed => (ResourceKind::Account, Operation::Demote, Outcome::Failure),
            ApiCode::AccountDemotion => (ResourceKind::Account, Operation::Demote, Outcome::Success),
            ApiCode::MasterKeyStatusFailed => (ResourceKind::Masterkey, Operation::List, Outcome::Failure),
            ApiCode::MasterKeyStatusSuccess => (ResourceKind::Masterkey, Operation::List, Outcome::Success),

            ApiCode::SystemStatusSuccess => (ResourceKind::Global, Operation::Fetch, Outcome::Success),
            ApiCode::SystemStatusFailed => (ResourceKind::Global, Operation::Fetch, Outcome::Failure),

            ApiCode::AboutFetched => (ResourceKind::Global, Operation::Fetch, Outcome::Success),

            ApiCode::LicenseStatusFetched => (ResourceKind::Global, Operation::Fetch, Outcome::Success),
            ApiCode::LicenseStatusFetchFailed => (ResourceKind::Global, Operation::Fetch, Outcome::Failure),
            ApiCode::LicenseSet => (ResourceKind::Global, Operation::Create, Outcome::Success),
            ApiCode::LicenseSetFailed => (ResourceKind::Global, Operation::Create, Outcome::Failure),
            ApiCode::LicenseRemoved => (ResourceKind::Global, Operation::Delete, Outcome::Success),
            ApiCode::LicenseRemoveFailed => (ResourceKind::Global, Operation::Delete, Outcome::Failure),

            ApiCode::RateLimited => (ResourceKind::Global, Operation::Global, Outcome::Failure),
            ApiCode::Unauthorized => (ResourceKind::Global, Operation::Global, Outcome::Failure),
            ApiCode::InvalidContentType => (ResourceKind::Global, Operation::Global, Outcome::Failure),
            ApiCode::InvalidJson => (ResourceKind::Global, Operation::Global, Outcome::Failure),
            ApiCode::InvalidRequest => (ResourceKind::Global, Operation::Global, Outcome::Failure),
            ApiCode::InvalidQuery => (ResourceKind::Global, Operation::Global, Outcome::Failure),
            ApiCode::InvalidPath => (ResourceKind::Global, Operation::Global, Outcome::Failure),
            ApiCode::RequestBodyTooLarge => (ResourceKind::Global, Operation::Global, Outcome::Failure),
            ApiCode::RequestTimedOut => (ResourceKind::Global, Operation::Global, Outcome::Failure),
            ApiCode::InternalError => (ResourceKind::Global, Operation::Global, Outcome::Failure),

            ApiCode::MasterKeyLockFailed => (ResourceKind::Masterkey, Operation::Lock, Outcome::Failure),
            ApiCode::MasterKeyLocked => (ResourceKind::Masterkey, Operation::Lock, Outcome::Success),
            ApiCode::MasterKeyUnlockFailed => (ResourceKind::Masterkey, Operation::Unlock, Outcome::Failure),
            ApiCode::MasterKeyUnlocked => (ResourceKind::Masterkey, Operation::Unlock, Outcome::Success),
            ApiCode::MasterKeyAlreadyUnlocked => (ResourceKind::Masterkey, Operation::Unlock, Outcome::Success),
            ApiCode::MasterKeyAlreadyLocked => (ResourceKind::Masterkey, Operation::Lock, Outcome::Success),
            ApiCode::MasterKeyCreateFailed => (ResourceKind::Masterkey, Operation::Create, Outcome::Failure),
            ApiCode::MasterKeyDeleteFailed => (ResourceKind::Masterkey, Operation::Delete, Outcome::Failure),
            ApiCode::MasterKeyDeleted => (ResourceKind::Masterkey, Operation::Delete, Outcome::Success),
            ApiCode::MasterKeyAlreadyActivated => (ResourceKind::Masterkey, Operation::Activate, Outcome::Success),
            ApiCode::MasterKeyActivated => (ResourceKind::Masterkey, Operation::Activate, Outcome::Success),
            ApiCode::MasterKeyActivateFailed => (ResourceKind::Masterkey, Operation::Activate, Outcome::Failure),
            ApiCode::MasterKeyRewrapKeks => (ResourceKind::Masterkey, Operation::Rewrap, Outcome::Success),
            ApiCode::MasterKeyRewrapKeksFailed => (ResourceKind::Masterkey, Operation::Rewrap, Outcome::Failure),

            ApiCode::AccountLockFailed => (ResourceKind::Account, Operation::Lock, Outcome::Failure),
            ApiCode::AccountLock => (ResourceKind::Account, Operation::Lock, Outcome::Success),
            ApiCode::AccountUnlock => (ResourceKind::Account, Operation::Unlock, Outcome::Success),
            ApiCode::AccountUnlockFailed => (ResourceKind::Account, Operation::Unlock, Outcome::Failure),
            ApiCode::AccountEnable => (ResourceKind::Account, Operation::Enable, Outcome::Success),
            ApiCode::AccountDisable => (ResourceKind::Account, Operation::Disable, Outcome::Success),
            ApiCode::Forbidden => (ResourceKind::Global, Operation::Global, Outcome::Failure),

            ApiCode::RbacRoleList => (ResourceKind::RbacRole, Operation::List, Outcome::Success),
            ApiCode::RbacRoleListFailed => (ResourceKind::RbacRole, Operation::List, Outcome::Failure),
            ApiCode::RbacRoleDescribe => (ResourceKind::RbacRole, Operation::Fetch, Outcome::Success),
            ApiCode::RbacRoleDescribeFailed => (ResourceKind::RbacRole, Operation::Fetch, Outcome::Failure),
            ApiCode::RbacRuleCreateFailed => (ResourceKind::RbacRule, Operation::Create, Outcome::Failure),
            ApiCode::RbacRuleCreated => (ResourceKind::RbacRule, Operation::Create, Outcome::Success),
            ApiCode::RbacRuleDeleteFailed => (ResourceKind::RbacRule, Operation::Delete, Outcome::Failure),
            ApiCode::RbacRuleDeleted => (ResourceKind::RbacRule, Operation::Delete, Outcome::Success),
            ApiCode::RbacRuleDescribeFailed => (ResourceKind::RbacRule, Operation::Fetch, Outcome::Failure),
            ApiCode::RbacRuleDescribe => (ResourceKind::RbacRule, Operation::Fetch, Outcome::Success),
            ApiCode::RbacRuleListFailed => (ResourceKind::RbacRule, Operation::List, Outcome::Failure),
            ApiCode::RbacRuleList => (ResourceKind::RbacRule, Operation::List, Outcome::Success),
            ApiCode::RbacBindFailed => (ResourceKind::RbacBinding, Operation::Create, Outcome::Failure),
            ApiCode::RbacBindCreated => (ResourceKind::RbacBinding, Operation::Create, Outcome::Success),
            ApiCode::AuthTokenFailed => (ResourceKind::Auth, Operation::Revoke, Outcome::Failure),
            ApiCode::AuthTokenSucceeded => (ResourceKind::Auth, Operation::Revoke, Outcome::Success),
            ApiCode::RbacExplain => (ResourceKind::Rbac, Operation::Fetch, Outcome::Success),
            ApiCode::RbacExplainFailed => (ResourceKind::Rbac, Operation::Fetch, Outcome::Failure),
            ApiCode::RbacBindingsList => (ResourceKind::RbacBinding, Operation::List, Outcome::Success),
            ApiCode::RbacBindingsListAll => (ResourceKind::RbacBinding, Operation::List, Outcome::Success),
            ApiCode::RbacBindingsListAllFailed => (ResourceKind::RbacBinding, Operation::List, Outcome::Failure),
            ApiCode::RbacBindingsListFailed => (ResourceKind::RbacBinding, Operation::List, Outcome::Failure),

            ApiCode::AuditQuerySucceeded => (ResourceKind::Audit, Operation::List, Outcome::Success),
            ApiCode::AuditQueryFailed => (ResourceKind::Audit, Operation::List, Outcome::Failure),
            ApiCode::AuditVerifySucceeded => (ResourceKind::Audit, Operation::Fetch, Outcome::Success),
            ApiCode::AuditVerifyFailed => (ResourceKind::Audit, Operation::Fetch, Outcome::Failure),
        }
    }

    pub fn new(code: ApiCode, message: impl Into<String>) -> Self {
        let (resource, operation, outcome) = Self::derive(code);

        Self {
            resource,
            operation,
            outcome,
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiCode {
    AccountCreateFailed,
    AccountCreated,
    AccountDeleteFailed,
    AccountDeleted,
    AccountDemotion,
    AccountDemotionFailed,
    AccountDisable,
    AccountDisableFailed,
    AccountDisabled,
    AccountEnable,
    AccountEnableFailed,
    AccountEnabled,
    AccountListFailed,
    AccountListSucceeded,
    AccountLock,
    AccountLockFailed,
    AccountPasswordRotateFailed,
    AccountPasswordRotated,
    AccountPromotion,
    AccountPromotionFailed,
    AccountRetrievalFailed,
    AccountRetrieve,
    AccountUnlock,
    AccountUnlockFailed,
    AccountUpdateFailed,
    AccountUpdated,

    AuthLoginFailed,
    AuthLoginSucceeded,
    AuthPasswordChangeRequired,
    AuthTokenFailed,
    AuthTokenIssueFailed,
    AuthTokenIssued,
    AuthTokenListFailed,
    AuthTokenListSucceeded,
    AuthTokenRevokeFailed,
    AuthTokenRevoked,
    AuthTokenSucceeded,
    AuthWhoamiSucceeded,

    Forbidden,
    InternalError,
    InvalidContentType,
    InvalidJson,
    InvalidPath,
    InvalidQuery,
    InvalidRequest,

    KekCreateFailed,
    KekCreated,
    KekDisableFailed,
    KekDisabled,
    KekEnableFailed,
    KekEnabled,
    KekRotateFailed,
    KekRotated,

    MasterKeyActivateFailed,
    MasterKeyActivated,
    MasterKeyAlreadyActivated,
    MasterKeyAlreadyLocked,
    MasterKeyAlreadyUnlocked,
    MasterKeyCreateFailed,
    MasterKeyDeleteFailed,
    MasterKeyDeleted,
    MasterKeyLockFailed,
    MasterKeyLocked,
    MasterKeyRewrapKeks,
    MasterKeyRewrapKeksFailed,
    MasterKeyStatusFailed,
    MasterKeyStatusSuccess,
    MasterKeyUnlockFailed,
    MasterKeyUnlocked,

    MfaChallengeFailed,
    MfaChallengeRequired,
    MfaDisableFailed,
    MfaDisabled,
    MfaEnrollmentCompleteFailed,
    MfaEnrollmentCompleted,
    MfaEnrollmentStartFailed,
    MfaEnrollmentStarted,

    NamespaceCreateFailed,
    NamespaceCreated,
    NamespaceDeleteFailed,
    NamespaceDeleted,
    NamespaceDestroyFailed,
    NamespaceDestroyed,
    NamespaceDisableFailed,
    NamespaceDisabled,
    NamespaceEnableFailed,
    NamespaceEnabled,
    NamespaceFetchFailed,
    NamespaceFetched,
    NamespaceListed,
    NamespaceUpdateFailed,
    NamespaceUpdated,

    RbacBindCreated,
    RbacBindFailed,
    RbacBindingCreateFailed,
    RbacBindingCreated,
    RbacBindingDeleteFailed,
    RbacBindingDeleted,
    RbacBindingsList,
    RbacBindingsListAll,
    RbacBindingsListAllFailed,
    RbacBindingsListFailed,
    RbacExplain,
    RbacExplainFailed,
    RbacPermissionGrantFailed,
    RbacPermissionGranted,
    RbacPermissionRevokeFailed,
    RbacPermissionRevoked,
    RbacRoleCreateFailed,
    RbacRoleCreated,
    RbacRoleDeleteFailed,
    RbacRoleDeleted,
    RbacRoleDescribe,
    RbacRoleDescribeFailed,
    RbacRoleList,
    RbacRoleListFailed,
    RbacRoleUpdateFailed,
    RbacRoleUpdated,
    RbacRuleCreateFailed,
    RbacRuleCreated,
    RbacRuleDeleteFailed,
    RbacRuleDeleted,
    RbacRuleDescribe,
    RbacRuleDescribeFailed,
    RbacRuleList,
    RbacRuleListFailed,

    RequestBodyTooLarge,
    RequestTimedOut,

    SecretAnnotateFailed,
    SecretAnnotated,
    SecretCreateFailed,
    SecretCreated,
    SecretDeleteFailed,
    SecretDeleted,
    SecretDestroyFailed,
    SecretDestroyed,
    SecretDisableFailed,
    SecretDisabled,
    SecretEnableFailed,
    SecretEnabled,
    SecretFetchFailed,
    SecretFetched,
    SecretListed,
    SecretRekeyFailed,
    SecretRekeyed,
    SecretRevealFailed,
    SecretRevealed,
    SecretRevisionActivateFailed,
    SecretRevisionActivated,
    SecretRevisionCreateFailed,
    SecretRevisionCreated,
    SecretRevisionDeactivateFailed,
    SecretRevisionDeactivated,
    SecretRevisionFetched,
    SecretRestoreFailed,
    SecretRestored,
    SecretRewrapFailed,
    SecretRewrapped,
    SecretUpdateFailed,
    SecretUpdated,

    SystemStatusFailed,
    SystemStatusSuccess,

    AboutFetched,

    LicenseStatusFetched,
    LicenseStatusFetchFailed,
    LicenseSet,
    LicenseSetFailed,
    LicenseRemoved,
    LicenseRemoveFailed,

    RateLimited,

    Unauthorized,

    AuditQueryFailed,
    AuditQuerySucceeded,
    AuditVerifyFailed,
    AuditVerifySucceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    AlreadyExists,
    Conflict,
    CryptoError,
    DbError,
    DekUnwrapFailed,
    Forbidden,
    InternalError,
    InvalidRequest,
    KekNotActive,
    KekNotFound,
    LicenseLimitReached,
    LicenseRequired,
    NotFound,
    PreconditionFailed,
    RateLimited,
    SecretEncryptFailed,
    SecretDecryptFailed,
    SerializationError,
    StorageError,
    Timeout,
    Unauthorized,
    ValidationFailed,
}
