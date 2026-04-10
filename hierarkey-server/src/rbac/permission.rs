// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::CkError;
use hierarkey_core::error::rbac::RbacError;
use sqlx::postgres::{PgTypeInfo, PgValueRef};
use sqlx::{Decode, Encode, Postgres, Type};
use std::str::FromStr;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PermissionInfo {
    pub name: &'static str,
    pub description: &'static str,
}

macro_rules! define_permissions {
    (
        $(
            $variant:ident => {
                name: $name:literal,
                description: $desc:literal
            }
        ),+ $(,)?
    ) => {
        #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
        pub enum Permission {
            $($variant),+
        }

        impl Permission {
            /// Metadata in the same order as declared.
            pub const INFO: &'static [PermissionInfo] = &[
                $(
                    PermissionInfo {
                        name: $name,
                        description: $desc,
                    }
                ),+
            ];

            /// Stable external representation (used in RBAC specs, API, CLI).
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Permission::$variant => $name),+
                }
            }

            /// Human-readable description (for `hkey help`, docs, TUI).
            pub const fn description(self) -> &'static str {
                match self {
                    $(Permission::$variant => $desc),+
                }
            }

            /// Parse (case-insensitive ASCII) from string.
            pub fn parse(s: &str) -> Result<Self, CkError> {
                let lower = s.trim().to_ascii_lowercase();
                match lower.as_str() {
                    $($name => Ok(Permission::$variant),)+
                    _ => Err(RbacError::Validation(format!("unknown permission: {}", s)).into()),
                }
            }
        }

        impl std::fmt::Display for Permission {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for Permission {
            type Err = CkError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        #[cfg(test)]
        mod permission_tests {
            use super::*;

            #[test]
            fn permission_roundtrip_display_fromstr() {
                // Ensure every enum variant roundtrips via Display -> FromStr
                let perms: &[Permission] = &[
                    $(Permission::$variant),+
                ];

                for &p in perms {
                    let s = p.to_string();
                    let parsed = Permission::from_str(&s).unwrap();
                    assert_eq!(p, parsed, "roundtrip failed for {}", s);
                }
            }
        }
    };
}

define_permissions! {
    // Secrets (scoped to namespace; secret refs are typically <namespace>:<path>)
    SecretReveal => {
        name: "secret:reveal",
        description: "Reveal a secret value (latest or a specific revision)."
    },
    SecretList => {
        name: "secret:list",
        description: "List secrets within a namespace (paths/names only; no values)."
    },
    SecretDescribe => {
        name: "secret:describe",
        description: "Read secret metadata (description, labels, timestamps, current revision, etc.)."
    },
    SecretCreate => {
        name: "secret:create",
        description: "Create a new secret at a given path (initial revision)."
    },
    SecretRevise => {
        name: "secret:revise",
        description: "Create a new revision for an existing secret (write/update value)."
    },
    SecretDelete => {
        name: "secret:delete",
        description: "Delete/tombstone a secret."
    },
    SecretRestore => {
        name: "secret:restore",
        description: "Restore/undelete a previously deleted secret (if supported)."
    },
    SecretUpdateMeta => {
        name: "secret:update:meta",
        description: "Update secret metadata (description/labels/tags) without changing the value."
    },
    SecretManageLifecycle => {
        name: "secret:lifecycle",
        description: "Manage secret lifecycle controls (e.g., lock/freeze/disable) if supported."
    },
    SecretReadHistory => {
        name: "secret:history:read",
        description: "Read secret history/revisions list and related metadata."
    },
    SecretRollback => {
        name: "secret:rollback",
        description: "Rollback/promote an older revision to become the current revision (if supported)."
    },
    SecretAll => {
        name: "secret:*",
        description: "All secret permissions."
    },

    // Namespaces
    NamespaceCreate => {
        name: "namespace:create",
        description: "Create a namespace."
    },
    NamespaceList => {
        name: "namespace:list",
        description: "List namespaces visible to the caller."
    },
    NamespaceDescribe => {
        name: "namespace:describe",
        description: "Read namespace metadata (description, labels, timestamps, etc.)."
    },
    NamespaceUpdateMeta => {
        name: "namespace:update:meta",
        description: "Update namespace metadata (description/labels/tags)."
    },
    NamespaceDelete => {
        name: "namespace:delete",
        description: "Delete a namespace (often restricted)."
    },
    NamespacePolicyRead => {
        name: "namespace:policy:read",
        description: "Read namespace policy (RBAC bindings/roles/rules attached to the namespace)."
    },
    NamespacePolicyWrite => {
        name: "namespace:policy:write",
        description: "Modify namespace policy (bind/unbind roles, attach/detach rules, etc.)."
    },
    NamespaceKekRotate => {
        name: "namespace:kek_rotate",
        description: "Rotate/manage namespace KEK linkage (namespace_kek revision/rotation)."
    },
    NamespaceAll => {
        name: "namespace:*",
        description: "All namespace permissions."
    },

    // Global / platform-level
    AuditRead => {
        name: "audit:read",
        description: "Read audit events (scope may be global or filtered by RBAC)."
    },
    RbacAdmin => {
        name: "rbac:admin",
        description: "Administer RBAC objects (roles/rules/bindings) at a platform level."
    },
    PlatformAdmin => {
        name: "platform:admin",
        description: "Full platform administration (superuser)."
    },
    All => {
        name: "all",
        description: "Wildcard super-permission (equivalent to platform admin)."
    },
}

impl Permission {
    /// Returns true if `self` (the permission a rule grants) covers `required` (the permission being checked).
    ///
    /// Subsumption hierarchy:
    ///   `all` / `platform:admin`  ->  any permission
    ///   `secret:*`                ->  any `secret:*` permission
    ///   `namespace:*`             ->  any `namespace:*` permission
    ///   anything else             ->  only exact match
    pub fn grants(self, required: Permission) -> bool {
        match self {
            // Super-permissions: grant everything
            Permission::All | Permission::PlatformAdmin => true,

            // secret:* grants all secret-scoped permissions
            Permission::SecretAll => matches!(
                required,
                Permission::SecretReveal
                    | Permission::SecretList
                    | Permission::SecretDescribe
                    | Permission::SecretCreate
                    | Permission::SecretRevise
                    | Permission::SecretDelete
                    | Permission::SecretRestore
                    | Permission::SecretUpdateMeta
                    | Permission::SecretManageLifecycle
                    | Permission::SecretReadHistory
                    | Permission::SecretRollback
                    | Permission::SecretAll
            ),

            // namespace:* grants all namespace-scoped permissions
            Permission::NamespaceAll => matches!(
                required,
                Permission::NamespaceCreate
                    | Permission::NamespaceList
                    | Permission::NamespaceDescribe
                    | Permission::NamespaceUpdateMeta
                    | Permission::NamespaceDelete
                    | Permission::NamespacePolicyRead
                    | Permission::NamespacePolicyWrite
                    | Permission::NamespaceKekRotate
                    | Permission::NamespaceAll
            ),

            // All other permissions only cover themselves (exact match)
            _ => self == required,
        }
    }
}

impl Type<Postgres> for Permission {
    fn type_info() -> PgTypeInfo {
        <str as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <str as Type<Postgres>>::compatible(ty)
    }
}

impl<'r> Decode<'r, Postgres> for Permission {
    fn decode(value: PgValueRef<'r>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let s = <&str as Decode<Postgres>>::decode(value)?;
        Permission::from_str(s).map_err(|e| Box::new(e) as _)
    }
}

impl<'q> Encode<'q, Postgres> for Permission {
    fn encode_by_ref(
        &self,
        buf: &mut <Postgres as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
        let s = self.to_string();
        <String as Encode<Postgres>>::encode(s, buf)
    }

    fn size_hint(&self) -> usize {
        self.to_string().len()
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn as_str_matches_display() {
        let cases = [
            Permission::SecretReveal,
            Permission::SecretAll,
            Permission::NamespaceCreate,
            Permission::PlatformAdmin,
            Permission::All,
        ];
        for p in cases {
            assert_eq!(p.as_str(), p.to_string(), "as_str != Display for {p:?}");
        }
    }

    #[test]
    fn description_is_non_empty_for_all_permissions() {
        for info in Permission::INFO {
            assert!(!info.description.is_empty(), "empty description for {}", info.name);
        }
    }

    #[test]
    fn description_method_returns_non_empty() {
        let cases = [
            Permission::SecretReveal,
            Permission::SecretCreate,
            Permission::SecretDelete,
            Permission::NamespaceCreate,
            Permission::PlatformAdmin,
            Permission::RbacAdmin,
            Permission::AuditRead,
        ];
        for p in cases {
            assert!(!p.description().is_empty(), "empty description for {p:?}");
        }
    }

    #[test]
    fn parse_unknown_permission_returns_error() {
        assert!(Permission::parse("not:a:permission").is_err());
        assert!(Permission::parse("").is_err());
        assert!(Permission::parse("SECRET:REVEAL").is_ok(), "parse should be case-insensitive");
    }

    #[test]
    fn from_str_unknown_returns_error() {
        assert!(Permission::from_str("totally:unknown").is_err());
    }
}
