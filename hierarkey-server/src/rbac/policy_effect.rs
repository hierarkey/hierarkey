// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

#[derive(Debug, Clone, sqlx::Type, PartialEq, Eq)]
#[sqlx(type_name = "rbac_effect", rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

impl std::fmt::Display for PolicyEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyEffect::Allow => write!(f, "allow"),
            PolicyEffect::Deny => write!(f, "deny"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_allow() {
        assert_eq!(PolicyEffect::Allow.to_string(), "allow");
    }

    #[test]
    fn display_deny() {
        assert_eq!(PolicyEffect::Deny.to_string(), "deny");
    }

    #[test]
    fn equality() {
        assert_eq!(PolicyEffect::Allow, PolicyEffect::Allow);
        assert_ne!(PolicyEffect::Allow, PolicyEffect::Deny);
    }
}
