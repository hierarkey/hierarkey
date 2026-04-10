// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::rbac::pattern::NamespacePattern;
use crate::rbac::{AccountPattern, RbacResource, SecretPattern, TargetKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    All,
    Platform,
    Namespace(NamespacePattern),
    Secret(SecretPattern),
    Account(AccountPattern),
    // later: Role(...), ApiKey(...), etc.
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::All => write!(f, "all"),
            Target::Platform => write!(f, "platform"),
            Target::Namespace(pat) => write!(f, "namespace {pat}"),
            Target::Secret(pat) => write!(f, "secret {pat}"),
            Target::Account(pat) => write!(f, "account {pat}"),
        }
    }
}

impl Target {
    pub fn kind(&self) -> TargetKind {
        match self {
            Target::All => TargetKind::All,
            Target::Platform => TargetKind::Platform,
            Target::Namespace(_) => TargetKind::Namespace,
            Target::Secret(_) => TargetKind::Secret,
            Target::Account(_) => TargetKind::Account,
        }
    }

    pub fn kind_str(&self) -> &'static str {
        match self {
            Target::All => "all",
            Target::Platform => "platform",
            Target::Namespace(_) => "namespace",
            Target::Secret(_) => "secret",
            Target::Account(_) => "account",
        }
    }

    pub fn pattern(&self) -> Option<String> {
        match self {
            Target::All => None,
            Target::Platform => None,
            Target::Namespace(p) => Some(p.to_string()),
            Target::Secret(p) => Some(p.to_string()),
            Target::Account(p) => Some(p.to_string()),
        }
    }

    pub fn matches_request(&self, resource: &RbacResource) -> bool {
        match (self, resource) {
            (Target::All, _) => true,

            (Target::Platform, RbacResource::Platform) => true,

            (Target::Namespace(p), RbacResource::Namespace { path }) => p.matches(&canonical_ns(path)),

            // A namespace-scoped rule also covers secrets within that namespace.
            // e.g. "allow secret:reveal to namespace /prod" grants access to all secrets in /prod.
            (Target::Namespace(p), RbacResource::Secret { namespace, .. }) => p.matches(&canonical_ns(namespace)),

            (Target::Account(p), RbacResource::Account { name }) => p.matches(name),

            (Target::Secret(p), RbacResource::Secret { namespace, path }) => {
                let s = canonical_secret(namespace, path);
                p.matches(&s)
            }

            // Target kind mismatch => not applicable
            _ => false,
        }
    }

    pub fn specificity_score(&self) -> u32 {
        // Higher = more specific. You can tune these weights, but this works well:
        // - Secret > Namespace > Account > Platform > All
        // - Exact > Prefix/Subtree > Glob
        match self {
            Target::All => 0,
            Target::Platform => 50,
            Target::Account(p) => 100 + p.specificity_score(),
            Target::Namespace(p) => 200 + p.specificity_score(),
            Target::Secret(p) => 300 + p.specificity_score(),
        }
    }
}

// ----- canonicalization helpers -----

fn canonical_ns(path: &str) -> String {
    // Ensure leading slash, avoid trailing slash (except root "/")
    let mut p = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    p
}

fn canonical_secret(namespace: &str, path: &str) -> String {
    let ns = canonical_ns(namespace);
    let sp = path.trim_start_matches('/'); // store secret paths without leading slash
    format!("{ns}:{sp}")
}

// ----- match helpers -----

// A tiny glob matcher:
// - '*' matches any sequence of characters (including '/' and ':')
// - we treat '**' the same as '*' (good enough for your use-cases)
// If later you want '*' not to cross '/', we can add a flag.
pub fn glob_match(s: &str, pat: &str) -> bool {
    // Classic wildcard matching with backtracking on '*'
    let (mut si, mut pi) = (0usize, 0usize);
    let bytes_s = s.as_bytes();
    let bytes_p = pat.as_bytes();
    let (mut star_pi, mut star_si) = (None, 0usize);

    while si < bytes_s.len() {
        if pi < bytes_p.len() && (bytes_p[pi] == bytes_s[si]) {
            si += 1;
            pi += 1;
            continue;
        }

        if pi < bytes_p.len() && bytes_p[pi] == b'*' {
            // collapse consecutive '*'
            while pi < bytes_p.len() && bytes_p[pi] == b'*' {
                pi += 1;
            }
            star_pi = Some(pi);
            star_si = si;
            continue;
        }

        if let Some(spi) = star_pi {
            // backtrack: extend the '*' to cover one more char
            star_si += 1;
            si = star_si;
            pi = spi;
            continue;
        }

        return false;
    }

    // Consume remaining '*' in pattern
    while pi < bytes_p.len() && bytes_p[pi] == b'*' {
        pi += 1;
    }

    pi == bytes_p.len()
}

#[cfg(test)]
fn prefix_with_boundary(s: &str, prefix: &str) -> bool {
    if !s.starts_with(prefix) {
        return false;
    }
    let rest = &s[prefix.len()..];
    if rest.is_empty() {
        return true;
    }
    if prefix.ends_with('/') || prefix.ends_with(':') {
        return true;
    }
    rest.starts_with('/') || rest.starts_with(':')
}

#[cfg(test)]
fn subtree_match(s: &str, base: &str) -> bool {
    if s == base {
        return true;
    }
    s.starts_with(&format!("{base}/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::{AccountPattern, MatchKind, NamespacePattern, RbacResource, SecretPattern};
    use std::str::FromStr;

    // ---- Display ----

    #[test]
    fn display_all() {
        assert_eq!(Target::All.to_string(), "all");
    }

    #[test]
    fn display_namespace() {
        let t = Target::Namespace(NamespacePattern {
            base: "/prod".to_string(),
            kind: MatchKind::Exact,
        });
        assert_eq!(t.to_string(), "namespace /prod");
    }

    #[test]
    fn display_secret() {
        let t = Target::Secret(SecretPattern::from_str("/prod/app:db/pw").unwrap());
        assert_eq!(t.to_string(), "secret /prod/app:db/pw");
    }

    #[test]
    fn display_platform() {
        assert_eq!(Target::Platform.to_string(), "platform");
    }

    #[test]
    fn display_account() {
        let t = Target::Account(AccountPattern::from_str("admin").unwrap());
        assert_eq!(t.to_string(), "account admin");
    }

    // ---- kind() ----

    #[test]
    fn kind_all() {
        assert_eq!(Target::All.kind(), TargetKind::All);
    }

    #[test]
    fn kind_namespace() {
        let t = Target::Namespace(NamespacePattern {
            base: "/prod".to_string(),
            kind: MatchKind::Exact,
        });
        assert_eq!(t.kind(), TargetKind::Namespace);
    }

    #[test]
    fn kind_secret() {
        let t = Target::Secret(SecretPattern::from_str("/prod:all").unwrap());
        assert_eq!(t.kind(), TargetKind::Secret);
    }

    #[test]
    fn kind_platform() {
        assert_eq!(Target::Platform.kind(), crate::rbac::TargetKind::Platform);
    }

    #[test]
    fn kind_account() {
        let t = Target::Account(AccountPattern::from_str("admin").unwrap());
        assert_eq!(t.kind(), TargetKind::Account);
    }

    // ---- kind_str() ----

    #[test]
    fn kind_str_all_variants() {
        assert_eq!(Target::All.kind_str(), "all");
        let ns = Target::Namespace(NamespacePattern {
            base: "/prod".to_string(),
            kind: MatchKind::Exact,
        });
        assert_eq!(ns.kind_str(), "namespace");
        let sec = Target::Secret(SecretPattern::from_str("/prod:all").unwrap());
        assert_eq!(sec.kind_str(), "secret");
        let acc = Target::Account(AccountPattern::from_str("admin").unwrap());
        assert_eq!(acc.kind_str(), "account");
    }

    // ---- pattern() ----

    #[test]
    fn pattern_all_is_none() {
        assert!(Target::All.pattern().is_none());
    }

    #[test]
    fn pattern_namespace_is_some() {
        let t = Target::Namespace(NamespacePattern {
            base: "/prod".to_string(),
            kind: MatchKind::Exact,
        });
        assert_eq!(t.pattern(), Some("/prod".to_string()));
    }

    #[test]
    fn pattern_secret_is_some() {
        let t = Target::Secret(SecretPattern::from_str("/prod/app:db/pw").unwrap());
        assert!(t.pattern().is_some());
    }

    #[test]
    fn pattern_account_is_some() {
        let t = Target::Account(AccountPattern::from_str("admin").unwrap());
        assert_eq!(t.pattern(), Some("admin".to_string()));
    }

    // ---- matches_request() ----

    #[test]
    fn matches_all_accepts_any_resource() {
        assert!(Target::All.matches_request(&RbacResource::Platform));
        assert!(Target::All.matches_request(&RbacResource::Namespace {
            path: "/prod".to_string()
        }));
        assert!(Target::All.matches_request(&RbacResource::Secret {
            namespace: "/prod".to_string(),
            path: "db/pw".to_string(),
        }));
        assert!(Target::All.matches_request(&RbacResource::Account {
            name: "john".to_string()
        }));
    }

    #[test]
    fn matches_platform_only_matches_platform_resource() {
        assert!(Target::Platform.matches_request(&RbacResource::Platform));
        assert!(!Target::Platform.matches_request(&RbacResource::Namespace {
            path: "/prod".to_string()
        }));
        assert!(!Target::Platform.matches_request(&RbacResource::Account {
            name: "admin".to_string()
        }));
    }

    #[test]
    fn account_wildcard_does_not_match_platform() {
        let t = Target::Account(AccountPattern::from_str("*").unwrap());
        assert!(!t.matches_request(&RbacResource::Platform));
    }

    #[test]
    fn matches_namespace_exact() {
        let t = Target::Namespace(NamespacePattern::from_str("/prod").unwrap());
        assert!(t.matches_request(&RbacResource::Namespace {
            path: "/prod".to_string()
        }));
        assert!(!t.matches_request(&RbacResource::Namespace {
            path: "/staging".to_string()
        }));
    }

    #[test]
    fn matches_namespace_canonicalizes_missing_leading_slash() {
        let t = Target::Namespace(NamespacePattern::from_str("/prod").unwrap());
        assert!(t.matches_request(&RbacResource::Namespace {
            path: "prod".to_string()
        }));
    }

    #[test]
    fn matches_namespace_canonicalizes_trailing_slash() {
        let t = Target::Namespace(NamespacePattern::from_str("/prod").unwrap());
        assert!(t.matches_request(&RbacResource::Namespace {
            path: "/prod/".to_string()
        }));
    }

    #[test]
    fn matches_account() {
        let t = Target::Account(AccountPattern::from_str("admin").unwrap());
        assert!(t.matches_request(&RbacResource::Account {
            name: "admin".to_string()
        }));
        assert!(!t.matches_request(&RbacResource::Account {
            name: "other".to_string()
        }));
    }

    #[test]
    fn matches_secret() {
        let t = Target::Secret(SecretPattern::from_str("/prod:db/pw").unwrap());
        assert!(t.matches_request(&RbacResource::Secret {
            namespace: "/prod".to_string(),
            path: "db/pw".to_string(),
        }));
        assert!(!t.matches_request(&RbacResource::Secret {
            namespace: "/prod".to_string(),
            path: "db/other".to_string(),
        }));
    }

    #[test]
    fn namespace_target_matches_secrets_in_that_namespace() {
        let t = Target::Namespace(NamespacePattern::from_str("/prod").unwrap());
        assert!(t.matches_request(&RbacResource::Secret {
            namespace: "/prod".to_string(),
            path: "db_password".to_string(),
        }));
        assert!(t.matches_request(&RbacResource::Secret {
            namespace: "/prod".to_string(),
            path: "app/api_key".to_string(),
        }));
        assert!(!t.matches_request(&RbacResource::Secret {
            namespace: "/staging".to_string(),
            path: "db_password".to_string(),
        }));
    }

    #[test]
    fn matches_kind_mismatch_returns_false() {
        let t_ns = Target::Namespace(NamespacePattern::from_str("/prod").unwrap());
        assert!(!t_ns.matches_request(&RbacResource::Account {
            name: "admin".to_string()
        }));
        // A namespace target DOES match secrets in that namespace (by design).
        assert!(t_ns.matches_request(&RbacResource::Secret {
            namespace: "/prod".to_string(),
            path: "db/pw".to_string(),
        }));

        let t_acc = Target::Account(AccountPattern::from_str("admin").unwrap());
        assert!(!t_acc.matches_request(&RbacResource::Namespace {
            path: "/prod".to_string()
        }));

        let t_sec = Target::Secret(SecretPattern::from_str("/prod:db/pw").unwrap());
        assert!(!t_sec.matches_request(&RbacResource::Namespace {
            path: "/prod".to_string()
        }));
        assert!(!t_sec.matches_request(&RbacResource::Account {
            name: "admin".to_string()
        }));
    }

    // ---- specificity_score() ordering ----

    #[test]
    fn specificity_score_ordering_secret_gt_namespace_gt_account_gt_all() {
        let all = Target::All;
        let acc = Target::Account(AccountPattern::from_str("admin").unwrap());
        let ns = Target::Namespace(NamespacePattern::from_str("/prod").unwrap());
        let sec = Target::Secret(SecretPattern::from_str("/prod:db/pw").unwrap());
        assert_eq!(all.specificity_score(), 0);
        assert!(acc.specificity_score() > all.specificity_score());
        assert!(ns.specificity_score() > acc.specificity_score());
        assert!(sec.specificity_score() > ns.specificity_score());
    }

    // ---- prefix_with_boundary() ----

    #[test]
    fn prefix_boundary_exact_match() {
        assert!(prefix_with_boundary("/prod", "/prod"));
    }

    #[test]
    fn prefix_boundary_slash_separator() {
        assert!(prefix_with_boundary("/prod/app", "/prod"));
    }

    #[test]
    fn prefix_boundary_colon_separator() {
        assert!(prefix_with_boundary("/prod:pw", "/prod"));
    }

    #[test]
    fn prefix_boundary_no_boundary_character() {
        assert!(!prefix_with_boundary("/production", "/prod"));
    }

    #[test]
    fn prefix_boundary_no_prefix_match_at_all() {
        assert!(!prefix_with_boundary("/staging", "/prod"));
    }

    #[test]
    fn prefix_boundary_prefix_ends_with_slash() {
        assert!(prefix_with_boundary("/prod/app", "/prod/"));
    }

    #[test]
    fn prefix_boundary_prefix_ends_with_colon() {
        assert!(prefix_with_boundary("/prod:pw", "/prod:"));
    }

    // ---- subtree_match() ----

    #[test]
    fn subtree_self_matches() {
        assert!(subtree_match("/prod", "/prod"));
    }

    #[test]
    fn subtree_child_matches() {
        assert!(subtree_match("/prod/app1", "/prod"));
    }

    #[test]
    fn subtree_no_boundary_does_not_match() {
        assert!(!subtree_match("/production", "/prod"));
    }

    #[test]
    fn subtree_unrelated_does_not_match() {
        assert!(!subtree_match("/staging/app1", "/prod"));
    }

    // ---- glob_match() ----

    #[test]
    fn glob_exact() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn glob_empty_inputs() {
        assert!(glob_match("", ""));
        assert!(!glob_match("a", ""));
        assert!(glob_match("", "*"));
    }

    #[test]
    fn glob_star_only() {
        assert!(glob_match("anything", "*"));
        assert!(glob_match("/prod/app", "*"));
    }

    #[test]
    fn glob_trailing_star() {
        assert!(glob_match("hello", "hello*"));
        assert!(glob_match("helloworld", "hello*"));
        assert!(!glob_match("hell", "hello*"));
    }

    #[test]
    fn glob_leading_star() {
        assert!(glob_match("/prod/app1", "*/app1"));
        assert!(!glob_match("/prod/app2", "*/app1"));
    }

    #[test]
    fn glob_star_crosses_separators() {
        assert!(glob_match("/prod/app1", "/*/app1"));
        assert!(glob_match("/prod/app1", "/prod/*"));
        assert!(glob_match("/prod/app1/sub", "/**"));
    }

    #[test]
    fn glob_double_star_same_as_star() {
        assert!(glob_match("/prod/app1", "/prod/**"));
        assert!(glob_match("hello", "hello**"));
    }

    #[test]
    fn glob_no_match() {
        assert!(!glob_match("/staging/app1", "/prod/*"));
    }
}
