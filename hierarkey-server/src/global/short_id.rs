// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use rand::RngExt;

// Short ID consists of an optional prefix with _ and remaning chars which is the short
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ShortId {
    prefix: String,
    short: String,
}

impl ShortId {
    // We don't use 0, 1, l, o to avoid confusion
    const ALPHABET: &'static [u8] = b"23456789abcdefghjkmnpqrstvwxyz";

    pub fn new(prefix: &str, short: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
            short: short.to_string(),
        }
    }

    pub fn generate(prefix: &str, len: usize) -> Self {
        let mut rng = rand::rng();
        let short: String = (0..len)
            .map(|_| {
                let idx = rng.random_range(0..ShortId::ALPHABET.len());
                ShortId::ALPHABET[idx] as char
            })
            .collect();
        Self::new(prefix, &short)
    }
}

impl serde::Serialize for ShortId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ShortId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(ShortId::from(s.as_str()))
    }
}

impl std::fmt::Display for ShortId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.prefix.is_empty() {
            write!(f, "{}", self.short)
        } else {
            write!(f, "{}{}", self.prefix, self.short)
        }
    }
}

impl From<&str> for ShortId {
    fn from(s: &str) -> Self {
        let (prefix, short) = if let Some(pos) = s.rfind('_') {
            let (p, s) = s.split_at(pos + 1);
            (p.to_string(), s.to_string())
        } else {
            ("".to_string(), s.to_string())
        };
        Self { prefix, short }
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for ShortId {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(ShortId::from(s.as_str()))
    }
}

impl sqlx::Type<sqlx::Postgres> for ShortId {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

// -----------------------------------------------------------------------------------------------

/// When we resolve an (partial) short ID, we can have three cases:
/// - No results found
/// - Exactly one result found
/// - Multiple results found, which might be returned as count (if the caller only needs to know if there are multiple, but not the actual results)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOne<T> {
    None,                // No results found
    One(T),              // Exactly a single result found
    Many(Option<usize>), // Multiple found, which might be returned as count
}

#[cfg(test)]
mod tests {
    use super::ShortId;
    use std::collections::HashSet;

    #[test]
    fn new_stores_prefix_and_short() {
        let id = ShortId::new("pfx_", "abc123");
        assert_eq!(id.to_string(), "pfx_abc123");
    }

    #[test]
    fn new_empty_prefix() {
        let id = ShortId::new("", "abc123");
        assert_eq!(id.to_string(), "abc123");
    }

    #[test]
    fn display_with_prefix_concatenates() {
        let id = ShortId::new("tok_", "xyz");
        assert_eq!(format!("{id}"), "tok_xyz");
    }

    #[test]
    fn display_without_prefix_omits_underscore() {
        let id = ShortId::new("", "xyz");
        assert_eq!(format!("{id}"), "xyz");
    }

    #[test]
    fn from_str_with_prefix() {
        let id = ShortId::from("tok_abc123");
        assert_eq!(id, ShortId::new("tok_", "abc123"));
    }

    #[test]
    fn from_str_without_underscore() {
        let id = ShortId::from("abc123");
        assert_eq!(id, ShortId::new("", "abc123"));
    }

    #[test]
    fn from_str_multiple_underscores_splits_at_last() {
        // rfind means the split is after the last underscore
        let id = ShortId::from("a_b_cde");
        assert_eq!(id, ShortId::new("a_b_", "cde"));
    }

    #[test]
    fn from_str_roundtrip_via_display() {
        let original = "tok_abc123";
        let id = ShortId::from(original);
        assert_eq!(id.to_string(), original);
    }

    #[test]
    fn from_str_empty_string() {
        let id = ShortId::from("");
        assert_eq!(id.to_string(), "");
    }

    #[test]
    fn from_str_trailing_underscore_gives_empty_short() {
        // "pfx_" -> prefix="pfx_", short=""
        let id = ShortId::from("pfx_");
        assert_eq!(id, ShortId::new("pfx_", ""));
        assert_eq!(id.to_string(), "pfx_");
    }

    #[test]
    fn generate_produces_correct_length() {
        let id = ShortId::generate("tok_", 12);
        let displayed = id.to_string();
        // prefix "tok_" is 4 chars, short is 12 chars
        assert_eq!(displayed.len(), 4 + 12);
    }

    #[test]
    fn generate_zero_length_short() {
        let id = ShortId::generate("tok_", 0);
        assert_eq!(id.to_string(), "tok_");
    }

    #[test]
    fn generate_only_alphabet_chars() {
        let alphabet: HashSet<char> = ShortId::ALPHABET.iter().map(|&b| b as char).collect();
        let id = ShortId::generate("", 100);
        for ch in id.to_string().chars() {
            assert!(alphabet.contains(&ch), "unexpected char: {ch:?}");
        }
    }

    #[test]
    fn generate_no_ambiguous_chars() {
        // 0, 1, l, o must never appear
        let id = ShortId::generate("", 500);
        let s = id.to_string();
        assert!(!s.contains('0'), "found ambiguous char '0'");
        assert!(!s.contains('1'), "found ambiguous char '1'");
        assert!(!s.contains('l'), "found ambiguous char 'l'");
        assert!(!s.contains('o'), "found ambiguous char 'o'");
    }

    #[test]
    fn generate_produces_different_values() {
        let a = ShortId::generate("tok_", 16);
        let b = ShortId::generate("tok_", 16);
        // Probability of collision with 30^16 space is negligible
        assert_ne!(a, b);
    }

    #[test]
    fn equality_same_prefix_and_short() {
        assert_eq!(ShortId::new("p_", "abc"), ShortId::new("p_", "abc"));
    }

    #[test]
    fn equality_differs_on_short() {
        assert_ne!(ShortId::new("p_", "abc"), ShortId::new("p_", "xyz"));
    }

    #[test]
    fn equality_differs_on_prefix() {
        assert_ne!(ShortId::new("a_", "abc"), ShortId::new("b_", "abc"));
    }

    #[test]
    fn hash_usable_in_hashset() {
        let mut set = HashSet::new();
        set.insert(ShortId::new("tok_", "abc"));
        set.insert(ShortId::new("tok_", "abc")); // duplicate
        set.insert(ShortId::new("tok_", "xyz"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn serde_roundtrip() {
        let id = ShortId::new("tok_", "abc123");
        let json = serde_json::to_string(&id).unwrap();
        let decoded: ShortId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn clone_is_equal() {
        let id = ShortId::new("tok_", "abc");
        assert_eq!(id.clone(), id);
    }
}
