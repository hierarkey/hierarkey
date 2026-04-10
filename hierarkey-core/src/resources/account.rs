// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::error::validation::ValidationError;
use crate::{CkError, CkResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef};
use sqlx::{Decode, Encode, Postgres, Type};
use std::str::FromStr;

const MIN_NAME_LENGTH: usize = 3;
const MAX_NAME_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct AccountName {
    inner: String, // Always stored in canonical (lowercase) form
}

impl AccountName {
    /// Returns the account name as a string slice
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Returns whether this is a system account (starts with $)
    pub fn is_system_name(&self) -> bool {
        self.inner.starts_with('$')
    }

    pub fn system() -> Self {
        AccountName {
            inner: "$system".to_string(),
        }
    }

    /// Returns an unresolved placeholder — `fmt_user_ref` will fall back to the account ID.
    pub fn unknown() -> Self {
        AccountName { inner: String::new() }
    }
}

impl TryFrom<&str> for AccountName {
    type Error = CkError;

    fn try_from(name: &str) -> CkResult<Self> {
        let canonical = validate_name(name)?;
        Ok(AccountName { inner: canonical })
    }
}

impl FromStr for AccountName {
    type Err = CkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AccountName::try_from(s.to_string())
    }
}

impl TryFrom<String> for AccountName {
    type Error = CkError;

    fn try_from(name: String) -> CkResult<Self> {
        AccountName::try_from(name.as_str())
    }
}

impl TryFrom<&String> for AccountName {
    type Error = CkError;

    fn try_from(name: &String) -> CkResult<Self> {
        AccountName::try_from(name.as_str())
    }
}

impl std::fmt::Display for AccountName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl AsRef<str> for AccountName {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl PartialEq<str> for AccountName {
    fn eq(&self, other: &str) -> bool {
        self.inner == canonicalize(other)
    }
}

impl PartialEq<&str> for AccountName {
    fn eq(&self, other: &&str) -> bool {
        self.inner == canonicalize(other)
    }
}

impl Serialize for AccountName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.inner.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AccountName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        // Empty string is the wire representation of AccountName::unknown().
        if s.is_empty() {
            return Ok(AccountName::unknown());
        }
        AccountName::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Type<Postgres> for AccountName {
    fn type_info() -> PgTypeInfo {
        <String as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <String as Type<Postgres>>::compatible(ty)
    }
}

impl<'r> Decode<'r, Postgres> for AccountName {
    fn decode(value: PgValueRef<'r>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let s = <String as Decode<Postgres>>::decode(value)?;
        AccountName::try_from(s).map_err(|e| e.into())
    }
}

impl<'q> Encode<'q, Postgres> for AccountName {
    fn encode_by_ref(
        &self,
        buf: &mut PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
        <&str as Encode<Postgres>>::encode(self.as_str(), buf)
    }
}

// ------------------------------------------------------------------------------------------------

/// Convert the account name to its canonical form
fn canonicalize(name: &str) -> String {
    // Normalize to lowercase and return
    name.to_ascii_lowercase()
}

/*
Rulesets:
    min-length: 3
    max-length: 64
    allowed-chars: a-z A-Z 0-9 _ - .
    must start with a letter (a-z,A-Z) or number (0-9)
    cannot end with . or -
    system-accounts starts with $ and can be the only place to have a $
    cannot have -- __ or .. or .- -_ etc. sequences (no two specials next to each other)
    names are case-insensitive (stored as lowercase)
 */
fn validate_name(name: &str) -> CkResult<String> {
    // Check for empty string first
    if name.is_empty() {
        return Err(ValidationError::TooShort {
            field: "name",
            min: MIN_NAME_LENGTH,
        }
        .into());
    }

    // Handle system accounts (start with $)
    let (is_system_account, name_to_validate) = if let Some(rest) = name.strip_prefix('$') {
        (true, rest)
    } else {
        (false, name)
    };

    // Check that $ doesn't appear anywhere else
    if name_to_validate.contains('$') {
        return Err(ValidationError::InvalidChars {
            field: "name",
            allowed: "'$' is only allowed as the first character for system accounts",
        }
        .into());
    }

    // Check allowed characters (alphanumeric, underscore, hyphen, period)
    if !name_to_validate
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(ValidationError::InvalidChars {
            field: "name",
            allowed: "alphanumeric characters, underscores, hyphens, and periods",
        }
        .into());
    }

    // Name must start with a letter or number
    if let Some(first_char) = name_to_validate.chars().next() {
        if !first_char.is_ascii_alphanumeric() {
            return Err(ValidationError::InvalidChars {
                field: "name",
                allowed: "must start with an alphanumeric character",
            }
            .into());
        }
    } else if is_system_account {
        // System account with only "$" and nothing after
        return Err(ValidationError::TooShort {
            field: "name",
            min: MIN_NAME_LENGTH,
        }
        .into());
    }

    // Name cannot end with . or -
    if let Some(last_char) = name_to_validate.chars().last()
        && !last_char.is_alphanumeric()
    {
        return Err(ValidationError::InvalidChars {
            field: "name",
            allowed: "cannot end with a special character",
        }
        .into());
    }

    // No consecutive special characters
    let special_chars = ['_', '-', '.'];
    for window in name_to_validate.as_bytes().windows(2) {
        let a = window[0] as char;
        let b = window[1] as char;
        if special_chars.contains(&a) && special_chars.contains(&b) {
            return Err(ValidationError::InvalidChars {
                field: "name",
                allowed: "cannot have consecutive special characters",
            }
            .into());
        }
    }

    // Check length (of the full name including $ for system accounts)
    let mut min_len = MIN_NAME_LENGTH;
    let mut max_len = MAX_NAME_LENGTH;
    if is_system_account {
        min_len += 1; // System accounts also have a $ in front, don't count that
        max_len += 1;
    }

    if name.len() < min_len {
        return Err(ValidationError::TooShort {
            field: "name",
            min: MIN_NAME_LENGTH,
        }
        .into());
    }
    if name.len() > max_len {
        return Err(ValidationError::TooLong {
            field: "name",
            max: MAX_NAME_LENGTH,
        }
        .into());
    }

    Ok(canonicalize(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_simple_names() {
        assert!(AccountName::try_from("alice").is_ok());
        assert!(AccountName::try_from("bob").is_ok());
        assert!(AccountName::try_from("user123").is_ok());
        assert!(AccountName::try_from("123user").is_ok());
        assert!(AccountName::try_from("a1b").is_ok());
    }

    #[test]
    fn valid_with_special_chars() {
        assert!(AccountName::try_from("alice_bob").is_ok());
        assert!(AccountName::try_from("alice-bob").is_ok());
        assert!(AccountName::try_from("alice.bob").is_ok());
        assert!(AccountName::try_from("a_b-c.d").is_ok());
        assert!(AccountName::try_from("user_name_123").is_ok());
        assert!(AccountName::try_from("my-cool-account").is_ok());
        assert!(AccountName::try_from("test.account.name").is_ok());
    }

    #[test]
    fn valid_mixed_case_canonicalizes() {
        let name = AccountName::try_from("AlIcE").unwrap();
        assert_eq!(name.as_str(), "alice");

        let name = AccountName::try_from("BOB").unwrap();
        assert_eq!(name.as_str(), "bob");

        let name = AccountName::try_from("User_Name").unwrap();
        assert_eq!(name.as_str(), "user_name");
    }

    #[test]
    fn valid_minimum_length() {
        assert!(AccountName::try_from("abc").is_ok());
        assert!(AccountName::try_from("a1b").is_ok());
        assert!(AccountName::try_from("123").is_ok());
    }

    #[test]
    fn valid_maximum_length() {
        let name = "a".repeat(64);
        assert!(AccountName::try_from(name.as_str()).is_ok());

        let name = "abcdefghij".repeat(6) + "abcd"; // 64 chars
        assert!(AccountName::try_from(name.as_str()).is_ok());
    }

    #[test]
    fn valid_system_accounts() {
        assert!(AccountName::try_from("$system").is_ok());
        assert!(AccountName::try_from("$admin").is_ok());
        assert!(AccountName::try_from("$root").is_ok());
        assert!(AccountName::try_from("$sys_account").is_ok());
        assert!(AccountName::try_from("$system123").is_ok());
    }

    #[test]
    fn valid_system_account_canonicalizes() {
        let name = AccountName::try_from("$SYSTEM").unwrap();
        assert_eq!(name.as_str(), "$system");
    }

    #[test]
    fn valid_system_account_minimum_length() {
        // $abc = 4 chars total, but the "abc" part is 3 chars (minimum)
        assert!(AccountName::try_from("$abc").is_ok());
        assert!(AccountName::try_from("$123").is_ok());
    }

    #[test]
    fn valid_system_account_maximum_length() {
        // $ + 64 chars = 65 total allowed for system accounts
        let name = "$".to_string() + &"a".repeat(64);
        assert!(AccountName::try_from(name.as_str()).is_ok());
    }

    #[test]
    fn invalid_empty_string() {
        assert!(AccountName::try_from("").is_err());
    }

    #[test]
    fn invalid_too_short() {
        assert!(AccountName::try_from("a").is_err());
        assert!(AccountName::try_from("ab").is_err());
        assert!(AccountName::try_from("12").is_err());
    }

    #[test]
    fn invalid_too_long() {
        let name = "a".repeat(65);
        assert!(AccountName::try_from(name.as_str()).is_err());

        let name = "a".repeat(100);
        assert!(AccountName::try_from(name.as_str()).is_err());
    }

    #[test]
    fn invalid_system_account_too_short() {
        assert!(AccountName::try_from("$").is_err());
        assert!(AccountName::try_from("$a").is_err());
        assert!(AccountName::try_from("$ab").is_err());
    }

    #[test]
    fn invalid_system_account_too_long() {
        // $ + 65 chars = 66 total, too long
        let name = "$".to_string() + &"a".repeat(65);
        assert!(AccountName::try_from(name.as_str()).is_err());
    }

    #[test]
    fn invalid_special_chars() {
        assert!(AccountName::try_from("alice@bob").is_err());
        assert!(AccountName::try_from("alice#bob").is_err());
        assert!(AccountName::try_from("alice!bob").is_err());
        assert!(AccountName::try_from("alice bob").is_err()); // space
        assert!(AccountName::try_from("alice\tbob").is_err()); // tab
        assert!(AccountName::try_from("alice%bob").is_err());
        assert!(AccountName::try_from("alice&bob").is_err());
        assert!(AccountName::try_from("alice*bob").is_err());
        assert!(AccountName::try_from("alice/bob").is_err());
        assert!(AccountName::try_from("alice\\bob").is_err());
        assert!(AccountName::try_from("alice:bob").is_err());
        assert!(AccountName::try_from("alice;bob").is_err());
        assert!(AccountName::try_from("alice'bob").is_err());
        assert!(AccountName::try_from("alice\"bob").is_err());
        assert!(AccountName::try_from("alice<bob").is_err());
        assert!(AccountName::try_from("alice>bob").is_err());
        assert!(AccountName::try_from("alice=bob").is_err());
        assert!(AccountName::try_from("alice+bob").is_err());
    }

    #[test]
    fn invalid_unicode_chars() {
        assert!(AccountName::try_from("alicé").is_err());
        assert!(AccountName::try_from("日本語").is_err());
        assert!(AccountName::try_from("emoji😀").is_err());
        assert!(AccountName::try_from("über").is_err());
        assert!(AccountName::try_from("naïve").is_err());
    }

    #[test]
    fn invalid_dollar_in_middle() {
        assert!(AccountName::try_from("alice$bob").is_err());
        assert!(AccountName::try_from("test$").is_err());
        assert!(AccountName::try_from("a$b").is_err());
    }

    #[test]
    fn invalid_dollar_in_system_account_name() {
        assert!(AccountName::try_from("$sys$tem").is_err());
        assert!(AccountName::try_from("$$system").is_err());
        assert!(AccountName::try_from("$system$").is_err());
    }

    #[test]
    fn invalid_start_with_special() {
        assert!(AccountName::try_from("_alice").is_err());
        assert!(AccountName::try_from("-alice").is_err());
        assert!(AccountName::try_from(".alice").is_err());
        assert!(AccountName::try_from("_123").is_err());
    }

    #[test]
    fn invalid_end_with_special() {
        assert!(AccountName::try_from("alice_").is_err());
        assert!(AccountName::try_from("alice-").is_err());
        assert!(AccountName::try_from("alice.").is_err());
        assert!(AccountName::try_from("123-").is_err());
    }

    #[test]
    fn invalid_system_account_start_with_special() {
        assert!(AccountName::try_from("$_system").is_err());
        assert!(AccountName::try_from("$-system").is_err());
        assert!(AccountName::try_from("$.system").is_err());
    }

    #[test]
    fn invalid_system_account_end_with_special() {
        assert!(AccountName::try_from("$system_").is_err());
        assert!(AccountName::try_from("$system-").is_err());
        assert!(AccountName::try_from("$system.").is_err());
    }

    #[test]
    fn invalid_consecutive_underscores() {
        assert!(AccountName::try_from("alice__bob").is_err());
        assert!(AccountName::try_from("a___b").is_err());
    }

    #[test]
    fn invalid_consecutive_hyphens() {
        assert!(AccountName::try_from("alice--bob").is_err());
        assert!(AccountName::try_from("a---b").is_err());
    }

    #[test]
    fn invalid_consecutive_periods() {
        assert!(AccountName::try_from("alice..bob").is_err());
        assert!(AccountName::try_from("a...b").is_err());
    }

    #[test]
    fn invalid_mixed_consecutive_specials() {
        assert!(AccountName::try_from("alice._bob").is_err());
        assert!(AccountName::try_from("alice-.bob").is_err());
        assert!(AccountName::try_from("alice_-bob").is_err());
        assert!(AccountName::try_from("alice.-bob").is_err());
        assert!(AccountName::try_from("alice-_bob").is_err());
        assert!(AccountName::try_from("alice_.bob").is_err());
    }

    #[test]
    fn canonicalization_is_consistent() {
        let name1 = AccountName::try_from("Alice").unwrap();
        let name2 = AccountName::try_from("ALICE").unwrap();
        let name3 = AccountName::try_from("alice").unwrap();
        let name4 = AccountName::try_from("aLiCe").unwrap();

        assert_eq!(name1, name2);
        assert_eq!(name2, name3);
        assert_eq!(name3, name4);
        assert_eq!(name1.as_str(), "alice");
    }

    #[test]
    fn as_str_returns_canonical() {
        let name = AccountName::try_from("MyAccount").unwrap();
        assert_eq!(name.as_str(), "myaccount");
    }

    #[test]
    fn to_string_returns_canonical() {
        let name = AccountName::try_from("MyAccount").unwrap();
        assert_eq!(name.to_string(), "myaccount");
    }

    #[test]
    fn as_ref_returns_canonical() {
        let name = AccountName::try_from("MyAccount").unwrap();
        let s: &str = name.as_ref();
        assert_eq!(s, "myaccount");
    }

    #[test]
    fn is_system_account_true() {
        let name = AccountName::try_from("$system").unwrap();
        assert!(name.is_system_name());

        let name = AccountName::try_from("$ADMIN").unwrap();
        assert!(name.is_system_name());
    }

    #[test]
    fn is_system_account_false() {
        let name = AccountName::try_from("alice").unwrap();
        assert!(!name.is_system_name());

        let name = AccountName::try_from("system").unwrap();
        assert!(!name.is_system_name());
    }

    #[test]
    fn equality_with_str() {
        let name = AccountName::try_from("Alice").unwrap();
        assert_eq!(name, "alice");
        assert_eq!(name, "ALICE");
        assert_eq!(name, "Alice");
        assert_ne!(name, "bob");
    }

    #[test]
    fn equality_between_account_names() {
        let name1 = AccountName::try_from("Alice").unwrap();
        let name2 = AccountName::try_from("alice").unwrap();
        let name3 = AccountName::try_from("bob").unwrap();

        assert_eq!(name1, name2);
        assert_ne!(name1, name3);
    }

    #[test]
    fn try_from_str() {
        let name = AccountName::try_from("alice").unwrap();
        assert_eq!(name.as_str(), "alice");
    }

    #[test]
    fn try_from_string() {
        let s = String::from("alice");
        let name = AccountName::try_from(s).unwrap();
        assert_eq!(name.as_str(), "alice");
    }

    #[test]
    fn try_from_ref_string() {
        let s = String::from("alice");
        let name = AccountName::try_from(&s).unwrap();
        assert_eq!(name.as_str(), "alice");
    }

    #[test]
    fn clone_works() {
        let name1 = AccountName::try_from("alice").unwrap();
        let name2 = name1.clone();
        assert_eq!(name1, name2);
    }

    #[test]
    fn hash_is_consistent() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(AccountName::try_from("alice").unwrap());
        set.insert(AccountName::try_from("ALICE").unwrap()); // Same as "alice"
        set.insert(AccountName::try_from("bob").unwrap());

        assert_eq!(set.len(), 2); // alice and bob
        assert!(set.contains(&AccountName::try_from("Alice").unwrap()));
    }

    #[test]
    fn display_format() {
        let name = AccountName::try_from("Alice").unwrap();
        assert_eq!(format!("{name}"), "alice");

        let name = AccountName::try_from("$SYSTEM").unwrap();
        assert_eq!(format!("{name}"), "$system");
    }

    #[test]
    fn edge_case_all_numbers() {
        assert!(AccountName::try_from("123").is_ok());
        assert!(AccountName::try_from("000").is_ok());
        assert!(AccountName::try_from("999999").is_ok());
    }

    #[test]
    fn edge_case_single_special_in_middle() {
        assert!(AccountName::try_from("a_b").is_ok());
        assert!(AccountName::try_from("a-b").is_ok());
        assert!(AccountName::try_from("a.b").is_ok());
    }

    #[test]
    fn edge_case_alternating_specials() {
        assert!(AccountName::try_from("a_b-c.d").is_ok());
        assert!(AccountName::try_from("1-2_3.4").is_ok());
    }

    #[test]
    fn edge_case_exactly_min_length() {
        assert!(AccountName::try_from("abc").is_ok());
        assert!(AccountName::try_from("ab").is_err());
    }

    #[test]
    fn edge_case_exactly_max_length() {
        let exactly_64 = "a".repeat(64);
        let exactly_65 = "a".repeat(65);
        assert!(AccountName::try_from(exactly_64.as_str()).is_ok());
        assert!(AccountName::try_from(exactly_65.as_str()).is_err());
    }

    #[test]
    fn edge_case_system_account_exactly_min() {
        // $abc = $ + 3 chars minimum
        assert!(AccountName::try_from("$abc").is_ok());
        assert!(AccountName::try_from("$ab").is_err());
    }

    #[test]
    fn edge_case_system_account_exactly_max() {
        // $ + 64 chars = 65 total
        let exactly_max = "$".to_string() + &"a".repeat(64);
        let over_max = "$".to_string() + &"a".repeat(65);
        assert!(AccountName::try_from(exactly_max.as_str()).is_ok());
        assert!(AccountName::try_from(over_max.as_str()).is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let original = AccountName::try_from("Alice").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"alice\"");

        let deserialized: AccountName = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn serde_deserialize_with_validation() {
        // Valid name
        let result: Result<AccountName, _> = serde_json::from_str("\"alice\"");
        assert!(result.is_ok());

        // Invalid name (too short)
        let result: Result<AccountName, _> = serde_json::from_str("\"ab\"");
        assert!(result.is_err());

        // Invalid name (bad chars)
        let result: Result<AccountName, _> = serde_json::from_str("\"alice@bob\"");
        assert!(result.is_err());
    }

    #[test]
    fn serde_deserialize_canonicalizes() {
        let name: AccountName = serde_json::from_str("\"ALICE\"").unwrap();
        assert_eq!(name.as_str(), "alice");
    }

    #[test]
    fn system_constructor() {
        let name = AccountName::system();
        assert_eq!(name.as_str(), "$system");
        assert!(name.is_system_name());
    }

    #[test]
    fn from_str_trait() {
        use std::str::FromStr;
        let name = AccountName::from_str("alice").unwrap();
        assert_eq!(name.as_str(), "alice");
        assert!(AccountName::from_str("ab").is_err());
    }

    #[test]
    fn partial_eq_str_impl() {
        let name = AccountName::try_from("alice").unwrap();
        // PartialEq<str> (not &str) — call via explicit trait dispatch
        assert!(<AccountName as PartialEq<str>>::eq(&name, "alice"));
        assert!(<AccountName as PartialEq<str>>::eq(&name, "ALICE")); // case-insensitive
        assert!(!<AccountName as PartialEq<str>>::eq(&name, "bob"));
    }
}
