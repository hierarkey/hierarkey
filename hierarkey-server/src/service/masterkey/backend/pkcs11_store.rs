// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

#![allow(unused)]

use hierarkey_core::{CkError, CkResult};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pkcs11Ref {
    pub library_path: String,
    #[serde(default)]
    pub slot_id: Option<u64>,
    #[serde(default)]
    pub token_label: Option<String>,
    pub key_label: String,
    #[serde(default)]
    pub user_type: Option<String>,
    #[serde(default)]
    pub pin_policy: Option<String>,
}

impl Pkcs11Ref {
    pub fn from_json(value: &JsonValue) -> CkResult<Self> {
        let r: Pkcs11Ref = serde_json::from_value(value.clone())
            .map_err(|e| CkError::MasterKey(format!("invalid pkcs11_ref json: {e}")))?;

        r.validate()?;
        Ok(r)
    }

    /// Convert back to JSON
    pub fn to_json(&self) -> CkResult<JsonValue> {
        serde_json::to_value(self).map_err(|e| CkError::MasterKey(format!("pkcs11_ref serialize: {e}")))
    }

    /// Validate required fields / invariants.
    pub fn validate(&self) -> CkResult<()> {
        if self.library_path.trim().is_empty() {
            return Err(CkError::MasterKey("pkcs11_ref.library_path is required".into()));
        }
        if self.key_label.trim().is_empty() {
            return Err(CkError::MasterKey("pkcs11_ref.key_label is required".into()));
        }

        let has_slot = self.slot_id.is_some();
        let has_token = self.token_label.as_ref().is_some_and(|s| !s.trim().is_empty());

        if !has_slot && !has_token {
            return Err(CkError::MasterKey(
                "pkcs11_ref must include either slot_id or token_label".into(),
            ));
        }

        if self.library_path.contains('\0') || self.key_label.contains('\0') {
            return Err(CkError::MasterKey("pkcs11_ref contains NUL byte".into()));
        }
        if let Some(t) = &self.token_label
            && t.contains('\0')
        {
            return Err(CkError::MasterKey("pkcs11_ref.token_label contains NUL byte".into()));
        }

        Ok(())
    }

    /// A stable, non-secret fingerprint for checksums/audit/debugging.
    pub fn fingerprint(&self) -> String {
        // Keep it stable and explicit; do not include PIN.
        let slot = self.slot_id.map(|v| v.to_string()).unwrap_or_else(|| "-".into());
        let token = self.token_label.clone().unwrap_or_else(|| "-".into());
        let user_type = self.user_type.clone().unwrap_or_else(|| "-".into());
        let pin_policy = self.pin_policy.clone().unwrap_or_else(|| "-".into());

        format!(
            "pkcs11:lib={};slot={};token={};key={};user_type={};pin_policy={}",
            self.library_path, slot, token, self.key_label, user_type, pin_policy
        )
    }
}

/// Extract a PIN from UnlockArgs
pub fn pin_from_unlock_args(args: &crate::service::masterkey::provider::UnlockArgs) -> CkResult<Zeroizing<String>> {
    match args {
        crate::service::masterkey::provider::UnlockArgs::Pkcs11 { pin } => Ok(pin.clone()),
        _ => Err(CkError::MasterKey("invalid unlock arguments for pkcs11 provider".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::masterkey::provider::UnlockArgs;
    use zeroize::Zeroizing;

    fn valid_ref() -> Pkcs11Ref {
        Pkcs11Ref {
            library_path: "/usr/lib/libpkcs11.so".into(),
            slot_id: Some(0),
            token_label: None,
            key_label: "my-key".into(),
            user_type: None,
            pin_policy: None,
        }
    }

    #[test]
    fn validate_valid_with_slot_id() {
        assert!(valid_ref().validate().is_ok());
    }

    #[test]
    fn validate_valid_with_token_label() {
        let mut r = valid_ref();
        r.slot_id = None;
        r.token_label = Some("MyToken".into());
        assert!(r.validate().is_ok());
    }

    #[test]
    fn validate_missing_library_path_fails() {
        let mut r = valid_ref();
        r.library_path = "".into();
        assert!(r.validate().is_err());
    }

    #[test]
    fn validate_whitespace_library_path_fails() {
        let mut r = valid_ref();
        r.library_path = "   ".into();
        assert!(r.validate().is_err());
    }

    #[test]
    fn validate_missing_key_label_fails() {
        let mut r = valid_ref();
        r.key_label = "".into();
        assert!(r.validate().is_err());
    }

    #[test]
    fn validate_no_slot_or_token_fails() {
        let mut r = valid_ref();
        r.slot_id = None;
        r.token_label = None;
        assert!(r.validate().is_err());
    }

    #[test]
    fn validate_nul_in_library_path_fails() {
        let mut r = valid_ref();
        r.library_path = "/lib/bad\0path.so".into();
        assert!(r.validate().is_err());
    }

    #[test]
    fn validate_nul_in_key_label_fails() {
        let mut r = valid_ref();
        r.key_label = "key\0label".into();
        assert!(r.validate().is_err());
    }

    #[test]
    fn validate_nul_in_token_label_fails() {
        let mut r = valid_ref();
        r.slot_id = None;
        r.token_label = Some("tok\0en".into());
        assert!(r.validate().is_err());
    }

    #[test]
    fn from_json_roundtrip() {
        let r = valid_ref();
        let json = r.to_json().unwrap();
        let r2 = Pkcs11Ref::from_json(&json).unwrap();
        assert_eq!(r2.library_path, r.library_path);
        assert_eq!(r2.key_label, r.key_label);
        assert_eq!(r2.slot_id, r.slot_id);
    }

    #[test]
    fn from_json_invalid_fails() {
        let json = serde_json::json!({"not_a_valid_field": true});
        // Missing required fields -> validate() should fail
        assert!(Pkcs11Ref::from_json(&json).is_err());
    }

    #[test]
    fn fingerprint_contains_key_info() {
        let r = valid_ref();
        let fp = r.fingerprint();
        assert!(fp.contains("pkcs11:"));
        assert!(fp.contains("my-key"));
        assert!(fp.contains("slot=0"));
    }

    #[test]
    fn pin_from_unlock_args_pkcs11() {
        let pin = Zeroizing::new("secret-pin".to_string());
        let args = UnlockArgs::Pkcs11 { pin: pin.clone() };
        let result = pin_from_unlock_args(&args).unwrap();
        assert_eq!(*result, *pin);
    }

    #[test]
    fn pin_from_unlock_args_wrong_type_fails() {
        let args = UnlockArgs::None;
        assert!(pin_from_unlock_args(&args).is_err());
    }
}
