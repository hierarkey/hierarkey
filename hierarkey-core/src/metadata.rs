// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::Labels;
use crate::api::search::query::SecretType;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef};
use sqlx::types::Json;
use sqlx::{Decode, Encode, Postgres, Type};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct Metadata(HashMap<String, serde_json::Value>);

const DESCRIPTION_KEY: &str = "description";
const LABELS_KEY: &str = "labels";

impl Metadata {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(&mut self, key: &str, value: impl Into<serde_json::Value>) {
        self.0.insert(key.to_string(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key)
    }

    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        self.0.remove(key)
    }

    pub fn add_description(&mut self, description: &str) {
        self.insert(DESCRIPTION_KEY, description);
    }

    pub fn clear_description(&mut self) {
        self.remove(DESCRIPTION_KEY);
    }

    pub fn remove_label(&mut self, key: &str) {
        if let Some(labels) = self.0.get_mut(LABELS_KEY)
            && let Some(obj) = labels.as_object_mut()
        {
            obj.remove(key);
        }
    }

    pub fn add_label(&mut self, key: &str, value: &str) {
        let labels = self.0.entry(LABELS_KEY.to_string()).or_insert_with(|| json!({}));

        if let Some(obj) = labels.as_object_mut() {
            obj.insert(key.to_string(), json!(value));
        }
    }

    pub fn add_labels(&mut self, labels: Labels) {
        self.insert(LABELS_KEY, json!(labels));
    }

    pub fn description(&self) -> Option<String> {
        self.0
            .get(DESCRIPTION_KEY)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    pub fn labels(&self) -> Labels {
        self.0
            .get(LABELS_KEY)
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn set_secret_type(&mut self, secret_type: SecretType) {
        self.insert("secret_type", secret_type.to_string());
    }

    pub fn secret_type(&self) -> SecretType {
        self.0
            .get("secret_type")
            .and_then(|v| v.as_str())
            .and_then(|s| SecretType::from_str(s).ok())
            .unwrap_or(SecretType::Opaque)
    }
}

impl Default for Metadata {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Metadata> for serde_json::Value {
    fn from(metadata: Metadata) -> Self {
        serde_json::Value::Object(metadata.0.into_iter().collect())
    }
}

impl From<HashMap<String, serde_json::Value>> for Metadata {
    fn from(map: HashMap<String, serde_json::Value>) -> Self {
        Self(map)
    }
}

impl Type<Postgres> for Metadata {
    fn type_info() -> PgTypeInfo {
        <Json<HashMap<String, serde_json::Value>> as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <Json<HashMap<String, serde_json::Value>> as Type<Postgres>>::compatible(ty)
    }
}

impl<'r> Decode<'r, Postgres> for Metadata {
    fn decode(value: PgValueRef<'r>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let Json(map) = <Json<HashMap<String, serde_json::Value>> as Decode<Postgres>>::decode(value)?;
        Ok(Metadata(map))
    }
}

impl<'q> Encode<'q, Postgres> for Metadata {
    fn encode_by_ref(
        &self,
        buf: &mut PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
        <Json<&HashMap<String, serde_json::Value>> as Encode<Postgres>>::encode(Json(&self.0), buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_new_metadata() {
        let metadata = Metadata::new();
        assert_eq!(metadata.0.len(), 0);
    }

    #[test]
    fn test_insert_and_get() {
        let mut metadata = Metadata::new();
        metadata.insert(DESCRIPTION_KEY, "foobar");
        metadata.insert("created_by", "John doe");

        assert_eq!(metadata.get(DESCRIPTION_KEY), Some(&json!("foobar")));
        assert_eq!(metadata.get("created_by"), Some(&json!("John doe")));
        assert_eq!(metadata.get("nonexistent"), None);
    }

    #[test]
    fn test_insert_different_types() {
        let mut metadata = Metadata::new();
        metadata.insert("string", "value");
        metadata.insert("number", 42);
        metadata.insert("boolean", true);
        metadata.insert("array", json!(["foo", "bar"]));
        metadata.insert("object", json!({"key": "value"}));

        assert_eq!(metadata.get("string"), Some(&json!("value")));
        assert_eq!(metadata.get("number"), Some(&json!(42)));
        assert_eq!(metadata.get("boolean"), Some(&json!(true)));
        assert_eq!(metadata.get("array"), Some(&json!(["foo", "bar"])));
        assert_eq!(metadata.get("object"), Some(&json!({"key": "value"})));
    }

    #[test]
    fn test_remove() {
        let mut metadata = Metadata::new();
        metadata.insert("key", "value");

        assert_eq!(metadata.remove("key"), Some(json!("value")));
        assert_eq!(metadata.get("key"), None);
        assert_eq!(metadata.remove("key"), None);
    }

    #[test]
    fn test_to_json_value() {
        let mut metadata = Metadata::new();
        metadata.insert(DESCRIPTION_KEY, "foobar");
        metadata.insert("created_by", "John doe");

        let json_value: serde_json::Value = metadata.into();
        assert_eq!(
            json_value,
            json!({
                DESCRIPTION_KEY: "foobar",
                "created_by": "John doe"
            })
        );
    }

    #[test]
    fn test_serialize() {
        let mut metadata = Metadata::new();
        metadata.insert(DESCRIPTION_KEY, "foobar");
        metadata.insert("count", 42);

        let serialized = serde_json::to_string(&metadata).unwrap();
        let expected = r#"{"description":"foobar","count":42}"#;

        let parsed_serialized: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        let parsed_expected: serde_json::Value = serde_json::from_str(expected).unwrap();
        assert_eq!(parsed_serialized, parsed_expected);
    }

    #[test]
    fn test_deserialize() {
        let json_str = r#"{"description":"foobar","created_by":"John doe","count":42}"#;
        let metadata: Metadata = serde_json::from_str(json_str).unwrap();

        assert_eq!(metadata.get("description"), Some(&json!("foobar")));
        assert_eq!(metadata.get("created_by"), Some(&json!("John doe")));
        assert_eq!(metadata.get("count"), Some(&json!(42)));
    }

    #[test]
    fn test_complex_structure() {
        let mut metadata = Metadata::new();
        metadata.insert(DESCRIPTION_KEY, "foobar");
        metadata.insert("created_by", "John doe");
        metadata.insert(
            LABELS_KEY,
            json!({
                "foo": "1",
                "bar": "baz",
                "write_protected": "true"
            }),
        );

        let json_value: serde_json::Value = metadata.into();
        assert_eq!(
            json_value,
            json!({
                "description": "foobar",
                "created_by": "John doe",
                "labels": {
                    "foo": "1",
                    "bar": "baz",
                    "write_protected": "true"
                }
            })
        );
    }

    #[test]
    fn test_from_hashmap() {
        let mut map = HashMap::new();
        map.insert("key1".to_string(), json!("value1"));
        map.insert("key2".to_string(), json!(123));

        let metadata: Metadata = map.into();
        assert_eq!(metadata.get("key1"), Some(&json!("value1")));
        assert_eq!(metadata.get("key2"), Some(&json!(123)));
    }

    #[test]
    fn test_default() {
        let metadata = Metadata::default();
        assert_eq!(metadata.0.len(), 0);
    }

    #[test]
    fn test_description_helper() {
        let mut metadata = Metadata::new();
        assert_eq!(metadata.description(), None);

        metadata.insert(DESCRIPTION_KEY, "foobar");
        assert_eq!(metadata.description(), Some("foobar".to_string()));

        metadata.insert(DESCRIPTION_KEY, 123);
        assert_eq!(metadata.description(), None);
    }

    #[test]
    fn test_labels_helper() {
        let mut metadata = Metadata::new();
        assert_eq!(metadata.labels(), HashMap::new());

        metadata.insert(
            LABELS_KEY,
            json!({
                "foo": "1",
                "bar": "baz",
                "write_protected": "true"
            }),
        );

        let labels = metadata.labels();
        assert_eq!(labels.get("foo"), Some(&"1".to_string()));
        assert_eq!(labels.get("bar"), Some(&"baz".to_string()));
        assert_eq!(labels.get("write_protected"), Some(&"true".to_string()));

        metadata.insert(LABELS_KEY, "not an object");
        assert_eq!(metadata.labels(), HashMap::new());
    }

    #[test]
    fn test_labels_helper_filters_non_strings() {
        let mut metadata = Metadata::new();
        metadata.insert(
            LABELS_KEY,
            json!({
                "foo": "valid_string",
                "bar": 123,
                "baz": true,
                "qux": "another_string"
            }),
        );

        let labels = metadata.labels();
        assert_eq!(labels.get("foo"), Some(&"valid_string".to_string()));
        assert_eq!(labels.get("bar"), None);
        assert_eq!(labels.get("baz"), None);
        assert_eq!(labels.get("qux"), Some(&"another_string".to_string()));
    }

    #[test]
    fn test_add_label() {
        let mut metadata = Metadata::new();
        metadata.add_label("foo", "bar");

        let labels = metadata.labels();
        assert_eq!(labels.get("foo"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_add_label_multiple() {
        let mut metadata = Metadata::new();
        metadata.add_label("foo", "bar");
        metadata.add_label("baz", "qux");
        metadata.add_label("num", "123");

        let labels = metadata.labels();
        assert_eq!(labels.get("foo"), Some(&"bar".to_string()));
        assert_eq!(labels.get("baz"), Some(&"qux".to_string()));
        assert_eq!(labels.get("num"), Some(&"123".to_string()));
    }

    #[test]
    fn test_add_label_overwrites() {
        let mut metadata = Metadata::new();
        metadata.add_label("foo", "bar");
        metadata.add_label("foo", "updated");

        let labels = metadata.labels();
        assert_eq!(labels.get("foo"), Some(&"updated".to_string()));
    }

    #[test]
    fn test_remove_label() {
        let mut metadata = Metadata::new();
        metadata.add_label("foo", "bar");
        metadata.add_label("baz", "qux");

        metadata.remove_label("foo");

        let labels = metadata.labels();
        assert_eq!(labels.get("foo"), None);
        assert_eq!(labels.get("baz"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_remove_label_nonexistent() {
        let mut metadata = Metadata::new();
        metadata.add_label("foo", "bar");

        metadata.remove_label("nonexistent");

        let labels = metadata.labels();
        assert_eq!(labels.get("foo"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_remove_label_no_labels() {
        let mut metadata = Metadata::new();
        metadata.remove_label("foo");

        let labels = metadata.labels();
        assert_eq!(labels.len(), 0);
    }

    #[test]
    fn test_add_labels_empty() {
        let mut metadata = Metadata::new();
        metadata.add_labels(HashMap::new());

        let labels = metadata.labels();
        assert_eq!(labels.len(), 0);
    }

    #[test]
    fn test_add_labels_multiple() {
        let mut metadata = Metadata::new();
        let mut labels_map = HashMap::new();
        labels_map.insert("foo".to_string(), "1".to_string());
        labels_map.insert("bar".to_string(), "baz".to_string());
        labels_map.insert("write_protected".to_string(), "true".to_string());

        metadata.add_labels(labels_map);

        let labels = metadata.labels();
        assert_eq!(labels.get("foo"), Some(&"1".to_string()));
        assert_eq!(labels.get("bar"), Some(&"baz".to_string()));
        assert_eq!(labels.get("write_protected"), Some(&"true".to_string()));
    }

    #[test]
    fn test_add_labels_replaces_existing() {
        let mut metadata = Metadata::new();
        metadata.add_label("existing", "old");

        let mut labels_map = HashMap::new();
        labels_map.insert("foo".to_string(), "bar".to_string());
        labels_map.insert("baz".to_string(), "qux".to_string());

        metadata.add_labels(labels_map);

        let labels = metadata.labels();
        assert_eq!(labels.get("existing"), None);
        assert_eq!(labels.get("foo"), Some(&"bar".to_string()));
        assert_eq!(labels.get("baz"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_add_label_then_add_labels() {
        let mut metadata = Metadata::new();
        metadata.add_label("initial", "value");

        let mut labels_map = HashMap::new();
        labels_map.insert("foo".to_string(), "bar".to_string());

        metadata.add_labels(labels_map);

        let labels = metadata.labels();
        assert_eq!(labels.get("initial"), None);
        assert_eq!(labels.get("foo"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_add_labels_then_add_label() {
        let mut metadata = Metadata::new();

        let mut labels_map = HashMap::new();
        labels_map.insert("foo".to_string(), "bar".to_string());
        metadata.add_labels(labels_map);

        metadata.add_label("additional", "value");

        let labels = metadata.labels();
        assert_eq!(labels.get("foo"), Some(&"bar".to_string()));
        assert_eq!(labels.get("additional"), Some(&"value".to_string()));
    }

    #[test]
    fn test_remove_all_labels() {
        let mut metadata = Metadata::new();
        metadata.add_label("foo", "bar");
        metadata.add_label("baz", "qux");

        metadata.remove_label("foo");
        metadata.remove_label("baz");

        let labels = metadata.labels();
        assert_eq!(labels.len(), 0);
    }
}
