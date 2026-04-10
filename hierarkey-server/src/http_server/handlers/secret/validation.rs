// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as base64_standard, URL_SAFE_NO_PAD as base64_url};
use hierarkey_core::api::search::query::SecretType;
use hierarkey_core::error::validation::ValidationError;
use hierarkey_core::{CkError, CkResult};

use crate::manager::secret::secret_data::SecretData;

// Known schemes for connection strings.
const CONNECTION_STRING_SCHEMES: &[&str] = &[
    "postgres",
    "postgresql",
    "mysql",
    "mariadb",
    "redis",
    "rediss",
    "mongodb",
    "mongodb+srv",
    "amqp",
    "amqps",
    "cassandra",
    "elasticsearch",
    "kafka",
    "memcached",
    "couchdb",
    "neo4j",
    "bolt",
];

// PEM label groups.
const PRIVATE_KEY_LABELS: &[&str] = &[
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
];

const PUBLIC_KEY_LABELS: &[&str] = &["PUBLIC KEY", "RSA PUBLIC KEY"];

/// Validate that the secret data is appropriate for the given secret type.
pub(super) fn validate_secret_data(data: &SecretData, secret_type: SecretType) -> CkResult<()> {
    match secret_type {
        SecretType::Opaque => Ok(()),
        SecretType::Password => Ok(()),
        SecretType::Json => validate_json(data),
        SecretType::Yaml => validate_yaml(data),
        SecretType::Jwt => validate_jwt(data),
        SecretType::Certificate => validate_pem_labeled(data, &["CERTIFICATE"], 1, Some(1)),
        SecretType::CertificateChain => validate_pem_labeled(data, &["CERTIFICATE"], 1, None),
        SecretType::CertificateKeyPair => validate_cert_key_pair(data),
        SecretType::PrivateKey => validate_pem_labeled(data, PRIVATE_KEY_LABELS, 1, Some(1)),
        SecretType::PublicKey => validate_pem_labeled(data, PUBLIC_KEY_LABELS, 1, Some(1)),
        SecretType::SshPrivateKey => validate_ssh_private_key(data),
        SecretType::Uri => validate_uri(data, None),
        SecretType::ConnectionString => validate_uri(data, Some(CONNECTION_STRING_SCHEMES)),
    }
}

fn err(code: &'static str, message: impl Into<std::borrow::Cow<'static, str>>) -> CkError {
    ValidationError::Field {
        field: "value",
        code,
        message: message.into(),
    }
    .into()
}

fn require_utf8<'a>(data: &'a SecretData, code: &'static str) -> CkResult<&'a str> {
    std::str::from_utf8(data.expose_secret()).map_err(|_| err(code, "value must be valid UTF-8"))
}

fn validate_json(data: &SecretData) -> CkResult<()> {
    let text = require_utf8(data, "invalid_utf8")?;
    serde_json::from_str::<serde_json::Value>(text).map_err(|e| err("invalid_json", format!("not valid JSON: {e}")))?;
    Ok(())
}

fn validate_yaml(data: &SecretData) -> CkResult<()> {
    let text = require_utf8(data, "invalid_utf8")?;
    serde_yaml::from_str::<serde_yaml::Value>(text).map_err(|e| err("invalid_yaml", format!("not valid YAML: {e}")))?;
    Ok(())
}

fn validate_jwt(data: &SecretData) -> CkResult<()> {
    let text = require_utf8(data, "invalid_utf8")?;
    let text = text.trim();

    let parts: Vec<&str> = text.splitn(4, '.').collect();
    if parts.len() != 3 {
        return Err(err("invalid_jwt", "JWT must have exactly three dot-separated parts"));
    }

    // Decode and validate the header (first part).
    let header_bytes = base64_url
        .decode(parts[0])
        .map_err(|_| err("invalid_jwt", "JWT header is not valid base64url"))?;

    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| err("invalid_jwt", "JWT header is not valid JSON"))?;

    if !header.is_object() {
        return Err(err("invalid_jwt", "JWT header must be a JSON object"));
    }

    if header.get("alg").is_none() {
        return Err(err("invalid_jwt", "JWT header must contain an 'alg' field"));
    }

    // Payload must be valid base64url (we don't require it to be JSON — JWTs allow
    // opaque payloads, e.g. JWE).
    base64_url
        .decode(parts[1])
        .map_err(|_| err("invalid_jwt", "JWT payload is not valid base64url"))?;

    // Signature must be valid base64url.
    base64_url
        .decode(parts[2])
        .map_err(|_| err("invalid_jwt", "JWT signature is not valid base64url"))?;

    Ok(())
}

/// A decoded PEM block.
struct PemBlock {
    label: String,
    der: Vec<u8>,
}

// /// Extract all well-formed PEM blocks from `pem` whose label is in `allowed_labels`.
// /// Each label in `allowed_labels` is matched against `-----BEGIN {label}-----`.
// /// Returns an error string if a matching BEGIN is found without a matching END,
// /// or if the base64 body is invalid.
// fn extract_pem_blocks(pem: &str, allowed_labels: &[&str]) -> Result<Vec<PemBlock>, String> {
//     let mut blocks = Vec::new();
//
//     for &label in allowed_labels {
//         let header = format!("-----BEGIN {label}-----");
//         let footer = format!("-----END {label}-----");
//         let mut rest = pem;
//
//         loop {
//             let Some(start) = rest.find(&header) else {
//                 break;
//             };
//
//             let after_header = &rest[start + header.len()..];
//
//             let Some(end) = after_header.find(&footer) else {
//                 return Err(format!("PEM block 'BEGIN {label}' has no matching END"));
//             };
//
//             let body: String = after_header[..end].chars().filter(|c| !c.is_whitespace()).collect();
//
//             if body.is_empty() {
//                 return Err(format!("PEM block '{label}' has an empty body"));
//             }
//
//             let der = base64_standard
//                 .decode(&body)
//                 .map_err(|_| format!("PEM block '{label}' contains invalid base64"))?;
//
//             blocks.push(PemBlock {
//                 label: label.to_string(),
//                 der,
//             });
//             rest = &after_header[end + footer.len()..];
//         }
//     }
//
//     // Sort by order of appearance so count checks are label-order-independent.
//     // (Stable: blocks are pushed in label order, not document order, so re-sort.)
//     // Re-extract in document order by scanning once more.
//     let _ = blocks; // discard label-ordered result
//     extract_pem_blocks_ordered(pem, allowed_labels)
// }

/// Like `extract_pem_blocks` but preserves document order across all labels.
fn extract_pem_blocks_ordered(pem: &str, allowed_labels: &[&str]) -> Result<Vec<PemBlock>, String> {
    let mut blocks: Vec<(usize, PemBlock)> = Vec::new();

    for &label in allowed_labels {
        let header = format!("-----BEGIN {label}-----");
        let footer = format!("-----END {label}-----");
        let mut rest = pem;
        let mut offset = 0;

        while let Some(rel_start) = rest.find(&header) {
            let abs_start = offset + rel_start;
            let after_header = &rest[rel_start + header.len()..];

            let Some(end) = after_header.find(&footer) else {
                return Err(format!("PEM block 'BEGIN {label}' has no matching END"));
            };

            let body: String = after_header[..end].chars().filter(|c| !c.is_whitespace()).collect();

            if body.is_empty() {
                return Err(format!("PEM block '{label}' has an empty body"));
            }

            let der = base64_standard
                .decode(&body)
                .map_err(|_| format!("PEM block '{label}' contains invalid base64"))?;

            blocks.push((
                abs_start,
                PemBlock {
                    label: label.to_string(),
                    der,
                },
            ));
            offset = abs_start + header.len() + end + footer.len();
            rest = &pem[offset..];
        }
    }

    blocks.sort_by_key(|(pos, _)| *pos);
    Ok(blocks.into_iter().map(|(_, b)| b).collect())
}

fn validate_pem_labeled(data: &SecretData, allowed_labels: &[&str], min: usize, max: Option<usize>) -> CkResult<()> {
    let text = require_utf8(data, "invalid_utf8")?;

    let blocks = extract_pem_blocks_ordered(text, allowed_labels).map_err(|e| err("invalid_pem", e))?;
    let count = blocks.len();

    if count < min {
        let label_list = allowed_labels.join(" / ");
        return Err(err(
            "invalid_pem",
            format!("expected at least {min} PEM block(s) [{label_list}], found {count}"),
        ));
    }

    if let Some(max) = max
        && count > max
    {
        let label_list = allowed_labels.join(" / ");
        return Err(err(
            "invalid_pem",
            format!("expected at most {max} PEM block(s) [{label_list}], found {count}"),
        ));
    }

    Ok(())
}

fn validate_ssh_private_key(data: &SecretData) -> CkResult<()> {
    let text = require_utf8(data, "invalid_utf8")?;

    let blocks =
        extract_pem_blocks_ordered(text, &["OPENSSH PRIVATE KEY"]).map_err(|e| err("invalid_ssh_private_key", e))?;

    if blocks.len() != 1 {
        return Err(err(
            "invalid_ssh_private_key",
            format!("expected exactly one 'BEGIN OPENSSH PRIVATE KEY' block, found {}", blocks.len()),
        ));
    }

    // The OpenSSH private key format starts with a fixed magic string.
    const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
    if !blocks[0].der.starts_with(OPENSSH_MAGIC) {
        return Err(err(
            "invalid_ssh_private_key",
            "OpenSSH private key body does not start with expected magic bytes",
        ));
    }

    Ok(())
}

fn validate_uri(data: &SecretData, allowed_schemes: Option<&[&str]>) -> CkResult<()> {
    let text = require_utf8(data, "invalid_utf8")?;
    let text = text.trim();

    let parsed = url::Url::parse(text).map_err(|e| err("invalid_uri", format!("not a valid URI: {e}")))?;

    if let Some(schemes) = allowed_schemes {
        let scheme = parsed.scheme();
        if !schemes.contains(&scheme) {
            return Err(err(
                "invalid_connection_string",
                format!("unsupported scheme '{scheme}'; expected one of: {}", schemes.join(", ")),
            ));
        }
    }

    Ok(())
}

fn validate_cert_key_pair(data: &SecretData) -> CkResult<()> {
    let text = require_utf8(data, "invalid_utf8")?;

    // Extract exactly one certificate block.
    let cert_blocks =
        extract_pem_blocks_ordered(text, &["CERTIFICATE"]).map_err(|e| err("invalid_cert_key_pair", e))?;

    if cert_blocks.len() != 1 {
        return Err(err(
            "invalid_cert_key_pair",
            format!("expected exactly one CERTIFICATE block, found {}", cert_blocks.len()),
        ));
    }

    // Extract exactly one private key block (any flavour).
    let key_blocks =
        extract_pem_blocks_ordered(text, PRIVATE_KEY_LABELS).map_err(|e| err("invalid_cert_key_pair", e))?;

    if key_blocks.len() != 1 {
        return Err(err(
            "invalid_cert_key_pair",
            format!("expected exactly one private key block, found {}", key_blocks.len()),
        ));
    }

    let cert_der = &cert_blocks[0].der;
    let key_der = &key_blocks[0].der;
    let key_label = key_blocks[0].label.as_str();

    // Only PKCS#8 keys ("PRIVATE KEY") can be verified via ring.
    // Legacy PEM formats (RSA PRIVATE KEY, EC PRIVATE KEY) require additional
    // parsing. Accept them structurally but skip crypto verification.
    if key_label != "PRIVATE KEY" {
        return Ok(());
    }

    verify_key_matches_cert(cert_der, key_der).map_err(|e| err("invalid_cert_key_pair", e))
}

/// Verify that the PKCS#8 private key (`key_der`) matches the public key in
/// the X.509 certificate (`cert_der`).
/// Supports Ed25519, ECDSA P-256, and ECDSA P-384.
fn verify_key_matches_cert(cert_der: &[u8], key_der: &[u8]) -> Result<(), String> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|_| "failed to parse certificate DER".to_string())?;

    // Raw bytes of the subjectPublicKey BIT STRING (the actual key material,
    // not the SubjectPublicKeyInfo wrapper).
    let cert_pub_key_bytes = cert.tbs_certificate.subject_pki.subject_public_key.as_ref();

    // Try each algorithm ring supports for PKCS#8.
    let extracted = try_extract_public_key_bytes(key_der)?;

    if extracted != cert_pub_key_bytes {
        return Err("private key does not match the certificate's public key".into());
    }

    Ok(())
}

/// Attempt to extract the raw public key bytes from a PKCS#8 DER blob by
/// trying each algorithm ring knows about.
/// Returns the raw public key bytes on success, or an error if no algorithm matched.
fn try_extract_public_key_bytes(key_der: &[u8]) -> Result<Vec<u8>, String> {
    use ring::signature::KeyPair;

    // Ed25519
    if let Ok(pair) = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(key_der) {
        return Ok(pair.public_key().as_ref().to_vec());
    }

    let rng = ring::rand::SystemRandom::new();

    // ECDSA P-256
    if let Ok(pair) =
        ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, key_der, &rng)
    {
        return Ok(pair.public_key().as_ref().to_vec());
    }

    // ECDSA P-384
    if let Ok(pair) =
        ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING, key_der, &rng)
    {
        return Ok(pair.public_key().as_ref().to_vec());
    }

    Err("private key algorithm not supported for matching (only Ed25519, P-256, P-384 ECDSA); structural validation passed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::secret::secret_data::SecretData;
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD as b64, URL_SAFE_NO_PAD as b64url};
    use hierarkey_core::api::search::query::SecretType;

    fn data(s: &str) -> SecretData {
        SecretData::from_vec(s.as_bytes().to_vec())
    }

    fn data_bytes(b: &[u8]) -> SecretData {
        SecretData::from_slice_copy(b)
    }

    fn fake_cert_pem() -> String {
        let body = b64.encode(b"not-a-real-cert-but-valid-base64");
        format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
    }

    fn fake_key_pem(label: &str) -> String {
        let body = b64.encode(b"not-a-real-key-but-valid-base64");
        format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
    }

    fn make_jwt(header: &str, payload: &str, sig: &str) -> String {
        format!("{}.{}.{}", b64url.encode(header), b64url.encode(payload), b64url.encode(sig))
    }

    fn make_openssh_pem() -> String {
        let mut payload = b"openssh-key-v1\0".to_vec();
        payload.extend_from_slice(b"rest-of-key-data");
        let body = b64.encode(&payload);
        format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n")
    }

    /// Generate a real self-signed cert + PKCS#8 private key using rcgen.
    /// Returns (cert_pem, key_pem, combined_pem).
    fn real_cert_and_key() -> (String, String, String) {
        let cert_key = rcgen::generate_simple_self_signed(["localhost".into()]).unwrap();
        let cert_pem = cert_key.cert.pem();
        let key_pem = cert_key.key_pair.serialize_pem();
        let combined = format!("{cert_pem}{key_pem}");
        (cert_pem, key_pem, combined)
    }

    #[test]
    fn opaque_accepts_binary() {
        assert!(validate_secret_data(&data_bytes(&[0, 1, 2, 255]), SecretType::Opaque).is_ok());
    }

    #[test]
    fn opaque_accepts_text() {
        assert!(validate_secret_data(&data("hello world"), SecretType::Opaque).is_ok());
    }

    #[test]
    fn opaque_accepts_empty() {
        assert!(validate_secret_data(&data(""), SecretType::Opaque).is_ok());
    }

    #[test]
    fn password_accepts_text() {
        assert!(validate_secret_data(&data("hunter2"), SecretType::Password).is_ok());
    }

    #[test]
    fn password_accepts_binary_for_now() {
        // No rules defined yet — anything passes.
        assert!(validate_secret_data(&data_bytes(&[0xff, 0x00]), SecretType::Password).is_ok());
    }

    #[test]
    fn json_accepts_object() {
        assert!(validate_secret_data(&data(r#"{"key":"value","n":42}"#), SecretType::Json).is_ok());
    }

    #[test]
    fn json_accepts_array() {
        assert!(validate_secret_data(&data(r#"[1,2,3]"#), SecretType::Json).is_ok());
    }

    #[test]
    fn json_accepts_scalar() {
        assert!(validate_secret_data(&data("42"), SecretType::Json).is_ok());
        assert!(validate_secret_data(&data("true"), SecretType::Json).is_ok());
        assert!(validate_secret_data(&data("null"), SecretType::Json).is_ok());
    }

    #[test]
    fn json_accepts_nested() {
        assert!(validate_secret_data(&data(r#"{"a":{"b":{"c":[1,2,3]}}}"#), SecretType::Json).is_ok());
    }

    #[test]
    fn json_rejects_bare_text() {
        assert!(validate_secret_data(&data("not json"), SecretType::Json).is_err());
    }

    #[test]
    fn json_rejects_malformed_object() {
        assert!(validate_secret_data(&data("{bad}"), SecretType::Json).is_err());
        assert!(validate_secret_data(&data("{\"key\":}"), SecretType::Json).is_err());
    }

    #[test]
    fn json_rejects_trailing_garbage() {
        assert!(validate_secret_data(&data(r#"{"k":"v"} garbage"#), SecretType::Json).is_err());
    }

    #[test]
    fn json_rejects_non_utf8() {
        assert!(validate_secret_data(&data_bytes(&[0xff, 0xfe]), SecretType::Json).is_err());
    }

    #[test]
    fn yaml_accepts_mapping() {
        assert!(validate_secret_data(&data("key: value\nother: 123"), SecretType::Yaml).is_ok());
    }

    #[test]
    fn yaml_accepts_list() {
        assert!(validate_secret_data(&data("- a\n- b\n- c"), SecretType::Yaml).is_ok());
    }

    #[test]
    fn yaml_accepts_nested() {
        assert!(validate_secret_data(&data("key: value\nlist:\n  - a\n  - b"), SecretType::Yaml).is_ok());
    }

    #[test]
    fn yaml_accepts_document_marker() {
        assert!(validate_secret_data(&data("---\nfoo: bar"), SecretType::Yaml).is_ok());
    }

    #[test]
    fn yaml_accepts_scalar() {
        assert!(validate_secret_data(&data("42"), SecretType::Yaml).is_ok());
    }

    #[test]
    fn yaml_accepts_empty() {
        // Empty string is null in YAML — valid.
        assert!(validate_secret_data(&data(""), SecretType::Yaml).is_ok());
    }

    #[test]
    fn yaml_accepts_json_superset() {
        // Valid JSON is also valid YAML.
        assert!(validate_secret_data(&data(r#"{"key": "value"}"#), SecretType::Yaml).is_ok());
    }

    #[test]
    fn yaml_rejects_tab_indentation() {
        assert!(validate_secret_data(&data("key:\n\t- bad"), SecretType::Yaml).is_err());
    }

    #[test]
    fn yaml_rejects_non_utf8() {
        assert!(validate_secret_data(&data_bytes(&[0xff, 0xfe]), SecretType::Yaml).is_err());
    }

    #[test]
    fn jwt_accepts_hs256() {
        let t = make_jwt(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            r#"{"sub":"1234","iat":1516239022}"#,
            "fakesig",
        );
        assert!(validate_secret_data(&data(&t), SecretType::Jwt).is_ok());
    }

    #[test]
    fn jwt_accepts_rs256() {
        let t = make_jwt(r#"{"alg":"RS256","typ":"JWT"}"#, r#"{"iss":"auth.example.com"}"#, "sig");
        assert!(validate_secret_data(&data(&t), SecretType::Jwt).is_ok());
    }

    #[test]
    fn jwt_accepts_with_leading_trailing_whitespace() {
        let _ = format!("  {}.  ", make_jwt(r#"{"alg":"ES256"}"#, r#"{}"#, "s"));
        // The whole thing won't be a valid 3-part JWT after trim, so this should fail — but if
        // someone stores a JWT with surrounding whitespace, trim() handles it.
        // Actually "  header.payload.sig.  " trimmed is "header.payload.sig." — still 4 parts
        // Let's test clean whitespace around a valid JWT.
        let inner = make_jwt(r#"{"alg":"ES256"}"#, r#"{}"#, "sig");
        let padded = format!("  {inner}  ");
        assert!(validate_secret_data(&data(&padded), SecretType::Jwt).is_ok());
    }

    #[test]
    fn jwt_rejects_two_parts() {
        assert!(validate_secret_data(&data("header.payload"), SecretType::Jwt).is_err());
    }

    #[test]
    fn jwt_rejects_four_parts() {
        assert!(validate_secret_data(&data("a.b.c.d"), SecretType::Jwt).is_err());
    }

    #[test]
    fn jwt_rejects_empty_string() {
        assert!(validate_secret_data(&data(""), SecretType::Jwt).is_err());
    }

    #[test]
    fn jwt_rejects_invalid_base64url_in_header() {
        let bad = "!!!.payload.sig";
        assert!(validate_secret_data(&data(bad), SecretType::Jwt).is_err());
    }

    #[test]
    fn jwt_rejects_invalid_base64url_in_payload() {
        let header = b64url.encode(r#"{"alg":"HS256"}"#);
        let bad = format!("{header}.!!!.sig");
        assert!(validate_secret_data(&data(&bad), SecretType::Jwt).is_err());
    }

    #[test]
    fn jwt_rejects_invalid_base64url_in_signature() {
        let header = b64url.encode(r#"{"alg":"HS256"}"#);
        let payload = b64url.encode(r#"{}"#);
        let bad = format!("{header}.{payload}.!!!");
        assert!(validate_secret_data(&data(&bad), SecretType::Jwt).is_err());
    }

    #[test]
    fn jwt_rejects_non_json_header() {
        let bad = format!("{}.{}.sig", b64url.encode("not json"), b64url.encode("payload"));
        assert!(validate_secret_data(&data(&bad), SecretType::Jwt).is_err());
    }

    #[test]
    fn jwt_rejects_header_json_array() {
        // JSON array is not an object.
        let bad = format!("{}.{}.sig", b64url.encode(r#"["alg","HS256"]"#), b64url.encode("{}"));
        assert!(validate_secret_data(&data(&bad), SecretType::Jwt).is_err());
    }

    #[test]
    fn jwt_rejects_header_json_string() {
        let bad = format!("{}.{}.sig", b64url.encode(r#""HS256""#), b64url.encode("{}"));
        assert!(validate_secret_data(&data(&bad), SecretType::Jwt).is_err());
    }

    #[test]
    fn jwt_rejects_header_without_alg() {
        let t = make_jwt(r#"{"typ":"JWT"}"#, r#"{}"#, "sig");
        assert!(validate_secret_data(&data(&t), SecretType::Jwt).is_err());
    }

    #[test]
    fn jwt_rejects_non_utf8() {
        assert!(validate_secret_data(&data_bytes(&[0xff, 0xfe]), SecretType::Jwt).is_err());
    }

    #[test]
    fn certificate_accepts_single_cert() {
        assert!(validate_secret_data(&data(&fake_cert_pem()), SecretType::Certificate).is_ok());
    }

    #[test]
    fn certificate_rejects_two_certs() {
        let pem = format!("{}{}", fake_cert_pem(), fake_cert_pem());
        assert!(validate_secret_data(&data(&pem), SecretType::Certificate).is_err());
    }

    #[test]
    fn certificate_rejects_empty() {
        assert!(validate_secret_data(&data(""), SecretType::Certificate).is_err());
    }

    #[test]
    fn certificate_rejects_missing_footer() {
        let body = b64.encode(b"fake");
        let pem = format!("-----BEGIN CERTIFICATE-----\n{body}\n");
        assert!(validate_secret_data(&data(&pem), SecretType::Certificate).is_err());
    }

    #[test]
    fn certificate_rejects_invalid_base64_body() {
        let pem = "-----BEGIN CERTIFICATE-----\n!!!not_base64!!!\n-----END CERTIFICATE-----\n";
        assert!(validate_secret_data(&data(pem), SecretType::Certificate).is_err());
    }

    #[test]
    fn certificate_rejects_wrong_label() {
        // A private key PEM is not a certificate.
        assert!(validate_secret_data(&data(&fake_key_pem("PRIVATE KEY")), SecretType::Certificate).is_err());
    }

    #[test]
    fn certificate_rejects_non_utf8() {
        assert!(validate_secret_data(&data_bytes(&[0xff, 0xfe]), SecretType::Certificate).is_err());
    }

    #[test]
    fn chain_accepts_single_cert() {
        assert!(validate_secret_data(&data(&fake_cert_pem()), SecretType::CertificateChain).is_ok());
    }

    #[test]
    fn chain_accepts_two_certs() {
        let pem = format!("{}{}", fake_cert_pem(), fake_cert_pem());
        assert!(validate_secret_data(&data(&pem), SecretType::CertificateChain).is_ok());
    }

    #[test]
    fn chain_accepts_many_certs() {
        let pem = fake_cert_pem().repeat(5);
        assert!(validate_secret_data(&data(&pem), SecretType::CertificateChain).is_ok());
    }

    #[test]
    fn chain_rejects_empty() {
        assert!(validate_secret_data(&data(""), SecretType::CertificateChain).is_err());
    }

    #[test]
    fn chain_rejects_missing_footer() {
        let body = b64.encode(b"fake");
        let pem = format!("-----BEGIN CERTIFICATE-----\n{body}\n");
        assert!(validate_secret_data(&data(&pem), SecretType::CertificateChain).is_err());
    }

    #[test]
    fn chain_rejects_invalid_base64_body() {
        let pem = "-----BEGIN CERTIFICATE-----\n!!!not_base64!!!\n-----END CERTIFICATE-----\n";
        assert!(validate_secret_data(&data(pem), SecretType::CertificateChain).is_err());
    }

    #[test]
    fn private_key_accepts_pkcs8() {
        assert!(validate_secret_data(&data(&fake_key_pem("PRIVATE KEY")), SecretType::PrivateKey).is_ok());
    }

    #[test]
    fn private_key_accepts_all_legacy_labels() {
        for label in &[
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
        ] {
            assert!(
                validate_secret_data(&data(&fake_key_pem(label)), SecretType::PrivateKey).is_ok(),
                "failed for label: {label}"
            );
        }
    }

    #[test]
    fn private_key_rejects_public_key_label() {
        assert!(validate_secret_data(&data(&fake_key_pem("PUBLIC KEY")), SecretType::PrivateKey).is_err());
        assert!(validate_secret_data(&data(&fake_key_pem("RSA PUBLIC KEY")), SecretType::PrivateKey).is_err());
    }

    #[test]
    fn private_key_rejects_certificate_label() {
        assert!(validate_secret_data(&data(&fake_cert_pem()), SecretType::PrivateKey).is_err());
    }

    #[test]
    fn private_key_rejects_multiple_blocks() {
        let pem = format!("{}{}", fake_key_pem("PRIVATE KEY"), fake_key_pem("PRIVATE KEY"));
        assert!(validate_secret_data(&data(&pem), SecretType::PrivateKey).is_err());
    }

    #[test]
    fn private_key_rejects_two_blocks_different_labels() {
        // One RSA + one EC is still two blocks — must be exactly one.
        let pem = format!("{}{}", fake_key_pem("RSA PRIVATE KEY"), fake_key_pem("EC PRIVATE KEY"));
        assert!(validate_secret_data(&data(&pem), SecretType::PrivateKey).is_err());
    }

    #[test]
    fn private_key_rejects_missing_footer() {
        let body = b64.encode(b"fake");
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{body}\n");
        assert!(validate_secret_data(&data(&pem), SecretType::PrivateKey).is_err());
    }

    #[test]
    fn private_key_rejects_invalid_base64_body() {
        let pem = "-----BEGIN PRIVATE KEY-----\n!!!not_base64!!!\n-----END PRIVATE KEY-----\n";
        assert!(validate_secret_data(&data(pem), SecretType::PrivateKey).is_err());
    }

    #[test]
    fn private_key_rejects_empty() {
        assert!(validate_secret_data(&data(""), SecretType::PrivateKey).is_err());
    }

    #[test]
    fn private_key_rejects_non_utf8() {
        assert!(validate_secret_data(&data_bytes(&[0xff, 0xfe]), SecretType::PrivateKey).is_err());
    }

    #[test]
    fn public_key_accepts_pkcs8_public() {
        assert!(validate_secret_data(&data(&fake_key_pem("PUBLIC KEY")), SecretType::PublicKey).is_ok());
    }

    #[test]
    fn public_key_accepts_rsa_public() {
        assert!(validate_secret_data(&data(&fake_key_pem("RSA PUBLIC KEY")), SecretType::PublicKey).is_ok());
    }

    #[test]
    fn public_key_rejects_private_key() {
        assert!(validate_secret_data(&data(&fake_key_pem("PRIVATE KEY")), SecretType::PublicKey).is_err());
        assert!(validate_secret_data(&data(&fake_key_pem("RSA PRIVATE KEY")), SecretType::PublicKey).is_err());
    }

    #[test]
    fn public_key_rejects_multiple_blocks() {
        let pem = format!("{}{}", fake_key_pem("PUBLIC KEY"), fake_key_pem("PUBLIC KEY"));
        assert!(validate_secret_data(&data(&pem), SecretType::PublicKey).is_err());
    }

    #[test]
    fn public_key_rejects_missing_footer() {
        let body = b64.encode(b"fake");
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{body}\n");
        assert!(validate_secret_data(&data(&pem), SecretType::PublicKey).is_err());
    }

    #[test]
    fn public_key_rejects_invalid_base64_body() {
        let pem = "-----BEGIN PUBLIC KEY-----\n!!!not_base64!!!\n-----END PUBLIC KEY-----\n";
        assert!(validate_secret_data(&data(pem), SecretType::PublicKey).is_err());
    }

    #[test]
    fn public_key_rejects_empty() {
        assert!(validate_secret_data(&data(""), SecretType::PublicKey).is_err());
    }

    #[test]
    fn ssh_private_key_accepts_valid() {
        assert!(validate_secret_data(&data(&make_openssh_pem()), SecretType::SshPrivateKey).is_ok());
    }

    #[test]
    fn ssh_private_key_rejects_pkcs8_label() {
        assert!(validate_secret_data(&data(&fake_key_pem("PRIVATE KEY")), SecretType::SshPrivateKey).is_err());
    }

    #[test]
    fn ssh_private_key_rejects_rsa_label() {
        assert!(validate_secret_data(&data(&fake_key_pem("RSA PRIVATE KEY")), SecretType::SshPrivateKey).is_err());
    }

    #[test]
    fn ssh_private_key_rejects_wrong_magic() {
        let body = b64.encode(b"notopensshmagic---rest-of-data");
        let pem = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n");
        assert!(validate_secret_data(&data(&pem), SecretType::SshPrivateKey).is_err());
    }

    #[test]
    fn ssh_private_key_rejects_truncated_magic() {
        // "openssh-key-v1" without the null byte terminator.
        let body = b64.encode(b"openssh-key-v1");
        let pem = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n");
        assert!(validate_secret_data(&data(&pem), SecretType::SshPrivateKey).is_err());
    }

    #[test]
    fn ssh_private_key_rejects_multiple_blocks() {
        let pem = format!("{}{}", make_openssh_pem(), make_openssh_pem());
        assert!(validate_secret_data(&data(&pem), SecretType::SshPrivateKey).is_err());
    }

    #[test]
    fn ssh_private_key_rejects_missing_footer() {
        let body = b64.encode(b"openssh-key-v1\0rest");
        let pem = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n");
        assert!(validate_secret_data(&data(&pem), SecretType::SshPrivateKey).is_err());
    }

    #[test]
    fn ssh_private_key_rejects_empty() {
        assert!(validate_secret_data(&data(""), SecretType::SshPrivateKey).is_err());
    }

    #[test]
    fn ssh_private_key_rejects_non_utf8() {
        assert!(validate_secret_data(&data_bytes(&[0xff, 0xfe]), SecretType::SshPrivateKey).is_err());
    }

    #[test]
    fn uri_accepts_https() {
        assert!(validate_secret_data(&data("https://example.com/path?q=1#frag"), SecretType::Uri).is_ok());
    }

    #[test]
    fn uri_accepts_http() {
        assert!(validate_secret_data(&data("http://user:pass@host:8080/path"), SecretType::Uri).is_ok());
    }

    #[test]
    fn uri_accepts_ftp() {
        assert!(validate_secret_data(&data("ftp://files.example.org"), SecretType::Uri).is_ok());
    }

    #[test]
    fn uri_accepts_urn() {
        assert!(validate_secret_data(&data("urn:isbn:0451450523"), SecretType::Uri).is_ok());
    }

    #[test]
    fn uri_accepts_with_surrounding_whitespace() {
        assert!(validate_secret_data(&data("  https://example.com  "), SecretType::Uri).is_ok());
    }

    #[test]
    fn uri_rejects_bare_text() {
        assert!(validate_secret_data(&data("not a uri"), SecretType::Uri).is_err());
    }

    #[test]
    fn uri_rejects_missing_scheme() {
        assert!(validate_secret_data(&data("://missing-scheme"), SecretType::Uri).is_err());
    }

    #[test]
    fn uri_rejects_empty() {
        assert!(validate_secret_data(&data(""), SecretType::Uri).is_err());
    }

    #[test]
    fn uri_rejects_relative_path() {
        assert!(validate_secret_data(&data("/relative/path"), SecretType::Uri).is_err());
    }

    #[test]
    fn uri_rejects_non_utf8() {
        assert!(validate_secret_data(&data_bytes(&[0xff, 0xfe]), SecretType::Uri).is_err());
    }

    #[test]
    fn connection_string_accepts_all_known_schemes() {
        let uris = [
            "postgres://user:pass@localhost:5432/mydb",
            "postgresql://user:pass@localhost:5432/mydb",
            "mysql://user:pass@localhost:3306/mydb",
            "mariadb://user:pass@localhost:3306/mydb",
            "redis://localhost:6379/0",
            "rediss://localhost:6380/0",
            "mongodb://user:pass@host:27017/db",
            "mongodb+srv://user:pass@cluster.example.net/db",
            "amqp://user:pass@localhost:5672/vhost",
            "amqps://user:pass@localhost:5671/vhost",
            "cassandra://localhost:9042/keyspace",
            "elasticsearch://localhost:9200",
            "kafka://localhost:9092",
            "memcached://localhost:11211",
            "couchdb://localhost:5984/db",
            "neo4j://localhost:7687",
            "bolt://localhost:7687",
        ];
        for uri in &uris {
            assert!(
                validate_secret_data(&data(uri), SecretType::ConnectionString).is_ok(),
                "should accept: {uri}"
            );
        }
    }

    #[test]
    fn connection_string_rejects_http() {
        assert!(validate_secret_data(&data("https://example.com"), SecretType::ConnectionString).is_err());
    }

    #[test]
    fn connection_string_rejects_ftp() {
        assert!(validate_secret_data(&data("ftp://files.example.org"), SecretType::ConnectionString).is_err());
    }

    #[test]
    fn connection_string_rejects_bare_text() {
        assert!(validate_secret_data(&data("localhost:5432"), SecretType::ConnectionString).is_err());
    }

    #[test]
    fn connection_string_rejects_empty() {
        assert!(validate_secret_data(&data(""), SecretType::ConnectionString).is_err());
    }

    #[test]
    fn connection_string_rejects_non_utf8() {
        assert!(validate_secret_data(&data_bytes(&[0xff, 0xfe]), SecretType::ConnectionString).is_err());
    }

    #[test]
    fn cert_key_pair_rejects_cert_only() {
        assert!(validate_secret_data(&data(&fake_cert_pem()), SecretType::CertificateKeyPair).is_err());
    }

    #[test]
    fn cert_key_pair_rejects_key_only() {
        assert!(validate_secret_data(&data(&fake_key_pem("RSA PRIVATE KEY")), SecretType::CertificateKeyPair).is_err());
    }

    #[test]
    fn cert_key_pair_rejects_multiple_certs() {
        let pem = format!("{}{}{}", fake_cert_pem(), fake_cert_pem(), fake_key_pem("RSA PRIVATE KEY"));
        assert!(validate_secret_data(&data(&pem), SecretType::CertificateKeyPair).is_err());
    }

    #[test]
    fn cert_key_pair_rejects_multiple_keys() {
        let pem = format!(
            "{}{}{}",
            fake_cert_pem(),
            fake_key_pem("RSA PRIVATE KEY"),
            fake_key_pem("EC PRIVATE KEY")
        );
        assert!(validate_secret_data(&data(&pem), SecretType::CertificateKeyPair).is_err());
    }

    #[test]
    fn cert_key_pair_rejects_empty() {
        assert!(validate_secret_data(&data(""), SecretType::CertificateKeyPair).is_err());
    }

    #[test]
    fn cert_key_pair_rejects_non_utf8() {
        assert!(validate_secret_data(&data_bytes(&[0xff, 0xfe]), SecretType::CertificateKeyPair).is_err());
    }

    #[test]
    fn cert_key_pair_accepts_legacy_rsa_key_structurally() {
        // Legacy RSA key — crypto matching is skipped, structural check passes.
        let pem = format!("{}{}", fake_cert_pem(), fake_key_pem("RSA PRIVATE KEY"));
        assert!(validate_secret_data(&data(&pem), SecretType::CertificateKeyPair).is_ok());
    }

    #[test]
    fn cert_key_pair_accepts_legacy_ec_key_structurally() {
        let pem = format!("{}{}", fake_cert_pem(), fake_key_pem("EC PRIVATE KEY"));
        assert!(validate_secret_data(&data(&pem), SecretType::CertificateKeyPair).is_ok());
    }

    #[test]
    fn cert_key_pair_accepts_matching_pkcs8_key() {
        let (_cert_pem, _key_pem, combined) = real_cert_and_key();
        assert!(
            validate_secret_data(&data(&combined), SecretType::CertificateKeyPair).is_ok(),
            "matching cert+key should pass"
        );
    }

    #[test]
    fn cert_key_pair_rejects_mismatched_pkcs8_key() {
        let (cert_pem, _key_pem, _) = real_cert_and_key();
        let (_cert2_pem, key2_pem, _) = real_cert_and_key();
        // Cert from pair 1, key from pair 2 — different keys.
        let mismatched = format!("{cert_pem}{key2_pem}");
        assert!(
            validate_secret_data(&data(&mismatched), SecretType::CertificateKeyPair).is_err(),
            "mismatched cert+key should fail"
        );
    }

    #[test]
    fn cert_key_pair_rejects_malformed_pkcs8_der() {
        // PKCS#8 label but garbage DER body — ring parse fails, returns error.
        let body = b64.encode(b"this is not valid pkcs8 der");
        let pem = format!(
            "{}-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n",
            real_cert_and_key().0
        );
        assert!(validate_secret_data(&data(&pem), SecretType::CertificateKeyPair).is_err());
    }
}
