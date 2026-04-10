// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use base64::Engine as _;
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey, spki::der::pem::LineEnding},
};
use rand_core::{CryptoRng, Rng};
use ring::signature::{Ed25519KeyPair, KeyPair};
use thiserror::Error;

/// Errors that can occur during Ed25519 signing and verification operations, as well as PEM encoding/decoding.
#[derive(Debug, Error)]
pub enum Ed25519CryptoError {
    #[error("invalid signature encoding")]
    InvalidSignature,

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("pkcs8 error: {0}")]
    Pkcs8(ed25519_dalek::pkcs8::Error),

    #[error("spki error: {0:?}")]
    Spki(ed25519_dalek::pkcs8::spki::Error),
}

impl From<ed25519_dalek::pkcs8::Error> for Ed25519CryptoError {
    fn from(err: ed25519_dalek::pkcs8::Error) -> Self {
        Ed25519CryptoError::Pkcs8(err)
    }
}

impl From<ed25519_dalek::pkcs8::spki::Error> for Ed25519CryptoError {
    fn from(err: ed25519_dalek::pkcs8::spki::Error) -> Self {
        Ed25519CryptoError::Spki(err)
    }
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("{0}")]
    Custom(String),
}

/// Wrapper around ed25519-dalek to provide a simple interface for key generation, signing, and verification,
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Crypto;

impl Ed25519Crypto {
    /// Generate a new keypair using the provided RNG
    pub fn generate_keypair<R>(mut rng: R) -> (Ed25519PrivateKey, Ed25519PublicKey)
    where
        R: Rng + CryptoRng,
    {
        let signing = SigningKey::generate(&mut rng);
        let verifying = signing.verifying_key();
        (Ed25519PrivateKey(signing), Ed25519PublicKey(verifying))
    }

    /// Sign arbitrary bytes
    pub fn sign(private_key: &Ed25519PrivateKey, data: &[u8]) -> Vec<u8> {
        let sig: Signature = private_key.0.sign(data);
        sig.to_bytes().to_vec()
    }

    /// Verify signature bytes against data
    pub fn verify(public_key: &Ed25519PublicKey, data: &[u8], signature: &[u8]) -> Result<(), Ed25519CryptoError> {
        let sig = Signature::try_from(signature).map_err(|_| Ed25519CryptoError::InvalidSignature)?;
        public_key
            .0
            .verify_strict(data, &sig)
            .map_err(|_| Ed25519CryptoError::VerificationFailed)
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519PrivateKey(SigningKey);

#[derive(Debug, Clone, Copy)]
pub struct Ed25519PublicKey(VerifyingKey);

impl Ed25519PrivateKey {
    /// Derive the public key from this private key
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.0.verifying_key())
    }

    /// Export private key as PKCS#8 v1 PEM (no public key appendix).
    ///
    /// ed25519_dalek's `to_pkcs8_pem` emits PKCS#8 v2 which embeds the
    /// public key. Several consumers (Python's `cryptography` library,
    /// some OpenSSL builds) reject v2 with "extra data". We manually
    /// construct the 48-byte v1 DER instead.
    pub fn to_pem(&self) -> Result<String, Ed25519CryptoError> {
        let seed = self.to_seed_bytes();

        // PKCS#8 v1 DER for Ed25519 — exactly 48 bytes:
        //   SEQUENCE (46 bytes) {
        //     INTEGER 0                       -- version = v1
        //     SEQUENCE { OID 1.3.101.112 }    -- AlgorithmIdentifier (Ed25519)
        //     OCTET STRING {
        //       OCTET STRING (32 bytes)        -- private key seed
        //     }
        //   }
        let mut der = vec![
            0x30, 0x2e, // SEQUENCE, 46 bytes
            0x02, 0x01, 0x00, // INTEGER 0 (v1)
            0x30, 0x05, // SEQUENCE, 5 bytes
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
            0x04, 0x22, // OCTET STRING, 34 bytes
            0x04, 0x20, // OCTET STRING, 32 bytes (seed)
        ];
        der.extend_from_slice(&seed);

        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        let mut i = 0;
        while i < b64.len() {
            let end = (i + 64).min(b64.len());
            pem.push_str(&b64[i..end]);
            pem.push('\n');
            i = end;
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        Ok(pem)
    }

    /// Import private key from PKCS#8 PEM
    pub fn from_pem(pem: &str) -> Result<Self, Ed25519CryptoError> {
        let key = SigningKey::from_pkcs8_pem(pem)?;
        Ok(Self(key))
    }

    pub fn to_seed_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_seed_bytes(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }
}

impl Ed25519PublicKey {
    pub fn to_pem(&self) -> Result<String, Ed25519CryptoError> {
        let pem = self.0.to_public_key_pem(LineEnding::LF)?;
        Ok(pem)
    }

    pub fn from_pem(pem: &str) -> Result<Self, Ed25519CryptoError> {
        let key = VerifyingKey::from_public_key_pem(pem)?;
        Ok(Self(key))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Ed25519CryptoError> {
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| Ed25519CryptoError::Pkcs8(ed25519_dalek::pkcs8::Error::KeyMalformed))?;
        Ok(Self(key))
    }
}

/// returns (public_key_b64url, private_key_b64url)
pub fn generate_ed25519_keypair() -> Result<(String, String), ValidationError> {
    use ring::rand::SystemRandom;

    let rng = SystemRandom::new();

    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| ValidationError::Custom("Failed to generate ed25519 keypair".into()))?;

    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| ValidationError::Custom("Failed to parse generated PKCS#8 key".into()))?;

    let public_key_bytes = keypair.public_key().as_ref(); // 32 bytes
    let pkcs8_bytes = pkcs8.as_ref(); // variable length

    // Choose an encoding. URL-safe no-pad is convenient for CLI/env-vars
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let public_b64 = b64.encode(public_key_bytes);
    let private_b64 = b64.encode(pkcs8_bytes);

    Ok((public_b64, private_b64))
}

pub fn pkcs8_der_b64url_to_pem(priv_b64url: &str) -> Result<String, ValidationError> {
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let stdb64 = base64::engine::general_purpose::STANDARD;

    let der = b64url
        .decode(priv_b64url.as_bytes())
        .map_err(|_| ValidationError::Custom("Invalid private key base64".into()))?;

    let b64 = stdb64.encode(&der);

    // wrap at 64 chars
    let mut out = String::new();
    out.push_str("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        let s = std::str::from_utf8(chunk)
            .map_err(|_| ValidationError::Custom("Failed to convert private key to PEM (UTF-8 error)".into()))?;
        out.push_str(s);
        out.push('\n');
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_pem_block(pem: &str, header: &str, footer: &str) {
        assert!(pem.starts_with(header), "pem missing header: {header}");
        assert!(pem.ends_with(footer), "pem missing footer: {footer}");
    }

    fn pem_body_lines(pem: &str) -> Vec<&str> {
        pem.lines()
            .filter(|l| !l.starts_with("-----BEGIN ") && !l.starts_with("-----END "))
            .collect()
    }

    #[test]
    fn sign_verify_roundtrip_ok() {
        let (sk, pk) = Ed25519Crypto::generate_keypair(rand::rng());

        let msg = b"hello";
        let sig = Ed25519Crypto::sign(&sk, msg);

        Ed25519Crypto::verify(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn verify_fails_for_wrong_message() {
        let (sk, pk) = Ed25519Crypto::generate_keypair(rand::rng());

        let msg = b"hello";
        let sig = Ed25519Crypto::sign(&sk, msg);

        let err = Ed25519Crypto::verify(&pk, b"HELLO", &sig).unwrap_err();
        assert!(matches!(err, Ed25519CryptoError::VerificationFailed));
    }

    #[test]
    fn verify_fails_for_wrong_public_key() {
        let (sk1, _pk1) = Ed25519Crypto::generate_keypair(rand::rng());
        let (_sk2, pk2) = Ed25519Crypto::generate_keypair(rand::rng());

        let msg = b"hello";
        let sig = Ed25519Crypto::sign(&sk1, msg);

        let err = Ed25519Crypto::verify(&pk2, msg, &sig).unwrap_err();
        assert!(matches!(err, Ed25519CryptoError::VerificationFailed));
    }

    #[test]
    fn verify_fails_for_tampered_signature() {
        let (sk, pk) = Ed25519Crypto::generate_keypair(rand::rng());

        let msg = b"hello";
        let mut sig = Ed25519Crypto::sign(&sk, msg);

        // flip a bit
        sig[0] ^= 0b0000_0001;

        let err = Ed25519Crypto::verify(&pk, msg, &sig).unwrap_err();
        assert!(matches!(err, Ed25519CryptoError::VerificationFailed));
    }

    #[test]
    fn verify_rejects_malformed_signature_length() {
        let (_sk, pk) = Ed25519Crypto::generate_keypair(rand::rng());

        let msg = b"hello";

        // Ed25519 signatures are 64 bytes; try something else
        let sig = vec![0u8; 63];
        let err = Ed25519Crypto::verify(&pk, msg, &sig).unwrap_err();
        assert!(matches!(err, Ed25519CryptoError::InvalidSignature));
    }

    #[test]
    fn public_key_matches_private_key_derived() {
        let (sk, pk) = Ed25519Crypto::generate_keypair(rand::rng());

        let derived = sk.public_key().to_bytes();
        let original = pk.to_bytes();
        assert_eq!(derived, original);
    }

    #[test]
    fn seed_roundtrip_private_key() {
        let (sk, pk) = Ed25519Crypto::generate_keypair(rand::rng());

        let seed = sk.to_seed_bytes();
        let sk2 = Ed25519PrivateKey::from_seed_bytes(seed);

        assert_eq!(sk2.public_key().to_bytes(), pk.to_bytes());
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let (_sk, pk) = Ed25519Crypto::generate_keypair(rand::rng());

        let bytes = pk.to_bytes();
        let pk2 = Ed25519PublicKey::from_bytes(bytes).unwrap();

        assert_eq!(pk2.to_bytes(), bytes);
    }

    #[test]
    fn deterministic_signature_from_same_seed() {
        // fixed seed
        let seed = [42u8; 32];
        let sk1 = Ed25519PrivateKey::from_seed_bytes(seed);
        let sk2 = Ed25519PrivateKey::from_seed_bytes(seed);

        let msg = b"same msg";
        let sig1 = Ed25519Crypto::sign(&sk1, msg);
        let sig2 = Ed25519Crypto::sign(&sk2, msg);

        assert_eq!(sig1, sig2);
        assert_eq!(sk1.public_key().to_bytes(), sk2.public_key().to_bytes());
    }

    #[test]
    fn private_key_pem_roundtrip() {
        let (sk, pk) = Ed25519Crypto::generate_keypair(rand::rng());

        let pem = sk.to_pem().unwrap();
        assert_pem_block(&pem, "-----BEGIN PRIVATE KEY-----\n", "-----END PRIVATE KEY-----\n");

        let sk2 = Ed25519PrivateKey::from_pem(&pem).unwrap();
        assert_eq!(sk2.public_key().to_bytes(), pk.to_bytes());
    }

    #[test]
    fn public_key_pem_roundtrip() {
        let (_sk, pk) = Ed25519Crypto::generate_keypair(rand::rng());

        let pem = pk.to_pem().unwrap();
        assert_pem_block(&pem, "-----BEGIN PUBLIC KEY-----\n", "-----END PUBLIC KEY-----\n");

        let pk2 = Ed25519PublicKey::from_pem(&pem).unwrap();
        assert_eq!(pk2.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn private_key_from_pem_rejects_garbage() {
        let pem = "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n";
        let err = Ed25519PrivateKey::from_pem(pem).unwrap_err();
        assert!(matches!(err, Ed25519CryptoError::Pkcs8(_)));
    }

    #[test]
    fn public_key_from_pem_rejects_garbage() {
        let pem = "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n";
        let err = Ed25519PublicKey::from_pem(pem).unwrap_err();
        assert!(matches!(err, Ed25519CryptoError::Spki(_)));
    }

    #[test]
    fn pem_roundtrip_keeps_sign_verify_working() {
        let (sk, pk) = Ed25519Crypto::generate_keypair(rand::rng());

        let sk_pem = sk.to_pem().unwrap();
        let pk_pem = pk.to_pem().unwrap();

        let sk2 = Ed25519PrivateKey::from_pem(&sk_pem).unwrap();
        let pk2 = Ed25519PublicKey::from_pem(&pk_pem).unwrap();

        let msg = b"hi";
        let sig = Ed25519Crypto::sign(&sk2, msg);
        Ed25519Crypto::verify(&pk2, msg, &sig).unwrap();
    }

    #[test]
    fn pkcs8_der_b64url_to_pem_has_header_footer_and_wraps_at_64() {
        let (sk, _pk) = Ed25519Crypto::generate_keypair(rand::rng());

        let pkcs8_pem = sk.to_pem().unwrap();

        // Extract base64 body from PEM and decode to DER
        let body: String = pem_body_lines(&pkcs8_pem).join("");
        let der = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .unwrap();

        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&der);
        let pem2 = pkcs8_der_b64url_to_pem(&b64url).unwrap();

        assert_pem_block(&pem2, "-----BEGIN PRIVATE KEY-----\n", "-----END PRIVATE KEY-----\n");

        // Ensure body lines (excluding headers/footers) are at most 64 chars
        let lines = pem_body_lines(&pem2);
        assert!(!lines.is_empty(), "pem body should not be empty");

        for (i, line) in lines.iter().enumerate() {
            assert!(line.len() <= 64, "line {i} too long: {} chars", line.len());
        }

        // If more than one body line, all but last should be exactly 64
        if lines.len() > 1 {
            for (i, line) in lines[..lines.len() - 1].iter().enumerate() {
                assert_eq!(line.len(), 64, "line {i} should be exactly 64 chars");
            }
        }
    }

    #[test]
    fn pkcs8_der_b64url_to_pem_roundtrips_to_same_der() {
        let (sk, _pk) = Ed25519Crypto::generate_keypair(rand::rng());
        let pkcs8_pem = sk.to_pem().unwrap();

        // PEM -> DER
        let body: String = pem_body_lines(&pkcs8_pem).join("");
        let der1 = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .unwrap();

        // DER -> b64url -> PEM2
        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&der1);
        let pem2 = pkcs8_der_b64url_to_pem(&b64url).unwrap();

        // PEM2 -> DER2
        let body2: String = pem_body_lines(&pem2).join("");
        let der2 = base64::engine::general_purpose::STANDARD
            .decode(body2.as_bytes())
            .unwrap();

        assert_eq!(der1, der2);
    }

    #[test]
    fn pkcs8_der_b64url_to_pem_rejects_invalid_base64url() {
        let err = pkcs8_der_b64url_to_pem("%%%not base64%%%").unwrap_err();
        let _ = err;
    }

    #[test]
    fn ring_generated_pkcs8_can_be_loaded_by_dalek() {
        let (_pub_b64url, priv_b64url) = generate_ed25519_keypair().unwrap();

        let pem = pkcs8_der_b64url_to_pem(&priv_b64url).unwrap();
        let sk = Ed25519PrivateKey::from_pem(&pem).unwrap();

        // sanity: can sign and verify with derived public key
        let pk = sk.public_key();

        let msg = b"interop";
        let sig = Ed25519Crypto::sign(&sk, msg);
        Ed25519Crypto::verify(&pk, msg, &sig).unwrap();
    }
}
