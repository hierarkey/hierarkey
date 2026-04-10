// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    println!("cargo:rustc-env=BUILD_TIME_UNIX={now}");
    println!("cargo:rerun-if-changed=build.rs");

    // Embed git commit hash and dirty flag at build time.
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    println!("cargo:rustc-env=GIT_COMMIT={commit}");
    println!("cargo:rustc-env=GIT_DIRTY={dirty}");
    // If either dev key file is absent, Cargo will re-run this build script on
    // the next build so the key generation step is triggered automatically.
    println!("cargo:rerun-if-changed=keys/dev/hierarkey-dev-2026.priv.pem");
    println!("cargo:rerun-if-changed=keys/dev/hierarkey-dev-2026.pub.pem");

    // Generate dev key pair if the private key is missing.
    // The public key is overwritten so it always matches the private key.
    // The private key must NOT be committed — it is only needed for local tests.
    if std::env::var("PROFILE").as_deref() != Ok("release") {
        generate_dev_keys();
    }
}

fn generate_dev_keys() {
    let priv_path = "keys/dev/hierarkey-dev-2026.priv.pem";
    let pub_path = "keys/dev/hierarkey-dev-2026.pub.pem";

    if std::path::Path::new(priv_path).exists() && std::path::Path::new(pub_path).exists() {
        return;
    }

    println!("cargo:warning=Dev private key not found — generating new key pair (do not commit the private key)");

    let status = std::process::Command::new("openssl")
        .args(["genpkey", "-algorithm", "ed25519", "-out", priv_path])
        .status()
        .expect("build.rs: 'openssl' not found — cannot generate dev key pair");
    assert!(status.success(), "build.rs: openssl genpkey failed");

    let status = std::process::Command::new("openssl")
        .args(["pkey", "-in", priv_path, "-pubout", "-out", pub_path])
        .status()
        .expect("build.rs: 'openssl pkey' failed");
    assert!(status.success(), "build.rs: openssl pkey -pubout failed");
}
