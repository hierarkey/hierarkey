// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use std::process::Command;

fn main() {
    let output = Command::new("git").args(["rev-parse", "HEAD"]).output();

    let git_hash = match output {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    };

    println!(
        "cargo:rustc-env=GIT_HASH_SHORT={}",
        git_hash.chars().take(7).collect::<String>()
    );
    println!("cargo:rustc-env=GIT_HASH_FULL={git_hash}");

    let date = chrono::Local::now().format("%Y-%m-%d").to_string();
    println!("cargo:rustc-env=BUILD_DATE={date}");
}
