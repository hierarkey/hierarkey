// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::CkResult;
use hierarkey_core::error::validation::ValidationError;
use rand::RngExt;
use rpassword::read_password;
use zeroize::Zeroizing;

pub fn read_password_from_tty(prompt: &str) -> CkResult<Zeroizing<String>> {
    print!("{prompt} ");
    std::io::Write::flush(&mut std::io::stdout()).ok(); // flush so prompt shows

    let password = Zeroizing::from(read_password()?);
    if password.is_empty() {
        return Err(ValidationError::Custom("Password cannot be empty".into()).into());
    }

    Ok(password)
}

/// Generates a strong random passphrase of the specified length.
pub fn generate_strong_passphrase(len: usize) -> Zeroizing<String> {
    const CHARSET: &[u8] =
        b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    let mut rng = rand::rng();
    let passphrase: String = (0..len)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    Zeroizing::from(passphrase)
}

pub fn read_passphrase_from_user(min_len: usize) -> CkResult<Zeroizing<String>> {
    use rpassword::read_password;

    let passphrase = loop {
        print!("Enter passphrase (hidden): ");
        std::io::Write::flush(&mut std::io::stdout()).ok(); // flush so prompt shows
        let passphrase = Zeroizing::from(read_password()?);

        if passphrase.is_empty() {
            println!("Passphrase cannot be empty. Please try again.");
            continue;
        }

        if passphrase.len() < min_len {
            println!("Passphrase must be at least {min_len} characters long. Please try again.");
            continue;
        }

        break passphrase; // return value from loop
    };

    print!("Confirm passphrase (hidden): ");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let confirm_passphrase = Zeroizing::from(read_password()?);

    if passphrase != confirm_passphrase {
        return Err(ValidationError::Custom("Passphrases do not match".to_string()).into());
    }

    Ok(passphrase)
}
