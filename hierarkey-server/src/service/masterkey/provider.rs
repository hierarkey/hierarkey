// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

pub mod crypto;
pub mod traits;

pub mod insecure;
pub mod passphrase;
pub mod pkcs11;
#[cfg(test)]
mod test;

pub use traits::{LoadedMaterial, MasterKeyProvider, Pkcs11TokenInfo, StartupDisposition};

#[cfg(test)]
pub use test::TestMasterKeyProvider;

use zeroize::Zeroizing;

/// Unlock arguments accepted by providers.
#[derive(Debug)]
pub enum UnlockArgs {
    None,
    Passphrase(Zeroizing<String>),
    Pkcs11 { pin: Zeroizing<String> },
}
