// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

/// Managers that will handle the business logic for different entities. They ONLY deal with the given
/// entity and do not interact with other entities directly. Any interaction between entities should be
/// handled at a higher level (e.g., in services).
pub(crate) mod account;
pub(crate) mod federated_identity;
pub(crate) mod kek;
pub(crate) mod masterkey;
pub(crate) mod namespace;
pub(crate) mod rbac;
pub(crate) mod secret;
pub(crate) mod token;

pub(crate) use account::AccountManager;
pub(crate) use kek::KekManager;
pub(crate) use namespace::NamespaceManager;
