// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::CkResult;
use std::path::Path;
use tracing::trace;

pub fn check_file_permissions(path: &Path) -> CkResult<bool> {
    // Check 600 permissions on Unix-like systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;

        trace!("Checking file permissions");
        if !metadata.is_file() {
            trace!("File is not a regular file");
            return Ok(false);
        }

        let mode = metadata.permissions().mode();

        let perms = mode & 0o777;
        trace!("File permissions found: {perms:#o}");

        if perms & 0o077 != 0 {
            trace!("File permissions are insecure: {perms:#o} (group/other have access)");
            return Ok(false);
        }

        trace!("File permissions are secure");
        Ok(true)
    }

    #[cfg(not(unix))]
    {
        // On non-Unix systems, we skip permission checks for now
        trace!("Permission checks not implemented on this platform");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_secure() {
        use std::os::unix::fs::PermissionsExt;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "test content").unwrap();
        temp_file.flush().unwrap();

        // Set secure permissions (0o600)
        let mut perms = temp_file.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(temp_file.path(), perms).unwrap();

        let result = check_file_permissions(temp_file.path()).unwrap();
        assert!(result);
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_insecure_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "test content").unwrap();
        temp_file.flush().unwrap();

        // Set insecure permissions (0o644 - world readable)
        let mut perms = temp_file.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(temp_file.path(), perms).unwrap();

        let result = check_file_permissions(temp_file.path()).unwrap();
        assert!(!result);
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_insecure_group_readable() {
        use std::os::unix::fs::PermissionsExt;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "test content").unwrap();
        temp_file.flush().unwrap();

        // Set insecure permissions (0o640 - group readable)
        let mut perms = temp_file.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o640);
        std::fs::set_permissions(temp_file.path(), perms).unwrap();

        let result = check_file_permissions(temp_file.path()).unwrap();
        assert!(!result);
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_insecure_group_writable() {
        use std::os::unix::fs::PermissionsExt;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "test content").unwrap();
        temp_file.flush().unwrap();
        temp_file.flush().unwrap();

        // Set insecure permissions (0o620 - group writable)
        let mut perms = temp_file.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o620);
        std::fs::set_permissions(temp_file.path(), perms).unwrap();

        let result = check_file_permissions(temp_file.path()).unwrap();
        assert!(!result);
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_insecure_world_writable() {
        use std::os::unix::fs::PermissionsExt;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "test content").unwrap();
        temp_file.flush().unwrap();

        // Set insecure permissions (0o602 - world writable)
        let mut perms = temp_file.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o602);
        std::fs::set_permissions(temp_file.path(), perms).unwrap();

        let result = check_file_permissions(temp_file.path()).unwrap();
        assert!(!result);
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_0400() {
        use std::os::unix::fs::PermissionsExt;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "test content").unwrap();
        temp_file.flush().unwrap();

        // Set secure permissions (0o400 - read-only for owner)
        let mut perms = temp_file.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o400);
        std::fs::set_permissions(temp_file.path(), perms).unwrap();

        let result = check_file_permissions(temp_file.path()).unwrap();
        assert!(result);
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_insecure_all_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "test content").unwrap();
        temp_file.flush().unwrap();

        // Set very insecure permissions (0o777)
        let mut perms = temp_file.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(temp_file.path(), perms).unwrap();

        let result = check_file_permissions(temp_file.path()).unwrap();
        assert!(!result);
    }
}
