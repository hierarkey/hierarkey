// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::CkResult;
use std::fs::File;
use tracing::trace;

/// Check that an already-open file has secure permissions (no group/other access).
pub fn check_file_permissions(file: &File) -> CkResult<bool> {
    // Check 600 permissions on Unix-like systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;

        trace!("Checking file permissions");
        if !metadata.is_file() {
            trace!("File is not a regular file");
            return Ok(false);
        }

        let perms = metadata.mode() & 0o777;
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
        let _ = file;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Helper: set permissions on a NamedTempFile and re-open it as a read-only File.
    #[cfg(unix)]
    fn open_with_mode(temp_file: &mut NamedTempFile, mode: u32) -> File {
        use std::os::unix::fs::PermissionsExt;
        write!(temp_file, "test content").unwrap();
        temp_file.flush().unwrap();
        let mut perms = temp_file.as_file().metadata().unwrap().permissions();
        perms.set_mode(mode);
        std::fs::set_permissions(temp_file.path(), perms).unwrap();
        File::open(temp_file.path()).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_secure() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let file = open_with_mode(&mut temp_file, 0o600);
        assert!(check_file_permissions(&file).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_insecure_world_readable() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let file = open_with_mode(&mut temp_file, 0o644);
        assert!(!check_file_permissions(&file).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_insecure_group_readable() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let file = open_with_mode(&mut temp_file, 0o640);
        assert!(!check_file_permissions(&file).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_insecure_group_writable() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let file = open_with_mode(&mut temp_file, 0o620);
        assert!(!check_file_permissions(&file).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_insecure_world_writable() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let file = open_with_mode(&mut temp_file, 0o602);
        assert!(!check_file_permissions(&file).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_0400() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let file = open_with_mode(&mut temp_file, 0o400);
        assert!(check_file_permissions(&file).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_insecure_all_permissions() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let file = open_with_mode(&mut temp_file, 0o777);
        assert!(!check_file_permissions(&file).unwrap());
    }
}
