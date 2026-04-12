// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use hierarkey_core::{CkError, CkResult};
use tracing::{error, trace};
use zeroize::Zeroizing;

use hierarkey_core::error::validation::ValidationError;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Maximum filesize of a master key file
pub const MAX_MASTERKEY_FILE_SIZE: usize = 16 * 1024; // 16 KiB

/// Only read/write by owner. No access for group/others.
pub const MASTERKEY_FILE_PERMISSIONS: u32 = 0o600;

#[derive(Clone, Debug)]
pub struct FileStore {
    base_dir: PathBuf,
}

impl FileStore {
    pub fn new(base_dir: impl AsRef<Path>) -> CkResult<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();

        if base_dir.as_os_str().is_empty() {
            return Err(CkError::MasterKey("file store base_dir is empty".into()));
        }

        Ok(Self { base_dir })
    }

    /// Reads the file contents with size/permission checks.
    pub fn read_to_string(&self, filename: &str) -> CkResult<Zeroizing<String>> {
        let path = resolve_rel_path(self.base_dir.as_path(), filename)?;
        read_file_to_string(&path)
    }

    /// Atomically writes JSON to filename under A with secure permissions.
    pub fn write_json_atomic(&self, filename: &str, value: &serde_json::Value) -> CkResult<PathBuf> {
        let path = resolve_rel_path(self.base_dir.as_path(), filename)?;
        write_json_atomic(&path, value)?;
        Ok(path)
    }

    // /// Optional helper: ensure base directory exists.
    // pub fn ensure_base_dir(&self) -> CkResult<()> {
    //     fs::create_dir_all(&self.base_dir)?;
    //     Ok(())
    // }

    /// FileStore::base_dir()
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

// ------------------------------------------------------------------------------------------
/// Resolve a user-provided *relative* path safely against a configured base directory.
///
/// Policy:
/// - must be relative (no absolute paths, no Windows prefixes, no UNC)
/// - no "." or ".." segments
/// - no NUL bytes
pub fn resolve_rel_path(base_dir: &Path, rel: &str) -> CkResult<PathBuf> {
    if rel.is_empty() {
        return Err(ValidationError::InvalidValue {
            field: "path",
            value: "path may not be empty".into(),
        }
        .into());
    }
    if rel.contains('\0') {
        return Err(ValidationError::InvalidValue {
            field: "path",
            value: "path may not be contain NUL bytes".into(),
        }
        .into());
    }

    let rel_path = Path::new(rel);

    // Reject absolute paths and Windows/UNC prefixes
    for c in rel_path.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => {
                return Err(ValidationError::InvalidValue {
                    field: "path",
                    value: "path must be relative".into(),
                }
                .into());
            }
            Component::CurDir | Component::ParentDir => {
                return Err(ValidationError::InvalidValue {
                    field: "path",
                    value: "path may not be contain '.' or '..' segments".into(),
                }
                .into());
            }
            Component::Normal(_) => {}
        }
    }

    Ok(base_dir.join(rel_path))
}

/// read_file_to_string()
fn read_file_to_string(path: &Path) -> CkResult<Zeroizing<String>> {
    let file = File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            // Give a clear message: distinguish missing file vs missing directory
            let dir = path.parent().unwrap_or(path);
            if !dir.exists() {
                tracing::debug!(
                    "master key directory does not exist: {} (expected file: {})",
                    dir.display(),
                    path.display()
                );
                CkError::MasterKey("master key directory does not exist".into())
            } else {
                tracing::debug!("master key file not found: {}", path.display());
                CkError::MasterKey("master key file not found".into())
            }
        } else {
            tracing::debug!("failed to open master key file {}: {e}", path.display());
            CkError::MasterKey("failed to open master key file".into())
        }
    })?;

    // Size cap first (metadata read does not read content)
    let len = file.metadata()?.len() as usize;
    if len > MAX_MASTERKEY_FILE_SIZE {
        error!(
            "master key file too large: {} ({} bytes, max {})",
            path.display(),
            len,
            MAX_MASTERKEY_FILE_SIZE
        );
        return Err(CkError::MasterKey("master key file too large".into()));
    }

    // Permissions check on Unix
    #[cfg(unix)]
    {
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if (mode & 0o077) != 0 {
            error!(
                "master key file does not have secure permissions (expected 0600/0400, got {:#o}): {}",
                mode,
                path.display()
            );
            return Err(CkError::MasterKey("master key file does not have secure permissions".into()));
        }
    }

    let mut buf = Zeroizing::new(String::new());
    let mut reader = std::io::BufReader::new(file);
    reader.read_to_string(&mut buf)?;
    Ok(buf)
}

/// write_json_atomic()
/// Write to temp file in same directory then rename.
/// Ensures permissions are restricted.
fn write_json_atomic(final_path: &Path, value: &serde_json::Value) -> CkResult<()> {
    let dir = final_path
        .parent()
        .ok_or_else(|| CkError::MasterKey("invalid target path".into()))?;

    fs::create_dir_all(dir)?;

    let tmp_path = temp_sibling_path(final_path);

    // Serialize once
    let payload = serde_json::to_vec_pretty(value)?;

    // Create temp file (new) and write
    {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp_path)?;

        f.write_all(&payload)?;
        f.sync_all()?;

        #[cfg(unix)]
        {
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(MASTERKEY_FILE_PERMISSIONS))?;
        }
    }

    // Rename is atomic on same filesystem
    fs::rename(&tmp_path, final_path)?;

    #[cfg(unix)]
    {
        if let Ok(dirfd) = OpenOptions::new().read(true).open(dir) {
            let _ = dirfd.sync_all();
        }
    }

    trace!("wrote master key file {}", final_path.display());
    Ok(())
}

/// temp_sibling_path()
fn temp_sibling_path(final_path: &Path) -> PathBuf {
    // e.g. "hkey-master-root-v1.json.tmp"
    let mut p = final_path.to_path_buf();
    let mut os = p.file_name().unwrap_or_default().to_os_string();
    os.push(".tmp");
    p.set_file_name(os);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- resolve_rel_path (pure, no I/O) ----

    #[test]
    fn resolve_simple_relative_path() {
        let base = Path::new("/data/keys");
        let result = resolve_rel_path(base, "mykey.json").unwrap();
        assert_eq!(result, PathBuf::from("/data/keys/mykey.json"));
    }

    #[test]
    fn resolve_empty_path_is_error() {
        let base = Path::new("/data/keys");
        assert!(resolve_rel_path(base, "").is_err());
    }

    #[test]
    fn resolve_nul_byte_is_error() {
        let base = Path::new("/data/keys");
        assert!(resolve_rel_path(base, "bad\0name.json").is_err());
    }

    #[test]
    fn resolve_absolute_path_is_error() {
        let base = Path::new("/data/keys");
        assert!(resolve_rel_path(base, "/etc/passwd").is_err());
    }

    #[test]
    fn resolve_dotdot_is_error() {
        let base = Path::new("/data/keys");
        assert!(resolve_rel_path(base, "../escape.json").is_err());
    }

    #[test]
    fn resolve_embedded_dotdot_is_error() {
        let base = Path::new("/data/keys");
        assert!(resolve_rel_path(base, "sub/../escape.json").is_err());
    }

    #[test]
    fn resolve_curdir_is_error() {
        let base = Path::new("/data/keys");
        assert!(resolve_rel_path(base, "./file.json").is_err());
    }

    #[test]
    fn resolve_nested_path_is_ok() {
        let base = Path::new("/data/keys");
        let result = resolve_rel_path(base, "subdir/nested.json").unwrap();
        assert_eq!(result, PathBuf::from("/data/keys/subdir/nested.json"));
    }

    // ---- FileStore::new ----

    #[test]
    fn new_with_empty_path_is_error() {
        assert!(FileStore::new("").is_err());
    }

    #[test]
    fn new_with_valid_path_succeeds() {
        let store = FileStore::new("/tmp/keys").unwrap();
        assert_eq!(store.base_dir(), Path::new("/tmp/keys"));
    }

    // ---- FileStore read/write roundtrip ----

    #[test]
    fn write_and_read_roundtrip() {
        let tmp_dir = std::env::temp_dir().join(format!("hkey-test-{}", uuid::Uuid::new_v4()));
        let store = FileStore::new(&tmp_dir).unwrap();
        let value = serde_json::json!({"hello": "world", "num": 99});
        store.write_json_atomic("test.json", &value).unwrap();
        let content = store.read_to_string("test.json").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["hello"], "world");
        assert_eq!(parsed["num"], 99);
        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn read_missing_file_returns_error() {
        let tmp_dir = std::env::temp_dir().join(format!("hkey-test-{}", uuid::Uuid::new_v4()));
        let store = FileStore::new(&tmp_dir).unwrap();
        assert!(store.read_to_string("nonexistent.json").is_err());
    }

    #[test]
    fn write_rejects_dotdot_filename() {
        let tmp_dir = std::env::temp_dir().join(format!("hkey-test-{}", uuid::Uuid::new_v4()));
        let store = FileStore::new(&tmp_dir).unwrap();
        let value = serde_json::json!({});
        assert!(store.write_json_atomic("../escape.json", &value).is_err());
    }
}
