// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::commands::secret::{SecretCreateArgs, SecretReviseArgs};
use crate::error::{CliError, CliResult};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64_standard;
use hierarkey_core::CkError;
use hierarkey_core::error::validation::ValidationError;
use std::fs;

/// Represents the source of a secret value, which can be provided in various formats or from different sources.
pub enum ValueSource {
    /// A plain string value provided directly via the command line.
    String(String),
    /// A hexadecimal string value provided via the command line.
    Hex(String),
    /// A base64-encoded string value provided via the command line.
    Base64(String),
    /// A file path from which to read the secret value.
    File(String),
    /// Indicates that the secret value should be read from standard input (stdin).
    Stdin,
    /// Indicates that the secret value should be entered using the system's default text editor.
    Editor,
}

impl TryFrom<&SecretCreateArgs> for ValueSource {
    type Error = CkError;

    fn try_from(args: &SecretCreateArgs) -> Result<Self, Self::Error> {
        ValueSource::from(&args.value, &args.value_hex, &args.value_base64, &args.from_file, args.stdin, args.use_editor).ok_or_else(|| {
            ValidationError::Field {
                field: "value_source",
                code: "missing_value",
                message: "Secret value must be provided via --value, --value-hex, --value-base64, --from-file, --stdin or --use-editor".into(),
            }.into()
        })
    }
}

impl TryFrom<&SecretReviseArgs> for ValueSource {
    type Error = CkError;

    fn try_from(args: &SecretReviseArgs) -> Result<Self, Self::Error> {
        ValueSource::from(&args.value, &args.value_hex, &args.value_base64, &args.from_file, args.stdin, args.use_editor).ok_or_else(|| {
            ValidationError::Field {
                field: "value_source",
                code: "missing_value",
                message: "Secret value must be provided via --value, --value-hex, --value-base64, --from-file, --stdin or --use-editor".into(),
            }.into()
        })
    }
}

impl ValueSource {
    fn from(
        value: &Option<String>,
        value_hex: &Option<String>,
        value_base64: &Option<String>,
        from_file: &Option<String>,
        stdin: bool,
        use_editor: bool,
    ) -> Option<Self> {
        if let Some(v) = &value {
            Some(ValueSource::String(v.clone()))
        } else if let Some(h) = &value_hex {
            Some(ValueSource::Hex(h.clone()))
        } else if let Some(b64) = &value_base64 {
            Some(ValueSource::Base64(b64.clone()))
        } else if let Some(path) = &from_file {
            Some(ValueSource::File(path.clone()))
        } else if stdin {
            Some(ValueSource::Stdin)
        } else if use_editor {
            Some(ValueSource::Editor)
        } else {
            None
        }
    }
}

pub fn open_editor(initial_content: &str) -> CliResult<String> {
    use std::io::Write;
    use std::process::Command;

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());

    let mut temp_file = tempfile::NamedTempFile::new().map_err(CliError::IoError)?;
    temp_file
        .write_all(initial_content.as_bytes())
        .map_err(CliError::IoError)?;

    let path = temp_file.path().to_path_buf();

    let status = Command::new(&editor).arg(&path).status().map_err(CliError::IoError)?;
    if !status.success() {
        return Err(CliError::InvalidInput("Editor exited with error".into()));
    }

    let content = fs::read_to_string(&path).map_err(CliError::IoError)?.trim().to_string();
    Ok(content)
}

pub fn resolve_value(value: ValueSource) -> CliResult<Option<Vec<u8>>> {
    match value {
        ValueSource::String(v) => Ok(Some(v.into_bytes())),
        ValueSource::Hex(h) => {
            let h = h.trim_start_matches("0x");
            let h = h.trim_start_matches("0X");
            let bytes = hex::decode(h).map_err(|_| CliError::InvalidInput("invalid hex value".into()))?;
            Ok(Some(bytes))
        }
        ValueSource::Base64(b64) => {
            let bytes = base64_standard
                .decode(b64)
                .map_err(|_| CliError::InvalidInput("invalid base64 value".into()))?;
            Ok(Some(bytes))
        }
        ValueSource::File(path) => {
            let bytes = fs::read(path).map_err(CliError::IoError)?;
            Ok(Some(bytes))
        }
        ValueSource::Stdin => {
            use std::io::{self, Read};

            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf).map_err(CliError::IoError)?;

            if buf.is_empty() {
                return Err(CliError::InvalidInput("empty input".into()));
            }

            Ok(Some(buf))
        }
        ValueSource::Editor => {
            let text = open_editor("")?;
            Ok(Some(text.into_bytes()))
        }
    }
}
