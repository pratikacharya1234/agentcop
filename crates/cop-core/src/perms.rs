//! File permissions for AgentCop's state. Never rely on the umask (2026-10-27): every folder AgentCop
//! creates is 0700 and every file is 0600, set explicitly. The hook refuses to run when one of its files is
//! group- or world-writable, and the refusal names the command that fixes it.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Folders are 0700.
pub const PRIVATE_DIR_MODE: u32 = 0o700;
/// Files are 0600.
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// Create the folder if needed and set it to 0700 (explicit, whatever the umask).
pub fn ensure_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    set_mode(path, PRIVATE_DIR_MODE)
}

/// Set a file to 0600 if it exists.
pub fn secure_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    set_mode(path, PRIVATE_FILE_MODE)
}

/// Set a file or folder to the given mode.
pub fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {:o} {}: {e}", mode, path.display()))
}

/// Refuse (Err) when an existing path is group- or world-writable. Missing paths are fine. The message
/// includes the exact command that fixes it.
pub fn check_not_group_or_world_writable(paths: &[PathBuf]) -> Result<(), String> {
    for path in paths {
        let Ok(meta) = fs::metadata(path) else {
            continue;
        };
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            let want = if meta.is_dir() { 700 } else { 600 };
            return Err(format!(
                "{} is group- or world-writable (mode {:o}); refusing to run (fail closed). Fix it: run: chmod {} {}",
                path.display(),
                mode,
                want,
                path.display()
            ));
        }
    }
    Ok(())
}
