use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::Result;

/// Write data to a file, creating it atomically with mode 0600 on Unix.
///
/// Uses `create_new` to ensure the file does not already exist, and sets
/// permissions at creation time to avoid a TOCTOU window where the file
/// is world-readable.
pub fn write_file_restricted_new(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
    }
    Ok(())
}

/// Write data to a file with mode 0600 on Unix, truncating if it already exists.
///
/// Callers must separately invoke `refuse_symlink` before writing for
/// pre-open TOCTOU protection. On existing files, the mode is downgraded
/// to 0o600 after write — `OpenOptions::mode` only applies at creation
/// time, so a pre-existing 0o644 file would otherwise retain its old mode
/// after truncation.
pub fn write_file_restricted(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
        // Explicitly downgrade permissions: `mode(0o600)` above only takes
        // effect at creation, so an existing world-readable file would
        // otherwise keep its old mode after truncation.
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
    }
    Ok(())
}

/// Refuse to operate on symlinks. Returns an error if `path` exists and is a symlink.
///
/// `action` should be a short verb phrase describing the pending operation
/// (e.g. `"apply"`, `"save"`, `"dump to"`) — it is embedded in the error
/// message as `"refusing to {action} symlink: {path}"`.
pub fn refuse_symlink(path: &Path, action: &str) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(crate::error::Error::Other(format!(
            "refusing to {action} symlink: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_file_restricted_downgrades_mode_on_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("pre-existing.env");

        // Create the file with world-readable mode 0o644.
        fs::write(&target, b"initial").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );

        // Overwrite via write_file_restricted — mode must be downgraded.
        write_file_restricted(&target, b"secret").unwrap();

        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "existing file must be downgraded to 0o600");
        assert_eq!(fs::read(&target).unwrap(), b"secret");
    }

    #[test]
    fn refuse_symlink_error_phrasing() {
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let real = dir.path().join("real");
            fs::write(&real, b"x").unwrap();
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();

            let err = refuse_symlink(&link, "apply").unwrap_err().to_string();
            assert!(
                err.contains("refusing to apply symlink:"),
                "expected canonical phrasing, got: {err}"
            );
        }
    }
}
