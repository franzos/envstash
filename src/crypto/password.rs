use std::path::Path;

use argon2::Argon2;
use argon2::password_hash::SaltString;
use rand::rngs::OsRng;

use crate::crypto::aes::{self, KEY_LEN};
use crate::error::{Error, Result};

/// Argon2id salt length in bytes (encoded as a 22-char base64 string by SaltString).
const SALT_LEN: usize = 22;

/// Wrap an AES key by encrypting it with a password-derived key (argon2id).
///
/// Returns: `salt_string (22 bytes) || AES-GCM blob (nonce + ciphertext + tag)`.
pub fn wrap_key_password(aes_key: &[u8; KEY_LEN], password: &str) -> Result<Vec<u8>> {
    let salt = SaltString::generate(&mut OsRng);
    let derived = derive_key(password, salt.as_str())?;

    let encrypted = aes::encrypt(&derived, aes_key)?;

    let salt_bytes = salt.as_str().as_bytes();
    let mut blob = Vec::with_capacity(salt_bytes.len() + encrypted.len());
    blob.extend_from_slice(salt_bytes);
    blob.extend_from_slice(&encrypted);
    Ok(blob)
}

/// Unwrap an AES key from a password-wrapped blob.
///
/// Expects: `salt_string (22 bytes) || AES-GCM blob`.
pub fn unwrap_key_password(blob: &[u8], password: &str) -> Result<[u8; KEY_LEN]> {
    if blob.len() < SALT_LEN {
        return Err(Error::Decryption(
            "password-wrapped blob too short".to_string(),
        ));
    }

    let salt_str = std::str::from_utf8(&blob[..SALT_LEN])
        .map_err(|e| Error::Decryption(format!("invalid salt encoding: {e}")))?;

    let derived = derive_key(password, salt_str)?;
    let plaintext = aes::decrypt(&derived, &blob[SALT_LEN..])?;

    if plaintext.len() != KEY_LEN {
        return Err(Error::InvalidKeyLength {
            expected: KEY_LEN,
            got: plaintext.len(),
        });
    }

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Derive a 32-byte key from a password and salt using argon2id.
pub fn derive_key(password: &str, salt: &str) -> Result<[u8; KEY_LEN]> {
    let argon2 = Argon2::default();
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key)
        .map_err(|e| Error::Encryption(format!("argon2 key derivation failed: {e}")))?;
    Ok(key)
}

/// Prompt the user for a password via the terminal.
///
/// Uses `rpassword` to suppress echo.
pub fn prompt_password(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    rpassword::read_password().map_err(|e| Error::Other(format!("password prompt failed: {e}")))
}

/// Get the encryption password.
///
/// Checks `ENVSTASH_PASSWORD` environment variable first, then falls back
/// to an interactive terminal prompt.
pub fn get_password() -> Result<String> {
    if let Ok(pw) = std::env::var("ENVSTASH_PASSWORD")
        && !pw.is_empty()
    {
        return Ok(pw);
    }
    prompt_password("Password: ")
}

/// Resolve a password from a password file, environment variable, or prompt.
///
/// Priority: `--password-file <path>` > `ENVSTASH_PASSWORD` env var >
/// interactive prompt.
///
/// When a file is provided, the contents are read and the trailing newline
/// (CR / LF / CRLF) is stripped. On unix, the file must have mode 0600 (or
/// otherwise have no group/world bits set) — we refuse to read anything
/// lax so a misconfigured `.password` can't be slurped by other users.
pub fn resolve_password(password_file: Option<&Path>) -> Result<String> {
    if let Some(path) = password_file {
        return read_password_file(path);
    }
    get_password()
}

fn read_password_file(path: &Path) -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| Error::Other(format!("failed to stat password file: {e}")))?;
        let mode = meta.permissions().mode();
        // Refuse if any group/world bits are set. We allow execute for self
        // since that's irrelevant for readability.
        if mode & 0o077 != 0 {
            return Err(Error::Other(format!(
                "refusing to read password file {}: permissions too lax (mode {:o}); chmod 600",
                path.display(),
                mode & 0o777
            )));
        }
    }

    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("failed to read password file: {e}")))?;
    // Strip trailing CRLF / LF / CR (one set), preserving interior whitespace.
    let trimmed = raw
        .strip_suffix("\r\n")
        .or_else(|| raw.strip_suffix('\n'))
        .or_else(|| raw.strip_suffix('\r'))
        .unwrap_or(&raw);
    if trimmed.is_empty() {
        return Err(Error::Other("password file is empty".to_string()));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aes;

    #[test]
    fn round_trip() {
        let key = aes::generate_key();
        let password = "test-password-123";
        let blob = wrap_key_password(&key, password).unwrap();
        let unwrapped = unwrap_key_password(&blob, password).unwrap();
        assert_eq!(unwrapped, key);
    }

    #[test]
    fn wrong_password_fails() {
        let key = aes::generate_key();
        let blob = wrap_key_password(&key, "correct").unwrap();
        let result = unwrap_key_password(&blob, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn different_passwords_produce_different_blobs() {
        let key = aes::generate_key();
        let blob1 = wrap_key_password(&key, "password1").unwrap();
        let blob2 = wrap_key_password(&key, "password2").unwrap();
        assert_ne!(blob1, blob2);
    }

    #[test]
    fn truncated_blob_fails() {
        let result = unwrap_key_password(&[0u8; 10], "password");
        assert!(result.is_err());
    }

    #[test]
    fn get_password_from_env() {
        // Safety: this test is single-threaded for env var access.
        unsafe {
            std::env::set_var("ENVSTASH_PASSWORD", "from-env");
        }
        let pw = get_password().unwrap();
        assert_eq!(pw, "from-env");
        unsafe {
            std::env::remove_var("ENVSTASH_PASSWORD");
        }
    }

    #[test]
    fn resolve_password_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "file-pw\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let pw = resolve_password(Some(&path)).unwrap();
        assert_eq!(pw, "file-pw");
    }

    #[test]
    fn resolve_password_from_env() {
        unsafe {
            std::env::set_var("ENVSTASH_PASSWORD", "env-pw");
        }
        let pw = resolve_password(None).unwrap();
        assert_eq!(pw, "env-pw");
        unsafe {
            std::env::remove_var("ENVSTASH_PASSWORD");
        }
    }

    #[test]
    fn resolve_password_file_overrides_env() {
        unsafe {
            std::env::set_var("ENVSTASH_PASSWORD", "env-pw");
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "file-pw").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let pw = resolve_password(Some(&path)).unwrap();
        assert_eq!(pw, "file-pw");
        unsafe {
            std::env::remove_var("ENVSTASH_PASSWORD");
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_password_file_rejects_lax_perms() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "pw").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = resolve_password(Some(&path)).unwrap_err().to_string();
        assert!(err.contains("permissions too lax"), "unexpected: {err}");
    }

    #[test]
    fn resolve_password_file_empty_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let err = resolve_password(Some(&path)).unwrap_err().to_string();
        assert!(err.contains("empty"), "unexpected: {err}");
    }
}
