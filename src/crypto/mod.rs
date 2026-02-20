pub mod aes;
pub mod gpg;
pub mod hmac;
pub mod password;

use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::error::{Error, Result};

/// Encryption mode for the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    None,
    Gpg,
    Password,
}

impl FromStr for EncryptionMode {
    type Err = Error;

    /// Parse from the string stored in the database config.
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "none" => Ok(Self::None),
            "gpg" => Ok(Self::Gpg),
            "password" => Ok(Self::Password),
            other => Err(Error::Other(format!("unknown encryption mode: {other}"))),
        }
    }
}

impl EncryptionMode {
    /// Serialize to the string stored in the database config.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gpg => "gpg",
            Self::Password => "password",
        }
    }
}

/// Resolve the key file path using priority: CLI flag > env var > db config.
///
/// Returns `None` if no key file is configured anywhere.
pub fn resolve_key_file(
    cli_flag: Option<&Path>,
    env_var: Option<&str>,
    db_config: Option<&str>,
) -> Option<PathBuf> {
    if let Some(p) = cli_flag {
        return Some(p.to_path_buf());
    }

    if let Some(val) = env_var {
        if !val.is_empty() {
            return Some(PathBuf::from(val));
        }
    }

    if let Some(val) = db_config {
        if !val.is_empty() {
            return Some(PathBuf::from(val));
        }
    }

    None
}

/// Load the AES key by unwrapping it according to the encryption mode.
///
/// - `Gpg`: reads the key file and decrypts it with GPG.
/// - `Password`: reads the key file and decrypts it with a password.
/// - `None`: no key needed, returns an error (caller should not call this).
pub fn load_key(mode: EncryptionMode, key_file: &Path) -> Result<[u8; aes::KEY_LEN]> {
    match mode {
        EncryptionMode::None => Err(Error::Other(
            "no encryption configured, key not needed".to_string(),
        )),
        EncryptionMode::Gpg => {
            let blob = std::fs::read(key_file)
                .map_err(|_| Error::KeyFileNotFound(key_file.to_path_buf()))?;
            let raw = gpg::unwrap_key_gpg(&blob)?;
            if raw.len() != aes::KEY_LEN {
                return Err(Error::InvalidKeyLength {
                    expected: aes::KEY_LEN,
                    got: raw.len(),
                });
            }
            let mut key = [0u8; aes::KEY_LEN];
            key.copy_from_slice(&raw);
            Ok(key)
        }
        EncryptionMode::Password => {
            let blob = std::fs::read(key_file)
                .map_err(|_| Error::KeyFileNotFound(key_file.to_path_buf()))?;
            let pw = password::get_password()?;
            password::unwrap_key_password(&blob, &pw)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // -----------------------------------------------------------------------
    // EncryptionMode
    // -----------------------------------------------------------------------

    #[test]
    fn encryption_mode_round_trip() {
        for mode in [
            EncryptionMode::None,
            EncryptionMode::Gpg,
            EncryptionMode::Password,
        ] {
            let s = mode.as_str();
            let parsed: EncryptionMode = s.parse().unwrap();
            assert_eq!(parsed, mode);
        }
    }

    #[test]
    fn encryption_mode_unknown() {
        let result: Result<EncryptionMode> = "aes-only".parse();
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // resolve_key_file
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_cli_flag_wins() {
        let result = resolve_key_file(
            Some(Path::new("/cli/key.gpg")),
            Some("/env/key.gpg"),
            Some("/db/key.gpg"),
        );
        assert_eq!(result, Some(PathBuf::from("/cli/key.gpg")));
    }

    #[test]
    fn resolve_env_var_second() {
        let result = resolve_key_file(None, Some("/env/key.gpg"), Some("/db/key.gpg"));
        assert_eq!(result, Some(PathBuf::from("/env/key.gpg")));
    }

    #[test]
    fn resolve_db_config_last() {
        let result = resolve_key_file(None, None, Some("/db/key.gpg"));
        assert_eq!(result, Some(PathBuf::from("/db/key.gpg")));
    }

    #[test]
    fn resolve_none_when_all_empty() {
        let result = resolve_key_file(None, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn resolve_skips_empty_env_var() {
        let result = resolve_key_file(None, Some(""), Some("/db/key.gpg"));
        assert_eq!(result, Some(PathBuf::from("/db/key.gpg")));
    }

    #[test]
    fn resolve_skips_empty_db_config() {
        let result = resolve_key_file(None, None, Some(""));
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // load_key
    // -----------------------------------------------------------------------

    #[test]
    fn load_key_none_mode_errors() {
        let result = load_key(EncryptionMode::None, Path::new("/nonexistent"));
        assert!(result.is_err());
    }

    #[test]
    fn load_key_missing_file_errors() {
        let result = load_key(EncryptionMode::Password, Path::new("/nonexistent/key.gpg"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("key file not found"));
    }

    #[test]
    fn load_key_password_round_trip() {
        let key = aes::generate_key();
        let pw = "integration-test-pw";

        // Write wrapped key to a temp file.
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.enc");
        let blob = password::wrap_key_password(&key, pw).unwrap();
        std::fs::write(&key_path, &blob).unwrap();

        // Safety: this test is single-threaded for env var access.
        unsafe {
            std::env::set_var("ENVSTASH_PASSWORD", pw);
        }
        let loaded = load_key(EncryptionMode::Password, &key_path).unwrap();
        unsafe {
            std::env::remove_var("ENVSTASH_PASSWORD");
        }

        assert_eq!(loaded, key);
    }
}
