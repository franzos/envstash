//! Transport encryption for export/import blobs.
//!
//! This module provides encryption/decryption for exported data (share, dump).
//! Transport encryption is SEPARATE from at-rest encryption -- even an
//! unencrypted store can produce encrypted exports.
//!
//! Two methods are supported:
//! - **GPG**: shells out to `gpg --encrypt --armor` / `gpg --decrypt`
//! - **Password**: AES-256-GCM with an argon2id-derived key
//!
//! # Wire formats
//!
//! ## Password-encrypted blob
//! ```text
//! EVPW (4 bytes magic) || salt (22 bytes, argon2id) || nonce (12 bytes) || ciphertext+tag
//! ```
//!
//! ## GPG-encrypted blob
//! ASCII-armored PGP message (starts with `-----BEGIN PGP MESSAGE-----`).
//!
//! ## Plaintext
//! Anything that doesn't match the above patterns.

use crate::crypto::{aes, gpg, password};
use crate::error::{Error, Result};

use argon2::password_hash::SaltString;
use rand::rngs::OsRng;

/// Magic header for password-encrypted transport blobs.
const PASSWORD_MAGIC: &[u8; 4] = b"EVPW";

/// Argon2id salt string length (base64-encoded, as produced by `SaltString`).
const SALT_LEN: usize = 22;

/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;

/// Detected transport encryption method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportEncryption {
    /// No transport encryption detected.
    None,
    /// GPG (ASCII-armored PGP message).
    Gpg,
    /// Password-based (AES-256-GCM + argon2id).
    Password,
}

/// Detect the transport encryption method from the blob's prefix.
pub fn detect(data: &[u8]) -> TransportEncryption {
    if data.starts_with(PASSWORD_MAGIC) {
        return TransportEncryption::Password;
    }

    // ASCII-armored GPG messages start with this header.
    if data.starts_with(b"-----BEGIN PGP MESSAGE-----") {
        return TransportEncryption::Gpg;
    }

    TransportEncryption::None
}

// ---------------------------------------------------------------------------
// GPG transport encryption (delegates to crypto::gpg)
// ---------------------------------------------------------------------------

/// Encrypt data with GPG for the given recipients.
///
/// Shells out to `gpg --encrypt --armor`. Returns an ASCII-armored PGP message.
pub fn encrypt_gpg(data: &[u8], recipients: &[String]) -> Result<Vec<u8>> {
    gpg::gpg_encrypt(data, recipients)
}

/// Decrypt a GPG-encrypted blob.
///
/// Shells out to `gpg --decrypt`. The user's gpg-agent handles passphrase
/// or hardware token interaction.
pub fn decrypt_gpg(data: &[u8]) -> Result<Vec<u8>> {
    gpg::gpg_decrypt(data)
}

// ---------------------------------------------------------------------------
// Password transport encryption
// ---------------------------------------------------------------------------

/// Encrypt data with a password using AES-256-GCM + argon2id key derivation.
///
/// Output format: `EVPW (4) || salt (22) || nonce (12) || ciphertext+tag`.
pub fn encrypt_password(data: &[u8], pw: &str) -> Result<Vec<u8>> {
    if pw.is_empty() {
        return Err(Error::PasswordRequired);
    }

    let salt = SaltString::generate(&mut OsRng);
    let derived = password::derive_key(pw, salt.as_str())?;
    let encrypted = aes::encrypt(&derived, data)?;

    let salt_bytes = salt.as_str().as_bytes();
    let mut blob = Vec::with_capacity(PASSWORD_MAGIC.len() + salt_bytes.len() + encrypted.len());
    blob.extend_from_slice(PASSWORD_MAGIC);
    blob.extend_from_slice(salt_bytes);
    blob.extend_from_slice(&encrypted);
    Ok(blob)
}

/// Decrypt a password-encrypted transport blob.
///
/// Expects: `EVPW (4) || salt (22) || nonce+ciphertext+tag`.
pub fn decrypt_password(data: &[u8], pw: &str) -> Result<Vec<u8>> {
    let min_len = PASSWORD_MAGIC.len() + SALT_LEN + NONCE_LEN;
    if data.len() < min_len {
        return Err(Error::Decryption(
            "password-encrypted blob too short".to_string(),
        ));
    }

    if &data[..PASSWORD_MAGIC.len()] != PASSWORD_MAGIC {
        return Err(Error::Decryption(
            "invalid magic header for password-encrypted blob".to_string(),
        ));
    }

    let offset = PASSWORD_MAGIC.len();
    let salt_str = std::str::from_utf8(&data[offset..offset + SALT_LEN])
        .map_err(|e| Error::Decryption(format!("invalid salt encoding: {e}")))?;

    let derived = password::derive_key(pw, salt_str)?;
    aes::decrypt(&derived, &data[offset + SALT_LEN..])
}

// ---------------------------------------------------------------------------
// Decrypt with auto-detection
// ---------------------------------------------------------------------------

/// Decrypt a transport blob, auto-detecting the encryption method.
///
/// - If password-encrypted, `password` must be `Some`.
/// - If GPG-encrypted, gpg-agent handles decryption.
/// - If plaintext, returns the data as-is.
pub fn decrypt_auto(data: &[u8], password: Option<&str>) -> Result<Vec<u8>> {
    match detect(data) {
        TransportEncryption::None => Ok(data.to_vec()),
        TransportEncryption::Gpg => decrypt_gpg(data),
        TransportEncryption::Password => {
            let pw = password.ok_or(Error::PasswordRequired)?;
            decrypt_password(data, pw)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Detection
    // -----------------------------------------------------------------------

    #[test]
    fn detect_plaintext() {
        let data = b"just some plaintext export data";
        assert_eq!(detect(data), TransportEncryption::None);
    }

    #[test]
    fn detect_password_encrypted() {
        let mut data = Vec::new();
        data.extend_from_slice(PASSWORD_MAGIC);
        data.extend_from_slice(b"some trailing bytes here");
        assert_eq!(detect(&data), TransportEncryption::Password);
    }

    #[test]
    fn detect_gpg_encrypted() {
        let data = b"-----BEGIN PGP MESSAGE-----\nsome gpg data\n-----END PGP MESSAGE-----";
        assert_eq!(detect(data), TransportEncryption::Gpg);
    }

    #[test]
    fn detect_empty() {
        assert_eq!(detect(b""), TransportEncryption::None);
    }

    // -----------------------------------------------------------------------
    // Password round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn password_round_trip() {
        let data = b"DB_HOST=localhost\nAPI_KEY=secret123\n";
        let password = "test-transport-pw";

        let encrypted = encrypt_password(data, password).unwrap();
        assert_ne!(encrypted, data);
        assert!(encrypted.starts_with(PASSWORD_MAGIC));

        let decrypted = decrypt_password(&encrypted, password).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn password_round_trip_empty_data() {
        let encrypted = encrypt_password(b"", "pw").unwrap();
        let decrypted = decrypt_password(&encrypted, "pw").unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn password_round_trip_large_data() {
        let data: Vec<u8> = (0..10_000)
            .map(|i| u8::try_from(i & 0xff).unwrap())
            .collect();
        let encrypted = encrypt_password(&data, "big-data-pw").unwrap();
        let decrypted = decrypt_password(&encrypted, "big-data-pw").unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn password_wrong_password_fails() {
        let data = b"secret data";
        let encrypted = encrypt_password(data, "correct").unwrap();
        let result = decrypt_password(&encrypted, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn password_empty_password_fails() {
        let result = encrypt_password(b"data", "");
        assert!(result.is_err());
    }

    #[test]
    fn password_truncated_blob_fails() {
        let result = decrypt_password(b"EVPWshort", "pw");
        assert!(result.is_err());
    }

    #[test]
    fn password_tampered_ciphertext_fails() {
        let data = b"secret data here";
        let mut encrypted = encrypt_password(data, "pw").unwrap();
        // Flip a byte in the ciphertext region.
        let idx = PASSWORD_MAGIC.len() + SALT_LEN + NONCE_LEN + 1;
        if idx < encrypted.len() {
            encrypted[idx] ^= 0xff;
        }
        let result = decrypt_password(&encrypted, "pw");
        assert!(result.is_err());
    }

    #[test]
    fn password_different_encryptions_differ() {
        let data = b"same data";
        let e1 = encrypt_password(data, "pw").unwrap();
        let e2 = encrypt_password(data, "pw").unwrap();
        // Random salt + nonce means blobs differ.
        assert_ne!(e1, e2);
    }

    // -----------------------------------------------------------------------
    // Auto-detection round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn auto_detect_plaintext() {
        let data = b"plaintext export data";
        let result = decrypt_auto(data, None).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn auto_detect_password() {
        let data = b"some env data";
        let pw = "auto-pw";
        let encrypted = encrypt_password(data, pw).unwrap();
        let decrypted = decrypt_auto(&encrypted, Some(pw)).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn auto_detect_password_missing_password() {
        let encrypted = encrypt_password(b"data", "pw").unwrap();
        let result = decrypt_auto(&encrypted, None);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // GPG (integration, skipped if unavailable)
    // -----------------------------------------------------------------------

    #[test]
    fn gpg_encrypt_fails_without_recipients() {
        if !gpg::is_available() {
            return;
        }
        let result = encrypt_gpg(b"data", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn gpg_round_trip() {
        if !gpg::is_available() {
            eprintln!("GPG not available, skipping transport GPG round-trip test");
            return;
        }

        // Find a usable GPG key.
        let output = std::process::Command::new("gpg")
            .args(["--list-keys", "--with-colons", "--batch"])
            .output();

        let Ok(output) = output else { return };
        if !output.status.success() {
            return;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let recipient = stdout
            .lines()
            .filter(|l| l.starts_with("uid:") || l.starts_with("pub:"))
            .filter_map(|l| l.split(':').nth(4).filter(|s| !s.is_empty()))
            .next();

        let Some(recipient) = recipient else {
            eprintln!("No GPG keys found, skipping transport GPG round-trip test");
            return;
        };

        let data = b"DB_HOST=localhost\nAPI_KEY=super-secret\n";
        let encrypted = encrypt_gpg(data, &[recipient.to_string()]).unwrap();

        // Verify it's ASCII-armored PGP.
        assert!(encrypted.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        assert_eq!(detect(&encrypted), TransportEncryption::Gpg);

        let decrypted = decrypt_gpg(&encrypted).unwrap();
        assert_eq!(decrypted, data);

        // Also test auto-detect path.
        let auto_decrypted = decrypt_auto(&encrypted, None).unwrap();
        assert_eq!(auto_decrypted, data);
    }
}
