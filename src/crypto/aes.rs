use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};

use crate::error::{Error, Result};

/// AES-256 key length in bytes.
pub const KEY_LEN: usize = 32;

/// AES-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;

/// Generate a random 32-byte AES-256 key.
pub fn generate_key() -> [u8; KEY_LEN] {
    let key = Aes256Gcm::generate_key(OsRng);
    let mut buf = [0u8; KEY_LEN];
    buf.copy_from_slice(&key);
    buf
}

/// Encrypt plaintext with AES-256-GCM.
///
/// Returns `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
/// The `aes-gcm` crate appends the tag to the ciphertext automatically.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Encryption(e.to_string()))?;

    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| Error::Encryption(e.to_string()))?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt an AES-256-GCM blob produced by [`encrypt`].
///
/// Expects `nonce (12 bytes) || ciphertext || tag`.
pub fn decrypt(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(Error::Decryption(
            "ciphertext too short (missing nonce)".to_string(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Decryption(e.to_string()))?;

    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    let ciphertext = &blob[NONCE_LEN..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| Error::Decryption(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = generate_key();
        let plaintext = b"secret environment value";
        let blob = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let key = generate_key();
        let blob = encrypt(&key, b"").unwrap();
        let decrypted = decrypt(&key, &blob).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let blob = encrypt(&key1, b"secret").unwrap();
        let result = decrypt(&key2, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = generate_key();
        let mut blob = encrypt(&key, b"secret").unwrap();
        // Flip a byte in the ciphertext (after the nonce).
        if blob.len() > 13 {
            blob[13] ^= 0xff;
        }
        let result = decrypt(&key, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_nonce_fails() {
        let key = generate_key();
        let mut blob = encrypt(&key, b"secret").unwrap();
        blob[0] ^= 0xff;
        let result = decrypt(&key, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_blob_fails() {
        let key = generate_key();
        let result = decrypt(&key, &[0u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn different_encryptions_produce_different_blobs() {
        let key = generate_key();
        let blob1 = encrypt(&key, b"same").unwrap();
        let blob2 = encrypt(&key, b"same").unwrap();
        // Random nonce means blobs differ even for same plaintext.
        assert_ne!(blob1, blob2);
    }
}
