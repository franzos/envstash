use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// Compute an HMAC-SHA256 over the given data, returning the hex-encoded tag.
pub fn compute_hmac(key: &[u8], data: &[u8]) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| Error::Encryption(format!("HMAC init failed: {e}")))?;
    mac.update(data);
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Verify an HMAC-SHA256 tag (hex-encoded) against the given data.
///
/// Uses constant-time comparison to prevent timing attacks.
pub fn verify_hmac(key: &[u8], data: &[u8], expected_hex: &str) -> Result<bool> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| Error::Encryption(format!("HMAC init failed: {e}")))?;
    mac.update(data);

    let expected = hex::decode(expected_hex)
        .map_err(|e| Error::Decryption(format!("invalid HMAC hex: {e}")))?;

    Ok(mac.verify_slice(&expected).is_ok())
}

/// Helper: encode bytes as hex string (used internally).
mod hex {
    use std::fmt::Write;

    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().fold(
            String::with_capacity(bytes.as_ref().len() * 2),
            |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            },
        )
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd-length hex string".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("invalid hex at position {i}: {e}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = b"test-hmac-key-for-envstash";
        let data = b"project=/home/user/proj;file=.env;ts=2024-01-01";
        let tag = compute_hmac(key, data).unwrap();
        assert!(verify_hmac(key, data, &tag).unwrap());
    }

    #[test]
    fn tampered_data_fails() {
        let key = b"test-hmac-key";
        let data = b"original data";
        let tag = compute_hmac(key, data).unwrap();
        assert!(!verify_hmac(key, b"tampered data", &tag).unwrap());
    }

    #[test]
    fn wrong_key_fails() {
        let data = b"some metadata";
        let tag = compute_hmac(b"key1", data).unwrap();
        assert!(!verify_hmac(b"key2", data, &tag).unwrap());
    }

    #[test]
    fn invalid_hex_tag() {
        let key = b"key";
        let data = b"data";
        let result = verify_hmac(key, data, "not-valid-hex!");
        assert!(result.is_err());
    }

    #[test]
    fn deterministic() {
        let key = b"key";
        let data = b"data";
        let tag1 = compute_hmac(key, data).unwrap();
        let tag2 = compute_hmac(key, data).unwrap();
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn tag_is_64_hex_chars() {
        let tag = compute_hmac(b"key", b"data").unwrap();
        // SHA-256 produces 32 bytes = 64 hex characters.
        assert_eq!(tag.len(), 64);
    }
}
