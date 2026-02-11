pub mod email;
pub mod gist;
pub mod paste;
pub mod ssh;

use crate::config;
use crate::error::{Error, Result};

/// Send data to a remote target based on the `--to` value.
///
/// Returns `Ok(Some(url))` for backends that produce a URL (paste, gist),
/// `Ok(None)` for backends that don't (email, ssh).
pub fn send(target: &str, data: &[u8], public: bool, filename: Option<&str>) -> Result<Option<String>> {
    if target == "gist" {
        // For gist: base64-encode binary data (encrypted output).
        let payload = if is_binary(data) {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(data).into_bytes()
        } else {
            data.to_vec()
        };
        let url = gist::send(&payload, public, filename)?;
        Ok(Some(url))
    } else if let Some(addr) = target.strip_prefix("email:") {
        email::send(data, addr, "envstash send")?;
        Ok(None)
    } else if target.starts_with("ssh://") {
        ssh::send(data, target)?;
        Ok(None)
    } else if is_url(target) {
        let headers = config::load().send.headers;
        let url = paste::send(data, target, &headers)?;
        Ok(Some(url))
    } else {
        Err(Error::Other(format!(
            "Unknown target '{target}'. Use: --to, --to <url>, gist, email:<addr>, or ssh://user@host"
        )))
    }
}

/// Fetch data from a remote source based on the `--from` value.
pub fn fetch(source: &str) -> Result<Vec<u8>> {
    if source.starts_with("ssh://") {
        ssh::fetch(source)
    } else if is_gist_url(source) {
        let id = gist::extract_gist_id(source);
        let raw = gist::fetch(id)?;
        // If the gist content looks base64-encoded, decode it.
        maybe_base64_decode(&raw)
    } else if is_url(source) {
        let headers = config::load().send.headers;
        paste::fetch(source, &headers)
    } else {
        Err(Error::Other(format!(
            "Unknown source '{source}'. Use: https://<url>, ssh://user@host, or a gist URL"
        )))
    }
}

/// Check whether the data is binary (contains non-text bytes).
fn is_binary(data: &[u8]) -> bool {
    data.iter()
        .any(|&b| b > 127 || (b < 32 && b != b'\n' && b != b'\r' && b != b'\t'))
}

/// Check whether a string looks like an HTTP(S) URL.
fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Check whether a URL points to a GitHub Gist.
fn is_gist_url(s: &str) -> bool {
    s.starts_with("https://gist.github.com/") || s.starts_with("http://gist.github.com/")
}

/// If the data looks like a base64-encoded blob (no whitespace-separated words,
/// valid base64 chars), attempt to decode. Otherwise return as-is.
fn maybe_base64_decode(data: &[u8]) -> Result<Vec<u8>> {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t.trim(),
        Err(_) => return Ok(data.to_vec()),
    };

    // If it starts with known plaintext markers, don't decode.
    if text.starts_with("# envstash") || text.starts_with('{') {
        return Ok(data.to_vec());
    }

    // Try base64 decode.
    use base64::Engine;
    match base64::engine::general_purpose::STANDARD.decode(text) {
        Ok(decoded) => Ok(decoded),
        Err(_) => Ok(data.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::{self, ExportEntry, ExportEnvelope};

    // -- URL detection --

    #[test]
    fn is_url_https() {
        assert!(is_url("https://0x0.st"));
        assert!(is_url("https://example.com/path"));
    }

    #[test]
    fn is_url_http() {
        assert!(is_url("http://example.com"));
    }

    #[test]
    fn is_url_non_urls() {
        assert!(!is_url("gist"));
        assert!(!is_url("ssh://user@host"));
        assert!(!is_url("email:user@host"));
        assert!(!is_url("ftp://example.com"));
    }

    #[test]
    fn is_gist_url_valid() {
        assert!(is_gist_url("https://gist.github.com/user/abc123"));
        assert!(is_gist_url("https://gist.github.com/user/abc123/"));
    }

    #[test]
    fn is_gist_url_not_gist() {
        assert!(!is_gist_url("https://github.com/user/repo"));
        assert!(!is_gist_url("https://0x0.st/abc"));
    }

    // -- binary detection --

    #[test]
    fn is_binary_plaintext() {
        assert!(!is_binary(b"DB_HOST=localhost\n"));
        assert!(!is_binary(b"line1\r\nline2\ttab"));
    }

    #[test]
    fn is_binary_with_high_bytes() {
        assert!(is_binary(&[0x80, 0x90, 0xFF]));
    }

    #[test]
    fn is_binary_with_control_chars() {
        assert!(is_binary(&[0x00]));
        assert!(is_binary(&[0x01]));
    }

    #[test]
    fn is_binary_empty() {
        assert!(!is_binary(b""));
    }

    // -- base64 auto-decode --

    #[test]
    fn maybe_decode_plaintext_export() {
        let data = b"# envstash export\nDB_HOST=localhost\n";
        let result = maybe_base64_decode(data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn maybe_decode_json_export() {
        let data = b"{\"version\":1,\"entries\":[]}";
        let result = maybe_base64_decode(data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn maybe_decode_actual_base64() {
        use base64::Engine;
        let original = b"secret binary data";
        let encoded = base64::engine::general_purpose::STANDARD.encode(original);
        let result = maybe_base64_decode(encoded.as_bytes()).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn maybe_decode_invalid_base64_returns_as_is() {
        let data = b"not base64 at all!!! with spaces";
        let result = maybe_base64_decode(data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn maybe_decode_raw_binary_returns_as_is() {
        let data: Vec<u8> = vec![0x00, 0x80, 0xFF, 0x01];
        let result = maybe_base64_decode(&data).unwrap();
        assert_eq!(result, data);
    }

    // -- gist ID extraction --

    #[test]
    fn extract_gist_id_from_url() {
        assert_eq!(
            gist::extract_gist_id("https://gist.github.com/user/abc123"),
            "abc123"
        );
    }

    #[test]
    fn extract_gist_id_trailing_slash() {
        assert_eq!(
            gist::extract_gist_id("https://gist.github.com/user/abc123/"),
            "abc123"
        );
    }

    #[test]
    fn extract_gist_id_bare() {
        assert_eq!(gist::extract_gist_id("abc123"), "abc123");
    }

    // -- SSH dest parsing --

    #[test]
    fn ssh_parse_dest_with_prefix() {
        assert_eq!(ssh::parse_dest("ssh://user@host"), "user@host");
    }

    #[test]
    fn ssh_parse_dest_without_prefix() {
        assert_eq!(ssh::parse_dest("user@host"), "user@host");
    }

    // -- send dispatch routing --

    #[test]
    fn send_rejects_unknown_target() {
        let result = send("ftp://something", b"data", false, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unknown target"));
    }

    // -- integration: 0x0.st paste round-trip --

    #[test]
    #[ignore] // requires network access
    fn paste_0x0_round_trip() {
        let env_entries = vec![
            crate::types::EnvEntry {
                key: "DB_HOST".to_string(),
                value: "localhost".to_string(),
                comment: Some("database host".to_string()),
            },
            crate::types::EnvEntry {
                key: "API_KEY".to_string(),
                value: "sk-test-12345".to_string(),
                comment: None,
            },
        ];
        let hash = crate::parser::content_hash(&env_entries);

        let envelope = ExportEnvelope {
            version: 1,
            file: ".env".to_string(),
            branch: "main".to_string(),
            commit: "abc123".to_string(),
            timestamp: "2024-06-17T12:00:00Z".to_string(),
            content_hash: hash,
            message: None,
            entries: vec![
                ExportEntry {
                    key: "DB_HOST".to_string(),
                    value: "localhost".to_string(),
                    comment: Some("database host".to_string()),
                },
                ExportEntry {
                    key: "API_KEY".to_string(),
                    value: "sk-test-12345".to_string(),
                    comment: None,
                },
            ],
        };
        let serialized = export::to_text(&envelope);
        let headers = std::collections::HashMap::new();

        let url = paste::send(serialized.as_bytes(), "https://0x0.st", &headers)
            .expect("paste upload to 0x0.st failed");

        assert!(
            url.starts_with("https://0x0.st/") || url.starts_with("http://0x0.st/"),
            "unexpected paste URL: {url}"
        );

        let fetched = paste::fetch(&url, &headers).expect("paste fetch from 0x0.st failed");
        let text = std::str::from_utf8(&fetched).expect("fetched data is not valid UTF-8");
        let parsed = export::auto_detect(text).expect("failed to parse fetched export data");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].key, "DB_HOST");
        assert_eq!(parsed.entries[0].value, "localhost");
        assert_eq!(parsed.entries[1].key, "API_KEY");
        assert_eq!(parsed.entries[1].value, "sk-test-12345");
    }

    // -- integration: GitHub Gist round-trip (skipped if gh unavailable) --

    #[test]
    #[ignore] // requires network access + gh auth
    fn gist_round_trip() {
        if !gist::is_available() {
            eprintln!("gh CLI not available, skipping gist round-trip test");
            return;
        }

        // Also verify the user is actually authenticated.
        let auth = std::process::Command::new("gh")
            .args(["auth", "status"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match auth {
            Ok(s) if s.success() => {}
            _ => {
                eprintln!("gh auth not logged in, skipping gist round-trip test");
                return;
            }
        }

        // Build entries and compute a real content hash, matching what share.rs does.
        let env_entries = vec![
            crate::types::EnvEntry {
                key: "DB_HOST".to_string(),
                value: "localhost".to_string(),
                comment: Some("database host".to_string()),
            },
            crate::types::EnvEntry {
                key: "API_KEY".to_string(),
                value: "sk-test-12345".to_string(),
                comment: None,
            },
        ];
        let hash = crate::parser::content_hash(&env_entries);

        let envelope = ExportEnvelope {
            version: 1,
            file: ".env".to_string(),
            branch: "main".to_string(),
            commit: "abc123".to_string(),
            timestamp: "2024-06-17T12:00:00Z".to_string(),
            content_hash: hash.clone(),
            message: None,
            entries: vec![
                ExportEntry {
                    key: "DB_HOST".to_string(),
                    value: "localhost".to_string(),
                    comment: Some("database host".to_string()),
                },
                ExportEntry {
                    key: "API_KEY".to_string(),
                    value: "sk-test-12345".to_string(),
                    comment: None,
                },
            ],
        };
        let serialized = export::to_text(&envelope);

        let url =
            gist::send(serialized.as_bytes(), false, Some(&hash)).expect("gist create failed");
        let id = gist::extract_gist_id(&url).to_string();

        let fetched = gist::fetch(&id).expect("gist fetch failed");
        let text = std::str::from_utf8(&fetched).expect("fetched gist is not valid UTF-8");
        let parsed = export::auto_detect(text.trim()).expect("failed to parse fetched gist data");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].key, "DB_HOST");
        assert_eq!(parsed.entries[0].value, "localhost");
        assert_eq!(parsed.entries[1].key, "API_KEY");
        assert_eq!(parsed.entries[1].value, "sk-test-12345");

        // Cleanup: delete the gist so we don't leave litter.
        let _ = std::process::Command::new("gh")
            .args(["gist", "delete", &id])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}
