use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Config file path (~/.config/envstash/config.toml).
pub fn config_path() -> Result<PathBuf> {
    let config_dir = match std::env::var("XDG_CONFIG_HOME") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => {
            let home = std::env::var("HOME")
                .map_err(|_| Error::Other("HOME environment variable not set".to_string()))?;
            PathBuf::from(home).join(".config")
        }
    };
    Ok(config_dir.join("envstash").join("config.toml"))
}

/// Top-level config structure.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub send: SendConfig,
}

/// Config for the `send` command.
///
/// `headers` is keyed by host name. Use `"*"` as a wildcard fallback for
/// hosts not otherwise matched.
///
/// Example (~/.config/envstash/config.toml):
///
/// ```toml
/// [send]
/// default_to = "https://my.paste.service"
///
/// [send.headers."my.paste.service"]
/// Authorization = "Bearer my-token"
///
/// [send.headers."*"]
/// User-Agent = "envstash"
/// ```
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SendConfig {
    /// Default target for `--to` when no value is given.
    pub default_to: Option<String>,
    /// Per-host HTTP headers to send with paste uploads. Outer key = host,
    /// inner key = header name. Use `"*"` for a global fallback.
    #[serde(default)]
    pub headers: HashMap<String, HashMap<String, String>>,
}

impl SendConfig {
    /// Resolve the set of HTTP headers that should be applied when talking
    /// to `url`. Picks the host-specific map if present; otherwise falls back
    /// to `"*"`.
    ///
    /// For safety, if the URL is `http://` (non-HTTPS) and the resolved
    /// headers include an `Authorization` (or similar auth header), the
    /// auth headers are stripped and a warning is printed, unless the host
    /// is `localhost` / `127.0.0.1`.
    pub fn resolve_headers_for_url(&self, url: &str) -> HashMap<String, String> {
        let host = host_from_url(url).unwrap_or_default();

        let mut headers = self
            .headers
            .get(&host)
            .cloned()
            .or_else(|| self.headers.get("*").cloned())
            .unwrap_or_default();

        let is_http = url.starts_with("http://");
        let is_local = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1");

        if is_http && !is_local && has_auth_header(&headers) {
            eprintln!(
                "warning: stripping auth headers for non-HTTPS URL to avoid credential leak: {url}"
            );
            strip_auth_headers(&mut headers);
        }

        headers
    }
}

/// Extract the host from an HTTP(S) URL. Returns `None` if not a URL we
/// recognize.
fn host_from_url(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    // Stop at `/`, `?`, `#`, or end-of-string; also strip optional `:port`.
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host_with_port = &rest[..end];
    let host = host_with_port.rsplit_once(':').map_or(host_with_port, |p| {
        // Keep host part only if port is all digits; otherwise the split
        // might be inside an ipv6 bracket.
        if p.1.chars().all(|c| c.is_ascii_digit()) {
            p.0
        } else {
            host_with_port
        }
    });
    Some(host.to_ascii_lowercase())
}

/// True if `headers` contains an authorization-like header (case-insensitive).
fn has_auth_header(headers: &HashMap<String, String>) -> bool {
    headers.keys().any(|k| is_auth_header_name(k))
}

/// Drop authorization-like headers in place.
fn strip_auth_headers(headers: &mut HashMap<String, String>) {
    headers.retain(|k, _| !is_auth_header_name(k));
}

fn is_auth_header_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(lower.as_str(), "authorization" | "proxy-authorization")
        || lower.starts_with("x-api-key")
        || lower.starts_with("x-auth-")
}

/// Load the config file, returning defaults if it doesn't exist.
pub fn load() -> Config {
    let path = match config_path() {
        Ok(p) => p,
        Err(_) => return Config::default(),
    };
    load_from(&path)
}

/// Load config from a specific path, returning defaults on missing/invalid files.
pub fn load_from(path: &std::path::Path) -> Config {
    match std::fs::read_to_string(path) {
        Ok(contents) => toml::from_str(&contents).unwrap_or_else(|e| {
            eprintln!("warning: failed to parse {}: {e}", path.display());
            Config::default()
        }),
        Err(_) => Config::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_path_uses_xdg() {
        let path = config_path().unwrap();
        assert!(path.ends_with("envstash/config.toml"));
    }

    #[test]
    fn default_config_has_no_default_to() {
        let cfg = Config::default();
        assert!(cfg.send.default_to.is_none());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[send]
default_to = "https://my.paste.service"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.send.default_to.as_deref(),
            Some("https://my.paste.service")
        );
    }

    #[test]
    fn parse_empty_config() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(cfg.send.default_to.is_none());
    }

    #[test]
    fn parse_partial_config_without_send() {
        let toml = "# empty config\n";
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.send.default_to.is_none());
    }

    #[test]
    fn load_missing_file_returns_default() {
        let cfg = load_from(std::path::Path::new("/tmp/nonexistent-envstash-test.toml"));
        assert!(cfg.send.default_to.is_none());
    }

    #[test]
    fn load_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[send]\ndefault_to = \"https://paste.example.com\"\n",
        )
        .unwrap();

        let cfg = load_from(&path);
        assert_eq!(
            cfg.send.default_to.as_deref(),
            Some("https://paste.example.com")
        );
    }

    #[test]
    fn load_invalid_toml_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "this is not valid toml {{{{").unwrap();

        let cfg = load_from(&path);
        assert!(cfg.send.default_to.is_none());
    }

    #[test]
    fn default_config_has_empty_headers() {
        let cfg = Config::default();
        assert!(cfg.send.headers.is_empty());
    }

    #[test]
    fn parse_config_with_per_host_headers() {
        let toml = r#"
[send]
default_to = "https://paste.example.com"

[send.headers."paste.example.com"]
Authorization = "Bearer mytoken"
X-Custom = "value"

[send.headers."*"]
User-Agent = "envstash"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.send
                .headers
                .get("paste.example.com")
                .and_then(|h| h.get("Authorization"))
                .map(String::as_str),
            Some("Bearer mytoken")
        );
        assert_eq!(
            cfg.send
                .headers
                .get("*")
                .and_then(|h| h.get("User-Agent"))
                .map(String::as_str),
            Some("envstash")
        );
    }

    #[test]
    fn parse_config_without_headers() {
        let toml = r#"
[send]
default_to = "https://paste.example.com"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.send.headers.is_empty());
    }

    #[test]
    fn host_from_url_basic() {
        assert_eq!(
            host_from_url("https://paste.example.com/abc"),
            Some("paste.example.com".to_string())
        );
        assert_eq!(
            host_from_url("http://localhost:8080/x"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn host_from_url_lowercases() {
        assert_eq!(
            host_from_url("https://Gist.GitHub.com/xyz"),
            Some("gist.github.com".to_string())
        );
    }

    #[test]
    fn resolve_headers_matches_host() {
        let mut cfg = SendConfig::default();
        let mut inner = HashMap::new();
        inner.insert("Authorization".to_string(), "Bearer a".to_string());
        cfg.headers.insert("example.com".to_string(), inner);

        let h = cfg.resolve_headers_for_url("https://example.com/foo");
        assert_eq!(h.get("Authorization").map(String::as_str), Some("Bearer a"));
    }

    #[test]
    fn resolve_headers_wildcard_fallback() {
        let mut cfg = SendConfig::default();
        let mut inner = HashMap::new();
        inner.insert("User-Agent".to_string(), "envstash".to_string());
        cfg.headers.insert("*".to_string(), inner);

        let h = cfg.resolve_headers_for_url("https://anything.tld/x");
        assert_eq!(h.get("User-Agent").map(String::as_str), Some("envstash"));
    }

    #[test]
    fn resolve_headers_strips_auth_on_http_non_local() {
        let mut cfg = SendConfig::default();
        let mut inner = HashMap::new();
        inner.insert("Authorization".to_string(), "Bearer a".to_string());
        inner.insert("X-Custom".to_string(), "v".to_string());
        cfg.headers.insert("evil.example.com".to_string(), inner);

        let h = cfg.resolve_headers_for_url("http://evil.example.com/x");
        assert!(!h.contains_key("Authorization"));
        assert_eq!(h.get("X-Custom").map(String::as_str), Some("v"));
    }

    #[test]
    fn resolve_headers_keeps_auth_on_localhost_http() {
        let mut cfg = SendConfig::default();
        let mut inner = HashMap::new();
        inner.insert("Authorization".to_string(), "Bearer a".to_string());
        cfg.headers.insert("localhost".to_string(), inner);

        let h = cfg.resolve_headers_for_url("http://localhost:8080/x");
        assert_eq!(h.get("Authorization").map(String::as_str), Some("Bearer a"));
    }

    #[test]
    fn resolve_headers_missing_host_returns_empty() {
        let cfg = SendConfig::default();
        let h = cfg.resolve_headers_for_url("https://nohost.tld/x");
        assert!(h.is_empty());
    }
}
