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
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SendConfig {
    /// Default target for `--to` when no value is given.
    pub default_to: Option<String>,
    /// Custom HTTP headers to send with paste uploads.
    #[serde(default)]
    pub headers: HashMap<String, String>,
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
    fn parse_config_with_headers() {
        let toml = r#"
[send]
default_to = "https://paste.example.com"

[send.headers]
Authorization = "Bearer mytoken"
X-Custom = "value"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.send.headers.get("Authorization").map(|s| s.as_str()),
            Some("Bearer mytoken")
        );
        assert_eq!(
            cfg.send.headers.get("X-Custom").map(|s| s.as_str()),
            Some("value")
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
}
