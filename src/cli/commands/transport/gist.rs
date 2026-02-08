use std::process::{Command, Stdio};

use crate::error::{Error, Result};

/// Check whether `gh` CLI is available.
pub fn is_available() -> bool {
    Command::new("gh")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Create a GitHub Gist via `gh gist create`.
/// Returns the gist URL.
/// If `filename` is provided, the temp file (and thus the gist file) is named `<filename>.env`.
pub fn send(data: &[u8], public: bool, filename: Option<&str>) -> Result<String> {
    if !is_available() {
        return Err(Error::Other("gh CLI is not installed. See https://cli.github.com".to_string()));
    }

    // gh gist create requires a file, so write to a temp file.
    let name = match filename {
        Some(n) => format!("{n}.env"),
        None => "envstash-share.env".to_string(),
    };
    let file_path = std::env::temp_dir().join(name);
    std::fs::write(&file_path, data)
        .map_err(|e| Error::Other(format!("failed to write temp file: {e}")))?;

    let mut cmd = Command::new("gh");
    cmd.arg("gist").arg("create");

    if public {
        cmd.arg("--public");
    }

    cmd.arg(&file_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd
        .output()
        .map_err(|e| Error::Other(format!("failed to run gh gist create: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Other(format!(
            "gh gist create failed: {stderr}. Run `gh auth login` first."
        )));
    }

    // Clean up temp file.
    let _ = std::fs::remove_file(&file_path);

    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if url.is_empty() {
        return Err(Error::Other("gh gist create returned empty response".to_string()));
    }

    Ok(url)
}

/// Fetch a gist by ID via `gh gist view <id> --raw`.
pub fn fetch(gist_id: &str) -> Result<Vec<u8>> {
    if !is_available() {
        return Err(Error::Other("gh CLI is not installed. See https://cli.github.com".to_string()));
    }

    let output = Command::new("gh")
        .args(["gist", "view", gist_id, "--raw"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::Other(format!("failed to run gh gist view: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Other(format!("gh gist view failed: {stderr}")));
    }

    Ok(output.stdout)
}

/// Extract a gist ID from a GitHub gist URL.
/// Supports: https://gist.github.com/<user>/<id> and bare IDs.
pub fn extract_gist_id(url: &str) -> &str {
    url.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(url)
}
