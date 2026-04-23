use std::io::Write;
use std::process::Stdio;

use crate::error::{Error, Result};
use crate::util::subprocess::{is_available as util_is_available, spawn_clean};

/// Check whether `gh` CLI is available.
pub fn is_available() -> bool {
    util_is_available("gh")
}

/// Create a GitHub Gist via `gh gist create`.
/// Returns the gist URL.
/// If `filename` is provided, the temp file (and thus the gist file) is named `<filename>.env`.
pub fn send(data: &[u8], public: bool, filename: Option<&str>) -> Result<String> {
    if !is_available() {
        return Err(Error::Other(
            "gh CLI is not installed. See https://cli.github.com".to_string(),
        ));
    }

    // gh gist create requires a file. Use a tempfile::NamedTempFile with a
    // randomized name and mode 0600 (via tempfile's defaults), so the file
    // is safe from predictable-path races and auto-deletes on Drop.
    let suffix = match filename {
        Some(n) => format!("-{n}.env"),
        None => "-envstash-send.env".to_string(),
    };
    let mut tmp = tempfile::Builder::new()
        .prefix("envstash-")
        .suffix(&suffix)
        .tempfile()
        .map_err(|e| Error::Other(format!("failed to create temp file: {e}")))?;

    tmp.write_all(data)
        .map_err(|e| Error::Other(format!("failed to write temp file: {e}")))?;
    tmp.flush()
        .map_err(|e| Error::Other(format!("failed to flush temp file: {e}")))?;

    let mut cmd = spawn_clean("gh");
    cmd.arg("gist").arg("create");

    if public {
        cmd.arg("--public");
    }

    cmd.arg(tmp.path())
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

    // `tmp` auto-deletes on Drop.
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if url.is_empty() {
        return Err(Error::Other(
            "gh gist create returned empty response".to_string(),
        ));
    }

    Ok(url)
}

/// Fetch a gist by ID via `gh gist view <id> --raw`.
pub fn fetch(gist_id: &str) -> Result<Vec<u8>> {
    if !is_available() {
        return Err(Error::Other(
            "gh CLI is not installed. See https://cli.github.com".to_string(),
        ));
    }

    // `--` stops option parsing so a malicious gist ID starting with `-`
    // cannot be interpreted as a `gh` flag.
    let output = spawn_clean("gh")
        .args(["gist", "view", "--raw", "--", gist_id])
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
    url.trim_end_matches('/').rsplit('/').next().unwrap_or(url)
}
