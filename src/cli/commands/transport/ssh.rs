use std::process::Stdio;

use crate::error::{Error, Result};
use crate::util::subprocess::spawn_clean;

/// Parse an SSH destination from `ssh://user@host` or `user@host`.
pub fn parse_dest(target: &str) -> &str {
    target.strip_prefix("ssh://").unwrap_or(target)
}

/// Validate an ssh destination to reject argv-option injection (leading `-`)
/// and control characters. Allowed characters: alnum, `._+@:/-`.
fn validate_dest(dest: &str) -> Result<()> {
    if dest.is_empty() {
        return Err(Error::Other("invalid ssh destination".into()));
    }
    if dest.starts_with('-') {
        return Err(Error::Other("invalid ssh destination".into()));
    }
    let ok = dest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '@' | ':' | '/' | '-'));
    if !ok {
        return Err(Error::Other("invalid ssh destination".into()));
    }
    Ok(())
}

/// Send data to a remote host via `ssh <dest> 'envstash receive'`.
/// Pipes the bytes to the remote envstash receive's stdin.
pub fn send(data: &[u8], dest: &str) -> Result<()> {
    let dest = parse_dest(dest);
    validate_dest(dest)?;

    let mut child = spawn_clean("ssh")
        .arg("--")
        .arg(dest)
        .arg("envstash receive")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Other(format!("failed to spawn ssh: {e}")))?;

    {
        use std::io::Write;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Other("ssh stdin not available".into()))?;
        stdin
            .write_all(data)
            .map_err(|e| Error::Other(format!("failed to write to ssh stdin: {e}")))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| Error::Other(format!("ssh wait failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Other(format!("ssh failed: {stderr}")));
    }

    // Print any stdout from the remote side (e.g., "Imported .env ...")
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.is_empty() {
        eprint!("{stdout}");
    }

    Ok(())
}

/// Fetch data from a remote host via `ssh <dest> 'envstash send'`.
/// Returns the bytes from the remote envstash send's stdout.
pub fn fetch(source: &str) -> Result<Vec<u8>> {
    let dest = parse_dest(source);
    validate_dest(dest)?;

    let output = spawn_clean("ssh")
        .arg("--")
        .arg(dest)
        .arg("envstash send")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::Other(format!("failed to run ssh: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Other(format!("ssh failed: {stderr}")));
    }

    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_allows_normal_host() {
        assert!(validate_dest("user@example.com").is_ok());
        assert!(validate_dest("example.com").is_ok());
        assert!(validate_dest("user@host:2222").is_ok());
    }

    #[test]
    fn validate_rejects_leading_dash() {
        assert!(validate_dest("-oProxyCommand=evil").is_err());
    }

    #[test]
    fn validate_rejects_empty() {
        assert!(validate_dest("").is_err());
    }

    #[test]
    fn validate_rejects_control_chars() {
        assert!(validate_dest("user@host\nexploit").is_err());
        assert!(validate_dest("user@host exploit").is_err());
    }
}
