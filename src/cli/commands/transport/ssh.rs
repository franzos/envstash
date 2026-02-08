use std::process::{Command, Stdio};

use crate::error::{Error, Result};

/// Parse an SSH destination from `ssh://user@host` or `user@host`.
pub fn parse_dest(target: &str) -> &str {
    target.strip_prefix("ssh://").unwrap_or(target)
}

/// Send data to a remote host via `ssh <dest> 'envstash import'`.
/// Pipes the bytes to the remote envstash import's stdin.
pub fn send(data: &[u8], dest: &str) -> Result<()> {
    let dest = parse_dest(dest);

    let mut child = Command::new("ssh")
        .arg(dest)
        .arg("envstash import")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Other(format!("failed to spawn ssh: {e}")))?;

    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        stdin
            .write_all(data)
            .map_err(|e| Error::Other(format!("failed to write to ssh stdin: {e}")))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| Error::Other(format!("failed to wait on ssh: {e}")))?;

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

/// Fetch data from a remote host via `ssh <dest> 'envstash share'`.
/// Returns the bytes from the remote envstash share's stdout.
pub fn fetch(source: &str) -> Result<Vec<u8>> {
    let dest = parse_dest(source);

    let output = Command::new("ssh")
        .arg(dest)
        .arg("envstash share")
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
