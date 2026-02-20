use std::process::{Command, Stdio};

use crate::error::{Error, Result};

/// Detect which mail transport is available.
/// Tries msmtp first, then sendmail.
fn detect_mailer() -> Result<&'static str> {
    for cmd in &["msmtp", "sendmail"] {
        let ok = Command::new(cmd)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            return Ok(cmd);
        }
    }
    Err(Error::Other(
        "neither msmtp nor sendmail is installed. Install msmtp or a sendmail-compatible MTA."
            .to_string(),
    ))
}

/// Send data via email to the given recipient.
/// Prepends basic email headers (To, Subject, MIME).
pub fn send(data: &[u8], recipient: &str, subject: &str) -> Result<()> {
    let mailer = detect_mailer()?;

    // Build the email with headers.
    let is_binary = data
        .iter()
        .any(|&b| b > 127 || (b < 32 && b != b'\n' && b != b'\r' && b != b'\t'));

    let mut message = Vec::new();
    message.extend_from_slice(format!("To: {recipient}\r\n").as_bytes());
    message.extend_from_slice(format!("Subject: {subject}\r\n").as_bytes());
    message.extend_from_slice(b"MIME-Version: 1.0\r\n");

    if is_binary {
        use base64::Engine;
        message.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
        message.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n");
        message.extend_from_slice(b"\r\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        message.extend_from_slice(encoded.as_bytes());
    } else {
        message.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
        message.extend_from_slice(b"\r\n");
        message.extend_from_slice(data);
    }

    let mut child = Command::new(mailer)
        .arg(recipient)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Other(format!("failed to spawn {mailer}: {e}")))?;

    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        stdin
            .write_all(&message)
            .map_err(|e| Error::Other(format!("failed to write to {mailer} stdin: {e}")))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| Error::Other(format!("failed to wait on {mailer}: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Other(format!("{mailer} failed: {stderr}")));
    }

    Ok(())
}
