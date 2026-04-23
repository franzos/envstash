use std::process::Stdio;

use crate::error::{Error, Result};
use crate::util::subprocess::{is_available, spawn_clean};

/// Detect which mail transport is available.
/// Tries msmtp first, then sendmail.
fn detect_mailer() -> Result<&'static str> {
    for cmd in &["msmtp", "sendmail"] {
        if is_available(cmd) {
            return Ok(cmd);
        }
    }
    Err(Error::Other(
        "neither msmtp nor sendmail is installed. Install msmtp or a sendmail-compatible MTA."
            .to_string(),
    ))
}

/// Validate an email recipient: must contain exactly one `@`, must not start
/// with `-` (argv option injection), must not contain `\r`, `\n`, or any
/// ASCII control byte (CRLF header injection).
fn validate_recipient(addr: &str) -> Result<()> {
    if addr.is_empty() {
        return Err(Error::Other("invalid email recipient".into()));
    }
    if addr.starts_with('-') {
        return Err(Error::Other("invalid email recipient".into()));
    }
    if addr.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(Error::Other("invalid email recipient".into()));
    }
    if addr.chars().filter(|&c| c == '@').count() != 1 {
        return Err(Error::Other("invalid email recipient".into()));
    }
    Ok(())
}

/// Send data via email to the given recipient.
/// Prepends basic email headers (To, Subject, MIME).
pub fn send(data: &[u8], recipient: &str, subject: &str) -> Result<()> {
    validate_recipient(recipient)?;

    let mailer = detect_mailer()?;

    // Build the email with headers. We only insert the recipient into the
    // "To:" header after validate_recipient has ruled out CRLF injection.
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

    let mut child = spawn_clean(mailer)
        .arg("--")
        .arg(recipient)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Other(format!("failed to spawn {mailer}: {e}")))?;

    {
        use std::io::Write;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Other(format!("{mailer} stdin not available")))?;
        stdin
            .write_all(&message)
            .map_err(|e| Error::Other(format!("failed to write to {mailer} stdin: {e}")))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| Error::Other(format!("{mailer} wait failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Other(format!("{mailer} failed: {stderr}")));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_accepts_valid() {
        assert!(validate_recipient("user@example.com").is_ok());
        assert!(validate_recipient("a.b+c@sub.domain.io").is_ok());
    }

    #[test]
    fn recipient_rejects_empty() {
        assert!(validate_recipient("").is_err());
    }

    #[test]
    fn recipient_rejects_leading_dash() {
        assert!(validate_recipient("-oInjected=1").is_err());
    }

    #[test]
    fn recipient_rejects_crlf_injection() {
        assert!(validate_recipient("user@host\r\nBcc: evil@x").is_err());
        assert!(validate_recipient("user@host\nBcc: evil@x").is_err());
    }

    #[test]
    fn recipient_rejects_control_chars() {
        assert!(validate_recipient("user@host\x00").is_err());
        assert!(validate_recipient("user@host\x1b").is_err());
    }

    #[test]
    fn recipient_rejects_missing_at() {
        assert!(validate_recipient("no-at-sign").is_err());
    }

    #[test]
    fn recipient_rejects_multiple_at() {
        assert!(validate_recipient("a@b@c").is_err());
    }
}
