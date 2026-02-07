use std::path::Path;
use std::process::Command;

use crate::error::{Error, Result};
use crate::git;

/// Check whether `gpg` is available on the system.
pub fn is_available() -> bool {
    Command::new("gpg")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Read the default GPG recipient from git `user.signingkey`.
///
/// Returns `None` if not in a git repo or the key is not configured.
pub fn default_recipient(dir: &Path) -> Result<Option<String>> {
    git::signing_key(dir)
}

/// Resolve GPG recipients from explicit values or git signing key fallback.
///
/// If `explicit` is non-empty, returns it. Otherwise, falls back to the
/// git signing key via `default_recipient()`.
pub fn resolve_recipients(explicit: &[String], cwd: &Path) -> Result<Vec<String>> {
    if !explicit.is_empty() {
        return Ok(explicit.to_vec());
    }
    if let Some(key) = default_recipient(cwd)? {
        return Ok(vec![key]);
    }
    Err(Error::NoGpgRecipient)
}

/// Encrypt data with GPG for the given recipients.
///
/// Shells out to `gpg --encrypt --armor --recipient <r> ...` and returns
/// the GPG-encrypted (ASCII-armored) blob.
pub fn gpg_encrypt(data: &[u8], recipients: &[String]) -> Result<Vec<u8>> {
    if !is_available() {
        return Err(Error::GpgNotAvailable);
    }
    if recipients.is_empty() {
        return Err(Error::NoGpgRecipient);
    }

    let mut cmd = Command::new("gpg");
    cmd.arg("--encrypt")
        .arg("--armor")
        .arg("--batch")
        .arg("--yes")
        .arg("--trust-model")
        .arg("always");

    for r in recipients {
        cmd.arg("--recipient").arg(r);
    }

    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| Error::Gpg(format!("failed to spawn gpg: {e}")))?;

    // Write data to gpg's stdin.
    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        stdin
            .write_all(data)
            .map_err(|e| Error::Gpg(format!("failed to write to gpg stdin: {e}")))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| Error::Gpg(format!("failed to wait on gpg: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Gpg(format!("gpg --encrypt failed: {stderr}")));
    }

    Ok(output.stdout)
}

/// Decrypt a GPG-encrypted blob.
///
/// Shells out to `gpg --decrypt`. The user's gpg-agent handles passphrase
/// or hardware token interaction.
pub fn gpg_decrypt(data: &[u8]) -> Result<Vec<u8>> {
    if !is_available() {
        return Err(Error::GpgNotAvailable);
    }

    let mut cmd = Command::new("gpg");
    cmd.arg("--decrypt")
        .arg("--batch")
        .arg("--yes")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| Error::Gpg(format!("failed to spawn gpg: {e}")))?;

    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        stdin
            .write_all(data)
            .map_err(|e| Error::Gpg(format!("failed to write to gpg stdin: {e}")))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| Error::Gpg(format!("failed to wait on gpg: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Gpg(format!("gpg --decrypt failed: {stderr}")));
    }

    Ok(output.stdout)
}

/// Encrypt an AES key with GPG for the given recipients.
///
/// Convenience wrapper around [`gpg_encrypt`] for key wrapping.
pub fn wrap_key_gpg(aes_key: &[u8], recipients: &[String]) -> Result<Vec<u8>> {
    gpg_encrypt(aes_key, recipients)
}

/// Decrypt a GPG-encrypted blob back to the raw AES key.
///
/// Convenience wrapper around [`gpg_decrypt`] for key unwrapping.
pub fn unwrap_key_gpg(blob: &[u8]) -> Result<Vec<u8>> {
    gpg_decrypt(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpg_availability_check() {
        // Just verify this doesn't panic; result depends on the environment.
        let _ = is_available();
    }

    #[test]
    fn wrap_fails_without_recipients() {
        if !is_available() {
            return; // skip
        }
        let key = [0u8; 32];
        let result = wrap_key_gpg(&key, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        if !is_available() {
            eprintln!("GPG not available, skipping wrap/unwrap round-trip test");
            return;
        }

        // Try to find a usable GPG key. If none exist, skip.
        let output = Command::new("gpg")
            .args(["--list-keys", "--with-colons", "--batch"])
            .output();

        let Ok(output) = output else { return };
        if !output.status.success() {
            return;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let recipient = stdout
            .lines()
            .filter(|l| l.starts_with("uid:") || l.starts_with("pub:"))
            .filter_map(|l| l.split(':').nth(4).filter(|s| !s.is_empty()))
            .next();

        let Some(recipient) = recipient else {
            eprintln!("No GPG keys found, skipping wrap/unwrap round-trip test");
            return;
        };

        let key = crate::crypto::aes::generate_key();
        let wrapped = wrap_key_gpg(&key, &[recipient.to_string()]).unwrap();
        assert!(!wrapped.is_empty());

        let unwrapped = unwrap_key_gpg(&wrapped).unwrap();
        assert_eq!(unwrapped, key);
    }

    #[test]
    fn default_recipient_returns_result() {
        // In a non-git temp dir, signing_key should be None.
        let dir = tempfile::tempdir().unwrap();

        // default_recipient delegates to git::signing_key. We just verify
        // it returns Ok (not panic). The actual value depends on global
        // git config.
        let result = default_recipient(dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_recipients_explicit() {
        let result = resolve_recipients(
            &["ABCD1234".to_string()],
            Path::new("/tmp"),
        )
        .unwrap();
        assert_eq!(result, vec!["ABCD1234".to_string()]);
    }

    #[test]
    fn resolve_recipients_empty_no_git_key() {
        let dir = tempfile::tempdir().unwrap();
        // resolve_recipients reads global git config, so the result depends
        // on whether the system has a global user.signingkey.
        let result = resolve_recipients(&[], dir.path());
        // If the system has a global signing key, this will succeed.
        // If not, it will return NoGpgRecipient. Both are valid.
        match &result {
            Ok(recipients) => assert!(!recipients.is_empty()),
            Err(_) => {} // NoGpgRecipient is expected when no key
        }
    }
}
