use std::fs;
use std::path::PathBuf;

use crate::cli;
use crate::crypto;
use crate::error::{Error, Result};
use crate::store;
use crate::store::queries;
use crate::util::fs as util_fs;

/// Run the `init` command: create store directory and database.
pub fn run(encrypt: &str, recipients: &[String], key_file: Option<&str>) -> Result<()> {
    let dir = cli::store_dir()?;
    let path = cli::store_path()?;

    if path.exists() {
        let conn = store::open(&path)?;
        if store::is_initialized(&conn)? {
            return Err(Error::StoreAlreadyInitialized);
        }
    }

    fs::create_dir_all(&dir)?;
    set_dir_permissions(&dir)?;

    let conn = store::open(&path)?;

    match encrypt {
        "none" => {
            store::init(&conn, "none")?;
        }
        "password" => {
            let aes_key = crypto::aes::generate_key();
            let password = get_init_password()?;
            let wrapped = crypto::password::wrap_key_password(&aes_key, &password)?;

            let key_path = key_file
                .map(PathBuf::from)
                .unwrap_or_else(|| dir.join("key.gpg"));

            util_fs::write_file_restricted_new(&key_path, &wrapped)?;

            store::init(&conn, "password")?;

            if key_file.is_some() {
                let key_path_str = key_path
                    .to_str()
                    .ok_or_else(|| Error::Other("key file path must be valid UTF-8".to_string()))?;
                queries::set_config(&conn, "key_file", key_path_str)?;
            }
        }
        "gpg" => {
            if !crypto::gpg::is_available() {
                return Err(Error::GpgNotAvailable);
            }

            let rcpts = recipients.to_vec();
            if rcpts.is_empty() {
                let keys = crypto::gpg::list_secret_keys()?;
                if keys.is_empty() {
                    return Err(Error::Other(
                        "No GPG secret keys found. Generate a key with `gpg --gen-key` first."
                            .to_string(),
                    ));
                }
                eprintln!("\nAvailable GPG keys:\n");
                for (key_id, uid) in &keys {
                    eprintln!("  {key_id}  {uid}");
                }
                eprintln!("\nRe-run with --recipient <key_id> to select a key.");
                return Err(Error::NoGpgRecipient);
            }

            let aes_key = crypto::aes::generate_key();
            let wrapped = crypto::gpg::wrap_key_gpg(&aes_key, &rcpts)?;

            let key_path = key_file
                .map(PathBuf::from)
                .unwrap_or_else(|| dir.join("key.gpg"));

            util_fs::write_file_restricted_new(&key_path, &wrapped)?;

            store::init(&conn, "gpg")?;

            if key_file.is_some() {
                let key_path_str = key_path
                    .to_str()
                    .ok_or_else(|| Error::Other("key file path must be valid UTF-8".to_string()))?;
                queries::set_config(&conn, "key_file", key_path_str)?;
            }

            set_file_permissions(&path)?;
            println!("Initialized envstash store at {}", dir.display());
            println!("Encryption: gpg (key: {})", rcpts.join(", "));
            return Ok(());
        }
        other => {
            return Err(Error::Other(format!(
                "Unknown encryption mode: {other}. Use 'none', 'gpg', or 'password'."
            )));
        }
    }

    set_file_permissions(&path)?;

    println!("Initialized envstash store at {}", dir.display());
    if encrypt == "password" {
        println!("Encryption: password");
    }
    Ok(())
}

/// Get password for init: check ENVSTASH_PASSWORD first, then prompt
/// with confirmation.
fn get_init_password() -> Result<String> {
    if let Ok(pw) = std::env::var("ENVSTASH_PASSWORD")
        && !pw.is_empty()
    {
        return Ok(pw);
    }
    let pw1 = crypto::password::prompt_password("Password: ")?;
    if pw1.is_empty() {
        return Err(Error::Other("Password cannot be empty.".to_string()));
    }
    let pw2 = crypto::password::prompt_password("Confirm password: ")?;
    if pw1 != pw2 {
        return Err(Error::Other("Passwords do not match.".to_string()));
    }
    Ok(pw1)
}

/// Set file permissions to 0600 on Unix.
fn set_file_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Set directory permissions to 0700 on Unix.
fn set_dir_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
