use std::io::Write;

use crate::cli;
use crate::crypto;
use crate::error::{Error, Result};
use crate::export;
use crate::export::transport;
use crate::store::queries;

/// Run the `dump` command: export the entire store to a file.
pub fn run(
    path: &str,
    encrypt: bool,
    encryption_method: &str,
    recipients: &[String],
    password: Option<&str>,
    key_file: Option<&str>,
) -> Result<()> {
    let conn = cli::require_store()?;
    let aes_key = cli::load_encryption_key(&conn, key_file)?;

    // Load all saves (decrypting if the store is encrypted).
    let all_saves = queries::get_all_saves(&conn, aes_key.as_ref())?;

    // Build the dump envelope.
    let dump_saves: Vec<export::DumpSave> = all_saves
        .iter()
        .map(|(save, entries)| export::build_dump_save(save, entries))
        .collect();
    let dump = export::build_dump(dump_saves);
    let json = export::dump_to_json(&dump)?;

    // Optionally apply transport encryption.
    let data = if encrypt {
        match encryption_method {
            "password" => {
                let pw = crypto::password::resolve_password(password)?;
                transport::encrypt_password(json.as_bytes(), &pw)?
            }
            _ => {
                let recips = if !recipients.is_empty() {
                    recipients.to_vec()
                } else {
                    let mode_str =
                        queries::get_config(&conn, "encryption_mode")?.unwrap_or_default();
                    if mode_str == "gpg" {
                        let db_key_path = queries::get_config(&conn, "key_file")?;
                        let env_key_path = std::env::var("ENVSTASH_KEY_FILE").ok();
                        let key_path = crypto::resolve_key_file(
                            key_file.map(std::path::Path::new),
                            env_key_path.as_deref(),
                            db_key_path.as_deref(),
                        )
                        .unwrap_or_else(|| cli::store_dir().join("key.gpg"));
                        crypto::gpg::key_recipients(&key_path)?
                    } else {
                        return Err(Error::NoGpgRecipient);
                    }
                };
                if recips.is_empty() {
                    return Err(Error::NoGpgRecipient);
                }
                transport::encrypt_gpg(json.as_bytes(), &recips)?
            }
        }
    } else {
        json.into_bytes()
    };

    write_dump_file(path, &data)?;

    println!("Dumped {} saves to {path}", dump.saves.len());

    Ok(())
}

/// Write dump data to a file with restrictive permissions (0600 on Unix).
fn write_dump_file(path: &str, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::export;
    use crate::export::transport;
    use crate::store::queries;
    use crate::test_helpers::{sample_entries, test_conn};

    #[test]
    fn dump_and_load_round_trip() {
        let conn = test_conn();
        let entries = sample_entries();
        queries::insert_save(
            &conn,
            "/proj1",
            ".env",
            "main",
            "a1",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            None,
        )
        .unwrap();
        queries::insert_save(
            &conn,
            "/proj2",
            "apps/.env",
            "dev",
            "a2",
            "2024-01-02T00:00:00Z",
            "h2",
            &entries,
            None,
        )
        .unwrap();

        // Dump.
        let all = queries::get_all_saves(&conn, None).unwrap();
        let dump_saves: Vec<export::DumpSave> = all
            .iter()
            .map(|(s, e)| export::build_dump_save(s, e))
            .collect();
        let dump = export::build_dump(dump_saves);
        let json = export::dump_to_json(&dump).unwrap();

        // Load into a new store.
        let conn2 = test_conn();
        let parsed = export::dump_from_json(&json).unwrap();
        let (inserted, skipped) = queries::insert_all_saves(&conn2, &parsed.saves, None).unwrap();
        assert_eq!(inserted, 2);
        assert_eq!(skipped, 0);

        // Verify content.
        let all2 = queries::get_all_saves(&conn2, None).unwrap();
        assert_eq!(all2.len(), 2);
        assert_eq!(all2[0].0.project_path, "/proj1");
        assert_eq!(all2[1].0.project_path, "/proj2");
        assert_eq!(all2[0].1, entries);
    }

    #[test]
    fn dump_empty_store() {
        let conn = test_conn();
        let all = queries::get_all_saves(&conn, None).unwrap();
        let dump = export::build_dump(
            all.iter()
                .map(|(s, e)| export::build_dump_save(s, e))
                .collect(),
        );
        let json = export::dump_to_json(&dump).unwrap();

        let conn2 = test_conn();
        let parsed = export::dump_from_json(&json).unwrap();
        let (inserted, skipped) = queries::insert_all_saves(&conn2, &parsed.saves, None).unwrap();
        assert_eq!(inserted, 0);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn dump_with_password_encryption_round_trip() {
        let conn = test_conn();
        let entries = sample_entries();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "a1",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            None,
        )
        .unwrap();

        // Dump + encrypt.
        let all = queries::get_all_saves(&conn, None).unwrap();
        let dump_saves: Vec<export::DumpSave> = all
            .iter()
            .map(|(s, e)| export::build_dump_save(s, e))
            .collect();
        let dump = export::build_dump(dump_saves);
        let json = export::dump_to_json(&dump).unwrap();
        let encrypted = transport::encrypt_password(json.as_bytes(), "test-pw").unwrap();

        // Decrypt + load.
        let decrypted = transport::decrypt_auto(&encrypted, Some("test-pw")).unwrap();
        let text = String::from_utf8(decrypted).unwrap();
        let parsed = export::dump_from_json(&text).unwrap();
        let conn2 = test_conn();
        let (inserted, _) = queries::insert_all_saves(&conn2, &parsed.saves, None).unwrap();
        assert_eq!(inserted, 1);

        let loaded = queries::get_all_saves(&conn2, None).unwrap();
        assert_eq!(loaded[0].1, entries);
    }

    #[test]
    fn dump_load_idempotent() {
        let conn = test_conn();
        let entries = sample_entries();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "a1",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            None,
        )
        .unwrap();

        let all = queries::get_all_saves(&conn, None).unwrap();
        let dump_saves: Vec<export::DumpSave> = all
            .iter()
            .map(|(s, e)| export::build_dump_save(s, e))
            .collect();
        let dump = export::build_dump(dump_saves);
        let json = export::dump_to_json(&dump).unwrap();

        // Load twice into the same store.
        let parsed = export::dump_from_json(&json).unwrap();
        let (i1, s1) = queries::insert_all_saves(&conn, &parsed.saves, None).unwrap();
        assert_eq!(i1, 0);
        assert_eq!(s1, 1);

        let parsed2 = export::dump_from_json(&json).unwrap();
        let (i2, s2) = queries::insert_all_saves(&conn, &parsed2.saves, None).unwrap();
        assert_eq!(i2, 0);
        assert_eq!(s2, 1);

        // Still only 1 save.
        let all = queries::get_all_saves(&conn, None).unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn dump_file_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let dump_path = dir.path().join("dump.json");
        let data = b"test dump data";

        super::write_dump_file(dump_path.to_str().unwrap(), data).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&dump_path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "Dump file should have mode 0600");
        }

        let contents = std::fs::read(&dump_path).unwrap();
        assert_eq!(contents, data);
    }
}
