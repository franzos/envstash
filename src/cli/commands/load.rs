use crate::cli;
use crate::error::{Error, Result};
use crate::export;
use crate::export::transport;
use crate::store::queries;

/// Run the `load` command: import a dump file into the store.
pub fn run(path: &str, password: Option<&str>, key_file: Option<&str>) -> Result<()> {
    let conn = cli::require_store()?;
    let aes_key = cli::load_encryption_key(&conn, key_file)?;

    // Read the file.
    let data =
        std::fs::read(path).map_err(|e| Error::Other(format!("failed to read {path}: {e}")))?;

    if data.is_empty() {
        return Err(Error::Other("empty dump file".to_string()));
    }

    // Auto-detect transport encryption and decrypt if needed.
    let decrypted = transport::decrypt_auto(&data, password)?;

    let text = String::from_utf8(decrypted)
        .map_err(|e| Error::Other(format!("invalid UTF-8 in dump file: {e}")))?;

    // Parse the dump envelope.
    let dump = export::dump_from_json(&text)?;

    // Insert all saves, skipping duplicates.
    let (inserted, skipped) = queries::insert_all_saves(&conn, &dump.saves, aes_key.as_ref())?;

    println!("Loaded {inserted} saves ({skipped} skipped as duplicates)");

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::export;
    use crate::export::transport;
    use crate::store::queries;
    use crate::test_helpers::{sample_entries, test_conn};
    use crate::types::EnvEntry;

    #[test]
    fn load_from_dump_json() {
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

        // Create dump JSON.
        let all = queries::get_all_saves(&conn, None).unwrap();
        let dump_saves: Vec<export::DumpSave> = all
            .iter()
            .map(|(s, e)| export::build_dump_save(s, e))
            .collect();
        let dump = export::build_dump(dump_saves);
        let json = export::dump_to_json(&dump).unwrap();

        // Load into fresh store.
        let conn2 = test_conn();
        let parsed = export::dump_from_json(&json).unwrap();
        let (inserted, skipped) = queries::insert_all_saves(&conn2, &parsed.saves, None).unwrap();
        assert_eq!(inserted, 1);
        assert_eq!(skipped, 0);

        let loaded = queries::get_all_saves(&conn2, None).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1, entries);
    }

    #[test]
    fn load_skips_duplicates() {
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

        // Build dump.
        let all = queries::get_all_saves(&conn, None).unwrap();
        let dump_saves: Vec<export::DumpSave> = all
            .iter()
            .map(|(s, e)| export::build_dump_save(s, e))
            .collect();
        let dump = export::build_dump(dump_saves);
        let json = export::dump_to_json(&dump).unwrap();

        // Load into the same store.
        let parsed = export::dump_from_json(&json).unwrap();
        let (inserted, skipped) = queries::insert_all_saves(&conn, &parsed.saves, None).unwrap();
        assert_eq!(inserted, 0);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn load_password_encrypted_dump() {
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
        let encrypted = transport::encrypt_password(json.as_bytes(), "dump-pw").unwrap();

        // Decrypt + load.
        let decrypted = transport::decrypt_auto(&encrypted, Some("dump-pw")).unwrap();
        let text = String::from_utf8(decrypted).unwrap();
        let parsed = export::dump_from_json(&text).unwrap();

        let conn2 = test_conn();
        let (inserted, _) = queries::insert_all_saves(&conn2, &parsed.saves, None).unwrap();
        assert_eq!(inserted, 1);

        let loaded = queries::get_all_saves(&conn2, None).unwrap();
        assert_eq!(loaded[0].1, entries);
    }

    #[test]
    fn load_encrypted_dump_into_encrypted_store() {
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

        // Dump (plaintext store).
        let all = queries::get_all_saves(&conn, None).unwrap();
        let dump_saves: Vec<export::DumpSave> = all
            .iter()
            .map(|(s, e)| export::build_dump_save(s, e))
            .collect();
        let dump = export::build_dump(dump_saves);
        let json = export::dump_to_json(&dump).unwrap();

        // Load into encrypted store.
        let conn2 = test_conn();
        let key = crate::crypto::aes::generate_key();
        let parsed = export::dump_from_json(&json).unwrap();
        let (inserted, _) = queries::insert_all_saves(&conn2, &parsed.saves, Some(&key)).unwrap();
        assert_eq!(inserted, 1);

        // Verify decryption works.
        let loaded = queries::get_all_saves(&conn2, Some(&key)).unwrap();
        assert_eq!(loaded[0].1, entries);
    }

    #[test]
    fn load_from_encrypted_store_dump_into_plaintext() {
        let conn = test_conn();
        let key = crate::crypto::aes::generate_key();
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
            Some(&key),
        )
        .unwrap();

        // Dump (encrypted store, decrypts on read).
        let all = queries::get_all_saves(&conn, Some(&key)).unwrap();
        let dump_saves: Vec<export::DumpSave> = all
            .iter()
            .map(|(s, e)| export::build_dump_save(s, e))
            .collect();
        let dump = export::build_dump(dump_saves);
        let json = export::dump_to_json(&dump).unwrap();

        // Load into plaintext store.
        let conn2 = test_conn();
        let parsed = export::dump_from_json(&json).unwrap();
        let (inserted, _) = queries::insert_all_saves(&conn2, &parsed.saves, None).unwrap();
        assert_eq!(inserted, 1);

        let loaded = queries::get_all_saves(&conn2, None).unwrap();
        assert_eq!(loaded[0].1, entries);
    }

    #[test]
    fn load_multiple_projects_and_branches() {
        let conn = test_conn();
        let entries1 = vec![EnvEntry {
            comment: None,
            key: "A".to_string(),
            value: "1".to_string(),
        }];
        let entries2 = vec![EnvEntry {
            comment: None,
            key: "B".to_string(),
            value: "2".to_string(),
        }];
        let entries3 = vec![EnvEntry {
            comment: Some("Third".to_string()),
            key: "C".to_string(),
            value: "3".to_string(),
        }];

        queries::insert_save(
            &conn,
            "/proj1",
            ".env",
            "main",
            "a1",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries1,
            None,
        )
        .unwrap();
        queries::insert_save(
            &conn,
            "/proj1",
            ".env",
            "dev",
            "a2",
            "2024-01-02T00:00:00Z",
            "h2",
            &entries2,
            None,
        )
        .unwrap();
        queries::insert_save(
            &conn,
            "/proj2",
            "apps/.env",
            "main",
            "a3",
            "2024-01-03T00:00:00Z",
            "h3",
            &entries3,
            None,
        )
        .unwrap();

        // Dump.
        let all = queries::get_all_saves(&conn, None).unwrap();
        assert_eq!(all.len(), 3);
        let dump_saves: Vec<export::DumpSave> = all
            .iter()
            .map(|(s, e)| export::build_dump_save(s, e))
            .collect();
        let dump = export::build_dump(dump_saves);
        let json = export::dump_to_json(&dump).unwrap();

        // Load into fresh store.
        let conn2 = test_conn();
        let parsed = export::dump_from_json(&json).unwrap();
        let (inserted, skipped) = queries::insert_all_saves(&conn2, &parsed.saves, None).unwrap();
        assert_eq!(inserted, 3);
        assert_eq!(skipped, 0);

        // Verify all data.
        let loaded = queries::get_all_saves(&conn2, None).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].0.project_path, "/proj1");
        assert_eq!(loaded[0].1, entries1);
        assert_eq!(loaded[1].0.project_path, "/proj1");
        assert_eq!(loaded[1].0.branch, "dev");
        assert_eq!(loaded[1].1, entries2);
        assert_eq!(loaded[2].0.project_path, "/proj2");
        assert_eq!(loaded[2].1, entries3);
    }
}
