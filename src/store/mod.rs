pub mod queries;
pub mod schema;

use std::path::Path;

use rusqlite::Connection;

use crate::error::{Error, Result};

/// Open (or create) the SQLite store at the given path.
pub fn open(path: &Path) -> Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    schema::migrate(&mut conn)?;
    Ok(conn)
}

/// Open an in-memory SQLite store (for tests).
pub fn open_memory() -> Result<Connection> {
    let mut conn = Connection::open_in_memory()?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    schema::migrate(&mut conn)?;
    Ok(conn)
}

/// Initialize a new store: create tables and write initial config.
pub fn init(conn: &Connection, encryption_mode: &str) -> Result<()> {
    // Check if already initialized.
    if is_initialized(conn)? {
        return Err(Error::StoreAlreadyInitialized);
    }

    queries::set_config(conn, "version", "1")?;
    queries::set_config(conn, "encryption_mode", encryption_mode)?;
    Ok(())
}

/// Check if the store has been initialized.
pub fn is_initialized(conn: &Connection) -> Result<bool> {
    // Check if the config table has a version key.
    match queries::get_config(conn, "version") {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        // If the table doesn't exist at all, that's also "not initialized".
        Err(Error::Database(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{sample_entries, test_conn};
    use crate::types::EnvEntry;

    // -----------------------------------------------------------------------
    // Init / Config
    // -----------------------------------------------------------------------

    #[test]
    fn init_and_check() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        schema::migrate(&mut conn).unwrap();
        assert!(!is_initialized(&conn).unwrap());
        init(&conn, "none").unwrap();
        assert!(is_initialized(&conn).unwrap());
    }

    #[test]
    fn init_twice_fails() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        schema::migrate(&mut conn).unwrap();
        init(&conn, "none").unwrap();
        let err = init(&conn, "none").unwrap_err();
        assert!(err.to_string().contains("already initialized"));
    }

    #[test]
    fn config_round_trip() {
        let conn = test_conn();
        queries::set_config(&conn, "foo", "bar").unwrap();
        assert_eq!(
            queries::get_config(&conn, "foo").unwrap(),
            Some("bar".to_string())
        );
    }

    #[test]
    fn config_update() {
        let conn = test_conn();
        queries::set_config(&conn, "foo", "bar").unwrap();
        queries::set_config(&conn, "foo", "baz").unwrap();
        assert_eq!(
            queries::get_config(&conn, "foo").unwrap(),
            Some("baz".to_string())
        );
    }

    #[test]
    fn config_missing_key() {
        let conn = test_conn();
        assert_eq!(queries::get_config(&conn, "nope").unwrap(), None);
    }

    // -----------------------------------------------------------------------
    // Insert + List saves
    // -----------------------------------------------------------------------

    #[test]
    fn insert_and_list() {
        let conn = test_conn();
        let entries = sample_entries();
        let id = queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc123",
            "2024-06-17T12:00:00Z",
            "hash1",
            &entries,
            None,
        )
        .unwrap();
        assert!(id > 0);

        let saves = queries::list_saves(&conn, "/proj", Some("main"), None, 10, None).unwrap();
        assert_eq!(saves.len(), 1);
        assert_eq!(saves[0].file_path, ".env");
        assert_eq!(saves[0].content_hash, "hash1");
    }

    #[test]
    fn list_filters_by_branch() {
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
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "dev",
            "a2",
            "2024-01-02T00:00:00Z",
            "h2",
            &entries,
            None,
        )
        .unwrap();

        let main_saves = queries::list_saves(&conn, "/proj", Some("main"), None, 10, None).unwrap();
        assert_eq!(main_saves.len(), 1);
        assert_eq!(main_saves[0].branch, "main");

        let all_saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert_eq!(all_saves.len(), 2);
    }

    #[test]
    fn list_filters_by_commit() {
        let conn = test_conn();
        let entries = sample_entries();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "commit1",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            None,
        )
        .unwrap();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "commit2",
            "2024-01-02T00:00:00Z",
            "h2",
            &entries,
            None,
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", None, Some("commit1"), 10, None).unwrap();
        assert_eq!(saves.len(), 1);
        assert_eq!(saves[0].commit_hash, "commit1");
    }

    #[test]
    fn list_respects_max() {
        let conn = test_conn();
        let entries = sample_entries();
        for i in 0..10 {
            queries::insert_save(
                &conn,
                "/proj",
                ".env",
                "main",
                &format!("c{i}"),
                &format!("2024-01-{:02}T00:00:00Z", i + 1),
                &format!("h{i}"),
                &entries,
                None,
            )
            .unwrap();
        }

        let saves = queries::list_saves(&conn, "/proj", None, None, 3, None).unwrap();
        assert_eq!(saves.len(), 3);
    }

    #[test]
    fn list_filter_by_filename() {
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
        queries::insert_save(
            &conn,
            "/proj",
            ".db-env",
            "main",
            "a2",
            "2024-01-02T00:00:00Z",
            "h2",
            &entries,
            None,
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", None, None, 10, Some("*.env")).unwrap();
        assert_eq!(saves.len(), 1);
        assert_eq!(saves[0].file_path, ".env");
    }

    #[test]
    fn list_ordered_newest_first() {
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
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "a2",
            "2024-01-03T00:00:00Z",
            "h2",
            &entries,
            None,
        )
        .unwrap();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "a3",
            "2024-01-02T00:00:00Z",
            "h3",
            &entries,
            None,
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert_eq!(saves[0].timestamp, "2024-01-03T00:00:00Z");
        assert_eq!(saves[1].timestamp, "2024-01-02T00:00:00Z");
        assert_eq!(saves[2].timestamp, "2024-01-01T00:00:00Z");
    }

    // -----------------------------------------------------------------------
    // Get entries
    // -----------------------------------------------------------------------

    #[test]
    fn get_entries_round_trip() {
        let conn = test_conn();
        let entries = sample_entries();
        let id = queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            None,
        )
        .unwrap();

        let loaded = queries::get_save_entries(&conn, id, None).unwrap();
        assert_eq!(loaded, entries);
    }

    #[test]
    fn get_entries_nonexistent_save() {
        let conn = test_conn();
        let loaded = queries::get_save_entries(&conn, 9999, None).unwrap();
        assert!(loaded.is_empty());
    }

    // -----------------------------------------------------------------------
    // Hash lookup
    // -----------------------------------------------------------------------

    #[test]
    fn find_by_exact_hash() {
        let conn = test_conn();
        let entries = sample_entries();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "deadbeef1234",
            &entries,
            None,
        )
        .unwrap();

        let found = queries::get_save_by_hash(&conn, "/proj", "deadbeef1234").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().content_hash, "deadbeef1234");
    }

    #[test]
    fn find_by_prefix_hash() {
        let conn = test_conn();
        let entries = sample_entries();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "deadbeef1234",
            &entries,
            None,
        )
        .unwrap();

        let found = queries::get_save_by_hash(&conn, "/proj", "dead").unwrap();
        assert!(found.is_some());
    }

    #[test]
    fn find_by_hash_not_found() {
        let conn = test_conn();
        let found = queries::get_save_by_hash(&conn, "/proj", "nonexistent").unwrap();
        assert!(found.is_none());
    }

    // -----------------------------------------------------------------------
    // History (cross-branch)
    // -----------------------------------------------------------------------

    #[test]
    fn list_saves_history_excludes_branch() {
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
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "dev",
            "a2",
            "2024-01-02T00:00:00Z",
            "h2",
            &entries,
            None,
        )
        .unwrap();

        let history = queries::list_saves_history(&conn, "/proj", "dev", 10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].branch, "main");
    }

    // -----------------------------------------------------------------------
    // Delete
    // -----------------------------------------------------------------------

    #[test]
    fn delete_single_save() {
        let conn = test_conn();
        let entries = sample_entries();
        let id = queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            None,
        )
        .unwrap();

        queries::delete_save(&conn, id).unwrap();
        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert!(saves.is_empty());

        // Entries should also be gone.
        let loaded = queries::get_save_entries(&conn, id, None).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn delete_nonexistent_save_errors() {
        let conn = test_conn();
        let err = queries::delete_save(&conn, 9999).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn delete_by_branch() {
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
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "a2",
            "2024-01-02T00:00:00Z",
            "h2",
            &entries,
            None,
        )
        .unwrap();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "dev",
            "a3",
            "2024-01-03T00:00:00Z",
            "h3",
            &entries,
            None,
        )
        .unwrap();

        let count = queries::delete_saves_by_branch(&conn, "/proj", "main").unwrap();
        assert_eq!(count, 2);

        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert_eq!(saves.len(), 1);
        assert_eq!(saves[0].branch, "dev");
    }

    #[test]
    fn delete_by_project() {
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
        queries::insert_save(
            &conn,
            "/other",
            ".env",
            "main",
            "a2",
            "2024-01-02T00:00:00Z",
            "h2",
            &entries,
            None,
        )
        .unwrap();

        let count = queries::delete_saves_by_project(&conn, "/proj").unwrap();
        assert_eq!(count, 1);

        let proj_saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert!(proj_saves.is_empty());

        // Other project unaffected.
        let other_saves = queries::list_saves(&conn, "/other", None, None, 10, None).unwrap();
        assert_eq!(other_saves.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Projects
    // -----------------------------------------------------------------------

    #[test]
    fn list_projects_summary() {
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
            "/proj1",
            ".env",
            "main",
            "a2",
            "2024-01-03T00:00:00Z",
            "h2",
            &entries,
            None,
        )
        .unwrap();
        queries::insert_save(
            &conn,
            "/proj2",
            ".env",
            "main",
            "a3",
            "2024-01-02T00:00:00Z",
            "h3",
            &entries,
            None,
        )
        .unwrap();

        let projects = queries::list_projects(&conn).unwrap();
        assert_eq!(projects.len(), 2);
        // Ordered by last_save DESC.
        assert_eq!(projects[0].project_path, "/proj1");
        assert_eq!(projects[0].save_count, 2);
        assert_eq!(projects[0].last_save, "2024-01-03T00:00:00Z");
        assert_eq!(projects[1].project_path, "/proj2");
        assert_eq!(projects[1].save_count, 1);
    }

    #[test]
    fn list_projects_empty() {
        let conn = test_conn();
        let projects = queries::list_projects(&conn).unwrap();
        assert!(projects.is_empty());
    }

    // -----------------------------------------------------------------------
    // Get all saves (dump)
    // -----------------------------------------------------------------------

    #[test]
    fn get_all_saves_round_trip() {
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
            ".env",
            "dev",
            "a2",
            "2024-01-02T00:00:00Z",
            "h2",
            &entries,
            None,
        )
        .unwrap();

        let all = queries::get_all_saves(&conn, None).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].1, entries);
        assert_eq!(all[1].1, entries);
    }

    // -----------------------------------------------------------------------
    // Encryption integration
    // -----------------------------------------------------------------------

    #[test]
    fn encrypted_round_trip() {
        let conn = test_conn();
        let key = crate::crypto::aes::generate_key();
        let entries = sample_entries();
        let id = queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            Some(&key),
        )
        .unwrap();

        let loaded = queries::get_save_entries(&conn, id, Some(&key)).unwrap();
        assert_eq!(loaded, entries);
    }

    #[test]
    fn encrypted_values_not_plaintext_in_db() {
        let conn = test_conn();
        let key = crate::crypto::aes::generate_key();
        let entries = vec![EnvEntry {
            comment: Some("secret comment".to_string()),
            key: "SECRET_KEY".to_string(),
            value: "super_secret_value".to_string(),
        }];
        let id = queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            Some(&key),
        )
        .unwrap();

        // Read raw bytes from the database.
        let mut stmt = conn
            .prepare("SELECT value, comment FROM entries WHERE save_id = ?1")
            .unwrap();
        let raw: Vec<(Vec<u8>, Vec<u8>)> = stmt
            .query_map(rusqlite::params![id], |row| {
                let val = queries::tests_read_bytes(row, 0)?;
                let com = queries::tests_read_bytes(row, 1)?;
                Ok((val, com))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert_eq!(raw.len(), 1);
        // Raw value should NOT contain the plaintext.
        let raw_value_str = String::from_utf8_lossy(&raw[0].0);
        assert!(
            !raw_value_str.contains("super_secret_value"),
            "Plaintext value found in encrypted DB"
        );
        let raw_comment_str = String::from_utf8_lossy(&raw[0].1);
        assert!(
            !raw_comment_str.contains("secret comment"),
            "Plaintext comment found in encrypted DB"
        );
    }

    #[test]
    fn encrypted_wrong_key_fails() {
        let conn = test_conn();
        let key1 = crate::crypto::aes::generate_key();
        let key2 = crate::crypto::aes::generate_key();
        let entries = sample_entries();
        let id = queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            Some(&key1),
        )
        .unwrap();

        let result = queries::get_save_entries(&conn, id, Some(&key2));
        assert!(result.is_err());
    }

    #[test]
    fn hmac_computed_on_encrypted_insert() {
        let conn = test_conn();
        let key = crate::crypto::aes::generate_key();
        let entries = sample_entries();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            Some(&key),
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert!(
            !saves[0].hmac.is_empty(),
            "HMAC should be set for encrypted saves"
        );
        assert_eq!(
            saves[0].hmac.len(),
            64,
            "HMAC should be 64 hex chars (SHA-256)"
        );
    }

    #[test]
    fn hmac_empty_for_plaintext_insert() {
        let conn = test_conn();
        let entries = sample_entries();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            None,
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert!(
            saves[0].hmac.is_empty(),
            "HMAC should be empty for plaintext saves"
        );
    }

    #[test]
    fn hmac_verification_passes() {
        let conn = test_conn();
        let key = crate::crypto::aes::generate_key();
        let entries = sample_entries();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            Some(&key),
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        queries::verify_save_hmac(&saves[0], &key).unwrap();
    }

    #[test]
    fn hmac_tamper_detection() {
        let conn = test_conn();
        let key = crate::crypto::aes::generate_key();
        let entries = sample_entries();
        let id = queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            Some(&key),
        )
        .unwrap();

        // Tamper with metadata.
        conn.execute(
            "UPDATE saves SET file_path = '.env-tampered' WHERE id = ?1",
            rusqlite::params![id],
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        let result = queries::verify_save_hmac(&saves[0], &key);
        assert!(result.is_err(), "HMAC should fail after tampering");
        assert!(
            result.unwrap_err().to_string().contains("tampered"),
            "Error should mention tampering"
        );
    }

    #[test]
    fn hmac_wrong_key_fails() {
        let conn = test_conn();
        let key1 = crate::crypto::aes::generate_key();
        let key2 = crate::crypto::aes::generate_key();
        let entries = sample_entries();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            Some(&key1),
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        let result = queries::verify_save_hmac(&saves[0], &key2);
        assert!(result.is_err(), "HMAC should fail with wrong key");
    }

    #[test]
    fn metadata_operations_work_without_key() {
        let conn = test_conn();
        let key = crate::crypto::aes::generate_key();
        let entries = sample_entries();
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            Some(&key),
        )
        .unwrap();

        // Metadata-only operations work fine without the key.
        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert_eq!(saves.len(), 1);
        assert_eq!(saves[0].file_path, ".env");

        let projects = queries::list_projects(&conn).unwrap();
        assert_eq!(projects.len(), 1);

        // Delete also works without key.
        queries::delete_save(&conn, saves[0].id).unwrap();
        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert!(saves.is_empty());
    }

    #[test]
    fn encrypted_get_all_saves_round_trip() {
        let conn = test_conn();
        let key = crate::crypto::aes::generate_key();
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
            Some(&key),
        )
        .unwrap();
        queries::insert_save(
            &conn,
            "/proj2",
            ".env",
            "dev",
            "a2",
            "2024-01-02T00:00:00Z",
            "h2",
            &entries,
            Some(&key),
        )
        .unwrap();

        let all = queries::get_all_saves(&conn, Some(&key)).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].1, entries);
        assert_eq!(all[1].1, entries);
    }

    #[test]
    fn encrypted_empty_values_round_trip() {
        let conn = test_conn();
        let key = crate::crypto::aes::generate_key();
        let entries = vec![EnvEntry {
            comment: None,
            key: "EMPTY".to_string(),
            value: String::new(),
        }];
        let id = queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-01-01T00:00:00Z",
            "h1",
            &entries,
            Some(&key),
        )
        .unwrap();

        let loaded = queries::get_save_entries(&conn, id, Some(&key)).unwrap();
        assert_eq!(loaded, entries);
    }
}
