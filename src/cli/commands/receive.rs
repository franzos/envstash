use std::io::Read;
use std::path::Path;

use colored::Colorize;

use crate::cli;
use crate::error::Result;
use crate::export;
use crate::export::transport;
use crate::parser;
use crate::store::queries;

use super::transport as remote;

/// Run the `receive` command: read an exported envelope (possibly encrypted)
/// and insert into the store.
pub fn run(
    cwd: &Path,
    file: Option<&str>,
    key_file: Option<&str>,
    transport_password: Option<&str>,
    from: Option<&str>,
) -> Result<()> {
    let conn = cli::require_store()?;
    let aes_key = cli::load_encryption_key(&conn, key_file)?;
    let (project_path, _git_ctx) = cli::resolve_project(cwd)?;

    // Read raw bytes from transport backend, file, or stdin.
    let raw_bytes = if let Some(source) = from {
        remote::fetch(source)?
    } else {
        match file {
            Some(path) => std::fs::read(path)?,
            None => {
                let mut buf = Vec::new();
                std::io::stdin().read_to_end(&mut buf)?;
                buf
            }
        }
    };

    if raw_bytes.is_empty() {
        return Err(crate::error::Error::Other(
            "empty input: nothing to import".to_string(),
        ));
    }

    // Detect transport encryption and decrypt if needed.
    let decrypted = transport::decrypt_auto(&raw_bytes, transport_password)?;

    // Convert decrypted bytes to string for parsing.
    let input = std::str::from_utf8(&decrypted)
        .map_err(|e| crate::error::Error::Other(format!("invalid UTF-8 in import data: {e}")))?;

    // Auto-detect format and parse.
    let envelope = export::auto_detect(input)?;

    // Reject file paths containing path traversal components.
    if super::apply::has_path_traversal(&envelope.file) {
        return Err(crate::error::Error::Other(format!(
            "Refusing to import: file path '{}' contains path traversal components",
            envelope.file
        )));
    }

    // Convert entries and compute content hash for verification.
    let entries = export::to_env_entries(&envelope);
    let computed_hash = parser::content_hash(&entries);

    // Warn if content hash doesn't match (but still import).
    if !envelope.content_hash.is_empty() && computed_hash != envelope.content_hash {
        eprintln!(
            "{} content hash mismatch (expected {}, computed {})",
            "warning:".yellow(),
            envelope.content_hash,
            computed_hash
        );
    }

    // Insert into the store, preserving message.
    queries::insert_save_with_message(
        &conn,
        &project_path,
        &envelope.file,
        &envelope.branch,
        &envelope.commit,
        &envelope.timestamp,
        &computed_hash,
        &entries,
        aes_key.as_ref(),
        envelope.message.as_deref(),
    )?;

    println!(
        "{} {} ({} variables, branch: {}, timestamp: {})",
        "Imported".green().bold(),
        envelope.file,
        entries.len(),
        if envelope.branch.is_empty() {
            "(none)"
        } else {
            &envelope.branch
        },
        envelope.timestamp,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::export::transport;
    use crate::export::{self, ExportEntry, ExportEnvelope};
    use crate::store::queries;
    use crate::test_helpers::{sample_entries, test_conn};

    fn sample_envelope() -> ExportEnvelope {
        ExportEnvelope {
            version: 1,
            file: ".env".to_string(),
            branch: "main".to_string(),
            commit: "abc123".to_string(),
            timestamp: "2024-06-17T12:00:00Z".to_string(),
            content_hash: "will_be_recomputed".to_string(),
            message: None,
            entries: vec![
                ExportEntry {
                    key: "DB_HOST".to_string(),
                    value: "localhost".to_string(),
                    comment: Some("Host config".to_string()),
                },
                ExportEntry {
                    key: "DB_PORT".to_string(),
                    value: "5432".to_string(),
                    comment: None,
                },
            ],
        }
    }

    #[test]
    fn import_json_envelope() {
        let conn = test_conn();
        let envelope = sample_envelope();
        let json = export::to_json(&envelope).unwrap();

        let parsed = export::auto_detect(&json).unwrap();
        let entries = export::to_env_entries(&parsed);
        let hash = crate::parser::content_hash(&entries);

        queries::insert_save(
            &conn,
            "/proj",
            &parsed.file,
            &parsed.branch,
            &parsed.commit,
            &parsed.timestamp,
            &hash,
            &entries,
            None,
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert_eq!(saves.len(), 1);
        assert_eq!(saves[0].file_path, ".env");
        assert_eq!(saves[0].branch, "main");

        let loaded = queries::get_save_entries(&conn, saves[0].id, None).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].key, "DB_HOST");
    }

    #[test]
    fn import_text_envelope() {
        let conn = test_conn();
        let envelope = sample_envelope();
        let text = export::to_text(&envelope);

        let parsed = export::auto_detect(&text).unwrap();
        let entries = export::to_env_entries(&parsed);
        let hash = crate::parser::content_hash(&entries);

        queries::insert_save(
            &conn,
            "/proj",
            &parsed.file,
            &parsed.branch,
            &parsed.commit,
            &parsed.timestamp,
            &hash,
            &entries,
            None,
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert_eq!(saves.len(), 1);
        assert_eq!(saves[0].branch, "main");
    }

    #[test]
    fn import_into_encrypted_store() {
        let conn = test_conn();
        let key = crate::crypto::aes::generate_key();
        let envelope = sample_envelope();
        let json = export::to_json(&envelope).unwrap();

        let parsed = export::auto_detect(&json).unwrap();
        let entries = export::to_env_entries(&parsed);
        let hash = crate::parser::content_hash(&entries);

        queries::insert_save(
            &conn,
            "/proj",
            &parsed.file,
            &parsed.branch,
            &parsed.commit,
            &parsed.timestamp,
            &hash,
            &entries,
            Some(&key),
        )
        .unwrap();

        // Verify we can decrypt.
        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        let loaded = queries::get_save_entries(&conn, saves[0].id, Some(&key)).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].key, "DB_HOST");
        assert_eq!(loaded[0].value, "localhost");
    }

    #[test]
    fn pipe_simulation_json() {
        let conn = test_conn();
        let entries = sample_entries();

        // Save.
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-06-17T12:00:00Z",
            "h1",
            &entries,
            None,
        )
        .unwrap();

        // Share (simulate).
        let saves = queries::list_saves(&conn, "/proj", Some("main"), None, 1, None).unwrap();
        let loaded = queries::get_save_entries(&conn, saves[0].id, None).unwrap();
        let envelope = export::build_envelope(&saves[0], &loaded);
        let shared = export::to_json(&envelope).unwrap();

        // Import (simulate pipe: parse the shared output).
        let parsed = export::auto_detect(&shared).unwrap();
        let imported_entries = export::to_env_entries(&parsed);
        let hash = crate::parser::content_hash(&imported_entries);

        queries::insert_save(
            &conn,
            "/proj2",
            &parsed.file,
            &parsed.branch,
            &parsed.commit,
            &parsed.timestamp,
            &hash,
            &imported_entries,
            None,
        )
        .unwrap();

        // Verify.
        let proj2_saves = queries::list_saves(&conn, "/proj2", None, None, 10, None).unwrap();
        assert_eq!(proj2_saves.len(), 1);
        let proj2_entries = queries::get_save_entries(&conn, proj2_saves[0].id, None).unwrap();
        assert_eq!(proj2_entries, entries);
    }

    #[test]
    fn pipe_simulation_text() {
        let conn = test_conn();
        let entries = sample_entries();

        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "dev",
            "def",
            "2024-06-17T12:00:00Z",
            "h2",
            &entries,
            None,
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", Some("dev"), None, 1, None).unwrap();
        let loaded = queries::get_save_entries(&conn, saves[0].id, None).unwrap();
        let envelope = export::build_envelope(&saves[0], &loaded);
        let shared = export::to_text(&envelope);

        let parsed = export::auto_detect(&shared).unwrap();
        let imported_entries = export::to_env_entries(&parsed);
        let hash = crate::parser::content_hash(&imported_entries);

        queries::insert_save(
            &conn,
            "/proj2",
            &parsed.file,
            &parsed.branch,
            &parsed.commit,
            &parsed.timestamp,
            &hash,
            &imported_entries,
            None,
        )
        .unwrap();

        let proj2_saves = queries::list_saves(&conn, "/proj2", None, None, 10, None).unwrap();
        assert_eq!(proj2_saves.len(), 1);
        let proj2_entries = queries::get_save_entries(&conn, proj2_saves[0].id, None).unwrap();
        assert_eq!(proj2_entries, entries);
    }

    // ----- Transport encryption import tests -----

    #[test]
    fn import_auto_detects_plaintext() {
        let envelope = sample_envelope();
        let json = export::to_json(&envelope).unwrap();
        let raw_bytes = json.as_bytes();

        // detect should return None (plaintext).
        assert_eq!(
            transport::detect(raw_bytes),
            transport::TransportEncryption::None,
        );

        // decrypt_auto should return as-is.
        let decrypted = transport::decrypt_auto(raw_bytes, None).unwrap();
        assert_eq!(decrypted, raw_bytes);

        // Parse should work.
        let text = std::str::from_utf8(&decrypted).unwrap();
        let parsed = export::auto_detect(text).unwrap();
        assert_eq!(parsed.entries.len(), 2);
    }

    #[test]
    fn import_auto_detects_password_encrypted() {
        let envelope = sample_envelope();
        let json = export::to_json(&envelope).unwrap();
        let encrypted = transport::encrypt_password(json.as_bytes(), "import-pw").unwrap();

        // detect should return Password.
        assert_eq!(
            transport::detect(&encrypted),
            transport::TransportEncryption::Password,
        );

        // decrypt_auto with correct password should work.
        let decrypted = transport::decrypt_auto(&encrypted, Some("import-pw")).unwrap();
        let text = std::str::from_utf8(&decrypted).unwrap();
        let parsed = export::auto_detect(text).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.branch, "main");
    }

    #[test]
    fn import_password_encrypted_wrong_password_fails() {
        let envelope = sample_envelope();
        let json = export::to_json(&envelope).unwrap();
        let encrypted = transport::encrypt_password(json.as_bytes(), "correct").unwrap();

        let result = transport::decrypt_auto(&encrypted, Some("wrong"));
        assert!(result.is_err());
    }

    #[test]
    fn import_password_encrypted_no_password_fails() {
        let envelope = sample_envelope();
        let json = export::to_json(&envelope).unwrap();
        let encrypted = transport::encrypt_password(json.as_bytes(), "pw").unwrap();

        let result = transport::decrypt_auto(&encrypted, None);
        assert!(result.is_err());
    }

    #[test]
    fn full_encrypted_share_import_round_trip() {
        let conn = test_conn();
        let entries = sample_entries();

        // Save to store.
        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "main",
            "abc",
            "2024-06-17T12:00:00Z",
            "h1",
            &entries,
            None,
        )
        .unwrap();

        // Share with password encryption.
        let saves = queries::list_saves(&conn, "/proj", Some("main"), None, 1, None).unwrap();
        let loaded = queries::get_save_entries(&conn, saves[0].id, None).unwrap();
        let envelope = export::build_envelope(&saves[0], &loaded);
        let serialized = export::to_json(&envelope).unwrap();
        let encrypted = transport::encrypt_password(serialized.as_bytes(), "roundtrip-pw").unwrap();

        // Import: decrypt and parse.
        let decrypted = transport::decrypt_auto(&encrypted, Some("roundtrip-pw")).unwrap();
        let text = std::str::from_utf8(&decrypted).unwrap();
        let parsed = export::auto_detect(text).unwrap();
        let imported_entries = export::to_env_entries(&parsed);
        let hash = crate::parser::content_hash(&imported_entries);

        queries::insert_save(
            &conn,
            "/proj2",
            &parsed.file,
            &parsed.branch,
            &parsed.commit,
            &parsed.timestamp,
            &hash,
            &imported_entries,
            None,
        )
        .unwrap();

        // Verify round-trip.
        let proj2_saves = queries::list_saves(&conn, "/proj2", None, None, 10, None).unwrap();
        assert_eq!(proj2_saves.len(), 1);
        let proj2_entries = queries::get_save_entries(&conn, proj2_saves[0].id, None).unwrap();
        assert_eq!(proj2_entries, entries);
    }

    #[test]
    fn full_encrypted_text_format_round_trip() {
        let conn = test_conn();
        let entries = sample_entries();

        queries::insert_save(
            &conn,
            "/proj",
            ".env",
            "dev",
            "def",
            "2024-06-17T12:00:00Z",
            "h2",
            &entries,
            None,
        )
        .unwrap();

        // Share as text with password encryption.
        let saves = queries::list_saves(&conn, "/proj", Some("dev"), None, 1, None).unwrap();
        let loaded = queries::get_save_entries(&conn, saves[0].id, None).unwrap();
        let envelope = export::build_envelope(&saves[0], &loaded);
        let serialized = export::to_text(&envelope);
        let encrypted = transport::encrypt_password(serialized.as_bytes(), "text-rt").unwrap();

        // Import.
        let decrypted = transport::decrypt_auto(&encrypted, Some("text-rt")).unwrap();
        let text = std::str::from_utf8(&decrypted).unwrap();
        let parsed = export::auto_detect(text).unwrap();
        let imported_entries = export::to_env_entries(&parsed);
        let hash = crate::parser::content_hash(&imported_entries);

        queries::insert_save(
            &conn,
            "/proj2",
            &parsed.file,
            &parsed.branch,
            &parsed.commit,
            &parsed.timestamp,
            &hash,
            &imported_entries,
            None,
        )
        .unwrap();

        let proj2_saves = queries::list_saves(&conn, "/proj2", None, None, 10, None).unwrap();
        let proj2_entries = queries::get_save_entries(&conn, proj2_saves[0].id, None).unwrap();
        assert_eq!(proj2_entries, entries);
    }

    // ----- Path traversal rejection -----

    #[test]
    fn import_rejects_path_traversal() {
        use super::super::apply::has_path_traversal;

        assert!(has_path_traversal("../../.bashrc"));
        assert!(has_path_traversal("../secret"));
        assert!(has_path_traversal("apps/../../.bashrc"));
        assert!(!has_path_traversal(".env"));
        assert!(!has_path_traversal("apps/backend/.env"));
    }

    // ----- Import preserves message -----

    #[test]
    fn import_preserves_message_json() {
        let conn = test_conn();
        let mut envelope = sample_envelope();
        envelope.message = Some("important config".to_string());
        let json = export::to_json(&envelope).unwrap();

        let parsed = export::auto_detect(&json).unwrap();
        assert_eq!(parsed.message.as_deref(), Some("important config"));

        let entries = export::to_env_entries(&parsed);
        let hash = crate::parser::content_hash(&entries);

        queries::insert_save_with_message(
            &conn,
            "/proj",
            &parsed.file,
            &parsed.branch,
            &parsed.commit,
            &parsed.timestamp,
            &hash,
            &entries,
            None,
            parsed.message.as_deref(),
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert_eq!(saves[0].message.as_deref(), Some("important config"));
    }

    #[test]
    fn import_preserves_message_text() {
        let conn = test_conn();
        let mut envelope = sample_envelope();
        envelope.message = Some("text format message".to_string());
        let text = export::to_text(&envelope);

        let parsed = export::auto_detect(&text).unwrap();
        assert_eq!(parsed.message.as_deref(), Some("text format message"));

        let entries = export::to_env_entries(&parsed);
        let hash = crate::parser::content_hash(&entries);

        queries::insert_save_with_message(
            &conn,
            "/proj",
            &parsed.file,
            &parsed.branch,
            &parsed.commit,
            &parsed.timestamp,
            &hash,
            &entries,
            None,
            parsed.message.as_deref(),
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert_eq!(saves[0].message.as_deref(), Some("text format message"));
    }
}
