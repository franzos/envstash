pub mod transport;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::{EnvEntry, SaveMetadata};

/// Current export format version.
const FORMAT_VERSION: u32 = 1;

/// Text format header prefix.
const TEXT_HEADER_PREFIX: &str = "# envmgr export";

/// JSON envelope for a shared .env snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEnvelope {
    pub version: u32,
    pub file: String,
    pub branch: String,
    pub commit: String,
    pub timestamp: String,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub entries: Vec<ExportEntry>,
}

/// A single entry in the export envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub key: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl From<&EnvEntry> for ExportEntry {
    fn from(e: &EnvEntry) -> Self {
        Self {
            key: e.key.clone(),
            value: e.value.clone(),
            comment: e.comment.clone(),
        }
    }
}

impl From<&ExportEntry> for EnvEntry {
    fn from(e: &ExportEntry) -> Self {
        Self {
            key: e.key.clone(),
            value: e.value.clone(),
            comment: e.comment.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Dump format (all saves across all projects)
// ---------------------------------------------------------------------------

/// Envelope for a full store dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpEnvelope {
    pub version: u32,
    #[serde(rename = "type")]
    pub dump_type: String,
    pub saves: Vec<DumpSave>,
}

/// A single save within a dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpSave {
    pub project_path: String,
    pub file: String,
    pub branch: String,
    pub commit: String,
    pub timestamp: String,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub entries: Vec<ExportEntry>,
}

/// Build a dump save from save metadata and decrypted entries.
pub fn build_dump_save(save: &SaveMetadata, entries: &[EnvEntry]) -> DumpSave {
    DumpSave {
        project_path: save.project_path.clone(),
        file: save.file_path.clone(),
        branch: save.branch.clone(),
        commit: save.commit_hash.clone(),
        timestamp: save.timestamp.clone(),
        content_hash: save.content_hash.clone(),
        message: save.message.clone(),
        entries: entries.iter().map(ExportEntry::from).collect(),
    }
}

/// Build a dump envelope from a list of dump saves.
pub fn build_dump(saves: Vec<DumpSave>) -> DumpEnvelope {
    DumpEnvelope {
        version: FORMAT_VERSION,
        dump_type: "dump".to_string(),
        saves,
    }
}

/// Serialize a dump envelope to JSON.
pub fn dump_to_json(envelope: &DumpEnvelope) -> Result<String> {
    serde_json::to_string_pretty(envelope).map_err(Error::from)
}

/// Deserialize a dump envelope from JSON.
pub fn dump_from_json(input: &str) -> Result<DumpEnvelope> {
    serde_json::from_str(input).map_err(Error::from)
}

/// Convert dump save entries to domain entries.
pub fn dump_save_to_env_entries(save: &DumpSave) -> Vec<EnvEntry> {
    save.entries.iter().map(EnvEntry::from).collect()
}

// ---------------------------------------------------------------------------
// Single-save export (share/import)
// ---------------------------------------------------------------------------

/// Build an export envelope from save metadata and entries.
pub fn build_envelope(save: &SaveMetadata, entries: &[EnvEntry]) -> ExportEnvelope {
    ExportEnvelope {
        version: FORMAT_VERSION,
        file: save.file_path.clone(),
        branch: save.branch.clone(),
        commit: save.commit_hash.clone(),
        timestamp: save.timestamp.clone(),
        content_hash: save.content_hash.clone(),
        message: save.message.clone(),
        entries: entries.iter().map(ExportEntry::from).collect(),
    }
}

/// Serialize an envelope to JSON.
pub fn to_json(envelope: &ExportEnvelope) -> Result<String> {
    serde_json::to_string_pretty(envelope).map_err(Error::from)
}

/// Deserialize an envelope from JSON.
pub fn from_json(input: &str) -> Result<ExportEnvelope> {
    serde_json::from_str(input).map_err(Error::from)
}

/// Serialize an envelope to the text format.
///
/// Format:
/// ```text
/// # envmgr export
/// # version: 1
/// # file: path/to/.env
/// # branch: feature/foo
/// # commit: abc123...
/// # timestamp: 2024-06-17T12:05:00Z
/// # content_hash: def456...
/// # message: trying new DB config
///
/// # Database configuration
/// DB_HOST=localhost
/// DB_PORT=5432
/// ```
pub fn to_text(envelope: &ExportEnvelope) -> String {
    let mut out = String::new();
    out.push_str(&format!("{TEXT_HEADER_PREFIX}\n"));
    out.push_str(&format!("# version: {}\n", envelope.version));
    out.push_str(&format!("# file: {}\n", envelope.file));
    out.push_str(&format!("# branch: {}\n", envelope.branch));
    out.push_str(&format!("# commit: {}\n", envelope.commit));
    out.push_str(&format!("# timestamp: {}\n", envelope.timestamp));
    out.push_str(&format!("# content_hash: {}\n", envelope.content_hash));
    if let Some(ref msg) = envelope.message {
        out.push_str(&format!("# message: {msg}\n"));
    }
    out.push('\n');

    for entry in &envelope.entries {
        if let Some(ref comment) = entry.comment {
            out.push_str(&format!("# {comment}\n"));
        }
        out.push_str(&format!("{}={}\n", entry.key, entry.value));
    }

    out
}

/// Deserialize an envelope from the text format.
pub fn from_text(input: &str) -> Result<ExportEnvelope> {
    let mut lines = input.lines();

    // Expect header line.
    let first = lines.next().ok_or_else(|| {
        Error::Other("empty export text".to_string())
    })?;
    if first.trim() != TEXT_HEADER_PREFIX {
        return Err(Error::Other(format!(
            "invalid export text: expected '{TEXT_HEADER_PREFIX}', got '{first}'"
        )));
    }

    let mut version: Option<u32> = None;
    let mut file = String::new();
    let mut branch = String::new();
    let mut commit = String::new();
    let mut timestamp = String::new();
    let mut content_hash = String::new();
    let mut message: Option<String> = None;

    // Parse header metadata lines.
    let mut body_lines: Vec<&str> = Vec::new();
    let mut in_header = true;

    for line in lines {
        if in_header {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                in_header = false;
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("# ") {
                if let Some(val) = rest.strip_prefix("version: ") {
                    version = Some(val.parse::<u32>().map_err(|e| {
                        Error::Other(format!("invalid version: {e}"))
                    })?);
                } else if let Some(val) = rest.strip_prefix("file: ") {
                    file = val.to_string();
                } else if let Some(val) = rest.strip_prefix("branch: ") {
                    branch = val.to_string();
                } else if let Some(val) = rest.strip_prefix("commit: ") {
                    commit = val.to_string();
                } else if let Some(val) = rest.strip_prefix("timestamp: ") {
                    timestamp = val.to_string();
                } else if let Some(val) = rest.strip_prefix("content_hash: ") {
                    content_hash = val.to_string();
                } else if let Some(val) = rest.strip_prefix("message: ") {
                    message = Some(val.to_string());
                }
            }
        } else {
            body_lines.push(line);
        }
    }

    let version = version.ok_or_else(|| {
        Error::Other("missing version in export text".to_string())
    })?;

    // Parse entries from the body using the parser module.
    let body = body_lines.join("\n");
    let entries = crate::parser::parse(&body)?;

    Ok(ExportEnvelope {
        version,
        file,
        branch,
        commit,
        timestamp,
        content_hash,
        message,
        entries: entries.iter().map(ExportEntry::from).collect(),
    })
}

/// Auto-detect format and parse. Tries JSON first, then text.
pub fn auto_detect(input: &str) -> Result<ExportEnvelope> {
    let trimmed = input.trim_start();
    if trimmed.starts_with('{') {
        from_json(input)
    } else {
        from_text(input)
    }
}

/// Convert export entries back to domain entries.
pub fn to_env_entries(envelope: &ExportEnvelope) -> Vec<EnvEntry> {
    envelope.entries.iter().map(EnvEntry::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{sample_entries, test_conn};

    fn sample_envelope() -> ExportEnvelope {
        ExportEnvelope {
            version: 1,
            file: "apps/backend/.env".to_string(),
            branch: "feature/auth".to_string(),
            commit: "46beae29b4d5af32308c4673addec86a82d95355".to_string(),
            timestamp: "2024-06-17T12:05:00Z".to_string(),
            content_hash: "abc123def456".to_string(),
            message: None,
            entries: vec![
                ExportEntry {
                    key: "DB_HOST".to_string(),
                    value: "localhost".to_string(),
                    comment: Some("Database configuration".to_string()),
                },
                ExportEntry {
                    key: "DB_PORT".to_string(),
                    value: "5432".to_string(),
                    comment: None,
                },
                ExportEntry {
                    key: "API_KEY".to_string(),
                    value: "secret123".to_string(),
                    comment: Some("API credentials".to_string()),
                },
            ],
        }
    }

    fn sample_metadata() -> SaveMetadata {
        SaveMetadata {
            id: 1,
            project_path: "/home/user/project".to_string(),
            file_path: "apps/backend/.env".to_string(),
            branch: "feature/auth".to_string(),
            commit_hash: "46beae29".to_string(),
            timestamp: "2024-06-17T12:05:00Z".to_string(),
            content_hash: "abc123".to_string(),
            hmac: String::new(),
            message: None,
        }
    }

    // ----- JSON round-trip -----

    #[test]
    fn json_round_trip() {
        let envelope = sample_envelope();
        let json = to_json(&envelope).unwrap();
        let parsed = from_json(&json).unwrap();
        assert_eq!(parsed.version, envelope.version);
        assert_eq!(parsed.file, envelope.file);
        assert_eq!(parsed.branch, envelope.branch);
        assert_eq!(parsed.commit, envelope.commit);
        assert_eq!(parsed.timestamp, envelope.timestamp);
        assert_eq!(parsed.content_hash, envelope.content_hash);
        assert_eq!(parsed.message, None);
        assert_eq!(parsed.entries.len(), envelope.entries.len());
        for (a, b) in parsed.entries.iter().zip(envelope.entries.iter()) {
            assert_eq!(a.key, b.key);
            assert_eq!(a.value, b.value);
            assert_eq!(a.comment, b.comment);
        }
    }

    #[test]
    fn json_preserves_comments() {
        let envelope = sample_envelope();
        let json = to_json(&envelope).unwrap();
        let parsed = from_json(&json).unwrap();
        assert_eq!(
            parsed.entries[0].comment,
            Some("Database configuration".to_string())
        );
        assert_eq!(parsed.entries[1].comment, None);
    }

    // ----- Text round-trip -----

    #[test]
    fn text_round_trip() {
        let envelope = sample_envelope();
        let text = to_text(&envelope);
        let parsed = from_text(&text).unwrap();
        assert_eq!(parsed.version, envelope.version);
        assert_eq!(parsed.file, envelope.file);
        assert_eq!(parsed.branch, envelope.branch);
        assert_eq!(parsed.commit, envelope.commit);
        assert_eq!(parsed.timestamp, envelope.timestamp);
        assert_eq!(parsed.content_hash, envelope.content_hash);
        assert_eq!(parsed.message, None);
        assert_eq!(parsed.entries.len(), envelope.entries.len());
        for (a, b) in parsed.entries.iter().zip(envelope.entries.iter()) {
            assert_eq!(a.key, b.key);
            assert_eq!(a.value, b.value);
            assert_eq!(a.comment, b.comment);
        }
    }

    #[test]
    fn text_format_has_header() {
        let envelope = sample_envelope();
        let text = to_text(&envelope);
        assert!(text.starts_with("# envmgr export\n"));
        assert!(text.contains("# version: 1\n"));
        assert!(text.contains("# file: apps/backend/.env\n"));
        assert!(text.contains("# branch: feature/auth\n"));
    }

    #[test]
    fn text_format_has_entries() {
        let envelope = sample_envelope();
        let text = to_text(&envelope);
        assert!(text.contains("DB_HOST=localhost"));
        assert!(text.contains("DB_PORT=5432"));
        assert!(text.contains("# Database configuration"));
    }

    // ----- Auto-detect -----

    #[test]
    fn auto_detect_json() {
        let envelope = sample_envelope();
        let json = to_json(&envelope).unwrap();
        let parsed = auto_detect(&json).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.entries.len(), 3);
    }

    #[test]
    fn auto_detect_text() {
        let envelope = sample_envelope();
        let text = to_text(&envelope);
        let parsed = auto_detect(&text).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.entries.len(), 3);
    }

    // ----- Error cases -----

    #[test]
    fn from_text_empty_fails() {
        let result = from_text("");
        assert!(result.is_err());
    }

    #[test]
    fn from_text_wrong_header_fails() {
        let result = from_text("not a valid header\nstuff\n");
        assert!(result.is_err());
    }

    #[test]
    fn from_text_missing_version_fails() {
        let input = "# envmgr export\n# file: .env\n\nKEY=val\n";
        let result = from_text(input);
        assert!(result.is_err());
    }

    #[test]
    fn from_json_invalid_fails() {
        let result = from_json("not json at all");
        assert!(result.is_err());
    }

    // ----- build_envelope -----

    #[test]
    fn build_envelope_from_metadata_and_entries() {
        let meta = sample_metadata();
        let entries = sample_entries();
        let envelope = build_envelope(&meta, &entries);
        assert_eq!(envelope.version, 1);
        assert_eq!(envelope.file, "apps/backend/.env");
        assert_eq!(envelope.branch, "feature/auth");
        assert_eq!(envelope.commit, "46beae29");
        assert_eq!(envelope.message, None);
        assert_eq!(envelope.entries.len(), 2);
    }

    // ----- to_env_entries -----

    #[test]
    fn to_env_entries_converts() {
        let envelope = sample_envelope();
        let entries = to_env_entries(&envelope);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].key, "DB_HOST");
        assert_eq!(entries[0].value, "localhost");
        assert_eq!(
            entries[0].comment,
            Some("Database configuration".to_string())
        );
        assert_eq!(entries[1].comment, None);
    }

    // ----- Text with empty branch/commit -----

    #[test]
    fn text_round_trip_non_git() {
        let envelope = ExportEnvelope {
            version: 1,
            file: ".env".to_string(),
            branch: String::new(),
            commit: String::new(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            content_hash: "hash123".to_string(),
            message: None,
            entries: vec![ExportEntry {
                key: "KEY".to_string(),
                value: "val".to_string(),
                comment: None,
            }],
        };
        let text = to_text(&envelope);
        let parsed = from_text(&text).unwrap();
        assert_eq!(parsed.branch, "");
        assert_eq!(parsed.commit, "");
        assert_eq!(parsed.entries.len(), 1);
    }

    // ----- Cross-format -----

    #[test]
    fn json_then_text_preserves_data() {
        let envelope = sample_envelope();
        let json = to_json(&envelope).unwrap();
        let from_j = from_json(&json).unwrap();
        let text = to_text(&from_j);
        let from_t = from_text(&text).unwrap();
        assert_eq!(from_t.file, envelope.file);
        assert_eq!(from_t.entries.len(), envelope.entries.len());
    }

    #[test]
    fn text_then_json_preserves_data() {
        let envelope = sample_envelope();
        let text = to_text(&envelope);
        let from_t = from_text(&text).unwrap();
        let json = to_json(&from_t).unwrap();
        let from_j = from_json(&json).unwrap();
        assert_eq!(from_j.file, envelope.file);
        assert_eq!(from_j.entries.len(), envelope.entries.len());
    }

    // ----- Special characters -----

    #[test]
    fn json_round_trip_special_chars() {
        let envelope = ExportEnvelope {
            version: 1,
            file: "path/with spaces/.env".to_string(),
            branch: "feature/special-chars".to_string(),
            commit: "abc".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            content_hash: "hash".to_string(),
            message: None,
            entries: vec![ExportEntry {
                key: "URL".to_string(),
                value: "postgres://user:p@ss=w0rd@host/db".to_string(),
                comment: Some("Connection with = sign".to_string()),
            }],
        };
        let json = to_json(&envelope).unwrap();
        let parsed = from_json(&json).unwrap();
        assert_eq!(
            parsed.entries[0].value,
            "postgres://user:p@ss=w0rd@host/db"
        );
    }

    #[test]
    fn text_round_trip_value_with_equals() {
        let envelope = ExportEnvelope {
            version: 1,
            file: ".env".to_string(),
            branch: "main".to_string(),
            commit: "abc".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            content_hash: "hash".to_string(),
            message: None,
            entries: vec![ExportEntry {
                key: "CONN".to_string(),
                value: "postgres://host/db?opt=val".to_string(),
                comment: None,
            }],
        };
        let text = to_text(&envelope);
        let parsed = from_text(&text).unwrap();
        assert_eq!(
            parsed.entries[0].value,
            "postgres://host/db?opt=val"
        );
    }

    // ----- Full round-trip: save -> share -> import -----

    #[test]
    fn full_round_trip_json() {
        let conn = test_conn();
        let entries = sample_entries();
        let _id = crate::store::queries::insert_save(
            &conn, "/proj", ".env", "main", "abc123",
            "2024-06-17T12:00:00Z", "hashvalue", &entries, None,
        )
        .unwrap();

        // Simulate share: load from store, build envelope, serialize.
        let saves = crate::store::queries::list_saves(
            &conn, "/proj", Some("main"), None, 1, None,
        )
        .unwrap();
        let save = &saves[0];
        let loaded = crate::store::queries::get_save_entries(&conn, save.id, None).unwrap();
        let envelope = build_envelope(save, &loaded);
        let json = to_json(&envelope).unwrap();

        // Simulate import: parse envelope, insert into store.
        let parsed = from_json(&json).unwrap();
        let imported_entries = to_env_entries(&parsed);
        let _new_id = crate::store::queries::insert_save(
            &conn,
            "/proj",
            &parsed.file,
            &parsed.branch,
            &parsed.commit,
            &parsed.timestamp,
            &parsed.content_hash,
            &imported_entries,
            None,
        )
        .unwrap();

        // Verify the imported data matches.
        let all = crate::store::queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert_eq!(all.len(), 2);
        let imported = crate::store::queries::get_save_entries(&conn, all[0].id, None).unwrap();
        assert_eq!(imported, entries);
    }

    #[test]
    fn full_round_trip_text() {
        let conn = test_conn();
        let entries = sample_entries();
        crate::store::queries::insert_save(
            &conn, "/proj", ".env", "dev", "def456",
            "2024-06-17T12:00:00Z", "hashval2", &entries, None,
        )
        .unwrap();

        let saves = crate::store::queries::list_saves(
            &conn, "/proj", Some("dev"), None, 1, None,
        )
        .unwrap();
        let save = &saves[0];
        let loaded = crate::store::queries::get_save_entries(&conn, save.id, None).unwrap();
        let envelope = build_envelope(save, &loaded);
        let text = to_text(&envelope);

        let parsed = from_text(&text).unwrap();
        let imported_entries = to_env_entries(&parsed);
        crate::store::queries::insert_save(
            &conn,
            "/proj",
            &parsed.file,
            &parsed.branch,
            &parsed.commit,
            &parsed.timestamp,
            &parsed.content_hash,
            &imported_entries,
            None,
        )
        .unwrap();

        let all = crate::store::queries::list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn full_round_trip_encrypted_store() {
        let conn = test_conn();
        let key = crate::crypto::aes::generate_key();
        let entries = sample_entries();
        crate::store::queries::insert_save(
            &conn, "/proj", ".env", "main", "abc",
            "2024-06-17T12:00:00Z", "hash1", &entries, Some(&key),
        )
        .unwrap();

        // Share: decrypt from store, build envelope.
        let saves = crate::store::queries::list_saves(
            &conn, "/proj", Some("main"), None, 1, None,
        )
        .unwrap();
        let loaded = crate::store::queries::get_save_entries(&conn, saves[0].id, Some(&key)).unwrap();
        let envelope = build_envelope(&saves[0], &loaded);
        let json = to_json(&envelope).unwrap();

        // Import: parse envelope, re-encrypt into store.
        let parsed = from_json(&json).unwrap();
        let imported_entries = to_env_entries(&parsed);
        crate::store::queries::insert_save(
            &conn,
            "/proj2",
            &parsed.file,
            &parsed.branch,
            &parsed.commit,
            &parsed.timestamp,
            &parsed.content_hash,
            &imported_entries,
            Some(&key),
        )
        .unwrap();

        // Verify: decrypt and compare.
        let reimported = crate::store::queries::list_saves(
            &conn, "/proj2", None, None, 1, None,
        )
        .unwrap();
        let reimported_entries = crate::store::queries::get_save_entries(
            &conn, reimported[0].id, Some(&key),
        )
        .unwrap();
        assert_eq!(reimported_entries, entries);
    }

    // ----- Dump format -----

    #[test]
    fn dump_json_round_trip() {
        let meta = sample_metadata();
        let entries = sample_entries();
        let dump_save = build_dump_save(&meta, &entries);
        let dump = build_dump(vec![dump_save]);

        let json = dump_to_json(&dump).unwrap();
        let parsed = dump_from_json(&json).unwrap();

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.dump_type, "dump");
        assert_eq!(parsed.saves.len(), 1);
        assert_eq!(parsed.saves[0].project_path, "/home/user/project");
        assert_eq!(parsed.saves[0].file, "apps/backend/.env");
        assert_eq!(parsed.saves[0].branch, "feature/auth");
        assert_eq!(parsed.saves[0].entries.len(), 2);
    }

    #[test]
    fn dump_empty_saves() {
        let dump = build_dump(vec![]);
        let json = dump_to_json(&dump).unwrap();
        let parsed = dump_from_json(&json).unwrap();
        assert_eq!(parsed.saves.len(), 0);
    }

    #[test]
    fn dump_multiple_projects() {
        let meta1 = SaveMetadata {
            id: 1,
            project_path: "/proj1".to_string(),
            file_path: ".env".to_string(),
            branch: "main".to_string(),
            commit_hash: "abc".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            content_hash: "h1".to_string(),
            hmac: String::new(),
            message: None,
        };
        let meta2 = SaveMetadata {
            id: 2,
            project_path: "/proj2".to_string(),
            file_path: ".env".to_string(),
            branch: "dev".to_string(),
            commit_hash: "def".to_string(),
            timestamp: "2024-01-02T00:00:00Z".to_string(),
            content_hash: "h2".to_string(),
            hmac: String::new(),
            message: None,
        };
        let entries = sample_entries();
        let saves = vec![
            build_dump_save(&meta1, &entries),
            build_dump_save(&meta2, &entries),
        ];
        let dump = build_dump(saves);
        let json = dump_to_json(&dump).unwrap();
        let parsed = dump_from_json(&json).unwrap();

        assert_eq!(parsed.saves.len(), 2);
        assert_eq!(parsed.saves[0].project_path, "/proj1");
        assert_eq!(parsed.saves[1].project_path, "/proj2");
    }

    #[test]
    fn dump_save_to_env_entries_converts() {
        let meta = sample_metadata();
        let entries = sample_entries();
        let dump_save = build_dump_save(&meta, &entries);
        let converted = dump_save_to_env_entries(&dump_save);
        assert_eq!(converted, entries);
    }

    #[test]
    fn dump_full_store_round_trip() {
        let conn = test_conn();
        let entries = sample_entries();
        crate::store::queries::insert_save(
            &conn, "/proj1", ".env", "main", "a1",
            "2024-01-01T00:00:00Z", "h1", &entries, None,
        )
        .unwrap();
        crate::store::queries::insert_save(
            &conn, "/proj2", ".env", "dev", "a2",
            "2024-01-02T00:00:00Z", "h2", &entries, None,
        )
        .unwrap();

        // Dump.
        let all = crate::store::queries::get_all_saves(&conn, None).unwrap();
        let dump_saves: Vec<DumpSave> = all
            .iter()
            .map(|(save, e)| build_dump_save(save, e))
            .collect();
        let dump = build_dump(dump_saves);
        let json = dump_to_json(&dump).unwrap();

        // Load into fresh store.
        let conn2 = test_conn();
        let parsed = dump_from_json(&json).unwrap();
        let (inserted, skipped) =
            crate::store::queries::insert_all_saves(&conn2, &parsed.saves, None).unwrap();
        assert_eq!(inserted, 2);
        assert_eq!(skipped, 0);

        // Verify.
        let all2 = crate::store::queries::get_all_saves(&conn2, None).unwrap();
        assert_eq!(all2.len(), 2);
        assert_eq!(all2[0].1, entries);
        assert_eq!(all2[1].1, entries);
    }

    #[test]
    fn dump_load_duplicate_detection() {
        let conn = test_conn();
        let entries = sample_entries();
        crate::store::queries::insert_save(
            &conn, "/proj", ".env", "main", "a1",
            "2024-01-01T00:00:00Z", "h1", &entries, None,
        )
        .unwrap();

        // Build dump.
        let all = crate::store::queries::get_all_saves(&conn, None).unwrap();
        let dump_saves: Vec<DumpSave> = all
            .iter()
            .map(|(save, e)| build_dump_save(save, e))
            .collect();
        let dump = build_dump(dump_saves);
        let json = dump_to_json(&dump).unwrap();

        // Load into the SAME store -- should skip duplicates.
        let parsed = dump_from_json(&json).unwrap();
        let (inserted, skipped) =
            crate::store::queries::insert_all_saves(&conn, &parsed.saves, None).unwrap();
        assert_eq!(inserted, 0);
        assert_eq!(skipped, 1);

        // Still only 1 save in store.
        let all = crate::store::queries::get_all_saves(&conn, None).unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn dump_load_encrypted_store() {
        let conn = test_conn();
        let key = crate::crypto::aes::generate_key();
        let entries = sample_entries();
        crate::store::queries::insert_save(
            &conn, "/proj", ".env", "main", "a1",
            "2024-01-01T00:00:00Z", "h1", &entries, Some(&key),
        )
        .unwrap();

        // Dump (decrypting).
        let all = crate::store::queries::get_all_saves(&conn, Some(&key)).unwrap();
        let dump_saves: Vec<DumpSave> = all
            .iter()
            .map(|(save, e)| build_dump_save(save, e))
            .collect();
        let dump = build_dump(dump_saves);
        let json = dump_to_json(&dump).unwrap();

        // Load into unencrypted store.
        let conn2 = test_conn();
        let parsed = dump_from_json(&json).unwrap();
        let (inserted, _) =
            crate::store::queries::insert_all_saves(&conn2, &parsed.saves, None).unwrap();
        assert_eq!(inserted, 1);

        let loaded = crate::store::queries::get_all_saves(&conn2, None).unwrap();
        assert_eq!(loaded[0].1, entries);
    }

    #[test]
    fn dump_load_into_encrypted_store() {
        let conn = test_conn();
        let entries = sample_entries();
        crate::store::queries::insert_save(
            &conn, "/proj", ".env", "main", "a1",
            "2024-01-01T00:00:00Z", "h1", &entries, None,
        )
        .unwrap();

        // Dump from unencrypted store.
        let all = crate::store::queries::get_all_saves(&conn, None).unwrap();
        let dump_saves: Vec<DumpSave> = all
            .iter()
            .map(|(save, e)| build_dump_save(save, e))
            .collect();
        let dump = build_dump(dump_saves);
        let json = dump_to_json(&dump).unwrap();

        // Load into encrypted store.
        let conn2 = test_conn();
        let key = crate::crypto::aes::generate_key();
        let parsed = dump_from_json(&json).unwrap();
        let (inserted, _) =
            crate::store::queries::insert_all_saves(&conn2, &parsed.saves, Some(&key)).unwrap();
        assert_eq!(inserted, 1);

        let loaded = crate::store::queries::get_all_saves(&conn2, Some(&key)).unwrap();
        assert_eq!(loaded[0].1, entries);
    }

    // ----- Message round-trip tests -----

    #[test]
    fn json_round_trip_with_message() {
        let mut envelope = sample_envelope();
        envelope.message = Some("trying new DB config".to_string());
        let json = to_json(&envelope).unwrap();
        let parsed = from_json(&json).unwrap();
        assert_eq!(parsed.message.as_deref(), Some("trying new DB config"));
    }

    #[test]
    fn json_round_trip_without_message() {
        let envelope = sample_envelope();
        let json = to_json(&envelope).unwrap();
        let parsed = from_json(&json).unwrap();
        assert_eq!(parsed.message, None);
        // message field should not appear in JSON when None
        assert!(!json.contains("message"));
    }

    #[test]
    fn text_round_trip_with_message() {
        let mut envelope = sample_envelope();
        envelope.message = Some("production values".to_string());
        let text = to_text(&envelope);
        assert!(text.contains("# message: production values\n"));
        let parsed = from_text(&text).unwrap();
        assert_eq!(parsed.message.as_deref(), Some("production values"));
    }

    #[test]
    fn text_round_trip_without_message() {
        let envelope = sample_envelope();
        let text = to_text(&envelope);
        assert!(!text.contains("# message:"));
        let parsed = from_text(&text).unwrap();
        assert_eq!(parsed.message, None);
    }

    #[test]
    fn build_envelope_preserves_message() {
        let mut meta = sample_metadata();
        meta.message = Some("before migration".to_string());
        let entries = sample_entries();
        let envelope = build_envelope(&meta, &entries);
        assert_eq!(envelope.message.as_deref(), Some("before migration"));
    }

    #[test]
    fn dump_round_trip_with_message() {
        let conn = test_conn();
        let entries = sample_entries();
        crate::store::queries::insert_save_with_message(
            &conn, "/proj", ".env", "main", "a1",
            "2024-01-01T00:00:00Z", "h1", &entries, None,
            Some("initial config"),
        )
        .unwrap();

        let all = crate::store::queries::get_all_saves(&conn, None).unwrap();
        assert_eq!(all[0].0.message.as_deref(), Some("initial config"));

        let dump_saves: Vec<DumpSave> = all
            .iter()
            .map(|(save, e)| build_dump_save(save, e))
            .collect();
        assert_eq!(dump_saves[0].message.as_deref(), Some("initial config"));

        let dump = build_dump(dump_saves);
        let json = dump_to_json(&dump).unwrap();
        let parsed = dump_from_json(&json).unwrap();
        assert_eq!(parsed.saves[0].message.as_deref(), Some("initial config"));

        // Load into fresh store and verify message survives.
        let conn2 = test_conn();
        let (inserted, _) =
            crate::store::queries::insert_all_saves(&conn2, &parsed.saves, None).unwrap();
        assert_eq!(inserted, 1);
        let loaded = crate::store::queries::get_all_saves(&conn2, None).unwrap();
        assert_eq!(loaded[0].0.message.as_deref(), Some("initial config"));
    }

    #[test]
    fn share_import_round_trip_with_message() {
        let conn = test_conn();
        let entries = sample_entries();
        crate::store::queries::insert_save_with_message(
            &conn, "/proj", ".env", "main", "abc",
            "2024-06-17T12:00:00Z", "h1", &entries, None,
            Some("share test message"),
        )
        .unwrap();

        // Share.
        let saves = crate::store::queries::list_saves(
            &conn, "/proj", Some("main"), None, 1, None,
        )
        .unwrap();
        let loaded = crate::store::queries::get_save_entries(&conn, saves[0].id, None).unwrap();
        let envelope = build_envelope(&saves[0], &loaded);
        assert_eq!(envelope.message.as_deref(), Some("share test message"));

        // JSON round-trip.
        let json = to_json(&envelope).unwrap();
        let parsed = from_json(&json).unwrap();
        assert_eq!(parsed.message.as_deref(), Some("share test message"));

        // Text round-trip.
        let text = to_text(&envelope);
        let parsed_text = from_text(&text).unwrap();
        assert_eq!(parsed_text.message.as_deref(), Some("share test message"));
    }
}
