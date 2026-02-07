use rusqlite::{Connection, params};

use crate::error::{Error, Result};
use crate::types::{EnvEntry, ProjectSummary, SaveMetadata};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Get a config value by key.
pub fn get_config(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM config WHERE key = ?1")?;
    let mut rows = stmt.query(params![key])?;
    match rows.next()? {
        Some(row) => Ok(Some(row.get(0)?)),
        None => Ok(None),
    }
}

/// Set a config value (insert or update).
pub fn set_config(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO config (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// HMAC helpers
// ---------------------------------------------------------------------------

/// Format metadata fields into a deterministic string for HMAC computation.
///
/// Uses length-prefixed encoding to prevent delimiter confusion:
/// each field is prefixed with its byte length, making
/// `"3:a|b|1:c"` distinct from `"1:a|3:b|c"`.
fn format_hmac_data(
    project_path: &str,
    file_path: &str,
    branch: &str,
    commit_hash: &str,
    timestamp: &str,
    content_hash: &str,
) -> String {
    let fields = [project_path, file_path, branch, commit_hash, timestamp, content_hash];
    fields
        .iter()
        .map(|f| format!("{}:{f}", f.len()))
        .collect::<Vec<_>>()
        .join("|")
}

/// Verify the HMAC on a save's metadata row.
pub fn verify_save_hmac(save: &SaveMetadata, key: &[u8; 32]) -> Result<()> {
    if save.hmac.is_empty() {
        return Err(Error::HmacMismatch);
    }
    let data = format_hmac_data(
        &save.project_path,
        &save.file_path,
        &save.branch,
        &save.commit_hash,
        &save.timestamp,
        &save.content_hash,
    );
    if !crate::crypto::hmac::verify_hmac(key, data.as_bytes(), &save.hmac)? {
        return Err(Error::HmacMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Saves
// ---------------------------------------------------------------------------

/// Input parameters for inserting a save.
pub struct SaveInput<'a> {
    pub project_path: &'a str,
    pub file_path: &'a str,
    pub branch: &'a str,
    pub commit_hash: &'a str,
    pub timestamp: &'a str,
    pub content_hash: &'a str,
    pub entries: &'a [EnvEntry],
    pub aes_key: Option<&'a [u8; 32]>,
    pub message: Option<&'a str>,
}

/// Insert a save and its entries. Returns the save id.
///
/// When `aes_key` is `Some`, entry values and comments are AES-256-GCM
/// encrypted, and an HMAC is computed over metadata fields.
#[allow(clippy::too_many_arguments)]
pub fn insert_save(
    conn: &Connection,
    project_path: &str,
    file_path: &str,
    branch: &str,
    commit_hash: &str,
    timestamp: &str,
    content_hash: &str,
    entries: &[EnvEntry],
    aes_key: Option<&[u8; 32]>,
) -> Result<i64> {
    insert_save_input(
        conn,
        &SaveInput {
            project_path,
            file_path,
            branch,
            commit_hash,
            timestamp,
            content_hash,
            entries,
            aes_key,
            message: None,
        },
    )
}

/// Insert a save with an optional message. Returns the save id.
#[allow(clippy::too_many_arguments)]
pub fn insert_save_with_message(
    conn: &Connection,
    project_path: &str,
    file_path: &str,
    branch: &str,
    commit_hash: &str,
    timestamp: &str,
    content_hash: &str,
    entries: &[EnvEntry],
    aes_key: Option<&[u8; 32]>,
    message: Option<&str>,
) -> Result<i64> {
    insert_save_input(
        conn,
        &SaveInput {
            project_path,
            file_path,
            branch,
            commit_hash,
            timestamp,
            content_hash,
            entries,
            aes_key,
            message,
        },
    )
}

/// Insert a save using a `SaveInput` struct.
fn insert_save_input(conn: &Connection, input: &SaveInput<'_>) -> Result<i64> {
    let hmac_value = if let Some(key) = input.aes_key {
        let data = format_hmac_data(
            input.project_path, input.file_path, input.branch,
            input.commit_hash, input.timestamp, input.content_hash,
        );
        crate::crypto::hmac::compute_hmac(key, data.as_bytes())?
    } else {
        String::new()
    };

    let message_value = input.message.unwrap_or("");

    conn.execute(
        "INSERT INTO saves (project_path, file_path, branch, commit_hash, timestamp, content_hash, hmac, message)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            input.project_path, input.file_path, input.branch,
            input.commit_hash, input.timestamp, input.content_hash, hmac_value,
            message_value
        ],
    )?;

    let save_id = conn.last_insert_rowid();

    let mut stmt = conn.prepare(
        "INSERT INTO entries (save_id, key, value, comment) VALUES (?1, ?2, ?3, ?4)",
    )?;

    for entry in input.entries {
        let comment_str = entry.comment.as_deref().unwrap_or("");
        if let Some(key) = input.aes_key {
            let enc_value = crate::crypto::aes::encrypt(key, entry.value.as_bytes())?;
            let enc_comment = crate::crypto::aes::encrypt(key, comment_str.as_bytes())?;
            stmt.execute(params![save_id, entry.key, enc_value, enc_comment])?;
        } else {
            stmt.execute(params![save_id, entry.key, entry.value, comment_str])?;
        }
    }

    Ok(save_id)
}

/// Helper to map a row into `SaveMetadata`. Expects columns in the order:
/// id, project_path, file_path, branch, commit_hash, timestamp, content_hash, hmac, message
fn row_to_save_metadata(row: &rusqlite::Row<'_>) -> rusqlite::Result<SaveMetadata> {
    let message_raw: String = row.get(8)?;
    Ok(SaveMetadata {
        id: row.get(0)?,
        project_path: row.get(1)?,
        file_path: row.get(2)?,
        branch: row.get(3)?,
        commit_hash: row.get(4)?,
        timestamp: row.get(5)?,
        content_hash: row.get(6)?,
        hmac: row.get(7)?,
        message: if message_raw.is_empty() { None } else { Some(message_raw) },
    })
}

/// Read raw bytes from a row column, handling both TEXT and BLOB storage.
fn read_bytes_from_row(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<Vec<u8>> {
    let val = row.get_ref(idx)?;
    Ok(match val {
        rusqlite::types::ValueRef::Text(b) => b.to_vec(),
        rusqlite::types::ValueRef::Blob(b) => b.to_vec(),
        rusqlite::types::ValueRef::Null => Vec::new(),
        _ => Vec::new(),
    })
}

/// Test-only: expose `read_bytes_from_row` for verifying raw DB contents.
#[cfg(test)]
pub fn tests_read_bytes(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<Vec<u8>> {
    read_bytes_from_row(row, idx)
}

/// The column list used in all SELECT queries returning `SaveMetadata`.
const SAVE_COLUMNS: &str =
    "id, project_path, file_path, branch, commit_hash, timestamp, content_hash, hmac, message";

/// List saves matching filters, ordered newest first.
pub fn list_saves(
    conn: &Connection,
    project_path: &str,
    branch: Option<&str>,
    commit: Option<&str>,
    max: usize,
    filter: Option<&str>,
) -> Result<Vec<SaveMetadata>> {
    let mut sql = format!(
        "SELECT {SAVE_COLUMNS} FROM saves WHERE project_path = ?1",
    );
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(project_path.to_string())];
    let mut idx = 2;

    if let Some(b) = branch {
        sql.push_str(&format!(" AND branch = ?{idx}"));
        param_values.push(Box::new(b.to_string()));
        idx += 1;
    }

    if let Some(c) = commit {
        sql.push_str(&format!(" AND commit_hash = ?{idx}"));
        param_values.push(Box::new(c.to_string()));
        idx += 1;
    }

    if let Some(f) = filter {
        sql.push_str(&format!(" AND file_path LIKE ?{idx}"));
        // Convert glob-style `*` to SQL `%`.
        let pattern = f.replace('*', "%");
        param_values.push(Box::new(pattern));
        idx += 1;
    }

    let _ = idx; // suppress unused warning

    sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT {max}"));

    let mut stmt = conn.prepare(&sql)?;
    let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
    let rows = stmt.query_map(params_ref.as_slice(), row_to_save_metadata)?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row?);
    }
    Ok(results)
}

/// List saves for a project, excluding a given branch (for cross-branch history).
pub fn list_saves_history(
    conn: &Connection,
    project_path: &str,
    exclude_branch: &str,
    max: usize,
) -> Result<Vec<SaveMetadata>> {
    let sql = format!(
        "SELECT {SAVE_COLUMNS} FROM saves
         WHERE project_path = ?1 AND branch != ?2
         ORDER BY timestamp DESC
         LIMIT ?3",
    );
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(
        params![project_path, exclude_branch, max as i64],
        row_to_save_metadata,
    )?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row?);
    }
    Ok(results)
}

/// Get entries for a given save id.
///
/// When `aes_key` is `Some`, values and comments are decrypted from
/// AES-256-GCM blobs. When `None`, they are read as plaintext.
pub fn get_save_entries(
    conn: &Connection,
    save_id: i64,
    aes_key: Option<&[u8; 32]>,
) -> Result<Vec<EnvEntry>> {
    let mut stmt = conn.prepare(
        "SELECT key, value, comment FROM entries WHERE save_id = ?1 ORDER BY id",
    )?;

    // Read raw data first (handles both TEXT and BLOB column types).
    let raw_rows: Vec<(String, Vec<u8>, Vec<u8>)> = {
        let rows = stmt.query_map(params![save_id], |row| {
            let key: String = row.get(0)?;
            let value_bytes = read_bytes_from_row(row, 1)?;
            let comment_bytes = read_bytes_from_row(row, 2)?;
            Ok((key, value_bytes, comment_bytes))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        result
    };

    // Decrypt if needed and build EnvEntry vec.
    let mut results = Vec::new();
    for (key, value_bytes, comment_bytes) in raw_rows {
        let (value, comment_str) = if let Some(k) = aes_key {
            let v = crate::crypto::aes::decrypt(k, &value_bytes)?;
            let c = crate::crypto::aes::decrypt(k, &comment_bytes)?;
            (
                String::from_utf8(v)
                    .map_err(|e| Error::Decryption(format!("invalid UTF-8 in value: {e}")))?,
                String::from_utf8(c)
                    .map_err(|e| Error::Decryption(format!("invalid UTF-8 in comment: {e}")))?,
            )
        } else {
            (
                String::from_utf8(value_bytes)
                    .map_err(|e| Error::Other(format!("invalid UTF-8 in value: {e}")))?,
                String::from_utf8(comment_bytes)
                    .map_err(|e| Error::Other(format!("invalid UTF-8 in comment: {e}")))?,
            )
        };

        results.push(EnvEntry {
            key,
            value,
            comment: if comment_str.is_empty() {
                None
            } else {
                Some(comment_str)
            },
        });
    }
    Ok(results)
}

/// Find a save by content hash within a project.
pub fn get_save_by_hash(
    conn: &Connection,
    project_path: &str,
    hash: &str,
) -> Result<Option<SaveMetadata>> {
    let sql = format!(
        "SELECT {SAVE_COLUMNS} FROM saves
         WHERE project_path = ?1 AND content_hash LIKE ?2
         ORDER BY timestamp DESC
         LIMIT 1",
    );
    let mut stmt = conn.prepare(&sql)?;

    // Support prefix match (e.g. "abc..HASH" -> "abc%").
    let pattern = if hash.contains("..") {
        let prefix = hash.split("..").next().unwrap_or(hash);
        format!("{prefix}%")
    } else {
        hash.to_string()
    };

    let mut rows = stmt.query(params![project_path, pattern])?;
    match rows.next()? {
        Some(row) => Ok(Some(row_to_save_metadata(row)?)),
        None => Ok(None),
    }
}

/// Delete a single save and its entries (cascade).
pub fn delete_save(conn: &Connection, save_id: i64) -> Result<()> {
    // Delete entries first (in case foreign key enforcement is off).
    conn.execute("DELETE FROM entries WHERE save_id = ?1", params![save_id])?;
    let count = conn.execute("DELETE FROM saves WHERE id = ?1", params![save_id])?;
    if count == 0 {
        return Err(Error::SaveNotFound(save_id.to_string()));
    }
    Ok(())
}

/// Delete all saves for a branch within a project. Returns number deleted.
pub fn delete_saves_by_branch(
    conn: &Connection,
    project_path: &str,
    branch: &str,
) -> Result<usize> {
    // First delete entries.
    conn.execute(
        "DELETE FROM entries WHERE save_id IN
         (SELECT id FROM saves WHERE project_path = ?1 AND branch = ?2)",
        params![project_path, branch],
    )?;
    let count = conn.execute(
        "DELETE FROM saves WHERE project_path = ?1 AND branch = ?2",
        params![project_path, branch],
    )?;
    Ok(count)
}

/// Delete all saves for a project. Returns number deleted.
pub fn delete_saves_by_project(conn: &Connection, project_path: &str) -> Result<usize> {
    conn.execute(
        "DELETE FROM entries WHERE save_id IN
         (SELECT id FROM saves WHERE project_path = ?1)",
        params![project_path],
    )?;
    let count = conn.execute(
        "DELETE FROM saves WHERE project_path = ?1",
        params![project_path],
    )?;
    Ok(count)
}

/// List all projects with save counts and last timestamp.
pub fn list_projects(conn: &Connection) -> Result<Vec<ProjectSummary>> {
    let mut stmt = conn.prepare(
        "SELECT project_path, COUNT(*) as cnt, MAX(timestamp) as last_ts
         FROM saves
         GROUP BY project_path
         ORDER BY last_ts DESC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(ProjectSummary {
            project_path: row.get(0)?,
            save_count: row.get(1)?,
            last_save: row.get(2)?,
        })
    })?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row?);
    }
    Ok(results)
}

/// Get all saves (for dump).
pub fn get_all_saves(
    conn: &Connection,
    aes_key: Option<&[u8; 32]>,
) -> Result<Vec<(SaveMetadata, Vec<EnvEntry>)>> {
    let saves = {
        let sql = format!(
            "SELECT {SAVE_COLUMNS} FROM saves ORDER BY timestamp",
        );
        let mut stmt = conn.prepare(&sql)?;

        let rows = stmt.query_map([], row_to_save_metadata)?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        results
    };

    let mut out = Vec::new();
    for save in saves {
        let entries = get_save_entries(conn, save.id, aes_key)?;
        out.push((save, entries));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Bulk import (for load)
// ---------------------------------------------------------------------------

/// Check if a save with the given content hash already exists in a project.
fn has_save_with_hash(
    conn: &Connection,
    project_path: &str,
    content_hash: &str,
) -> Result<bool> {
    let mut stmt = conn.prepare(
        "SELECT 1 FROM saves WHERE project_path = ?1 AND content_hash = ?2 LIMIT 1",
    )?;
    let exists = stmt.exists(params![project_path, content_hash])?;
    Ok(exists)
}

/// Bulk-insert saves from a dump. Skips saves that already exist (by
/// project_path + content_hash).
///
/// Returns `(inserted_count, skipped_count)`.
pub fn insert_all_saves(
    conn: &Connection,
    saves: &[crate::export::DumpSave],
    aes_key: Option<&[u8; 32]>,
) -> Result<(usize, usize)> {
    let mut inserted = 0;
    let mut skipped = 0;

    for save in saves {
        if has_save_with_hash(conn, &save.project_path, &save.content_hash)? {
            skipped += 1;
            continue;
        }

        let entries: Vec<EnvEntry> = save.entries.iter().map(EnvEntry::from).collect();
        insert_save_with_message(
            conn,
            &save.project_path,
            &save.file,
            &save.branch,
            &save.commit,
            &save.timestamp,
            &save.content_hash,
            &entries,
            aes_key,
            save.message.as_deref(),
        )?;
        inserted += 1;
    }

    Ok((inserted, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_data_length_prefixed() {
        // Verify that length-prefixed encoding prevents delimiter confusion.
        let a = format_hmac_data("a|b", "c", "", "", "", "");
        let b = format_hmac_data("a", "b|c", "", "", "", "");
        assert_ne!(a, b, "Length-prefixed HMAC data should distinguish fields with | in values");
    }

    #[test]
    fn hmac_data_deterministic() {
        let a = format_hmac_data("/proj", ".env", "main", "abc", "2024-01-01", "h1");
        let b = format_hmac_data("/proj", ".env", "main", "abc", "2024-01-01", "h1");
        assert_eq!(a, b);
    }

    #[test]
    fn hmac_data_format() {
        let data = format_hmac_data("ab", "c", "d", "ef", "g", "hi");
        // "2:ab|1:c|1:d|2:ef|1:g|2:hi"
        assert_eq!(data, "2:ab|1:c|1:d|2:ef|1:g|2:hi");
    }

    #[test]
    fn insert_save_with_message_stores_and_retrieves() {
        let conn = crate::test_helpers::test_conn();
        let entries = crate::test_helpers::sample_entries();
        let id = insert_save_with_message(
            &conn, "/proj", ".env", "main", "abc",
            "2024-01-01T00:00:00Z", "h1", &entries, None,
            Some("trying new DB config"),
        )
        .unwrap();
        assert!(id > 0);

        let saves = list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert_eq!(saves.len(), 1);
        assert_eq!(saves[0].message.as_deref(), Some("trying new DB config"));
    }

    #[test]
    fn insert_save_without_message_returns_none() {
        let conn = crate::test_helpers::test_conn();
        let entries = crate::test_helpers::sample_entries();
        insert_save(
            &conn, "/proj", ".env", "main", "abc",
            "2024-01-01T00:00:00Z", "h1", &entries, None,
        )
        .unwrap();

        let saves = list_saves(&conn, "/proj", None, None, 10, None).unwrap();
        assert_eq!(saves.len(), 1);
        assert_eq!(saves[0].message, None);
    }
}
