use rusqlite::Connection;

use crate::error::Result;

/// Create all tables if they don't already exist.
pub fn create_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS saves (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            project_path TEXT    NOT NULL,
            file_path    TEXT    NOT NULL,
            branch       TEXT    NOT NULL DEFAULT '',
            commit_hash  TEXT    NOT NULL DEFAULT '',
            timestamp    TEXT    NOT NULL,
            content_hash TEXT    NOT NULL,
            hmac         TEXT    NOT NULL DEFAULT '',
            message      TEXT    NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_saves_project_branch
            ON saves(project_path, branch);

        CREATE INDEX IF NOT EXISTS idx_saves_content_hash
            ON saves(content_hash);

        CREATE TABLE IF NOT EXISTS entries (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            save_id  INTEGER NOT NULL REFERENCES saves(id) ON DELETE CASCADE,
            key      TEXT    NOT NULL,
            value    BLOB    NOT NULL,
            comment  BLOB    NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_entries_save_id
            ON entries(save_id);
        ",
    )?;
    Ok(())
}
