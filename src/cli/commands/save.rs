use std::path::Path;

use chrono::{SecondsFormat, Utc};

use crate::cli;
use crate::error::{Error, Result};
use crate::parser;
use crate::store::queries;

/// Run the `save` command: read .env from disk, parse, and store.
pub fn run(cwd: &Path, file: Option<&str>, key_file: Option<&str>, message: Option<&str>) -> Result<()> {
    let conn = cli::require_store()?;
    let aes_key = cli::load_encryption_key(&conn, key_file)?;
    let (project_path, git_ctx) = cli::resolve_project(cwd)?;

    let file_name = file.unwrap_or(".env");
    let disk_path = cwd.join(file_name);

    if !disk_path.exists() {
        return Err(Error::FileNotFound(disk_path));
    }

    let content = std::fs::read_to_string(&disk_path)?;
    let entries = parser::parse(&content)?;
    let hash = parser::content_hash(&entries);
    let file_path = cli::resolve_file_path(file_name, cwd, &git_ctx)?;

    let (branch, commit) = match &git_ctx {
        Some(ctx) => (ctx.branch.as_str(), ctx.commit.as_str()),
        None => ("", ""),
    };

    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

    queries::insert_save_with_message(
        &conn,
        &project_path,
        &file_path,
        branch,
        commit,
        &timestamp,
        &hash,
        &entries,
        aes_key.as_ref(),
        message,
    )?;

    let msg_suffix = match message {
        Some(m) => format!(" -- {m}"),
        None => String::new(),
    };

    println!("Saved {} ({} variables){}", file_path, entries.len(), msg_suffix);
    Ok(())
}
