use std::path::Path;

use crate::cli::{self, output};
use crate::error::Result;
use crate::parser;
use crate::types::EnvEntry;

/// Resolve a diff argument: if it's a file on disk, parse it; otherwise look
/// up a saved version from the store.
fn resolve_entries(
    ref_str: &str,
    cwd: &Path,
    conn: &rusqlite::Connection,
    project_path: &str,
    current_branch: Option<&str>,
    aes_key: Option<&[u8; 32]>,
) -> Result<Vec<EnvEntry>> {
    let candidate = cwd.join(ref_str);
    if candidate.is_file() {
        let content = std::fs::read_to_string(&candidate)?;
        return parser::parse(&content);
    }
    let save = cli::resolve_version(conn, project_path, current_branch, ref_str)?;
    cli::load_entries(conn, &save, aes_key)
}

/// Run the `diff` command: compare two saved versions (or files on disk).
pub fn run(
    cwd: &Path,
    a: &str,
    b: &str,
    full: bool,
    output_format: &str,
    key_file: Option<&str>,
) -> Result<()> {
    let conn = cli::require_store()?;
    let aes_key = cli::load_encryption_key(&conn, key_file)?;
    let (project_path, git_ctx) = cli::resolve_project(cwd)?;
    let current_branch = git_ctx.as_ref().map(|c| c.branch.as_str());

    let entries_a = resolve_entries(
        a,
        cwd,
        &conn,
        &project_path,
        current_branch,
        aes_key.as_ref(),
    )?;
    let entries_b = resolve_entries(
        b,
        cwd,
        &conn,
        &project_path,
        current_branch,
        aes_key.as_ref(),
    )?;

    let result = crate::diff::diff(&entries_a, &entries_b);

    if output_format == "json" {
        println!("{}", output::format_diff_json(&result, full)?);
    } else {
        print!("{}", output::format_diff_text(&result, full));
    }

    Ok(())
}
