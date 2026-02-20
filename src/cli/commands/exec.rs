use std::path::Path;
use std::process::Command;

use crate::cli;
use crate::error::{Error, Result};
use crate::store::queries;

/// Run the `exec` command: spawn a subprocess with saved env vars.
pub fn run(
    cwd: &Path,
    version: Option<&str>,
    filter: Option<&str>,
    isolated: bool,
    command: &[String],
    key_file: Option<&str>,
) -> Result<()> {
    if command.is_empty() {
        return Err(Error::Other("No command specified.".to_string()));
    }

    let conn = cli::require_store()?;
    let aes_key = cli::load_encryption_key(&conn, key_file)?;
    let (project_path, git_ctx) = cli::resolve_project(cwd)?;
    let current_branch = git_ctx.as_ref().map(|c| c.branch.as_str());

    let entries = if let Some(v) = version {
        let save = cli::resolve_version(&conn, &project_path, current_branch, v)?;
        cli::load_entries(&conn, &save, aes_key.as_ref())?
    } else {
        let branch = current_branch.unwrap_or("");
        let saves = queries::list_saves(&conn, &project_path, Some(branch), None, 1, None)?;
        let save = saves
            .first()
            .ok_or_else(|| Error::SaveNotFound("no saves on current branch".to_string()))?;
        cli::load_entries(&conn, save, aes_key.as_ref())?
    };

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.current_dir(cwd);

    if isolated {
        cmd.env_clear();
    }

    for entry in &entries {
        if filter.is_none_or(|f| cli::matches_filter(&entry.key, f)) {
            cmd.env(&entry.key, &entry.value);
        }
    }

    // Never leak the store password to child processes.
    cmd.env_remove("ENVSTASH_PASSWORD");

    let status = cmd
        .status()
        .map_err(|e| Error::Other(format!("Failed to execute '{}': {e}", command[0])))?;

    std::process::exit(status.code().unwrap_or(1));
}
