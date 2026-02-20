use std::path::Path;

use colored::Colorize;

use crate::cli;
use crate::error::{Error, Result};
use crate::store::queries;

/// Run the `delete` command: remove saved versions from the store.
pub fn run(
    cwd: &Path,
    version: Option<&str>,
    branch: Option<&str>,
    all: bool,
    force: bool,
) -> Result<()> {
    let conn = cli::require_store()?;
    let (project_path, git_ctx) = cli::resolve_project(cwd)?;

    if let Some(b) = branch {
        let saves = queries::list_saves(&conn, &project_path, Some(b), None, 10000, None)?;
        let count = saves.len();

        if count == 0 {
            println!("No saved versions for branch '{b}'.");
            return Ok(());
        }

        if !force && !cli::confirm(&format!("Delete {count} saved versions for branch '{b}'?")) {
            println!("{}", "Aborted.".yellow());
            return Ok(());
        }

        let deleted = queries::delete_saves_by_branch(&conn, &project_path, b)?;
        println!("{}", format!("Deleted {deleted} versions.").green().bold());
        return Ok(());
    }

    if all {
        let saves = queries::list_saves(&conn, &project_path, None, None, 10000, None)?;
        let count = saves.len();

        if count == 0 {
            println!("No saved versions for this project.");
            return Ok(());
        }

        if !force
            && !cli::confirm(&format!(
                "Delete all {count} saved versions for this project?"
            ))
        {
            println!("{}", "Aborted.".yellow());
            return Ok(());
        }

        let deleted = queries::delete_saves_by_project(&conn, &project_path)?;
        println!("{}", format!("Deleted {deleted} versions.").green().bold());
        return Ok(());
    }

    if let Some(v) = version {
        let current_branch = git_ctx.as_ref().map(|c| c.branch.as_str());
        let save = cli::resolve_version(&conn, &project_path, current_branch, v)?;

        if !force {
            let branch_info = if save.branch.is_empty() {
                String::new()
            } else {
                format!(" / {}", save.branch)
            };
            println!(
                "Delete: {} ({}{}).",
                save.file_path, save.timestamp, branch_info
            );
            if !cli::confirm("Proceed?") {
                println!("{}", "Aborted.".yellow());
                return Ok(());
            }
        }

        queries::delete_save(&conn, save.id)?;
        let branch_info = if save.branch.is_empty() {
            String::new()
        } else {
            format!(" / {}", save.branch)
        };
        println!(
            "{} {} ({}{})",
            "Deleted:".green().bold(),
            save.file_path,
            save.timestamp,
            branch_info
        );
        return Ok(());
    }

    Err(Error::Other(
        "Specify a version hash, --branch, or --all.".to_string(),
    ))
}
