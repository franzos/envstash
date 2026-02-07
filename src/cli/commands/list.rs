use std::path::Path;

use crate::cli::{self, output};
use crate::error::Result;
use crate::store::queries;
use crate::types::SaveMetadata;

/// Run the `list` command: show saved versions for the current project.
pub fn run(
    cwd: &Path,
    branch: Option<&str>,
    commit: Option<&str>,
    max: usize,
    long: bool,
    output_format: &str,
    filter: Option<&str>,
) -> Result<()> {
    let conn = cli::require_store()?;
    let (project_path, git_ctx) = cli::resolve_project(cwd)?;

    let current_branch = git_ctx.as_ref().map(|c| c.branch.as_str());

    // Warn about branch/commit flags in non-git context.
    if git_ctx.is_none() {
        if branch.is_some() {
            eprintln!("warning: Not a git repository, branch options ignored.");
        }
        if commit.is_some() {
            eprintln!("warning: Not a git repository, commit options ignored.");
        }
    }

    // JSON output mode.
    if output_format == "json" {
        let query_branch = if git_ctx.is_some() {
            branch.or(current_branch)
        } else {
            None
        };
        return run_json(&conn, &project_path, query_branch, commit, max, filter);
    }

    // Explicit branch query.
    if branch.is_some() && git_ctx.is_some() {
        let saves = queries::list_saves(&conn, &project_path, branch, commit, max, filter)?;
        if saves.is_empty() {
            println!("No saved versions for branch '{}'.", branch.unwrap_or(""));
        } else {
            print_saves(&saves, 1, long, &project_path, true);
        }
        return Ok(());
    }

    // Explicit commit query.
    if commit.is_some() && git_ctx.is_some() {
        let saves =
            queries::list_saves(&conn, &project_path, None, commit, max, filter)?;
        if saves.is_empty() {
            println!("No saved versions for commit '{}'.", commit.unwrap_or(""));
        } else {
            print_saves(&saves, 1, long, &project_path, true);
        }
        return Ok(());
    }

    // Default view: show header.
    if let Some(ref ctx) = git_ctx {
        println!("-> {}", ctx.branch);
        println!("commit: {}", ctx.commit);
    } else {
        println!("-> {}", project_path);
    }

    // Non-git: show all saves without branch logic.
    if git_ctx.is_none() {
        let saves =
            queries::list_saves(&conn, &project_path, None, None, max, filter)?;
        if saves.is_empty() {
            println!("No saved versions.");
        } else {
            print_saves(&saves, 1, long, &project_path, false);
        }
        return Ok(());
    }

    // Git context: current branch + cross-branch history.
    let cb = current_branch.unwrap_or("");
    let branch_saves =
        queries::list_saves(&conn, &project_path, Some(cb), None, max, filter)?;

    if branch_saves.is_empty() {
        println!("No saved versions of .env file in this branch.");
        let history =
            queries::list_saves_history(&conn, &project_path, cb, max)?;
        if !history.is_empty() {
            println!();
            println!("History:");
            print_saves(&history, 1, long, &project_path, true);
        }
    } else {
        print_saves(&branch_saves, 1, long, &project_path, false);
        let remaining = max.saturating_sub(branch_saves.len());
        if remaining > 0 {
            let history =
                queries::list_saves_history(&conn, &project_path, cb, remaining)?;
            if !history.is_empty() {
                println!();
                println!("History:");
                let start = branch_saves.len() + 1;
                print_saves(&history, start, long, &project_path, true);
            }
        }
    }

    Ok(())
}

/// Format the message suffix for display: " -- message" or "".
fn message_suffix(save: &SaveMetadata) -> String {
    match &save.message {
        Some(m) => format!(" -- {m}"),
        None => String::new(),
    }
}

fn print_saves(
    saves: &[SaveMetadata],
    start_num: usize,
    long: bool,
    project_path: &str,
    show_branch: bool,
) {
    for (i, save) in saves.iter().enumerate() {
        let num = start_num + i;
        let marker = match cli::disk_content_hash(project_path, &save.file_path) {
            Some(ref h) if *h == save.content_hash => "*",
            _ => "",
        };
        let msg = message_suffix(save);

        if long {
            let hash = output::truncate_hash(&save.content_hash);
            if show_branch && !save.branch.is_empty() {
                println!(
                    "{}. {}: {} | {} | {}{}{}",
                    num, save.file_path, save.timestamp, hash, save.branch, marker, msg
                );
            } else {
                println!(
                    "{}. {}: {} | {}{}{}",
                    num, save.file_path, save.timestamp, hash, marker, msg
                );
            }
        } else if show_branch && !save.branch.is_empty() {
            println!(
                "{}. {}: {} / {}{}{}",
                num, save.file_path, save.timestamp, save.branch, marker, msg
            );
        } else {
            println!(
                "{}. {}: {}{}{}",
                num, save.file_path, save.timestamp, marker, msg
            );
        }
    }
}

fn run_json(
    conn: &rusqlite::Connection,
    project_path: &str,
    branch: Option<&str>,
    commit: Option<&str>,
    max: usize,
    filter: Option<&str>,
) -> Result<()> {
    let saves = queries::list_saves(conn, project_path, branch, commit, max, filter)?;

    let json_saves: Vec<serde_json::Value> = saves
        .iter()
        .map(|s| {
            let mut obj = serde_json::json!({
                "file": s.file_path,
                "timestamp": s.timestamp,
                "hash": s.content_hash,
            });
            if !s.branch.is_empty() {
                obj["branch"] = serde_json::json!(s.branch);
            }
            if !s.commit_hash.is_empty() {
                obj["commit"] = serde_json::json!(s.commit_hash);
            }
            obj["message"] = match &s.message {
                Some(m) => serde_json::json!(m),
                None => serde_json::Value::Null,
            };
            obj
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_saves)?);
    Ok(())
}
