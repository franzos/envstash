use std::path::Path;

use colored::Colorize;
use comfy_table::{Table, presets};

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
        let saves = queries::list_saves(&conn, &project_path, None, commit, max, filter)?;
        if saves.is_empty() {
            println!("No saved versions for commit '{}'.", commit.unwrap_or(""));
        } else {
            print_saves(&saves, 1, long, &project_path, true);
        }
        return Ok(());
    }

    // Default view: show header.
    if let Some(ref ctx) = git_ctx {
        println!("{} {}", "->".bold(), ctx.branch.bold());
        println!("{} {}", "commit:".dimmed(), ctx.commit.dimmed());
    } else {
        println!("{} {}", "->".bold(), project_path.bold());
    }

    // Non-git: show all saves without branch logic.
    if git_ctx.is_none() {
        let saves = queries::list_saves(&conn, &project_path, None, None, max, filter)?;
        if saves.is_empty() {
            println!("No saved versions.");
        } else {
            print_saves(&saves, 1, long, &project_path, false);
        }
        return Ok(());
    }

    // Git context: current branch + cross-branch history.
    let cb = current_branch.unwrap_or("");
    let branch_saves = queries::list_saves(&conn, &project_path, Some(cb), None, max, filter)?;

    if branch_saves.is_empty() {
        println!("No saved versions of .env file in this branch.");
        let history = queries::list_saves_history(&conn, &project_path, cb, max)?;
        if !history.is_empty() {
            println!();
            println!("{}", "History:".bold());
            print_saves(&history, 1, long, &project_path, true);
        }
    } else {
        print_saves(&branch_saves, 1, long, &project_path, false);
        let remaining = max.saturating_sub(branch_saves.len());
        if remaining > 0 {
            let history = queries::list_saves_history(&conn, &project_path, cb, remaining)?;
            if !history.is_empty() {
                println!();
                println!("{}", "History:".bold());
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
        Some(m) => format!(" {}", format!("-- {m}").dimmed().italic()),
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
    if long {
        print_saves_table(saves, start_num, project_path, show_branch);
    } else {
        print_saves_short(saves, start_num, project_path, show_branch);
    }
}

fn print_saves_short(
    saves: &[SaveMetadata],
    start_num: usize,
    project_path: &str,
    show_branch: bool,
) {
    for (i, save) in saves.iter().enumerate() {
        let num = start_num + i;
        let hash = output::short_hash(&save.content_hash);
        let marker = match cli::disk_content_hash(project_path, &save.file_path) {
            Some(ref h) if *h == save.content_hash => format!(" {}", "*".bold().green()),
            _ => String::new(),
        };
        let msg = message_suffix(save);

        if show_branch && !save.branch.is_empty() {
            println!(
                "{}. {} {}: {} / {}{}{}",
                format!("{num}").dimmed(),
                hash.bold(),
                save.file_path,
                save.timestamp.dimmed(),
                save.branch.cyan(),
                marker,
                msg,
            );
        } else {
            println!(
                "{}. {} {}: {}{}{}",
                format!("{num}").dimmed(),
                hash.bold(),
                save.file_path,
                save.timestamp.dimmed(),
                marker,
                msg,
            );
        }
    }
}

fn print_saves_table(
    saves: &[SaveMetadata],
    start_num: usize,
    project_path: &str,
    show_branch: bool,
) {
    let mut table = Table::new();
    table.load_preset(presets::NOTHING);

    if show_branch {
        table.set_header(vec!["#", "Hash", "File", "Timestamp", "Branch", "Msg"]);
    } else {
        table.set_header(vec!["#", "Hash", "File", "Timestamp", "Msg"]);
    }

    for (i, save) in saves.iter().enumerate() {
        let num = format!("{}", start_num + i);
        let marker = match cli::disk_content_hash(project_path, &save.file_path) {
            Some(ref h) if *h == save.content_hash => " *",
            _ => "",
        };
        let hash = format!("{}{marker}", output::short_hash(&save.content_hash));
        let msg = save.message.as_deref().unwrap_or("");

        if show_branch {
            table.add_row(vec![
                &num,
                &hash,
                &save.file_path,
                &save.timestamp,
                &save.branch,
                msg,
            ]);
        } else {
            table.add_row(vec![&num, &hash, &save.file_path, &save.timestamp, msg]);
        }
    }

    println!("{table}");
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
