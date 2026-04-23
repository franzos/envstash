use std::path::Path;

use colored::Colorize;

use crate::cli::{self, output};
use crate::error::Result;
use crate::store::queries;
use crate::types::EnvEntry;

/// Run the `history` command: show consecutive diffs between saved versions.
pub fn run(
    cwd: &Path,
    branch: Option<&str>,
    commit: Option<&str>,
    max: usize,
    _long: bool,
    filter: Option<&str>,
    key_file: Option<&str>,
) -> Result<()> {
    let conn = cli::require_store()?;
    let aes_key = cli::load_encryption_key(&conn, key_file)?;
    let (project_path, git_ctx) = cli::resolve_project(cwd)?;

    let query_branch = if git_ctx.is_some() {
        branch.or(git_ctx.as_ref().map(|c| c.branch.as_str()))
    } else {
        None
    };

    let saves = queries::list_saves(&conn, &project_path, query_branch, commit, max, filter)?;

    if saves.is_empty() {
        println!("No saved versions found.");
        return Ok(());
    }

    // Decrypt each save's entries exactly once by carrying the previous
    // iteration's `entries_new` forward as the next iteration's `entries_old`.
    let mut prev_entries: Option<Vec<EnvEntry>> = None;

    for (i, save) in saves.iter().enumerate() {
        let num = i + 1;
        let hash = output::short_hash(&save.content_hash);
        let branch_label = if save.branch.is_empty() {
            String::new()
        } else {
            format!(" | {}", save.branch.cyan())
        };
        let msg = match &save.message {
            Some(m) => format!(" {}", format!("-- {m}").dimmed().italic()),
            None => String::new(),
        };

        println!(
            "{}. {} {}: {}{}{}",
            format!("{num}").dimmed(),
            hash.bold(),
            save.file_path,
            save.timestamp.dimmed(),
            branch_label,
            msg,
        );

        // For the diff between this version (newer) and the next one (older),
        // fetch entries_new once and reuse the previous iteration's value
        // as entries_new-from-last-loop (which becomes our entries_old here).
        if i + 1 < saves.len() {
            let entries_new = match prev_entries.take() {
                Some(e) => e,
                None => cli::load_entries(&conn, save, aes_key.as_deref())?,
            };
            let entries_old = cli::load_entries(&conn, &saves[i + 1], aes_key.as_deref())?;
            let diff_result = crate::diff::diff(&entries_old, &entries_new);

            let diff_text = output::format_diff_text(&diff_result, false);
            if !diff_text.is_empty() {
                print!("{diff_text}");
            }
            println!("{}", "---".dimmed());

            // Carry entries_old forward as the next loop's entries_new.
            prev_entries = Some(entries_old);
        }
    }

    Ok(())
}
