use std::path::Path;

use crate::cli;
use crate::error::{Error, Result};
use crate::store::queries;

/// Run the `env` command: print export statements for a saved version.
pub fn run(
    cwd: &Path,
    version: Option<&str>,
    filter: Option<&str>,
    shell: &str,
    key_file: Option<&str>,
) -> Result<()> {
    let conn = cli::require_store()?;
    let aes_key = cli::load_encryption_key(&conn, key_file)?;
    let (project_path, git_ctx) = cli::resolve_project(cwd)?;
    let current_branch = git_ctx.as_ref().map(|c| c.branch.as_str());

    let entries = if let Some(v) = version {
        let save = cli::resolve_version(&conn, &project_path, current_branch, v)?;
        cli::load_entries(&conn, &save, aes_key.as_ref())?
    } else {
        // Default: latest on current branch.
        let branch = current_branch.unwrap_or("");
        let saves = queries::list_saves(&conn, &project_path, Some(branch), None, 1, None)?;
        let save = saves
            .first()
            .ok_or_else(|| Error::SaveNotFound("no saves on current branch".to_string()))?;
        cli::load_entries(&conn, save, aes_key.as_ref())?
    };

    let filtered: Vec<_> = entries
        .iter()
        .filter(|e| filter.is_none_or(|f| cli::matches_filter(&e.key, f)))
        .collect();

    match shell {
        "bash" => {
            for entry in &filtered {
                println!("export {}='{}'", entry.key, shell_escape_bash(&entry.value));
            }
        }
        "fish" => {
            for entry in &filtered {
                println!("set -x {} '{}'", entry.key, shell_escape_fish(&entry.value));
            }
        }
        "json" => {
            let map: serde_json::Map<String, serde_json::Value> = filtered
                .iter()
                .map(|e| (e.key.clone(), serde_json::Value::String(e.value.clone())))
                .collect();
            println!("{}", serde_json::to_string_pretty(&map)?);
        }
        other => {
            return Err(Error::Other(format!("Unknown shell format: {other}")));
        }
    }

    Ok(())
}

/// Escape a value for safe use inside bash single quotes.
///
/// Single quotes in bash cannot contain literal single quotes, so we end the
/// quoted string, insert an escaped single quote, and restart the quoted string:
/// `'` becomes `'\''`.
fn shell_escape_bash(value: &str) -> String {
    value.replace('\'', "'\\''")
}

/// Escape a value for safe use inside fish single quotes.
///
/// In fish, single quotes support backslash escaping of `'` and `\`:
/// `'` becomes `\'`.
fn shell_escape_fish(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_escape_simple() {
        assert_eq!(shell_escape_bash("hello"), "hello");
    }

    #[test]
    fn bash_escape_single_quote() {
        assert_eq!(shell_escape_bash("it's"), "it'\\''s");
    }

    #[test]
    fn bash_escape_double_quote() {
        assert_eq!(shell_escape_bash("say \"hi\""), "say \"hi\"");
    }

    #[test]
    fn bash_escape_dollar_subst() {
        assert_eq!(shell_escape_bash("$(rm -rf /)"), "$(rm -rf /)");
    }

    #[test]
    fn bash_escape_backtick() {
        assert_eq!(shell_escape_bash("`whoami`"), "`whoami`");
    }

    #[test]
    fn bash_escape_spaces() {
        assert_eq!(shell_escape_bash("hello world"), "hello world");
    }

    #[test]
    fn bash_escape_newline() {
        assert_eq!(shell_escape_bash("line1\nline2"), "line1\nline2");
    }

    #[test]
    fn bash_escape_combined() {
        // A value with single quotes, dollar subst, and backticks.
        let input = "it's $(dangerous) `stuff`";
        let escaped = shell_escape_bash(input);
        assert_eq!(escaped, "it'\\''s $(dangerous) `stuff`");
    }

    #[test]
    fn fish_escape_simple() {
        assert_eq!(shell_escape_fish("hello"), "hello");
    }

    #[test]
    fn fish_escape_single_quote() {
        assert_eq!(shell_escape_fish("it's"), "it\\'s");
    }

    #[test]
    fn fish_escape_backslash() {
        assert_eq!(shell_escape_fish("path\\to\\file"), "path\\\\to\\\\file");
    }

    #[test]
    fn fish_escape_dollar_subst() {
        assert_eq!(shell_escape_fish("$(rm -rf /)"), "$(rm -rf /)");
    }

    #[test]
    fn fish_escape_backtick() {
        assert_eq!(shell_escape_fish("`whoami`"), "`whoami`");
    }

    #[test]
    fn fish_escape_spaces() {
        assert_eq!(shell_escape_fish("hello world"), "hello world");
    }

    #[test]
    fn fish_escape_newline() {
        assert_eq!(shell_escape_fish("line1\nline2"), "line1\nline2");
    }

    #[test]
    fn fish_escape_combined() {
        let input = "it's a \\path";
        let escaped = shell_escape_fish(input);
        assert_eq!(escaped, "it\\'s a \\\\path");
    }

    #[test]
    fn bash_output_format() {
        // Verify the full output line format for bash.
        let key = "DB_HOST";
        let value = "local'host";
        let line = format!("export {}='{}'", key, shell_escape_bash(value));
        assert_eq!(line, "export DB_HOST='local'\\''host'");
    }

    #[test]
    fn fish_output_format() {
        // Verify the full output line format for fish.
        let key = "DB_HOST";
        let value = "local'host";
        let line = format!("set -x {} '{}'", key, shell_escape_fish(value));
        assert_eq!(line, "set -x DB_HOST 'local\\'host'");
    }
}
