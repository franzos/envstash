pub mod commands;
pub mod output;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use rusqlite::Connection;

use crate::crypto;
use crate::error::{Error, Result};
use crate::git;
use crate::parser;
use crate::store;
use crate::store::queries;
use crate::types::{EnvEntry, GitContext, SaveMetadata};

#[derive(Parser)]
#[command(
    name = "envmgr",
    version,
    about = "Manage .env files across git branches",
    help_template = "\
{about-with-newline}
{usage-heading} {usage}

Daily Operations:
  init       Initialize the envmgr store
  save       Save the current .env file
  list       List saved versions
  diff       Show diff between two versions or files
  apply      Apply a saved version to disk
  env        Print export statements for a saved version
  exec       Run a command with saved environment variables
  history    Show history with diffs between consecutive versions
  delete     Delete saved versions
  global     List all projects with save counts

Sharing:
  share      Share a saved .env version (export to stdout)
  import     Import a shared .env file into the store

Backup & Transfer:
  dump       Export entire store to a file
  load       Import a dump file into the store

Options:
{options}{after-help}"
)]
pub struct Cli {
    /// Path to the encryption key file
    #[arg(long, global = true)]
    pub key_file: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize the envmgr store
    Init {
        /// Encryption mode: none, gpg, or password
        #[arg(long, default_value = "none")]
        encrypt: String,

        /// GPG recipient key ID(s) for --encrypt gpg
        #[arg(long)]
        recipient: Vec<String>,
    },

    /// Save the current .env file
    Save {
        /// Path to the .env file (default: .env)
        file: Option<String>,

        /// Optional message describing this save
        #[arg(short, long)]
        message: Option<String>,
    },

    /// List saved versions
    List {
        /// List versions for a specific branch
        #[arg(short, long)]
        branch: Option<String>,
        /// List versions for a specific commit
        #[arg(short, long)]
        commit: Option<String>,
        /// Maximum number of versions to list
        #[arg(short, long, default_value_t = 5)]
        max: usize,
        /// Show detailed information (hash, branch)
        #[arg(short, long)]
        long: bool,
        /// Output format: text (default) or json
        #[arg(long, default_value = "text")]
        output: String,
        /// Filter by file name pattern (e.g. *.env)
        #[arg(short, long)]
        filter: Option<String>,
    },

    /// Show diff between two versions or files
    Diff {
        /// First version (number, hash, or file path)
        a: String,
        /// Second version (number, hash, or file path)
        b: String,
        /// Show all variables including unchanged
        #[arg(long)]
        full: bool,
        /// Output format: text (default) or json
        #[arg(long, default_value = "text")]
        output: String,
    },

    /// Apply a saved version to disk
    Apply {
        /// Version number or hash
        version: String,
        /// Overwrite without confirmation
        #[arg(long)]
        force: bool,
        /// Write to a different path
        #[arg(long)]
        dest: Option<String>,
    },

    /// Print export statements for a saved version
    Env {
        /// Version number or hash (default: latest)
        version: Option<String>,
        /// Filter variables by pattern (e.g. DB_*)
        #[arg(short, long)]
        filter: Option<String>,
        /// Shell format: bash (default), fish, json
        #[arg(long, default_value = "bash")]
        shell: String,
    },

    /// Run a command with saved environment variables
    Exec {
        /// Version number or hash (optional)
        version: Option<String>,
        /// Filter variables by pattern
        #[arg(short, long)]
        filter: Option<String>,
        /// Only use saved variables, ignore current env
        #[arg(long)]
        isolated: bool,
        /// Command and arguments (after --)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Show history with diffs between consecutive versions
    History {
        /// Filter by branch
        #[arg(short, long)]
        branch: Option<String>,
        /// Filter by commit
        #[arg(short, long)]
        commit: Option<String>,
        /// Maximum number of versions
        #[arg(short, long, default_value_t = 5)]
        max: usize,
        /// Show detailed information
        #[arg(short, long)]
        long: bool,
        /// Filter by file name pattern (e.g. *.env)
        #[arg(short, long)]
        filter: Option<String>,
    },

    /// Delete saved versions
    Delete {
        /// Version number to delete
        version: Option<String>,
        /// Delete all versions for a branch
        #[arg(long)]
        branch: Option<String>,
        /// Delete all versions for the current project
        #[arg(long)]
        all: bool,
        /// Skip confirmation prompts
        #[arg(long)]
        force: bool,
    },

    /// List all projects with save counts
    Global,

    /// Share a saved .env version (export to stdout)
    Share {
        /// File path to share (default: latest saved)
        file: Option<String>,
        /// Lookup by content hash
        #[arg(long)]
        hash: Option<String>,
        /// Bypass safety checks
        #[arg(long)]
        ignore: bool,
        /// Output format: text (default) or json
        #[arg(long, default_value = "text")]
        output: String,
        /// Enable transport encryption for the export
        #[arg(long)]
        encrypt: bool,
        /// Transport encryption method: gpg (default) or password
        #[arg(long, default_value = "gpg")]
        encryption_method: String,
        /// GPG recipient key ID (defaults to git signing key)
        #[arg(long)]
        recipient: Option<String>,
        /// Password for password-based transport encryption (scripted/CI use)
        #[arg(long)]
        password: Option<String>,
        /// Force output even when writing encrypted data to a terminal
        #[arg(long)]
        force: bool,
    },

    /// Import a shared .env file into the store
    Import {
        /// Path to import file (reads from stdin if omitted)
        file: Option<String>,
        /// Password for decrypting password-encrypted imports
        #[arg(long)]
        password: Option<String>,
    },

    /// Export entire store to a file
    Dump {
        /// Path to write the dump file
        path: String,
        /// Enable transport encryption
        #[arg(long)]
        encrypt: bool,
        /// Encryption method: gpg (default) or password
        #[arg(long, default_value = "gpg")]
        encryption_method: String,
        /// GPG recipient key ID(s)
        #[arg(long)]
        recipient: Vec<String>,
        /// Password for password-based encryption
        #[arg(long)]
        password: Option<String>,
    },

    /// Import a dump file into the store
    Load {
        /// Path to the dump file
        path: String,
        /// Password for password-encrypted dumps
        #[arg(long)]
        password: Option<String>,
    },
}

/// Run the CLI application.
pub fn run() -> Result<()> {
    // Disable ANSI colors when stdout is not a terminal (piped/redirected).
    if !output::is_stdout_terminal() {
        colored::control::set_override(false);
    }

    let cli = Cli::parse();
    let cwd = std::env::current_dir()?;
    let key_file = cli.key_file.as_deref();

    match cli.command {
        Commands::Init { encrypt, recipient } => {
            commands::init::run(&encrypt, &recipient, key_file)
        }
        Commands::Save { file, message } => {
            commands::save::run(&cwd, file.as_deref(), key_file, message.as_deref())
        }
        Commands::List {
            branch,
            commit,
            max,
            long,
            output,
            filter,
        } => commands::list::run(
            &cwd,
            branch.as_deref(),
            commit.as_deref(),
            max,
            long,
            &output,
            filter.as_deref(),
        ),
        Commands::Diff { a, b, full, output } => {
            commands::diff::run(&cwd, &a, &b, full, &output, key_file)
        }
        Commands::Apply {
            version,
            force,
            dest,
        } => commands::apply::run(&cwd, &version, force, dest.as_deref(), key_file),
        Commands::Env {
            version,
            filter,
            shell,
        } => commands::env_cmd::run(&cwd, version.as_deref(), filter.as_deref(), &shell, key_file),
        Commands::Exec {
            version,
            filter,
            isolated,
            command,
        } => commands::exec::run(
            &cwd,
            version.as_deref(),
            filter.as_deref(),
            isolated,
            &command,
            key_file,
        ),
        Commands::History {
            branch,
            commit,
            max,
            long,
            filter,
        } => commands::history::run(
            &cwd,
            branch.as_deref(),
            commit.as_deref(),
            max,
            long,
            filter.as_deref(),
            key_file,
        ),
        Commands::Delete {
            version,
            branch,
            all,
            force,
        } => commands::delete::run(
            &cwd,
            version.as_deref(),
            branch.as_deref(),
            all,
            force,
        ),
        Commands::Global => commands::global::run(),
        Commands::Share {
            file,
            hash,
            ignore,
            output,
            encrypt,
            encryption_method,
            recipient,
            password,
            force,
        } => commands::share::run(
            &cwd,
            file.as_deref(),
            hash.as_deref(),
            ignore,
            &output,
            key_file,
            encrypt,
            &encryption_method,
            recipient.as_deref(),
            password.as_deref(),
            force,
        ),
        Commands::Import { file, password } => {
            commands::import::run(&cwd, file.as_deref(), key_file, password.as_deref())
        }
        Commands::Dump {
            path,
            encrypt,
            encryption_method,
            recipient,
            password,
        } => commands::dump::run(
            &path,
            encrypt,
            &encryption_method,
            &recipient,
            password.as_deref(),
            key_file,
        ),
        Commands::Load { path, password } => {
            commands::load::run(&path, password.as_deref(), key_file)
        }
    }
}

// ---------------------------------------------------------------------------
// Shared CLI helpers
// ---------------------------------------------------------------------------

/// Store directory path (~/.local/share/envmgr/).
pub fn store_dir() -> PathBuf {
    let data_dir = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").expect("HOME not set");
            PathBuf::from(home).join(".local/share")
        });
    data_dir.join("envmgr")
}

/// Store database file path.
pub fn store_path() -> PathBuf {
    store_dir().join("store.db")
}

/// Open the store, returning an error if not initialized.
pub fn require_store() -> Result<Connection> {
    let path = store_path();
    if !path.exists() {
        return Err(Error::StoreNotInitialized);
    }
    let conn = store::open(&path)?;
    if !store::is_initialized(&conn)? {
        return Err(Error::StoreNotInitialized);
    }
    Ok(conn)
}

/// Load the encryption key if encryption is enabled in the store.
///
/// Returns `Ok(None)` when encryption mode is "none".
/// Returns `Err(EncryptionKeyRequired)` when encryption is enabled but
/// the key file cannot be found.
pub fn load_encryption_key(
    conn: &Connection,
    key_file_flag: Option<&str>,
) -> Result<Option<[u8; 32]>> {
    let mode_str = queries::get_config(conn, "encryption_mode")?
        .unwrap_or_else(|| "none".to_string());
    let mode: crypto::EncryptionMode = mode_str.parse()?;

    if mode == crypto::EncryptionMode::None {
        return Ok(None);
    }

    let db_key_path = queries::get_config(conn, "key_file")?;
    let env_key_path = std::env::var("ENVMGR_KEY_FILE").ok();

    let key_path = crypto::resolve_key_file(
        key_file_flag.map(Path::new),
        env_key_path.as_deref(),
        db_key_path.as_deref(),
    )
    .unwrap_or_else(|| store_dir().join("key.gpg"));

    let key = crypto::load_key(mode, &key_path)?;
    Ok(Some(key))
}

/// Load entries for a save, handling decryption and HMAC verification.
pub fn load_entries(
    conn: &Connection,
    save: &SaveMetadata,
    aes_key: Option<&[u8; 32]>,
) -> Result<Vec<EnvEntry>> {
    if let Some(key) = aes_key {
        queries::verify_save_hmac(save, key)?;
    }
    queries::get_save_entries(conn, save.id, aes_key)
}

/// Resolve the project path and optional git context for a directory.
pub fn resolve_project(cwd: &Path) -> Result<(String, Option<GitContext>)> {
    let git_ctx = git::detect(cwd)?;
    let project_path = match &git_ctx {
        Some(ctx) => ctx.repo_root.to_string_lossy().to_string(),
        None => cwd.to_string_lossy().to_string(),
    };
    Ok((project_path, git_ctx))
}

/// Compute the relative file path within the project.
pub fn resolve_file_path(
    file: &str,
    cwd: &Path,
    git_ctx: &Option<GitContext>,
) -> Result<String> {
    match git_ctx {
        Some(ctx) => {
            let abs = cwd.join(file);
            let rel = git::relative_path(&abs, &ctx.repo_root)?;
            Ok(rel.to_string_lossy().to_string())
        }
        None => Ok(file.to_string()),
    }
}

/// Build the combined version list (branch saves + cross-branch history).
///
/// Returns `(combined_list, branch_save_count)`.
pub fn build_version_list(
    conn: &Connection,
    project_path: &str,
    current_branch: Option<&str>,
    max: usize,
) -> Result<(Vec<SaveMetadata>, usize)> {
    if let Some(b) = current_branch {
        let branch_saves =
            queries::list_saves(conn, project_path, Some(b), None, max, None)?;
        let branch_count = branch_saves.len();
        let mut result = branch_saves;

        if result.len() < max {
            let remaining = max - result.len();
            let history =
                queries::list_saves_history(conn, project_path, b, remaining)?;
            result.extend(history);
        }

        Ok((result, branch_count))
    } else {
        let saves = queries::list_saves(conn, project_path, None, None, max, None)?;
        let count = saves.len();
        Ok((saves, count))
    }
}

/// Resolve a version reference (1-indexed number or content hash prefix).
pub fn resolve_version(
    conn: &Connection,
    project_path: &str,
    current_branch: Option<&str>,
    version_ref: &str,
) -> Result<SaveMetadata> {
    // Try as a 1-indexed number.
    if let Ok(n) = version_ref.parse::<usize>() {
        if n == 0 {
            return Err(Error::SaveNotFound("0".to_string()));
        }

        let (all, _) = build_version_list(conn, project_path, current_branch, n)?;

        if n <= all.len() {
            return Ok(all[n - 1].clone());
        }
        return Err(Error::SaveNotFound(version_ref.to_string()));
    }

    // Try as a content hash (exact or prefix).
    queries::get_save_by_hash(conn, project_path, version_ref)?
        .ok_or_else(|| Error::SaveNotFound(version_ref.to_string()))
}

/// Compute the content hash of the .env file currently on disk.
pub fn disk_content_hash(project_path: &str, file_path: &str) -> Option<String> {
    let full = PathBuf::from(project_path).join(file_path);
    let content = std::fs::read_to_string(full).ok()?;
    let entries = parser::parse(&content).ok()?;
    Some(parser::content_hash(&entries))
}

/// Prompt the user for yes/no confirmation on stderr.
pub fn confirm(prompt: &str) -> bool {
    use std::io::Write;
    eprint!("{prompt} [y/N] ");
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Check if a variable name matches a simple glob filter pattern.
///
/// Supports `PREFIX*`, `*SUFFIX`, and exact match.
pub fn matches_filter(name: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        name.ends_with(suffix)
    } else {
        name == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_prefix_match() {
        assert!(matches_filter("DB_HOST", "DB_*"));
        assert!(matches_filter("DB_PORT", "DB_*"));
        assert!(!matches_filter("API_KEY", "DB_*"));
    }

    #[test]
    fn filter_suffix_match() {
        assert!(matches_filter("DB_HOST", "*_HOST"));
        assert!(!matches_filter("DB_PORT", "*_HOST"));
    }

    #[test]
    fn filter_exact_match() {
        assert!(matches_filter("KEY", "KEY"));
        assert!(!matches_filter("KEY", "OTHER"));
    }

    #[test]
    fn filter_star_only_matches_everything() {
        assert!(matches_filter("ANYTHING", "*"));
    }

    #[test]
    fn store_dir_uses_xdg() {
        let dir = store_dir();
        assert!(dir.ends_with("envmgr"));
    }
}
