pub mod commands;
pub mod output;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use clap_complete::engine::{ArgValueCompleter, CompletionCandidate};
use rusqlite::{Connection, OpenFlags};

use crate::crypto;
use crate::error::{Error, Result};
use crate::git;
use crate::parser;
use crate::store;
use crate::store::queries;
use crate::types::{EnvEntry, GitContext, SaveMetadata};

// Section text shared between `--help` (static template) and bare `envstash` (dynamic help).
macro_rules! section_setup {
    () => {
        "\
Setup:
  init       Initialize the envstash store"
    };
}

macro_rules! section_daily {
    () => {
        "\
Daily Operations:
  save       Save the current .env file
  ls         List saved versions
  diff       Show diff between two versions or files
  checkout   Apply a saved version to disk
  env        Print export statements for a saved version
  exec       Run a command with saved environment variables
  log        Show history with diffs between consecutive versions
  rm         Delete saved versions
  global     List all projects with save counts"
    };
}

macro_rules! section_sharing {
    () => {
        "\
Sharing:
  send       Send a saved .env version (stdout, paste, gist, email, ssh)
  receive    Receive a shared .env file (stdin, file, URL, gist, ssh)"
    };
}

macro_rules! section_backup {
    () => {
        "\
Backup & Transfer:
  dump       Export entire store to a file
  load       Import a dump file into the store"
    };
}

macro_rules! section_guides {
    () => {
        "\
Guides:
  man        Show usage examples and detailed guide"
    };
}

macro_rules! section_completion_tip {
    () => {
        "\
Tip: Enable tab completion \u{2192} source <(COMPLETE=bash envstash)
     More shells: https://github.com/franzos/envstash#tab-completion"
    };
}

#[derive(Parser)]
#[command(
    name = "envstash",
    version,
    about = "Manage .env files across git branches",
    help_template = concat!("\
{about-with-newline}
{usage-heading} {usage}

", section_setup!(), "

", section_daily!(), "

", section_sharing!(), "

", section_backup!(), "

", section_guides!(), "

Options:
{options}

", section_completion_tip!(), "
")
)]
pub struct Cli {
    /// Path to the encryption key file
    #[arg(long, global = true)]
    pub key_file: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize the envstash store
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
    #[command(name = "ls", alias = "list")]
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
        /// First version (hash prefix or file path)
        #[arg(add = ArgValueCompleter::new(complete_version))]
        a: String,
        /// Second version (hash prefix or file path)
        #[arg(add = ArgValueCompleter::new(complete_version))]
        b: String,
        /// Show all variables including unchanged
        #[arg(long)]
        full: bool,
        /// Output format: text (default) or json
        #[arg(long, default_value = "text")]
        output: String,
    },

    /// Apply a saved version to disk
    #[command(name = "checkout", alias = "co", alias = "apply")]
    Apply {
        /// Version hash (prefix match supported)
        #[arg(add = ArgValueCompleter::new(complete_version))]
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
        /// Version hash (default: latest, prefix match supported)
        #[arg(add = ArgValueCompleter::new(complete_version))]
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
        /// Version hash (optional, prefix match supported)
        #[arg(add = ArgValueCompleter::new(complete_version))]
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
    #[command(name = "log", alias = "history")]
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
    #[command(name = "rm", alias = "delete")]
    Delete {
        /// Version hash to delete (prefix match supported)
        #[arg(add = ArgValueCompleter::new(complete_version))]
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

    /// Send a saved .env version (export to stdout)
    #[command(
        name = "send",
        alias = "share",
        long_about = "Send a saved .env version.\n\n\
        By default, outputs to stdout. Use --to to send via a transport backend:\n\n  \
        --to                       Upload to 0x0.st (or config default)\n  \
        --to https://my.paste.srv  Upload to a custom paste service\n  \
        --to gist                  Create a GitHub Gist via gh CLI\n  \
        --to email:<address>       Send via msmtp or sendmail\n  \
        --to ssh://user@host       Pipe to remote envstash receive via SSH\n\n\
        Configure defaults and auth in ~/.config/envstash/config.toml:\n\n  \
        [send]\n  \
        default_to = \"https://my.paste.service\"\n\n  \
        [send.headers]\n  \
        Authorization = \"Bearer mytoken\""
    )]
    Send {
        /// File path to send (default: latest saved)
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
        /// GPG recipient key ID(s) for transport encryption
        #[arg(long)]
        recipient: Vec<String>,
        /// Password for password-based transport encryption (scripted/CI use)
        #[arg(long)]
        password: Option<String>,
        /// Force output even when writing encrypted data to a terminal
        #[arg(long)]
        force: bool,
        /// Send to a remote target instead of stdout
        #[arg(long, value_name = "TARGET", default_missing_value = "", num_args = 0..=1)]
        to: Option<String>,
        /// Create a public gist (default: secret). Only used with --to gist.
        #[arg(long)]
        public: bool,
    },

    /// Receive a shared .env file into the store
    #[command(
        name = "receive",
        alias = "import",
        long_about = "Receive a shared .env file into the store.\n\n\
        By default, reads from a file or stdin. Use --from to fetch via a transport backend:\n\n  \
        --from https://<url>       Fetch via curl (paste URLs, raw gist URLs, etc.)\n  \
        --from ssh://user@host     Pipe from remote envstash send via SSH"
    )]
    Receive {
        /// Path to file (reads from stdin if omitted)
        file: Option<String>,
        /// Password for decrypting password-encrypted imports
        #[arg(long)]
        password: Option<String>,
        /// Fetch from a remote source instead of stdin/file
        #[arg(long, value_name = "SOURCE")]
        from: Option<String>,
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

    /// Show detailed usage guide with examples
    #[command(name = "man")]
    Man,
}

/// Run the CLI application.
pub fn run() -> Result<()> {
    // Disable ANSI colors when stdout is not a terminal (piped/redirected).
    if !output::is_stdout_terminal() {
        colored::control::set_override(false);
    }

    let cli = Cli::parse();

    match cli.command {
        None => {
            print_dynamic_help();
            Ok(())
        }
        Some(Commands::Man) => {
            print_manpage();
            Ok(())
        }
        Some(cmd) => run_command(cmd, cli.key_file.as_deref()),
    }
}

fn run_command(cmd: Commands, key_file: Option<&str>) -> Result<()> {
    let cwd = std::env::current_dir()?;

    match cmd {
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
        } => commands::env_cmd::run(
            &cwd,
            version.as_deref(),
            filter.as_deref(),
            &shell,
            key_file,
        ),
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
        } => commands::delete::run(&cwd, version.as_deref(), branch.as_deref(), all, force),
        Commands::Global => commands::global::run(),
        Commands::Send {
            file,
            hash,
            ignore,
            output,
            encrypt,
            encryption_method,
            recipient,
            password,
            force,
            to,
            public,
        } => commands::send::run(
            file.as_deref(),
            hash.as_deref(),
            ignore,
            &output,
            key_file,
            encrypt,
            &encryption_method,
            &recipient,
            password.as_deref(),
            force,
            to.as_deref(),
            public,
        ),
        Commands::Receive {
            file,
            password,
            from,
        } => commands::receive::run(
            &cwd,
            file.as_deref(),
            key_file,
            password.as_deref(),
            from.as_deref(),
        ),
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
        Commands::Man => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Dynamic help & manpage
// ---------------------------------------------------------------------------

/// Check if the store at `path` is initialized (read-only, non-failing).
fn is_store_initialized_at(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let conn = match Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c,
        Err(_) => return false,
    };
    store::is_initialized(&conn).unwrap_or(false)
}

fn is_store_initialized() -> bool {
    is_store_initialized_at(&store_path())
}

/// Check if any of the given RC files contain envstash completion config.
fn is_completion_configured_in(paths: &[PathBuf]) -> bool {
    for path in paths {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if contents.contains("COMPLETE=") && contents.contains("envstash") {
                return true;
            }
        }
    }
    false
}

fn is_completion_configured() -> bool {
    let home = match std::env::var("HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => return false,
    };
    let candidates = [
        home.join(".bashrc"),
        home.join(".bash_profile"),
        home.join(".zshrc"),
        home.join(".config/fish/config.fish"),
    ];
    is_completion_configured_in(&candidates)
}

/// Build the dynamic help text. Separate from printing so it can be tested.
fn build_dynamic_help(initialized: bool, completions: bool) -> String {
    let mut out = String::new();

    out.push_str(
        "Manage .env files across git branches\n\nUsage: envstash [OPTIONS] <COMMAND>\n\n",
    );

    if !initialized {
        out.push_str(section_setup!());
        out.push_str("\n\n");
    }

    out.push_str(section_daily!());
    out.push_str("\n\n");
    out.push_str(section_sharing!());
    out.push_str("\n\n");
    out.push_str(section_backup!());
    out.push_str("\n\n");
    out.push_str(section_guides!());
    out.push_str("\n\n");
    out.push_str("Options:\n");
    out.push_str("      --key-file <KEY_FILE>  Path to the encryption key file\n");
    out.push_str("  -h, --help                 Print help\n");
    out.push_str("  -V, --version              Print version");

    if !completions {
        out.push_str("\n\n");
        out.push_str(section_completion_tip!());
    }
    out.push('\n');

    out
}

fn print_dynamic_help() {
    let initialized = is_store_initialized();
    let completions = is_completion_configured();
    print!("{}", build_dynamic_help(initialized, completions));
}

fn print_manpage() {
    print!(
        "\
ENVSTASH(1)                    User Commands

NAME
    envstash - manage .env files across git branches

SYNOPSIS
    envstash [OPTIONS] <COMMAND>

EXAMPLES
    Getting started:
      envstash init                          Initialize the store
      envstash init --encrypt password       Initialize with password encryption
      envstash init --encrypt gpg            Initialize with GPG encryption

    Saving and restoring:
      envstash save                          Save current .env
      envstash save -m \"new DB config\"       Save with a message
      envstash ls                            List saved versions
      envstash checkout abcdef12             Restore version by hash prefix
      envstash checkout 1                    Restore by number (latest = 1)

    Comparing:
      envstash diff 1 2                      Diff two versions
      envstash diff abcdef12 .env            Diff a version against current file
      envstash log                           Show history with diffs

    Shell integration:
      eval $(envstash env)                   Load variables into current shell
      envstash exec -- npm start             Run command with saved env
      envstash exec --isolated -- npm test   Run with only saved env (clean)

    Sharing:
      envstash send > export.env             Export to stdout
      envstash send --to                     Upload to paste service
      envstash send --to gist                Create a GitHub Gist
      envstash receive export.env            Import from file
      envstash receive --from <url>          Fetch from URL

    Backup:
      envstash dump backup.json              Full store export
      envstash load backup.json              Import a dump

    Tab completion:
      source <(COMPLETE=bash envstash)       Bash
      source <(COMPLETE=zsh envstash)        Zsh
      source (COMPLETE=fish envstash | psub) Fish

FILES
    ~/.local/share/envstash/store.db         Version database
    ~/.local/share/envstash/key.gpg          Encryption key (if enabled)
    ~/.config/envstash/config.toml           Configuration

SEE ALSO
    https://github.com/franzos/envstash
"
    );
}

// ---------------------------------------------------------------------------
// Shared CLI helpers
// ---------------------------------------------------------------------------

/// Store directory path (~/.local/share/envstash/).
pub fn store_dir() -> PathBuf {
    let data_dir = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").expect("HOME not set");
            PathBuf::from(home).join(".local/share")
        });
    data_dir.join("envstash")
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
    let mode_str =
        queries::get_config(conn, "encryption_mode")?.unwrap_or_else(|| "none".to_string());
    let mode: crypto::EncryptionMode = mode_str.parse()?;

    if mode == crypto::EncryptionMode::None {
        return Ok(None);
    }

    let db_key_path = queries::get_config(conn, "key_file")?;
    let env_key_path = std::env::var("ENVSTASH_KEY_FILE").ok();

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
pub fn resolve_file_path(file: &str, cwd: &Path, git_ctx: &Option<GitContext>) -> Result<String> {
    match git_ctx {
        Some(ctx) => {
            let abs = cwd.join(file);
            let rel = git::relative_path(&abs, &ctx.repo_root)?;
            Ok(rel.to_string_lossy().to_string())
        }
        None => Ok(file.to_string()),
    }
}

/// Resolve a version reference (content hash prefix, or 1-indexed number as fallback).
pub fn resolve_version(
    conn: &Connection,
    project_path: &str,
    current_branch: Option<&str>,
    version_ref: &str,
) -> Result<SaveMetadata> {
    // Try hash prefix first (primary).
    if let Some(save) = queries::get_save_by_hash(conn, project_path, version_ref)? {
        return Ok(save);
    }

    // Fallback: try as a 1-indexed number.
    if let Ok(n) = version_ref.parse::<usize>() {
        if n == 0 {
            return Err(Error::SaveNotFound("0".to_string()));
        }
        let saves = queries::list_saves(conn, project_path, current_branch, None, n, None)?;
        if n <= saves.len() {
            return Ok(saves[n - 1].clone());
        }
    }

    Err(Error::SaveNotFound(version_ref.to_string()))
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

/// Shell completion: suggest saved version hashes for the current project.
fn complete_version(current: &std::ffi::OsStr) -> Vec<CompletionCandidate> {
    let prefix = current.to_string_lossy();
    let conn = match require_store() {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(_) => return vec![],
    };
    let (project_path, _) = match resolve_project(&cwd) {
        Ok(p) => p,
        Err(_) => return vec![],
    };

    let saves = match queries::list_saves(&conn, &project_path, None, None, 50, None) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    saves
        .into_iter()
        .filter(|s| s.content_hash.starts_with(prefix.as_ref()))
        .map(|s| {
            let hash = output::short_hash(&s.content_hash);
            let help = match &s.message {
                Some(m) => format!("{} -- {m}", s.timestamp),
                None => s.timestamp.clone(),
            };
            CompletionCandidate::new(hash).help(Some(help.into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        assert!(dir.ends_with("envstash"));
    }

    // -- is_store_initialized_at ----------------------------------------

    #[test]
    fn store_initialized_false_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("store.db");
        assert!(!is_store_initialized_at(&db));
    }

    #[test]
    fn store_initialized_false_when_empty_db() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("store.db");
        // Create an empty file — not a valid SQLite database.
        fs::write(&db, b"").unwrap();
        assert!(!is_store_initialized_at(&db));
    }

    #[test]
    fn store_initialized_true_after_init() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("store.db");
        let conn = store::open(&db).unwrap();
        store::init(&conn, "none").unwrap();
        drop(conn);
        assert!(is_store_initialized_at(&db));
    }

    #[test]
    fn store_initialized_false_for_migrated_but_not_inited() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("store.db");
        // open() runs migrations but doesn't call init().
        let conn = store::open(&db).unwrap();
        drop(conn);
        assert!(!is_store_initialized_at(&db));
    }

    // -- is_completion_configured_in ------------------------------------

    #[test]
    fn completion_configured_false_when_no_files() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = [tmp.path().join(".bashrc"), tmp.path().join(".zshrc")];
        assert!(!is_completion_configured_in(&paths));
    }

    #[test]
    fn completion_configured_false_without_pattern() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".bashrc");
        fs::write(&rc, "alias ls='ls --color'\n").unwrap();
        assert!(!is_completion_configured_in(&[rc]));
    }

    #[test]
    fn completion_configured_true_with_bash_pattern() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".bashrc");
        fs::write(&rc, "source <(COMPLETE=bash envstash)\n").unwrap();
        assert!(is_completion_configured_in(&[rc]));
    }

    #[test]
    fn completion_configured_true_with_fish_pattern() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join("config.fish");
        fs::write(&rc, "source (COMPLETE=fish envstash | psub)\n").unwrap();
        assert!(is_completion_configured_in(&[rc]));
    }

    #[test]
    fn completion_configured_needs_both_keywords() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".bashrc");
        // Has COMPLETE= but not envstash.
        fs::write(&rc, "COMPLETE=bash othertool\n").unwrap();
        assert!(!is_completion_configured_in(&[rc]));
    }

    // -- build_dynamic_help ---------------------------------------------

    #[test]
    fn dynamic_help_shows_setup_when_not_initialized() {
        let help = build_dynamic_help(false, true);
        assert!(help.contains("Setup:"));
        assert!(help.contains("  init"));
    }

    #[test]
    fn dynamic_help_hides_setup_when_initialized() {
        let help = build_dynamic_help(true, true);
        assert!(!help.contains("Setup:"));
        assert!(!help.contains("  init"));
    }

    #[test]
    fn dynamic_help_shows_completion_tip_when_not_configured() {
        let help = build_dynamic_help(true, false);
        assert!(help.contains("Tip:"));
        assert!(help.contains("COMPLETE=bash"));
    }

    #[test]
    fn dynamic_help_hides_completion_tip_when_configured() {
        let help = build_dynamic_help(true, true);
        assert!(!help.contains("Tip:"));
    }

    #[test]
    fn dynamic_help_always_shows_core_sections() {
        let help = build_dynamic_help(true, true);
        assert!(help.contains("Daily Operations:"));
        assert!(help.contains("Sharing:"));
        assert!(help.contains("Backup & Transfer:"));
        assert!(help.contains("Guides:"));
        assert!(help.contains("  man"));
    }

    // -- manpage --------------------------------------------------------

    #[test]
    fn manpage_contains_expected_sections() {
        // Can't easily capture print!(), so verify the source has the headings.
        let content = include_str!("mod.rs");
        for heading in [
            "ENVSTASH(1)",
            "NAME",
            "SYNOPSIS",
            "EXAMPLES",
            "FILES",
            "SEE ALSO",
        ] {
            assert!(
                content.contains(heading),
                "missing manpage heading: {heading}"
            );
        }
    }
}
