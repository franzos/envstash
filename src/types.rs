use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A single environment variable entry parsed from a .env file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvEntry {
    /// Optional comment line directly above the variable (without the `#` prefix).
    pub comment: Option<String>,
    /// Variable name.
    pub key: String,
    /// Variable value (raw, including quotes if present in the file).
    pub value: String,
}

/// Git context for the current working directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitContext {
    /// Absolute path to the repository root.
    pub repo_root: PathBuf,
    /// Current branch name (e.g. "main", "feature/foo").
    pub branch: String,
    /// Current commit hash (full SHA).
    pub commit: String,
}

/// Metadata for a saved .env snapshot (no entry values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveMetadata {
    /// Database row id.
    pub id: i64,
    /// Absolute path to the project root.
    pub project_path: String,
    /// Relative path of the .env file within the project.
    pub file_path: String,
    /// Branch name at time of save (empty if non-git).
    pub branch: String,
    /// Commit hash at time of save (empty if non-git).
    pub commit_hash: String,
    /// ISO-8601 timestamp of the save.
    pub timestamp: String,
    /// SHA-256 hash of the parsed content.
    pub content_hash: String,
    /// HMAC-SHA256 of metadata fields (empty when encryption is disabled).
    #[serde(default, skip_serializing)]
    pub hmac: String,
    /// Optional user-provided message describing this save.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Summary of a project for `global` listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSummary {
    /// Absolute path to the project root.
    pub project_path: String,
    /// Number of saved snapshots.
    pub save_count: i64,
    /// Timestamp of the most recent save.
    pub last_save: String,
}

/// Result of diffing two sets of env entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffResult {
    /// Variables present in the new set but not the old.
    pub added: Vec<EnvEntry>,
    /// Variables present in the old set but not the new.
    pub removed: Vec<EnvEntry>,
    /// Variables present in both but with different value or comment: (old, new).
    pub changed: Vec<(EnvEntry, EnvEntry)>,
    /// Variables identical in both sets.
    pub unchanged: Vec<EnvEntry>,
}
