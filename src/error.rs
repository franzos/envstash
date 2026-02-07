use std::path::PathBuf;

/// All errors produced by envmgr.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("migration error: {0}")]
    Migration(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("parse error at line {line}: {message}")]
    Parse { line: usize, message: String },

    #[error("file not found: {0}")]
    FileNotFound(PathBuf),

    #[error("store not initialized. Run `envmgr init` first.")]
    StoreNotInitialized,

    #[error("store already initialized. Use `envmgr rekey` to change encryption.")]
    StoreAlreadyInitialized,

    #[error("not a git repository")]
    NotAGitRepo,

    #[error("git error: {0}")]
    Git(#[from] git2::Error),

    #[error("save not found: {0}")]
    SaveNotFound(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("GPG error: {0}")]
    Gpg(String),

    #[error("GPG not available")]
    GpgNotAvailable,

    #[error("no GPG recipient specified and no git signing key configured")]
    NoGpgRecipient,

    #[error("password required but not provided")]
    PasswordRequired,

    #[error("HMAC verification failed: metadata may have been tampered with")]
    HmacMismatch,

    #[error("key file not found: {0}")]
    KeyFileNotFound(PathBuf),

    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Encryption key required. Provide via --key-file or ENVMGR_KEY_FILE.")]
    EncryptionKeyRequired,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
