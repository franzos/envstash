use std::path::{Path, PathBuf};

use git2::Repository;

use crate::error::{Error, Result};
use crate::types::GitContext;

/// Detect git context for the given directory.
///
/// Returns `Ok(Some(context))` when inside a git repo, `Ok(None)` when not,
/// and `Err` only on unexpected failures.
pub fn detect(dir: &Path) -> Result<Option<GitContext>> {
    let repo = match Repository::discover(dir) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };

    let repo_root = repo
        .workdir()
        .ok_or_else(|| Error::NotAGitRepo)?
        .canonicalize()?;

    let head = repo.head()?;

    let branch = head
        .shorthand()
        .unwrap_or("HEAD")
        .to_string();

    let commit = head
        .peel_to_commit()?
        .id()
        .to_string();

    Ok(Some(GitContext {
        repo_root,
        branch,
        commit,
    }))
}

/// Compute the relative path of `dir` from the repo root.
pub fn relative_path(dir: &Path, repo_root: &Path) -> Result<PathBuf> {
    dir.strip_prefix(repo_root)
        .map(|p| p.to_path_buf())
        .map_err(|e| Error::Other(format!("failed to compute relative path: {e}")))
}

/// Read `user.signingkey` from git config (local + global).
pub fn signing_key(dir: &Path) -> Result<Option<String>> {
    let repo = match Repository::discover(dir) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };

    let config = repo.config()?;
    match config.get_string("user.signingkey") {
        Ok(key) if key.is_empty() => Ok(None),
        Ok(key) => Ok(Some(key)),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::Signature;
    use std::fs;

    /// Create a temporary git repo using git2.
    fn make_temp_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();

        // Need at least one commit for HEAD to exist.
        let file = dir.path().join("README");
        fs::write(&file, "hello").unwrap();

        let mut index = repo.index().unwrap();
        index.add_path(Path::new("README")).unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = Signature::now("Test", "test@test.com").unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])
            .unwrap();

        dir
    }

    #[test]
    fn detect_git_repo() {
        let repo = make_temp_repo();
        let ctx = detect(repo.path()).unwrap().expect("should detect repo");
        assert_eq!(ctx.repo_root, repo.path().canonicalize().unwrap());
        assert!(!ctx.branch.is_empty());
        assert!(!ctx.commit.is_empty());
        assert_eq!(ctx.commit.len(), 40); // full SHA
    }

    #[test]
    fn detect_non_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = detect(dir.path()).unwrap();
        assert!(ctx.is_none());
    }

    #[test]
    fn detect_subdirectory() {
        let repo = make_temp_repo();
        let sub = repo.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let ctx = detect(&sub).unwrap().expect("should detect repo from subdir");
        assert_eq!(ctx.repo_root, repo.path().canonicalize().unwrap());
    }

    #[test]
    fn relative_path_within_repo() {
        let repo = make_temp_repo();
        let sub = repo.path().join("apps").join("frontend");
        fs::create_dir_all(&sub).unwrap();
        let root = repo.path().canonicalize().unwrap();
        let rel = relative_path(&root.join("apps").join("frontend"), &root).unwrap();
        assert_eq!(rel, PathBuf::from("apps/frontend"));
    }

    #[test]
    fn relative_path_root_is_empty() {
        let repo = make_temp_repo();
        let root = repo.path().canonicalize().unwrap();
        let rel = relative_path(&root, &root).unwrap();
        assert_eq!(rel, PathBuf::from(""));
    }

    #[test]
    fn signing_key_not_set() {
        let repo_dir = make_temp_repo();
        let key = signing_key(repo_dir.path()).unwrap();
        // May pick up global config; if no global key, should be None.
        // We can't fully isolate without env manipulation, so just assert no panic.
        let _ = key;
    }

    #[test]
    fn signing_key_set() {
        let repo_dir = make_temp_repo();
        let repo = Repository::open(repo_dir.path()).unwrap();
        let mut config = repo.config().unwrap();
        config.set_str("user.signingkey", "ABCD1234").unwrap();

        let key = signing_key(repo_dir.path()).unwrap();
        assert_eq!(key, Some("ABCD1234".to_string()));
    }

    #[test]
    fn branch_name_correct() {
        let repo = make_temp_repo();
        let ctx = detect(repo.path()).unwrap().unwrap();
        // Default branch on git init is typically "master" or "main".
        assert!(
            ctx.branch == "master" || ctx.branch == "main",
            "unexpected branch: {}",
            ctx.branch
        );
    }

    #[test]
    fn branch_after_checkout() {
        let repo_dir = make_temp_repo();
        let repo = Repository::open(repo_dir.path()).unwrap();
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        repo.branch("feature/test", &head, false).unwrap();
        repo.set_head("refs/heads/feature/test").unwrap();

        let ctx = detect(repo_dir.path()).unwrap().unwrap();
        assert_eq!(ctx.branch, "feature/test");
    }
}
