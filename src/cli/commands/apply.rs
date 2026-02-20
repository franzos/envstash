use std::path::Path;

use colored::Colorize;

use crate::cli::{self, output};
use crate::error::{Error, Result};
use crate::parser;

/// Run the `apply` command: restore a saved version to disk.
pub fn run(
    cwd: &Path,
    version: &str,
    force: bool,
    dest: Option<&str>,
    key_file: Option<&str>,
) -> Result<()> {
    let conn = cli::require_store()?;
    let aes_key = cli::load_encryption_key(&conn, key_file)?;
    let (project_path, git_ctx) = cli::resolve_project(cwd)?;
    let current_branch = git_ctx.as_ref().map(|c| c.branch.as_str());

    let save = cli::resolve_version(&conn, &project_path, current_branch, version)?;
    let entries = cli::load_entries(&conn, &save, aes_key.as_ref())?;
    let content = parser::serialize(&entries);

    let target_path = match dest {
        Some(d) => Path::new(d).to_path_buf(),
        None => Path::new(&project_path).join(&save.file_path),
    };

    // Validate that the target path stays within the project directory.
    validate_target_path(&target_path, &project_path)?;

    if target_path.exists() && !force {
        let current_content = std::fs::read_to_string(&target_path)?;
        let current_entries = parser::parse(&current_content)?;
        let diff_result = crate::diff::diff(&current_entries, &entries);

        if diff_result.added.is_empty()
            && diff_result.removed.is_empty()
            && diff_result.changed.is_empty()
        {
            println!("{}", "File is identical to saved version.".dimmed());
            return Ok(());
        }

        println!(
            "{}",
            format!("Changes to {}:", target_path.display()).bold()
        );
        print!("{}", output::format_diff_text(&diff_result, false));

        if !cli::confirm("Apply changes?") {
            println!("{}", "Aborted.".yellow());
            return Ok(());
        }
    }

    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&target_path, &content)?;
    println!(
        "{} {}",
        "Applied version to".green().bold(),
        target_path.display()
    );
    Ok(())
}

/// Validate that a target path does not escape the project directory.
///
/// For existing paths, we canonicalize the target itself. For new paths
/// (file doesn't exist yet), we canonicalize the parent directory and
/// append the filename.
fn validate_target_path(target: &Path, project_path: &str) -> Result<()> {
    let project_root = Path::new(project_path).canonicalize().map_err(|e| {
        Error::Other(format!(
            "Cannot resolve project path '{}': {e}",
            project_path
        ))
    })?;

    let resolved = if target.exists() {
        target.canonicalize().map_err(|e| {
            Error::Other(format!(
                "Cannot resolve target path '{}': {e}",
                target.display()
            ))
        })?
    } else {
        // For new files, canonicalize the parent and append the file name.
        let parent = target.parent().unwrap_or(Path::new("."));
        let file_name = target
            .file_name()
            .ok_or_else(|| Error::Other("Invalid target path".to_string()))?;
        let canon_parent = parent.canonicalize().map_err(|e| {
            Error::Other(format!(
                "Cannot resolve parent directory '{}': {e}",
                parent.display()
            ))
        })?;
        canon_parent.join(file_name)
    };

    if !resolved.starts_with(&project_root) {
        return Err(Error::Other(format!(
            "Refusing to write outside project directory: {}",
            target.display()
        )));
    }

    Ok(())
}

/// Check if a file path contains path traversal components (`..`).
pub fn has_path_traversal(file_path: &str) -> bool {
    Path::new(file_path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_detection_dotdot() {
        assert!(has_path_traversal("../../.bashrc"));
        assert!(has_path_traversal("foo/../bar"));
        assert!(has_path_traversal(".."));
    }

    #[test]
    fn traversal_detection_safe() {
        assert!(!has_path_traversal(".env"));
        assert!(!has_path_traversal("apps/backend/.env"));
        assert!(!has_path_traversal("some..file"));
    }

    #[test]
    fn validate_target_within_project() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        // Create a subdirectory to use as target.
        let sub = project.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let target = sub.join(".env");

        let result = validate_target_path(&target, &project.to_string_lossy());
        assert!(result.is_ok());
    }

    #[test]
    fn validate_target_outside_project() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let target = outside.join(".bashrc");

        let result = validate_target_path(&target, &project.to_string_lossy());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Refusing to write outside"));
    }

    #[test]
    fn validate_target_with_dotdot_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let sub = project.join("sub");
        std::fs::create_dir_all(&sub).unwrap();

        // "../" from sub goes to project, then "../" escapes.
        let target = sub.join("../../escape.txt");

        let result = validate_target_path(&target, &project.to_string_lossy());
        assert!(result.is_err());
    }

    #[test]
    fn validate_new_file_in_project() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let target = project.join("new-file.env");

        let result = validate_target_path(&target, &project.to_string_lossy());
        assert!(result.is_ok());
    }
}
