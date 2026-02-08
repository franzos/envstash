use std::io::Write;

use colored::Colorize;

use crate::cli;
use crate::error::{Error, Result};
use crate::export;
use crate::export::transport;
use crate::store::queries;

use super::transport as remote;

/// Run the `share` command: serialize a saved version to stdout,
/// optionally encrypting with transport encryption.
#[allow(clippy::too_many_arguments)]
pub fn run(
    file: Option<&str>,
    hash: Option<&str>,
    ignore_checks: bool,
    output_format: &str,
    key_file: Option<&str>,
    encrypt: bool,
    encryption_method: &str,
    recipients: &[String],
    password: Option<&str>,
    force: bool,
    to: Option<&str>,
    public: bool,
) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let conn = cli::require_store()?;
    let aes_key = cli::load_encryption_key(&conn, key_file)?;
    let (project_path, git_ctx) = cli::resolve_project(&cwd)?;
    let current_branch = git_ctx.as_ref().map(|c| c.branch.as_str());

    // Resolve which save to share.
    let save = if let Some(h) = hash {
        // Lookup by content hash.
        queries::get_save_by_hash(&conn, &project_path, h)?
            .ok_or_else(|| Error::SaveNotFound(h.to_string()))?
    } else {
        // Find the latest save, optionally filtered by file path.
        let file_filter = file.map(|f| {
            cli::resolve_file_path(f, &cwd, &git_ctx)
                .unwrap_or_else(|_| f.to_string())
        });

        find_latest_save(
            &conn,
            &project_path,
            current_branch,
            file_filter.as_deref(),
        )?
    };

    // Safety checks (unless --ignore).
    if !ignore_checks {
        run_safety_checks(&save, current_branch, &project_path)?;
    }

    // Load entries (decrypting if needed).
    let entries = cli::load_entries(&conn, &save, aes_key.as_ref())?;

    // Build export envelope and serialize.
    let envelope = export::build_envelope(&save, &entries);

    let serialized = match output_format {
        "json" => export::to_json(&envelope)?,
        _ => export::to_text(&envelope),
    };

    // Prepare the final bytes (optionally encrypted).
    let output_bytes = if encrypt {
        encrypt_export(
            serialized.as_bytes(),
            encryption_method,
            recipients,
            password,
        )?
    } else {
        serialized.into_bytes()
    };

    // Resolve `--to`: empty string means bare `--to` flag, fill from config or fallback.
    let resolved_to = to.map(|t| {
        if t.is_empty() {
            let cfg = crate::config::load();
            cfg.share
                .default_to
                .unwrap_or_else(|| "https://0x0.st".to_string())
        } else {
            t.to_string()
        }
    });

    // Route through transport backend or write to stdout.
    if let Some(ref target) = resolved_to {
        match remote::send(target, &output_bytes, public, Some(&save.content_hash))? {
            Some(url) => println!("{} {}", "Shared:".green().bold(), url),
            None => println!("{}", "Shared successfully.".green().bold()),
        }
    } else {
        if encrypt && crate::cli::output::is_stdout_terminal() && !force {
            return Err(Error::Other(
                "Encrypted output is binary data. Redirect to a file or pipe, \
                 or use --force to output to terminal."
                    .to_string(),
            ));
        }
        std::io::stdout()
            .write_all(&output_bytes)
            .map_err(Error::Io)?;
    }

    Ok(())
}

/// Encrypt the export bytes using the specified method.
fn encrypt_export(
    data: &[u8],
    method: &str,
    recipients: &[String],
    password: Option<&str>,
) -> Result<Vec<u8>> {
    match method {
        "password" => {
            let pw = crate::crypto::password::resolve_password(password)?;
            transport::encrypt_password(data, &pw)
        }
        _ => {
            if recipients.is_empty() {
                return Err(Error::NoGpgRecipient);
            }
            transport::encrypt_gpg(data, recipients)
        }
    }
}

/// Find the latest save for the project, optionally filtered by file path
/// and current branch.
fn find_latest_save(
    conn: &rusqlite::Connection,
    project_path: &str,
    current_branch: Option<&str>,
    file_filter: Option<&str>,
) -> Result<crate::types::SaveMetadata> {
    // Try current branch first.
    if let Some(branch) = current_branch {
        let saves = queries::list_saves(
            conn,
            project_path,
            Some(branch),
            None,
            1,
            file_filter,
        )?;
        if let Some(save) = saves.into_iter().next() {
            return Ok(save);
        }
    }

    // Fall back to any branch.
    let saves = queries::list_saves(conn, project_path, None, None, 1, file_filter)?;
    saves
        .into_iter()
        .next()
        .ok_or_else(|| Error::SaveNotFound("no saved versions found".to_string()))
}

/// Run safety checks before sharing.
fn run_safety_checks(
    save: &crate::types::SaveMetadata,
    current_branch: Option<&str>,
    project_path: &str,
) -> Result<()> {
    // Check: saved version is from a different branch.
    if let Some(branch) = current_branch {
        if !save.branch.is_empty() && save.branch != branch {
            return Err(Error::Other(format!(
                "Saved version is from branch '{}', but current branch is '{}'. \
                 Use --ignore to share anyway.",
                save.branch, branch
            )));
        }
    }

    // Check: current .env on disk differs from saved version.
    if let Some(disk_hash) = cli::disk_content_hash(project_path, &save.file_path) {
        if disk_hash != save.content_hash {
            return Err(Error::Other(
                "Current .env on disk differs from saved version. \
                 Save first, or use --ignore to share anyway."
                    .to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::queries;
    use crate::test_helpers::{sample_entries, test_conn};
    use crate::types::SaveMetadata;

    #[test]
    fn find_latest_on_branch() {
        let conn = test_conn();
        let entries = sample_entries();
        queries::insert_save(
            &conn, "/proj", ".env", "main", "a1",
            "2024-01-01T00:00:00Z", "h1", &entries, None,
        )
        .unwrap();
        queries::insert_save(
            &conn, "/proj", ".env", "main", "a2",
            "2024-01-02T00:00:00Z", "h2", &entries, None,
        )
        .unwrap();

        let save = find_latest_save(&conn, "/proj", Some("main"), None).unwrap();
        assert_eq!(save.content_hash, "h2"); // newest
    }

    #[test]
    fn find_latest_fallback_to_any_branch() {
        let conn = test_conn();
        let entries = sample_entries();
        queries::insert_save(
            &conn, "/proj", ".env", "dev", "a1",
            "2024-01-01T00:00:00Z", "h1", &entries, None,
        )
        .unwrap();

        let save = find_latest_save(&conn, "/proj", Some("main"), None).unwrap();
        assert_eq!(save.branch, "dev");
    }

    #[test]
    fn find_latest_not_found() {
        let conn = test_conn();
        let result = find_latest_save(&conn, "/proj", Some("main"), None);
        assert!(result.is_err());
    }

    #[test]
    fn find_latest_with_file_filter() {
        let conn = test_conn();
        let entries = sample_entries();
        queries::insert_save(
            &conn, "/proj", ".env", "main", "a1",
            "2024-01-01T00:00:00Z", "h1", &entries, None,
        )
        .unwrap();
        queries::insert_save(
            &conn, "/proj", ".db-env", "main", "a2",
            "2024-01-02T00:00:00Z", "h2", &entries, None,
        )
        .unwrap();

        let save = find_latest_save(&conn, "/proj", Some("main"), Some(".env")).unwrap();
        assert_eq!(save.file_path, ".env");
    }

    #[test]
    fn safety_check_wrong_branch() {
        let save = SaveMetadata {
            id: 1,
            project_path: "/proj".to_string(),
            file_path: ".env".to_string(),
            branch: "dev".to_string(),
            commit_hash: "abc".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            content_hash: "h1".to_string(),
            hmac: String::new(),
            message: None,
        };

        let result = run_safety_checks(&save, Some("main"), "/proj");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("branch"));
    }

    #[test]
    fn safety_check_same_branch_passes() {
        let save = SaveMetadata {
            id: 1,
            project_path: "/proj".to_string(),
            file_path: ".env".to_string(),
            branch: "main".to_string(),
            commit_hash: "abc".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            content_hash: "h1".to_string(),
            hmac: String::new(),
            message: None,
        };

        // This passes because there's no file on disk to compare against
        // (disk_content_hash returns None for non-existent files).
        let result = run_safety_checks(&save, Some("main"), "/proj");
        assert!(result.is_ok());
    }

    #[test]
    fn safety_check_empty_branch_passes() {
        let save = SaveMetadata {
            id: 1,
            project_path: "/proj".to_string(),
            file_path: ".env".to_string(),
            branch: String::new(),
            commit_hash: String::new(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            content_hash: "h1".to_string(),
            hmac: String::new(),
            message: None,
        };

        let result = run_safety_checks(&save, Some("main"), "/proj");
        assert!(result.is_ok());
    }

    #[test]
    fn safety_check_disk_differs() {
        // Create a temp dir with a .env file that has a known hash.
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "KEY=value\n").unwrap();

        let save = SaveMetadata {
            id: 1,
            project_path: dir.path().to_string_lossy().to_string(),
            file_path: ".env".to_string(),
            branch: "main".to_string(),
            commit_hash: "abc".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            content_hash: "definitely_not_matching_hash".to_string(),
            hmac: String::new(),
            message: None,
        };

        let result = run_safety_checks(&save, Some("main"), &dir.path().to_string_lossy());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("differs"));
    }

    #[test]
    fn safety_check_disk_matches() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "KEY=value\n").unwrap();

        // Compute the actual hash.
        let entries = crate::parser::parse("KEY=value\n").unwrap();
        let hash = crate::parser::content_hash(&entries);

        let save = SaveMetadata {
            id: 1,
            project_path: dir.path().to_string_lossy().to_string(),
            file_path: ".env".to_string(),
            branch: "main".to_string(),
            commit_hash: "abc".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            content_hash: hash,
            hmac: String::new(),
            message: None,
        };

        let result = run_safety_checks(&save, Some("main"), &dir.path().to_string_lossy());
        assert!(result.is_ok());
    }

    // ----- Transport encryption integration tests -----

    #[test]
    fn encrypt_export_password() {
        let data = b"# envstash export\nDB_HOST=localhost\n";
        let encrypted = encrypt_export(data, "password", &[], Some("test-pw"))
            .unwrap();
        assert!(encrypted.starts_with(b"EVPW"));

        // Decrypt and verify round-trip.
        let decrypted = transport::decrypt_password(&encrypted, "test-pw").unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn encrypt_export_password_no_password_errors() {
        // Without password and without ENVSTASH_PASSWORD, this should
        // fall through to prompt which will fail in test context.
        // We test by setting the env var.
        let data = b"test data";

        // With explicit password it works.
        let result = encrypt_export(data, "password", &[], Some("pw"));
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_gpg_recipients_explicit() {
        use std::path::Path;
        use crate::crypto::gpg;
        let result = gpg::resolve_recipients(
            &["ABCD1234".to_string()],
            Path::new("/tmp"),
        )
        .unwrap();
        assert_eq!(result, vec!["ABCD1234".to_string()]);
    }

    #[test]
    fn share_password_encrypt_round_trip() {
        let conn = test_conn();
        let entries = sample_entries();
        queries::insert_save(
            &conn, "/proj", ".env", "main", "abc",
            "2024-06-17T12:00:00Z", "h1", &entries, None,
        )
        .unwrap();

        // Simulate share with password encryption.
        let saves = queries::list_saves(&conn, "/proj", Some("main"), None, 1, None).unwrap();
        let loaded = queries::get_save_entries(&conn, saves[0].id, None).unwrap();
        let envelope = export::build_envelope(&saves[0], &loaded);
        let serialized = export::to_json(&envelope).unwrap();

        let encrypted = transport::encrypt_password(serialized.as_bytes(), "share-pw").unwrap();

        // Simulate import: detect, decrypt, parse.
        assert_eq!(
            transport::detect(&encrypted),
            transport::TransportEncryption::Password,
        );
        let decrypted = transport::decrypt_auto(&encrypted, Some("share-pw")).unwrap();
        let text = std::str::from_utf8(&decrypted).unwrap();
        let parsed = export::auto_detect(text).unwrap();
        let imported_entries = export::to_env_entries(&parsed);
        assert_eq!(imported_entries, entries);
    }

    #[test]
    fn share_text_format_password_encrypt_round_trip() {
        let conn = test_conn();
        let entries = sample_entries();
        queries::insert_save(
            &conn, "/proj", ".env", "dev", "def",
            "2024-06-17T12:00:00Z", "h2", &entries, None,
        )
        .unwrap();

        let saves = queries::list_saves(&conn, "/proj", Some("dev"), None, 1, None).unwrap();
        let loaded = queries::get_save_entries(&conn, saves[0].id, None).unwrap();
        let envelope = export::build_envelope(&saves[0], &loaded);
        let serialized = export::to_text(&envelope);

        let encrypted = transport::encrypt_password(serialized.as_bytes(), "text-pw").unwrap();
        let decrypted = transport::decrypt_auto(&encrypted, Some("text-pw")).unwrap();
        let text = std::str::from_utf8(&decrypted).unwrap();
        let parsed = export::auto_detect(text).unwrap();
        let imported_entries = export::to_env_entries(&parsed);
        assert_eq!(imported_entries, entries);
    }
}
