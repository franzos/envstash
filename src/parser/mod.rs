use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::types::EnvEntry;

/// Parse a .env file's contents into a list of environment entries.
///
/// Rules:
/// - Lines matching `KEY=VALUE` or `export KEY=VALUE` are parsed.
/// - Quoted values (`"..."` or `'...'`) are preserved as-is.
/// - A single `# comment` line directly above a variable is attached to it.
/// - Blank lines and orphan comments (not directly above a variable) are skipped.
/// - Leading/trailing whitespace on each line is trimmed.
pub fn parse(input: &str) -> Result<Vec<EnvEntry>> {
    let mut entries = Vec::new();
    let mut pending_comment: Option<String> = None;

    for line in input.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            // Blank line resets any pending comment.
            pending_comment = None;
            continue;
        }

        if trimmed.starts_with('#') {
            // Store the comment text (without the leading `#`).
            // If there was already a pending comment, the previous one was orphan.
            let text = trimmed.strip_prefix('#').unwrap_or("").trim();
            pending_comment = Some(text.to_string());
            continue;
        }

        // Try to parse as a variable assignment.
        if let Some(entry) = parse_assignment(trimmed, &pending_comment) {
            entries.push(entry);
            pending_comment = None;
        } else {
            // Unrecognized line — discard any pending comment.
            pending_comment = None;
        }
    }

    Ok(entries)
}

/// Try to parse a line as `[export] KEY=VALUE`.
fn parse_assignment(line: &str, comment: &Option<String>) -> Option<EnvEntry> {
    let line = line
        .strip_prefix("export")
        .map_or(line, |rest| rest.trim_start());

    let eq_pos = line.find('=')?;
    let key = line[..eq_pos].trim();

    if key.is_empty() {
        return None;
    }

    // Reject keys with spaces (not valid env var names).
    if key.contains(' ') {
        return None;
    }

    let value = line[eq_pos + 1..].trim().to_string();

    Some(EnvEntry {
        comment: comment.clone(),
        key: key.to_string(),
        value,
    })
}

/// Serialize entries back to .env format.
pub fn serialize(entries: &[EnvEntry]) -> String {
    let mut out = String::new();

    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if let Some(ref comment) = entry.comment {
            out.push_str(&format!("# {comment}\n"));
        }
        out.push_str(&format!("{}={}\n", entry.key, entry.value));
    }

    out
}

/// Compute a deterministic SHA-256 hash of a set of entries.
///
/// Entries are sorted by key before hashing to ensure order-independence.
pub fn content_hash(entries: &[EnvEntry]) -> String {
    let mut sorted: Vec<&EnvEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.key.cmp(&b.key));

    let mut hasher = Sha256::new();
    for entry in &sorted {
        hasher.update(entry.key.as_bytes());
        hasher.update(b"=");
        hasher.update(entry.value.as_bytes());
        if let Some(ref c) = entry.comment {
            hasher.update(b"#");
            hasher.update(c.as_bytes());
        }
        hasher.update(b"\n");
    }

    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_key_value() {
        let input = "DB_HOST=localhost\nDB_PORT=5432\n";
        let entries = parse(input).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "DB_HOST");
        assert_eq!(entries[0].value, "localhost");
        assert_eq!(entries[0].comment, None);
        assert_eq!(entries[1].key, "DB_PORT");
        assert_eq!(entries[1].value, "5432");
    }

    #[test]
    fn parse_quoted_values() {
        let input = "KEY1=\"hello world\"\nKEY2='single quoted'\n";
        let entries = parse(input).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].value, "\"hello world\"");
        assert_eq!(entries[1].value, "'single quoted'");
    }

    #[test]
    fn parse_export_prefix() {
        let input = "export API_KEY=secret123\nexport DB_HOST=localhost\n";
        let entries = parse(input).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "API_KEY");
        assert_eq!(entries[0].value, "secret123");
        assert_eq!(entries[1].key, "DB_HOST");
    }

    #[test]
    fn parse_comment_above_variable() {
        let input = "# Database configuration\nDB_HOST=localhost\n";
        let entries = parse(input).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].comment,
            Some("Database configuration".to_string())
        );
        assert_eq!(entries[0].key, "DB_HOST");
    }

    #[test]
    fn parse_orphan_comment_skipped() {
        let input = "# This is orphan\n\nDB_HOST=localhost\n";
        let entries = parse(input).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].comment, None);
    }

    #[test]
    fn parse_blank_lines_separate_comment() {
        let input = "# Comment\n\nKEY=value\n";
        let entries = parse(input).unwrap();
        assert_eq!(entries.len(), 1);
        // Blank line between comment and variable means the comment is orphan.
        assert_eq!(entries[0].comment, None);
    }

    #[test]
    fn parse_empty_file() {
        let entries = parse("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_empty_value() {
        let input = "EMPTY=\n";
        let entries = parse(input).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "EMPTY");
        assert_eq!(entries[0].value, "");
    }

    #[test]
    fn parse_value_with_equals_sign() {
        let input = "CONNECTION=postgres://user:pass@host/db?opt=val\n";
        let entries = parse(input).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "postgres://user:pass@host/db?opt=val");
    }

    #[test]
    fn parse_unicode_value() {
        let input = "GREETING=\u{1F600} hello\n";
        let entries = parse(input).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "\u{1F600} hello");
    }

    #[test]
    fn parse_trailing_whitespace_trimmed() {
        let input = "  KEY=value  \n";
        let entries = parse(input).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "KEY");
        assert_eq!(entries[0].value, "value");
    }

    #[test]
    fn parse_only_comments_and_blanks() {
        let input = "# comment1\n\n# comment2\n# comment3\n";
        let entries = parse(input).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn serialize_round_trip() {
        let input = "# DB config\nDB_HOST=localhost\n\nDB_PORT=5432\n";
        let entries = parse(input).unwrap();
        let output = serialize(&entries);
        let re_parsed = parse(&output).unwrap();
        assert_eq!(entries, re_parsed);
    }

    #[test]
    fn serialize_produces_expected_output() {
        let entries = vec![
            EnvEntry {
                comment: Some("Server".to_string()),
                key: "HOST".to_string(),
                value: "0.0.0.0".to_string(),
            },
            EnvEntry {
                comment: None,
                key: "PORT".to_string(),
                value: "8080".to_string(),
            },
        ];
        let out = serialize(&entries);
        assert_eq!(out, "# Server\nHOST=0.0.0.0\n\nPORT=8080\n");
    }

    #[test]
    fn content_hash_deterministic() {
        let entries = vec![
            EnvEntry {
                comment: None,
                key: "B".to_string(),
                value: "2".to_string(),
            },
            EnvEntry {
                comment: None,
                key: "A".to_string(),
                value: "1".to_string(),
            },
        ];
        let h1 = content_hash(&entries);

        // Same entries in different order should produce the same hash.
        let entries_reversed = vec![
            EnvEntry {
                comment: None,
                key: "A".to_string(),
                value: "1".to_string(),
            },
            EnvEntry {
                comment: None,
                key: "B".to_string(),
                value: "2".to_string(),
            },
        ];
        let h2 = content_hash(&entries_reversed);
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_hash_changes_with_value() {
        let e1 = vec![EnvEntry {
            comment: None,
            key: "A".to_string(),
            value: "1".to_string(),
        }];
        let e2 = vec![EnvEntry {
            comment: None,
            key: "A".to_string(),
            value: "2".to_string(),
        }];
        assert_ne!(content_hash(&e1), content_hash(&e2));
    }

    #[test]
    fn content_hash_changes_with_comment() {
        let e1 = vec![EnvEntry {
            comment: Some("old".to_string()),
            key: "A".to_string(),
            value: "1".to_string(),
        }];
        let e2 = vec![EnvEntry {
            comment: Some("new".to_string()),
            key: "A".to_string(),
            value: "1".to_string(),
        }];
        assert_ne!(content_hash(&e1), content_hash(&e2));
    }

    #[test]
    fn parse_multiple_comments_only_last_attached() {
        // Two consecutive comment lines: only the last one is attached.
        let input = "# First comment\n# Second comment\nKEY=val\n";
        let entries = parse(input).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].comment, Some("Second comment".to_string()));
    }

    #[test]
    fn content_hash_empty_entries() {
        let h = content_hash(&[]);
        // Should produce a valid hash (SHA-256 of empty input).
        assert_eq!(h.len(), 64);
    }
}
