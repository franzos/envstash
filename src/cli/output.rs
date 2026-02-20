use std::io::{self, IsTerminal};

use colored::Colorize;

use crate::types::DiffResult;

/// Check if stdout is a terminal (vs piped).
pub fn is_stdout_terminal() -> bool {
    io::stdout().is_terminal()
}

/// Abbreviate a hash for display, git-style: "abcdef1234..." -> "abcdef12"
pub fn short_hash(hash: &str) -> String {
    if hash.len() > 8 {
        hash[..8].to_string()
    } else {
        hash.to_string()
    }
}

/// Format a diff result as human-readable text with colors.
pub fn format_diff_text(result: &DiffResult, full: bool) -> String {
    let mut out = String::new();

    for entry in &result.removed {
        out.push_str(&format!(
            "{}\n",
            format!("- {}={}", entry.key, entry.value).red()
        ));
    }

    for entry in &result.added {
        out.push_str(&format!(
            "{}\n",
            format!("+ {}={}", entry.key, entry.value).green()
        ));
    }

    for (old, new) in &result.changed {
        if old.comment != new.comment {
            let old_c = old.comment.as_deref().unwrap_or("");
            let new_c = new.comment.as_deref().unwrap_or("");
            out.push_str(&format!(
                "{}\n",
                format!("~ # {old_c}  ->  # {new_c}").yellow()
            ));
        }
        if old.value != new.value {
            out.push_str(&format!(
                "{}\n",
                format!("- {}={}", old.key, old.value).red()
            ));
            out.push_str(&format!(
                "{}\n",
                format!("+ {}={}", new.key, new.value).green()
            ));
        } else {
            out.push_str(&format!(
                "{}\n",
                format!("  {}={}", new.key, new.value).dimmed()
            ));
        }
    }

    if full {
        for entry in &result.unchanged {
            out.push_str(&format!(
                "{}\n",
                format!("  {}={}", entry.key, entry.value).dimmed()
            ));
        }
    }

    out
}

/// Format a diff result as JSON.
pub fn format_diff_json(result: &DiffResult, full: bool) -> crate::error::Result<String> {
    let mut output = serde_json::Map::new();

    let added: Vec<serde_json::Value> = result
        .added
        .iter()
        .map(|e| serde_json::json!({"key": e.key, "value": e.value, "comment": e.comment}))
        .collect();

    let removed: Vec<serde_json::Value> = result
        .removed
        .iter()
        .map(|e| serde_json::json!({"key": e.key, "value": e.value, "comment": e.comment}))
        .collect();

    let changed: Vec<serde_json::Value> = result
        .changed
        .iter()
        .map(|(old, new)| {
            serde_json::json!({
                "key": old.key,
                "old": {"value": old.value, "comment": old.comment},
                "new": {"value": new.value, "comment": new.comment},
            })
        })
        .collect();

    output.insert("added".to_string(), serde_json::Value::Array(added));
    output.insert("removed".to_string(), serde_json::Value::Array(removed));
    output.insert("changed".to_string(), serde_json::Value::Array(changed));

    if full {
        let unchanged: Vec<serde_json::Value> = result
            .unchanged
            .iter()
            .map(|e| serde_json::json!({"key": e.key, "value": e.value, "comment": e.comment}))
            .collect();
        output.insert("unchanged".to_string(), serde_json::Value::Array(unchanged));
    }

    Ok(serde_json::to_string_pretty(&serde_json::Value::Object(
        output,
    ))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EnvEntry;

    fn no_color() {
        colored::control::set_override(false);
    }

    #[test]
    fn short_hash_long() {
        let hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        assert_eq!(short_hash(hash), "abcdef12");
    }

    #[test]
    fn short_hash_short() {
        assert_eq!(short_hash("short"), "short");
    }

    #[test]
    fn diff_text_added() {
        no_color();
        let result = DiffResult {
            added: vec![EnvEntry {
                key: "NEW".to_string(),
                value: "val".to_string(),
                comment: None,
            }],
            removed: vec![],
            changed: vec![],
            unchanged: vec![],
        };
        let text = format_diff_text(&result, false);
        assert!(text.contains("+ NEW=val"));
    }

    #[test]
    fn diff_text_removed() {
        no_color();
        let result = DiffResult {
            added: vec![],
            removed: vec![EnvEntry {
                key: "OLD".to_string(),
                value: "val".to_string(),
                comment: None,
            }],
            changed: vec![],
            unchanged: vec![],
        };
        let text = format_diff_text(&result, false);
        assert!(text.contains("- OLD=val"));
    }

    #[test]
    fn diff_text_changed_value() {
        no_color();
        let result = DiffResult {
            added: vec![],
            removed: vec![],
            changed: vec![(
                EnvEntry {
                    key: "KEY".to_string(),
                    value: "old".to_string(),
                    comment: None,
                },
                EnvEntry {
                    key: "KEY".to_string(),
                    value: "new".to_string(),
                    comment: None,
                },
            )],
            unchanged: vec![],
        };
        let text = format_diff_text(&result, false);
        assert!(text.contains("- KEY=old"));
        assert!(text.contains("+ KEY=new"));
    }

    #[test]
    fn diff_text_changed_comment() {
        no_color();
        let result = DiffResult {
            added: vec![],
            removed: vec![],
            changed: vec![(
                EnvEntry {
                    key: "KEY".to_string(),
                    value: "same".to_string(),
                    comment: Some("old comment".to_string()),
                },
                EnvEntry {
                    key: "KEY".to_string(),
                    value: "same".to_string(),
                    comment: Some("new comment".to_string()),
                },
            )],
            unchanged: vec![],
        };
        let text = format_diff_text(&result, false);
        assert!(text.contains("~ # old comment  ->  # new comment"));
        assert!(text.contains("  KEY=same"));
    }

    #[test]
    fn diff_text_unchanged_hidden_by_default() {
        no_color();
        let result = DiffResult {
            added: vec![],
            removed: vec![],
            changed: vec![],
            unchanged: vec![EnvEntry {
                key: "SAME".to_string(),
                value: "val".to_string(),
                comment: None,
            }],
        };
        let text = format_diff_text(&result, false);
        assert!(!text.contains("SAME"));
    }

    #[test]
    fn diff_text_unchanged_shown_with_full() {
        no_color();
        let result = DiffResult {
            added: vec![],
            removed: vec![],
            changed: vec![],
            unchanged: vec![EnvEntry {
                key: "SAME".to_string(),
                value: "val".to_string(),
                comment: None,
            }],
        };
        let text = format_diff_text(&result, true);
        assert!(text.contains("  SAME=val"));
    }

    #[test]
    fn diff_json_round_trip() {
        let result = DiffResult {
            added: vec![EnvEntry {
                key: "A".to_string(),
                value: "1".to_string(),
                comment: None,
            }],
            removed: vec![],
            changed: vec![],
            unchanged: vec![],
        };
        let json = format_diff_json(&result, false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["added"][0]["key"], "A");
    }
}
