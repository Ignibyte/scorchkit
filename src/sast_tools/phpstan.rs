//! `PHPStan` wrapper for PHP static analysis.
//!
//! Wraps the `phpstan` tool which performs static analysis on PHP code
//! to find bugs, type errors, and potential security issues.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// PHP static analysis via `PHPStan`.
#[derive(Debug)]
pub struct PhpstanModule;

#[async_trait]
impl CodeModule for PhpstanModule {
    fn name(&self) -> &'static str {
        "PHPStan"
    }
    fn id(&self) -> &'static str {
        "phpstan"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sast
    }
    fn description(&self) -> &'static str {
        "PHP static analysis for bugs and security issues via PHPStan"
    }
    fn languages(&self) -> &[&str] {
        &["php"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("phpstan")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        let output = subprocess::run_tool_lenient(
            "phpstan",
            &["analyse", "--error-format", "json", "--no-progress", &path_str],
            Duration::from_secs(300),
        )
        .await?;

        Ok(parse_phpstan_output(&output.stdout))
    }
}

/// Parse `PHPStan` JSON output into findings.
///
/// `PHPStan` outputs a JSON object with `totals` and `files` map.
/// Each file entry has a `messages` array with `message`, `line`,
/// and optionally `tip`.
#[must_use]
pub fn parse_phpstan_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(root) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };

    let Some(files) = root["files"].as_object() else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    for (file_path, file_data) in files {
        let Some(messages) = file_data["messages"].as_array() else {
            continue;
        };

        for msg in messages {
            let message = msg["message"].as_str().unwrap_or("Unknown error");
            let line = msg["line"].as_u64().unwrap_or(0);
            let tip = msg["tip"].as_str().unwrap_or("");

            let affected = format!("{file_path}:{line}");

            let mut finding = Finding::new(
                "phpstan",
                Severity::Medium,
                format!("PHPStan: {message}"),
                message,
                &affected,
            )
            .with_owasp("A03:2021 Injection")
            .with_confidence(0.7);

            if tip.is_empty() {
                finding =
                    finding.with_remediation(format!("Review and fix the issue in {file_path}"));
            } else {
                finding = finding.with_remediation(tip);
            }

            findings.push(finding);
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify PHPStan JSON output is correctly parsed with file paths,
    /// line numbers, messages, and optional tips as remediation.
    #[test]
    fn test_parse_phpstan_output() {
        let output = r#"{
            "totals": {"errors": 0, "file_errors": 2},
            "files": {
                "/app/src/Controller/UserController.php": {
                    "errors": 2,
                    "messages": [
                        {
                            "message": "Call to an undefined method App\\Entity\\User::getPasswd().",
                            "line": 45,
                            "tip": "Did you mean getPassword()?"
                        },
                        {
                            "message": "Parameter $id of method expects int, string given.",
                            "line": 78
                        }
                    ]
                }
            }
        }"#;

        let findings = parse_phpstan_output(output);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("getPasswd"));
        assert_eq!(findings[0].affected_target, "/app/src/Controller/UserController.php:45");
        assert!(findings[0].remediation.as_ref().is_some_and(|r| r.contains("getPassword")));
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    /// Verify empty or invalid input produces no findings.
    #[test]
    fn test_parse_phpstan_empty() {
        assert!(parse_phpstan_output("").is_empty());
        assert!(parse_phpstan_output("not json").is_empty());
        assert!(parse_phpstan_output(r#"{"totals": {}, "files": {}}"#).is_empty());
    }
}
