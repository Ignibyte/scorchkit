//! `ESLint` security wrapper for JavaScript/TypeScript static analysis.
//!
//! Wraps `eslint` with the `eslint-plugin-security` plugin to detect
//! common security issues in JavaScript and TypeScript source code.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// JavaScript/TypeScript security analysis via `ESLint`.
#[derive(Debug)]
pub struct EslintSecurityModule;

#[async_trait]
impl CodeModule for EslintSecurityModule {
    fn name(&self) -> &'static str {
        "ESLint Security"
    }
    fn id(&self) -> &'static str {
        "eslint-security"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sast
    }
    fn description(&self) -> &'static str {
        "JavaScript/TypeScript security static analysis via ESLint with security plugin"
    }
    fn languages(&self) -> &[&str] {
        &["javascript"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("eslint")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        let output = subprocess::run_tool_lenient(
            "eslint",
            &[
                "--format",
                "json",
                "--no-eslintrc",
                "--plugin",
                "security",
                "--rule",
                "security/detect-eval-with-expression: error",
                "--rule",
                "security/detect-non-literal-regexp: warn",
                "--rule",
                "security/detect-non-literal-fs-filename: warn",
                "--rule",
                "security/detect-object-injection: warn",
                "--rule",
                "security/detect-possible-timing-attacks: warn",
                &path_str,
            ],
            Duration::from_secs(120),
        )
        .await?;

        Ok(parse_eslint_output(&output.stdout))
    }
}

/// Map `ESLint` severity integers to `ScorchKit` severity levels.
///
/// `ESLint` uses 1 = warning, 2 = error.
const fn map_eslint_severity(severity: u64) -> Severity {
    match severity {
        2 => Severity::High,
        1 => Severity::Medium,
        _ => Severity::Info,
    }
}

/// Parse `ESLint` JSON output into findings.
///
/// `ESLint` outputs a JSON array of file results. Each file has a `messages`
/// array with `ruleId`, `message`, `severity`, `line`, and `column`.
#[must_use]
pub fn parse_eslint_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(files) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    for file_result in &files {
        let file_path = file_result["filePath"].as_str().unwrap_or("unknown");

        let Some(messages) = file_result["messages"].as_array() else {
            continue;
        };

        for msg in messages {
            let Some(rule_id) = msg["ruleId"].as_str() else {
                continue;
            };
            let message = msg["message"].as_str().unwrap_or(rule_id);
            let severity = msg["severity"].as_u64().unwrap_or(1);
            let line = msg["line"].as_u64().unwrap_or(0);

            let affected = format!("{file_path}:{line}");

            findings.push(
                Finding::new(
                    "eslint-security",
                    map_eslint_severity(severity),
                    format!("{rule_id}: {message}"),
                    message,
                    &affected,
                )
                .with_remediation(format!("Fix ESLint security rule violation: {rule_id}"))
                .with_owasp("A03:2021 Injection")
                .with_confidence(0.75),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify ESLint JSON output is correctly parsed into findings
    /// with rule ID, file path, line number, and severity mapping.
    #[test]
    fn test_parse_eslint_output() {
        let output = r#"[
            {
                "filePath": "/app/src/index.js",
                "messages": [
                    {
                        "ruleId": "security/detect-eval-with-expression",
                        "severity": 2,
                        "message": "eval can be harmful",
                        "line": 15,
                        "column": 5
                    },
                    {
                        "ruleId": "security/detect-object-injection",
                        "severity": 1,
                        "message": "Variable access with non-literal key",
                        "line": 42,
                        "column": 10
                    }
                ]
            }
        ]"#;

        let findings = parse_eslint_output(output);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("detect-eval"));
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].affected_target, "/app/src/index.js:15");
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    /// Verify empty or invalid input produces no findings.
    #[test]
    fn test_parse_eslint_empty() {
        assert!(parse_eslint_output("").is_empty());
        assert!(parse_eslint_output("[]").is_empty());
        assert!(parse_eslint_output("not json").is_empty());
        // File with no messages
        assert!(
            parse_eslint_output(r#"[{"filePath": "/app/index.js", "messages": []}]"#).is_empty()
        );
    }
}
