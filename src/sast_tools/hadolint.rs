//! Hadolint wrapper for Dockerfile linting.
//!
//! Wraps the `hadolint` tool which checks Dockerfiles against best-practice
//! rules for security, efficiency, and maintainability.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Dockerfile linting via Hadolint.
#[derive(Debug)]
pub struct HadolintModule;

#[async_trait]
impl CodeModule for HadolintModule {
    fn name(&self) -> &'static str {
        "Hadolint Dockerfile Linter"
    }
    fn id(&self) -> &'static str {
        "hadolint"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Iac
    }
    fn description(&self) -> &'static str {
        "Dockerfile best-practice and security linting via Hadolint"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("hadolint")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let dockerfile = ctx.path.join("Dockerfile");
        if !dockerfile.exists() {
            return Ok(Vec::new());
        }
        let path_str = dockerfile.display().to_string();
        let output = subprocess::run_tool_lenient(
            "hadolint",
            &["--format", "json", &path_str],
            Duration::from_secs(60),
        )
        .await?;

        Ok(parse_hadolint_output(&output.stdout))
    }
}

/// Map Hadolint severity strings to `ScorchKit` severity levels.
fn map_hadolint_severity(level: &str) -> Severity {
    match level.to_lowercase().as_str() {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        "info" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse Hadolint JSON output into findings.
///
/// Hadolint outputs a JSON array of objects with `code`, `message`,
/// `column`, `file`, `level`, and `line` fields.
#[must_use]
pub fn parse_hadolint_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(issues) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) else {
        return Vec::new();
    };

    issues
        .iter()
        .filter_map(|issue| {
            let code = issue["code"].as_str()?;
            let message = issue["message"].as_str().unwrap_or(code);
            let file = issue["file"].as_str().unwrap_or("Dockerfile");
            let line = issue["line"].as_u64().unwrap_or(0);
            let level = issue["level"].as_str().unwrap_or("warning");

            let affected = format!("{file}:{line}");

            Some(
                Finding::new(
                    "hadolint",
                    map_hadolint_severity(level),
                    format!("{code}: {message}"),
                    message,
                    &affected,
                )
                .with_remediation(format!("Fix Dockerfile issue {code}: {message}"))
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_confidence(0.85),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Hadolint JSON output is correctly parsed into findings
    /// with rule code, message, file location, and severity.
    #[test]
    fn test_parse_hadolint_output() {
        let output = r#"[
            {
                "code": "DL3007",
                "message": "Using latest is prone to errors",
                "column": 1,
                "file": "Dockerfile",
                "level": "warning",
                "line": 1
            },
            {
                "code": "DL3008",
                "message": "Pin versions in apt get install",
                "column": 1,
                "file": "Dockerfile",
                "level": "error",
                "line": 5
            }
        ]"#;

        let findings = parse_hadolint_output(output);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("DL3007"));
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].affected_target, "Dockerfile:1");
        assert_eq!(findings[1].severity, Severity::High);
    }

    /// Verify empty or invalid input produces no findings.
    #[test]
    fn test_parse_hadolint_empty() {
        assert!(parse_hadolint_output("").is_empty());
        assert!(parse_hadolint_output("[]").is_empty());
        assert!(parse_hadolint_output("not json").is_empty());
    }
}
