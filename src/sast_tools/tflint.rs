//! `tflint` wrapper — Terraform linter.
//!
//! Wraps [tflint](https://github.com/terraform-linters/tflint) for
//! Terraform-specific lint rules: deprecated syntax, unused
//! variables, provider best practices. Complements `checkov` (which
//! focuses on security misconfig) with style + correctness checks.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Terraform linter via tflint.
#[derive(Debug)]
pub struct TflintModule;

#[async_trait]
impl CodeModule for TflintModule {
    fn name(&self) -> &'static str {
        "tflint Terraform Linter"
    }
    fn id(&self) -> &'static str {
        "tflint"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Iac
    }
    fn description(&self) -> &'static str {
        "Terraform-specific lint rules: deprecated syntax, unused vars, provider best practices"
    }
    fn languages(&self) -> &[&str] {
        &["terraform", "hcl"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("tflint")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        let output = subprocess::run_tool_lenient(
            "tflint",
            &["--format", "json", "--chdir", &path_str],
            Duration::from_secs(60),
        )
        .await?;
        Ok(parse_tflint_output(&output.stdout))
    }
}

/// Parse tflint JSON output into findings.
///
/// Format: `{"issues": [{"rule": {"name": "...", "severity": "..."}, "message": "...",
/// "range": {"filename": "...", "start": {"line": ..., "column": ...}}}]}`.
#[must_use]
pub fn parse_tflint_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };
    let Some(issues) = v["issues"].as_array() else {
        return Vec::new();
    };
    issues
        .iter()
        .filter_map(|i| {
            let rule = i["rule"]["name"].as_str()?;
            let message = i["message"].as_str().unwrap_or("");
            let sev = match i["rule"]["severity"].as_str() {
                Some("ERROR" | "error") => Severity::High,
                Some("WARNING" | "warning") => Severity::Medium,
                _ => Severity::Low,
            };
            let file = i["range"]["filename"].as_str().unwrap_or("?");
            let line = i["range"]["start"]["line"].as_i64().unwrap_or(0);
            Some(
                Finding::new(
                    "tflint",
                    sev,
                    format!("tflint {rule}: {message}"),
                    message.to_string(),
                    format!("{file}:{line}"),
                )
                .with_evidence(format!("rule={rule} file={file}:{line}"))
                .with_remediation("Address the lint per tflint's rule documentation.")
                .with_confidence(0.85),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tflint_output_with_issues() {
        let stdout = r#"{"issues": [
            {"rule": {"name": "deprecated_index", "severity": "WARNING"},
             "message": "Use brackets instead",
             "range": {"filename": "main.tf", "start": {"line": 12, "column": 5}}},
            {"rule": {"name": "unused_variable", "severity": "ERROR"},
             "message": "Variable foo is unused",
             "range": {"filename": "vars.tf", "start": {"line": 3, "column": 1}}}
        ]}"#;
        let findings = parse_tflint_output(stdout);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[1].severity, Severity::High);
    }

    #[test]
    fn parse_tflint_output_empty() {
        assert!(parse_tflint_output("").is_empty());
        assert!(parse_tflint_output(r#"{"issues": []}"#).is_empty());
    }
}
