//! `brakeman` wrapper — Ruby on Rails SAST.
//!
//! Wraps [brakeman](https://brakemanscanner.org/) — the
//! widely-deployed Rails-specific static analyzer that detects
//! SQL injection, XSS, mass assignment, weak crypto, and other
//! Rails-specific anti-patterns.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Ruby on Rails SAST via brakeman.
#[derive(Debug)]
pub struct BrakemanModule;

#[async_trait]
impl CodeModule for BrakemanModule {
    fn name(&self) -> &'static str {
        "brakeman Rails SAST"
    }
    fn id(&self) -> &'static str {
        "brakeman"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sast
    }
    fn description(&self) -> &'static str {
        "Ruby on Rails security static analysis: SQLi, XSS, mass assignment, weak crypto"
    }
    fn languages(&self) -> &[&str] {
        &["ruby"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("brakeman")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        let output = subprocess::run_tool_lenient(
            "brakeman",
            &["-f", "json", "-q", &path_str],
            Duration::from_secs(180),
        )
        .await?;
        Ok(parse_brakeman_output(&output.stdout))
    }
}

/// Parse brakeman JSON output into findings.
///
/// Format: `{"warnings": [{"warning_type": "...", "message": "...",
/// "file": "...", "line": ..., "confidence": "..."}]}`.
#[must_use]
pub fn parse_brakeman_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };
    let Some(warnings) = v["warnings"].as_array() else {
        return Vec::new();
    };
    warnings
        .iter()
        .map(|w| {
            let kind = w["warning_type"].as_str().unwrap_or("?");
            let message = w["message"].as_str().unwrap_or("");
            let confidence_str = w["confidence"].as_str().unwrap_or("Medium");
            let severity = match confidence_str {
                "High" => Severity::High,
                "Medium" => Severity::Medium,
                _ => Severity::Low,
            };
            let confidence = match confidence_str {
                "High" => 0.9,
                "Medium" => 0.7,
                _ => 0.5,
            };
            let file = w["file"].as_str().unwrap_or("?");
            let line = w["line"].as_i64().unwrap_or(0);
            Finding::new(
                "brakeman",
                severity,
                format!("brakeman {kind}"),
                message.to_string(),
                format!("{file}:{line}"),
            )
            .with_evidence(format!("warning_type={kind} confidence={confidence_str}"))
            .with_owasp("A03:2021 Injection")
            .with_confidence(confidence)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_brakeman_output_with_warnings() {
        let stdout = r#"{"warnings": [
            {"warning_type": "SQL Injection", "message": "Possible SQL injection",
             "file": "app/models/user.rb", "line": 42, "confidence": "High"},
            {"warning_type": "Mass Assignment", "message": "Unprotected attribute",
             "file": "app/controllers/users_controller.rb", "line": 15, "confidence": "Medium"}
        ]}"#;
        let findings = parse_brakeman_output(stdout);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    #[test]
    fn parse_brakeman_output_empty() {
        assert!(parse_brakeman_output("").is_empty());
        assert!(parse_brakeman_output(r#"{"warnings": []}"#).is_empty());
    }
}
