//! Semgrep wrapper for multi-language static analysis.
//!
//! Wraps the `semgrep` tool which performs rule-based static analysis
//! across many languages including Python, JavaScript, Go, Java, Ruby, and more.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use scorchkit_core::AdapterParseOutcome;

/// Multi-language static analysis via Semgrep.
#[derive(Debug)]
pub struct SemgrepModule;

#[async_trait]
impl CodeModule for SemgrepModule {
    fn name(&self) -> &'static str {
        "Semgrep SAST"
    }
    fn id(&self) -> &'static str {
        "semgrep"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sast
    }
    fn description(&self) -> &'static str {
        "Multi-language static analysis for security vulnerabilities via Semgrep"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("semgrep")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        let output = ctx
            .run_tool(
                "semgrep",
                &["scan", "--config", "auto", "--json", "--quiet", &path_str],
                Duration::from_mins(5),
            )
            .await?;
        parse_semgrep_output_v1(&output.stdout).into_result("semgrep")
    }
}

/// Map Semgrep severity strings to `ScorchKit` severity levels.
fn map_semgrep_severity(severity: &str) -> Severity {
    match severity.to_uppercase().as_str() {
        "ERROR" => Severity::High,
        "WARNING" => Severity::Medium,
        "INFO" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse Semgrep JSON output into findings.
///
/// Semgrep outputs a JSON object with a `results` array. Each result
/// contains `check_id`, `path`, `start`/`end` positions, `extra.severity`,
/// `extra.message`, and optional `extra.metadata` (CWE, OWASP).
#[must_use]
pub fn parse_semgrep_output(stdout: &str) -> Vec<Finding> {
    parse_semgrep_output_v1(stdout).into_legacy()
}

fn parse_semgrep_output_v1(stdout: &str) -> AdapterParseOutcome<Vec<Finding>> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return AdapterParseOutcome::NoFindings;
    }

    let root = match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(root) => root,
        Err(error) => {
            return AdapterParseOutcome::malformed(format!("invalid JSON document: {error}"));
        }
    };

    let Some(results) = root["results"].as_array() else {
        return AdapterParseOutcome::malformed("JSON document has no results array");
    };
    if root["errors"].as_array().is_some_and(|errors| !errors.is_empty()) {
        return AdapterParseOutcome::malformed("JSON document reports one or more scan errors");
    }

    if results.is_empty() {
        return AdapterParseOutcome::NoFindings;
    }

    let mut findings = Vec::with_capacity(results.len());
    for (index, result) in results.iter().enumerate() {
        let Some(check_id) = result["check_id"].as_str() else {
            return AdapterParseOutcome::malformed(format!("result {} has no check_id", index + 1));
        };
        let Some(path) = result["path"].as_str() else {
            return AdapterParseOutcome::malformed(format!("result {} has no path", index + 1));
        };
        let Some(line) = result["start"]["line"].as_u64() else {
            return AdapterParseOutcome::malformed(format!(
                "result {} has no start.line",
                index + 1
            ));
        };
        let Some(message) = result["extra"]["message"].as_str() else {
            return AdapterParseOutcome::malformed(format!(
                "result {} has no extra.message",
                index + 1
            ));
        };
        let severity_str = result["extra"]["severity"].as_str().unwrap_or("INFO");
        let lines = result["extra"]["lines"].as_str().unwrap_or("");

        let affected = format!("{path}:{line}");

        let mut finding = Finding::new(
            "semgrep",
            map_semgrep_severity(severity_str),
            check_id,
            message,
            &affected,
        )
        .with_confidence(0.8);

        if !lines.is_empty() {
            finding = finding.with_evidence(lines);
        }

        // Extract CWE from metadata if available
        if let Some(cwe_arr) = result["extra"]["metadata"]["cwe"].as_array() {
            if let Some(first_cwe) = cwe_arr.first().and_then(|v| v.as_str()) {
                // CWE format: "CWE-79" -> extract number
                if let Some(num_str) = first_cwe.strip_prefix("CWE-") {
                    if let Ok(cwe_num) = num_str.parse::<u32>() {
                        finding = finding.with_cwe(cwe_num);
                    }
                }
            }
        }

        // Extract OWASP from metadata
        if let Some(owasp_arr) = result["extra"]["metadata"]["owasp"].as_array() {
            if let Some(first_owasp) = owasp_arr.first().and_then(|v| v.as_str()) {
                finding = finding.with_owasp(first_owasp);
            }
        }

        finding = finding.with_remediation(format!(
            "Review and fix the issue identified by Semgrep rule: {check_id}"
        ));

        findings.push(finding);
    }

    AdapterParseOutcome::Findings(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Semgrep JSON output is correctly parsed into findings.
    #[test]
    fn test_parse_semgrep_output() {
        let output = r#"{
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval-detected",
                    "path": "app/views.py",
                    "start": {"line": 42, "col": 5},
                    "end": {"line": 42, "col": 20},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Detected use of eval(). This is dangerous.",
                        "lines": "    result = eval(user_input)",
                        "metadata": {
                            "cwe": ["CWE-95"],
                            "owasp": ["A03:2021 Injection"]
                        }
                    }
                }
            ]
        }"#;

        let findings = parse_semgrep_output(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].affected_target, "app/views.py:42");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cwe_id, Some(95));
        assert!(findings[0].evidence.as_ref().is_some_and(|e| e.contains("eval")));
    }

    /// Verify empty or missing results produce no findings.
    #[test]
    fn test_parse_semgrep_empty() {
        assert!(parse_semgrep_output("").is_empty());
        assert!(parse_semgrep_output(r#"{"results": []}"#).is_empty());
        assert!(parse_semgrep_output("not json").is_empty());
    }

    #[test]
    fn malformed_semgrep_json_is_not_reported_as_no_findings() {
        for malformed in [
            "not json",
            r#"{"errors": []}"#,
            r#"{"results": [], "errors": [{}]}"#,
            r#"{"results": [{"check_id": "partial"}]}"#,
        ] {
            assert!(matches!(
                parse_semgrep_output_v1(malformed),
                AdapterParseOutcome::Malformed { .. }
            ));
        }
    }
}
