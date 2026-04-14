//! Bandit wrapper for Python static analysis.
//!
//! Wraps the `bandit` tool which performs security-focused static analysis
//! on Python source code, detecting common security issues like hardcoded
//! passwords, SQL injection, command injection, and unsafe deserialization.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Python security analysis via Bandit.
#[derive(Debug)]
pub struct BanditModule;

#[async_trait]
impl CodeModule for BanditModule {
    fn name(&self) -> &'static str {
        "Bandit Python SAST"
    }
    fn id(&self) -> &'static str {
        "bandit"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sast
    }
    fn description(&self) -> &'static str {
        "Python security static analysis for common vulnerabilities via Bandit"
    }
    fn languages(&self) -> &[&str] {
        &["python"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("bandit")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        // bandit exits 1 when issues are found — that's normal, not an error.
        let output = subprocess::run_tool_lenient(
            "bandit",
            &["-r", "-f", "json", &path_str],
            Duration::from_secs(120),
        )
        .await?;

        Ok(parse_bandit_output(&output.stdout))
    }
}

/// Map Bandit severity strings to `ScorchKit` severity levels.
fn map_bandit_severity(severity: &str) -> Severity {
    match severity.to_uppercase().as_str() {
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Map Bandit confidence strings to numeric confidence values.
fn map_bandit_confidence(confidence: &str) -> f64 {
    match confidence.to_uppercase().as_str() {
        "HIGH" => 0.9,
        "LOW" => 0.5,
        _ => 0.7,
    }
}

/// Parse Bandit JSON output into findings.
///
/// Bandit outputs a JSON object with a `results` array. Each result
/// contains `test_id`, `test_name`, `filename`, `line_number`,
/// `issue_severity`, `issue_confidence`, `issue_text`, and `issue_cwe`.
#[must_use]
pub fn parse_bandit_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(root) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };

    let Some(results) = root["results"].as_array() else {
        return Vec::new();
    };

    results
        .iter()
        .filter_map(|result| {
            let test_id = result["test_id"].as_str()?;
            let test_name = result["test_name"].as_str().unwrap_or(test_id);
            let filename = result["filename"].as_str().unwrap_or("unknown");
            let line = result["line_number"].as_u64().unwrap_or(0);
            let severity_str = result["issue_severity"].as_str().unwrap_or("MEDIUM");
            let confidence_str = result["issue_confidence"].as_str().unwrap_or("MEDIUM");
            let issue_text = result["issue_text"].as_str().unwrap_or(test_name);
            let code = result["code"].as_str().unwrap_or("");

            let affected = format!("{filename}:{line}");

            let mut finding = Finding::new(
                "bandit",
                map_bandit_severity(severity_str),
                format!("{test_id}: {test_name}"),
                issue_text,
                &affected,
            )
            .with_confidence(map_bandit_confidence(confidence_str))
            .with_remediation(format!(
                "Review and fix the issue identified by Bandit rule {test_id} ({test_name})."
            ))
            .with_owasp("A03:2021 Injection");

            if !code.is_empty() {
                finding = finding.with_evidence(code);
            }

            // Extract CWE from issue_cwe object
            if let Some(cwe_id) = result["issue_cwe"]["id"].as_u64() {
                // JUSTIFICATION: CWE IDs are well within u32 range (max ~1400)
                #[allow(clippy::cast_possible_truncation)]
                {
                    finding = finding.with_cwe(cwe_id as u32);
                }
            }

            Some(finding)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Bandit JSON output is correctly parsed into findings
    /// with severity, confidence, CWE, and evidence extraction.
    #[test]
    fn test_parse_bandit_output() {
        let output = r#"{
            "results": [
                {
                    "test_id": "B301",
                    "test_name": "blacklist_imports",
                    "filename": "app/utils.py",
                    "line_number": 12,
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": "Use of unsafe pickle module detected.",
                    "code": "import pickle\n",
                    "issue_cwe": {"id": 502, "link": "https://cwe.mitre.org/data/definitions/502.html"}
                },
                {
                    "test_id": "B105",
                    "test_name": "hardcoded_password_string",
                    "filename": "config/settings.py",
                    "line_number": 45,
                    "issue_severity": "LOW",
                    "issue_confidence": "MEDIUM",
                    "issue_text": "Possible hardcoded password: 'admin123'",
                    "code": "PASSWORD = 'admin123'\n",
                    "issue_cwe": {"id": 259, "link": "https://cwe.mitre.org/data/definitions/259.html"}
                }
            ]
        }"#;

        let findings = parse_bandit_output(output);
        assert_eq!(findings.len(), 2);

        // First finding: HIGH severity, HIGH confidence
        assert_eq!(findings[0].affected_target, "app/utils.py:12");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("B301"));
        assert_eq!(findings[0].cwe_id, Some(502));
        assert!(findings[0].evidence.as_ref().is_some_and(|e| e.contains("pickle")));
        assert!((findings[0].confidence - 0.9).abs() < f64::EPSILON);

        // Second finding: LOW severity, MEDIUM confidence
        assert_eq!(findings[1].affected_target, "config/settings.py:45");
        assert_eq!(findings[1].severity, Severity::Low);
        assert_eq!(findings[1].cwe_id, Some(259));
        assert!((findings[1].confidence - 0.7).abs() < f64::EPSILON);
    }

    /// Verify empty or invalid input produces no findings.
    #[test]
    fn test_parse_bandit_empty() {
        assert!(parse_bandit_output("").is_empty());
        assert!(parse_bandit_output(r#"{"results": []}"#).is_empty());
        assert!(parse_bandit_output("not json").is_empty());
    }
}
