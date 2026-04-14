//! Gosec wrapper for Go static analysis.
//!
//! Wraps the `gosec` tool which inspects Go source code for security
//! problems by scanning the Go AST for patterns that indicate potential
//! vulnerabilities such as SQL injection, command injection, and weak crypto.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Go security analysis via Gosec.
#[derive(Debug)]
pub struct GosecModule;

#[async_trait]
impl CodeModule for GosecModule {
    fn name(&self) -> &'static str {
        "Gosec Go SAST"
    }
    fn id(&self) -> &'static str {
        "gosec"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sast
    }
    fn description(&self) -> &'static str {
        "Go security static analysis for common vulnerabilities via Gosec"
    }
    fn languages(&self) -> &[&str] {
        &["go"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("gosec")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_arg = format!("{}/...", ctx.path.display());
        // gosec exits 1 when issues are found — that's normal, not an error.
        let output = subprocess::run_tool_lenient(
            "gosec",
            &["-fmt", "json", "-quiet", &path_arg],
            Duration::from_secs(120),
        )
        .await?;

        Ok(parse_gosec_output(&output.stdout))
    }
}

/// Map Gosec severity strings to `ScorchKit` severity levels.
fn map_gosec_severity(severity: &str) -> Severity {
    match severity.to_uppercase().as_str() {
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Map Gosec confidence strings to numeric confidence values.
fn map_gosec_confidence(confidence: &str) -> f64 {
    match confidence.to_uppercase().as_str() {
        "HIGH" => 0.9,
        "LOW" => 0.5,
        _ => 0.7,
    }
}

/// Parse Gosec JSON output into findings.
///
/// Gosec outputs a JSON object with an `Issues` array. Each issue
/// contains `severity`, `confidence`, `cwe` (with `id`), `rule_id`,
/// `details`, `file`, `line`, and `code`.
#[must_use]
pub fn parse_gosec_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(root) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };

    let Some(issues) = root["Issues"].as_array() else {
        return Vec::new();
    };

    issues
        .iter()
        .filter_map(|issue| {
            let rule_id = issue["rule_id"].as_str()?;
            let details = issue["details"].as_str().unwrap_or(rule_id);
            let file = issue["file"].as_str().unwrap_or("unknown");
            let line = issue["line"].as_str().unwrap_or("0");
            let severity_str = issue["severity"].as_str().unwrap_or("MEDIUM");
            let confidence_str = issue["confidence"].as_str().unwrap_or("MEDIUM");
            let code = issue["code"].as_str().unwrap_or("");

            let affected = format!("{file}:{line}");

            let mut finding = Finding::new(
                "gosec",
                map_gosec_severity(severity_str),
                format!("{rule_id}: {details}"),
                details,
                &affected,
            )
            .with_confidence(map_gosec_confidence(confidence_str))
            .with_remediation(format!(
                "Review and fix the issue identified by Gosec rule {rule_id}."
            ))
            .with_owasp("A03:2021 Injection");

            if !code.is_empty() {
                finding = finding.with_evidence(code);
            }

            // Extract CWE — gosec provides it as cwe.id (string)
            if let Some(cwe_str) = issue["cwe"]["id"].as_str() {
                // CWE ID may have "CWE-" prefix or be bare number
                let num_str = cwe_str.strip_prefix("CWE-").unwrap_or(cwe_str);
                if let Ok(cwe_num) = num_str.parse::<u32>() {
                    finding = finding.with_cwe(cwe_num);
                }
            }

            Some(finding)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Gosec JSON output is correctly parsed into findings
    /// with severity, confidence, CWE, and code evidence.
    #[test]
    fn test_parse_gosec_output() {
        let output = r#"{
            "Issues": [
                {
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "cwe": {"id": "89"},
                    "rule_id": "G201",
                    "details": "SQL string formatting",
                    "file": "db/queries.go",
                    "line": "34",
                    "code": "query := fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", id)\n"
                },
                {
                    "severity": "MEDIUM",
                    "confidence": "LOW",
                    "cwe": {"id": "CWE-327"},
                    "rule_id": "G401",
                    "details": "Use of weak cryptographic primitive",
                    "file": "crypto/hash.go",
                    "line": "15",
                    "code": "h := md5.New()\n"
                }
            ],
            "Stats": {
                "files": 42,
                "lines": 3500,
                "nosec": 2,
                "found": 2
            }
        }"#;

        let findings = parse_gosec_output(output);
        assert_eq!(findings.len(), 2);

        // First finding: SQL injection, HIGH/HIGH
        assert_eq!(findings[0].affected_target, "db/queries.go:34");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("G201"));
        assert_eq!(findings[0].cwe_id, Some(89));
        assert!(findings[0].evidence.as_ref().is_some_and(|e| e.contains("SELECT")));
        assert!((findings[0].confidence - 0.9).abs() < f64::EPSILON);

        // Second finding: weak crypto, MEDIUM/LOW with CWE- prefix
        assert_eq!(findings[1].affected_target, "crypto/hash.go:15");
        assert_eq!(findings[1].severity, Severity::Medium);
        assert_eq!(findings[1].cwe_id, Some(327));
        assert!((findings[1].confidence - 0.5).abs() < f64::EPSILON);
    }

    /// Verify empty or invalid input produces no findings.
    #[test]
    fn test_parse_gosec_empty() {
        assert!(parse_gosec_output("").is_empty());
        assert!(parse_gosec_output(r#"{"Issues": []}"#).is_empty());
        assert!(parse_gosec_output("not json").is_empty());
    }
}
