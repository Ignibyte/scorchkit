//! Snyk Code wrapper for static application security testing.
//!
//! Wraps `snyk code test` which performs SAST analysis on source code
//! to detect security issues. Works with the free tier (limited scans).

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Source code security analysis via Snyk Code.
#[derive(Debug)]
pub struct SnykCodeModule;

#[async_trait]
impl CodeModule for SnykCodeModule {
    fn name(&self) -> &'static str {
        "Snyk Code SAST"
    }
    fn id(&self) -> &'static str {
        "snyk-code"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sast
    }
    fn description(&self) -> &'static str {
        "Source code security analysis via Snyk Code (free tier compatible)"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("snyk")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        // snyk code test exits 1 when issues are found — that's normal.
        let output = subprocess::run_tool_lenient(
            "snyk",
            &["code", "test", "--json", &path_str],
            Duration::from_secs(300),
        )
        .await?;

        Ok(parse_snyk_code_output(&output.stdout))
    }
}

/// Map Snyk Code severity to `ScorchKit` severity levels.
const fn map_snyk_code_severity(level: u64) -> Severity {
    match level {
        3 => Severity::High,
        2 => Severity::Medium,
        1 => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse Snyk Code test JSON output into findings.
///
/// Snyk Code outputs a JSON object with `runs[0].results` (SARIF-like format).
/// Each result has `ruleId`, `message.text`, `level` (error/warning/note),
/// and `locations` with file path and line numbers.
#[must_use]
pub fn parse_snyk_code_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(root) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };

    // Snyk Code uses SARIF-like format: runs[0].results
    let results = root["runs"]
        .as_array()
        .and_then(|runs| runs.first())
        .and_then(|run| run["results"].as_array());

    let Some(results) = results else {
        return Vec::new();
    };

    results
        .iter()
        .filter_map(|result| {
            let rule_id = result["ruleId"].as_str()?;
            let message = result["message"]["text"].as_str().unwrap_or(rule_id);
            let severity = result["properties"]["priorityScore"].as_u64().unwrap_or(2);

            // Extract location from first physical location
            let location = result["locations"]
                .as_array()
                .and_then(|locs| locs.first())
                .and_then(|loc| loc["physicalLocation"].as_object());

            let (file, line) = location.map_or_else(
                || ("unknown".to_string(), 0u64),
                |loc| {
                    let file = loc
                        .get("artifactLocation")
                        .and_then(|a| a["uri"].as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let line = loc.get("region").and_then(|r| r["startLine"].as_u64()).unwrap_or(0);
                    (file, line)
                },
            );

            let affected = format!("{file}:{line}");

            Some(
                Finding::new(
                    "snyk-code",
                    map_snyk_code_severity(severity),
                    format!("{rule_id}: {message}"),
                    message,
                    &affected,
                )
                .with_remediation(format!("Fix the issue identified by Snyk Code rule {rule_id}."))
                .with_owasp("A03:2021 Injection")
                .with_confidence(0.8),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Snyk Code SARIF-like JSON output is correctly parsed
    /// with rule IDs, file locations, and severity mapping.
    #[test]
    fn test_parse_snyk_code_output() {
        let output = r#"{
            "runs": [{
                "results": [
                    {
                        "ruleId": "javascript/SqlInjection",
                        "message": {"text": "Unsanitized input from HTTP request flows into SQL query"},
                        "level": "error",
                        "properties": {"priorityScore": 3},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/db.js"},
                                "region": {"startLine": 42}
                            }
                        }]
                    },
                    {
                        "ruleId": "javascript/HardcodedSecret",
                        "message": {"text": "Hardcoded secret detected"},
                        "level": "warning",
                        "properties": {"priorityScore": 2},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "config/keys.js"},
                                "region": {"startLine": 10}
                            }
                        }]
                    }
                ]
            }]
        }"#;

        let findings = parse_snyk_code_output(output);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].affected_target, "src/db.js:42");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("SqlInjection"));
        assert_eq!(findings[1].affected_target, "config/keys.js:10");
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    /// Verify empty or invalid input produces no findings.
    #[test]
    fn test_parse_snyk_code_empty() {
        assert!(parse_snyk_code_output("").is_empty());
        assert!(parse_snyk_code_output("not json").is_empty());
        assert!(parse_snyk_code_output(r#"{"runs": [{"results": []}]}"#).is_empty());
    }
}
