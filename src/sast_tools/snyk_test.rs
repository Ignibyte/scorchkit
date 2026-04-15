//! Snyk dependency scanning wrapper.
//!
//! Wraps `snyk test` which checks project dependencies for known
//! vulnerabilities against the Snyk vulnerability database. Works
//! with the free tier (no paid license required).

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Dependency vulnerability scanning via Snyk.
#[derive(Debug)]
pub struct SnykTestModule;

#[async_trait]
impl CodeModule for SnykTestModule {
    fn name(&self) -> &'static str {
        "Snyk Dependency Scanner"
    }
    fn id(&self) -> &'static str {
        "snyk-test"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sca
    }
    fn description(&self) -> &'static str {
        "Dependency vulnerability scanning via Snyk (free tier compatible)"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("snyk")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        // snyk test exits 1 when vulnerabilities are found — that's normal.
        let output = subprocess::run_tool_lenient(
            "snyk",
            &["test", "--json", "--file", &path_str],
            Duration::from_secs(300),
        )
        .await?;

        Ok(parse_snyk_test_output(&output.stdout))
    }
}

/// Map Snyk severity strings to `ScorchKit` severity levels.
fn map_snyk_severity(severity: &str) -> Severity {
    match severity.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse Snyk test JSON output into findings.
///
/// Snyk test outputs a JSON object with a `vulnerabilities` array.
/// Each vulnerability has `id`, `title`, `severity`, `packageName`,
/// `version`, `from` (dependency path), and `fixedIn` (fix versions).
#[must_use]
pub fn parse_snyk_test_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(root) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };

    let Some(vulns) = root["vulnerabilities"].as_array() else {
        return Vec::new();
    };

    vulns
        .iter()
        .filter_map(|vuln| {
            let vuln_id = vuln["id"].as_str()?;
            let title = vuln["title"].as_str().unwrap_or(vuln_id);
            let severity_str = vuln["severity"].as_str().unwrap_or("medium");
            let pkg_name = vuln["packageName"].as_str().unwrap_or("unknown");
            let pkg_version = vuln["version"].as_str().unwrap_or("unknown");

            let affected = format!("{pkg_name}@{pkg_version}");

            // Extract fix versions
            let fix_versions: Vec<&str> = vuln["fixedIn"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();

            let remediation = if fix_versions.is_empty() {
                format!("No fix available yet for {vuln_id}. Monitor for updates.")
            } else {
                format!("Upgrade {pkg_name} to version {}.", fix_versions.join(" or "))
            };

            Some(
                Finding::new(
                    "snyk-test",
                    map_snyk_severity(severity_str),
                    format!("{vuln_id}: {title}"),
                    format!("Vulnerable dependency {pkg_name}@{pkg_version}: {title}"),
                    &affected,
                )
                .with_evidence(format!("Package: {pkg_name} {pkg_version}"))
                .with_remediation(remediation)
                .with_owasp("A06:2021 Vulnerable and Outdated Components")
                .with_cwe(1104)
                .with_confidence(0.9),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Snyk test JSON output is correctly parsed with vulnerability
    /// details, fix versions, and severity mapping.
    #[test]
    fn test_parse_snyk_test_output() {
        let output = r#"{
            "ok": false,
            "vulnerabilities": [
                {
                    "id": "SNYK-JS-LODASH-1018905",
                    "title": "Prototype Pollution",
                    "severity": "high",
                    "packageName": "lodash",
                    "version": "4.17.20",
                    "fixedIn": ["4.17.21"],
                    "from": ["my-app", "lodash@4.17.20"]
                },
                {
                    "id": "SNYK-JS-MINIMIST-559764",
                    "title": "Prototype Pollution",
                    "severity": "medium",
                    "packageName": "minimist",
                    "version": "1.2.5",
                    "fixedIn": [],
                    "from": ["my-app", "mkdirp@0.5.5", "minimist@1.2.5"]
                }
            ]
        }"#;

        let findings = parse_snyk_test_output(output);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].affected_target, "lodash@4.17.20");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("SNYK-JS-LODASH"));
        assert!(findings[0].remediation.as_ref().is_some_and(|r| r.contains("4.17.21")));
        assert!(findings[1].remediation.as_ref().is_some_and(|r| r.contains("No fix")));
    }

    /// Verify empty or invalid input produces no findings.
    #[test]
    fn test_parse_snyk_test_empty() {
        assert!(parse_snyk_test_output("").is_empty());
        assert!(parse_snyk_test_output(r#"{"ok": true}"#).is_empty());
        assert!(parse_snyk_test_output("not json").is_empty());
    }
}
