//! OSV-Scanner wrapper for dependency vulnerability scanning.
//!
//! Wraps Google's `osv-scanner` tool which checks project dependencies
//! against the OSV (Open Source Vulnerabilities) database across all
//! major package ecosystems.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Dependency vulnerability scanning via OSV-Scanner.
#[derive(Debug)]
pub struct OsvScannerModule;

#[async_trait]
impl CodeModule for OsvScannerModule {
    fn name(&self) -> &'static str {
        "OSV-Scanner"
    }
    fn id(&self) -> &'static str {
        "osv-scanner"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sca
    }
    fn description(&self) -> &'static str {
        "Dependency vulnerability scanning across all ecosystems via OSV-Scanner"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("osv-scanner")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        // osv-scanner exits 1 when vulnerabilities are found — that's normal,
        // not an error. Use run_tool_lenient to capture stdout regardless.
        let output = subprocess::run_tool_lenient(
            "osv-scanner",
            &["--json", "--recursive", &path_str],
            Duration::from_secs(120),
        )
        .await?;

        Ok(parse_osv_output(&output.stdout))
    }
}

/// Map OSV/CVSS severity strings to `ScorchKit` severity levels.
fn map_osv_severity(severity: &str) -> Severity {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MODERATE" | "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse OSV-Scanner JSON output into findings.
///
/// OSV-Scanner outputs a JSON object with a `results` array. Each result
/// contains `packages` (with `name` and `version`) and `vulnerabilities`
/// (with `id`, `summary`, `severity`, and `aliases`).
#[must_use]
pub fn parse_osv_output(stdout: &str) -> Vec<Finding> {
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

    let mut findings = Vec::new();

    for result in results {
        let Some(packages) = result["packages"].as_array() else {
            continue;
        };

        for pkg_entry in packages {
            let pkg_name = pkg_entry["package"]["name"].as_str().unwrap_or("unknown");
            let pkg_version = pkg_entry["package"]["version"].as_str().unwrap_or("unknown");
            let affected_target = format!("{pkg_name}@{pkg_version}");

            let Some(vulns) = pkg_entry["vulnerabilities"].as_array() else {
                continue;
            };

            for vuln in vulns {
                let vuln_id = vuln["id"].as_str().unwrap_or("unknown");
                let summary = vuln["summary"].as_str().unwrap_or(vuln_id);

                // Try to extract severity from database_specific or severity array
                let severity = vuln["database_specific"]["severity"]
                    .as_str()
                    .or_else(|| {
                        vuln["severity"]
                            .as_array()
                            .and_then(|arr| arr.first())
                            .and_then(|s| s["rating"].as_str())
                    })
                    .unwrap_or("MEDIUM");

                // Collect aliases (CVE cross-references)
                let aliases: Vec<&str> = vuln["aliases"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();

                let evidence = if aliases.is_empty() {
                    format!("Package: {pkg_name} {pkg_version}")
                } else {
                    format!("Package: {pkg_name} {pkg_version} | Aliases: {}", aliases.join(", "))
                };

                findings.push(
                    Finding::new(
                        "osv-scanner",
                        map_osv_severity(severity),
                        format!("{vuln_id}: {summary}"),
                        format!("Vulnerable dependency {pkg_name} {pkg_version}: {summary}"),
                        &affected_target,
                    )
                    .with_evidence(evidence)
                    .with_remediation(format!("Update {pkg_name} to a patched version."))
                    .with_owasp("A06:2021 Vulnerable and Outdated Components")
                    .with_cwe(1104)
                    .with_confidence(0.9),
                );
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify OSV-Scanner JSON output is correctly parsed.
    #[test]
    fn test_parse_osv_output() {
        let output = r#"{
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-jf85-cpcp-j695",
                                    "summary": "Prototype Pollution in lodash",
                                    "aliases": ["CVE-2021-23337"],
                                    "database_specific": {"severity": "HIGH"}
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        let findings = parse_osv_output(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].affected_target, "lodash@4.17.20");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("GHSA-jf85-cpcp-j695"));
        assert!(findings[0].evidence.as_ref().is_some_and(|e| e.contains("CVE-2021-23337")));
    }

    /// Verify empty or missing results produce no findings.
    #[test]
    fn test_parse_osv_empty() {
        assert!(parse_osv_output("").is_empty());
        assert!(parse_osv_output(r#"{"results": []}"#).is_empty());
        assert!(parse_osv_output("not json").is_empty());
    }
}
