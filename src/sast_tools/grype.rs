//! Grype wrapper for container and dependency vulnerability scanning.
//!
//! Wraps the `grype` tool which scans container images, filesystems,
//! and SBOMs for known vulnerabilities. Grype matches packages against
//! the Anchore vulnerability database covering CVEs across all major
//! package ecosystems and container base images.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Container and dependency vulnerability scanning via Grype.
#[derive(Debug)]
pub struct GrypeModule;

#[async_trait]
impl CodeModule for GrypeModule {
    fn name(&self) -> &'static str {
        "Grype Vulnerability Scanner"
    }
    fn id(&self) -> &'static str {
        "grype"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Container
    }
    fn description(&self) -> &'static str {
        "Container image and dependency vulnerability scanning via Grype"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("grype")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_arg = format!("dir:{}", ctx.path.display());
        // grype exits 1 when vulnerabilities are found — that's normal, not an error.
        let output = subprocess::run_tool_lenient(
            "grype",
            &[&path_arg, "-o", "json", "--quiet"],
            Duration::from_secs(120),
        )
        .await?;

        Ok(parse_grype_output(&output.stdout))
    }
}

/// Map Grype/CVSS severity strings to `ScorchKit` severity levels.
fn map_grype_severity(severity: &str) -> Severity {
    match severity.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse Grype JSON output into findings.
///
/// Grype outputs a JSON object with a `matches` array. Each match
/// contains `vulnerability` (with `id`, `severity`, `description`,
/// `fix` versions, and `urls`) and `artifact` (with `name`, `version`,
/// `type`).
#[must_use]
pub fn parse_grype_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(root) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };

    let Some(matches) = root["matches"].as_array() else {
        return Vec::new();
    };

    matches
        .iter()
        .filter_map(|m| {
            let vuln = &m["vulnerability"];
            let artifact = &m["artifact"];

            let vuln_id = vuln["id"].as_str()?;
            let severity_str = vuln["severity"].as_str().unwrap_or("Unknown");
            let description = vuln["description"].as_str().unwrap_or(vuln_id);

            let pkg_name = artifact["name"].as_str().unwrap_or("unknown");
            let pkg_version = artifact["version"].as_str().unwrap_or("unknown");
            let pkg_type = artifact["type"].as_str().unwrap_or("unknown");

            let affected = format!("{pkg_name}@{pkg_version}");

            // Check for fix versions
            let fix_versions: Vec<&str> = vuln["fix"]["versions"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();

            let evidence = format!("Package: {pkg_name} {pkg_version} ({pkg_type})");

            let remediation = if fix_versions.is_empty() {
                format!("No fix available yet for {vuln_id} in {pkg_name}. Monitor for updates.")
            } else {
                format!("Update {pkg_name} to version {}.", fix_versions.join(" or "))
            };

            // Collect related CVE/advisory URLs for context
            let urls: Vec<&str> = vuln["urls"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();

            let full_evidence = if urls.is_empty() {
                evidence
            } else {
                format!("{evidence} | Refs: {}", urls.join(", "))
            };

            Some(
                Finding::new(
                    "grype",
                    map_grype_severity(severity_str),
                    format!("{vuln_id}: {pkg_name}@{pkg_version}"),
                    description,
                    &affected,
                )
                .with_evidence(full_evidence)
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

    /// Verify Grype JSON output is correctly parsed into findings
    /// with vulnerability details, fix versions, and reference URLs.
    #[test]
    fn test_parse_grype_output() {
        let output = r#"{
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-44487",
                        "severity": "Critical",
                        "description": "HTTP/2 Rapid Reset attack vulnerability",
                        "fix": {
                            "versions": ["1.58.3", "1.59.2"],
                            "state": "fixed"
                        },
                        "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"]
                    },
                    "artifact": {
                        "name": "golang.org/x/net",
                        "version": "0.15.0",
                        "type": "go-module"
                    }
                },
                {
                    "vulnerability": {
                        "id": "GHSA-xxxx-yyyy-zzzz",
                        "severity": "Low",
                        "description": "Minor information disclosure",
                        "fix": {
                            "versions": [],
                            "state": "unknown"
                        },
                        "urls": []
                    },
                    "artifact": {
                        "name": "libc",
                        "version": "0.2.140",
                        "type": "rust-crate"
                    }
                }
            ]
        }"#;

        let findings = parse_grype_output(output);
        assert_eq!(findings.len(), 2);

        // First finding: Critical with fix versions and URL
        assert_eq!(findings[0].affected_target, "golang.org/x/net@0.15.0");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("CVE-2023-44487"));
        assert!(findings[0]
            .evidence
            .as_ref()
            .is_some_and(|e| e.contains("go-module") && e.contains("nvd.nist.gov")));
        assert!(findings[0].remediation.as_ref().is_some_and(|r| r.contains("1.58.3")));
        assert_eq!(findings[0].cwe_id, Some(1104));

        // Second finding: Low, no fix available
        assert_eq!(findings[1].affected_target, "libc@0.2.140");
        assert_eq!(findings[1].severity, Severity::Low);
        assert!(findings[1].remediation.as_ref().is_some_and(|r| r.contains("No fix available")));
    }

    /// Verify empty or invalid input produces no findings.
    #[test]
    fn test_parse_grype_empty() {
        assert!(parse_grype_output("").is_empty());
        assert!(parse_grype_output(r#"{"matches": []}"#).is_empty());
        assert!(parse_grype_output("not json").is_empty());
    }
}
