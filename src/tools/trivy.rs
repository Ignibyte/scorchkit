//! `Trivy` wrapper for container and dependency vulnerability scanning.
//!
//! Wraps the `trivy` tool for scanning container images, filesystems,
//! and git repositories for known vulnerabilities, misconfigurations,
//! and license issues.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Container and dependency vulnerability scanning via Trivy.
#[derive(Debug)]
pub struct TrivyModule;

#[async_trait]
impl ScanModule for TrivyModule {
    fn name(&self) -> &'static str {
        "Trivy Vulnerability Scanner"
    }

    fn id(&self) -> &'static str {
        "trivy"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Container image and dependency vulnerability scanning via Trivy"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("trivy")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());

        let output = subprocess::run_tool(
            "trivy",
            &["fs", "--format", "json", "--quiet", target],
            Duration::from_secs(300),
        )
        .await?;

        Ok(parse_trivy_output(&output.stdout, ctx.target.url.as_str()))
    }
}

/// Map Trivy/CVSS severity strings to `ScorchKit` severity levels.
fn map_trivy_severity(severity: &str) -> Severity {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse Trivy JSON output into findings.
///
/// Trivy outputs a JSON object with a `Results` array. Each result
/// contains a `Vulnerabilities` array with `VulnerabilityID`, `Severity`,
/// `Title`, `Description`, `PkgName`, `InstalledVersion`, and
/// `FixedVersion` fields.
#[must_use]
fn parse_trivy_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(root) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };

    let Some(results) = root["Results"].as_array() else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    for result in results {
        let target_name = result["Target"].as_str().unwrap_or("unknown");

        let Some(vulns) = result["Vulnerabilities"].as_array() else {
            continue;
        };

        for vuln in vulns {
            let vuln_id = vuln["VulnerabilityID"].as_str().unwrap_or("unknown");
            let severity_str = vuln["Severity"].as_str().unwrap_or("UNKNOWN");
            let title = vuln["Title"].as_str().unwrap_or(vuln_id);
            let pkg_name = vuln["PkgName"].as_str().unwrap_or("unknown");
            let installed = vuln["InstalledVersion"].as_str().unwrap_or("unknown");
            let fixed = vuln["FixedVersion"].as_str().unwrap_or("no fix available");

            findings.push(
                Finding::new(
                    "trivy",
                    map_trivy_severity(severity_str),
                    format!("{vuln_id}: {title}"),
                    format!(
                        "Vulnerable package {pkg_name} {installed} in {target_name}. \
                         Fix available: {fixed}."
                    ),
                    target_url,
                )
                .with_evidence(format!(
                    "Package: {pkg_name} | Installed: {installed} | Fixed: {fixed} | \
                     Target: {target_name}"
                ))
                .with_remediation(format!("Update {pkg_name} from {installed} to {fixed}."))
                .with_owasp("A06:2021 Vulnerable and Outdated Components")
                .with_cwe(1104)
                .with_confidence(0.8),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Trivy JSON output parsing with vulnerabilities and
    /// severity mapping.
    #[test]
    fn test_parse_trivy_output() {
        let output = r#"{
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "Severity": "HIGH",
                            "Title": "Prototype Pollution in lodash",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.20",
                            "FixedVersion": "4.17.21"
                        },
                        {
                            "VulnerabilityID": "CVE-2023-5678",
                            "Severity": "CRITICAL",
                            "Title": "RCE in express",
                            "PkgName": "express",
                            "InstalledVersion": "4.17.1",
                            "FixedVersion": "4.18.2"
                        }
                    ]
                }
            ]
        }"#;

        let findings = parse_trivy_output(output, "https://example.com");
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("CVE-2023-1234"));
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[1].title.contains("CVE-2023-5678"));
        assert_eq!(findings[1].severity, Severity::Critical);
    }

    /// Verify empty or no-vulnerability output produces no findings.
    #[test]
    fn test_parse_trivy_empty() {
        let findings = parse_trivy_output("", "https://example.com");
        assert!(findings.is_empty());

        let findings = parse_trivy_output(r#"{"Results": []}"#, "https://example.com");
        assert!(findings.is_empty());

        let findings =
            parse_trivy_output(r#"{"Results": [{"Target": "x"}]}"#, "https://example.com");
        assert!(findings.is_empty());
    }
}
