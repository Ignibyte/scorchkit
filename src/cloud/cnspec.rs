//! `cnspec` as a `CloudModule` — Mondoo cloud security & compliance (WORK-130).
//!
//! Wraps the `cnspec` binary for multi-cloud posture audits. Outputs
//! JSON via `cnspec scan --output json` and parses failed policies
//! into findings.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Timeout for a `cnspec` scan.
const CNSPEC_TIMEOUT: Duration = Duration::from_secs(600);

/// Mondoo `cnspec` cloud security and compliance scanner.
///
/// Runs `cnspec scan` against the configured cloud target and
/// parses policy failures into findings.
#[derive(Debug)]
pub struct CnspecCloudModule;

#[async_trait]
impl CloudModule for CnspecCloudModule {
    fn name(&self) -> &'static str {
        "Mondoo cnspec Cloud Security"
    }

    fn id(&self) -> &'static str {
        "cnspec-cloud"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Compliance
    }

    fn description(&self) -> &'static str {
        "Mondoo cnspec cloud-native security and compliance scanner"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&'static str> {
        Some("cnspec")
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Aws, CloudProvider::Gcp, CloudProvider::Azure]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let argv = vec!["scan", "--output", "json", "--score-threshold", "0"];
        let output = subprocess::run_tool_lenient("cnspec", &argv, CNSPEC_TIMEOUT).await?;
        let target_label = ctx.target.display_raw();
        Ok(parse_cnspec_output(&output.stdout, &target_label))
    }
}

/// Parse `cnspec` JSON output into findings.
#[must_use]
pub fn parse_cnspec_output(stdout: &str, target_label: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let policies =
        v["data"].as_object().or_else(|| v["policies"].as_object()).cloned().unwrap_or_default();

    for (_policy_id, policy) in &policies {
        let checks = policy["checks"].as_object().cloned().unwrap_or_default();
        for (check_id, check) in &checks {
            let score = check["score"].as_u64().unwrap_or(100);
            if score >= 80 {
                continue; // passing or near-passing
            }

            let title = check["title"].as_str().unwrap_or(check_id.as_str());
            let severity = if score == 0 {
                Severity::Critical
            } else if score < 40 {
                Severity::High
            } else if score < 60 {
                Severity::Medium
            } else {
                Severity::Low
            };

            let evidence = CloudEvidence::new(CloudProvider::Aws, "compliance")
                .with_check_id(check_id)
                .with_detail("score", score.to_string());

            let finding = Finding::new(
                "cnspec-cloud",
                severity,
                format!("cnspec: {title}"),
                check["desc"].as_str().unwrap_or("").to_string(),
                format!("cloud://{target_label}"),
            )
            .with_evidence(evidence.to_string())
            .with_remediation(
                check["remediation"].as_str().unwrap_or("Review the cnspec policy documentation."),
            )
            .with_confidence(0.85);
            findings.push(enrich_cloud_finding(finding, "compliance"));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Failed cnspec check → finding with score-based severity.
    #[test]
    fn test_cnspec_parse_failed_check() {
        let json = r#"{
            "data": {
                "policy-1": {
                    "checks": {
                        "check-root-mfa": {
                            "title": "Root MFA enabled",
                            "desc": "Root account should have MFA",
                            "score": 0,
                            "remediation": "Enable MFA"
                        },
                        "check-passing": {
                            "title": "Passing check",
                            "desc": "This passes",
                            "score": 100
                        }
                    }
                }
            }
        }"#;
        let findings = parse_cnspec_output(json, "aws:123");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("Root MFA"));
    }

    /// Empty output → zero findings.
    #[test]
    fn test_cnspec_empty_output() {
        assert!(parse_cnspec_output("", "aws:123").is_empty());
        assert!(parse_cnspec_output("{}", "aws:123").is_empty());
    }

    /// Module metadata.
    #[test]
    fn test_cnspec_module_metadata() {
        let m = CnspecCloudModule;
        assert_eq!(m.id(), "cnspec-cloud");
        assert_eq!(m.category(), CloudCategory::Compliance);
        assert!(m.requires_external_tool());
        assert_eq!(m.required_tool(), Some("cnspec"));
    }
}
