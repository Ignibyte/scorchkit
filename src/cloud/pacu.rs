//! `pacu` as a `CloudModule` — Rhino Security AWS exploitation framework (WORK-130).
//!
//! Wraps the `pacu` binary for offensive AWS validation. Runs
//! `pacu --exec` with reconnaissance modules and parses the session
//! data for discovered attack surfaces.
//!
//! **Important:** `pacu` is an offensive security tool. Findings from
//! this module indicate attack surfaces discovered during authorized
//! penetration testing, not configuration weaknesses.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Timeout for a `pacu` session.
const PACU_TIMEOUT: Duration = Duration::from_secs(600);

/// Rhino Security `pacu` AWS exploitation framework.
///
/// Runs reconnaissance modules against the active AWS session and
/// reports discovered attack surfaces. **For authorized testing only.**
#[derive(Debug)]
pub struct PacuCloudModule;

#[async_trait]
impl CloudModule for PacuCloudModule {
    fn name(&self) -> &'static str {
        "Pacu AWS Exploitation Recon"
    }

    fn id(&self) -> &'static str {
        "pacu-cloud"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Iam
    }

    fn description(&self) -> &'static str {
        "Pacu AWS exploitation framework — offensive recon for authorized testing"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&'static str> {
        Some("pacu")
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Aws]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let argv = vec!["--exec", "run iam__enum_permissions", "--set-regions", "all"];
        let output = subprocess::run_tool_lenient("pacu", &argv, PACU_TIMEOUT).await?;
        let target_label = ctx.target.display_raw();
        Ok(parse_pacu_output(&output.stdout, &target_label))
    }
}

/// Parse `pacu` output for discovered attack surfaces.
#[must_use]
pub fn parse_pacu_output(stdout: &str, target_label: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    // Parse Pacu's session data — permissions discovered
    let permissions = v["Permissions"]["Allow"].as_object().cloned().unwrap_or_default();

    for (action, _) in &permissions {
        // Flag high-risk actions
        let is_high_risk = action.contains('*')
            || action.starts_with("iam:Create")
            || action.starts_with("iam:Attach")
            || action.starts_with("sts:AssumeRole")
            || action.starts_with("lambda:Create")
            || action.starts_with("ec2:RunInstances");

        if !is_high_risk {
            continue;
        }

        let evidence = CloudEvidence::new(CloudProvider::Aws, "iam")
            .with_check_id("pacu-high-risk-permission")
            .with_detail("action", action);

        let finding = Finding::new(
            "pacu-cloud",
            Severity::High,
            format!("Pacu: High-risk permission discovered — {action}"),
            format!(
                "The active AWS session has the high-risk permission '{action}'. \
                 This could be leveraged for privilege escalation or lateral movement. \
                 (Discovered via authorized penetration testing)"
            ),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation(
            "Review IAM policies and apply least-privilege. Remove unused high-risk permissions.",
        )
        .with_confidence(0.75);
        findings.push(enrich_cloud_finding(finding, "iam"));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// High-risk permission discovered → High finding.
    #[test]
    fn test_pacu_high_risk_permission() {
        let json = r#"{
            "Permissions": {
                "Allow": {
                    "iam:CreateUser": {"Effect": "Allow"},
                    "s3:GetObject": {"Effect": "Allow"},
                    "sts:AssumeRole": {"Effect": "Allow"}
                }
            }
        }"#;
        let findings = parse_pacu_output(json, "aws:123");
        assert_eq!(findings.len(), 2, "only iam:CreateUser and sts:AssumeRole are high-risk");
        assert!(findings.iter().all(|f| f.severity == Severity::High));
    }

    /// No high-risk permissions → zero findings.
    #[test]
    fn test_pacu_no_high_risk() {
        let json = r#"{"Permissions": {"Allow": {"s3:GetObject": {}}}}"#;
        assert!(parse_pacu_output(json, "aws:123").is_empty());
    }

    /// Empty output → zero findings.
    #[test]
    fn test_pacu_empty() {
        assert!(parse_pacu_output("", "aws:123").is_empty());
    }

    /// Module metadata.
    #[test]
    fn test_pacu_module_metadata() {
        let m = PacuCloudModule;
        assert_eq!(m.id(), "pacu-cloud");
        assert!(m.requires_external_tool());
        assert_eq!(m.required_tool(), Some("pacu"));
        assert_eq!(m.providers(), &[CloudProvider::Aws]);
    }
}
