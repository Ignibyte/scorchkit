//! `cloudsplaining` as a `CloudModule` — Salesforce IAM least-privilege auditor (WORK-130).
//!
//! Wraps the `cloudsplaining` binary to identify over-privileged IAM
//! roles and policies in an AWS account. Outputs JSON and maps
//! findings to IAM posture violations.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Timeout for a `cloudsplaining` scan.
const CLOUDSPLAINING_TIMEOUT: Duration = Duration::from_secs(300);

/// Salesforce `cloudsplaining` IAM least-privilege auditor.
///
/// Identifies over-privileged IAM roles, policies, and users in an
/// AWS account. Reports privilege escalation paths, data exfiltration
/// risks, and overly permissive resource exposure.
#[derive(Debug)]
pub struct CloudsplainingCloudModule;

#[async_trait]
impl CloudModule for CloudsplainingCloudModule {
    fn name(&self) -> &'static str {
        "Cloudsplaining IAM Auditor"
    }

    fn id(&self) -> &'static str {
        "cloudsplaining-cloud"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Iam
    }

    fn description(&self) -> &'static str {
        "Cloudsplaining IAM least-privilege auditor — finds over-privileged AWS roles"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&'static str> {
        Some("cloudsplaining")
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Aws]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let tmp = tempfile::tempdir()
            .map_err(|e| crate::engine::error::ScorchError::Config(format!("tempdir: {e}")))?;
        let output_dir = tmp.path().to_string_lossy().to_string();
        let argv = vec!["scan", "--output", &output_dir, "--skip-open-report"];
        let _output =
            subprocess::run_tool_lenient("cloudsplaining", &argv, CLOUDSPLAINING_TIMEOUT).await?;

        let target_label = ctx.target.display_raw();

        // Read the JSON results file
        let results_path = format!("{output_dir}/iam-results.json");
        let json = std::fs::read_to_string(&results_path).unwrap_or_default();
        Ok(parse_cloudsplaining_output(&json, &target_label))
    }
}

/// Parse `cloudsplaining` JSON output.
#[must_use]
pub fn parse_cloudsplaining_output(json: &str, target_label: &str) -> Vec<Finding> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    // Privilege escalation risks
    for risk in v["privilege_escalation"].as_array().cloned().unwrap_or_default() {
        let name = risk["PolicyName"].as_str().unwrap_or("unknown");
        let actions = risk["Actions"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();

        let evidence = CloudEvidence::new(CloudProvider::Aws, "iam")
            .with_check_id("cloudsplaining-privesc")
            .with_resource(name)
            .with_detail("actions", &actions);

        let finding = Finding::new(
            "cloudsplaining-cloud",
            Severity::Critical,
            format!("Cloudsplaining: Privilege escalation via '{name}'"),
            format!("Policy '{name}' allows privilege escalation through: {actions}"),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Restrict the policy to remove privilege escalation paths.")
        .with_confidence(0.85);
        findings.push(enrich_cloud_finding(finding, "iam"));
    }

    // Data exfiltration risks
    for risk in v["data_exfiltration"].as_array().cloned().unwrap_or_default() {
        let name = risk["PolicyName"].as_str().unwrap_or("unknown");

        let evidence = CloudEvidence::new(CloudProvider::Aws, "iam")
            .with_check_id("cloudsplaining-data-exfil")
            .with_resource(name);

        let finding = Finding::new(
            "cloudsplaining-cloud",
            Severity::High,
            format!("Cloudsplaining: Data exfiltration risk via '{name}'"),
            format!("Policy '{name}' grants permissions that could enable data exfiltration"),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Restrict data access permissions to specific resources.")
        .with_confidence(0.8);
        findings.push(enrich_cloud_finding(finding, "iam"));
    }

    // Resource exposure
    for risk in v["resource_exposure"].as_array().cloned().unwrap_or_default() {
        let name = risk["PolicyName"].as_str().unwrap_or("unknown");

        let evidence = CloudEvidence::new(CloudProvider::Aws, "iam")
            .with_check_id("cloudsplaining-resource-exposure")
            .with_resource(name);

        let finding = Finding::new(
            "cloudsplaining-cloud",
            Severity::High,
            format!("Cloudsplaining: Resource exposure via '{name}'"),
            format!("Policy '{name}' grants permissions that could expose resources publicly"),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Restrict resource-sharing permissions to prevent public exposure.")
        .with_confidence(0.8);
        findings.push(enrich_cloud_finding(finding, "iam"));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Privilege escalation found → Critical finding.
    #[test]
    fn test_cloudsplaining_privesc() {
        let json = r#"{
            "privilege_escalation": [
                {"PolicyName": "AdminPolicy", "Actions": ["iam:CreateUser", "iam:AttachUserPolicy"]}
            ],
            "data_exfiltration": [],
            "resource_exposure": []
        }"#;
        let findings = parse_cloudsplaining_output(json, "aws:123");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("Privilege escalation"));
        assert!(findings[0].compliance.is_some());
    }

    /// All three risk categories → multiple findings.
    #[test]
    fn test_cloudsplaining_all_risks() {
        let json = r#"{
            "privilege_escalation": [{"PolicyName": "P1", "Actions": ["iam:*"]}],
            "data_exfiltration": [{"PolicyName": "P2"}],
            "resource_exposure": [{"PolicyName": "P3"}]
        }"#;
        let findings = parse_cloudsplaining_output(json, "aws:123");
        assert_eq!(findings.len(), 3);
    }

    /// Empty output → zero findings.
    #[test]
    fn test_cloudsplaining_empty() {
        assert!(parse_cloudsplaining_output("", "aws:123").is_empty());
        assert!(parse_cloudsplaining_output("{}", "aws:123").is_empty());
    }

    /// Module metadata.
    #[test]
    fn test_cloudsplaining_module_metadata() {
        let m = CloudsplainingCloudModule;
        assert_eq!(m.id(), "cloudsplaining-cloud");
        assert_eq!(m.category(), CloudCategory::Iam);
        assert!(m.requires_external_tool());
        assert_eq!(m.required_tool(), Some("cloudsplaining"));
        assert_eq!(m.providers(), &[CloudProvider::Aws]);
    }
}
