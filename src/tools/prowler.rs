//! `Prowler` wrapper for cloud security assessment.
//!
//! Wraps the `prowler` tool for AWS/multi-cloud infrastructure scanning:
//! public S3 buckets, overly permissive IAM, security group
//! misconfigurations, unencrypted storage, and metadata endpoint exposure.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Cloud infrastructure security assessment via Prowler.
#[derive(Debug)]
pub struct ProwlerModule;

#[async_trait]
impl ScanModule for ProwlerModule {
    fn name(&self) -> &'static str {
        "Prowler Cloud Scanner"
    }

    fn id(&self) -> &'static str {
        "prowler"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Cloud infrastructure security assessment via Prowler (AWS, Azure, GCP)"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("prowler")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let output = subprocess::run_tool(
            "prowler",
            &["-M", "json-ocsf", "--no-banner", "-q"],
            Duration::from_secs(600),
        )
        .await?;

        Ok(parse_prowler_output(&output.stdout, ctx.target.url.as_str()))
    }
}

/// Map Prowler severity strings to `ScorchKit` severity levels.
fn map_prowler_severity(severity: &str) -> Severity {
    match severity.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse Prowler JSON output (OCSF format) into findings.
///
/// Prowler outputs a JSON array of finding objects in OCSF format. Each
/// finding with `status_id != 1` (not PASS) is converted to a `ScorchKit`
/// finding with mapped severity.
#[must_use]
fn parse_prowler_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) else {
        // Try JSON lines format
        return parse_prowler_jsonl(stdout, target_url);
    };

    items
        .iter()
        .filter(|item| item["status_id"].as_i64().unwrap_or(0) != 1)
        .map(|item| {
            let check_title = item["finding_info"]["title"]
                .as_str()
                .or_else(|| item["metadata"]["event_code"].as_str())
                .unwrap_or("Unknown Check");
            let description =
                item["message"].as_str().or_else(|| item["status_detail"].as_str()).unwrap_or("");
            let severity_str = item["severity"].as_str().unwrap_or("informational");
            let service = item["resources"]
                .as_array()
                .and_then(|r| r.first())
                .and_then(|r| r["group"]["name"].as_str())
                .unwrap_or("unknown");

            Finding::new(
                "prowler",
                map_prowler_severity(severity_str),
                format!("Prowler: {check_title}"),
                format!("{description} (Service: {service})"),
                target_url,
            )
            .with_evidence(format!("Service: {service} | Severity: {severity_str}"))
            .with_remediation("Review the Prowler check documentation for remediation steps.")
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_confidence(0.8)
        })
        .collect()
}

/// Fallback parser for JSON-lines format (one JSON object per line).
fn parse_prowler_jsonl(stdout: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let Ok(item) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        if item["status_id"].as_i64().unwrap_or(0) == 1 {
            continue;
        }

        let check_title = item["finding_info"]["title"]
            .as_str()
            .or_else(|| item["metadata"]["event_code"].as_str())
            .unwrap_or("Unknown Check");
        let description =
            item["message"].as_str().or_else(|| item["status_detail"].as_str()).unwrap_or("");
        let severity_str = item["severity"].as_str().unwrap_or("informational");

        findings.push(
            Finding::new(
                "prowler",
                map_prowler_severity(severity_str),
                format!("Prowler: {check_title}"),
                description.to_string(),
                target_url,
            )
            .with_evidence(format!("Severity: {severity_str}"))
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_confidence(0.8),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Prowler JSON output parsing with FAIL findings and
    /// severity mapping.
    #[test]
    fn test_parse_prowler_output() {
        let output = r#"[
            {
                "status_id": 2,
                "finding_info": {"title": "S3 Bucket Public Access"},
                "message": "S3 bucket my-bucket has public read access enabled",
                "severity": "high",
                "resources": [{"group": {"name": "s3"}}]
            },
            {
                "status_id": 1,
                "finding_info": {"title": "IAM Root Account MFA"},
                "message": "Root account has MFA enabled",
                "severity": "critical",
                "resources": [{"group": {"name": "iam"}}]
            },
            {
                "status_id": 2,
                "finding_info": {"title": "CloudTrail Logging Disabled"},
                "message": "CloudTrail is not enabled in us-east-1",
                "severity": "medium",
                "resources": [{"group": {"name": "cloudtrail"}}]
            }
        ]"#;

        let findings = parse_prowler_output(output, "https://example.com");
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("S3 Bucket Public Access"));
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[1].title.contains("CloudTrail"));
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    /// Verify empty output produces no findings.
    #[test]
    fn test_parse_prowler_empty() {
        let findings = parse_prowler_output("", "https://example.com");
        assert!(findings.is_empty());

        let findings = parse_prowler_output("[]", "https://example.com");
        assert!(findings.is_empty());
    }
}
