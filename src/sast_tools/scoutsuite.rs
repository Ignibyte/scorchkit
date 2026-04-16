//! `scoutsuite` wrapper — multi-cloud configuration audit.
//!
//! Wraps [Scout Suite](https://github.com/nccgroup/ScoutSuite) for
//! multi-cloud security posture (AWS, GCP, Azure, `AliCloud`, OCI).
//! Complements `prowler` (AWS-deep) with broader cloud coverage.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Multi-cloud audit via Scout Suite.
#[derive(Debug)]
pub struct ScoutsuiteModule;

#[async_trait]
impl CodeModule for ScoutsuiteModule {
    fn name(&self) -> &'static str {
        "Scout Suite Multi-Cloud Audit"
    }
    fn id(&self) -> &'static str {
        "scoutsuite"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Iac
    }
    fn description(&self) -> &'static str {
        "Multi-cloud config audit across AWS / GCP / Azure / AliCloud / OCI"
    }
    fn languages(&self) -> &[&str] {
        &["cloud"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("scout")
    }

    async fn run(&self, _ctx: &CodeContext) -> Result<Vec<Finding>> {
        // Scout Suite reads cloud creds from the standard provider
        // environment (AWS_PROFILE, GOOGLE_APPLICATION_CREDENTIALS,
        // etc.). Default profile = aws; operators run scout
        // directly with --provider gcp / azure / ... for others.
        let Ok(out_dir) = tempfile::tempdir() else {
            return Ok(Vec::new());
        };
        let out_path = out_dir.path().to_string_lossy().to_string();
        let _output = subprocess::run_tool_lenient(
            "scout",
            &["aws", "--report-dir", &out_path, "--no-browser"],
            Duration::from_secs(600),
        )
        .await?;
        // Scout Suite emits a JS file that wraps the raw JSON.
        // Look for results.json under the output dir; if present,
        // parse it. If absent, no findings.
        let json_path = format!("{out_path}/scoutsuite-results/scoutsuite-results.json");
        let json = std::fs::read_to_string(&json_path).unwrap_or_default();
        Ok(parse_scoutsuite_output(&json))
    }
}

/// Parse Scout Suite results JSON into findings.
///
/// Scout's output is deeply nested per-service. We surface the
/// `findings` blocks from `service_groups`, mapping `level` to
/// severity. Best-effort — Scout's schema evolves between
/// versions; we extract what we can and skip the rest.
#[must_use]
pub fn parse_scoutsuite_output(json: &str) -> Vec<Finding> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    let Some(services) = v["services"].as_object() else {
        return findings;
    };
    for (svc_name, svc) in services {
        let Some(svc_findings) = svc["findings"].as_object() else {
            continue;
        };
        for (rule_id, rule) in svc_findings {
            let level = rule["level"].as_str().unwrap_or("");
            let flagged_count = rule["flagged_items"].as_u64().unwrap_or(0);
            if flagged_count == 0 {
                continue;
            }
            let severity = match level {
                "danger" => Severity::High,
                "warning" => Severity::Medium,
                _ => Severity::Low,
            };
            let description = rule["description"].as_str().unwrap_or("");
            findings.push(
                Finding::new(
                    "scoutsuite",
                    severity,
                    format!("Scout {svc_name}: {rule_id}"),
                    description.to_string(),
                    format!("cloud:{svc_name}"),
                )
                .with_evidence(format!(
                    "service={svc_name} rule={rule_id} flagged_items={flagged_count}"
                ))
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_confidence(0.85),
            );
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scoutsuite_output_with_findings() {
        let json = r#"{"services": {
            "ec2": {"findings": {
                "ec2-public-instance": {"level": "danger", "flagged_items": 3, "description": "Public EC2"},
                "ec2-default-sg": {"level": "warning", "flagged_items": 1, "description": "Default SG"}
            }},
            "s3": {"findings": {
                "s3-no-encryption": {"level": "warning", "flagged_items": 0, "description": "No encryption"}
            }}
        }}"#;
        let findings = parse_scoutsuite_output(json);
        // Two findings — the s3 entry has 0 flagged items so it's filtered out
        assert_eq!(findings.len(), 2);
        let high = findings.iter().find(|f| f.severity == Severity::High).expect("high");
        assert!(high.title.contains("ec2-public-instance"));
    }

    #[test]
    fn parse_scoutsuite_output_empty() {
        assert!(parse_scoutsuite_output("").is_empty());
        assert!(parse_scoutsuite_output(r#"{"services": {}}"#).is_empty());
    }
}
