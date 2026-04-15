//! Checkov wrapper for Infrastructure as Code scanning.
//!
//! Wraps the `checkov` tool which scans cloud infrastructure configurations
//! (Terraform, `CloudFormation`, Kubernetes, Dockerfile, ARM, Serverless)
//! for security misconfigurations and compliance violations.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Infrastructure as Code security scanning via Checkov.
#[derive(Debug)]
pub struct CheckovModule;

#[async_trait]
impl CodeModule for CheckovModule {
    fn name(&self) -> &'static str {
        "Checkov IaC Scanner"
    }
    fn id(&self) -> &'static str {
        "checkov"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Iac
    }
    fn description(&self) -> &'static str {
        "Infrastructure as Code security scanning for Terraform, CloudFormation, Kubernetes, and Dockerfile via Checkov"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("checkov")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        // checkov exits 1 when failures are found — that's normal, not an error.
        let output = subprocess::run_tool_lenient(
            "checkov",
            &["--directory", &path_str, "-o", "json", "--quiet", "--compact"],
            Duration::from_secs(300),
        )
        .await?;

        Ok(parse_checkov_output(&output.stdout))
    }
}

/// Map Checkov severity strings to `ScorchKit` severity levels.
///
/// Checkov uses CRITICAL/HIGH/MEDIUM/LOW/INFO severity levels.
fn map_checkov_severity(severity: &str) -> Severity {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse Checkov JSON output into findings.
///
/// Checkov outputs either a single JSON object or an array of objects
/// (one per framework). Each object has `check_type` and `results`
/// containing `failed_checks` with `check_id`, `check_result`,
/// `resource`, `file_path`, `file_line_range`, `guideline`, and `severity`.
#[must_use]
pub fn parse_checkov_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // Checkov may output a single object or an array of objects
    let check_results: Vec<serde_json::Value> =
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
            arr
        } else if let Ok(obj) = serde_json::from_str::<serde_json::Value>(trimmed) {
            vec![obj]
        } else {
            return Vec::new();
        };

    let mut findings = Vec::new();

    for result_obj in &check_results {
        let check_type = result_obj["check_type"].as_str().unwrap_or("unknown");

        let Some(failed_checks) = result_obj["results"]["failed_checks"].as_array() else {
            continue;
        };

        for check in failed_checks {
            let Some(check_id) = check["check_id"].as_str() else {
                continue;
            };
            let check_name = check["check_result"]["name"]
                .as_str()
                .or_else(|| check["name"].as_str())
                .unwrap_or(check_id);
            let resource = check["resource"].as_str().unwrap_or("unknown");
            let file_path = check["file_path"].as_str().unwrap_or("unknown");
            let guideline = check["guideline"].as_str().unwrap_or("");
            let severity_str = check["severity"].as_str().unwrap_or("MEDIUM");

            // Build affected target from file path and line range
            let affected = check["file_line_range"].as_array().map_or_else(
                || file_path.to_string(),
                |line_range| {
                    let start = line_range.first().and_then(serde_json::Value::as_u64).unwrap_or(0);
                    format!("{file_path}:{start}")
                },
            );

            let mut finding = Finding::new(
                "checkov",
                map_checkov_severity(severity_str),
                format!("{check_id}: {check_name}"),
                format!("IaC misconfiguration in {check_type} resource {resource}: {check_name}"),
                &affected,
            )
            .with_confidence(0.85)
            .with_evidence(format!("Framework: {check_type} | Resource: {resource}"))
            .with_owasp("A05:2021 Security Misconfiguration");

            if guideline.is_empty() {
                finding = finding.with_remediation(format!(
                    "Review and fix the IaC misconfiguration identified by Checkov rule {check_id}."
                ));
            } else {
                finding = finding
                    .with_remediation(format!("Follow the remediation guideline: {guideline}"));
            }

            findings.push(finding);
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Checkov JSON output is correctly parsed into findings
    /// with check type, resource, severity, and guideline-based remediation.
    #[test]
    fn test_parse_checkov_output() {
        let output = r#"[
            {
                "check_type": "terraform",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_18",
                            "name": "Ensure the S3 bucket has access logging enabled",
                            "check_result": {"result": "FAILED"},
                            "resource": "aws_s3_bucket.data",
                            "file_path": "/main.tf",
                            "file_line_range": [10, 25],
                            "guideline": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/s3-policies/s3-13-enable-logging",
                            "severity": "HIGH"
                        },
                        {
                            "check_id": "CKV_AWS_145",
                            "name": "Ensure S3 bucket is encrypted with KMS",
                            "check_result": {"result": "FAILED"},
                            "resource": "aws_s3_bucket.data",
                            "file_path": "/main.tf",
                            "file_line_range": [10, 25],
                            "guideline": "",
                            "severity": "LOW"
                        }
                    ]
                }
            }
        ]"#;

        let findings = parse_checkov_output(output);
        assert_eq!(findings.len(), 2);

        // First finding: S3 access logging
        assert_eq!(findings[0].affected_target, "/main.tf:10");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("CKV_AWS_18"));
        assert!(findings[0].evidence.as_ref().is_some_and(|e| e.contains("terraform")));
        assert!(findings[0].remediation.as_ref().is_some_and(|r| r.contains("prismacloud")));

        // Second finding: no guideline, generic remediation
        assert_eq!(findings[1].severity, Severity::Low);
        assert!(findings[1].remediation.as_ref().is_some_and(|r| r.contains("CKV_AWS_145")));
    }

    /// Verify empty or invalid input produces no findings.
    #[test]
    fn test_parse_checkov_empty() {
        assert!(parse_checkov_output("").is_empty());
        assert!(parse_checkov_output("[]").is_empty());
        assert!(parse_checkov_output("not json").is_empty());
        // Single object with no failed checks
        assert!(parse_checkov_output(
            r#"{"check_type": "terraform", "results": {"failed_checks": []}}"#
        )
        .is_empty());
    }
}
