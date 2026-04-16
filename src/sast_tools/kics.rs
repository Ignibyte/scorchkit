//! `kics` wrapper — `IaC` security from Checkmarx OSS.
//!
//! Wraps [KICS](https://github.com/Checkmarx/kics) (Keeping
//! Infrastructure as Code Secure). Broader rule set than `checkov`:
//! covers Terraform, `CloudFormation`, Kubernetes, Dockerfile, Helm,
//! Ansible, Pulumi, `OpenAPI`, gRPC, and more.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// `IaC` security via KICS.
#[derive(Debug)]
pub struct KicsModule;

#[async_trait]
impl CodeModule for KicsModule {
    fn name(&self) -> &'static str {
        "KICS `IaC` Security"
    }
    fn id(&self) -> &'static str {
        "kics"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Iac
    }
    fn description(&self) -> &'static str {
        "`IaC` security across Terraform / CloudFormation / K8s / Docker / Helm / Ansible"
    }
    fn languages(&self) -> &[&str] {
        &["terraform", "yaml", "dockerfile", "json"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("kics")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        // kics writes JSON to a file; we use --report-formats json
        // and read from the default output dir
        let Ok(tmp) = tempfile::tempdir() else {
            return Ok(Vec::new());
        };
        let out_dir = tmp.path().to_string_lossy().to_string();
        let _output = subprocess::run_tool_lenient(
            "kics",
            &["scan", "--path", &path_str, "--output-path", &out_dir, "--report-formats", "json"],
            Duration::from_secs(180),
        )
        .await?;
        let json_path = format!("{out_dir}/results.json");
        let json = std::fs::read_to_string(&json_path).unwrap_or_default();
        Ok(parse_kics_output(&json))
    }
}

/// Parse KICS JSON output into findings.
#[must_use]
pub fn parse_kics_output(json: &str) -> Vec<Finding> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };
    let Some(queries) = v["queries"].as_array() else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for q in queries {
        let query_name = q["query_name"].as_str().unwrap_or("?");
        let sev_str = q["severity"].as_str().unwrap_or("INFO");
        let severity = match sev_str {
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Info,
        };
        let Some(files) = q["files"].as_array() else {
            continue;
        };
        for f in files {
            let file_name = f["file_name"].as_str().unwrap_or("?");
            let line = f["line"].as_i64().unwrap_or(0);
            findings.push(
                Finding::new(
                    "kics",
                    severity,
                    format!("KICS {query_name}"),
                    f["expected_value"].as_str().unwrap_or("").to_string(),
                    format!("{file_name}:{line}"),
                )
                .with_evidence(format!("query={query_name} severity={sev_str}"))
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
    fn parse_kics_output_with_findings() {
        let json = r#"{"queries": [
            {"query_name": "Bucket without encryption", "severity": "HIGH",
             "files": [{"file_name": "main.tf", "line": 10, "expected_value": "encryption=enabled"}]},
            {"query_name": "Open ingress", "severity": "MEDIUM",
             "files": [{"file_name": "sg.tf", "line": 5, "expected_value": "specific cidr"}]}
        ]}"#;
        let findings = parse_kics_output(json);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn parse_kics_output_empty() {
        assert!(parse_kics_output("").is_empty());
        assert!(parse_kics_output(r#"{"queries": []}"#).is_empty());
    }
}
