//! `kubescape` wrapper — Kubernetes security posture.
//!
//! Wraps [kubescape](https://github.com/kubescape/kubescape) to
//! evaluate Kubernetes manifests against frameworks (NSA, MITRE,
//! `ArmoBest`, CIS). Complements `kics` and `checkov` by focusing
//! specifically on K8s posture.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Kubernetes posture via kubescape.
#[derive(Debug)]
pub struct KubescapeModule;

#[async_trait]
impl CodeModule for KubescapeModule {
    fn name(&self) -> &'static str {
        "kubescape K8s Security"
    }
    fn id(&self) -> &'static str {
        "kubescape"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Iac
    }
    fn description(&self) -> &'static str {
        "Kubernetes manifest scan against NSA / MITRE / ArmoBest / CIS frameworks"
    }
    fn languages(&self) -> &[&str] {
        &["yaml", "kubernetes"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("kubescape")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        let output = subprocess::run_tool_lenient(
            "kubescape",
            &["scan", "--format", "json", &path_str],
            Duration::from_secs(180),
        )
        .await?;
        Ok(parse_kubescape_output(&output.stdout))
    }
}

/// Parse kubescape JSON output into findings.
///
/// Format: `{"results": [{"controlID": "...", "name": "...", "status": "...",
/// "scoreFactor": N}]}`. We surface controls with `status == "failed"`.
#[must_use]
pub fn parse_kubescape_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };
    let Some(results) = v["results"].as_array() else {
        return Vec::new();
    };
    results
        .iter()
        .filter_map(|r| {
            let status = r["status"]["status"].as_str().or_else(|| r["status"].as_str());
            if status != Some("failed") {
                return None;
            }
            let id = r["controlID"].as_str().unwrap_or("?");
            let name = r["name"].as_str().unwrap_or("(no name)");
            let score = r["scoreFactor"].as_f64().unwrap_or(0.0);
            let severity = if score >= 7.0 {
                Severity::High
            } else if score >= 4.0 {
                Severity::Medium
            } else {
                Severity::Low
            };
            Some(
                Finding::new(
                    "kubescape",
                    severity,
                    format!("kubescape {id}: {name}"),
                    format!("Control {id} ({name}) failed"),
                    "kubernetes-manifests".to_string(),
                )
                .with_evidence(format!("controlID={id} score={score}"))
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_confidence(0.9),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kubescape_output_with_failures() {
        let stdout = r#"{"results": [
            {"controlID": "C-0001", "name": "Forbidden user", "status": "failed", "scoreFactor": 8.0},
            {"controlID": "C-0002", "name": "Resource limits", "status": "failed", "scoreFactor": 5.0},
            {"controlID": "C-0003", "name": "Image tag", "status": "passed", "scoreFactor": 3.0}
        ]}"#;
        let findings = parse_kubescape_output(stdout);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    #[test]
    fn parse_kubescape_output_empty() {
        assert!(parse_kubescape_output("").is_empty());
    }
}
