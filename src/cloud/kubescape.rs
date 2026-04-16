//! Kubescape as a `CloudModule` — Kubernetes cluster posture (WORK-153).
//!
//! Wraps the `kubescape` binary against a **live Kubernetes cluster**
//! via kubeconfig context, evaluating it against Kubescape's
//! framework battery (NSA, MITRE, `ArmoBest`, CIS Kubernetes
//! Benchmark). Module id `"kubescape-cloud"`;
//! [`CloudCategory::Kubernetes`] (the dedicated K8s category — not
//! `Compliance` like Prowler/Scoutsuite); [`CloudProvider::Kubernetes`].
//!
//! ## Relationship with `sast_tools::kubescape`
//!
//! The SAST family ships its own
//! [`crate::sast_tools::kubescape::KubescapeModule`] (module id
//! `"kubescape"`) which scans Kubernetes manifest YAML files **on
//! disk**. That wrapper stays in place — operators with existing
//! manifest-scan profiles are unaffected. This cloud-family module
//! uses the distinct id `"kubescape-cloud"` and runs against the
//! live cluster reachable via `kubectl`'s current context.
//!
//! ## Target validation
//!
//! Only `CloudTarget::KubeContext` and `CloudTarget::All` (with
//! `kube_context` configured in `[cloud]`) are accepted. Cloud
//! targets for AWS / GCP / Azure are rejected with operator-actionable
//! pointers to `prowler-cloud` (AWS) and `scoutsuite-cloud`
//! (GCP/Azure).

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_credentials::CloudCredentials;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::cloud_target::CloudTarget;
use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Kubescape's per-scan timeout. K8s posture scans are usually
/// well under 5 min even on large clusters; 10 min is a comfortable
/// upper bound.
const KUBESCAPE_TIMEOUT: Duration = Duration::from_secs(600);

/// Kubescape K8s cluster posture audit — NSA / MITRE / `ArmoBest` /
/// CIS Kubernetes Benchmark frameworks against a live cluster.
///
/// Uses the `kubescape` external binary (install via
/// `curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash`).
/// Cluster connection resolved from `CloudCredentials.kube_context`
/// or from `CloudTarget::KubeContext(ctx)` (target overrides config).
#[derive(Debug)]
pub struct KubescapeCloudModule;

#[async_trait]
impl CloudModule for KubescapeCloudModule {
    fn name(&self) -> &'static str {
        "Kubescape K8s Cluster Posture"
    }

    fn id(&self) -> &'static str {
        "kubescape-cloud"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Kubernetes
    }

    fn description(&self) -> &'static str {
        "Kubescape live-cluster posture (NSA / MITRE / ArmoBest / CIS Kubernetes)"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&'static str> {
        Some("kubescape")
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Kubernetes]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let creds = ctx.credentials.as_deref();
        let argv = build_kubescape_argv(&ctx.target, creds)?;
        let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let output =
            subprocess::run_tool_lenient("kubescape", &argv_refs, KUBESCAPE_TIMEOUT).await?;
        let target_label = ctx.target.display_raw();
        Ok(parse_kubescape_json(&output.stdout, &target_label))
    }
}

/// Build the canonical Kubescape argv for a Kubernetes cloud target.
///
/// # Errors
///
/// - `CloudTarget::Account` / `Project` / `Subscription` → rejected
///   with pointers to `prowler-cloud` (AWS) or `scoutsuite-cloud`
///   (GCP/Azure).
/// - `CloudTarget::All` without `kube_context` set in `CloudCredentials`
///   → rejected with remediation message (kubescape needs an explicit
///   context; AWS-CLI-style "default" doesn't generalize to kubeconfig).
fn build_kubescape_argv(
    target: &CloudTarget,
    creds: Option<&CloudCredentials>,
) -> Result<Vec<String>> {
    let mut argv: Vec<String> = vec!["scan".into(), "--format".into(), "json".into()];

    match target {
        CloudTarget::KubeContext(ctx) => {
            argv.push("--kube-context".into());
            argv.push(ctx.clone());
        }
        CloudTarget::All => {
            let kube_ctx = creds
                .and_then(|c| c.kube_context.as_deref())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    ScorchError::Config(
                        "kubescape-cloud All target requires kube_context in [cloud] config".into(),
                    )
                })?;
            argv.push("--kube-context".into());
            argv.push(kube_ctx.to_string());
        }
        CloudTarget::Account(_) => {
            return Err(ScorchError::Config(
                "kubescape-cloud does not support AWS targets — use prowler-cloud (WORK-151) \
                 for AWS"
                    .into(),
            ));
        }
        CloudTarget::Project(_) => {
            return Err(ScorchError::Config(
                "kubescape-cloud does not support GCP targets — use scoutsuite-cloud (WORK-152) \
                 for GCP"
                    .into(),
            ));
        }
        CloudTarget::Subscription(_) => {
            return Err(ScorchError::Config(
                "kubescape-cloud does not support Azure targets — use scoutsuite-cloud \
                 (WORK-152) for Azure"
                    .into(),
            ));
        }
    }

    Ok(argv)
}

/// Parse Kubescape's JSON output into cloud-tagged findings.
///
/// Walks `results[]`, filters `status.status == "failed"` (or the
/// older `status` string form), maps `scoreFactor` to severity at
/// parity with [`crate::sast_tools::kubescape::parse_kubescape_output`]
/// (`>= 7.0` → High, `>= 4.0` → Medium, else Low). Each finding
/// carries `provider:kubernetes` in its evidence string for
/// downstream filtering.
#[must_use]
fn parse_kubescape_json(stdout: &str, target_label: &str) -> Vec<Finding> {
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
            let evidence = CloudEvidence::new(CloudProvider::Kubernetes, "workload")
                .with_check_id(id)
                .with_detail("score", score.to_string())
                .with_detail("target", target_label);

            let finding = Finding::new(
                "kubescape-cloud",
                severity,
                format!("kubescape {id}: {name}"),
                format!("Control {id} ({name}) failed against the live cluster"),
                format!("cloud://{target_label}"),
            )
            .with_evidence(evidence.to_string())
            .with_remediation("Review the Kubescape control documentation for remediation steps.")
            .with_confidence(0.9);

            Some(enrich_cloud_finding(finding, "workload"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds_with_ctx(ctx: Option<&str>) -> CloudCredentials {
        CloudCredentials { kube_context: ctx.map(String::from), ..Default::default() }
    }

    // -----------------------------------------------------------------
    // argv builder — happy paths
    // -----------------------------------------------------------------

    #[test]
    fn test_argv_kube_context_target_uses_target_value() {
        let argv = build_kubescape_argv(&CloudTarget::KubeContext("prod-cluster".into()), None)
            .expect("argv");
        assert_eq!(argv, vec!["scan", "--format", "json", "--kube-context", "prod-cluster"]);
    }

    #[test]
    fn test_argv_kube_context_target_overrides_config() {
        // Even with a creds.kube_context set, the explicit target wins.
        let c = creds_with_ctx(Some("config-ctx"));
        let argv =
            build_kubescape_argv(&CloudTarget::KubeContext("explicit-target-ctx".into()), Some(&c))
                .expect("argv");
        assert!(
            argv.windows(2).any(|w| w[0] == "--kube-context" && w[1] == "explicit-target-ctx"),
            "target value must win over config: {argv:?}"
        );
    }

    #[test]
    fn test_argv_all_with_kube_context_config() {
        let c = creds_with_ctx(Some("staging-cluster"));
        let argv = build_kubescape_argv(&CloudTarget::All, Some(&c)).expect("argv");
        assert_eq!(argv, vec!["scan", "--format", "json", "--kube-context", "staging-cluster"]);
    }

    // -----------------------------------------------------------------
    // argv builder — error paths
    // -----------------------------------------------------------------

    #[test]
    fn test_argv_all_without_kube_context_errors() {
        let err = build_kubescape_argv(&CloudTarget::All, None).expect_err("err");
        let msg = err.to_string();
        assert!(msg.contains("kube_context"), "got: {msg}");
        assert!(msg.contains("kubescape-cloud"), "got: {msg}");
    }

    #[test]
    fn test_argv_all_empty_kube_context_errors() {
        let c = creds_with_ctx(Some(""));
        let err = build_kubescape_argv(&CloudTarget::All, Some(&c)).expect_err("err");
        assert!(err.to_string().contains("kube_context"));
    }

    #[test]
    fn test_argv_rejects_aws_target() {
        let err = build_kubescape_argv(&CloudTarget::Account("123".into()), None).expect_err("err");
        let msg = err.to_string();
        assert!(msg.contains("WORK-151"), "got: {msg}");
        assert!(msg.contains("prowler-cloud"), "got: {msg}");
    }

    #[test]
    fn test_argv_rejects_gcp_target() {
        let err = build_kubescape_argv(&CloudTarget::Project("p".into()), None).expect_err("err");
        let msg = err.to_string();
        assert!(msg.contains("WORK-152"), "got: {msg}");
        assert!(msg.contains("scoutsuite-cloud"), "got: {msg}");
    }

    #[test]
    fn test_argv_rejects_azure_target() {
        let err =
            build_kubescape_argv(&CloudTarget::Subscription("sub".into()), None).expect_err("err");
        let msg = err.to_string();
        assert!(msg.contains("WORK-152"), "got: {msg}");
        assert!(msg.contains("Azure"), "got: {msg}");
    }

    // -----------------------------------------------------------------
    // JSON parser
    // -----------------------------------------------------------------

    #[test]
    fn test_parse_kubescape_json_extracts_failed_controls_with_provider_tag() {
        let stdout = r#"{
            "results": [
                {"controlID": "C-0001", "name": "Forbidden user", "status": "failed", "scoreFactor": 8.5},
                {"controlID": "C-0002", "name": "Resource limits", "status": "failed", "scoreFactor": 5.0},
                {"controlID": "C-0003", "name": "Image tag", "status": "passed", "scoreFactor": 3.0},
                {"controlID": "C-0004", "name": "Low-score", "status": "failed", "scoreFactor": 2.0}
            ]
        }"#;
        let findings = parse_kubescape_json(stdout, "k8s:prod-cluster");
        assert_eq!(findings.len(), 3, "PASS entry filtered out, three FAILs remain");

        // Severity mapping
        assert_eq!(findings[0].severity, Severity::High, "scoreFactor 8.5 → High");
        assert_eq!(findings[1].severity, Severity::Medium, "scoreFactor 5.0 → Medium");
        assert_eq!(findings[2].severity, Severity::Low, "scoreFactor 2.0 → Low");

        // Finding shape pin — workload service → A05/CWE-16
        let f = &findings[0];
        assert_eq!(f.module_id, "kubescape-cloud");
        assert!(f.title.contains("C-0001"));
        assert_eq!(f.owasp_category.as_deref(), Some("A05:2021 Security Misconfiguration"));
        assert_eq!(f.cwe_id, Some(16));
        let evidence = f.evidence.as_deref().unwrap_or("");
        assert!(evidence.contains("provider:kubernetes"), "evidence: {evidence}");
        assert!(evidence.contains("check_id:C-0001"), "evidence: {evidence}");
        assert!(evidence.contains("target:k8s:prod-cluster"), "evidence: {evidence}");
        assert_eq!(f.affected_target, "cloud://k8s:prod-cluster");
        assert!(f.compliance.is_some(), "compliance must be populated via enrich_cloud_finding");
    }

    #[test]
    fn test_parse_kubescape_json_empty_or_invalid() {
        assert!(parse_kubescape_json("", "k8s:x").is_empty());
        assert!(parse_kubescape_json("not json", "k8s:x").is_empty());
        assert!(parse_kubescape_json(r#"{"results": []}"#, "k8s:x").is_empty());
    }

    // -----------------------------------------------------------------
    // Module trait surface
    // -----------------------------------------------------------------

    #[test]
    fn test_kubescape_cloud_module_metadata() {
        let m = KubescapeCloudModule;
        assert_eq!(m.id(), "kubescape-cloud");
        assert!(m.name().contains("Kubescape"));
        assert_eq!(m.category(), CloudCategory::Kubernetes);
        assert_eq!(m.providers(), &[CloudProvider::Kubernetes]);
        assert!(m.requires_external_tool());
        assert_eq!(m.required_tool(), Some("kubescape"));
    }
}
