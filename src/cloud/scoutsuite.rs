//! Scout Suite as a `CloudModule` (multi-cloud) — WORK-152.
//!
//! Wraps the `scout` binary for AWS / GCP / Azure posture audits
//! under the cloud family. Drives Scout with explicit credentials
//! resolved from [`crate::engine::cloud_credentials::CloudCredentials`]
//! and tags findings as [`CloudCategory::Compliance`] across
//! [`CloudProvider::Aws`] / [`CloudProvider::Gcp`] /
//! [`CloudProvider::Azure`].
//!
//! ## Relationship with `sast_tools::scoutsuite`
//!
//! The SAST family ships its own
//! [`crate::sast_tools::scoutsuite::ScoutsuiteModule`] (module id
//! `"scoutsuite"`, AWS-only, hardcoded `--report-dir`). That wrapper
//! stays in place — operators with existing scan profiles invoking
//! Scout via the SAST orchestrator are unaffected. This cloud-family
//! module uses the distinct id `"scoutsuite-cloud"` so the two paths
//! surface as separate modules in reports.
//!
//! ## Multi-cloud fan-out
//!
//! Unlike WORK-151's AWS-only Prowler wrapper, this module supports
//! all three Scout providers. [`CloudTarget::All`] iterates over every
//! configured provider and merges findings; single-provider targets
//! (`Account` → AWS, `Project` → GCP, `Subscription` → Azure) run a
//! single scout invocation. `KubeContext` is rejected — Kubescape
//! (WORK-153) is the dedicated cloud-family wrapper for K8s.
//!
//! ## JSON parser duplication (deferred extraction)
//!
//! ~50 lines below mirror [`crate::sast_tools::scoutsuite::parse_scoutsuite_output`].
//! Cloud findings carry a `provider:<x>` evidence tag the SAST
//! findings don't, so a shared parser would force a generic
//! finding-builder closure parameter. Same reasoning as WORK-151's
//! OCSF parser duplication; WORK-152 was speculated to be the
//! extraction trigger but Scoutsuite emits its own JSON schema (not
//! OCSF), so the trigger evaporated.

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

/// Per-provider sub-timeout for a single scout invocation.
const SCOUT_PER_PROVIDER_TIMEOUT: Duration = Duration::from_secs(900);

/// Scout Suite multi-cloud audit — AWS / GCP / Azure posture
/// against Scout's full check catalog.
///
/// Uses the `scout` external binary (install via `pip install
/// scoutsuite`). Credentials resolved from [`CloudCredentials`]:
/// `aws_profile` for AWS (passed via `--profile`),
/// `gcp_service_account_path` + `gcp_project_id` for GCP,
/// `azure_subscription_id` for Azure (assumes `az login` already run).
#[derive(Debug)]
pub struct ScoutsuiteCloudModule;

#[async_trait]
impl CloudModule for ScoutsuiteCloudModule {
    fn name(&self) -> &'static str {
        "Scout Suite Multi-Cloud Audit"
    }

    fn id(&self) -> &'static str {
        "scoutsuite-cloud"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Compliance
    }

    fn description(&self) -> &'static str {
        "Scout Suite multi-cloud config audit (AWS / GCP / Azure)"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&'static str> {
        Some("scout")
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Aws, CloudProvider::Gcp, CloudProvider::Azure]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let creds = ctx.credentials.as_deref();
        let providers = select_providers(&ctx.target, creds)?;
        let target_label = ctx.target.display_raw();

        let mut findings = Vec::new();
        let mut first_err: Option<ScorchError> = None;
        for provider in providers {
            match run_one_provider(provider, creds, &target_label).await {
                Ok(mut fs) => findings.append(&mut fs),
                Err(e) => {
                    tracing::warn!(
                        "scoutsuite-cloud: provider {} failed: {e}",
                        provider.cli_name()
                    );
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        // If at least one provider produced output (even empty), return
        // the merged set. If every provider errored, surface the first
        // error so the orchestrator marks the module as failed.
        if findings.is_empty() {
            if let Some(e) = first_err {
                return Err(e);
            }
        }
        Ok(findings)
    }
}

/// Internal per-Scout-provider tag.
///
/// Bridges between `CloudTarget` / `CloudProvider` (public, multi-stack
/// semantics) and the per-provider argv branching (Scoutsuite-specific).
/// Never exposed in the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScoutProvider {
    Aws,
    Gcp,
    Azure,
}

impl ScoutProvider {
    const fn cli_name(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
        }
    }
}

/// Resolve a [`CloudTarget`] into the list of Scout providers to scan.
///
/// # Errors
///
/// - [`CloudTarget::Project`] without `gcp_service_account_path` set
///   — explicit GCP target missing required credential.
/// - [`CloudTarget::KubeContext`] — Scout has K8s mode but Kubescape
///   (WORK-153) is the dedicated cloud-family wrapper.
/// - [`CloudTarget::All`] when no provider has any credentials configured
///   — no work to do; clear remediation message rather than silent
///   no-op.
fn select_providers(
    target: &CloudTarget,
    creds: Option<&CloudCredentials>,
) -> Result<Vec<ScoutProvider>> {
    match target {
        CloudTarget::Account(_) => Ok(vec![ScoutProvider::Aws]),
        CloudTarget::Project(_) => {
            let path_set = creds
                .and_then(|c| c.gcp_service_account_path.as_deref())
                .is_some_and(|s| !s.is_empty());
            if path_set {
                Ok(vec![ScoutProvider::Gcp])
            } else {
                Err(ScorchError::Config(
                    "scoutsuite-cloud GCP target requires gcp_service_account_path in [cloud] config"
                        .into(),
                ))
            }
        }
        CloudTarget::Subscription(_) => Ok(vec![ScoutProvider::Azure]),
        CloudTarget::KubeContext(_) => Err(ScorchError::Config(
            "scoutsuite-cloud does not support Kubernetes targets — use kubescape (WORK-153) for K8s"
                .into(),
        )),
        CloudTarget::All => {
            let mut providers = Vec::new();
            if creds
                .and_then(|c| c.aws_profile.as_deref())
                .is_some_and(|s| !s.is_empty())
            {
                providers.push(ScoutProvider::Aws);
            }
            if creds
                .and_then(|c| c.gcp_service_account_path.as_deref())
                .is_some_and(|s| !s.is_empty())
            {
                providers.push(ScoutProvider::Gcp);
            }
            if creds
                .and_then(|c| c.azure_subscription_id.as_deref())
                .is_some_and(|s| !s.is_empty())
            {
                providers.push(ScoutProvider::Azure);
            }
            if providers.is_empty() {
                return Err(ScorchError::Config(
                    "scoutsuite-cloud All requires at least one of aws_profile / \
                     gcp_service_account_path / azure_subscription_id in [cloud] config"
                        .into(),
                ));
            }
            Ok(providers)
        }
    }
}

/// Build the canonical Scout argv for a single provider.
///
/// Field-emission order is deterministic so golden-byte tests are
/// stable. The `report_dir` is appended as `--report-dir <D>` and
/// `--no-browser` is always last.
fn build_scoutsuite_argv(
    provider: ScoutProvider,
    creds: Option<&CloudCredentials>,
    report_dir: &str,
) -> Vec<String> {
    let mut argv: Vec<String> = vec![provider.cli_name().to_string()];
    match provider {
        ScoutProvider::Aws => {
            if let Some(profile) =
                creds.and_then(|c| c.aws_profile.as_deref()).filter(|s| !s.is_empty())
            {
                argv.push("--profile".into());
                argv.push(profile.to_string());
            }
        }
        ScoutProvider::Gcp => {
            // Caller (`select_providers`) guarantees the path is set.
            if let Some(path) =
                creds.and_then(|c| c.gcp_service_account_path.as_deref()).filter(|s| !s.is_empty())
            {
                argv.push("--service-account".into());
                argv.push(path.to_string());
            }
            if let Some(project) =
                creds.and_then(|c| c.gcp_project_id.as_deref()).filter(|s| !s.is_empty())
            {
                argv.push("--project-id".into());
                argv.push(project.to_string());
            }
        }
        ScoutProvider::Azure => {
            if let Some(sub) =
                creds.and_then(|c| c.azure_subscription_id.as_deref()).filter(|s| !s.is_empty())
            {
                argv.push("--subscription-id".into());
                argv.push(sub.to_string());
            }
            argv.push("--cli".into());
        }
    }
    argv.push("--report-dir".into());
    argv.push(report_dir.to_string());
    argv.push("--no-browser".into());
    argv
}

/// Spawn Scout for a single provider, parse its output JSON, and
/// return the cloud-tagged findings.
///
/// Graceful-degrade: if the output file is missing or unparseable
/// (possible if Scout's directory layout changes or the run
/// errored before writing), returns an empty vec with a `debug!`
/// log rather than failing the scan.
async fn run_one_provider(
    provider: ScoutProvider,
    creds: Option<&CloudCredentials>,
    target_label: &str,
) -> Result<Vec<Finding>> {
    let tmp = tempfile::tempdir().map_err(|e| ScorchError::Config(format!("tempdir: {e}")))?;
    let report_dir = tmp.path().to_string_lossy().to_string();

    let argv = build_scoutsuite_argv(provider, creds, &report_dir);
    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let _output =
        subprocess::run_tool_lenient("scout", &argv_refs, SCOUT_PER_PROVIDER_TIMEOUT).await?;

    let json_path = format!("{report_dir}/scoutsuite-results/scoutsuite-results.json");
    let json = std::fs::read_to_string(&json_path).unwrap_or_default();
    if json.is_empty() {
        tracing::debug!(
            "scoutsuite-cloud: no results file at {json_path} (provider {})",
            provider.cli_name()
        );
        return Ok(Vec::new());
    }
    Ok(parse_scoutsuite_json(&json, provider, target_label))
}

/// Parse Scout's results JSON into cloud-tagged findings.
///
/// Walks `services.<svc>.findings.<rule>` per Scout's schema. Rules
/// with `flagged_items == 0` are skipped (no impacted resources).
/// `level` maps to severity at parity with
/// [`crate::sast_tools::scoutsuite::parse_scoutsuite_output`] —
/// `danger` → High, `warning` → Medium, anything else → Low.
///
/// Each finding carries provider attribution in its evidence string
/// for downstream filtering and per-provider report grouping.
#[must_use]
fn parse_scoutsuite_json(json: &str, provider: ScoutProvider, target_label: &str) -> Vec<Finding> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };
    let Some(services) = v["services"].as_object() else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for (svc_name, svc) in services {
        let Some(svc_findings) = svc["findings"].as_object() else {
            continue;
        };
        for (rule_id, rule) in svc_findings {
            let flagged = rule["flagged_items"].as_u64().unwrap_or(0);
            if flagged == 0 {
                continue;
            }
            let level = rule["level"].as_str().unwrap_or("");
            let severity = match level {
                "danger" => Severity::High,
                "warning" => Severity::Medium,
                _ => Severity::Low,
            };
            let description = rule["description"].as_str().unwrap_or("");
            let cloud_provider = match provider {
                ScoutProvider::Aws => CloudProvider::Aws,
                ScoutProvider::Gcp => CloudProvider::Gcp,
                ScoutProvider::Azure => CloudProvider::Azure,
            };
            let evidence = CloudEvidence::new(cloud_provider, svc_name.as_str())
                .with_check_id(rule_id.as_str())
                .with_detail("flagged", flagged.to_string());

            let finding = Finding::new(
                "scoutsuite-cloud",
                severity,
                format!("Scout {svc_name}: {rule_id}"),
                description.to_string(),
                format!("cloud://{target_label}"),
            )
            .with_evidence(evidence.to_string())
            .with_remediation("Review Scout Suite check documentation for remediation steps.")
            .with_confidence(0.85);

            findings.push(enrich_cloud_finding(finding, svc_name));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds_with(
        aws_profile: Option<&str>,
        gcp_path: Option<&str>,
        gcp_project: Option<&str>,
        azure_sub: Option<&str>,
    ) -> CloudCredentials {
        CloudCredentials {
            aws_profile: aws_profile.map(String::from),
            gcp_service_account_path: gcp_path.map(String::from),
            gcp_project_id: gcp_project.map(String::from),
            azure_subscription_id: azure_sub.map(String::from),
            ..Default::default()
        }
    }

    // -----------------------------------------------------------------
    // select_providers — single-target paths
    // -----------------------------------------------------------------

    #[test]
    fn test_select_providers_account_yields_aws() {
        let providers = select_providers(&CloudTarget::Account("123".into()), None).expect("ok");
        assert_eq!(providers, vec![ScoutProvider::Aws]);
    }

    #[test]
    fn test_select_providers_project_yields_gcp_when_path_set() {
        let c = creds_with(None, Some("/path/to/sa.json"), None, None);
        let providers = select_providers(&CloudTarget::Project("p".into()), Some(&c)).expect("ok");
        assert_eq!(providers, vec![ScoutProvider::Gcp]);
    }

    #[test]
    fn test_select_providers_project_errors_without_sa_path() {
        let err = select_providers(&CloudTarget::Project("p".into()), None).expect_err("err");
        let msg = err.to_string();
        assert!(msg.contains("gcp_service_account_path"), "got: {msg}");
    }

    #[test]
    fn test_select_providers_subscription_yields_azure() {
        let providers = select_providers(&CloudTarget::Subscription("s".into()), None).expect("ok");
        assert_eq!(providers, vec![ScoutProvider::Azure]);
    }

    #[test]
    fn test_select_providers_kube_context_errors() {
        let err = select_providers(&CloudTarget::KubeContext("ctx".into()), None).expect_err("err");
        let msg = err.to_string();
        assert!(msg.contains("WORK-153"), "got: {msg}");
        assert!(msg.contains("Kubernetes") || msg.contains("kubescape"), "got: {msg}");
    }

    // -----------------------------------------------------------------
    // select_providers — All target
    // -----------------------------------------------------------------

    #[test]
    fn test_select_providers_all_with_aws_only() {
        let c = creds_with(Some("prod"), None, None, None);
        let providers = select_providers(&CloudTarget::All, Some(&c)).expect("ok");
        assert_eq!(providers, vec![ScoutProvider::Aws]);
    }

    #[test]
    fn test_select_providers_all_with_all_three() {
        let c = creds_with(Some("prod"), Some("/sa.json"), Some("p"), Some("sub"));
        let providers = select_providers(&CloudTarget::All, Some(&c)).expect("ok");
        assert_eq!(providers, vec![ScoutProvider::Aws, ScoutProvider::Gcp, ScoutProvider::Azure]);
    }

    #[test]
    fn test_select_providers_all_without_creds_errors() {
        let err = select_providers(&CloudTarget::All, None).expect_err("err");
        let msg = err.to_string();
        assert!(msg.contains("aws_profile"), "got: {msg}");
        assert!(msg.contains("gcp_service_account_path"), "got: {msg}");
        assert!(msg.contains("azure_subscription_id"), "got: {msg}");
    }

    // -----------------------------------------------------------------
    // build_scoutsuite_argv — per-provider golden vectors
    // -----------------------------------------------------------------

    #[test]
    fn test_argv_aws_with_profile() {
        let c = creds_with(Some("prod"), None, None, None);
        let argv = build_scoutsuite_argv(ScoutProvider::Aws, Some(&c), "/tmp/x");
        assert_eq!(
            argv,
            vec!["aws", "--profile", "prod", "--report-dir", "/tmp/x", "--no-browser"]
        );
    }

    #[test]
    fn test_argv_aws_no_profile() {
        let argv = build_scoutsuite_argv(ScoutProvider::Aws, None, "/tmp/x");
        assert_eq!(argv, vec!["aws", "--report-dir", "/tmp/x", "--no-browser"]);
    }

    #[test]
    fn test_argv_gcp_with_project_id() {
        let c = creds_with(None, Some("/sa.json"), Some("my-project"), None);
        let argv = build_scoutsuite_argv(ScoutProvider::Gcp, Some(&c), "/tmp/x");
        assert_eq!(
            argv,
            vec![
                "gcp",
                "--service-account",
                "/sa.json",
                "--project-id",
                "my-project",
                "--report-dir",
                "/tmp/x",
                "--no-browser",
            ]
        );
    }

    #[test]
    fn test_argv_gcp_no_project_id() {
        let c = creds_with(None, Some("/sa.json"), None, None);
        let argv = build_scoutsuite_argv(ScoutProvider::Gcp, Some(&c), "/tmp/x");
        assert_eq!(
            argv,
            vec!["gcp", "--service-account", "/sa.json", "--report-dir", "/tmp/x", "--no-browser",]
        );
    }

    #[test]
    fn test_argv_azure_with_subscription() {
        let c = creds_with(None, None, None, Some("sub-1234"));
        let argv = build_scoutsuite_argv(ScoutProvider::Azure, Some(&c), "/tmp/x");
        assert_eq!(
            argv,
            vec![
                "azure",
                "--subscription-id",
                "sub-1234",
                "--cli",
                "--report-dir",
                "/tmp/x",
                "--no-browser",
            ]
        );
    }

    // -----------------------------------------------------------------
    // JSON parser
    // -----------------------------------------------------------------

    #[test]
    fn test_parse_scoutsuite_json_extracts_findings_with_provider_tag() {
        let json = r#"{
            "services": {
                "ec2": {
                    "findings": {
                        "ec2-public-instance": {
                            "level": "danger",
                            "flagged_items": 3,
                            "description": "Public EC2 instance"
                        },
                        "ec2-default-sg": {
                            "level": "warning",
                            "flagged_items": 1,
                            "description": "Default SG in use"
                        }
                    }
                },
                "s3": {
                    "findings": {
                        "s3-no-encryption": {
                            "level": "warning",
                            "flagged_items": 0,
                            "description": "No encryption (no flagged items)"
                        },
                        "s3-public": {
                            "level": "danger",
                            "flagged_items": 2,
                            "description": "Public bucket"
                        }
                    }
                }
            }
        }"#;
        let findings = parse_scoutsuite_json(json, ScoutProvider::Aws, "aws:123456789012");
        // Two ec2 + one s3 = 3; the s3-no-encryption with flagged_items=0 is skipped.
        assert_eq!(findings.len(), 3);

        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        assert_eq!(high, 2, "danger-level rules → High");
        assert_eq!(medium, 1, "warning-level rules → Medium");

        // Finding shape pin — ec2 service → A05/CWE-16
        let f = &findings[0];
        assert_eq!(f.module_id, "scoutsuite-cloud");
        assert!(f.title.starts_with("Scout "));
        assert_eq!(f.owasp_category.as_deref(), Some("A05:2021 Security Misconfiguration"));
        assert_eq!(f.cwe_id, Some(16));
        let evidence = f.evidence.as_deref().unwrap_or("");
        assert!(evidence.contains("provider:aws"), "evidence missing provider tag: {evidence}");
        assert!(evidence.contains("flagged:"), "evidence missing flagged count: {evidence}");
        assert!(f.compliance.is_some(), "compliance must be populated via enrich_cloud_finding");
    }

    #[test]
    fn test_parse_scoutsuite_json_empty_or_invalid() {
        assert!(parse_scoutsuite_json("", ScoutProvider::Aws, "aws:1").is_empty());
        assert!(parse_scoutsuite_json("{not valid json}", ScoutProvider::Aws, "aws:1").is_empty());
        assert!(
            parse_scoutsuite_json(r#"{"services": {}}"#, ScoutProvider::Aws, "aws:1").is_empty()
        );
    }

    // -----------------------------------------------------------------
    // Module trait surface
    // -----------------------------------------------------------------

    #[test]
    fn test_scoutsuite_cloud_module_metadata() {
        let m = ScoutsuiteCloudModule;
        assert_eq!(m.id(), "scoutsuite-cloud");
        assert!(m.name().contains("Scout"));
        assert_eq!(m.category(), CloudCategory::Compliance);
        assert_eq!(m.providers(), &[CloudProvider::Aws, CloudProvider::Gcp, CloudProvider::Azure]);
        assert!(m.requires_external_tool());
        assert_eq!(m.required_tool(), Some("scout"));
    }
}
