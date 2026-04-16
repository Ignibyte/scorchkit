//! Prowler as a `CloudModule` (AWS) — WORK-151.
//!
//! Wraps the `prowler` binary for AWS-account posture audits under the
//! cloud family. Drives Prowler with explicit AWS credentials resolved
//! from [`crate::engine::cloud_credentials::CloudCredentials`] and
//! tags findings as [`CloudCategory::Compliance`] × [`CloudProvider::Aws`].
//!
//! ## Relationship with `tools::prowler`
//!
//! The DAST family ships its own [`crate::tools::prowler::ProwlerModule`]
//! (module id `"prowler"`). That wrapper stays in place — operators with
//! existing scan profiles invoking Prowler via the DAST orchestrator are
//! unaffected. This cloud-family module uses the distinct id
//! `"prowler-cloud"` so the two paths surface as separate modules in
//! reports. Per-finding CWE + per-check compliance mapping normalization
//! between the two lives in WORK-154.
//!
//! ## Scope — AWS only at WORK-151
//!
//! Prowler 4.x supports `aws` / `gcp` / `azure` / `kubernetes` as the
//! first positional arg. This wrapper scopes to `CloudProvider::Aws` only
//! — multi-cloud coverage lands in WORK-152 (Scoutsuite) and WORK-153
//! (Kubescape). `CloudTarget::Project` / `Subscription` / `KubeContext`
//! are rejected with an operator-actionable error message pointing to
//! the respective follow-up module.
//!
//! ## OCSF parser duplication (deferred extraction)
//!
//! The OCSF JSON parser below mirrors
//! [`crate::tools::prowler::parse_prowler_output`] in shape but emits
//! cloud-tagged findings (provider:aws in evidence, CWE-1188). Sharing
//! a single parser across the DAST and cloud families would force a
//! generic finding-builder closure parameter; premature at one cloud
//! consumer. Extraction to `engine::prowler_ocsf` is a follow-up once
//! WORK-152 Scoutsuite (potentially in OCSF mode) provides the second
//! consumer.

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

/// Wall-clock upper bound for a single Prowler invocation. Real scans
/// against a populated AWS account land in the 5–10 min range; the
/// 15-minute ceiling absorbs API-throttling without aborting the
/// orchestrator.
const PROWLER_TIMEOUT: Duration = Duration::from_secs(900);

/// Prowler-driven AWS posture audit — CIS AWS Foundations + 400+
/// checks across IAM, S3, EC2, `CloudTrail`, KMS, VPC, and more.
///
/// Uses the `prowler` external binary (install via `pip install
/// prowler`). Runs against the active AWS credentials resolved from
/// [`CloudCredentials`] — `aws_profile`, `aws_role_arn`, and
/// `aws_region` are all optional; when unset, Prowler falls back to
/// the AWS CLI default for each.
#[derive(Debug)]
pub struct ProwlerCloudModule;

#[async_trait]
impl CloudModule for ProwlerCloudModule {
    fn name(&self) -> &'static str {
        "Prowler Cloud Scanner (AWS)"
    }

    fn id(&self) -> &'static str {
        "prowler-cloud"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Compliance
    }

    fn description(&self) -> &'static str {
        "Prowler-driven AWS posture audit (CIS AWS Foundations + 400+ checks)"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&'static str> {
        Some("prowler")
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Aws]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let creds = ctx.credentials.as_deref();
        let argv = build_prowler_aws_argv(&ctx.target, creds)?;
        let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let output = subprocess::run_tool_lenient("prowler", &argv_refs, PROWLER_TIMEOUT).await?;
        let target_label = ctx.target.display_raw();
        Ok(parse_prowler_ocsf(&output.stdout, &target_label))
    }
}

/// Build the canonical Prowler argv for an AWS cloud target.
///
/// # Errors
///
/// Returns [`ScorchError::Config`] for non-AWS targets or for
/// [`CloudTarget::All`] without any AWS credentials configured.
///
/// Argv layout (deterministic order — emits `-p` / `-R` / `--role-arn`
/// in that sequence so golden-byte tests are stable):
///
/// ```text
/// aws -M json-ocsf --no-banner -q
///   [-p <aws_profile>]
///   [-R <aws_region>]
///   [--role-arn <aws_role_arn>]
/// ```
///
/// [`CloudTarget::Account`] passes through unchanged — Prowler
/// discovers the active account from credentials (profile / role /
/// env), not from a command-line flag. The account identifier in
/// `Account(id)` serves as evidence / report metadata only.
fn build_prowler_aws_argv(
    target: &CloudTarget,
    creds: Option<&CloudCredentials>,
) -> Result<Vec<String>> {
    match target {
        CloudTarget::Account(_) => {}
        CloudTarget::All => {
            let has_aws_creds = creds.is_some_and(|c| {
                c.aws_profile.as_deref().is_some_and(|s| !s.is_empty())
                    || c.aws_role_arn.as_deref().is_some_and(|s| !s.is_empty())
            });
            if !has_aws_creds {
                return Err(ScorchError::Config(
                    "CloudTarget::All requires aws_profile or aws_role_arn in [cloud] config \
                     to use prowler-cloud"
                        .into(),
                ));
            }
        }
        CloudTarget::Project(_) => {
            return Err(ScorchError::Config(
                "prowler-cloud only supports AWS targets at WORK-151; use scoutsuite \
                 (WORK-152) for GCP"
                    .into(),
            ));
        }
        CloudTarget::Subscription(_) => {
            return Err(ScorchError::Config(
                "prowler-cloud only supports AWS targets at WORK-151; use scoutsuite \
                 (WORK-152) for Azure"
                    .into(),
            ));
        }
        CloudTarget::KubeContext(_) => {
            return Err(ScorchError::Config(
                "prowler-cloud only supports AWS targets at WORK-151; use kubescape \
                 (WORK-153) for Kubernetes"
                    .into(),
            ));
        }
    }

    let mut argv: Vec<String> =
        vec!["aws".into(), "-M".into(), "json-ocsf".into(), "--no-banner".into(), "-q".into()];

    if let Some(c) = creds {
        if let Some(profile) = c.aws_profile.as_deref().filter(|s| !s.is_empty()) {
            argv.push("-p".into());
            argv.push(profile.to_string());
        }
        if let Some(region) = c.aws_region.as_deref().filter(|s| !s.is_empty()) {
            argv.push("-R".into());
            argv.push(region.to_string());
        }
        if let Some(role_arn) = c.aws_role_arn.as_deref().filter(|s| !s.is_empty()) {
            argv.push("--role-arn".into());
            argv.push(role_arn.to_string());
        }
    }

    Ok(argv)
}

/// Parse Prowler's OCSF JSON output into cloud-tagged findings.
///
/// Handles two input shapes:
/// - **Array form:** `[{...}, {...}, ...]` — preferred, emitted when
///   Prowler is invoked with `-M json-ocsf`.
/// - **JSON-lines:** one object per line — fallback parsing path; also
///   tolerant of invalid lines (silently skipped).
///
/// Entries with `status_id == 1` (OCSF PASS) are skipped — we only
/// report FAIL / Unknown / Skipped results. Invalid JSON at the top
/// level yields an empty vec (matches the [`crate::tools::prowler`]
/// precedent — operators see "0 findings" rather than a hard failure
/// on a misbehaving Prowler version).
#[must_use]
fn parse_prowler_ocsf(stdout: &str, target_label: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    if let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
        return items
            .iter()
            .filter_map(|item| finding_from_ocsf_value(item, target_label))
            .collect();
    }

    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|item| finding_from_ocsf_value(&item, target_label))
        .collect()
}

/// Extract a single `Finding` from one `OCSF` object, or `None` if the
/// entry is a PASS (`status_id == 1`).
///
/// Prowler's OCSF output includes a `compliance` object with
/// `requirements` containing framework-specific control IDs (CIS,
/// PCI-DSS, NIST, etc.). When present, these are extracted and
/// merged with the WORK-154 `enrich_cloud_finding` compliance
/// controls for richer compliance tagging.
fn finding_from_ocsf_value(item: &serde_json::Value, target_label: &str) -> Option<Finding> {
    if item["status_id"].as_i64().unwrap_or(0) == 1 {
        return None;
    }

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

    let evidence = CloudEvidence::new(CloudProvider::Aws, service)
        .with_check_id(check_title)
        .with_detail("severity", severity_str)
        .with_detail("target", target_label);

    let affected = format!("cloud://{target_label}");
    let mut finding = Finding::new(
        "prowler-cloud",
        map_prowler_severity(severity_str),
        format!("Prowler: {check_title}"),
        format!("{description} (Service: {service})"),
        affected,
    )
    .with_evidence(evidence.to_string())
    .with_remediation("Review the Prowler check documentation for remediation steps.")
    .with_confidence(0.8);

    // Enrich with per-service OWASP/CWE/compliance from WORK-154
    finding = enrich_cloud_finding(finding, service);

    // Extract Prowler-native compliance control IDs from the OCSF
    // compliance field and merge with the WORK-154 controls.
    let prowler_controls = extract_prowler_compliance(item);
    if !prowler_controls.is_empty() {
        let mut controls = finding.compliance.take().unwrap_or_default();
        for ctrl in prowler_controls {
            if !controls.contains(&ctrl) {
                controls.push(ctrl);
            }
        }
        finding.compliance = Some(controls);
    }

    Some(finding)
}

/// Extract compliance control IDs from Prowler's OCSF `compliance`
/// field.
///
/// Prowler 4.x OCSF output includes compliance mappings like:
/// ```json
/// {
///   "compliance": {
///     "requirements": ["CIS-1.4", "PCI-3.4", "NIST-AC-2"],
///     "status": "FAIL"
///   }
/// }
/// ```
///
/// Also handles the array-of-objects form:
/// ```json
/// {
///   "compliance": [
///     {"framework": "CIS", "requirement": "1.4"},
///     {"framework": "PCI", "requirement": "3.4"}
///   ]
/// }
/// ```
fn extract_prowler_compliance(item: &serde_json::Value) -> Vec<String> {
    let mut controls = Vec::new();

    // Form 1: compliance.requirements as string array
    if let Some(reqs) = item["compliance"]["requirements"].as_array() {
        for req in reqs {
            if let Some(s) = req.as_str() {
                if !s.is_empty() {
                    controls.push(s.to_string());
                }
            }
        }
    }

    // Form 2: compliance as array of {framework, requirement} objects
    if let Some(arr) = item["compliance"].as_array() {
        for entry in arr {
            let framework = entry["framework"].as_str().unwrap_or("");
            let requirement = entry["requirement"].as_str().unwrap_or("");
            if !framework.is_empty() && !requirement.is_empty() {
                controls.push(format!("{framework}-{requirement}"));
            }
        }
    }

    // Form 3: unmapped_compliance or finding_info.compliance
    if let Some(reqs) = item["finding_info"]["compliance"].as_array() {
        for req in reqs {
            if let Some(s) = req.as_str() {
                if !s.is_empty() && !controls.contains(&s.to_string()) {
                    controls.push(s.to_string());
                }
            }
        }
    }

    controls
}

/// Map Prowler's OCSF severity strings to `ScorchKit`'s [`Severity`].
/// Unknown strings fall through to `Info` — matches the DAST wrapper's
/// precedent.
fn map_prowler_severity(severity: &str) -> Severity {
    match severity.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    //! Pure-function coverage. The async `run()` is a thin glue layer
    //! around the two pure helpers plus `subprocess::run_tool_lenient`;
    //! a live smoke test against an installed Prowler binary is
    //! deferred to WORK-154 where finding-shape normalization is the
    //! deliverable.

    use super::*;

    // -----------------------------------------------------------------
    // Argv builder — happy paths
    // -----------------------------------------------------------------

    /// `CloudTarget::Account` with no credentials yields the canonical
    /// minimum argv.
    #[test]
    fn test_argv_account_no_creds() {
        let t = CloudTarget::Account("123456789012".into());
        let argv = build_prowler_aws_argv(&t, None).expect("argv");
        assert_eq!(argv, vec!["aws", "-M", "json-ocsf", "--no-banner", "-q"]);
    }

    /// `aws_profile = Some("prod")` appends `-p prod` after the prefix.
    #[test]
    fn test_argv_account_with_profile() {
        let t = CloudTarget::Account("123".into());
        let c = CloudCredentials { aws_profile: Some("prod".into()), ..Default::default() };
        let argv = build_prowler_aws_argv(&t, Some(&c)).expect("argv");
        assert_eq!(argv, vec!["aws", "-M", "json-ocsf", "--no-banner", "-q", "-p", "prod"]);
    }

    /// `aws_region` appends `-R <region>`.
    #[test]
    fn test_argv_account_with_region() {
        let t = CloudTarget::Account("123".into());
        let c = CloudCredentials { aws_region: Some("us-east-1".into()), ..Default::default() };
        let argv = build_prowler_aws_argv(&t, Some(&c)).expect("argv");
        assert_eq!(argv, vec!["aws", "-M", "json-ocsf", "--no-banner", "-q", "-R", "us-east-1"]);
    }

    /// `aws_role_arn` appends `--role-arn <arn>`.
    #[test]
    fn test_argv_account_with_role_arn() {
        let t = CloudTarget::Account("123".into());
        let c = CloudCredentials {
            aws_role_arn: Some("arn:aws:iam::123456789012:role/Audit".into()),
            ..Default::default()
        };
        let argv = build_prowler_aws_argv(&t, Some(&c)).expect("argv");
        assert_eq!(
            argv,
            vec![
                "aws",
                "-M",
                "json-ocsf",
                "--no-banner",
                "-q",
                "--role-arn",
                "arn:aws:iam::123456789012:role/Audit",
            ]
        );
    }

    /// Combined profile + region + role-arn emit in deterministic
    /// order. Golden vector pins the contract for future refactors.
    #[test]
    fn test_argv_account_with_all_three_creds() {
        let t = CloudTarget::Account("123".into());
        let c = CloudCredentials {
            aws_profile: Some("prod".into()),
            aws_region: Some("us-east-1".into()),
            aws_role_arn: Some("arn:aws:iam::123:role/Audit".into()),
            ..Default::default()
        };
        let argv = build_prowler_aws_argv(&t, Some(&c)).expect("argv");
        assert_eq!(
            argv,
            vec![
                "aws",
                "-M",
                "json-ocsf",
                "--no-banner",
                "-q",
                "-p",
                "prod",
                "-R",
                "us-east-1",
                "--role-arn",
                "arn:aws:iam::123:role/Audit",
            ],
            "argv field order must be profile → region → role-arn"
        );
    }

    /// Empty-string credential values are treated as unset (matches
    /// `NetworkCredentials::is_empty` semantics) — prevents `-p ""`
    /// leaking through from misconfigured env vars.
    #[test]
    fn test_argv_empty_string_treated_as_unset() {
        let t = CloudTarget::Account("123".into());
        let c = CloudCredentials {
            aws_profile: Some(String::new()),
            aws_region: Some(String::new()),
            aws_role_arn: Some(String::new()),
            ..Default::default()
        };
        let argv = build_prowler_aws_argv(&t, Some(&c)).expect("argv");
        assert_eq!(argv, vec!["aws", "-M", "json-ocsf", "--no-banner", "-q"]);
    }

    /// `CloudTarget::All` succeeds when `aws_profile` is configured.
    #[test]
    fn test_argv_all_with_profile_ok() {
        let c = CloudCredentials { aws_profile: Some("prod".into()), ..Default::default() };
        let argv = build_prowler_aws_argv(&CloudTarget::All, Some(&c)).expect("argv");
        assert!(argv.contains(&"-p".to_string()));
        assert!(argv.contains(&"prod".to_string()));
    }

    // -----------------------------------------------------------------
    // Argv builder — error paths
    // -----------------------------------------------------------------

    /// `CloudTarget::All` without AWS credentials must error with a
    /// remediation message — don't let operators silently fall through
    /// to whatever the AWS CLI default profile happens to be.
    #[test]
    fn test_argv_all_without_creds_errors() {
        let err = build_prowler_aws_argv(&CloudTarget::All, None).expect_err("should Err");
        let msg = err.to_string();
        assert!(msg.contains("aws_profile"), "got: {msg}");
        assert!(msg.contains("prowler-cloud"), "got: {msg}");
    }

    /// `CloudTarget::Project` (GCP) is rejected with a pointer to
    /// WORK-152 Scoutsuite.
    #[test]
    fn test_argv_rejects_gcp_target() {
        let err = build_prowler_aws_argv(&CloudTarget::Project("my-project".into()), None)
            .expect_err("should Err");
        let msg = err.to_string();
        assert!(msg.contains("WORK-152"), "got: {msg}");
        assert!(msg.contains("GCP"), "got: {msg}");
    }

    /// `CloudTarget::Subscription` (Azure) is rejected with a pointer
    /// to WORK-152.
    #[test]
    fn test_argv_rejects_azure_target() {
        let err = build_prowler_aws_argv(&CloudTarget::Subscription("abcd-1234".into()), None)
            .expect_err("should Err");
        let msg = err.to_string();
        assert!(msg.contains("WORK-152"), "got: {msg}");
        assert!(msg.contains("Azure"), "got: {msg}");
    }

    /// `CloudTarget::KubeContext` is rejected with a pointer to
    /// WORK-153 Kubescape.
    #[test]
    fn test_argv_rejects_k8s_target() {
        let err = build_prowler_aws_argv(&CloudTarget::KubeContext("prod-cluster".into()), None)
            .expect_err("should Err");
        let msg = err.to_string();
        assert!(msg.contains("WORK-153"), "got: {msg}");
        assert!(msg.contains("Kubernetes"), "got: {msg}");
    }

    // -----------------------------------------------------------------
    // OCSF parser
    // -----------------------------------------------------------------

    /// Array-form OCSF: mixed PASS / FAIL, 5 severity strings, finding
    /// shape pinned (module_id, OWASP, CWE, provider:aws evidence tag).
    #[test]
    fn test_parse_prowler_ocsf_array_skips_pass_maps_severities() {
        let output = r#"[
            {
                "status_id": 2,
                "finding_info": {"title": "S3 Bucket Public Access"},
                "message": "S3 bucket my-bucket has public read access",
                "severity": "critical",
                "resources": [{"group": {"name": "s3"}}]
            },
            {
                "status_id": 1,
                "finding_info": {"title": "IAM Root MFA Enabled"},
                "message": "Root account has MFA enabled",
                "severity": "high",
                "resources": [{"group": {"name": "iam"}}]
            },
            {
                "status_id": 2,
                "finding_info": {"title": "Default Security Group"},
                "message": "Default SG allows ingress",
                "severity": "high",
                "resources": [{"group": {"name": "vpc"}}]
            },
            {
                "status_id": 2,
                "finding_info": {"title": "CloudTrail Not Enabled"},
                "message": "CloudTrail disabled in us-east-1",
                "severity": "medium",
                "resources": [{"group": {"name": "cloudtrail"}}]
            },
            {
                "status_id": 2,
                "finding_info": {"title": "Low-Severity Gotcha"},
                "message": "minor drift",
                "severity": "low",
                "resources": [{"group": {"name": "config"}}]
            },
            {
                "status_id": 2,
                "finding_info": {"title": "Info Item"},
                "message": "informational",
                "severity": "informational",
                "resources": [{"group": {"name": "misc"}}]
            }
        ]"#;

        let findings = parse_prowler_ocsf(output, "aws:123456789012");
        assert_eq!(findings.len(), 5, "PASS entry (status_id=1) must be filtered out");

        // Severity mapping
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::High);
        assert_eq!(findings[2].severity, Severity::Medium);
        assert_eq!(findings[3].severity, Severity::Low);
        assert_eq!(findings[4].severity, Severity::Info);

        // Finding shape pin (first item — S3 service → A01/CWE-200)
        let f = &findings[0];
        assert_eq!(f.module_id, "prowler-cloud");
        assert!(f.title.contains("S3 Bucket Public Access"));
        assert_eq!(f.owasp_category.as_deref(), Some("A01:2021 Broken Access Control"));
        assert_eq!(f.cwe_id, Some(200));
        assert!(
            f.evidence.as_deref().unwrap_or("").contains("provider:aws"),
            "evidence must carry provider:aws tag for downstream filtering"
        );
        assert!(f.evidence.as_deref().unwrap_or("").contains("service:s3"));
        assert_eq!(f.affected_target, "cloud://aws:123456789012");
        assert!(f.compliance.is_some(), "compliance must be populated via enrich_cloud_finding");
    }

    /// JSON-lines fallback: one object per line, mixed PASS / FAIL,
    /// malformed lines silently skipped.
    #[test]
    fn test_parse_prowler_ocsf_jsonl_fallback() {
        let output = concat!(
            r#"{"status_id": 2, "finding_info": {"title": "A"}, "message": "a", "severity": "high", "resources": [{"group": {"name": "iam"}}]}"#,
            "\n",
            r#"this is a malformed line that must be skipped"#,
            "\n",
            r#"{"status_id": 1, "finding_info": {"title": "B"}, "message": "b", "severity": "high", "resources": [{"group": {"name": "iam"}}]}"#,
            "\n",
            r#"{"status_id": 2, "finding_info": {"title": "C"}, "message": "c", "severity": "medium", "resources": [{"group": {"name": "ec2"}}]}"#,
        );

        let findings = parse_prowler_ocsf(output, "aws:all");
        assert_eq!(findings.len(), 2, "PASS + malformed line are both filtered");
        assert!(findings[0].title.contains("A"));
        assert!(findings[1].title.contains("C"));
    }

    // -----------------------------------------------------------------
    // Compliance extraction (WORK-129)
    // -----------------------------------------------------------------

    /// Prowler OCSF with compliance.requirements array → controls extracted.
    #[test]
    fn test_prowler_compliance_requirements_form() {
        let item = serde_json::json!({
            "status_id": 2,
            "finding_info": {"title": "S3 Check"},
            "message": "test",
            "severity": "high",
            "resources": [{"group": {"name": "s3"}}],
            "compliance": {
                "requirements": ["CIS-1.4", "PCI-3.4", "NIST-AC-2"],
                "status": "FAIL"
            }
        });
        let finding = finding_from_ocsf_value(&item, "aws:123").expect("finding");
        let controls = finding.compliance.as_ref().expect("compliance");
        assert!(controls.iter().any(|c| c.contains("CIS-1.4")));
        assert!(controls.iter().any(|c| c.contains("PCI-3.4")));
        assert!(controls.iter().any(|c| c.contains("NIST-AC-2")));
    }

    /// Prowler OCSF with compliance as array of framework/requirement objects.
    #[test]
    fn test_prowler_compliance_framework_form() {
        let item = serde_json::json!({
            "status_id": 2,
            "finding_info": {"title": "IAM Check"},
            "message": "test",
            "severity": "medium",
            "resources": [{"group": {"name": "iam"}}],
            "compliance": [
                {"framework": "CIS", "requirement": "1.14"},
                {"framework": "PCI", "requirement": "8.2.1"}
            ]
        });
        let finding = finding_from_ocsf_value(&item, "aws:123").expect("finding");
        let controls = finding.compliance.as_ref().expect("compliance");
        assert!(controls.iter().any(|c| c.contains("CIS-1.14")));
        assert!(controls.iter().any(|c| c.contains("PCI-8.2.1")));
    }

    /// No compliance field → still gets WORK-154 enrichment controls.
    #[test]
    fn test_prowler_no_compliance_field_still_enriched() {
        let item = serde_json::json!({
            "status_id": 2,
            "finding_info": {"title": "Check"},
            "message": "test",
            "severity": "low",
            "resources": [{"group": {"name": "ec2"}}]
        });
        let finding = finding_from_ocsf_value(&item, "aws:123").expect("finding");
        // enrich_cloud_finding still populates compliance from OWASP/CWE mapping
        assert!(finding.compliance.is_some());
    }

    // -----------------------------------------------------------------
    // Module trait surface
    // -----------------------------------------------------------------

    /// Pins the trait-surface metadata — id, name, category, providers,
    /// required_tool, requires_external_tool.
    #[test]
    fn test_prowler_cloud_module_metadata() {
        let m = ProwlerCloudModule;
        assert_eq!(m.id(), "prowler-cloud");
        assert!(m.name().contains("Prowler"));
        assert_eq!(m.category(), CloudCategory::Compliance);
        assert_eq!(m.providers(), &[CloudProvider::Aws]);
        assert!(m.requires_external_tool());
        assert_eq!(m.required_tool(), Some("prowler"));
    }
}
