//! AWS `CloudTrail` posture checks — multi-region, encryption, log validation.
//!
//! Uses `aws-sdk-cloudtrail` to enumerate trails and check each for
//! security best practices per CIS AWS Foundations Benchmark.

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

use super::{build_aws_sdk_config, TrailStatus};

/// Built-in AWS `CloudTrail` posture module.
///
/// Checks trail configuration for multi-region coverage, KMS
/// encryption, log file validation, and active logging.
#[derive(Debug)]
pub struct CloudTrailCloudModule;

#[async_trait]
impl CloudModule for CloudTrailCloudModule {
    fn name(&self) -> &'static str {
        "AWS CloudTrail Posture"
    }

    fn id(&self) -> &'static str {
        "aws-cloudtrail"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Compliance
    }

    fn description(&self) -> &'static str {
        "Built-in AWS CloudTrail checks: multi-region, encryption, log validation"
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Aws]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let sdk_config = build_aws_sdk_config(&ctx.target, ctx.credentials.as_deref()).await?;
        let client = aws_sdk_cloudtrail::Client::new(&sdk_config);
        let target_label = ctx.target.display_raw();

        let trails = match fetch_trail_statuses(&client).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("aws-cloudtrail: failed to describe trails: {e}");
                return Ok(vec![permission_finding(&target_label)]);
            }
        };

        Ok(check_trails(&trails, &target_label))
    }
}

/// Fetch trail configuration and status for all trails.
async fn fetch_trail_statuses(
    client: &aws_sdk_cloudtrail::Client,
) -> std::result::Result<Vec<TrailStatus>, aws_sdk_cloudtrail::Error> {
    let resp = client.describe_trails().send().await?;
    let mut statuses = Vec::new();

    for trail in resp.trail_list() {
        let name = trail.name().unwrap_or("unnamed").to_string();
        let is_multi_region = trail.is_multi_region_trail.unwrap_or(false);
        let kms_key_id = trail.kms_key_id().map(String::from);
        let log_file_validation = trail.log_file_validation_enabled.unwrap_or(false);

        // Fetch logging status for this trail
        let is_logging = if let Some(arn) = trail.trail_arn() {
            client
                .get_trail_status()
                .name(arn)
                .send()
                .await
                .map(|s| s.is_logging.unwrap_or(false))
                .unwrap_or(false)
        } else {
            false
        };

        statuses.push(TrailStatus {
            name,
            is_multi_region,
            kms_key_id,
            log_file_validation,
            is_logging,
        });
    }

    Ok(statuses)
}

/// Generate an Info-level "insufficient permissions" finding.
fn permission_finding(target_label: &str) -> Finding {
    let finding = Finding::new(
        "aws-cloudtrail",
        Severity::Info,
        "AWS CloudTrail: Insufficient permissions for DescribeTrails",
        "The credentials lack cloudtrail:DescribeTrails permission.",
        format!("cloud://{target_label}"),
    )
    .with_evidence(
        CloudEvidence::new(CloudProvider::Aws, "cloudtrail")
            .with_check_id("cloudtrail-permission-describetrails")
            .to_string(),
    )
    .with_confidence(0.5);
    enrich_cloud_finding(finding, "cloudtrail")
}

// ---------------------------------------------------------------
// Pure check functions — testable without AWS SDK
// ---------------------------------------------------------------

/// Check all trails and produce findings.
#[must_use]
pub fn check_trails(trails: &[TrailStatus], target_label: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if trails.is_empty() {
        let evidence = CloudEvidence::new(CloudProvider::Aws, "cloudtrail")
            .with_check_id("cloudtrail-no-trail");
        let finding = Finding::new(
            "aws-cloudtrail",
            Severity::Critical,
            "AWS CloudTrail: No trails configured",
            "No CloudTrail trails exist in this account. API activity is not being logged.",
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation(
            "Create a multi-region CloudTrail trail with KMS encryption and log file validation.",
        )
        .with_confidence(0.95);
        findings.push(enrich_cloud_finding(finding, "cloudtrail"));
        return findings;
    }

    // Check if at least one multi-region trail exists
    let has_multi_region = trails.iter().any(|t| t.is_multi_region);
    if !has_multi_region {
        let evidence = CloudEvidence::new(CloudProvider::Aws, "cloudtrail")
            .with_check_id("cloudtrail-no-multi-region");
        let finding = Finding::new(
            "aws-cloudtrail",
            Severity::High,
            "AWS CloudTrail: No multi-region trail",
            "No CloudTrail trail is configured for multi-region logging. \
             API calls in other regions are not captured.",
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Enable multi-region on at least one CloudTrail trail.")
        .with_confidence(0.9);
        findings.push(enrich_cloud_finding(finding, "cloudtrail"));
    }

    // Per-trail checks
    for trail in trails {
        if trail.kms_key_id.is_none() {
            let evidence = CloudEvidence::new(CloudProvider::Aws, "cloudtrail")
                .with_check_id("cloudtrail-no-encryption")
                .with_resource(&trail.name);
            let finding = Finding::new(
                "aws-cloudtrail",
                Severity::High,
                format!("AWS CloudTrail: Trail '{}' not encrypted", trail.name),
                format!(
                    "CloudTrail trail '{}' is not using KMS encryption. \
                     Log files at rest are not protected.",
                    trail.name
                ),
                format!("cloud://{target_label}"),
            )
            .with_evidence(evidence.to_string())
            .with_remediation("Configure SSE-KMS encryption on this CloudTrail trail.")
            .with_confidence(0.9);
            findings.push(enrich_cloud_finding(finding, "cloudtrail"));
        }

        if !trail.log_file_validation {
            let evidence = CloudEvidence::new(CloudProvider::Aws, "cloudtrail")
                .with_check_id("cloudtrail-no-log-validation")
                .with_resource(&trail.name);
            let finding = Finding::new(
                "aws-cloudtrail",
                Severity::Medium,
                format!("AWS CloudTrail: Trail '{}' log file validation disabled", trail.name),
                format!(
                    "CloudTrail trail '{}' does not have log file validation enabled. \
                     Tampered logs cannot be detected.",
                    trail.name
                ),
                format!("cloud://{target_label}"),
            )
            .with_evidence(evidence.to_string())
            .with_remediation("Enable log file validation on this CloudTrail trail.")
            .with_confidence(0.9);
            findings.push(enrich_cloud_finding(finding, "cloudtrail"));
        }

        if !trail.is_logging {
            let evidence = CloudEvidence::new(CloudProvider::Aws, "cloudtrail")
                .with_check_id("cloudtrail-not-logging")
                .with_resource(&trail.name);
            let finding = Finding::new(
                "aws-cloudtrail",
                Severity::Critical,
                format!("AWS CloudTrail: Trail '{}' is not logging", trail.name),
                format!(
                    "CloudTrail trail '{}' exists but is not actively logging. \
                     API activity is not being captured.",
                    trail.name
                ),
                format!("cloud://{target_label}"),
            )
            .with_evidence(evidence.to_string())
            .with_remediation("Start logging on this CloudTrail trail.")
            .with_confidence(0.95);
            findings.push(enrich_cloud_finding(finding, "cloudtrail"));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No trails → Critical finding.
    #[test]
    fn test_cloudtrail_no_trail() {
        let findings = check_trails(&[], "aws:123456789012");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("No trails"));
        assert!(findings[0].compliance.is_some());
    }

    /// Trail without KMS encryption → High finding.
    #[test]
    fn test_cloudtrail_not_encrypted() {
        let trails = vec![TrailStatus {
            name: "main-trail".into(),
            is_multi_region: true,
            kms_key_id: None,
            log_file_validation: true,
            is_logging: true,
        }];
        let findings = check_trails(&trails, "aws:123456789012");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("not encrypted"));
    }

    /// Trail not actively logging → Critical finding.
    #[test]
    fn test_cloudtrail_not_logging() {
        let trails = vec![TrailStatus {
            name: "stopped-trail".into(),
            is_multi_region: true,
            kms_key_id: Some("alias/cloudtrail-key".into()),
            log_file_validation: true,
            is_logging: false,
        }];
        let findings = check_trails(&trails, "aws:123456789012");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("not logging"));
    }

    /// No multi-region trail → High finding.
    #[test]
    fn test_cloudtrail_no_multi_region() {
        let trails = vec![TrailStatus {
            name: "single-region".into(),
            is_multi_region: false,
            kms_key_id: Some("alias/key".into()),
            log_file_validation: true,
            is_logging: true,
        }];
        let findings = check_trails(&trails, "aws:123456789012");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("multi-region"));
    }

    /// Fully configured trail → zero findings.
    #[test]
    fn test_cloudtrail_healthy() {
        let trails = vec![TrailStatus {
            name: "healthy-trail".into(),
            is_multi_region: true,
            kms_key_id: Some("alias/cloudtrail-key".into()),
            log_file_validation: true,
            is_logging: true,
        }];
        let findings = check_trails(&trails, "aws:123456789012");
        assert!(findings.is_empty());
    }

    /// Multiple issues on one trail → multiple findings.
    #[test]
    fn test_cloudtrail_multiple_issues() {
        let trails = vec![TrailStatus {
            name: "bad-trail".into(),
            is_multi_region: false,
            kms_key_id: None,
            log_file_validation: false,
            is_logging: false,
        }];
        let findings = check_trails(&trails, "aws:123456789012");
        // no-multi-region + no-encryption + no-log-validation + not-logging = 4
        assert_eq!(findings.len(), 4);
    }

    /// Module metadata pins.
    #[test]
    fn test_cloudtrail_module_metadata() {
        let m = CloudTrailCloudModule;
        assert_eq!(m.id(), "aws-cloudtrail");
        assert_eq!(m.category(), CloudCategory::Compliance);
        assert_eq!(m.providers(), &[CloudProvider::Aws]);
    }
}
