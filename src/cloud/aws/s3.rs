//! AWS S3 posture checks — public access, encryption, versioning, logging.
//!
//! Uses `aws-sdk-s3` to enumerate buckets and check each for security
//! best practices per CIS AWS Foundations Benchmark.

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

use super::{build_aws_sdk_config, S3BucketPosture};

/// Built-in AWS S3 posture module.
///
/// Checks every bucket in the account for public access blocks,
/// server-side encryption, versioning, and access logging.
#[derive(Debug)]
pub struct S3CloudModule;

#[async_trait]
impl CloudModule for S3CloudModule {
    fn name(&self) -> &'static str {
        "AWS S3 Posture"
    }

    fn id(&self) -> &'static str {
        "aws-s3"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Storage
    }

    fn description(&self) -> &'static str {
        "Built-in AWS S3 checks: public access, encryption, versioning, logging"
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Aws]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let sdk_config = build_aws_sdk_config(&ctx.target, ctx.credentials.as_deref()).await?;
        let client = aws_sdk_s3::Client::new(&sdk_config);
        let target_label = ctx.target.display_raw();

        let buckets = match client.list_buckets().send().await {
            Ok(resp) => resp.buckets().to_vec(),
            Err(e) => {
                tracing::warn!("aws-s3: failed to list buckets: {e}");
                return Ok(vec![permission_finding("ListBuckets", &target_label)]);
            }
        };

        let mut findings = Vec::new();
        for bucket in buckets {
            let name = bucket.name().unwrap_or("unnamed");
            let posture = fetch_bucket_posture(&client, name).await;
            findings.extend(check_bucket_posture(&posture, &target_label));
        }

        Ok(findings)
    }
}

/// Fetch posture details for a single bucket. Gracefully degrades
/// on permission errors (returns worst-case assumptions).
async fn fetch_bucket_posture(client: &aws_sdk_s3::Client, name: &str) -> S3BucketPosture {
    let public_access_blocked = client
        .get_public_access_block()
        .bucket(name)
        .send()
        .await
        .map(|r| {
            r.public_access_block_configuration().is_some_and(|c| {
                c.block_public_acls.unwrap_or(false)
                    && c.block_public_policy.unwrap_or(false)
                    && c.ignore_public_acls.unwrap_or(false)
                    && c.restrict_public_buckets.unwrap_or(false)
            })
        })
        .unwrap_or(false);

    let encryption_enabled = client
        .get_bucket_encryption()
        .bucket(name)
        .send()
        .await
        .map(|r| r.server_side_encryption_configuration().is_some_and(|c| !c.rules().is_empty()))
        .unwrap_or(false);

    let versioning_enabled = client
        .get_bucket_versioning()
        .bucket(name)
        .send()
        .await
        .map(|r| {
            r.status().is_some_and(|s| *s == aws_sdk_s3::types::BucketVersioningStatus::Enabled)
        })
        .unwrap_or(false);

    let logging_enabled = client
        .get_bucket_logging()
        .bucket(name)
        .send()
        .await
        .map(|r| r.logging_enabled().is_some())
        .unwrap_or(false);

    S3BucketPosture {
        name: name.to_string(),
        public_access_blocked,
        encryption_enabled,
        versioning_enabled,
        logging_enabled,
    }
}

/// Generate an Info-level "insufficient permissions" finding.
fn permission_finding(api_call: &str, target_label: &str) -> Finding {
    let finding = Finding::new(
        "aws-s3",
        Severity::Info,
        format!("AWS S3: Insufficient permissions for {api_call}"),
        format!("The credentials lack permission to call s3:{api_call}."),
        format!("cloud://{target_label}"),
    )
    .with_evidence(
        CloudEvidence::new(CloudProvider::Aws, "s3")
            .with_check_id(format!("s3-permission-{}", api_call.to_lowercase()))
            .to_string(),
    )
    .with_confidence(0.5);
    enrich_cloud_finding(finding, "s3")
}

// ---------------------------------------------------------------
// Pure check functions — testable without AWS SDK
// ---------------------------------------------------------------

/// Check a single bucket's posture and produce findings.
#[must_use]
pub fn check_bucket_posture(bucket: &S3BucketPosture, target_label: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !bucket.public_access_blocked {
        let evidence = CloudEvidence::new(CloudProvider::Aws, "s3")
            .with_check_id("s3-public-access")
            .with_resource(&bucket.name);
        let finding = Finding::new(
            "aws-s3",
            Severity::Critical,
            format!("AWS S3: Bucket '{}' public access not blocked", bucket.name),
            format!(
                "S3 bucket '{}' does not have all public access block settings enabled. \
                 Data may be publicly accessible.",
                bucket.name
            ),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Enable all four S3 Block Public Access settings on this bucket.")
        .with_confidence(0.9);
        findings.push(enrich_cloud_finding(finding, "s3"));
    }

    if !bucket.encryption_enabled {
        let evidence = CloudEvidence::new(CloudProvider::Aws, "s3")
            .with_check_id("s3-no-encryption")
            .with_resource(&bucket.name);
        let finding = Finding::new(
            "aws-s3",
            Severity::High,
            format!("AWS S3: Bucket '{}' not encrypted", bucket.name),
            format!(
                "S3 bucket '{}' does not have server-side encryption configured. \
                 Data at rest is not protected.",
                bucket.name
            ),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Enable default SSE-S3 or SSE-KMS encryption on this bucket.")
        .with_confidence(0.9);
        findings.push(enrich_cloud_finding(finding, "s3"));
    }

    if !bucket.versioning_enabled {
        let evidence = CloudEvidence::new(CloudProvider::Aws, "s3")
            .with_check_id("s3-no-versioning")
            .with_resource(&bucket.name);
        let finding = Finding::new(
            "aws-s3",
            Severity::Medium,
            format!("AWS S3: Bucket '{}' versioning disabled", bucket.name),
            format!(
                "S3 bucket '{}' does not have versioning enabled. \
                 Deleted or overwritten objects cannot be recovered.",
                bucket.name
            ),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation(
            "Enable versioning on this bucket to protect against accidental deletion.",
        )
        .with_confidence(0.85);
        findings.push(enrich_cloud_finding(finding, "s3"));
    }

    if !bucket.logging_enabled {
        let evidence = CloudEvidence::new(CloudProvider::Aws, "s3")
            .with_check_id("s3-no-logging")
            .with_resource(&bucket.name);
        let finding = Finding::new(
            "aws-s3",
            Severity::Medium,
            format!("AWS S3: Bucket '{}' access logging disabled", bucket.name),
            format!(
                "S3 bucket '{}' does not have server access logging enabled. \
                 Access patterns cannot be audited.",
                bucket.name
            ),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Enable server access logging to an audit bucket.")
        .with_confidence(0.85);
        findings.push(enrich_cloud_finding(finding, "s3"));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Public bucket → Critical finding.
    #[test]
    fn test_s3_public_bucket() {
        let bucket = S3BucketPosture {
            name: "my-public-bucket".into(),
            public_access_blocked: false,
            encryption_enabled: true,
            versioning_enabled: true,
            logging_enabled: true,
        };
        let findings = check_bucket_posture(&bucket, "aws:123456789012");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("public access"));
        assert!(findings[0].compliance.is_some());
    }

    /// Missing encryption → High finding.
    #[test]
    fn test_s3_no_encryption() {
        let bucket = S3BucketPosture {
            name: "unencrypted".into(),
            public_access_blocked: true,
            encryption_enabled: false,
            versioning_enabled: true,
            logging_enabled: true,
        };
        let findings = check_bucket_posture(&bucket, "aws:123456789012");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("not encrypted"));
    }

    /// Fully secured bucket → zero findings.
    #[test]
    fn test_s3_secure_bucket() {
        let bucket = S3BucketPosture {
            name: "secure-bucket".into(),
            public_access_blocked: true,
            encryption_enabled: true,
            versioning_enabled: true,
            logging_enabled: true,
        };
        let findings = check_bucket_posture(&bucket, "aws:123456789012");
        assert!(findings.is_empty());
    }

    /// All issues at once → 4 findings.
    #[test]
    fn test_s3_all_issues() {
        let bucket = S3BucketPosture {
            name: "bad-bucket".into(),
            public_access_blocked: false,
            encryption_enabled: false,
            versioning_enabled: false,
            logging_enabled: false,
        };
        let findings = check_bucket_posture(&bucket, "aws:123456789012");
        assert_eq!(findings.len(), 4);
    }

    /// Module metadata pins.
    #[test]
    fn test_s3_module_metadata() {
        let m = S3CloudModule;
        assert_eq!(m.id(), "aws-s3");
        assert_eq!(m.category(), CloudCategory::Storage);
        assert_eq!(m.providers(), &[CloudProvider::Aws]);
    }
}
