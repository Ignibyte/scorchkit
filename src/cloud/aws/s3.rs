//! AWS S3 posture checks — public access, encryption, versioning, logging.
//!
//! Uses `aws-sdk-s3` to enumerate buckets and check each for security
//! best practices per CIS AWS Foundations Benchmark.

use std::sync::Arc;

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
#[derive(Debug, Default)]
pub struct S3CloudModule {
    api_override: Option<Arc<dyn S3Api>>,
}

impl S3CloudModule {
    #[cfg(test)]
    fn with_api(api: Arc<dyn S3Api>) -> Self {
        Self { api_override: Some(api) }
    }
}

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
        let target_label = ctx.target.display_raw();
        if let Some(api) = &self.api_override {
            return Ok(findings_from_api(api.as_ref(), &target_label).await);
        }

        let sdk_config = build_aws_sdk_config(&ctx.target, ctx.credentials.as_deref()).await?;
        let client = aws_sdk_s3::Client::new(&sdk_config);
        let api = AwsS3Api { client: &client };
        Ok(findings_from_api(&api, &target_label).await)
    }
}

#[async_trait]
trait S3Api: std::fmt::Debug + Send + Sync {
    async fn bucket_postures(&self) -> std::result::Result<Vec<S3BucketPosture>, String>;
}

#[derive(Debug)]
struct AwsS3Api<'a> {
    client: &'a aws_sdk_s3::Client,
}

#[async_trait]
impl S3Api for AwsS3Api<'_> {
    async fn bucket_postures(&self) -> std::result::Result<Vec<S3BucketPosture>, String> {
        let buckets = self.client.list_buckets().send().await.map_err(|error| error.to_string())?;

        let mut postures = Vec::new();
        for bucket in buckets.buckets() {
            let name = bucket.name().unwrap_or("unnamed");
            postures.push(fetch_bucket_posture(self.client, name).await);
        }
        Ok(postures)
    }
}

async fn findings_from_api(api: &dyn S3Api, target_label: &str) -> Vec<Finding> {
    let postures = match api.bucket_postures().await {
        Ok(postures) => postures,
        Err(error) => {
            tracing::warn!("aws-s3: failed to list buckets: {error}");
            return vec![permission_finding("ListBuckets", target_label)];
        }
    };

    let mut findings = Vec::new();
    for posture in postures {
        findings.extend(check_bucket_posture(&posture, target_label));
    }
    findings
}

/// Fetch posture details for a single bucket. Gracefully degrades
/// on permission errors (returns worst-case assumptions).
async fn fetch_bucket_posture(client: &aws_sdk_s3::Client, name: &str) -> S3BucketPosture {
    let public_access_blocked =
        client.get_public_access_block().bucket(name).send().await.is_ok_and(|r| {
            r.public_access_block_configuration().is_some_and(|c| {
                all_public_access_controls_enabled([
                    c.block_public_acls.unwrap_or(false),
                    c.block_public_policy.unwrap_or(false),
                    c.ignore_public_acls.unwrap_or(false),
                    c.restrict_public_buckets.unwrap_or(false),
                ])
            })
        });

    let encryption_enabled =
        client.get_bucket_encryption().bucket(name).send().await.is_ok_and(|r| {
            encryption_rules_enabled(
                r.server_side_encryption_configuration()
                    .map(|configuration| configuration.rules().len()),
            )
        });

    let versioning_enabled = client
        .get_bucket_versioning()
        .bucket(name)
        .send()
        .await
        .is_ok_and(|r| versioning_status_enabled(r.status()));

    let logging_enabled = client
        .get_bucket_logging()
        .bucket(name)
        .send()
        .await
        .is_ok_and(|r| r.logging_enabled().is_some());

    S3BucketPosture {
        name: name.to_string(),
        public_access_blocked,
        encryption_enabled,
        versioning_enabled,
        logging_enabled,
    }
}

fn all_public_access_controls_enabled(controls: [bool; 4]) -> bool {
    controls.into_iter().all(std::convert::identity)
}

fn encryption_rules_enabled(rule_count: Option<usize>) -> bool {
    rule_count.is_some_and(|count| count > 0)
}

fn versioning_status_enabled(status: Option<&aws_sdk_s3::types::BucketVersioningStatus>) -> bool {
    status.is_some_and(|value| *value == aws_sdk_s3::types::BucketVersioningStatus::Enabled)
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

    #[derive(Debug)]
    struct FixtureS3Api;

    #[async_trait]
    impl S3Api for FixtureS3Api {
        async fn bucket_postures(&self) -> std::result::Result<Vec<S3BucketPosture>, String> {
            Ok(vec![S3BucketPosture {
                name: "fixture-bucket".to_string(),
                public_access_blocked: false,
                encryption_enabled: false,
                versioning_enabled: true,
                logging_enabled: true,
            }])
        }
    }

    #[tokio::test]
    async fn module_run_observes_the_injected_s3_backend() {
        let module = S3CloudModule::with_api(Arc::new(FixtureS3Api));
        let context = CloudContext::new(
            crate::engine::cloud_target::CloudTarget::Account("123456789012".to_string()),
            Arc::new(crate::config::AppConfig::default()),
            Vec::new(),
        );

        let findings = module.run(&context).await.expect("run S3 module");
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|finding| finding.title.contains("public access")));
        assert!(findings.iter().any(|finding| finding.title.contains("not encrypted")));
    }

    #[tokio::test]
    async fn aws_s3_api_maps_loopback_rest_xml() {
        use httpmock::Method::GET;
        use httpmock::MockServer;

        let server = MockServer::start_async().await;
        let list = server
            .mock_async(|when, then| {
                when.method(GET).path("/");
                then.status(200).header("content-type", "application/xml").body(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Buckets><Bucket><Name>fixture-bucket</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate></Bucket></Buckets>
</ListAllMyBucketsResult>"#,
                );
            })
            .await;
        let public_access = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/fixture-bucket/")
                    .query_param_exists("publicAccessBlock");
                then.status(200).header("content-type", "application/xml").body(
                    r#"<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>"#,
                );
            })
            .await;
        let encryption = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/fixture-bucket/")
                    .query_param_exists("encryption");
                then.status(200).header("content-type", "application/xml").body(
                    r#"<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"#,
                );
            })
            .await;
        let versioning = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/fixture-bucket/")
                    .query_param_exists("versioning");
                then.status(200).header("content-type", "application/xml").body(
                    r#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>"#,
                );
            })
            .await;
        let logging = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/fixture-bucket/")
                    .query_param_exists("logging");
                then.status(200).header("content-type", "application/xml").body(
                    r#"<BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LoggingEnabled><TargetBucket>audit-bucket</TargetBucket><TargetPrefix>fixture/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>"#,
                );
            })
            .await;

        let config = aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "fixture-access-key",
                "fixture-secret-key",
                None,
                None,
                "loopback-test",
            ))
            .endpoint_url(server.base_url())
            .force_path_style(true)
            .build();
        let client = aws_sdk_s3::Client::from_conf(config);
        let api = AwsS3Api { client: &client };
        let postures = api.bucket_postures().await.expect("fetch loopback bucket posture");

        list.assert_calls_async(1).await;
        public_access.assert_calls_async(1).await;
        encryption.assert_calls_async(1).await;
        versioning.assert_calls_async(1).await;
        logging.assert_calls_async(1).await;
        assert_eq!(postures.len(), 1);
        assert_eq!(postures[0].name, "fixture-bucket");
        assert!(postures[0].public_access_blocked);
        assert!(postures[0].encryption_enabled);
        assert!(postures[0].versioning_enabled);
        assert!(postures[0].logging_enabled);
    }

    #[test]
    fn public_access_block_requires_all_four_controls() {
        for mask in 0_u8..16 {
            let actual = all_public_access_controls_enabled([
                mask & 0b0001 != 0,
                mask & 0b0010 != 0,
                mask & 0b0100 != 0,
                mask & 0b1000 != 0,
            ]);
            assert_eq!(actual, mask == 0b1111, "mask {mask:04b}");
        }
    }

    #[test]
    fn encryption_requires_at_least_one_rule() {
        assert!(!encryption_rules_enabled(None));
        assert!(!encryption_rules_enabled(Some(0)));
        assert!(encryption_rules_enabled(Some(1)));
    }

    #[test]
    fn versioning_requires_enabled_status() {
        use aws_sdk_s3::types::BucketVersioningStatus;

        assert!(!versioning_status_enabled(None));
        assert!(!versioning_status_enabled(Some(&BucketVersioningStatus::Suspended)));
        assert!(versioning_status_enabled(Some(&BucketVersioningStatus::Enabled)));
    }

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
        let m = S3CloudModule::default();
        assert_eq!(m.name(), "AWS S3 Posture");
        assert_eq!(m.id(), "aws-s3");
        assert_eq!(m.category(), CloudCategory::Storage);
        assert_eq!(
            m.description(),
            "Built-in AWS S3 checks: public access, encryption, versioning, logging"
        );
        assert_eq!(m.providers(), &[CloudProvider::Aws]);
    }
}
