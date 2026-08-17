//! AWS `CloudTrail` posture checks — multi-region, encryption, log validation.
//!
//! Uses `aws-sdk-cloudtrail` to enumerate trails and check each for
//! security best practices per CIS AWS Foundations Benchmark.

use std::sync::Arc;

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
#[derive(Debug, Default)]
pub struct CloudTrailCloudModule {
    api_override: Option<Arc<dyn CloudTrailApi>>,
}

impl CloudTrailCloudModule {
    #[cfg(test)]
    fn with_api(api: Arc<dyn CloudTrailApi>) -> Self {
        Self { api_override: Some(api) }
    }
}

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
        let target_label = ctx.target.display_raw();
        if let Some(api) = &self.api_override {
            return Ok(findings_from_api(api.as_ref(), &target_label).await);
        }

        let sdk_config = build_aws_sdk_config(&ctx.target, ctx.credentials.as_deref()).await?;
        let client = aws_sdk_cloudtrail::Client::new(&sdk_config);
        let api = AwsCloudTrailApi { client: &client };
        Ok(findings_from_api(&api, &target_label).await)
    }
}

async fn findings_from_api(api: &dyn CloudTrailApi, target_label: &str) -> Vec<Finding> {
    let trails = match fetch_trail_statuses(api).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("aws-cloudtrail: failed to describe trails: {e}");
            return vec![permission_finding(target_label)];
        }
    };

    check_trails(&trails, target_label)
}

/// Fetch trail configuration and status for all trails.
#[derive(Debug)]
struct TrailDescription {
    name: String,
    is_multi_region: bool,
    kms_key_id: Option<String>,
    log_file_validation: bool,
    arn: Option<String>,
}

#[async_trait]
trait CloudTrailApi: std::fmt::Debug + Send + Sync {
    async fn describe_trails(&self) -> std::result::Result<Vec<TrailDescription>, String>;
    async fn logging_status(&self, arn: &str) -> std::result::Result<bool, String>;
}

struct AwsCloudTrailApi<'a> {
    client: &'a aws_sdk_cloudtrail::Client,
}

impl std::fmt::Debug for AwsCloudTrailApi<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AwsCloudTrailApi").finish_non_exhaustive()
    }
}

#[async_trait]
impl CloudTrailApi for AwsCloudTrailApi<'_> {
    async fn describe_trails(&self) -> std::result::Result<Vec<TrailDescription>, String> {
        self.client
            .describe_trails()
            .send()
            .await
            .map(|response| {
                response
                    .trail_list()
                    .iter()
                    .map(|trail| TrailDescription {
                        name: trail.name().unwrap_or("unnamed").to_string(),
                        is_multi_region: trail.is_multi_region_trail.unwrap_or(false),
                        kms_key_id: trail.kms_key_id().map(String::from),
                        log_file_validation: trail.log_file_validation_enabled.unwrap_or(false),
                        arn: trail.trail_arn().map(String::from),
                    })
                    .collect()
            })
            .map_err(|error| error.to_string())
    }

    async fn logging_status(&self, arn: &str) -> std::result::Result<bool, String> {
        self.client
            .get_trail_status()
            .name(arn)
            .send()
            .await
            .map(|status| status.is_logging.unwrap_or(false))
            .map_err(|error| error.to_string())
    }
}

async fn fetch_trail_statuses(
    client: &dyn CloudTrailApi,
) -> std::result::Result<Vec<TrailStatus>, String> {
    let trails = client.describe_trails().await?;
    let mut statuses = Vec::new();

    for trail in trails {
        let is_logging = if let Some(arn) = trail.arn.as_deref() {
            match client.logging_status(arn).await {
                Ok(is_logging) => Some(is_logging),
                Err(error) => {
                    tracing::warn!(trail = %trail.name, "aws-cloudtrail: failed to read trail status: {error}");
                    None
                }
            }
        } else {
            None
        };

        statuses.push(TrailStatus {
            name: trail.name,
            is_multi_region: trail.is_multi_region,
            kms_key_id: trail.kms_key_id,
            log_file_validation: trail.log_file_validation,
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

        if let Some(finding) = logging_status_finding(trail, target_label) {
            findings.push(finding);
        }
    }

    findings
}

fn logging_status_finding(trail: &TrailStatus, target_label: &str) -> Option<Finding> {
    match trail.is_logging {
        Some(false) => {
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
            Some(enrich_cloud_finding(finding, "cloudtrail"))
        }
        None => {
            let evidence = CloudEvidence::new(CloudProvider::Aws, "cloudtrail")
                .with_check_id("cloudtrail-permission-gettrailstatus")
                .with_resource(&trail.name);
            let finding = Finding::new(
                "aws-cloudtrail",
                Severity::Info,
                format!("AWS CloudTrail: Trail '{}' logging status unavailable", trail.name),
                "The credentials could describe this trail but could not read its active logging status.",
                format!("cloud://{target_label}"),
            )
            .with_evidence(evidence.to_string())
            .with_confidence(0.5);
            Some(enrich_cloud_finding(finding, "cloudtrail"))
        }
        Some(true) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixtureCloudTrailApi;

    #[async_trait]
    impl CloudTrailApi for FixtureCloudTrailApi {
        async fn describe_trails(&self) -> std::result::Result<Vec<TrailDescription>, String> {
            Ok(vec![TrailDescription {
                name: "fixture-trail".to_string(),
                is_multi_region: true,
                kms_key_id: Some("alias/fixture".to_string()),
                log_file_validation: true,
                arn: Some("arn:aws:cloudtrail:us-east-1:123456789012:trail/fixture".to_string()),
            }])
        }

        async fn logging_status(&self, arn: &str) -> std::result::Result<bool, String> {
            assert!(arn.ends_with("trail/fixture"));
            Ok(true)
        }
    }

    #[tokio::test]
    async fn fetch_trail_statuses_observes_describe_and_status_calls() {
        let trails = fetch_trail_statuses(&FixtureCloudTrailApi).await.expect("fetch trails");
        assert_eq!(trails.len(), 1);
        assert_eq!(trails[0].name, "fixture-trail");
        assert!(trails[0].is_multi_region);
        assert_eq!(trails[0].kms_key_id.as_deref(), Some("alias/fixture"));
        assert!(trails[0].log_file_validation);
        assert_eq!(trails[0].is_logging, Some(true));
    }

    #[derive(Debug)]
    struct InsecureCloudTrailApi;

    #[async_trait]
    impl CloudTrailApi for InsecureCloudTrailApi {
        async fn describe_trails(&self) -> std::result::Result<Vec<TrailDescription>, String> {
            Ok(vec![TrailDescription {
                name: "insecure-trail".to_string(),
                is_multi_region: true,
                kms_key_id: None,
                log_file_validation: true,
                arn: Some("arn:aws:cloudtrail:us-east-1:123456789012:trail/insecure".to_string()),
            }])
        }

        async fn logging_status(&self, _arn: &str) -> std::result::Result<bool, String> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn module_run_observes_the_injected_cloudtrail_backend() {
        let module = CloudTrailCloudModule::with_api(Arc::new(InsecureCloudTrailApi));
        let context = CloudContext::new(
            crate::engine::cloud_target::CloudTarget::Account("123456789012".to_string()),
            Arc::new(crate::config::AppConfig::default()),
            Vec::new(),
        );

        let findings = module.run(&context).await.expect("run CloudTrail module");
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|finding| finding.title.contains("not encrypted")));
        assert!(findings.iter().any(|finding| finding.title.contains("not logging")));
    }

    #[tokio::test]
    async fn aws_cloudtrail_api_maps_loopback_json_protocol() {
        use httpmock::Method::POST;
        use httpmock::MockServer;

        let server = MockServer::start_async().await;
        let describe = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/")
                    .header("x-amz-target", "CloudTrail_20131101.DescribeTrails");
                then.status(200)
                    .header("content-type", "application/x-amz-json-1.1")
                    .body(
                        r#"{"trailList":[{"Name":"sdk-trail","TrailARN":"arn:aws:cloudtrail:us-east-1:123456789012:trail/sdk","IsMultiRegionTrail":true,"KmsKeyId":"alias/sdk","LogFileValidationEnabled":true}]}"#,
                    );
            })
            .await;
        let logging_true = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/")
                    .header("x-amz-target", "CloudTrail_20131101.GetTrailStatus")
                    .body_includes("trail/true");
                then.status(200)
                    .header("content-type", "application/x-amz-json-1.1")
                    .body(r#"{"IsLogging":true}"#);
            })
            .await;
        let logging_false = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/")
                    .header("x-amz-target", "CloudTrail_20131101.GetTrailStatus")
                    .body_includes("trail/false");
                then.status(200)
                    .header("content-type", "application/x-amz-json-1.1")
                    .body(r#"{"IsLogging":false}"#);
            })
            .await;

        let config = aws_sdk_cloudtrail::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_cloudtrail::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_cloudtrail::config::Credentials::new(
                "fixture-access-key",
                "fixture-secret-key",
                None,
                None,
                "loopback-test",
            ))
            .endpoint_url(server.base_url())
            .build();
        let client = aws_sdk_cloudtrail::Client::from_conf(config);
        let api = AwsCloudTrailApi { client: &client };

        assert_eq!(format!("{api:?}"), "AwsCloudTrailApi { .. }");
        let trails = api.describe_trails().await.expect("describe loopback trails");
        assert_eq!(trails.len(), 1);
        assert_eq!(trails[0].name, "sdk-trail");
        assert!(trails[0].is_multi_region);
        assert_eq!(trails[0].kms_key_id.as_deref(), Some("alias/sdk"));
        assert!(trails[0].log_file_validation);
        assert_eq!(
            trails[0].arn.as_deref(),
            Some("arn:aws:cloudtrail:us-east-1:123456789012:trail/sdk")
        );
        assert!(api
            .logging_status("arn:aws:cloudtrail:us-east-1:123456789012:trail/true")
            .await
            .expect("true logging status"));
        assert!(!api
            .logging_status("arn:aws:cloudtrail:us-east-1:123456789012:trail/false")
            .await
            .expect("false logging status"));
        describe.assert_calls_async(1).await;
        logging_true.assert_calls_async(1).await;
        logging_false.assert_calls_async(1).await;
    }

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
            is_logging: Some(true),
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
            is_logging: Some(false),
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
            is_logging: Some(true),
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
            is_logging: Some(true),
        }];
        let findings = check_trails(&trails, "aws:123456789012");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_cloudtrail_unknown_logging_status_is_informational() {
        let trails = vec![TrailStatus {
            name: "unreadable-status".into(),
            is_multi_region: true,
            kms_key_id: Some("alias/cloudtrail-key".into()),
            log_file_validation: true,
            is_logging: None,
        }];
        let findings = check_trails(&trails, "aws:123456789012");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].title.contains("status unavailable"));
    }

    /// Multiple issues on one trail → multiple findings.
    #[test]
    fn test_cloudtrail_multiple_issues() {
        let trails = vec![TrailStatus {
            name: "bad-trail".into(),
            is_multi_region: false,
            kms_key_id: None,
            log_file_validation: false,
            is_logging: Some(false),
        }];
        let findings = check_trails(&trails, "aws:123456789012");
        // no-multi-region + no-encryption + no-log-validation + not-logging = 4
        assert_eq!(findings.len(), 4);
    }

    /// Module metadata pins.
    #[test]
    fn test_cloudtrail_module_metadata() {
        let m = CloudTrailCloudModule::default();
        assert_eq!(m.name(), "AWS CloudTrail Posture");
        assert_eq!(m.id(), "aws-cloudtrail");
        assert_eq!(m.category(), CloudCategory::Compliance);
        assert_eq!(
            m.description(),
            "Built-in AWS CloudTrail checks: multi-region, encryption, log validation"
        );
        assert_eq!(m.providers(), &[CloudProvider::Aws]);
    }
}
