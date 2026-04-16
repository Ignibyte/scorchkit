//! Native AWS posture checks via `aws-sdk-rust` (WORK-126).
//!
//! Four built-in cloud modules that call AWS APIs directly rather than
//! shelling out to external tools:
//!
//! - [`iam::IamCloudModule`] — root access keys, MFA, password policy
//! - [`s3::S3CloudModule`] — public access, encryption, versioning, logging
//! - [`sg::SecurityGroupCloudModule`] — 0.0.0.0/0 ingress on sensitive ports
//! - [`cloudtrail::CloudTrailCloudModule`] — multi-region, encryption, log validation
//!
//! All modules use intermediate types (defined here) so check logic is
//! testable without mocking the AWS SDK HTTP layer.
//!
//! ## Feature gate
//!
//! Everything in this module is behind `feature = "aws-native"` which
//! depends on `cloud`. Operators who only use the Prowler / `ScoutSuite`
//! tool wrappers don't pay the compile-time cost of the AWS SDK.

pub mod cloudtrail;
pub mod iam;
pub mod s3;
pub mod sg;

use aws_config::SdkConfig;

use crate::engine::cloud_credentials::CloudCredentials;
use crate::engine::cloud_module::CloudModule;
use crate::engine::cloud_target::CloudTarget;
use crate::engine::error::{Result, ScorchError};

// ---------------------------------------------------------------
// Intermediate types — testable without AWS SDK mocking
// ---------------------------------------------------------------

/// IAM account summary extracted from `GetAccountSummary`.
#[derive(Debug, Clone)]
pub struct AwsIamSummary {
    /// Whether root account has access keys.
    pub root_access_keys_present: bool,
    /// Whether root account has MFA enabled.
    pub root_mfa_enabled: bool,
}

/// IAM password policy extracted from `GetAccountPasswordPolicy`.
// JUSTIFICATION: password policy has 4 boolean requirement fields — this
// mirrors the AWS API shape. Collapsing into a bitflag would hurt readability.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct AwsPasswordPolicy {
    /// Minimum password length.
    pub min_length: u32,
    /// Require at least one symbol.
    pub require_symbols: bool,
    /// Require at least one number.
    pub require_numbers: bool,
    /// Require at least one uppercase letter.
    pub require_uppercase: bool,
    /// Require at least one lowercase letter.
    pub require_lowercase: bool,
    /// Maximum password age in days (None = no expiry).
    pub max_age_days: Option<u32>,
}

/// S3 bucket posture extracted from multiple S3 API calls.
// JUSTIFICATION: each boolean maps to a distinct S3 API call result —
// this is the natural shape for the 4 independent posture checks.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct S3BucketPosture {
    /// Bucket name.
    pub name: String,
    /// Whether the public access block is fully enabled.
    pub public_access_blocked: bool,
    /// Whether server-side encryption is configured.
    pub encryption_enabled: bool,
    /// Whether versioning is enabled.
    pub versioning_enabled: bool,
    /// Whether server access logging is enabled.
    pub logging_enabled: bool,
}

/// A single security group ingress rule with an open CIDR.
#[derive(Debug, Clone)]
pub struct SecurityGroupRule {
    /// Security group ID.
    pub group_id: String,
    /// Security group name.
    pub group_name: String,
    /// Destination port.
    pub port: u16,
    /// Protocol (`"tcp"`, `"udp"`, or `"-1"` for all).
    pub protocol: String,
    /// Source CIDR (e.g. `"0.0.0.0/0"`).
    pub source_cidr: String,
}

/// `CloudTrail` trail status extracted from `DescribeTrails` +
/// `GetTrailStatus`.
#[derive(Debug, Clone)]
pub struct TrailStatus {
    /// Trail name.
    pub name: String,
    /// Whether the trail is multi-region.
    pub is_multi_region: bool,
    /// KMS key ID for log encryption (None = not encrypted).
    pub kms_key_id: Option<String>,
    /// Whether log file validation is enabled.
    pub log_file_validation: bool,
    /// Whether the trail is currently logging.
    pub is_logging: bool,
}

/// Sensitive ports that should never be open to 0.0.0.0/0.
pub const SENSITIVE_PORTS: &[(u16, &str)] = &[
    (22, "SSH"),
    (3389, "RDP"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (1433, "MSSQL"),
    (27017, "MongoDB"),
    (6379, "Redis"),
    (9200, "Elasticsearch"),
    (5601, "Kibana"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
];

// ---------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------

/// Build an AWS `SdkConfig` from `ScorchKit`'s [`CloudCredentials`].
///
/// Bridges the `aws_profile` and `aws_region` fields to the AWS
/// SDK's credential chain. When profile/region are unset, the SDK
/// falls through to its standard resolution (env → shared config →
/// IMDS).
///
/// # Errors
///
/// Returns [`ScorchError::Config`] if the target is not an AWS
/// target.
pub async fn build_aws_sdk_config(
    target: &CloudTarget,
    creds: Option<&CloudCredentials>,
) -> Result<SdkConfig> {
    validate_aws_target(target)?;

    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());

    if let Some(c) = creds {
        if let Some(profile) = c.aws_profile.as_deref().filter(|s| !s.is_empty()) {
            loader = loader.profile_name(profile);
        }
        if let Some(region) = c.aws_region.as_deref().filter(|s| !s.is_empty()) {
            loader = loader.region(aws_config::Region::new(region.to_string()));
        }
    }

    Ok(loader.load().await)
}

/// Validate that the target is an AWS-compatible target.
///
/// # Errors
///
/// Returns [`ScorchError::Config`] for GCP, Azure, and Kubernetes targets.
fn validate_aws_target(target: &CloudTarget) -> Result<()> {
    match target {
        CloudTarget::Account(_) | CloudTarget::All => Ok(()),
        CloudTarget::Project(_) => Err(ScorchError::Config(
            "AWS native modules do not support GCP targets — use scoutsuite-cloud for GCP".into(),
        )),
        CloudTarget::Subscription(_) => Err(ScorchError::Config(
            "AWS native modules do not support Azure targets — use scoutsuite-cloud for Azure"
                .into(),
        )),
        CloudTarget::KubeContext(_) => Err(ScorchError::Config(
            "AWS native modules do not support Kubernetes targets — use kubescape-cloud for K8s"
                .into(),
        )),
    }
}

/// Returns all built-in AWS native cloud modules.
///
/// Order is lexicographic by module id: `aws-cloudtrail`,
/// `aws-iam`, `aws-s3`, `aws-sg`.
#[must_use]
pub fn register_aws_modules() -> Vec<Box<dyn CloudModule>> {
    vec![
        Box::new(cloudtrail::CloudTrailCloudModule),
        Box::new(iam::IamCloudModule),
        Box::new(s3::S3CloudModule),
        Box::new(sg::SecurityGroupCloudModule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the registry shape: 4 modules in lex order.
    #[test]
    fn test_register_aws_modules_count() {
        let modules = register_aws_modules();
        assert_eq!(modules.len(), 4);
        assert_eq!(modules[0].id(), "aws-cloudtrail");
        assert_eq!(modules[1].id(), "aws-iam");
        assert_eq!(modules[2].id(), "aws-s3");
        assert_eq!(modules[3].id(), "aws-sg");
    }

    /// Non-AWS targets are rejected.
    #[test]
    fn test_validate_aws_target_rejects_non_aws() {
        assert!(validate_aws_target(&CloudTarget::Account("123".into())).is_ok());
        assert!(validate_aws_target(&CloudTarget::All).is_ok());
        assert!(validate_aws_target(&CloudTarget::Project("p".into())).is_err());
        assert!(validate_aws_target(&CloudTarget::Subscription("s".into())).is_err());
        assert!(validate_aws_target(&CloudTarget::KubeContext("k".into())).is_err());
    }
}
