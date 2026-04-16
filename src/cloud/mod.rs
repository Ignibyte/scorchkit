//! Cloud-posture scanning family — `CloudModule` implementations.
//!
//! Parallel to [`crate::scanner`] (DAST), [`crate::sast_tools`] (SAST),
//! and [`crate::infra`] (infra). Modules implement
//! [`crate::engine::cloud_module::CloudModule`] and are registered via
//! [`register_modules`].
//!
//! ## Registry
//!
//! **Tool wrappers** (always available with `feature = "cloud"`):
//! - [`kubescape::KubescapeCloudModule`] — Kubescape live cluster posture
//! - [`prowler::ProwlerCloudModule`] — Prowler AWS posture audit
//! - [`scoutsuite::ScoutsuiteCloudModule`] — Scout Suite multi-cloud audit
//!
//! **Native AWS checks** (requires `feature = "aws-native"`):
//! - [`aws::iam::IamCloudModule`] — IAM root keys, MFA, password policy
//! - [`aws::s3::S3CloudModule`] — S3 public access, encryption, versioning
//! - [`aws::sg::SecurityGroupCloudModule`] — open security groups
//! - [`aws::cloudtrail::CloudTrailCloudModule`] — `CloudTrail` health
//!
//! ## Finding normalization (WORK-154)
//!
//! All cloud modules use [`crate::engine::cloud_evidence::CloudEvidence`]
//! for structured evidence and [`crate::engine::cloud_evidence::enrich_cloud_finding`]
//! for per-service OWASP / CWE / compliance mapping instead of blanket
//! `A05:2021 / CWE-1188`.

#[cfg(feature = "aws-native")]
pub mod aws;
pub mod kubescape;
pub mod prowler;
pub mod scoutsuite;

use crate::engine::cloud_module::CloudModule;

/// Returns every built-in cloud module.
///
/// Order is lexicographic by module id so default scans have a stable
/// module sequence across builds. With `feature = "aws-native"`,
/// the 4 AWS modules are prepended (their ids sort before `kubescape-cloud`).
#[must_use]
pub fn register_modules() -> Vec<Box<dyn CloudModule>> {
    let mut modules: Vec<Box<dyn CloudModule>> = Vec::new();

    #[cfg(feature = "aws-native")]
    modules.extend(aws::register_aws_modules());

    modules.push(Box::new(kubescape::KubescapeCloudModule));
    modules.push(Box::new(prowler::ProwlerCloudModule));
    modules.push(Box::new(scoutsuite::ScoutsuiteCloudModule));

    modules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::cloud_module::{CloudCategory, CloudProvider};

    /// Pins the tool-wrapper registry shape: 3 modules in lex order.
    /// With `aws-native`, 4 additional AWS modules prepend.
    #[test]
    fn test_cloud_register_modules() {
        let modules = register_modules();

        #[cfg(not(feature = "aws-native"))]
        {
            assert_eq!(modules.len(), 3, "cloud-only registers 3 tool-wrapper modules");
            assert_eq!(modules[0].id(), "kubescape-cloud");
            assert_eq!(modules[1].id(), "prowler-cloud");
            assert_eq!(modules[2].id(), "scoutsuite-cloud");
        }

        #[cfg(feature = "aws-native")]
        {
            assert_eq!(modules.len(), 7, "aws-native adds 4 native modules to the 3 wrappers");
            // AWS modules first (lex order: aws-cloudtrail, aws-iam, aws-s3, aws-sg)
            assert_eq!(modules[0].id(), "aws-cloudtrail");
            assert_eq!(modules[1].id(), "aws-iam");
            assert_eq!(modules[2].id(), "aws-s3");
            assert_eq!(modules[3].id(), "aws-sg");
            // Tool wrappers after
            assert_eq!(modules[4].id(), "kubescape-cloud");
            assert_eq!(modules[5].id(), "prowler-cloud");
            assert_eq!(modules[6].id(), "scoutsuite-cloud");
            // AWS native modules do NOT require external tools
            assert!(!modules[0].requires_external_tool());
            assert!(!modules[1].requires_external_tool());
            assert!(!modules[2].requires_external_tool());
            assert!(!modules[3].requires_external_tool());
        }

        // Tool wrappers always require external tools
        let wrappers_start = if cfg!(feature = "aws-native") { 4 } else { 0 };
        assert!(modules[wrappers_start].requires_external_tool());
        assert_eq!(modules[wrappers_start].required_tool(), Some("kubescape"));
    }
}
