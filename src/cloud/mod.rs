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
#[cfg(feature = "azure-native")]
pub mod azure;
#[cfg(feature = "gcp-native")]
pub mod gcp;
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

    #[cfg(feature = "azure-native")]
    modules.extend(azure::register_azure_modules());

    #[cfg(feature = "gcp-native")]
    modules.extend(gcp::register_gcp_modules());

    modules.push(Box::new(kubescape::KubescapeCloudModule));
    modules.push(Box::new(prowler::ProwlerCloudModule));
    modules.push(Box::new(scoutsuite::ScoutsuiteCloudModule));

    modules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::cloud_module::{CloudCategory, CloudProvider};

    /// Verifies the registry contains expected modules based on active features.
    /// Base: 3 tool wrappers. Each native feature adds 4 modules.
    #[test]
    fn test_cloud_register_modules() {
        let modules = register_modules();

        // Count expected modules: 3 base + 4 per native feature
        let mut expected = 3;
        if cfg!(feature = "aws-native") {
            expected += 4;
        }
        if cfg!(feature = "azure-native") {
            expected += 4;
        }
        if cfg!(feature = "gcp-native") {
            expected += 4;
        }
        assert_eq!(modules.len(), expected, "expected {expected} modules with current features");

        // Tool wrappers are always last and always require external tools
        let last = modules.last().expect("at least 3 modules");
        assert_eq!(last.id(), "scoutsuite-cloud");
        assert!(last.requires_external_tool());

        // Verify all module IDs are unique
        let mut ids: Vec<&str> = modules.iter().map(|m| m.id()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), modules.len(), "module IDs must be unique");
    }
}
