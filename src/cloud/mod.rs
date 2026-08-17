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
//! Native AWS, GCP, and Azure checks still compile behind their provider
//! features, but they are private and absent from the production registry.
//! Their SDK transports do not yet use `ScorchKit`'s engagement-bound resolver,
//! so exposing them would bypass per-address authorization.
//!
//! ## Finding normalization (WORK-154)
//!
//! All cloud modules use [`crate::engine::cloud_evidence::CloudEvidence`]
//! for structured evidence and [`crate::engine::cloud_evidence::enrich_cloud_finding`]
//! for per-service OWASP / CWE / compliance mapping instead of blanket
//! `A05:2021 / CWE-1188`.

#[cfg(all(feature = "aws-native", test))]
pub(crate) mod aws;
#[cfg(all(feature = "azure-native", test))]
pub(crate) mod azure;
pub mod cloudsplaining;
pub mod cnspec;
#[cfg(all(feature = "gcp-native", test))]
pub(crate) mod gcp;
pub mod kubescape;
pub mod pacu;
pub mod prowler;
pub mod scoutsuite;

use crate::engine::cloud_module::CloudModule;

/// Returns every built-in cloud module.
///
/// Order is lexicographic by module id so default scans have a stable
/// module sequence across builds. Provider-native feature flags compile their
/// implementation and pure checks, but do not add modules until their HTTP
/// transports enforce the same resolver policy as native `ScorchKit` clients.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn CloudModule>> {
    // Safe posture wrappers. Pacu remains available as a module type but is
    // excluded until an explicit exploit-authorized cloud profile exists.
    vec![
        Box::new(cloudsplaining::CloudsplainingCloudModule),
        Box::new(cnspec::CnspecCloudModule),
        Box::new(kubescape::KubescapeCloudModule),
        Box::new(prowler::ProwlerCloudModule),
        Box::new(scoutsuite::ScoutsuiteCloudModule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Provider SDK modules stay quarantined until they use a policy-owned transport.
    #[test]
    fn test_cloud_register_modules() {
        let modules = register_modules();

        assert_eq!(modules.len(), 5);
        assert!(modules.iter().all(|module| module.requires_external_tool()));
        assert!(!modules.iter().any(|module| {
            module.id().starts_with("aws-")
                || module.id().starts_with("gcp-")
                || module.id().starts_with("azure-")
        }));

        // Tool wrappers are always last and always require external tools
        let last = modules.last().expect("at least one module");
        assert_eq!(last.id(), "scoutsuite-cloud");
        assert!(last.requires_external_tool());
        assert!(!modules.iter().any(|module| module.id() == "pacu-cloud"));

        // Verify all module IDs are unique
        let mut ids: Vec<&str> = modules.iter().map(|m| m.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), modules.len(), "module IDs must be unique");
    }
}
