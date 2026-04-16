//! Cloud-posture scanning family — `CloudModule` implementations.
//!
//! Parallel to [`crate::scanner`] (DAST), [`crate::sast_tools`] (SAST),
//! and [`crate::infra`] (infra). Modules implement
//! [`crate::engine::cloud_module::CloudModule`] and are registered via
//! [`register_modules`].
//!
//! ## Current registry
//!
//! - [`prowler::ProwlerCloudModule`] (WORK-151) — Prowler-driven AWS
//!   posture audit (CIS AWS Foundations + 400+ checks). Module id
//!   `"prowler-cloud"`.
//! - [`scoutsuite::ScoutsuiteCloudModule`] (WORK-152) — Scout Suite
//!   multi-cloud audit (AWS / GCP / Azure). Module id
//!   `"scoutsuite-cloud"`.
//!
//! ## Follow-up pipelines
//!
//! - **WORK-153** — Kubescape as `CloudModule` (Kubernetes cluster
//!   posture)
//! - **WORK-154** — Finding-shape normalization + compliance tagging
//!   across cloud modules

pub mod prowler;
pub mod scoutsuite;

use crate::engine::cloud_module::CloudModule;

/// Returns every built-in cloud module.
///
/// Order is lexicographic by module id so default scans have a stable
/// module sequence across builds — `prowler-cloud`, `scoutsuite-cloud`.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn CloudModule>> {
    vec![Box::new(prowler::ProwlerCloudModule), Box::new(scoutsuite::ScoutsuiteCloudModule)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::cloud_module::{CloudCategory, CloudProvider};

    /// Pins the WORK-152 registry shape: 2 modules in lex order, both
    /// `Compliance` category. When WORK-153 adds Kubescape the
    /// expected count flips to 3 and additional metadata assertions
    /// pin the new module.
    #[test]
    fn test_cloud_register_modules_v2() {
        let modules = register_modules();
        assert_eq!(modules.len(), 2, "WORK-152 registers exactly two cloud modules");

        // Lexicographic order: prowler-cloud, scoutsuite-cloud
        assert_eq!(modules[0].id(), "prowler-cloud");
        assert_eq!(modules[1].id(), "scoutsuite-cloud");

        // Both Compliance category
        assert_eq!(modules[0].category(), CloudCategory::Compliance);
        assert_eq!(modules[1].category(), CloudCategory::Compliance);

        // Provider coverage
        assert_eq!(modules[0].providers(), &[CloudProvider::Aws]);
        assert_eq!(
            modules[1].providers(),
            &[CloudProvider::Aws, CloudProvider::Gcp, CloudProvider::Azure]
        );

        // Both require external tools
        assert!(modules[0].requires_external_tool());
        assert!(modules[1].requires_external_tool());
        assert_eq!(modules[0].required_tool(), Some("prowler"));
        assert_eq!(modules[1].required_tool(), Some("scout"));
    }
}
