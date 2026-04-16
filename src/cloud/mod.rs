//! Cloud-posture scanning family — `CloudModule` implementations.
//!
//! Parallel to [`crate::scanner`] (DAST), [`crate::sast_tools`] (SAST),
//! and [`crate::infra`] (infra). Modules implement
//! [`crate::engine::cloud_module::CloudModule`] and are registered via
//! [`register_modules`].
//!
//! ## Current registry (3 modules)
//!
//! - [`kubescape::KubescapeCloudModule`] (WORK-153) — Kubescape live
//!   cluster posture (NSA / MITRE / `ArmoBest` / CIS Kubernetes).
//!   Module id `"kubescape-cloud"`.
//! - [`prowler::ProwlerCloudModule`] (WORK-151) — Prowler-driven AWS
//!   posture audit (CIS AWS Foundations + 400+ checks). Module id
//!   `"prowler-cloud"`.
//! - [`scoutsuite::ScoutsuiteCloudModule`] (WORK-152) — Scout Suite
//!   multi-cloud audit (AWS / GCP / Azure). Module id
//!   `"scoutsuite-cloud"`.
//!
//! ## Follow-up pipelines
//!
//! - **WORK-154** — Finding-shape normalization + per-check CWE /
//!   compliance tagging across cloud modules; CPE extraction for CVE
//!   correlation.

pub mod kubescape;
pub mod prowler;
pub mod scoutsuite;

use crate::engine::cloud_module::CloudModule;

/// Returns every built-in cloud module.
///
/// Order is lexicographic by module id so default scans have a stable
/// module sequence across builds — `kubescape-cloud`, `prowler-cloud`,
/// `scoutsuite-cloud`.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn CloudModule>> {
    vec![
        Box::new(kubescape::KubescapeCloudModule),
        Box::new(prowler::ProwlerCloudModule),
        Box::new(scoutsuite::ScoutsuiteCloudModule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::cloud_module::{CloudCategory, CloudProvider};

    /// Pins the WORK-153 registry shape: 3 modules in lex order with
    /// distinct categories — Kubernetes, Compliance, Compliance.
    #[test]
    fn test_cloud_register_modules_v3() {
        let modules = register_modules();
        assert_eq!(modules.len(), 3, "WORK-153 registers exactly three cloud modules");

        // Lexicographic order: kubescape-cloud, prowler-cloud, scoutsuite-cloud
        assert_eq!(modules[0].id(), "kubescape-cloud");
        assert_eq!(modules[1].id(), "prowler-cloud");
        assert_eq!(modules[2].id(), "scoutsuite-cloud");

        // Categories
        assert_eq!(modules[0].category(), CloudCategory::Kubernetes);
        assert_eq!(modules[1].category(), CloudCategory::Compliance);
        assert_eq!(modules[2].category(), CloudCategory::Compliance);

        // Provider coverage
        assert_eq!(modules[0].providers(), &[CloudProvider::Kubernetes]);
        assert_eq!(modules[1].providers(), &[CloudProvider::Aws]);
        assert_eq!(
            modules[2].providers(),
            &[CloudProvider::Aws, CloudProvider::Gcp, CloudProvider::Azure]
        );

        // All require external tools
        assert!(modules[0].requires_external_tool());
        assert!(modules[1].requires_external_tool());
        assert!(modules[2].requires_external_tool());
        assert_eq!(modules[0].required_tool(), Some("kubescape"));
        assert_eq!(modules[1].required_tool(), Some("prowler"));
        assert_eq!(modules[2].required_tool(), Some("scout"));
    }
}
