//! Cloud-posture scanning family — `CloudModule` implementations.
//!
//! Parallel to [`crate::scanner`] (DAST), [`crate::sast_tools`] (SAST),
//! and [`crate::infra`] (infra). Modules implement
//! [`crate::engine::cloud_module::CloudModule`] and are registered via
//! [`register_modules`].
//!
//! ## Current registry (WORK-151)
//!
//! - [`prowler::ProwlerCloudModule`] — Prowler-driven AWS posture audit
//!   (CIS AWS Foundations + 400+ checks). Module id `"prowler-cloud"`.
//!
//! ## Follow-up pipelines
//!
//! - **WORK-152** — Scoutsuite as `CloudModule` (multi-cloud fan-out —
//!   GCP / Azure / AWS / `AliCloud` / OCI)
//! - **WORK-153** — Kubescape as `CloudModule` (Kubernetes cluster
//!   posture)
//! - **WORK-154** — Finding-shape normalization + compliance tagging
//!   across cloud modules; shared OCSF parser extraction (once there
//!   are two consumers)

pub mod prowler;

use crate::engine::cloud_module::CloudModule;

/// Returns every built-in cloud module.
///
/// The list grows as concrete posture-checking modules land. Order
/// is lexicographic by module id so default scans have a stable
/// module sequence across builds.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn CloudModule>> {
    vec![Box::new(prowler::ProwlerCloudModule)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::cloud_module::{CloudCategory, CloudProvider};

    /// Pins the WORK-151 registry shape: exactly one module,
    /// `prowler-cloud`, Compliance category, AWS provider.
    ///
    /// When WORK-152 adds Scoutsuite the expected count flips to 2
    /// and additional assertions pin the new module's id + metadata.
    #[test]
    fn test_cloud_register_modules_contains_prowler() {
        let modules = register_modules();
        assert_eq!(modules.len(), 1, "WORK-151 registers exactly one cloud module");

        let m = &modules[0];
        assert_eq!(m.id(), "prowler-cloud");
        assert_eq!(m.category(), CloudCategory::Compliance);
        assert_eq!(m.providers(), &[CloudProvider::Aws]);
        assert!(m.requires_external_tool());
        assert_eq!(m.required_tool(), Some("prowler"));
    }
}
