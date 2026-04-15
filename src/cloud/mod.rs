//! Cloud-posture scanning family — `CloudModule` implementations.
//!
//! Parallel to [`crate::scanner`] (DAST), [`crate::sast_tools`] (SAST),
//! and [`crate::infra`] (infra). Modules implement
//! [`crate::engine::cloud_module::CloudModule`] and are registered via
//! [`register_modules`].
//!
//! ## WORK-150 state: empty registry
//!
//! This module tree ships empty at WORK-150 — the load-bearing type
//! surface and orchestrator wiring are the deliverable, not any
//! concrete posture check. Concrete modules land in:
//!
//! - **WORK-151** — Prowler-as-`CloudModule` (AWS coverage via the
//!   existing `tools::prowler` wrapper, reshaped to the cloud-family
//!   surface)
//! - **WORK-152** — Scoutsuite-as-`CloudModule` (multi-cloud fan-out)
//! - **WORK-153** — Kubescape-as-`CloudModule` (Kubernetes cluster
//!   posture)
//! - **WORK-154** — Finding-shape normalization + compliance tagging
//!   across the three wrappers

use crate::engine::cloud_module::CloudModule;

/// Returns every built-in cloud module. Empty at WORK-150 — populated
/// by WORK-151+.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn CloudModule>> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the WORK-150 empty-registry contract. When WORK-151 ships
    /// the Prowler cloud module, this test will update to assert the
    /// expected non-empty count.
    #[test]
    fn test_cloud_register_modules_empty() {
        let modules = register_modules();
        assert!(modules.is_empty(), "WORK-150 ships no concrete cloud modules");
    }
}
