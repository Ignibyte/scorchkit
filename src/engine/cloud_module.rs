//! Module trait and category/provider enums for cloud-posture scanning.
//!
//! [`CloudModule`] is the fourth module family in `ScorchKit`, parallel to
//! [`super::module_trait::ScanModule`] (DAST, URL-targeted),
//! [`super::code_module::CodeModule`] (SAST, path-targeted), and
//! [`super::infra_module::InfraModule`] (host/network, IP-targeted). Cloud
//! modules run against cloud accounts, projects, subscriptions, and
//! Kubernetes contexts via [`super::cloud_target::CloudTarget`].
//!
//! ## Two-axis classification
//!
//! Unlike the infra family, cloud posture scope and provider coverage
//! are independent. A single module lives under exactly one
//! [`CloudCategory`] (what kind of posture check) but may target
//! multiple [`CloudProvider`]s (which clouds it touches). Example: a
//! cross-cloud "publicly-readable object storage" module is
//! `CloudCategory::Storage` and `providers() == &[CloudProvider::Aws,
//! CloudProvider::Gcp, CloudProvider::Azure]`.
//!
//! ## Empty registry in WORK-150
//!
//! The load-bearing type surface ships in WORK-150 without any concrete
//! modules. [`crate::cloud::register_modules`] returns an empty vec.
//! Concrete modules land in WORK-151 (Prowler-as-CloudModule),
//! WORK-152 (Scoutsuite), WORK-153 (Kubescape), and WORK-154
//! (finding-shape normalization).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::cloud_context::CloudContext;
use super::error::Result;
use super::finding::Finding;

/// Posture-check category for a [`CloudModule`].
///
/// Orthogonal to [`CloudProvider`]. Exactly one per module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudCategory {
    /// Identity & access management — users, roles, policies,
    /// permission-boundary drift.
    Iam,
    /// Object/blob storage misconfiguration — public access, missing
    /// encryption, missing lifecycle rules.
    Storage,
    /// Network posture — VPC / security-group / firewall-rule drift,
    /// open-world ingress.
    Network,
    /// Compute-instance posture — EC2 / GCE VM / Azure VM
    /// misconfigurations (default `IMDSv1`, missing patch baseline, etc.).
    Compute,
    /// Kubernetes cluster posture — `RBAC`, admission policies, pod
    /// `SecurityContext`, network policies.
    Kubernetes,
    /// Cross-cutting compliance / benchmark modules (CIS, PCI-DSS,
    /// SOC2, HIPAA). Bridges into the v2.2 compliance arc.
    Compliance,
}

impl std::fmt::Display for CloudCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Iam => f.write_str("iam"),
            Self::Storage => f.write_str("storage"),
            Self::Network => f.write_str("network"),
            Self::Compute => f.write_str("compute"),
            Self::Kubernetes => f.write_str("kubernetes"),
            Self::Compliance => f.write_str("compliance"),
        }
    }
}

/// Cloud provider a [`CloudModule`] targets.
///
/// Orthogonal to [`CloudCategory`]. Zero or more per module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    /// Amazon Web Services.
    Aws,
    /// Google Cloud Platform.
    Gcp,
    /// Microsoft Azure.
    Azure,
    /// Kubernetes cluster (any distribution — EKS, GKE, AKS, on-prem).
    Kubernetes,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws => f.write_str("aws"),
            Self::Gcp => f.write_str("gcp"),
            Self::Azure => f.write_str("azure"),
            Self::Kubernetes => f.write_str("kubernetes"),
        }
    }
}

/// Core abstraction for cloud-posture scanning modules.
///
/// Parallel to [`super::module_trait::ScanModule`],
/// [`super::code_module::CodeModule`], and
/// [`super::infra_module::InfraModule`], but operates on cloud accounts
/// / projects / subscriptions / Kubernetes contexts via
/// [`CloudContext`].
#[async_trait]
pub trait CloudModule: Send + Sync {
    /// Human-readable name for display and reporting.
    fn name(&self) -> &str;

    /// Short identifier used in CLI flags and config keys.
    fn id(&self) -> &str;

    /// Category this module belongs to.
    fn category(&self) -> CloudCategory;

    /// Brief description of what this module checks.
    fn description(&self) -> &str;

    /// Run the posture check against the target in `ctx`.
    ///
    /// Returns findings. An empty vector means no issues detected.
    /// Errors represent orchestration failures, not absence of findings.
    ///
    /// # Errors
    ///
    /// Implementations may return any [`crate::engine::error::ScorchError`]
    /// variant; the orchestrator emits a `ModuleError` event and
    /// continues with other modules.
    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>>;

    /// Whether this module requires an external tool to be installed.
    fn requires_external_tool(&self) -> bool {
        false
    }

    /// The external tool binary name this module needs, if any.
    fn required_tool(&self) -> Option<&str> {
        None
    }

    /// Cloud providers this module targets. Empty slice means
    /// provider-agnostic (rare — compliance modules that introspect
    /// pre-scanned findings are one example).
    fn providers(&self) -> &[CloudProvider] {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant of `CloudCategory` has a stable `Display`
    /// representation. Pins the operator-visible `--category` filter
    /// vocabulary.
    #[test]
    fn test_cloud_category_display() {
        assert_eq!(CloudCategory::Iam.to_string(), "iam");
        assert_eq!(CloudCategory::Storage.to_string(), "storage");
        assert_eq!(CloudCategory::Network.to_string(), "network");
        assert_eq!(CloudCategory::Compute.to_string(), "compute");
        assert_eq!(CloudCategory::Kubernetes.to_string(), "kubernetes");
        assert_eq!(CloudCategory::Compliance.to_string(), "compliance");
    }

    /// `CloudCategory` round-trips through JSON for every variant.
    #[test]
    fn test_cloud_category_serde_round_trip() {
        for cat in [
            CloudCategory::Iam,
            CloudCategory::Storage,
            CloudCategory::Network,
            CloudCategory::Compute,
            CloudCategory::Kubernetes,
            CloudCategory::Compliance,
        ] {
            let json = serde_json::to_string(&cat).expect("serialize");
            let back: CloudCategory = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(cat, back);
        }
    }

    /// Every variant of `CloudProvider` has a stable `Display`
    /// representation.
    #[test]
    fn test_cloud_provider_display() {
        assert_eq!(CloudProvider::Aws.to_string(), "aws");
        assert_eq!(CloudProvider::Gcp.to_string(), "gcp");
        assert_eq!(CloudProvider::Azure.to_string(), "azure");
        assert_eq!(CloudProvider::Kubernetes.to_string(), "kubernetes");
    }

    /// `CloudProvider` round-trips through JSON for every variant.
    #[test]
    fn test_cloud_provider_serde_round_trip() {
        for p in [
            CloudProvider::Aws,
            CloudProvider::Gcp,
            CloudProvider::Azure,
            CloudProvider::Kubernetes,
        ] {
            let json = serde_json::to_string(&p).expect("serialize");
            let back: CloudProvider = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(p, back);
        }
    }
}
