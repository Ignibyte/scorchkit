//! Stable vocabulary for cloud-provider and Kubernetes posture modules.

use serde::{Deserialize, Serialize};

/// Posture-check category for a cloud module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudCategory {
    /// Identity and access management.
    Iam,
    /// Object and blob storage.
    Storage,
    /// Network posture.
    Network,
    /// Compute-instance posture.
    Compute,
    /// Kubernetes posture.
    Kubernetes,
    /// Cross-cutting compliance checks.
    Compliance,
}

impl std::fmt::Display for CloudCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Iam => formatter.write_str("iam"),
            Self::Storage => formatter.write_str("storage"),
            Self::Network => formatter.write_str("network"),
            Self::Compute => formatter.write_str("compute"),
            Self::Kubernetes => formatter.write_str("kubernetes"),
            Self::Compliance => formatter.write_str("compliance"),
        }
    }
}

/// Cloud provider targeted by a cloud module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    /// Amazon Web Services.
    Aws,
    /// Google Cloud Platform.
    Gcp,
    /// Microsoft Azure.
    Azure,
    /// Kubernetes on any distribution.
    Kubernetes,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws => formatter.write_str("aws"),
            Self::Gcp => formatter.write_str("gcp"),
            Self::Azure => formatter.write_str("azure"),
            Self::Kubernetes => formatter.write_str("kubernetes"),
        }
    }
}

/// Immutable metadata exposed by one cloud posture module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CloudModuleDescriptor<'a> {
    /// Human-readable module name.
    pub name: &'a str,
    /// Stable registry identifier.
    pub id: &'a str,
    /// Module family category.
    pub category: CloudCategory,
    /// Human-readable behavior description.
    pub description: &'a str,
    /// Supported providers; an empty slice means provider-agnostic.
    pub providers: &'a [CloudProvider],
    /// Whether execution requires a local external process.
    pub requires_external_tool: bool,
    /// Required executable name when applicable.
    pub required_tool: Option<&'a str>,
}
