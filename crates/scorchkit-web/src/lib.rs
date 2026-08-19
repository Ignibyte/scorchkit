//! Stable vocabulary for URL-targeted reconnaissance and DAST modules.

use scorchkit_core::AdapterContractV1;
use serde::{Deserialize, Serialize};

/// Categories for organizing web modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleCategory {
    /// Reconnaissance and attack-surface discovery.
    Recon,
    /// Vulnerability scanning.
    Scanner,
}

impl std::fmt::Display for ModuleCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Recon => formatter.write_str("recon"),
            Self::Scanner => formatter.write_str("scanner"),
        }
    }
}

/// Immutable metadata exposed by one web scanner module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WebModuleDescriptor<'a> {
    /// Common versioned scanner-adapter contract.
    pub adapter: AdapterContractV1<'a>,
    /// Human-readable module name.
    pub name: &'a str,
    /// Stable registry identifier.
    pub id: &'a str,
    /// Module family category.
    pub category: ModuleCategory,
    /// Human-readable behavior description.
    pub description: &'a str,
    /// Whether execution requires a local external process.
    pub requires_external_tool: bool,
    /// Required executable name when applicable.
    pub required_tool: Option<&'a str>,
}
