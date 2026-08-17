//! Stable vocabulary for local code and dependency analysis modules.

use serde::{Deserialize, Serialize};

/// Categories for static analysis modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeCategory {
    /// Static application security testing.
    Sast,
    /// Software composition analysis.
    Sca,
    /// Secret detection.
    Secrets,
    /// Infrastructure-as-code analysis.
    Iac,
    /// Container image analysis.
    Container,
}

impl std::fmt::Display for CodeCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sast => formatter.write_str("sast"),
            Self::Sca => formatter.write_str("sca"),
            Self::Secrets => formatter.write_str("secrets"),
            Self::Iac => formatter.write_str("iac"),
            Self::Container => formatter.write_str("container"),
        }
    }
}

/// Immutable metadata exposed by one code scanner module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CodeModuleDescriptor<'a> {
    /// Human-readable module name.
    pub name: &'a str,
    /// Stable registry identifier.
    pub id: &'a str,
    /// Module family category.
    pub category: CodeCategory,
    /// Human-readable behavior description.
    pub description: &'a str,
    /// Supported languages; an empty slice means language-agnostic.
    pub languages: &'a [&'a str],
    /// Whether execution requires a local external process.
    pub requires_external_tool: bool,
    /// Required executable name when applicable.
    pub required_tool: Option<&'a str>,
}
