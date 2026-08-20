//! Stable vocabulary for local code and dependency analysis modules.

use scorchkit_core::AdapterContractV1;
use serde::{Deserialize, Serialize};

/// Categories for static analysis modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeCategory {
    /// Static application security testing.
    Sast,
    /// Static correctness analysis that does not claim vulnerability coverage.
    Correctness,
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
            Self::Correctness => formatter.write_str("correctness"),
            Self::Sca => formatter.write_str("sca"),
            Self::Secrets => formatter.write_str("secrets"),
            Self::Iac => formatter.write_str("iac"),
            Self::Container => formatter.write_str("container"),
        }
    }
}

/// Relative cost and intended profile placement for a code analyzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeAnalysisDepth {
    /// Suitable for frequent standard analysis.
    Fast,
    /// Reserved for thorough, pentest, or explicit module selection.
    Deep,
}

/// Reproducible supply-chain work selected by one application analysis profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupplyChainProfile {
    /// Declared source dependencies through offline OSV lockfile analysis.
    Quick,
    /// Quick plus one Syft SBOM and Grype analysis of that exact document.
    Standard,
    /// Standard plus Trivy as an independent consumer of the same SBOM.
    Thorough,
    /// The thorough supply-chain contract inside the wider pentest profile.
    Pentest,
}

impl SupplyChainProfile {
    /// Parse one public scan-profile name without inventing aliases.
    #[must_use]
    pub fn from_name(profile: &str) -> Option<Self> {
        match profile {
            "quick" => Some(Self::Quick),
            "standard" => Some(Self::Standard),
            "thorough" => Some(Self::Thorough),
            "pentest" => Some(Self::Pentest),
            _ => None,
        }
    }

    /// Whether the profile requires an SBOM producer and primary consumer.
    #[must_use]
    pub const fn requires_sbom(self) -> bool {
        !matches!(self, Self::Quick)
    }

    /// Whether the profile requires Trivy as a secondary SBOM consumer.
    #[must_use]
    pub const fn requires_secondary_consumer(self) -> bool {
        matches!(self, Self::Thorough | Self::Pentest)
    }
}

/// Stable public operation names and effect classes for supply-chain hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplyChainOperation {
    ScanCode,
    ScanArtifact,
    CacheStatus,
    CacheRefresh,
}

/// Immutable metadata exposed by one code scanner module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CodeModuleDescriptor<'a> {
    /// Common versioned scanner-adapter contract.
    pub adapter: AdapterContractV1<'a>,
    /// Human-readable module name.
    pub name: &'a str,
    /// Stable registry identifier.
    pub id: &'a str,
    /// Module family category.
    pub category: CodeCategory,
    /// Intended implicit-profile depth.
    pub depth: CodeAnalysisDepth,
    /// Human-readable behavior description.
    pub description: &'a str,
    /// Supported languages; an empty slice means language-agnostic.
    pub languages: &'a [&'a str],
    /// Whether execution requires a local external process.
    pub requires_external_tool: bool,
    /// Required executable name when applicable.
    pub required_tool: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::SupplyChainProfile;

    #[test]
    fn supply_chain_profile_names_and_secondary_consumers_are_exact() {
        assert_eq!(SupplyChainProfile::from_name("quick"), Some(SupplyChainProfile::Quick));
        assert_eq!(SupplyChainProfile::from_name("standard"), Some(SupplyChainProfile::Standard));
        assert_eq!(SupplyChainProfile::from_name("thorough"), Some(SupplyChainProfile::Thorough));
        assert_eq!(SupplyChainProfile::from_name("pentest"), Some(SupplyChainProfile::Pentest));
        assert_eq!(SupplyChainProfile::from_name("unknown"), None);

        assert!(!SupplyChainProfile::Quick.requires_secondary_consumer());
        assert!(!SupplyChainProfile::Standard.requires_secondary_consumer());
        assert!(SupplyChainProfile::Thorough.requires_secondary_consumer());
        assert!(SupplyChainProfile::Pentest.requires_secondary_consumer());
    }
}
