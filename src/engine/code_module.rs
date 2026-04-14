//! Code scanning module trait and categories for SAST.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::code_context::CodeContext;
use super::error::Result;
use super::finding::Finding;

/// Categories for static analysis modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeCategory {
    /// Static application security testing (Semgrep, Bandit).
    Sast,
    /// Software composition analysis (OSV-Scanner, cargo-audit).
    Sca,
    /// Secret detection (Gitleaks, Trufflehog).
    Secrets,
    /// Infrastructure as Code scanning (Checkov, Hadolint).
    Iac,
    /// Container image scanning (Grype, Trivy).
    Container,
}

impl std::fmt::Display for CodeCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sast => write!(f, "sast"),
            Self::Sca => write!(f, "sca"),
            Self::Secrets => write!(f, "secrets"),
            Self::Iac => write!(f, "iac"),
            Self::Container => write!(f, "container"),
        }
    }
}

/// Trait for static code analysis modules.
///
/// Parallel to `ScanModule` but operates on file paths instead of URLs.
/// Every SAST tool wrapper implements this trait.
#[async_trait]
pub trait CodeModule: Send + Sync {
    /// Human-readable name for display and reporting.
    fn name(&self) -> &str;
    /// Short identifier used in CLI flags and config keys.
    fn id(&self) -> &str;
    /// Category this module belongs to.
    fn category(&self) -> CodeCategory;
    /// Brief description of what this module checks.
    fn description(&self) -> &str;
    /// Languages this module supports. Empty slice means language-agnostic.
    fn languages(&self) -> &[&str] {
        &[]
    }
    /// Run the code analysis against the path in `ctx`.
    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>>;
    /// Whether this module requires an external tool to be installed.
    fn requires_external_tool(&self) -> bool {
        false
    }
    /// The external tool binary name this module needs.
    fn required_tool(&self) -> Option<&str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify `CodeCategory` Display produces lowercase strings.
    #[test]
    fn test_code_category_display() {
        assert_eq!(CodeCategory::Sast.to_string(), "sast");
        assert_eq!(CodeCategory::Sca.to_string(), "sca");
        assert_eq!(CodeCategory::Secrets.to_string(), "secrets");
        assert_eq!(CodeCategory::Iac.to_string(), "iac");
        assert_eq!(CodeCategory::Container.to_string(), "container");
    }
}
