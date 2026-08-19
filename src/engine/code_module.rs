//! Code scanning module trait and categories for SAST.

use super::code_context::CodeContext;
use super::error::Result;
use super::finding::Finding;
use async_trait::async_trait;

pub use scorchkit_code::{CodeCategory, CodeModuleDescriptor};

/// Trait for static code analysis modules.
///
/// Parallel to `ScanModule` but operates on file paths instead of URLs.
/// Every SAST tool wrapper implements this trait.
#[async_trait]
pub trait CodeModule: Send + Sync {
    /// Return package-owned immutable module metadata.
    fn descriptor(&self) -> CodeModuleDescriptor<'_> {
        CodeModuleDescriptor {
            adapter: crate::adapter_catalog::code_adapter_contract(
                self.id(),
                self.category(),
                self.requires_external_tool(),
            ),
            name: self.name(),
            id: self.id(),
            category: self.category(),
            description: self.description(),
            languages: self.languages(),
            requires_external_tool: self.requires_external_tool(),
            required_tool: self.required_tool(),
        }
    }

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
