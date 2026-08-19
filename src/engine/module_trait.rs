use super::error::Result;
use super::finding::Finding;
use super::scan_context::ScanContext;
use async_trait::async_trait;

pub use scorchkit_web::{ModuleCategory, WebModuleDescriptor};

/// Core abstraction for all scanning modules.
///
/// Every module in `ScorchKit` implements this trait, whether it performs
/// built-in analysis or wraps an external tool. The orchestrator calls
/// modules through this uniform interface.
#[async_trait]
pub trait ScanModule: Send + Sync {
    /// Return package-owned immutable module metadata.
    fn descriptor(&self) -> WebModuleDescriptor<'_> {
        WebModuleDescriptor {
            adapter: crate::adapter_catalog::web_adapter_contract(
                self.id(),
                self.category(),
                self.requires_external_tool(),
                self.required_tool(),
            ),
            name: self.name(),
            id: self.id(),
            category: self.category(),
            description: self.description(),
            requires_external_tool: self.requires_external_tool(),
            required_tool: self.required_tool(),
        }
    }

    /// Human-readable name for display and reporting.
    fn name(&self) -> &str;

    /// Short identifier used in CLI flags and config keys.
    fn id(&self) -> &str;

    /// Category this module belongs to.
    fn category(&self) -> ModuleCategory;

    /// Brief description of what this module checks.
    fn description(&self) -> &str;

    /// Run the scan against the target in `ctx`.
    ///
    /// Returns findings. An empty vector means no issues detected.
    /// Errors represent infrastructure failures, not absence of vulnerabilities.
    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>>;

    /// Whether this module requires an external tool to be installed.
    fn requires_external_tool(&self) -> bool {
        false
    }

    /// The external tool binary name this module needs.
    fn required_tool(&self) -> Option<&str> {
        None
    }
}
