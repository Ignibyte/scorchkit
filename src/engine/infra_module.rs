//! Module trait and category enum for infrastructure scanning.
//!
//! [`InfraModule`] is the third module family in `ScorchKit`, parallel to
//! [`super::module_trait::ScanModule`] (DAST, URL-targeted) and
//! [`super::code_module::CodeModule`] (SAST, path-targeted). Infra modules
//! run against hosts, IP addresses, and CIDR ranges via [`super::infra_target::InfraTarget`].

use super::error::Result;
use super::finding::Finding;
use super::infra_context::InfraContext;
use async_trait::async_trait;

pub use scorchkit_infra::{InfraCategory, InfraModuleDescriptor};

/// Core abstraction for infra scanning modules.
///
/// Parallel to [`super::module_trait::ScanModule`] and
/// [`super::code_module::CodeModule`] but operates on
/// [`super::infra_target::InfraTarget`] through [`InfraContext`].
#[async_trait]
pub trait InfraModule: Send + Sync {
    /// Return package-owned immutable module metadata.
    fn descriptor(&self) -> InfraModuleDescriptor<'_> {
        InfraModuleDescriptor {
            adapter: crate::adapter_catalog::infra_adapter_contract(
                self.id(),
                self.category(),
                self.requires_external_tool(),
            ),
            name: self.name(),
            id: self.id(),
            category: self.category(),
            description: self.description(),
            protocols: self.protocols(),
            requires_external_tool: self.requires_external_tool(),
            required_tool: self.required_tool(),
        }
    }

    /// Human-readable name for display and reporting.
    fn name(&self) -> &str;

    /// Short identifier used in CLI flags and config keys.
    fn id(&self) -> &str;

    /// Category this module belongs to.
    fn category(&self) -> InfraCategory;

    /// Brief description of what this module checks.
    fn description(&self) -> &str;

    /// Run the probe against the target in `ctx`.
    ///
    /// Returns findings. An empty vector means no issues detected.
    /// Errors represent infrastructure failures, not absence of findings.
    ///
    /// # Errors
    ///
    /// Implementations may return any [`crate::engine::error::ScorchError`] variant; the
    /// orchestrator emits a `ModuleError` event and continues with other
    /// modules.
    async fn run(&self, ctx: &InfraContext) -> Result<Vec<Finding>>;

    /// Whether this module requires an external tool to be installed.
    fn requires_external_tool(&self) -> bool {
        false
    }

    /// The external tool binary name this module needs, if any.
    fn required_tool(&self) -> Option<&str> {
        None
    }

    /// Protocols this module probes (`"ssh"`, `"smb"`, `"snmp"`, ...).
    /// Empty slice means protocol-agnostic.
    fn protocols(&self) -> &[&str] {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant of `InfraCategory` has a Display representation.
    #[test]
    fn test_infra_category_display() {
        assert_eq!(InfraCategory::PortScan.to_string(), "portscan");
        assert_eq!(InfraCategory::Fingerprint.to_string(), "fingerprint");
        assert_eq!(InfraCategory::CveMatch.to_string(), "cvematch");
        assert_eq!(InfraCategory::TlsInfra.to_string(), "tlsinfra");
        assert_eq!(InfraCategory::Dns.to_string(), "dns");
        assert_eq!(InfraCategory::Cloud.to_string(), "cloud");
    }

    /// `InfraCategory` round-trips through JSON.
    #[test]
    fn test_infra_category_serde_round_trip() {
        for cat in [
            InfraCategory::PortScan,
            InfraCategory::Fingerprint,
            InfraCategory::CveMatch,
            InfraCategory::TlsInfra,
            InfraCategory::Dns,
            InfraCategory::Cloud,
        ] {
            let json = serde_json::to_string(&cat).expect("serialize");
            let back: InfraCategory = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(cat, back);
        }
    }
}
