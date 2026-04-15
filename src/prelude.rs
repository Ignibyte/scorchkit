//! Convenience re-exports for library consumers.
//!
//! Import the prelude to get all core types in scope:
//!
//! ```no_run
//! use scorchkit::prelude::*;
//! ```

// Core types
pub use crate::engine::error::{Result, ScorchError};
pub use crate::engine::finding::Finding;
pub use crate::engine::scan_result::ScanResult;
pub use crate::engine::severity::Severity;
pub use crate::engine::target::Target;

// Module traits
pub use crate::engine::code_module::{CodeCategory, CodeModule};
pub use crate::engine::module_trait::{ModuleCategory, ScanModule};

// Contexts
pub use crate::engine::code_context::CodeContext;
pub use crate::engine::scan_context::ScanContext;

// Event bus
pub use crate::engine::events::{
    subscribe_filtered, subscribe_handler, EventBus, EventHandler, ScanEvent,
};

// Audit log
pub use crate::engine::audit_log::AuditLogHandler;

// Service fingerprints (not feature-gated — useful wherever service data flows)
pub use crate::engine::service_fingerprint::ServiceFingerprint;

// CVE types (not feature-gated — useful across reporting and storage)
pub use crate::engine::cve::{CveLookup, CveRecord};

// CVE match module + backends (feature-gated)
#[cfg(feature = "infra")]
pub use crate::infra::cpe_purl::{cpe_to_package, PackageCoord};
#[cfg(feature = "infra")]
pub use crate::infra::cve_lookup::build_cve_lookup;
#[cfg(feature = "infra")]
pub use crate::infra::cve_match::CveMatchModule;
#[cfg(feature = "infra")]
pub use crate::infra::cve_mock::MockCveLookup;
#[cfg(feature = "infra")]
pub use crate::infra::cve_nvd::NvdCveLookup;
#[cfg(feature = "infra")]
pub use crate::infra::cve_osv::OsvCveLookup;

// CVE configuration (always available — `CveConfig` is on `AppConfig`).
pub use crate::config::cve::OsvConfig;
pub use crate::config::{CveBackendKind, CveConfig, NvdConfig};

// Infra (feature-gated)
#[cfg(feature = "infra")]
pub use crate::engine::infra_context::InfraContext;
#[cfg(feature = "infra")]
pub use crate::engine::infra_module::{InfraCategory, InfraModule};
#[cfg(feature = "infra")]
pub use crate::engine::infra_target::InfraTarget;

// Configuration
pub use crate::config::AppConfig;

// Facade
pub use crate::facade::Engine;

#[cfg(test)]
mod tests {
    /// Verify all prelude re-exports are accessible via wildcard import.
    #[test]
    fn test_prelude_imports() {
        use super::*;

        // Verify types are in scope by referencing them
        let _severity = Severity::High;
        let _category = ModuleCategory::Recon;
        let _code_category = CodeCategory::Sast;

        // Verify Result alias works
        fn _example() -> Result<()> {
            Ok(())
        }
    }
}
