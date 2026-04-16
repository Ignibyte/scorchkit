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

// Network credentials (WORK-146) — authenticated network scanning.
pub use crate::engine::network_credentials::NetworkCredentials;

// Service fingerprints (not feature-gated — useful wherever service data flows)
pub use crate::engine::service_fingerprint::ServiceFingerprint;

// TLS enumeration primitives (WORK-143) — published regardless of the
// infra feature because they're useful for any TLS-aware scanner.
pub use crate::engine::tls_enum::{CipherSuiteId, CipherWeakness, ProbeOutcome, TlsVersionId};

// API spec shared-data primitive (WORK-108) — published by tools like
// vespasian, consumed by injection / csrf / idor / graphql / auth /
// ratelimit scanners
pub use crate::engine::api_spec::{ApiEndpoint, ApiSpec};

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
pub use crate::infra::cve_multi::MultiCveLookup;
#[cfg(feature = "infra")]
pub use crate::infra::cve_nvd::NvdCveLookup;
#[cfg(feature = "infra")]
pub use crate::infra::cve_osv::OsvCveLookup;

// CVE configuration (always available — `CveConfig` is on `AppConfig`).
pub use crate::config::cve::OsvConfig;
pub use crate::config::{CompositeConfig, CompositeSource, CveBackendKind, CveConfig, NvdConfig};

// Infra (feature-gated)
#[cfg(feature = "infra")]
pub use crate::engine::infra_context::InfraContext;
#[cfg(feature = "infra")]
pub use crate::engine::infra_module::{InfraCategory, InfraModule};
#[cfg(feature = "infra")]
pub use crate::engine::infra_target::InfraTarget;

// Cloud (feature-gated — WORK-150)
#[cfg(feature = "cloud")]
pub use crate::engine::cloud_context::CloudContext;
#[cfg(feature = "cloud")]
pub use crate::engine::cloud_credentials::CloudCredentials;
#[cfg(feature = "cloud")]
pub use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
#[cfg(feature = "cloud")]
pub use crate::engine::cloud_target::CloudTarget;

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
