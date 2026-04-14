//! Module trait and category enum for infrastructure scanning.
//!
//! [`InfraModule`] is the third module family in `ScorchKit`, parallel to
//! [`super::module_trait::ScanModule`] (DAST, URL-targeted) and
//! [`super::code_module::CodeModule`] (SAST, path-targeted). Infra modules
//! run against hosts, IP addresses, and CIDR ranges via [`super::infra_target::InfraTarget`].

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::error::Result;
use super::finding::Finding;
use super::infra_context::InfraContext;

/// Categories for organising infra modules.
///
/// More variants will be added in later pipelines (WORK-104 adds
/// `NetworkAuth` and `ServiceEnum`). The current five cover the immediate
/// v2.0 scope: port scanning, service fingerprinting, CVE correlation,
/// TLS beyond HTTPS, and DNS infrastructure checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InfraCategory {
    /// Port enumeration (nmap-family).
    PortScan,
    /// Service version detection — produces `(product, version, cpe)` tuples.
    Fingerprint,
    /// CVE correlation against detected versions.
    CveMatch,
    /// TLS beyond HTTPS — STARTTLS, LDAPS, SMTPS, RDP-TLS.
    TlsInfra,
    /// DNS infrastructure checks — zone transfer, DNSSEC, wildcard detection.
    Dns,
}

impl std::fmt::Display for InfraCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PortScan => f.write_str("portscan"),
            Self::Fingerprint => f.write_str("fingerprint"),
            Self::CveMatch => f.write_str("cvematch"),
            Self::TlsInfra => f.write_str("tlsinfra"),
            Self::Dns => f.write_str("dns"),
        }
    }
}

/// Core abstraction for infra scanning modules.
///
/// Parallel to [`super::module_trait::ScanModule`] and
/// [`super::code_module::CodeModule`] but operates on
/// [`super::infra_target::InfraTarget`] through [`InfraContext`].
#[async_trait]
pub trait InfraModule: Send + Sync {
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
        ] {
            let json = serde_json::to_string(&cat).expect("serialize");
            let back: InfraCategory = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(cat, back);
        }
    }
}
