//! Stable vocabulary for host, network, DNS, CVE, and TLS modules.

use scorchkit_core::AdapterContractV1;
use serde::{Deserialize, Serialize};

/// Categories for infrastructure modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InfraCategory {
    /// Port enumeration.
    PortScan,
    /// Service version detection.
    Fingerprint,
    /// CVE correlation.
    CveMatch,
    /// TLS beyond HTTPS.
    TlsInfra,
    /// DNS infrastructure checks.
    Dns,
    /// Cloud-posture compatibility category.
    Cloud,
}

impl std::fmt::Display for InfraCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PortScan => formatter.write_str("portscan"),
            Self::Fingerprint => formatter.write_str("fingerprint"),
            Self::CveMatch => formatter.write_str("cvematch"),
            Self::TlsInfra => formatter.write_str("tlsinfra"),
            Self::Dns => formatter.write_str("dns"),
            Self::Cloud => formatter.write_str("cloud"),
        }
    }
}

/// Immutable metadata exposed by one infrastructure module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct InfraModuleDescriptor<'a> {
    /// Common versioned scanner-adapter contract.
    pub adapter: AdapterContractV1<'a>,
    /// Human-readable module name.
    pub name: &'a str,
    /// Stable registry identifier.
    pub id: &'a str,
    /// Module family category.
    pub category: InfraCategory,
    /// Human-readable behavior description.
    pub description: &'a str,
    /// Protocols probed; an empty slice means protocol-agnostic.
    pub protocols: &'a [&'a str],
    /// Whether execution requires a local external process.
    pub requires_external_tool: bool,
    /// Required executable name when applicable.
    pub required_tool: Option<&'a str>,
}
