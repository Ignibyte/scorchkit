//! Built-in infrastructure scanning modules.
//!
//! Parallel to [`crate::recon`] / [`crate::scanner`] / [`crate::tools`] for
//! DAST and [`crate::sast`] / [`crate::sast_tools`] for SAST. Every module
//! here implements [`crate::engine::infra_module::InfraModule`].

pub mod cpe_purl;
pub mod cve_cache;
pub mod cve_lookup;
pub mod cve_match;
pub mod cve_mock;
pub mod cve_nvd;
pub mod cve_osv;
pub mod dns_probe;
pub mod nmap;
pub mod tcp_probe;
pub mod tls_probe;

use crate::engine::infra_module::InfraModule;

/// Register every built-in infra module for the
/// [`crate::runner::infra_orchestrator::InfraOrchestrator`].
///
/// Note: [`cve_match::CveMatchModule`] is intentionally NOT in this list —
/// it requires a construction-time [`crate::engine::cve::CveLookup`]
/// injection. [`crate::facade::Engine::infra_scan`] consults
/// [`cve_lookup::build_cve_lookup`] and appends the module when a
/// backend is configured (`[cve] backend = "nvd"` or `"mock"` in
/// `config.toml`). For raw access, build the orchestrator directly
/// and call [`crate::runner::infra_orchestrator::InfraOrchestrator::add_module`].
#[must_use]
pub fn register_modules() -> Vec<Box<dyn InfraModule>> {
    vec![
        Box::new(tcp_probe::TcpProbeModule::default()),
        Box::new(nmap::NmapModule),
        Box::new(tls_probe::TlsInfraModule::default()),
        Box::new(dns_probe::DnsInfraModule),
    ]
}
