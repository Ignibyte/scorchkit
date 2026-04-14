//! Built-in infrastructure scanning modules.
//!
//! Parallel to [`crate::recon`] / [`crate::scanner`] / [`crate::tools`] for
//! DAST and [`crate::sast`] / [`crate::sast_tools`] for SAST. Every module
//! here implements [`crate::engine::infra_module::InfraModule`].

pub mod cve_match;
pub mod cve_mock;
pub mod nmap;
pub mod tcp_probe;

use crate::engine::infra_module::InfraModule;

/// Register every built-in infra module for the
/// [`crate::runner::infra_orchestrator::InfraOrchestrator`].
///
/// Note: [`cve_match::CveMatchModule`] is intentionally NOT in this list —
/// it requires a construction-time [`crate::engine::cve::CveLookup`]
/// injection. Build it manually and add to an `InfraOrchestrator` when
/// CVE correlation is desired. WORK-105's unified `assess` command will
/// wire the right lookup from config.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn InfraModule>> {
    vec![Box::new(tcp_probe::TcpProbeModule::default()), Box::new(nmap::NmapModule)]
}
