//! Built-in infrastructure scanning modules.
//!
//! Parallel to [`crate::recon`] / [`crate::scanner`] / [`crate::tools`] for
//! DAST and [`crate::sast`] / [`crate::sast_tools`] for SAST. Every module
//! here implements [`crate::engine::infra_module::InfraModule`].

pub mod nmap;
pub mod tcp_probe;

use crate::engine::infra_module::InfraModule;

/// Register every built-in infra module for the [`crate::runner::infra_orchestrator::InfraOrchestrator`].
#[must_use]
pub fn register_modules() -> Vec<Box<dyn InfraModule>> {
    vec![Box::new(tcp_probe::TcpProbeModule::default()), Box::new(nmap::NmapModule)]
}
