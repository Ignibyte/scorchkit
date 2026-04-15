//! Shared context passed to every infra module.
//!
//! Parallel to [`super::scan_context::ScanContext`] (DAST) and
//! [`super::code_context::CodeContext`] (SAST). Carries the target, app
//! configuration, HTTP client (useful for CVE lookups later), inter-module
//! shared data, and the event bus.
//!
//! Authenticated scanning credentials (`NetworkCredentials`) will be added
//! in WORK-104; they are intentionally absent in this foundation pipeline.

use std::sync::Arc;

use crate::config::AppConfig;

use super::events::EventBus;
use super::infra_target::InfraTarget;
use super::shared_data::SharedData;

/// Shared context passed to every [`super::infra_module::InfraModule`].
#[derive(Clone, Debug)]
pub struct InfraContext {
    /// The target of the infra scan.
    pub target: InfraTarget,
    /// Application configuration.
    pub config: Arc<AppConfig>,
    /// Shared HTTP client — useful for CVE lookups and HTTP-based
    /// infrastructure checks (ingress controllers, health endpoints, etc.).
    pub http_client: reqwest::Client,
    /// Shared data store for inter-module communication.
    ///
    /// Example: a future port-scan module publishes
    /// `Vec<ServiceFingerprint>`; a downstream CVE matcher reads it.
    pub shared_data: Arc<SharedData>,
    /// In-process event bus for scan lifecycle events.
    pub events: EventBus,
}

impl InfraContext {
    /// Create a new infra context with an empty shared data store and a
    /// default-capacity event bus.
    #[must_use]
    pub fn new(target: InfraTarget, config: Arc<AppConfig>, http_client: reqwest::Client) -> Self {
        Self {
            target,
            config,
            http_client,
            shared_data: Arc::new(SharedData::new()),
            events: EventBus::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Constructor produces a context with fresh `EventBus` and `SharedData`.
    #[test]
    fn test_infra_context_defaults() {
        let target = InfraTarget::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let config = Arc::new(AppConfig::default());
        let client = reqwest::Client::builder().build().expect("client");
        let ctx = InfraContext::new(target, config, client);
        // EventBus::default() capacity is 256; at minimum we can subscribe.
        let _rx = ctx.events.subscribe();
        // SharedData starts empty — no keys published yet.
        assert!(!ctx.shared_data.has("anything"));
    }
}
