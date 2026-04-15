//! Shared context passed to every infra module.
//!
//! Parallel to [`super::scan_context::ScanContext`] (DAST) and
//! [`super::code_context::CodeContext`] (SAST). Carries the target, app
//! configuration, HTTP client (useful for CVE lookups later), inter-module
//! shared data, and the event bus.
//!
//! Network credentials live on [`InfraContext::credentials`] (WORK-146);
//! tool wrappers and native infra probes read them from the config via
//! [`crate::engine::network_credentials::NetworkCredentials::from_config_with_env`].

use std::sync::Arc;

use crate::config::AppConfig;

use super::events::EventBus;
use super::infra_target::InfraTarget;
use super::network_credentials::NetworkCredentials;
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
    /// Authenticated-scanning credentials, resolved from config + env
    /// at context-construction time. `None` when no credentials have
    /// been configured. Future native infra-family modules read this
    /// field; existing tool wrappers (which also see `ScanContext`)
    /// reach the raw config via [`AppConfig::network_credentials`].
    pub credentials: Option<Arc<NetworkCredentials>>,
}

impl InfraContext {
    /// Create a new infra context with an empty shared data store, a
    /// default-capacity event bus, and credentials resolved from
    /// `config.network_credentials` + env-var overrides.
    ///
    /// Returns `credentials: None` when the resolved credentials are
    /// fully empty (no field set in config and no env override
    /// present) so downstream code can short-circuit with a single
    /// `is_none()` check.
    #[must_use]
    pub fn new(target: InfraTarget, config: Arc<AppConfig>, http_client: reqwest::Client) -> Self {
        let resolved = NetworkCredentials::from_config_with_env(&config.network_credentials);
        let credentials = if resolved.is_empty() { None } else { Some(Arc::new(resolved)) };
        Self {
            target,
            config,
            http_client,
            shared_data: Arc::new(SharedData::new()),
            events: EventBus::default(),
            credentials,
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

    /// Default AppConfig has no credentials → `InfraContext::credentials` is `None`.
    /// Pins the safe-by-default contract: unauthenticated unless opted in.
    #[test]
    fn infra_context_credentials_default_none() {
        let target = InfraTarget::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let config = Arc::new(AppConfig::default());
        let client = reqwest::Client::builder().build().expect("client");
        let ctx = InfraContext::new(target, config, client);
        assert!(ctx.credentials.is_none());
    }
}
