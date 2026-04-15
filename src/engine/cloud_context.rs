//! Shared context passed to every cloud-posture module.
//!
//! Parallel to [`super::scan_context::ScanContext`] (DAST),
//! [`super::code_context::CodeContext`] (SAST), and
//! [`super::infra_context::InfraContext`] (infra). Carries the cloud
//! target, app configuration, resolved credentials, inter-module
//! shared data, and the event bus.
//!
//! ## Architectural departure: no `http_client`
//!
//! Unlike [`super::infra_context::InfraContext`], [`CloudContext`]
//! deliberately **does not carry a `reqwest::Client`**. Cloud modules
//! interact with cloud APIs via provider SDKs (which manage their own
//! HTTP clients with appropriate auth signing) or via tool-wrapper
//! subprocesses (Prowler, Scoutsuite, Kubescape) — never through an
//! arbitrary `reqwest::Client`. Future modules that genuinely need
//! HTTP (e.g., metadata-endpoint probes) construct a client locally.

use std::sync::Arc;

use crate::config::AppConfig;

use super::cloud_credentials::CloudCredentials;
use super::cloud_target::CloudTarget;
use super::events::EventBus;
use super::shared_data::SharedData;

/// Shared context passed to every
/// [`super::cloud_module::CloudModule`].
#[derive(Clone, Debug)]
pub struct CloudContext {
    /// The target of the cloud-posture scan.
    pub target: CloudTarget,
    /// Application configuration.
    pub config: Arc<AppConfig>,
    /// Shared data store for inter-module communication. Mirrors the
    /// pattern from [`super::infra_context::InfraContext`] — a cloud
    /// module may publish enumerated resources (e.g., list of public
    /// S3 buckets) for downstream modules to consume.
    pub shared_data: Arc<SharedData>,
    /// In-process event bus for scan lifecycle events.
    pub events: EventBus,
    /// Cloud credentials resolved from [`AppConfig::cloud`] + env
    /// overrides at context construction time. `None` when the
    /// resolved credentials are fully empty (no field set in config
    /// and no env override present) so downstream code can
    /// short-circuit with a single `is_none()` check.
    pub credentials: Option<Arc<CloudCredentials>>,
}

impl CloudContext {
    /// Create a new cloud context with an empty shared data store, a
    /// default-capacity event bus, and credentials resolved from
    /// [`AppConfig::cloud`] + env-var overrides.
    ///
    /// Returns `credentials: None` when the resolved credentials are
    /// fully empty.
    #[must_use]
    pub fn new(target: CloudTarget, config: Arc<AppConfig>) -> Self {
        let resolved = CloudCredentials::from_config_with_env(&config.cloud);
        let credentials = if resolved.is_empty() { None } else { Some(Arc::new(resolved)) };
        Self {
            target,
            config,
            shared_data: Arc::new(SharedData::new()),
            events: EventBus::default(),
            credentials,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructor produces a context with fresh `EventBus` and
    /// `SharedData`; default `AppConfig` yields `credentials: None`
    /// (safe-by-default, unauthenticated unless opted in).
    #[test]
    fn test_cloud_context_defaults() {
        let target = CloudTarget::All;
        let config = Arc::new(AppConfig::default());
        let ctx = CloudContext::new(target, config);
        // EventBus::default() capacity is 256; at minimum we can subscribe.
        let _rx = ctx.events.subscribe();
        // SharedData starts empty.
        assert!(!ctx.shared_data.has("anything"));
        // Default config has no cloud credentials → None.
        assert!(ctx.credentials.is_none());
    }
}
