//! Shared context passed to every infra module.
//!
//! Parallel to [`super::scan_context::ScanContext`] (DAST) and
//! [`super::code_context::CodeContext`] (SAST). Carries the target, app
//! configuration, inter-module
//! shared data, and the event bus.
//!
//! Network credentials live on [`InfraContext::credentials`] (WORK-146);
//! tool wrappers and native infra probes read them from the config via
//! [`crate::engine::network_credentials::NetworkCredentials::from_config_with_env`].

use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use crate::runner::subprocess::{SystemToolExecutor, ToolExecutor, ToolInvocation, ToolOutput};

use super::error::Result;
use super::events::EventBus;
use super::infra_target::InfraTarget;
use super::network_credentials::NetworkCredentials;
use super::policy::{AuthorizationDecision, Capability, EffectClass, PolicyTarget};
use super::policy_network::PolicyNetwork;
use super::shared_data::SharedData;

/// Shared context passed to every [`super::infra_module::InfraModule`].
#[derive(Clone, Debug)]
pub struct InfraContext {
    /// The target of the infra scan.
    pub target: InfraTarget,
    /// Application configuration.
    pub config: Arc<AppConfig>,
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
    /// External-process boundary used by tool-backed infrastructure modules.
    tool_executor: Arc<dyn ToolExecutor>,
    /// Opaque proof that the context was created by the policy-gated engine.
    authorization: Vec<AuthorizationDecision>,
    /// Engagement-bound resolver and connector for native network probes.
    network_policy: PolicyNetwork,
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
    pub(crate) fn authorized(
        target: InfraTarget,
        config: Arc<AppConfig>,
        authorization: Vec<AuthorizationDecision>,
        network_policy: PolicyNetwork,
    ) -> Self {
        let resolved = NetworkCredentials::from_config_with_env(&config.network_credentials);
        let credentials = if resolved.is_empty() { None } else { Some(Arc::new(resolved)) };
        Self {
            target,
            config,
            shared_data: Arc::new(SharedData::new()),
            events: EventBus::default(),
            credentials,
            tool_executor: Arc::new(SystemToolExecutor),
            authorization,
            network_policy,
        }
    }

    #[cfg(test)]
    pub(crate) fn new(
        target: InfraTarget,
        config: Arc<AppConfig>,
        authorization: Vec<AuthorizationDecision>,
    ) -> Self {
        let network_policy = PolicyNetwork::for_test_target(
            &target.display_raw(),
            Capability::InfraScan,
            EffectClass::ActiveSafe,
        );
        Self::authorized(target, config, authorization, network_policy)
    }

    /// Authorize a native hostname or address without creating a resource.
    pub(crate) fn authorize_network_target(&self, target: &str) -> Result<()> {
        self.network_policy.authorize(target)
    }

    /// Return the policy owner used by shared native resolver and TLS helpers.
    pub(crate) const fn network_policy(&self) -> &PolicyNetwork {
        &self.network_policy
    }

    /// Replace the production process executor, primarily for contract tests.
    #[must_use]
    pub fn with_tool_executor(mut self, tool_executor: Arc<dyn ToolExecutor>) -> Self {
        self.tool_executor = tool_executor;
        self
    }

    /// Execute an external tool and require a successful exit status.
    ///
    /// # Errors
    ///
    /// Returns a policy, resolution, spawn, timeout, output-limit, or exit-status error.
    pub async fn run_tool(
        &self,
        tool_name: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<ToolOutput> {
        self.require_tool_authorization()?;
        self.tool_executor.execute(ToolInvocation::strict(tool_name, args, timeout)).await
    }

    /// Execute an external tool while accepting normal non-zero finding exits.
    ///
    /// # Errors
    ///
    /// Returns a policy, resolution, spawn, timeout, or output-limit error.
    pub async fn run_tool_lenient(
        &self,
        tool_name: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<ToolOutput> {
        self.require_tool_authorization()?;
        self.tool_executor.execute(ToolInvocation::lenient(tool_name, args, timeout)).await
    }

    fn require_tool_authorization(&self) -> Result<()> {
        if cfg!(test) && self.authorization.is_empty() {
            return Ok(());
        }
        let target = PolicyTarget::network(self.target.display_raw());
        if self.authorization.iter().any(|decision| {
            decision.grants_exactly(&target, Capability::ExternalTool, EffectClass::ActiveSafe)
        }) {
            return Ok(());
        }
        Err(crate::engine::error::ScorchError::Config(format!(
            "infrastructure tool denied: context has no ExternalTool/ActiveSafe grant for {target}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::policy::{AuthorizationDecision, DenialReason};
    use std::net::{IpAddr, Ipv4Addr};
    use uuid::Uuid;

    /// Constructor produces a context with fresh `EventBus` and `SharedData`.
    #[test]
    fn test_infra_context_defaults() {
        let target = InfraTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let config = Arc::new(AppConfig::default());
        let ctx = InfraContext::new(target, config, Vec::new());
        // EventBus::default() capacity is 256; at minimum we can subscribe.
        let _rx = ctx.events.subscribe();
        // SharedData starts empty — no keys published yet.
        assert!(!ctx.shared_data.has("anything"));
    }

    /// Default `AppConfig` has no credentials → `InfraContext::credentials` is `None`.
    /// Pins the safe-by-default contract: unauthenticated unless opted in.
    #[test]
    fn infra_context_credentials_default_none() {
        let target = InfraTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let config = Arc::new(AppConfig::default());
        let ctx = InfraContext::new(target, config, Vec::new());
        assert!(ctx.credentials.is_none());
    }

    #[test]
    fn infrastructure_tool_and_native_target_authorization_fail_closed() {
        let target = InfraTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let policy_target = PolicyTarget::network(target.display_raw());
        let grant = AuthorizationDecision {
            engagement_id: Uuid::nil(),
            target: policy_target.clone(),
            capability: Capability::ExternalTool,
            effect: EffectClass::ActiveSafe,
            allowed: true,
            matched_scope: None,
            denial: None,
        };
        let allowed =
            InfraContext::new(target.clone(), Arc::new(AppConfig::default()), vec![grant]);
        assert!(allowed.require_tool_authorization().is_ok());
        assert!(allowed.authorize_network_target("203.0.113.1").is_err());

        let denied = InfraContext::new(
            target,
            Arc::new(AppConfig::default()),
            vec![AuthorizationDecision {
                engagement_id: Uuid::nil(),
                target: policy_target,
                capability: Capability::InfraScan,
                effect: EffectClass::ActiveSafe,
                allowed: false,
                matched_scope: None,
                denial: Some(DenialReason::CapabilityNotGranted),
            }],
        );
        assert!(denied.require_tool_authorization().is_err());
    }
}
