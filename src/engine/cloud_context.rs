//! Shared context passed to every cloud-posture module.
//!
//! Parallel to [`super::scan_context::ScanContext`] (DAST),
//! [`super::code_context::CodeContext`] (SAST), and
//! [`super::infra_context::InfraContext`] (infra). Carries the cloud
//! target, app configuration, resolved credentials, inter-module
//! shared data, and the event bus.
//!
//! ## Architectural departure: no arbitrary `http_client`
//!
//! Unlike [`super::infra_context::InfraContext`], [`CloudContext`]
//! deliberately **does not carry a `reqwest::Client`**. Cloud modules
//! currently interact through policy-authorized tool-wrapper subprocesses.
//! Provider SDK modules remain outside the production registry until their
//! authentication and service transports use an engagement-bound resolver.
//! A future module that needs HTTP must receive a policy-owned transport from
//! this context; it must not construct a client locally.

use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use crate::runner::subprocess::{SystemToolExecutor, ToolExecutor, ToolInvocation, ToolOutput};

use super::cloud_credentials::CloudCredentials;
use super::cloud_target::CloudTarget;
use super::error::Result;
use super::events::EventBus;
use super::policy::AuthorizationDecision;
use super::policy::{Capability, EffectClass, PolicyTarget};
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
    /// External-process boundary used by tool-backed cloud modules.
    tool_executor: Arc<dyn ToolExecutor>,
    /// Opaque proof that the context was created by the policy-gated engine.
    authorization: Vec<AuthorizationDecision>,
}

impl CloudContext {
    /// Create a new cloud context with an empty shared data store, a
    /// default-capacity event bus, and credentials resolved from
    /// [`AppConfig::cloud`] + env-var overrides.
    ///
    /// Returns `credentials: None` when the resolved credentials are
    /// fully empty.
    #[must_use]
    pub(crate) fn new(
        target: CloudTarget,
        config: Arc<AppConfig>,
        authorization: Vec<AuthorizationDecision>,
    ) -> Self {
        let resolved = CloudCredentials::from_config_with_env(&config.cloud);
        let credentials = if resolved.is_empty() { None } else { Some(Arc::new(resolved)) };
        Self {
            target,
            config,
            shared_data: Arc::new(SharedData::new()),
            events: EventBus::default(),
            credentials,
            tool_executor: Arc::new(SystemToolExecutor),
            authorization,
        }
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
        self.require_tool_authorization(tool_name)?;
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
        self.require_tool_authorization(tool_name)?;
        self.tool_executor.execute(ToolInvocation::lenient(tool_name, args, timeout)).await
    }

    fn require_tool_authorization(&self, tool_name: &str) -> Result<()> {
        if cfg!(test) && self.authorization.is_empty() {
            return Ok(());
        }
        let effect = if tool_name == "pacu" { EffectClass::Exploit } else { EffectClass::Passive };
        self.require_grant(Capability::ExternalTool, effect)?;
        if tool_name == "pacu" {
            self.require_grant(Capability::Exploit, EffectClass::Exploit)?;
        } else {
            self.require_grant(Capability::CredentialUse, EffectClass::Passive)?;
        }
        Ok(())
    }

    fn require_grant(&self, capability: Capability, effect: EffectClass) -> Result<()> {
        let target = PolicyTarget::cloud(self.target.display_raw());
        if self.authorization.iter().any(|decision| {
            super::policy::decision_grants_exactly(decision, &target, capability, effect)
        }) {
            return Ok(());
        }
        Err(crate::engine::error::ScorchError::Config(format!(
            "cloud tool denied: context has no {capability:?}/{effect:?} grant for {target}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::policy::{AuthorizationDecision, DenialReason};
    use uuid::Uuid;

    fn grant(
        target: &PolicyTarget,
        capability: Capability,
        effect: EffectClass,
    ) -> AuthorizationDecision {
        AuthorizationDecision {
            engagement_id: Uuid::nil(),
            target: target.clone(),
            capability,
            effect,
            allowed: true,
            matched_scope: None,
            denial: None,
        }
    }

    /// Constructor produces a context with fresh `EventBus` and
    /// `SharedData`; default `AppConfig` yields `credentials: None`
    /// (safe-by-default, unauthenticated unless opted in).
    #[test]
    fn test_cloud_context_defaults() {
        let target = CloudTarget::All;
        let config = Arc::new(AppConfig::default());
        let ctx = CloudContext::new(target, config, Vec::new());
        // EventBus::default() capacity is 256; at minimum we can subscribe.
        let _rx = ctx.events.subscribe();
        // SharedData starts empty.
        assert!(!ctx.shared_data.has("anything"));
        // Default config has no cloud credentials → None.
        assert!(ctx.credentials.is_none());
    }

    #[test]
    fn cloud_tools_require_exact_credential_or_exploit_grants() {
        let target = CloudTarget::Project("fixture".to_string());
        let policy_target = PolicyTarget::cloud(target.display_raw());
        let normal = CloudContext::new(
            target.clone(),
            Arc::new(AppConfig::default()),
            vec![
                grant(&policy_target, Capability::ExternalTool, EffectClass::Passive),
                grant(&policy_target, Capability::CredentialUse, EffectClass::Passive),
            ],
        );
        assert!(normal.require_tool_authorization("prowler").is_ok());

        let exploit = CloudContext::new(
            target.clone(),
            Arc::new(AppConfig::default()),
            vec![
                grant(&policy_target, Capability::ExternalTool, EffectClass::Exploit),
                grant(&policy_target, Capability::Exploit, EffectClass::Exploit),
            ],
        );
        assert!(exploit.require_tool_authorization("pacu").is_ok());

        let denied = CloudContext::new(
            target,
            Arc::new(AppConfig::default()),
            vec![AuthorizationDecision {
                engagement_id: Uuid::nil(),
                target: policy_target,
                capability: Capability::ExternalTool,
                effect: EffectClass::Passive,
                allowed: false,
                matched_scope: None,
                denial: Some(DenialReason::CapabilityNotGranted),
            }],
        );
        assert!(denied.require_tool_authorization("prowler").is_err());
    }
}
