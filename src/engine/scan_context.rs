use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use crate::runner::subprocess::{SystemToolExecutor, ToolExecutor, ToolInvocation, ToolOutput};

use super::error::Result;
use super::events::EventBus;
use super::policy::AuthorizationDecision;
use super::policy::{Capability, EffectClass, PolicyTarget};
use super::policy_network::PolicyNetwork;
use super::shared_data::SharedData;
use super::target::Target;

/// Shared context passed to every scan module.
#[derive(Clone, Debug)]
pub struct ScanContext {
    /// The target being scanned.
    pub target: Target,
    /// Application configuration.
    pub config: Arc<AppConfig>,
    /// Shared HTTP client (connection pooling, TLS, timeouts).
    pub(crate) http_client: reqwest::Client,
    /// Policy-sealed client used by modules that must inspect redirect responses.
    pub(crate) no_redirect_http_client: reqwest::Client,
    /// Shared data store for inter-module communication.
    ///
    /// Modules publish discovered data (URLs, forms, technologies) and
    /// downstream modules read it. Thread-safe via internal `RwLock`.
    pub shared_data: Arc<SharedData>,
    /// In-process event bus for scan lifecycle events.
    ///
    /// Modules may publish custom events via `ctx.events.publish(...)` in
    /// addition to the lifecycle events emitted by orchestrators.
    pub events: EventBus,
    /// External-process boundary used by tool-backed modules.
    tool_executor: Arc<dyn ToolExecutor>,
    /// Opaque proof that the context was created by the policy-gated engine.
    authorization: Vec<AuthorizationDecision>,
    /// Engagement-bound resolver and connector for native network probes.
    network_policy: PolicyNetwork,
}

impl ScanContext {
    /// Create a new scan context with an empty shared data store and a
    /// default-capacity event bus.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn new(
        target: Target,
        config: Arc<AppConfig>,
        http_client: reqwest::Client,
        authorization: Vec<AuthorizationDecision>,
    ) -> Self {
        let host = target.url.host_str().unwrap_or("localhost");
        let effect = authorization
            .iter()
            .find(|decision| decision.capability == Capability::DastScan)
            .map_or(EffectClass::ActiveSafe, |decision| decision.effect);
        let network_policy = PolicyNetwork::for_test_target(host, Capability::DastScan, effect);
        Self::with_http_clients(
            target,
            config,
            http_client.clone(),
            http_client,
            authorization,
            network_policy,
        )
    }

    pub(crate) fn with_http_clients(
        target: Target,
        config: Arc<AppConfig>,
        http_client: reqwest::Client,
        no_redirect_http_client: reqwest::Client,
        authorization: Vec<AuthorizationDecision>,
        network_policy: PolicyNetwork,
    ) -> Self {
        Self {
            target,
            config,
            http_client,
            no_redirect_http_client,
            shared_data: Arc::new(SharedData::new()),
            events: EventBus::default(),
            tool_executor: Arc::new(SystemToolExecutor),
            authorization,
            network_policy,
        }
    }

    /// Return the policy-bound HTTP client for native and third-party modules.
    ///
    /// The client carries the engagement resolver, redirect policy, configured
    /// authentication, proxy, TLS, cookie, user-agent, and timeout settings.
    /// Modules should not construct a separate client for target traffic.
    #[must_use]
    pub const fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    /// Resolve a native hostname and authorize every returned address.
    pub(crate) async fn resolve_network_target(
        &self,
        host: &str,
        port: u16,
        budget: Duration,
    ) -> Result<Vec<std::net::SocketAddr>> {
        self.network_policy.resolve(host, port, budget).await
    }

    /// Connect a native protocol to one authorized concrete address.
    pub(crate) async fn connect_network_target(
        &self,
        host: &str,
        port: u16,
        budget: Duration,
    ) -> Result<tokio::net::TcpStream> {
        self.network_policy.connect(host, port, budget).await
    }

    /// Return the policy owner used by shared native TLS helpers.
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
    /// Returns executor errors for resolution, spawn, exit, timeout, or output limits.
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
    /// Returns executor errors for resolution, spawn, timeout, or output limits.
    pub async fn run_tool_lenient(
        &self,
        tool_name: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<ToolOutput> {
        self.require_tool_authorization(tool_name)?;
        self.tool_executor.execute(ToolInvocation::lenient(tool_name, args, timeout)).await
    }

    /// Execute an authorized external tool with owned standard input.
    pub(crate) async fn run_tool_with_stdin(
        &self,
        tool_name: &str,
        stdin: &[u8],
        timeout: Duration,
    ) -> Result<ToolOutput> {
        self.require_tool_authorization(tool_name)?;
        self.tool_executor
            .execute(ToolInvocation::strict(tool_name, &[], timeout).with_stdin(stdin))
            .await
    }

    pub(crate) fn require_tool_authorization(&self, tool_name: &str) -> Result<()> {
        if cfg!(test) && self.authorization.is_empty() {
            return Ok(());
        }

        let (effect, additional_capability) = match tool_name {
            "hydra" | "nxc" | "smbmap" => {
                (EffectClass::CredentialTest, Some(Capability::CredentialUse))
            }
            "commix" => (EffectClass::Exploit, Some(Capability::Exploit)),
            _ => {
                let effect = self
                    .authorization
                    .iter()
                    .find(|decision| decision.capability == Capability::DastScan)
                    .map(|decision| decision.effect)
                    .ok_or_else(|| {
                        crate::engine::error::ScorchError::Config(
                            "external tool denied: DAST context has no primary authorization"
                                .to_string(),
                        )
                    })?;
                (effect, None)
            }
        };

        self.require_grant(Capability::ExternalTool, effect)?;
        if let Some(capability) = additional_capability {
            self.require_grant(capability, effect)?;
        }
        Ok(())
    }

    fn require_grant(&self, capability: Capability, effect: EffectClass) -> Result<()> {
        let target = PolicyTarget::Web(self.target.url.clone());
        if self.authorization.iter().any(|decision| {
            super::policy::decision_grants_exactly(decision, &target, capability, effect)
        }) {
            return Ok(());
        }
        Err(crate::engine::error::ScorchError::Config(format!(
            "external tool denied: context has no {capability:?}/{effect:?} grant for {target}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::policy::{AuthorizationDecision, DenialReason};
    use uuid::Uuid;

    fn decision(
        target: &Target,
        capability: Capability,
        effect: EffectClass,
    ) -> AuthorizationDecision {
        AuthorizationDecision {
            engagement_id: Uuid::nil(),
            target: PolicyTarget::Web(target.url.clone()),
            capability,
            effect,
            allowed: true,
            matched_scope: None,
            denial: None,
        }
    }

    fn context(target: Target, authorization: Vec<AuthorizationDecision>) -> ScanContext {
        ScanContext::new(
            target,
            Arc::new(AppConfig::default()),
            reqwest::Client::new(),
            authorization,
        )
    }

    #[test]
    fn tool_authorization_distinguishes_profile_and_restricted_grants() {
        let target = Target::parse("https://example.com").expect("fixture target");

        let normal = context(
            target.clone(),
            vec![
                decision(&target, Capability::CredentialUse, EffectClass::Passive),
                decision(&target, Capability::DastScan, EffectClass::Intrusive),
                decision(&target, Capability::ExternalTool, EffectClass::Intrusive),
            ],
        );
        assert!(normal.require_tool_authorization("nikto").is_ok());

        let missing_external = context(
            target.clone(),
            vec![decision(&target, Capability::DastScan, EffectClass::Intrusive)],
        );
        assert!(missing_external.require_tool_authorization("nikto").is_err());

        let credential = context(
            target.clone(),
            vec![
                decision(&target, Capability::ExternalTool, EffectClass::CredentialTest),
                decision(&target, Capability::CredentialUse, EffectClass::CredentialTest),
            ],
        );
        assert!(credential.require_tool_authorization("hydra").is_ok());

        let missing_credential = context(
            target.clone(),
            vec![decision(&target, Capability::ExternalTool, EffectClass::CredentialTest)],
        );
        assert!(missing_credential.require_tool_authorization("hydra").is_err());

        let exploit = context(
            target.clone(),
            vec![
                decision(&target, Capability::ExternalTool, EffectClass::Exploit),
                decision(&target, Capability::Exploit, EffectClass::Exploit),
            ],
        );
        assert!(exploit.require_tool_authorization("commix").is_ok());

        let wrong_target = Target::parse("https://outside.test").expect("second fixture target");
        let mismatched = context(
            target,
            vec![AuthorizationDecision {
                engagement_id: Uuid::nil(),
                target: PolicyTarget::Web(wrong_target.url),
                capability: Capability::ExternalTool,
                effect: EffectClass::Exploit,
                allowed: false,
                matched_scope: None,
                denial: Some(DenialReason::TargetOutOfScope),
            }],
        );
        assert!(mismatched.require_tool_authorization("commix").is_err());
    }
}
