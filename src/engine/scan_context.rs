use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use crate::runner::subprocess::{SystemToolExecutor, ToolExecutor, ToolInvocation, ToolOutput};

use super::error::Result;
use super::events::EventBus;
use super::policy::AuthorizationDecision;
use super::policy::{AuthorizationDecision as PolicyAuthorizationDecision, Engagement};
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
    /// Active policy authorizer for adapter inputs discovered after context construction.
    engagement: Option<Arc<Engagement>>,
    /// Engagement-bound resolver and connector for native network probes.
    network_policy: PolicyNetwork,
}

impl ScanContext {
    /// Build the proposal ceiling from the exact grants already sealed into this context.
    pub(crate) fn run_pipeline_authority<I, S>(
        &self,
        modules: I,
    ) -> scorchkit_core::run_pipeline::RunAuthority
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let target = PolicyTarget::Web(self.target.url.clone());
        let mut capabilities: BTreeSet<_> = self
            .authorization
            .iter()
            .filter(|decision| decision.allowed && decision.target == target)
            .map(|decision| decision.capability)
            .collect();
        if cfg!(test) && capabilities.is_empty() {
            capabilities.extend([Capability::DastScan, Capability::ExternalTool]);
        }
        let max_effect = self
            .authorization
            .iter()
            .filter(|decision| {
                decision.allowed
                    && decision.target == target
                    && decision.capability == Capability::DastScan
            })
            .map(|decision| decision.effect)
            .max()
            .unwrap_or(EffectClass::ActiveSafe);
        scorchkit_core::run_pipeline::RunAuthority {
            target,
            modules: modules.into_iter().map(Into::into).collect(),
            credential_use: capabilities.contains(&Capability::CredentialUse),
            capabilities,
            max_effect,
        }
    }

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
            None,
        )
    }

    pub(crate) fn with_http_clients(
        target: Target,
        config: Arc<AppConfig>,
        http_client: reqwest::Client,
        no_redirect_http_client: reqwest::Client,
        authorization: Vec<AuthorizationDecision>,
        network_policy: PolicyNetwork,
        engagement: Option<Arc<Engagement>>,
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
            engagement,
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

    /// Resolve a target under one adapter's exact declared effect.
    pub(crate) async fn resolve_network_target_for_effect(
        &self,
        host: &str,
        port: u16,
        budget: Duration,
        effect: EffectClass,
    ) -> Result<Vec<std::net::SocketAddr>> {
        let engagement = self.engagement.as_ref().ok_or_else(|| {
            crate::engine::error::ScorchError::Config(
                "adapter target resolution denied: no active engagement authorizer".to_string(),
            )
        })?;
        PolicyNetwork::new(Arc::clone(engagement), Capability::DastScan, effect)
            .resolve(host, port, budget)
            .await
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

    /// Execute an authorized lifecycle processor with an exact stream ceiling.
    pub(crate) async fn run_tool_with_stdin_limit(
        &self,
        tool_name: &str,
        stdin: &[u8],
        timeout: Duration,
        output_limit_bytes: usize,
    ) -> Result<ToolOutput> {
        self.require_tool_authorization(tool_name)?;
        self.tool_executor
            .execute(
                ToolInvocation::strict(tool_name, &[], timeout)
                    .with_stdin(stdin)
                    .with_output_limit(output_limit_bytes),
            )
            .await
    }

    /// Execute one fully owned DAST invocation after applying the context's exact tool grant.
    pub(crate) async fn run_invocation(&self, invocation: ToolInvocation) -> Result<ToolOutput> {
        self.require_tool_authorization(&invocation.program)?;
        self.tool_executor.execute(invocation).await
    }

    /// Execute one fully owned invocation under an adapter's exact strongest effect.
    pub(crate) async fn run_invocation_for_effect(
        &self,
        invocation: ToolInvocation,
        effect: EffectClass,
    ) -> Result<ToolOutput> {
        self.require_adapter_authorization(effect)?;
        self.events.publish(crate::engine::events::ScanEvent::Custom {
            kind: "effect.subprocess_started".to_string(),
            data: serde_json::json!({
                "target": self.target.url,
                "program": crate::engine::observation::redact_text(&invocation.program),
                "capability": "external-tool",
                "effect": effect,
            }),
        });
        self.tool_executor.execute(invocation).await
    }

    /// Authorize one canonical local adapter input before reading it.
    pub(crate) fn authorize_local_state(
        &self,
        canonical_path: &std::path::Path,
    ) -> Result<PolicyAuthorizationDecision> {
        let engagement = self.engagement.as_ref().ok_or_else(|| {
            crate::engine::error::ScorchError::Config(
                "adapter local state denied: no active engagement authorizer".to_string(),
            )
        })?;
        let target = PolicyTarget::Code(canonical_path.to_path_buf());
        let decision = engagement
            .authorize(target.clone(), Capability::LocalState, EffectClass::Passive)
            .require()?;
        self.events.publish(crate::engine::events::ScanEvent::Custom {
            kind: "effect.local_state_authorized".to_string(),
            data: serde_json::json!({
                "target": target,
                "capability": "local-state",
                "effect": "passive",
            }),
        });
        Ok(decision)
    }

    /// Authorize one canonical extension manifest or module before opening it.
    pub(crate) fn authorize_extension_input(&self, canonical_path: &std::path::Path) -> Result<()> {
        let engagement = self.engagement.as_ref().ok_or_else(|| {
            crate::engine::error::ScorchError::Config(
                "extension input denied: no active engagement authorizer".to_string(),
            )
        })?;
        let target = PolicyTarget::Code(canonical_path.to_path_buf());
        engagement
            .authorize(target.clone(), Capability::LocalState, EffectClass::Passive)
            .require()?;
        engagement
            .authorize(target.clone(), Capability::ExtensionExecute, EffectClass::Passive)
            .require()?;
        self.events.publish(crate::engine::events::ScanEvent::Custom {
            kind: "extension.input_authorized".to_string(),
            data: serde_json::json!({
                "target": target,
                "capabilities": ["local-state", "extension-execute"],
                "effect": "passive",
            }),
        });
        Ok(())
    }

    /// Prove the complete grant set before an isolated worker is spawned.
    pub(crate) fn authorize_extension_execution(&self, effect: EffectClass) -> Result<()> {
        self.require_adapter_grant(Capability::DastScan, effect)?;
        self.require_adapter_grant(Capability::ExternalTool, effect)?;
        self.require_adapter_grant(Capability::ExtensionExecute, effect)?;
        self.events.publish(crate::engine::events::ScanEvent::Custom {
            kind: "extension.execution_authorized".to_string(),
            data: serde_json::json!({
                "target": self.target.url,
                "capabilities": ["dast-scan", "external-tool", "extension-execute"],
                "effect": effect,
            }),
        });
        Ok(())
    }

    /// Reauthorize an exact guest-proposed web target before a brokered effect or finding commit.
    pub(crate) fn authorize_extension_target(
        &self,
        target: &url::Url,
        effect: EffectClass,
    ) -> Result<()> {
        let policy_target = PolicyTarget::Web(target.clone());
        if let Some(engagement) = &self.engagement {
            engagement.authorize(policy_target.clone(), Capability::DastScan, effect).require()?;
            engagement.authorize(policy_target, Capability::ExtensionExecute, effect).require()?;
            return Ok(());
        }
        if target == &self.target.url {
            self.require_grant(Capability::DastScan, effect)?;
            self.require_grant(Capability::ExtensionExecute, effect)?;
            return Ok(());
        }
        Err(crate::engine::error::ScorchError::Config(
            "extension target denied: no active engagement authorizer".to_string(),
        ))
    }

    /// Build a credential-free, no-redirect client bound to an extension's exact effect.
    pub(crate) fn extension_http_client(
        &self,
        endpoint: &url::Url,
        effect: EffectClass,
    ) -> Result<reqwest::Client> {
        let engagement = self.engagement.as_ref().ok_or_else(|| {
            crate::engine::error::ScorchError::Config(
                "extension HTTP denied: no active engagement authorizer".to_string(),
            )
        })?;
        crate::engine::policy_http::build_service_client(
            Arc::clone(engagement),
            endpoint,
            Capability::DastScan,
            effect,
            &self.config.scan.user_agent,
            Duration::from_secs(self.config.scan.timeout_seconds),
            crate::engine::policy_http::RedirectMode::None,
        )
    }

    pub(crate) fn require_tool_authorization(&self, tool_name: &str) -> Result<()> {
        if cfg!(test) && self.authorization.is_empty() {
            return Ok(());
        }

        let special_effect = crate::adapter_catalog::external_web_tool_effect(tool_name);
        let effect = if let Some(effect) = special_effect {
            effect
        } else {
            self.authorization
                .iter()
                .find(|decision| decision.capability == Capability::DastScan)
                .map(|decision| decision.effect)
                .ok_or_else(|| {
                    crate::engine::error::ScorchError::Config(
                        "external tool denied: DAST context has no primary authorization"
                            .to_string(),
                    )
                })?
        };
        let additional_capability = match special_effect {
            Some(EffectClass::CredentialTest) => Some(Capability::CredentialUse),
            Some(EffectClass::Exploit) => Some(Capability::Exploit),
            _ => None,
        };

        self.require_grant(Capability::ExternalTool, effect)?;
        if crate::adapter_catalog::external_web_tool_uses_ambient_credentials(tool_name) {
            self.require_grant(Capability::CredentialUse, EffectClass::Passive)?;
        }
        if let Some(capability) = additional_capability {
            self.require_grant(capability, effect)?;
        }
        Ok(())
    }

    fn require_adapter_authorization(&self, effect: EffectClass) -> Result<()> {
        self.require_adapter_grant(Capability::DastScan, effect)?;
        self.require_adapter_grant(Capability::ExternalTool, effect)?;
        match effect {
            EffectClass::CredentialTest => {
                self.require_adapter_grant(Capability::CredentialUse, effect)?;
            }
            EffectClass::Exploit => {
                self.require_adapter_grant(Capability::Exploit, effect)?;
            }
            EffectClass::Passive | EffectClass::ActiveSafe | EffectClass::Intrusive => {}
        }
        Ok(())
    }

    /// Prove an adapter's complete target/process/capability grant set before effects begin.
    pub(crate) fn authorize_adapter_effect(&self, effect: EffectClass) -> Result<()> {
        self.require_adapter_authorization(effect)?;
        self.events.publish(crate::engine::events::ScanEvent::Custom {
            kind: "effect.adapter_authorized".to_string(),
            data: serde_json::json!({
                "target": self.target.url,
                "capabilities": ["dast-scan", "external-tool"],
                "effect": effect,
            }),
        });
        Ok(())
    }

    fn require_adapter_grant(&self, capability: Capability, effect: EffectClass) -> Result<()> {
        if let Some(engagement) = &self.engagement {
            engagement
                .authorize(PolicyTarget::Web(self.target.url.clone()), capability, effect)
                .require()?;
            return Ok(());
        }
        self.require_grant(capability, effect)
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
    use crate::engine::policy::{AuthorizationDecision, DenialReason, EngagementPolicy};
    use crate::engine::scope::ScopeRule;
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
        for tool in ["hydra", "kerbrute", "nxc", "onesixtyone", "smbmap"] {
            assert!(credential.require_tool_authorization(tool).is_ok());
        }

        let missing_credential = context(
            target.clone(),
            vec![decision(&target, Capability::ExternalTool, EffectClass::CredentialTest)],
        );
        assert!(missing_credential.require_tool_authorization("hydra").is_err());

        assert!(normal.require_tool_authorization("prowler").is_ok());
        let missing_passive_credential = context(
            target.clone(),
            vec![
                decision(&target, Capability::DastScan, EffectClass::Intrusive),
                decision(&target, Capability::ExternalTool, EffectClass::Intrusive),
            ],
        );
        assert!(missing_passive_credential.require_tool_authorization("prowler").is_err());

        let exploit = context(
            target.clone(),
            vec![
                decision(&target, Capability::ExternalTool, EffectClass::Exploit),
                decision(&target, Capability::Exploit, EffectClass::Exploit),
            ],
        );
        for tool in ["commix", "msfconsole"] {
            assert!(exploit.require_tool_authorization(tool).is_ok());
        }
        let missing_exploit_capability = context(
            target.clone(),
            vec![decision(&target, Capability::ExternalTool, EffectClass::Exploit)],
        );
        for tool in ["commix", "msfconsole"] {
            assert!(missing_exploit_capability.require_tool_authorization(tool).is_err());
        }

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

    #[test]
    fn dynamic_adapter_authorization_requires_the_exact_discovered_effect_and_capabilities() {
        let target = Target::parse("https://example.com").expect("target");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.com").expect("scope"))
            .allow_capability(Capability::DastScan)
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::ActiveSafe);
        let engagement = Arc::new(Engagement::new("adapter", policy));
        let context = ScanContext::with_http_clients(
            target,
            Arc::new(AppConfig::default()),
            reqwest::Client::new(),
            reqwest::Client::new(),
            Vec::new(),
            PolicyNetwork::new(
                Arc::clone(&engagement),
                Capability::DastScan,
                EffectClass::ActiveSafe,
            ),
            Some(engagement),
        );

        assert!(context.authorize_adapter_effect(EffectClass::ActiveSafe).is_ok());
        assert!(context.authorize_adapter_effect(EffectClass::Intrusive).is_err());
        assert!(context.authorize_adapter_effect(EffectClass::CredentialTest).is_err());
    }

    #[test]
    fn adapter_local_state_requires_an_explicit_canonical_path_grant() {
        let root = tempfile::tempdir().expect("local state");
        let file = root.path().join("manifest.json");
        std::fs::write(&file, b"{}").expect("manifest");
        let target = Target::parse("https://example.com").expect("target");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.com").expect("web scope"))
            .allow_scope(ScopeRule::path_prefix(root.path()).expect("path scope"))
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::Passive);
        let engagement = Arc::new(Engagement::new("local adapter state", policy));
        let context = ScanContext::with_http_clients(
            target,
            Arc::new(AppConfig::default()),
            reqwest::Client::new(),
            reqwest::Client::new(),
            Vec::new(),
            PolicyNetwork::new(
                Arc::clone(&engagement),
                Capability::DastScan,
                EffectClass::ActiveSafe,
            ),
            Some(engagement),
        );

        assert!(context.authorize_local_state(&file.canonicalize().expect("canonical")).is_ok());
        let outside = tempfile::NamedTempFile::new().expect("outside");
        assert!(context.authorize_local_state(&outside.path().canonicalize().unwrap()).is_err());
    }

    #[test]
    fn extension_execution_requires_all_three_exact_capability_grants() {
        let target = Target::parse("https://example.com").expect("target");
        let grants = [Capability::DastScan, Capability::ExternalTool, Capability::ExtensionExecute];
        let authorized = context(
            target.clone(),
            grants
                .into_iter()
                .map(|capability| decision(&target, capability, EffectClass::ActiveSafe))
                .collect(),
        );
        assert!(authorized.authorize_extension_execution(EffectClass::ActiveSafe).is_ok());

        for omitted in grants {
            let denied = context(
                target.clone(),
                grants
                    .into_iter()
                    .filter(|capability| *capability != omitted)
                    .map(|capability| decision(&target, capability, EffectClass::ActiveSafe))
                    .collect(),
            );
            assert!(
                denied.authorize_extension_execution(EffectClass::ActiveSafe).is_err(),
                "missing {omitted:?} must deny execution"
            );
        }
    }

    #[test]
    fn extension_target_without_an_engagement_must_match_the_context_target() {
        let target = Target::parse("https://example.com").expect("target");
        let grants = vec![
            decision(&target, Capability::DastScan, EffectClass::ActiveSafe),
            decision(&target, Capability::ExtensionExecute, EffectClass::ActiveSafe),
        ];
        let context = context(target.clone(), grants);
        assert!(context.authorize_extension_target(&target.url, EffectClass::ActiveSafe).is_ok());
        let other = url::Url::parse("https://outside.example/").expect("other target");
        assert!(context.authorize_extension_target(&other, EffectClass::ActiveSafe).is_err());
    }

    #[test]
    fn extension_http_client_requires_an_active_engagement_authorizer() {
        let target = Target::parse("https://example.com").expect("target");
        let context = context(target.clone(), Vec::new());
        assert!(context.extension_http_client(&target.url, EffectClass::ActiveSafe).is_err());
    }

    #[test]
    fn pipeline_authority_uses_only_allowed_exact_target_dast_grants() {
        let target = Target::parse("https://example.com").expect("target");
        let other = Target::parse("https://outside.test").expect("other target");
        let mut decisions = vec![
            decision(&target, Capability::DastScan, EffectClass::ActiveSafe),
            decision(&target, Capability::ExternalTool, EffectClass::Intrusive),
            decision(&other, Capability::DastScan, EffectClass::Exploit),
            decision(&target, Capability::ExternalTool, EffectClass::Exploit),
        ];
        decisions.push(AuthorizationDecision {
            engagement_id: Uuid::nil(),
            target: PolicyTarget::Web(target.url.clone()),
            capability: Capability::CredentialUse,
            effect: EffectClass::Exploit,
            allowed: false,
            matched_scope: None,
            denial: Some(DenialReason::CapabilityNotGranted),
        });
        decisions.push(AuthorizationDecision {
            engagement_id: Uuid::nil(),
            target: PolicyTarget::Web(target.url.clone()),
            capability: Capability::DastScan,
            effect: EffectClass::Exploit,
            allowed: false,
            matched_scope: None,
            denial: Some(DenialReason::CapabilityNotGranted),
        });
        let authorized = context(target.clone(), decisions);

        let authority = authorized.run_pipeline_authority(["headers"]);

        assert_eq!(authority.capabilities, [Capability::DastScan, Capability::ExternalTool].into());
        assert!(!authority.credential_use);
        assert_eq!(authority.max_effect, EffectClass::ActiveSafe);
        assert_eq!(authority.modules, ["headers".to_string()].into());

        let credential_only = context(
            target.clone(),
            vec![decision(&target, Capability::CredentialUse, EffectClass::CredentialTest)],
        );
        let authority = credential_only.run_pipeline_authority(["headers"]);
        assert_eq!(authority.capabilities, [Capability::CredentialUse].into());
        assert!(authority.credential_use);
    }
}
