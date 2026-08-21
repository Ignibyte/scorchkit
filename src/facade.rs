//! High-level facade for using `ScorchKit` as a library.
//!
//! The [`Engine`] struct provides a simple entry point for running DAST
//! and SAST scans without manually constructing orchestrators, contexts,
//! or HTTP clients.
//!
//! ```no_run
//! use std::sync::Arc;
//! use scorchkit::facade::Engine;
//! use scorchkit::config::AppConfig;
//! use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
//! use scorchkit::engine::scope::ScopeRule;
//!
//! # async fn example() -> scorchkit::engine::error::Result<()> {
//! let config = Arc::new(AppConfig::default());
//! let policy = EngagementPolicy::default()
//!     .allow_scope(ScopeRule::parse("example.com").expect("valid scope"))
//!     .allow_capability(Capability::DastScan)
//!     .allow_capability(Capability::ExternalTool)
//!     .allow_effect(EffectClass::Intrusive);
//! let engine = Engine::for_engagement(config, Arc::new(Engagement::new("example", policy)));
//! let result = engine.scan("https://example.com").await?;
//! println!("Found {} findings", result.findings.len());
//! # Ok(())
//! # }
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use scorchkit_code::SupplyChainProfile;
use scorchkit_core::{ProviderSnapshot, SupplyChainTargetKind};

use crate::application_dast::{
    canonical_schema_path, path_is_under, validate_schema, ApplicationDastOrchestrator,
    ApplicationDastRequest, ResolvedPersona, ResolvedPersonaKind,
};
use crate::config::AppConfig;
use crate::config::{DastPersonaConfig, DastVerificationConfig};
use crate::engine::code_context::CodeContext;
use crate::engine::error::{Result, ScorchError};
use crate::engine::policy::{Capability, EffectClass, Engagement, PolicyTarget};
use crate::engine::policy_http::{bind_builder, RedirectMode};
use crate::engine::policy_network::PolicyNetwork;
use crate::engine::scan_context::ScanContext;
use crate::engine::scan_result::ScanResult;
use crate::engine::target::Target;
use crate::runner::code_orchestrator::CodeOrchestrator;
use crate::runner::orchestrator::Orchestrator;
use crate::supply_chain::{
    authorize_local_target_shape, ProviderRefreshRequest, ProviderRefreshService,
    SupplyChainOrchestrator, SupplyChainRun, SupplyChainRunWorkspace, SupplyChainSnapshotStore,
};

/// High-level scanning engine for library consumers.
///
/// Wraps the DAST [`Orchestrator`] and SAST [`CodeOrchestrator`] with
/// simple methods that handle context setup, module registration, and
/// execution in a single call.
///
/// For fine-grained control over module selection, profiles, or hooks,
/// use [`Orchestrator`] or [`CodeOrchestrator`] directly.
#[derive(Debug, Clone)]
pub struct Engine {
    config: Arc<AppConfig>,
    engagement: Option<Arc<Engagement>>,
}

impl Engine {
    /// Create a new engine with the given configuration.
    #[must_use]
    pub fn new(config: Arc<AppConfig>) -> Self {
        let engagement = config.engagement.clone().map(Arc::new);
        Self { config, engagement }
    }

    /// Create an engine that evaluates every facade scan against one engagement.
    ///
    /// This is the provider-neutral entry point for agents and new integrations.
    /// This constructor is useful when the engagement is managed separately
    /// from serialized application configuration.
    #[must_use]
    pub const fn for_engagement(config: Arc<AppConfig>, engagement: Arc<Engagement>) -> Self {
        Self { config, engagement: Some(engagement) }
    }

    /// Run a DAST scan against a URL target.
    ///
    /// Creates an HTTP client, scan context, and orchestrator, registers all
    /// default modules, and runs the scan. Returns the complete scan result
    /// with findings.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is invalid, the HTTP client cannot be
    /// built, or the scan encounters a fatal error.
    pub async fn scan(&self, url: &str) -> Result<ScanResult> {
        let ctx = self.dast_context(url, "thorough")?;

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile("thorough");
        orchestrator.run(true).await
    }

    /// Run a DAST scan with a specific profile.
    ///
    /// Profiles control which modules run:
    /// - `"quick"` — fast built-in modules only (headers, tech, ssl, misconfig)
    /// - `"standard"` — built-in application modules
    /// - `"thorough"` — application modules except credential-test and exploit effects
    /// - `"pentest"` — all application modules with explicit effect grants
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is invalid or the scan fails.
    pub async fn scan_with_profile(&self, url: &str, profile: &str) -> Result<ScanResult> {
        let ctx = self.dast_context(url, profile)?;

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile(profile);
        orchestrator.run(true).await
    }

    /// Run one isolated, schema-driven OWASP ZAP assessment across explicit personas.
    ///
    /// The complete target, process, credential, and local-schema grant matrix is evaluated before
    /// any secret is resolved, schema is read, workspace is created, or process is launched.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid request, denied effect, invalid schema, missing credential,
    /// or configuration that could extend the authorized target. ZAP execution and artifact
    /// failures are retained as degraded typed coverage in the returned result.
    pub async fn application_dast(&self, request: &ApplicationDastRequest) -> Result<ScanResult> {
        let target = Target::parse(&request.target)?;
        validate_application_dast_target(&target.url)?;
        validate_dast_config(&self.config.dast)?;
        let requested_personas =
            request.personas.len().saturating_add(usize::from(request.include_anonymous));
        if requested_personas > self.config.dast.persona_limit_count {
            return Err(ScorchError::Config(format!(
                "application DAST accepts at most {} personas",
                self.config.dast.persona_limit_count
            )));
        }
        if request.schemas.len() > self.config.dast.schema_limit_count {
            return Err(ScorchError::Config(format!(
                "application DAST accepts at most {} schemas",
                self.config.dast.schema_limit_count
            )));
        }
        let selected = self.selected_dast_personas(request, &target.url)?;
        let canonical_schemas: Vec<_> =
            request.schemas.iter().map(canonical_schema_path).collect::<Result<_>>()?;

        let web_target = PolicyTarget::Web(target.url.clone());
        let mut authorization = vec![
            self.require_authorized(
                web_target.clone(),
                Capability::DastScan,
                EffectClass::Intrusive,
            )?,
            self.require_authorized(
                web_target.clone(),
                Capability::ExternalTool,
                EffectClass::Intrusive,
            )?,
        ];
        for path in &canonical_schemas {
            authorization.push(self.require_authorized(
                PolicyTarget::Code(path.clone()),
                Capability::LocalState,
                EffectClass::Passive,
            )?);
        }
        for _ in selected.iter().filter(|(_, persona)| persona.is_some()) {
            authorization.push(self.require_authorized(
                web_target.clone(),
                Capability::ExternalTool,
                EffectClass::CredentialTest,
            )?);
            authorization.push(self.require_authorized(
                web_target.clone(),
                Capability::CredentialUse,
                EffectClass::CredentialTest,
            )?);
        }

        let schemas = request
            .schemas
            .iter()
            .zip(&canonical_schemas)
            .map(|(schema, path)| {
                validate_schema(schema, path, &target.url, self.config.dast.schema_limit_bytes)
            })
            .collect::<Result<Vec<_>>>()?;
        let personas = selected
            .into_iter()
            .map(|(id, persona)| resolve_dast_persona(id, persona))
            .collect::<Result<Vec<_>>>()?;
        let http_client = self.authorized_http_client(
            Capability::DastScan,
            EffectClass::Intrusive,
            self.config.scan.follow_redirects,
        )?;
        let no_redirect_http_client =
            self.authorized_http_client(Capability::DastScan, EffectClass::Intrusive, false)?;
        let network_policy = self.policy_network(
            Capability::DastScan,
            EffectClass::Intrusive,
            "application DAST native network",
        )?;
        let context = ScanContext::with_http_clients(
            target,
            Arc::clone(&self.config),
            http_client,
            no_redirect_http_client,
            authorization,
            network_policy,
        );
        ApplicationDastOrchestrator::new(context, request.clone(), schemas, personas).run().await
    }

    /// Run a SAST code scan against a filesystem path.
    ///
    /// Creates a code context with auto-detected language and manifests,
    /// registers all default code modules (built-in + tool wrappers), and
    /// runs the scan.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or the scan fails.
    pub async fn code_scan(&self, path: &Path) -> Result<ScanResult> {
        self.code_scan_with_profile(path, "standard").await
    }

    /// Run a SAST code scan with a specific profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the path or requested effect is denied, or the scan fails.
    pub async fn code_scan_with_profile(&self, path: &Path, profile: &str) -> Result<ScanResult> {
        let supply_chain_profile = validated_supply_chain_profile(profile)?;
        let ctx = self.code_context(path, None)?;
        let supply_chain_context = ctx.clone();

        let mut orchestrator = CodeOrchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile(profile);
        let mut result = orchestrator.run_quiet(true).await?;
        let supply_chain = self
            .run_supply_chain(
                supply_chain_context,
                SupplyChainTargetKind::SourceDirectory,
                supply_chain_profile,
                None,
            )
            .await?;
        result.merge(supply_chain);
        Ok(result)
    }

    /// Run only the ordered, offline application supply-chain pipeline.
    ///
    /// `kind` is explicit so local paths can never be reinterpreted as registry or daemon targets.
    /// The configured cache root must already exist and be separately authorized with
    /// [`Capability::LocalState`].
    ///
    /// # Errors
    ///
    /// Returns an error before traversal or process creation when the target, local state, scan
    /// profile, or external-tool effect is not authorized.
    pub async fn supply_chain_scan_with_profile(
        &self,
        path: &Path,
        kind: SupplyChainTargetKind,
        profile: &str,
        revision: Option<String>,
    ) -> Result<ScanResult> {
        let supply_chain_profile = validated_supply_chain_profile(profile)?;
        let context = self.code_context(path, None)?;
        self.run_supply_chain(context, kind, supply_chain_profile, revision).await
    }

    /// Inspect all local provider snapshots after separately authorizing the cache root.
    ///
    /// # Errors
    ///
    /// Returns an error when the local-state root is missing, invalid, or denied by policy.
    pub fn supply_chain_cache_status(&self) -> Result<Vec<ProviderSnapshot>> {
        let store = self.supply_chain_snapshot_store()?;
        let now = Utc::now();
        Ok(["osv", "grype", "trivy"]
            .into_iter()
            .map(|provider| {
                let maximum_age_seconds = match provider {
                    "osv" => self.config.supply_chain.osv_maximum_age_seconds,
                    "grype" => self.config.supply_chain.grype_maximum_age_seconds,
                    "trivy" => self.config.supply_chain.trivy_maximum_age_seconds,
                    _ => unreachable!("fixed supply-chain provider list"),
                };
                store.status(provider, now, maximum_age_seconds)
            })
            .collect())
    }

    /// Refresh one explicit provider snapshot outside scan-time execution.
    ///
    /// # Errors
    ///
    /// Returns an error when local state, the provider endpoint, download integrity, import, or
    /// atomic promotion fails. The prior current snapshot remains selected on failure.
    pub async fn supply_chain_cache_refresh(
        &self,
        request: &ProviderRefreshRequest,
    ) -> Result<ProviderSnapshot> {
        let store = self.supply_chain_snapshot_store()?;
        let engagement = self.engagement.as_ref().ok_or_else(|| {
            ScorchError::Config(
                "provider refresh denied: no engagement authorization is configured".to_string(),
            )
        })?;
        ProviderRefreshService::new(Arc::clone(engagement), Arc::clone(&self.config), store)
            .refresh(request)
            .await
    }

    /// Run a SAST code scan for a specific language.
    ///
    /// Only modules supporting the given language will run. Language-agnostic
    /// modules (like the dependency auditor) always run regardless.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan fails.
    pub async fn code_scan_language(&self, path: &Path, language: &str) -> Result<ScanResult> {
        let ctx = self.code_context(path, Some(language))?;
        let supply_chain_context = ctx.clone();

        let mut orchestrator = CodeOrchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.filter_by_language(language);
        let mut result = orchestrator.run_quiet(true).await?;
        let supply_chain = self
            .run_supply_chain(
                supply_chain_context,
                SupplyChainTargetKind::SourceDirectory,
                SupplyChainProfile::Standard,
                None,
            )
            .await?;
        result.merge(supply_chain);
        Ok(result)
    }

    /// Run a combined DAST+SAST scan: web target and source code path.
    ///
    /// Runs DAST and SAST concurrently, then merges findings into a single
    /// `ScanResult`. The DAST target is the primary — SAST findings are
    /// appended. If SAST fails before it can return a partial result, DAST findings are preserved
    /// and the combined result is marked degraded with a redacted code-scan failure outcome.
    ///
    /// # Errors
    ///
    /// Returns an error if the DAST scan fails. SAST failures are non-fatal.
    pub async fn full_scan(&self, url: &str, code_path: &Path) -> Result<ScanResult> {
        let (dast_result, sast_result) = tokio::join!(self.scan(url), self.code_scan(code_path));

        let mut result = dast_result?;

        match sast_result {
            Ok(code_result) => result.merge(code_result),
            Err(error) => result.record_execution_failure("code-scan", error.to_string()),
        }

        Ok(result)
    }

    /// Get a reference to the engine's configuration.
    #[must_use]
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    /// Return the active engagement, if one was configured or supplied.
    #[must_use]
    pub fn engagement(&self) -> Option<&Engagement> {
        self.engagement.as_deref()
    }

    /// Build a policy-sealed DAST context for custom module selection.
    ///
    /// The returned context cannot be constructed without the same target,
    /// profile effect, external-tool, redirect, DNS, and proxy checks used by
    /// [`Self::scan_with_profile`].
    ///
    /// # Errors
    ///
    /// Returns a target, policy, or HTTP-client configuration error before any
    /// network or subprocess resource is created.
    pub fn dast_context(&self, url: &str, profile: &str) -> Result<ScanContext> {
        let target = Target::parse(url)?;
        self.dast_context_for_target(target, profile)
    }

    pub(crate) fn dast_context_for_target(
        &self,
        target: Target,
        profile: &str,
    ) -> Result<ScanContext> {
        let requirements = profile_policy_requirements(profile)?;
        let authorization = self.authorize_web_scan(&target.url, requirements)?;
        let http_client = self.authorized_http_client(
            Capability::DastScan,
            requirements.primary_effect,
            self.config.scan.follow_redirects,
        )?;
        let no_redirect_http_client =
            self.authorized_http_client(Capability::DastScan, requirements.primary_effect, false)?;
        let network_policy = self.policy_network(
            Capability::DastScan,
            requirements.primary_effect,
            "DAST native network",
        )?;
        Ok(ScanContext::with_http_clients(
            target,
            Arc::clone(&self.config),
            http_client,
            no_redirect_http_client,
            authorization,
            network_policy,
        ))
    }

    /// Build a policy-sealed code-analysis context for custom module selection.
    ///
    /// # Errors
    ///
    /// Returns an invalid-path or policy error before filesystem traversal or
    /// external-tool execution can begin.
    pub fn code_context(&self, path: &Path, language: Option<&str>) -> Result<CodeContext> {
        let (canonical_path, authorization) = self.code_scan_authorization(path)?;
        Ok(CodeContext::new(
            canonical_path,
            language.map(str::to_string),
            Arc::clone(&self.config),
            authorization,
        ))
    }

    /// Build a policy-sealed infrastructure context for custom module selection.
    ///
    /// # Errors
    ///
    /// Returns a target, policy, or HTTP-client configuration error before any
    /// network, credential, or subprocess resource is created.
    #[cfg(feature = "infra")]
    pub fn infra_context(
        &self,
        target: &str,
    ) -> Result<crate::engine::infra_context::InfraContext> {
        use crate::engine::infra_context::InfraContext;
        use crate::engine::infra_target::InfraTarget;

        let target = InfraTarget::parse(target)?;
        let policy_target = PolicyTarget::network(target.display_raw());
        let authorization = vec![
            self.require_authorized(
                policy_target.clone(),
                Capability::InfraScan,
                EffectClass::ActiveSafe,
            )?,
            self.require_authorized(
                policy_target,
                Capability::ExternalTool,
                EffectClass::ActiveSafe,
            )?,
        ];
        let network_policy = self.policy_network(
            Capability::InfraScan,
            EffectClass::ActiveSafe,
            "infrastructure native network",
        )?;
        Ok(InfraContext::authorized(
            target,
            Arc::clone(&self.config),
            authorization,
            network_policy,
        ))
    }

    /// Build a policy-sealed cloud context for custom module selection.
    ///
    /// # Errors
    ///
    /// Returns a target or policy error before credentials, SDK clients, or
    /// subprocess resources are created.
    #[cfg(feature = "cloud")]
    pub fn cloud_context(
        &self,
        target: &str,
    ) -> Result<crate::engine::cloud_context::CloudContext> {
        use crate::engine::cloud_context::CloudContext;
        use crate::engine::cloud_target::CloudTarget;

        let target = CloudTarget::parse(target)?;
        let policy_target = PolicyTarget::cloud(target.display_raw());
        let authorization = vec![
            self.require_authorized(
                policy_target.clone(),
                Capability::CloudScan,
                EffectClass::Passive,
            )?,
            self.require_authorized(
                policy_target.clone(),
                Capability::ExternalTool,
                EffectClass::Passive,
            )?,
            self.require_authorized(
                policy_target,
                Capability::CredentialUse,
                EffectClass::Passive,
            )?,
        ];
        Ok(CloudContext::new(target, Arc::clone(&self.config), authorization))
    }

    /// Run an infrastructure scan against a host, IP, or CIDR range.
    ///
    /// Parses `target` as an [`crate::engine::infra_target::InfraTarget`]
    /// (IP, CIDR, host, or `host:port`), builds a fresh
    /// [`crate::engine::infra_context::InfraContext`], registers every
    /// built-in [`crate::engine::infra_module::InfraModule`], and runs the
    /// orchestrator. Returns the resulting [`ScanResult`] with findings.
    ///
    /// For fine-grained control, use
    /// [`crate::runner::infra_orchestrator::InfraOrchestrator`] directly.
    ///
    /// # Errors
    ///
    /// Returns an error if the target cannot be parsed, the HTTP client
    /// cannot be built, or the scan encounters a fatal failure.
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use scorchkit::config::AppConfig;
    /// use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
    /// use scorchkit::engine::scope::ScopeRule;
    /// use scorchkit::facade::Engine;
    ///
    /// # async fn example() -> scorchkit::engine::error::Result<()> {
    /// let policy = EngagementPolicy::default()
    ///     .allow_scope(ScopeRule::parse("127.0.0.1").expect("scope"))
    ///     .allow_capability(Capability::InfraScan)
    ///     .allow_capability(Capability::ExternalTool)
    ///     .allow_effect(EffectClass::ActiveSafe);
    /// let engine = Engine::for_engagement(
    ///     Arc::new(AppConfig::default()),
    ///     Arc::new(Engagement::new("local infrastructure", policy)),
    /// );
    /// let result = engine.infra_scan("127.0.0.1").await?;
    /// println!("infra findings: {}", result.findings.len());
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "infra")]
    pub async fn infra_scan(&self, target: &str) -> Result<ScanResult> {
        self.infra_scan_with_profile(target, "standard").await
    }

    /// Run an infrastructure scan with a specific profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the target or requested effect is denied, CVE lookup setup fails, or
    /// the scan fails.
    #[cfg(feature = "infra")]
    pub async fn infra_scan_with_profile(&self, target: &str, profile: &str) -> Result<ScanResult> {
        use crate::infra::cve_lookup::build_cve_lookup;
        use crate::infra::cve_match::CveMatchModule;
        use crate::runner::infra_orchestrator::InfraOrchestrator;

        validate_scan_profile(profile)?;
        let ctx = self.infra_context(target)?;

        let mut orchestrator = InfraOrchestrator::new(ctx);
        orchestrator.register_default_modules();

        // Layer the CVE matcher on top of the defaults when [cve] is
        // configured. `build_cve_lookup` returns Ok(None) for the
        // default `disabled` backend, leaving the orchestrator
        // unchanged.
        let engagement = self.engagement.as_ref().ok_or_else(|| {
            ScorchError::Config(
                "CVE lookup denied: no engagement authorization is configured".to_string(),
            )
        })?;
        if let Some(lookup) = build_cve_lookup(&self.config, Arc::clone(engagement))? {
            orchestrator.add_module(Box::new(CveMatchModule::new(lookup)));
        }
        orchestrator.apply_profile(profile);

        orchestrator.run(true).await
    }

    /// Run a cloud-posture scan against a cloud target.
    ///
    /// Accepted target forms: `aws:123456789012`, `gcp:my-project`,
    /// `azure:abcd-1234`, `k8s:prod-cluster`, or `all`. The registry
    /// contains five policy-gated external-tool wrappers. Provider-native SDK
    /// modules remain quarantined until their transports enforce address-level
    /// policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the target cannot be parsed or the
    /// orchestrator fails.
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use scorchkit::config::AppConfig;
    /// use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
    /// use scorchkit::engine::scope::ScopeRule;
    /// use scorchkit::facade::Engine;
    ///
    /// # async fn example() -> scorchkit::engine::error::Result<()> {
    /// let target = "aws:123456789012";
    /// let policy = EngagementPolicy::default()
    ///     .allow_scope(ScopeRule::cloud(target))
    ///     .allow_capability(Capability::CloudScan)
    ///     .allow_capability(Capability::ExternalTool)
    ///     .allow_capability(Capability::CredentialUse)
    ///     .allow_effect(EffectClass::Passive);
    /// let engine = Engine::for_engagement(
    ///     Arc::new(AppConfig::default()),
    ///     Arc::new(Engagement::new("cloud posture", policy)),
    /// );
    /// let result = engine.cloud_scan(target).await?;
    /// println!("cloud findings: {}", result.findings.len());
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "cloud")]
    pub async fn cloud_scan(&self, target: &str) -> Result<ScanResult> {
        self.cloud_scan_with_profile(target, "standard").await
    }

    /// Run a cloud-posture scan with a specific profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the target or requested effect is denied, or the scan fails.
    #[cfg(feature = "cloud")]
    pub async fn cloud_scan_with_profile(&self, target: &str, profile: &str) -> Result<ScanResult> {
        use crate::runner::cloud_orchestrator::CloudOrchestrator;

        validate_scan_profile(profile)?;
        let ctx = self.cloud_context(target)?;

        let mut orchestrator = CloudOrchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile(profile);

        orchestrator.run(true).await
    }

    /// Run a unified DAST + SAST + Infra assessment.
    ///
    /// At least one target must be `Some`. The requested family orchestrators run concurrently via
    /// `tokio::join!`; failures in any domain are logged and skipped so
    /// partial results still come back. Results merge via
    /// [`ScanResult::merge`], with DAST → SAST → Infra priority for the
    /// receiving base (mirroring [`Engine::full_scan`]).
    ///
    /// # Errors
    ///
    /// Returns [`crate::engine::error::ScorchError::Config`] when every
    /// input is `None`. Returns the first available error only when every
    /// provided domain failed.
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use std::sync::Arc;
    /// use scorchkit::config::AppConfig;
    /// use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
    /// use scorchkit::engine::scope::ScopeRule;
    /// use scorchkit::facade::Engine;
    ///
    /// # async fn example() -> scorchkit::engine::error::Result<()> {
    /// let code = Path::new("./src").canonicalize()?;
    /// let policy = EngagementPolicy::default()
    ///     .allow_scope(ScopeRule::parse("example.com").expect("web scope"))
    ///     .allow_scope(ScopeRule::parse("127.0.0.1").expect("infra scope"))
    ///     .allow_scope(ScopeRule::path_prefix(&code)?)
    ///     .allow_capability(Capability::DastScan)
    ///     .allow_capability(Capability::CodeScan)
    ///     .allow_capability(Capability::InfraScan)
    ///     .allow_capability(Capability::ExternalTool)
    ///     .allow_effect(EffectClass::ActiveSafe)
    ///     .allow_effect(EffectClass::Intrusive)
    ///     .allow_effect(EffectClass::Passive);
    /// let engine = Engine::for_engagement(
    ///     Arc::new(AppConfig::default()),
    ///     Arc::new(Engagement::new("combined assessment", policy)),
    /// );
    /// let result = engine
    ///     .full_assessment(
    ///         Some("https://example.com"),
    ///         Some(&code),
    ///         Some("127.0.0.1"),
    ///         None,  // cloud target (optional; requires `cloud` feature)
    ///     )
    ///     .await?;
    /// println!("unified findings: {}", result.findings.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The `cloud_target` parameter is always present in the
    /// signature (it is not `cfg`-gated) so callers don't need their
    /// own `#[cfg(feature = "cloud")]` wrappers. Passing `Some(_)`
    /// when the `cloud` feature is **off** returns
    /// [`crate::engine::error::ScorchError::Config`] at call time.
    #[cfg(feature = "infra")]
    pub async fn full_assessment(
        &self,
        url: Option<&str>,
        code_path: Option<&Path>,
        infra_target: Option<&str>,
        cloud_target: Option<&str>,
    ) -> Result<ScanResult> {
        self.full_assessment_with_profile(url, code_path, infra_target, cloud_target, "thorough")
            .await
    }

    /// Run a unified assessment with one profile applied to every requested family.
    ///
    /// # Errors
    ///
    /// Returns [`crate::engine::error::ScorchError::Config`] when every input is `None` or a cloud
    /// target is requested without the cloud feature. Returns the first available error when all
    /// requested families fail.
    #[cfg(feature = "infra")]
    pub async fn full_assessment_with_profile(
        &self,
        url: Option<&str>,
        code_path: Option<&Path>,
        infra_target: Option<&str>,
        cloud_target: Option<&str>,
        profile: &str,
    ) -> Result<ScanResult> {
        use crate::engine::error::ScorchError;

        validate_scan_profile(profile)?;
        if url.is_none() && code_path.is_none() && infra_target.is_none() && cloud_target.is_none()
        {
            return Err(ScorchError::Config(
                "full_assessment requires at least one of url, code_path, infra_target, or \
                 cloud_target"
                    .into(),
            ));
        }

        // Reject cloud_target when the cloud feature is disabled — the
        // parameter is always-present in the signature, but the
        // orchestrator + SDKs live behind the feature flag.
        #[cfg(not(feature = "cloud"))]
        if cloud_target.is_some() {
            return Err(ScorchError::Config(
                "cloud_target provided but the `cloud` feature is not enabled — rebuild with \
                 `--features cloud`"
                    .into(),
            ));
        }

        let dast_future = async {
            match url {
                Some(u) => Some(self.scan_with_profile(u, profile).await),
                None => None,
            }
        };
        let sast_future = async {
            match code_path {
                Some(p) => Some(self.code_scan_with_profile(p, profile).await),
                None => None,
            }
        };
        let infra_future = async {
            match infra_target {
                Some(t) => Some(self.infra_scan_with_profile(t, profile).await),
                None => None,
            }
        };
        #[cfg(feature = "cloud")]
        let cloud_future = async {
            match cloud_target {
                Some(t) => Some(self.cloud_scan_with_profile(t, profile).await),
                None => None,
            }
        };
        #[cfg(not(feature = "cloud"))]
        let cloud_future = async { None::<Result<ScanResult>> };

        let (dast, sast, infra, cloud) =
            tokio::join!(dast_future, sast_future, infra_future, cloud_future);

        // Pick the first available Ok as the base, merge the others into it.
        // Priority: DAST > SAST > Infra > Cloud (matches full_scan precedent;
        // cloud last as it is the newest family).
        let mut base: Option<ScanResult> = None;
        let mut first_err: Option<ScorchError> = None;
        let mut failures = Vec::new();

        absorb_outcome("dast-scan", dast, &mut base, &mut first_err, &mut failures);
        absorb_outcome("code-scan", sast, &mut base, &mut first_err, &mut failures);
        absorb_outcome("infra-scan", infra, &mut base, &mut first_err, &mut failures);
        absorb_outcome("cloud-scan", cloud, &mut base, &mut first_err, &mut failures);

        if let Some(result) = base.as_mut() {
            for (family, message) in failures {
                result.record_execution_failure(family, message);
            }
        }

        base.ok_or_else(|| {
            first_err.unwrap_or_else(|| ScorchError::Config("assess: no results".into()))
        })
    }

    /// Require one exact authorization tuple and return its auditable decision.
    ///
    /// # Errors
    ///
    /// Fails closed when no engagement is configured or the policy denies the
    /// target, capability, or effect.
    pub fn require_authorized(
        &self,
        target: PolicyTarget,
        capability: Capability,
        effect: EffectClass,
    ) -> Result<crate::engine::policy::AuthorizationDecision> {
        let Some(engagement) = &self.engagement else {
            return Err(ScorchError::Config(
                "scan effect denied: no engagement authorization is configured".to_string(),
            ));
        };
        engagement.authorize(target, capability, effect).require().map_err(Into::into)
    }

    /// Authorize a web scan and build a client that reauthorizes redirects and DNS answers.
    ///
    /// # Errors
    ///
    /// Returns a policy or configuration error before client construction when
    /// the direct target, requested external-tool capability, or configured
    /// proxy is not authorized.
    #[cfg(test)]
    pub(crate) fn authorized_web_client(
        &self,
        target: &url::Url,
        effect: EffectClass,
        requires_external_tools: bool,
    ) -> Result<reqwest::Client> {
        self.require_authorized(PolicyTarget::Web(target.clone()), Capability::DastScan, effect)?;
        if requires_external_tools {
            self.require_authorized(
                PolicyTarget::Web(target.clone()),
                Capability::ExternalTool,
                effect,
            )?;
        }
        self.authorized_http_client(Capability::DastScan, effect, self.config.scan.follow_redirects)
    }

    /// Authorize a web scan using the effect and tool requirements of a named profile.
    ///
    /// # Errors
    ///
    /// Returns an authorization or client-construction error before any request is sent.
    #[cfg(feature = "storage")]
    pub(crate) fn authorize_web_scan_for_profile(
        &self,
        target: &url::Url,
        profile: &str,
    ) -> Result<()> {
        let requirements = profile_policy_requirements(profile)?;
        self.authorize_web_scan(target, requirements)?;
        Ok(())
    }

    fn authorized_http_client(
        &self,
        capability: Capability,
        effect: EffectClass,
        follow_redirects: bool,
    ) -> Result<reqwest::Client> {
        let engagement = self.engagement.as_ref().ok_or_else(|| {
            ScorchError::Config(
                "scan effect denied: no engagement authorization is configured".to_string(),
            )
        })?;
        build_authorized_http_client(&self.config, engagement, capability, effect, follow_redirects)
    }

    fn policy_network(
        &self,
        capability: Capability,
        effect: EffectClass,
        operation: &str,
    ) -> Result<PolicyNetwork> {
        let engagement = self.engagement.as_ref().ok_or_else(|| {
            ScorchError::Config(format!(
                "{operation} denied: no engagement authorization is configured"
            ))
        })?;
        Ok(PolicyNetwork::new(Arc::clone(engagement), capability, effect))
    }

    fn code_policy_target(path: &Path) -> Result<PolicyTarget> {
        PolicyTarget::code(path).map_err(|error| ScorchError::InvalidTarget {
            target: path.display().to_string(),
            reason: error.to_string(),
        })
    }

    fn authorize_web_scan(
        &self,
        target: &url::Url,
        requirements: ProfilePolicyRequirements,
    ) -> Result<Vec<crate::engine::policy::AuthorizationDecision>> {
        let mut authorization = vec![self.require_authorized(
            PolicyTarget::Web(target.clone()),
            Capability::DastScan,
            requirements.primary_effect,
        )?];
        if requirements.external_tools || !self.config.hooks.is_empty() {
            authorization.push(self.require_authorized(
                PolicyTarget::Web(target.clone()),
                Capability::ExternalTool,
                requirements.primary_effect,
            )?);
        }
        if requirements.credential_testing {
            authorization.push(self.require_authorized(
                PolicyTarget::Web(target.clone()),
                Capability::ExternalTool,
                EffectClass::CredentialTest,
            )?);
            authorization.push(self.require_authorized(
                PolicyTarget::Web(target.clone()),
                Capability::CredentialUse,
                EffectClass::CredentialTest,
            )?);
        }
        if requirements.exploitation {
            authorization.push(self.require_authorized(
                PolicyTarget::Web(target.clone()),
                Capability::ExternalTool,
                EffectClass::Exploit,
            )?);
            authorization.push(self.require_authorized(
                PolicyTarget::Web(target.clone()),
                Capability::Exploit,
                EffectClass::Exploit,
            )?);
        }
        if let Some(engagement) = &self.engagement {
            let credential = engagement.authorize(
                PolicyTarget::Web(target.clone()),
                Capability::CredentialUse,
                EffectClass::Passive,
            );
            if credential.allowed {
                authorization.push(credential);
            }
        }
        Ok(authorization)
    }

    fn code_scan_authorization(
        &self,
        path: &Path,
    ) -> Result<(PathBuf, Vec<crate::engine::policy::AuthorizationDecision>)> {
        let policy_target = Self::code_policy_target(path)?;
        let PolicyTarget::Code(canonical_path) = &policy_target else {
            unreachable!("code_policy_target always returns PolicyTarget::Code");
        };
        let canonical_path = canonical_path.clone();
        let mut authorization = vec![
            self.require_authorized(
                policy_target.clone(),
                Capability::CodeScan,
                EffectClass::Passive,
            )?,
            self.require_authorized(policy_target, Capability::ExternalTool, EffectClass::Passive)?,
        ];
        if let Some(engagement) = &self.engagement {
            let credential = engagement.authorize(
                PolicyTarget::Code(canonical_path.clone()),
                Capability::CredentialUse,
                EffectClass::Passive,
            );
            if credential.allowed {
                authorization.push(credential);
            }
        }
        Ok((canonical_path, authorization))
    }

    fn selected_dast_personas(
        &self,
        request: &ApplicationDastRequest,
        target: &url::Url,
    ) -> Result<Vec<(String, Option<DastPersonaConfig>)>> {
        let mut selected = Vec::new();
        let mut names = std::collections::BTreeSet::new();
        for name in &request.personas {
            validate_persona_id(name)?;
            if name == "anonymous" || !names.insert(name.clone()) {
                return Err(ScorchError::Config(format!(
                    "application DAST persona '{name}' is reserved or duplicated"
                )));
            }
            let persona = self.config.dast.personas.get(name).cloned().ok_or_else(|| {
                ScorchError::Config(format!("application DAST persona '{name}' is not configured"))
            })?;
            validate_persona_config(&persona, target)?;
            selected.push((name.clone(), Some(persona)));
        }
        if request.include_anonymous {
            selected.push(("anonymous".to_string(), None));
        }
        if selected.is_empty() {
            return Err(ScorchError::Config(
                "application DAST requires anonymous or at least one named persona".to_string(),
            ));
        }
        selected.sort_by_key(|(name, persona)| (persona.is_some(), name.clone()));
        Ok(selected)
    }

    fn supply_chain_snapshot_store(&self) -> Result<SupplyChainSnapshotStore> {
        let configured = &self.config.supply_chain.cache_root;
        let cache_root = configured.canonicalize().map_err(|error| {
            ScorchError::Config(format!(
                "cannot open supply-chain cache root '{}': {error}; create and authorize it before scanning",
                configured.display()
            ))
        })?;
        self.require_authorized(
            PolicyTarget::Code(cache_root.clone()),
            Capability::LocalState,
            EffectClass::Passive,
        )?;
        SupplyChainSnapshotStore::open(
            &cache_root,
            self.config.supply_chain.provider_download_limit_bytes,
        )
    }

    async fn run_supply_chain(
        &self,
        context: CodeContext,
        kind: SupplyChainTargetKind,
        profile: SupplyChainProfile,
        revision: Option<String>,
    ) -> Result<ScanResult> {
        let started_at = Utc::now();
        let target = authorize_local_target_shape(&context.path, kind, revision)?;
        let result_target = Target::from_path(&target.canonical_path)?;
        let snapshots = self.supply_chain_snapshot_store()?;
        let workspace = SupplyChainRunWorkspace::create(snapshots.root())?;
        let run = SupplyChainOrchestrator::new(context, target, profile, workspace, snapshots)
            .run()
            .await;
        Ok(supply_chain_scan_result(result_target, started_at, run))
    }
}

fn validate_application_dast_target(target: &url::Url) -> Result<()> {
    if !matches!(target.scheme(), "http" | "https")
        || target.host_str().is_none()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.query().is_some()
        || target.fragment().is_some()
    {
        return Err(ScorchError::InvalidTarget {
            target: target.to_string(),
            reason: "application DAST requires a credential-free HTTP(S) base URL without query or fragment"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_dast_config(config: &crate::config::DastConfig) -> Result<()> {
    let limits = [
        ("persona_limit_count", config.persona_limit_count as u64),
        ("schema_limit_bytes", config.schema_limit_bytes as u64),
        ("schema_limit_count", config.schema_limit_count as u64),
        ("output_limit_bytes", config.output_limit_bytes as u64),
        ("artifact_limit_files", config.artifact_limit_files),
        ("timeout_seconds", config.timeout_seconds),
        ("spider_minutes", config.spider_minutes),
        ("client_spider_minutes", config.client_spider_minutes),
        ("active_scan_minutes", config.active_scan_minutes),
        ("client_spider_depth", config.client_spider_depth),
        ("client_spider_children", config.client_spider_children),
    ];
    if config.artifact_limit_bytes == 0 {
        return Err(ScorchError::Config(
            "application DAST artifact_limit_bytes must be nonzero".to_string(),
        ));
    }
    if let Some((name, _)) = limits.into_iter().find(|(_, value)| *value == 0) {
        return Err(ScorchError::Config(format!("application DAST {name} must be nonzero")));
    }
    if !matches!(config.browser_id.as_str(), "chrome-headless" | "firefox-headless") {
        return Err(ScorchError::Config(
            "application DAST browser_id must be 'chrome-headless' or 'firefox-headless'"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_persona_id(value: &str) -> Result<()> {
    if !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(ScorchError::Config(
            "application DAST persona IDs must use 1-64 ASCII letters, digits, '-' or '_'"
                .to_string(),
        ))
    }
}

fn validate_persona_config(persona: &DastPersonaConfig, target: &url::Url) -> Result<()> {
    match persona {
        DastPersonaConfig::Header { header_name, value_env, verification } => {
            let header = reqwest::header::HeaderName::from_bytes(header_name.as_bytes()).map_err(
                |error| {
                    ScorchError::Config(format!(
                        "application DAST header persona has an invalid header name: {error}"
                    ))
                },
            )?;
            if matches!(
                header.as_str(),
                "host"
                    | "content-length"
                    | "transfer-encoding"
                    | "connection"
                    | "proxy-authorization"
                    | "proxy-authenticate"
                    | "upgrade"
                    | "te"
                    | "trailer"
            ) {
                return Err(ScorchError::Config(format!(
                    "application DAST header persona cannot override authority or framing header '{header}'"
                )));
            }
            validate_environment_name(value_env)?;
            validate_verification(verification, target)
        }
        DastPersonaConfig::Browser { login_url, username_env, password_env, verification } => {
            validate_environment_name(username_env)?;
            validate_environment_name(password_env)?;
            validate_same_origin_persona_url(login_url, target, "login")?;
            validate_verification(verification, target)
        }
    }
}

fn validate_verification(verification: &DastVerificationConfig, target: &url::Url) -> Result<()> {
    validate_same_origin_persona_url(&verification.url, target, "verification")?;
    if verification.logged_in_regex.is_empty() || verification.logged_out_regex.is_empty() {
        return Err(ScorchError::Config(
            "application DAST verification requires logged-in and logged-out regexes".to_string(),
        ));
    }
    regex::Regex::new(&verification.logged_in_regex).map_err(|error| {
        ScorchError::Config(format!("invalid application DAST logged-in regex: {error}"))
    })?;
    regex::Regex::new(&verification.logged_out_regex).map_err(|error| {
        ScorchError::Config(format!("invalid application DAST logged-out regex: {error}"))
    })?;
    if !(100..=599).contains(&verification.expected_status) {
        return Err(ScorchError::Config(
            "application DAST verification status must be between 100 and 599".to_string(),
        ));
    }
    Ok(())
}

fn validate_same_origin_persona_url(value: &str, target: &url::Url, purpose: &str) -> Result<()> {
    let url = url::Url::parse(value).map_err(|error| ScorchError::InvalidTarget {
        target: value.to_string(),
        reason: format!("invalid application DAST {purpose} URL: {error}"),
    })?;
    if url.scheme() != target.scheme()
        || url.host_str() != target.host_str()
        || url.port_or_known_default() != target.port_or_known_default()
        || !path_is_under(target.path(), url.path())
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ScorchError::InvalidTarget {
            target: value.to_string(),
            reason: format!(
                "application DAST {purpose} URL must be credential-free, same-origin, and under the authorized target path"
            ),
        });
    }
    Ok(())
}

fn validate_environment_name(value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    let valid_first = bytes.next().is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic());
    if valid_first && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()) {
        Ok(())
    } else {
        Err(ScorchError::Config(format!(
            "application DAST credential reference '{value}' is not an environment-variable name"
        )))
    }
}

fn resolve_dast_persona(id: String, persona: Option<DastPersonaConfig>) -> Result<ResolvedPersona> {
    let kind = match persona {
        None => ResolvedPersonaKind::Anonymous,
        Some(DastPersonaConfig::Header { header_name, value_env, verification }) => {
            let header_value = required_environment_secret(&value_env)?;
            validate_dast_header_value(&header_value, &value_env)?;
            ResolvedPersonaKind::Header { header_name, header_value, verification }
        }
        Some(DastPersonaConfig::Browser {
            login_url,
            username_env,
            password_env,
            verification,
        }) => ResolvedPersonaKind::Browser {
            login_url,
            username: required_environment_secret(&username_env)?,
            password: required_environment_secret(&password_env)?,
            verification,
        },
    };
    Ok(ResolvedPersona { id, kind })
}

fn validate_dast_header_value(value: &str, reference: &str) -> Result<()> {
    reqwest::header::HeaderValue::from_str(value).map(|_| ()).map_err(|_| {
        ScorchError::Config(format!(
            "application DAST credential environment variable '{reference}' is not a safe HTTP header value"
        ))
    })
}

fn required_environment_secret(name: &str) -> Result<String> {
    let value = std::env::var(name).map_err(|_| {
        ScorchError::Config(format!(
            "application DAST credential environment variable '{name}' is missing or not Unicode"
        ))
    })?;
    if value.is_empty() {
        return Err(ScorchError::Config(format!(
            "application DAST credential environment variable '{name}' is empty"
        )));
    }
    Ok(value)
}

fn supply_chain_scan_result(
    target: Target,
    started_at: chrono::DateTime<Utc>,
    run: SupplyChainRun,
) -> ScanResult {
    let SupplyChainRun { assessment, findings, modules_run, modules_skipped, module_outcomes } =
        run;
    ScanResult::new(
        uuid::Uuid::new_v4().to_string(),
        target,
        started_at,
        findings,
        modules_run,
        modules_skipped,
    )
    .with_module_outcomes(module_outcomes)
    .with_supply_chain(assessment)
}

/// Return the authorization requirements for one built-in scan profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProfilePolicyRequirements {
    primary_effect: EffectClass,
    external_tools: bool,
    credential_testing: bool,
    exploitation: bool,
}

/// Reject unknown profile names before any family constructs an effectful context.
pub(crate) fn validate_scan_profile(profile: &str) -> Result<()> {
    if matches!(profile, "quick" | "standard" | "thorough" | "pentest") {
        return Ok(());
    }
    Err(ScorchError::Config(format!(
        "unknown scan profile '{profile}'; expected quick, standard, thorough, or pentest"
    )))
}

fn validated_supply_chain_profile(profile: &str) -> Result<SupplyChainProfile> {
    validate_scan_profile(profile)?;
    SupplyChainProfile::from_name(profile).ok_or_else(|| {
        ScorchError::Config(format!(
            "unknown supply-chain profile '{profile}'; expected quick, standard, thorough, or pentest"
        ))
    })
}

fn profile_policy_requirements(profile: &str) -> Result<ProfilePolicyRequirements> {
    validate_scan_profile(profile)?;
    match profile {
        "quick" => Ok(ProfilePolicyRequirements {
            primary_effect: EffectClass::ActiveSafe,
            external_tools: false,
            credential_testing: false,
            exploitation: false,
        }),
        "standard" => Ok(ProfilePolicyRequirements {
            primary_effect: EffectClass::Intrusive,
            external_tools: false,
            credential_testing: false,
            exploitation: false,
        }),
        "thorough" => Ok(ProfilePolicyRequirements {
            primary_effect: EffectClass::Intrusive,
            external_tools: true,
            credential_testing: false,
            exploitation: false,
        }),
        "pentest" => Ok(ProfilePolicyRequirements {
            primary_effect: EffectClass::Intrusive,
            external_tools: true,
            credential_testing: true,
            exploitation: true,
        }),
        _ => unreachable!("profile was validated before requirements were selected"),
    }
}

/// Fold one orchestrator outcome into the assembling base result.
///
/// `None` means the domain wasn't requested and is a no-op. An `Ok`
/// result either becomes the base (if none yet) or is merged into the
/// existing base. An `Err` is logged at `warn` and retained as
/// `first_err` for the fallback error path.
#[cfg(feature = "infra")]
fn absorb_outcome(
    family: &'static str,
    outcome: Option<Result<ScanResult>>,
    base: &mut Option<ScanResult>,
    first_err: &mut Option<crate::engine::error::ScorchError>,
    failures: &mut Vec<(&'static str, String)>,
) {
    let Some(result) = outcome else {
        return;
    };
    match result {
        Ok(r) => match base.as_mut() {
            Some(b) => b.merge(r),
            None => *base = Some(r),
        },
        Err(e) => {
            let message = crate::engine::observation::redact_text(&e.to_string());
            tracing::warn!(family, %message, "assess: domain failed");
            failures.push((family, message));
            if first_err.is_none() {
                *first_err = Some(e);
            }
        }
    }
}

/// Build an HTTP client from application configuration.
///
/// Configures: auth headers (bearer, basic, cookies, custom), custom scan
/// headers, user agent, timeouts, TLS settings, redirect policy, cookie
/// jar, and proxy support.
///
/// # Errors
///
/// Returns an error if the proxy URL is invalid or the client cannot be built.
fn build_authorized_http_client(
    config: &AppConfig,
    engagement: &Arc<Engagement>,
    capability: Capability,
    effect: EffectClass,
    follow_redirects: bool,
) -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();

    // Auth headers
    if let Some(ref token) = config.auth.bearer_token {
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
    }
    if let Some(ref username) = config.auth.username {
        let password = config.auth.password.as_deref().unwrap_or("");
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{username}:{password}"),
        );
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Basic {encoded}")) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
    }
    if let Some(ref cookies) = config.auth.cookies {
        if let Ok(val) = reqwest::header::HeaderValue::from_str(cookies) {
            headers.insert(reqwest::header::COOKIE, val);
        }
    }
    if let (Some(ref name), Some(ref value)) =
        (&config.auth.custom_header, &config.auth.custom_header_value)
    {
        if let (Ok(header_name), Ok(header_val)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_val);
        }
    }

    // Custom scan headers
    for (name, value) in &config.scan.headers {
        if let (Ok(header_name), Ok(header_val)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_val);
        }
    }

    let mut builder = reqwest::Client::builder()
        .user_agent(&config.scan.user_agent)
        .timeout(std::time::Duration::from_secs(config.scan.timeout_seconds))
        .default_headers(headers)
        .cookie_store(true)
        .danger_accept_invalid_certs(config.scan.insecure);

    // Proxy support
    if let Some(ref proxy_url) = config.scan.proxy {
        let proxy_target = PolicyTarget::web(proxy_url).map_err(|error| {
            ScorchError::Config(format!("invalid proxy URL '{proxy_url}': {error}"))
        })?;
        engagement.authorize(proxy_target, capability, effect).require()?;
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| ScorchError::Config(format!("invalid proxy URL '{proxy_url}': {e}")))?;
        builder = builder.proxy(proxy);
    }

    let redirects = if follow_redirects {
        RedirectMode::Follow { max_redirects: config.scan.max_redirects }
    } else {
        RedirectMode::None
    };
    bind_builder(builder, Arc::clone(engagement), capability, effect, redirects)
        .build()
        .map_err(|e| ScorchError::Config(format!("failed to build HTTP client: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::policy::{DenialReason, EngagementPolicy};
    use crate::engine::policy_http::require_resolved_target;
    use crate::engine::scope::ScopeRule;

    fn authorized_loopback_engine() -> Engine {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("localhost").unwrap())
            .allow_scope(ScopeRule::parse("127.0.0.1").unwrap())
            .allow_scope(ScopeRule::parse("::1/128").unwrap())
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::ActiveSafe);
        Engine::for_engagement(
            Arc::new(AppConfig::default()),
            Arc::new(Engagement::new("loopback", policy)),
        )
    }

    /// Verify `Engine` can be constructed with a default config.
    #[test]
    fn test_engine_new() {
        let mut config = AppConfig::default();
        config.scan.user_agent = "scorchkit-engine-config-identity".to_string();
        let config = Arc::new(config);
        let engine = Engine::new(Arc::clone(&config));

        assert_eq!(engine.config().scan.user_agent, "scorchkit-engine-config-identity");
        assert!(std::ptr::eq(engine.config(), Arc::as_ref(&config)));
        assert!(engine.engagement().is_none());
    }

    #[test]
    fn policy_gated_engine_exposes_engagement_and_profile_requirements() {
        let engagement = Arc::new(Engagement::new("boundary-test", EngagementPolicy::default()));
        let engine =
            Engine::for_engagement(Arc::new(AppConfig::default()), Arc::clone(&engagement));

        assert_eq!(engine.engagement().map(|active| active.id), Some(engagement.id));
        assert_eq!(
            profile_policy_requirements("quick").expect("quick profile"),
            ProfilePolicyRequirements {
                primary_effect: EffectClass::ActiveSafe,
                external_tools: false,
                credential_testing: false,
                exploitation: false,
            }
        );
        assert!(!profile_policy_requirements("standard").expect("standard profile").external_tools);
        assert!(profile_policy_requirements("thorough").expect("thorough profile").external_tools);
        let pentest = profile_policy_requirements("pentest").expect("pentest profile");
        assert!(pentest.credential_testing && pentest.exploitation);
        assert!(profile_policy_requirements("unknown").is_err());
    }

    #[test]
    fn application_dast_config_rejects_unbounded_values_and_unknown_browsers() {
        let mut config = crate::config::DastConfig::default();
        assert!(validate_dast_config(&config).is_ok());
        config.client_spider_depth = 0;
        assert!(validate_dast_config(&config).is_err());
        config.client_spider_depth = 10;
        config.browser_id = "remote-browser".to_string();
        assert!(validate_dast_config(&config).is_err());
    }

    #[test]
    fn application_dast_target_validation_rejects_each_unsafe_url_component() {
        for value in ["http://example.com", "https://example.com/app"] {
            let target = url::Url::parse(value).expect("valid target");
            assert!(validate_application_dast_target(&target).is_ok(), "rejected {value}");
        }
        for value in [
            "ftp://example.com",
            "https://user@example.com",
            "https://user:password@example.com",
            "https://example.com?query=true",
            "https://example.com#fragment",
        ] {
            let target = url::Url::parse(value).expect("parseable invalid target");
            assert!(validate_application_dast_target(&target).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn application_dast_persona_and_environment_names_use_exact_grammars() {
        for value in ["a", "A_1-z", &"a".repeat(64)] {
            assert!(validate_persona_id(value).is_ok(), "rejected persona {value:?}");
        }
        for value in ["", &"a".repeat(65), "user.name", "naïve"] {
            assert!(validate_persona_id(value).is_err(), "accepted persona {value:?}");
        }

        for value in ["A", "_TOKEN", "TOKEN_123"] {
            assert!(validate_environment_name(value).is_ok(), "rejected environment {value:?}");
        }
        for value in ["", "1TOKEN", "TOKEN-NAME", "TÖKEN"] {
            assert!(validate_environment_name(value).is_err(), "accepted environment {value:?}");
        }
    }

    #[test]
    fn application_dast_verification_requires_both_state_regexes() {
        let target = url::Url::parse("https://example.com/app").expect("target");
        let valid = DastVerificationConfig {
            url: "https://example.com/app/account".to_string(),
            expected_status: 200,
            logged_in_regex: "Account".to_string(),
            logged_out_regex: "Sign in".to_string(),
            max_logged_out: 0,
        };
        assert!(validate_verification(&valid, &target).is_ok());
        let mut missing_logged_in = valid.clone();
        missing_logged_in.logged_in_regex.clear();
        assert!(validate_verification(&missing_logged_in, &target).is_err());
        let mut missing_logged_out = valid;
        missing_logged_out.logged_out_regex.clear();
        assert!(validate_verification(&missing_logged_out, &target).is_err());
    }

    #[test]
    fn application_dast_persona_urls_reject_each_origin_and_credential_escape() {
        let target = url::Url::parse("https://example.com:8443/app/").expect("target");
        assert!(validate_same_origin_persona_url(
            "https://example.com:8443/app/account",
            &target,
            "verification"
        )
        .is_ok());
        for value in [
            "http://example.com:8443/app/account",
            "https://other.example.com:8443/app/account",
            "https://example.com:9443/app/account",
            "https://example.com:8443/outside",
            "https://user@example.com:8443/app/account",
            "https://user:password@example.com:8443/app/account",
            "https://example.com:8443/app/account?query=true",
            "https://example.com:8443/app/account#fragment",
        ] {
            assert!(
                validate_same_origin_persona_url(value, &target, "verification").is_err(),
                "accepted {value}"
            );
        }
    }

    #[tokio::test]
    async fn application_dast_request_limits_are_strict_upper_bounds() {
        let schema = crate::application_dast::ApplicationDastSchemaRequest {
            kind: scorchkit_core::ApplicationDastSchemaKind::OpenApi,
            path: PathBuf::from("/fixture/missing-schema.yaml"),
            sha256: "0".repeat(64),
            endpoint: None,
        };
        let mut config = AppConfig::default();
        config.dast.persona_limit_count = 1;
        config.dast.schema_limit_count = 1;
        let engine = Engine::new(Arc::new(config));

        let over_personas = ApplicationDastRequest {
            target: "https://example.com".to_string(),
            profile: scorchkit_core::ApplicationDastProfile::Passive,
            include_anonymous: true,
            personas: vec!["first".to_string(), "second".to_string()],
            schemas: Vec::new(),
        };
        let error = engine
            .application_dast(&over_personas)
            .await
            .expect_err("three personas must exceed a one-persona limit");
        assert!(error.to_string().contains("at most 1 personas"));

        let exact_personas = ApplicationDastRequest::new(
            "https://example.com",
            scorchkit_core::ApplicationDastProfile::Passive,
        );
        let error = engine
            .application_dast(&exact_personas)
            .await
            .expect_err("an engagement is still required");
        assert!(!error.to_string().contains("at most 1 personas"));

        let over_schemas = ApplicationDastRequest {
            target: "https://example.com".to_string(),
            profile: scorchkit_core::ApplicationDastProfile::Passive,
            include_anonymous: true,
            personas: Vec::new(),
            schemas: vec![schema.clone(), schema.clone()],
        };
        let error = engine
            .application_dast(&over_schemas)
            .await
            .expect_err("two schemas must exceed a one-schema limit");
        assert!(error.to_string().contains("at most 1 schemas"));

        let exact_schemas = ApplicationDastRequest {
            target: "https://example.com".to_string(),
            profile: scorchkit_core::ApplicationDastProfile::Passive,
            include_anonymous: true,
            personas: Vec::new(),
            schemas: vec![schema],
        };
        let error = engine
            .application_dast(&exact_schemas)
            .await
            .expect_err("the missing schema must fail after the count check");
        assert!(!error.to_string().contains("at most 1 schemas"));
    }

    #[test]
    fn selected_application_dast_personas_reject_reserved_and_duplicate_ids_and_sort_anonymous() {
        let target = url::Url::parse("https://example.com/app").expect("target");
        let verification = DastVerificationConfig {
            url: "https://example.com/app/account".to_string(),
            expected_status: 200,
            logged_in_regex: "Account".to_string(),
            logged_out_regex: "Sign in".to_string(),
            max_logged_out: 0,
        };
        let persona = DastPersonaConfig::Header {
            header_name: "Authorization".to_string(),
            value_env: "SCORCHKIT_DAST_HEADER".to_string(),
            verification,
        };
        let mut config = AppConfig::default();
        config.dast.personas.insert("a".to_string(), persona);
        let engine = Engine::new(Arc::new(config));

        let reserved = ApplicationDastRequest {
            target: target.to_string(),
            profile: scorchkit_core::ApplicationDastProfile::Passive,
            include_anonymous: false,
            personas: vec!["anonymous".to_string()],
            schemas: Vec::new(),
        };
        let error =
            engine.selected_dast_personas(&reserved, &target).expect_err("anonymous is reserved");
        assert!(error.to_string().contains("reserved or duplicated"));

        let duplicate = ApplicationDastRequest {
            target: target.to_string(),
            profile: scorchkit_core::ApplicationDastProfile::Passive,
            include_anonymous: false,
            personas: vec!["a".to_string(), "a".to_string()],
            schemas: Vec::new(),
        };
        let error = engine
            .selected_dast_personas(&duplicate, &target)
            .expect_err("duplicate persona must fail");
        assert!(error.to_string().contains("reserved or duplicated"));

        let mixed = ApplicationDastRequest {
            target: target.to_string(),
            profile: scorchkit_core::ApplicationDastProfile::Passive,
            include_anonymous: true,
            personas: vec!["a".to_string()],
            schemas: Vec::new(),
        };
        let selected = engine.selected_dast_personas(&mixed, &target).expect("selected personas");
        assert_eq!(
            selected.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(),
            ["anonymous", "a"]
        );
    }

    #[test]
    fn application_dast_header_personas_cannot_override_request_authority_or_framing() {
        let target = url::Url::parse("https://example.com/app").expect("target");
        let verification = DastVerificationConfig {
            url: "https://example.com/app/account".to_string(),
            expected_status: 200,
            logged_in_regex: "Account".to_string(),
            logged_out_regex: "Sign in".to_string(),
            max_logged_out: 0,
        };
        for header_name in ["Host", "Content-Length", "Transfer-Encoding", "Connection"] {
            let persona = DastPersonaConfig::Header {
                header_name: header_name.to_string(),
                value_env: "SCORCHKIT_DAST_HEADER".to_string(),
                verification: verification.clone(),
            };
            assert!(validate_persona_config(&persona, &target).is_err(), "accepted {header_name}");
        }
        let authorization = DastPersonaConfig::Header {
            header_name: "Authorization".to_string(),
            value_env: "SCORCHKIT_DAST_HEADER".to_string(),
            verification,
        };
        assert!(validate_persona_config(&authorization, &target).is_ok());
        assert!(validate_dast_header_value("Bearer safe-token", "SAFE_TOKEN").is_ok());
        let error = validate_dast_header_value("safe\r\nX-Injected: true", "UNSAFE_TOKEN")
            .expect_err("header splitting must be rejected");
        assert!(error.to_string().contains("UNSAFE_TOKEN"));
        assert!(!error.to_string().contains("X-Injected"));
    }

    #[tokio::test]
    async fn application_dast_denies_all_grants_before_secret_resolution() {
        let mut config = AppConfig::default();
        config.dast.personas.insert(
            "user".to_string(),
            DastPersonaConfig::Header {
                header_name: "Authorization".to_string(),
                value_env: "SCORCHKIT_DAST_TEST_SECRET_MUST_NOT_EXIST".to_string(),
                verification: DastVerificationConfig {
                    url: "https://example.com/account".to_string(),
                    expected_status: 200,
                    logged_in_regex: "Account".to_string(),
                    logged_out_regex: "Sign in".to_string(),
                    max_logged_out: 0,
                },
            },
        );
        let request = ApplicationDastRequest {
            target: "https://example.com".to_string(),
            profile: scorchkit_core::ApplicationDastProfile::Passive,
            include_anonymous: false,
            personas: vec!["user".to_string()],
            schemas: Vec::new(),
        };
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.com").expect("scope"))
            .allow_capability(Capability::DastScan)
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::Intrusive);
        let engine = Engine::for_engagement(
            Arc::new(config.clone()),
            Arc::new(Engagement::new("missing credential grant", policy)),
        );
        let denied =
            engine.application_dast(&request).await.expect_err("credential use must be denied");
        assert!(matches!(denied, ScorchError::Policy(_)));
        assert!(!denied.to_string().contains("SCORCHKIT_DAST_TEST_SECRET_MUST_NOT_EXIST"));

        let allowed_policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.com").expect("scope"))
            .allow_capability(Capability::DastScan)
            .allow_capability(Capability::ExternalTool)
            .allow_capability(Capability::CredentialUse)
            .allow_effect(EffectClass::Intrusive)
            .allow_effect(EffectClass::CredentialTest);
        let engine = Engine::for_engagement(
            Arc::new(config),
            Arc::new(Engagement::new("credential grant", allowed_policy)),
        );
        let missing = engine
            .application_dast(&request)
            .await
            .expect_err("authorized request must then resolve its secret reference");
        assert!(
            matches!(missing, ScorchError::Config(ref message) if message.contains("environment variable"))
        );
    }

    #[tokio::test]
    async fn application_dast_authorizes_schema_before_parsing_it() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let schema = directory.path().join("schema.yaml");
        std::fs::write(&schema, b"not an OpenAPI schema").expect("schema fixture");
        let request = ApplicationDastRequest {
            target: "https://example.com".to_string(),
            profile: scorchkit_core::ApplicationDastProfile::Passive,
            include_anonymous: true,
            personas: Vec::new(),
            schemas: vec![crate::application_dast::ApplicationDastSchemaRequest {
                kind: scorchkit_core::ApplicationDastSchemaKind::OpenApi,
                path: schema,
                sha256: "not-a-digest".to_string(),
                endpoint: None,
            }],
        };
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.com").expect("scope"))
            .allow_capability(Capability::DastScan)
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::Intrusive);
        let engine = Engine::for_engagement(
            Arc::new(AppConfig::default()),
            Arc::new(Engagement::new("schema denied", policy)),
        );

        let error = engine
            .application_dast(&request)
            .await
            .expect_err("schema local-state grant must be required before parsing");
        assert!(matches!(error, ScorchError::Policy(_)));
        assert!(!error.to_string().contains("SHA-256"));
    }

    #[cfg(feature = "infra")]
    #[test]
    fn partial_assessment_records_failed_family_after_another_family_succeeds() {
        let mut base = None;
        let mut first_err = None;
        let mut failures = Vec::new();
        absorb_outcome(
            "code-scan",
            Some(Err(ScorchError::Config("api_key=assessment-fixture-secret".to_string()))),
            &mut base,
            &mut first_err,
            &mut failures,
        );

        let target = Target::parse("https://example.com").expect("fixture target");
        let clean = ScanResult::new(
            "dast-fixture".to_string(),
            target,
            chrono::Utc::now(),
            Vec::new(),
            vec!["headers".to_string()],
            Vec::new(),
        );
        absorb_outcome("dast-scan", Some(Ok(clean)), &mut base, &mut first_err, &mut failures);
        let mut result = base.expect("partial assessment result");
        for (family, message) in failures {
            result.record_execution_failure(family, message);
        }

        assert!(first_err.is_some());
        assert!(!result.execution_successful());
        assert!(result.modules_run.iter().any(|module| module == "headers"));
        let encoded = serde_json::to_string(&result).expect("serialize partial assessment");
        assert!(!encoded.contains("assessment-fixture-secret"));
        assert!(encoded.contains("code-scan"));
        assert!(encoded.contains("degraded"));
    }

    #[test]
    fn configured_hooks_require_external_tool_authorization() {
        let mut config = AppConfig::default();
        config.hooks.pre_scan.push(PathBuf::from("/opt/scorchkit/pre-scan"));
        let base_policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.com").unwrap())
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::ActiveSafe);
        let denied = Engine::for_engagement(
            Arc::new(config.clone()),
            Arc::new(Engagement::new("hooks-denied", base_policy.clone())),
        );
        assert!(denied.dast_context("https://example.com", "quick").is_err());

        let allowed = Engine::for_engagement(
            Arc::new(config),
            Arc::new(Engagement::new(
                "hooks-allowed",
                base_policy.allow_capability(Capability::ExternalTool),
            )),
        );
        assert!(allowed.dast_context("https://example.com", "quick").is_ok());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn schedule_profile_authorization_denies_without_an_engagement() {
        let engine = Engine::new(Arc::new(AppConfig::default()));
        let target = url::Url::parse("https://example.com").expect("fixture URL");

        let error = engine
            .authorize_web_scan_for_profile(&target, "quick")
            .expect_err("schedule authorization must fail closed");

        assert!(matches!(error, ScorchError::Config(message) if message.contains("no engagement")));
    }

    /// Verify `code_scan` on an empty temporary directory produces
    /// an empty scan result with no findings.
    #[tokio::test]
    async fn test_engine_code_scan() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| ScorchError::Config(e.to_string()))?;
        let cache_root = dir.path().join("supply-chain-cache");
        std::fs::create_dir(&cache_root)?;
        #[cfg(unix)]
        std::fs::set_permissions(&cache_root, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        let mut config = AppConfig::default();
        config.supply_chain.cache_root = cache_root;
        config.tools.syft = Some("/fixture/missing-syft".to_string());
        let config = Arc::new(config);
        let scope = ScopeRule::path_prefix(dir.path())?;
        let policy = EngagementPolicy::default()
            .allow_scope(scope)
            .allow_capability(Capability::CodeScan)
            .allow_capability(Capability::ExternalTool)
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::Passive);
        let engine = Engine::for_engagement(config, Arc::new(Engagement::new("test", policy)));
        let result = engine.code_scan(dir.path()).await?;
        assert!(result.findings.is_empty());
        assert!(result.supply_chain.is_some());
        assert_eq!(
            result.execution_status,
            crate::engine::scan_result::ScanExecutionStatus::Incomplete
        );
        Ok(())
    }

    #[tokio::test]
    async fn unconfigured_engine_denies_before_scan_resource_creation() {
        let engine = Engine::new(Arc::new(AppConfig::default()));
        let error = engine
            .scan_with_profile("http://127.0.0.1:9", "quick")
            .await
            .expect_err("an engine without an engagement must fail closed");
        assert!(matches!(error, ScorchError::Config(message) if message.contains("no engagement")));
    }

    #[cfg(feature = "infra")]
    #[tokio::test]
    async fn unified_assessment_applies_the_requested_profile() {
        let server = httpmock::MockServer::start_async().await;
        let root = server
            .mock_async(|when, then| {
                when.path("/");
                then.status(200).body("local fixture");
            })
            .await;
        let engine = authorized_loopback_engine();

        let quick = engine
            .full_assessment_with_profile(Some(&server.url("/")), None, None, None, "quick")
            .await;
        assert!(quick.is_ok(), "quick assessment should not require external-tool grants");
        assert!(root.calls_async().await > 0, "quick assessment should reach the local fixture");

        let error = engine
            .full_assessment_with_profile(Some(&server.url("/")), None, None, None, "thorough")
            .await
            .expect_err("thorough assessment must apply its external-tool requirement");
        assert!(matches!(error, ScorchError::Policy(_)));
    }

    #[tokio::test]
    async fn policy_gated_engine_denies_web_target_before_network_work() {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.com").unwrap())
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::ActiveSafe);
        let engagement = Arc::new(Engagement::new("test", policy));
        let engine = Engine::for_engagement(Arc::new(AppConfig::default()), engagement);

        let error = engine.scan_with_profile("https://outside.test", "quick").await.unwrap_err();
        assert!(matches!(
            error,
            ScorchError::Policy(ref violation)
                if violation.decision.denial.as_ref() == Some(&DenialReason::TargetOutOfScope)
        ));
    }

    #[tokio::test]
    async fn policy_gated_code_scan_requires_external_tool_capability() -> Result<()> {
        let root = tempfile::tempdir().map_err(|error| ScorchError::Config(error.to_string()))?;
        let scope = ScopeRule::path_prefix(root.path())
            .map_err(|error| ScorchError::Config(error.to_string()))?;
        let policy = EngagementPolicy::default()
            .allow_scope(scope)
            .allow_capability(Capability::CodeScan)
            .allow_effect(EffectClass::Passive);
        let engagement = Arc::new(Engagement::new("test", policy));
        let engine = Engine::for_engagement(Arc::new(AppConfig::default()), engagement);

        let error = engine.code_scan(root.path()).await.unwrap_err();
        assert!(matches!(
            error,
            ScorchError::Policy(ref violation)
                if violation.decision.denial.as_ref()
                    == Some(&DenialReason::CapabilityNotGranted)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn authorized_client_checks_hostname_and_every_dns_answer() {
        let server = httpmock::MockServer::start_async().await;
        let response = server
            .mock_async(|when, then| {
                when.path("/dns");
                then.status(200).body("ok");
            })
            .await;
        let url = url::Url::parse(&server.url("/dns").replace("127.0.0.1", "localhost"))
            .expect("loopback URL");

        let allowed = authorized_loopback_engine();
        let body = allowed
            .authorized_web_client(&url, EffectClass::ActiveSafe, false)
            .expect("authorized client")
            .get(url.clone())
            .send()
            .await
            .expect("authorized DNS request")
            .text()
            .await
            .expect("response body");
        assert_eq!(body, "ok");
        response.assert_calls_async(1).await;

        let hostname_only = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("localhost").unwrap())
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::ActiveSafe);
        let denied = Engine::for_engagement(
            Arc::new(AppConfig::default()),
            Arc::new(Engagement::new("hostname-only", hostname_only)),
        );
        let error = denied
            .authorized_web_client(&url, EffectClass::ActiveSafe, false)
            .expect("hostname itself is authorized")
            .get(url)
            .send()
            .await
            .expect_err("resolved loopback addresses must require separate scope grants");
        assert!(
            format!("{error:?}").contains("TargetOutOfScope"),
            "unexpected DNS denial: {error:?}"
        );
        response.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn native_dast_resolution_rejects_addresses_not_granted_with_the_hostname() {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("localhost").unwrap())
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::ActiveSafe);
        let engine = Engine::for_engagement(
            Arc::new(AppConfig::default()),
            Arc::new(Engagement::new("native DAST boundary", policy)),
        );
        let context = engine
            .dast_context("http://localhost:9", "quick")
            .expect("the hostname itself is authorized");

        let error = context
            .resolve_network_target("localhost", 9, std::time::Duration::from_secs(1))
            .await
            .expect_err("resolved loopback addresses need their own grants");

        assert!(matches!(error, ScorchError::Policy(_)));
    }

    #[cfg(feature = "infra")]
    #[tokio::test]
    async fn native_infra_resolution_uses_the_same_address_boundary() {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("localhost").unwrap())
            .allow_capability(Capability::InfraScan)
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::ActiveSafe);
        let engine = Engine::for_engagement(
            Arc::new(AppConfig::default()),
            Arc::new(Engagement::new("native infrastructure boundary", policy)),
        );
        let context = engine.infra_context("localhost").expect("hostname authorization");

        let error = context
            .network_policy()
            .resolve("localhost", 9, std::time::Duration::from_secs(1))
            .await
            .expect_err("resolved loopback addresses need their own grants");

        assert!(matches!(error, ScorchError::Policy(_)));
    }

    #[tokio::test]
    async fn authorized_client_rechecks_redirect_destinations() {
        let server = httpmock::MockServer::start_async().await;
        let denied_destination = "http://127.0.0.2:9/denied";
        let redirect = server
            .mock_async(|when, then| {
                when.path("/redirect");
                then.status(302).header("location", denied_destination);
            })
            .await;
        let start = url::Url::parse(&server.url("/redirect")).expect("start URL");
        let engine = authorized_loopback_engine();
        let error = engine
            .authorized_web_client(&start, EffectClass::ActiveSafe, false)
            .expect("initial target is authorized")
            .get(start)
            .send()
            .await
            .expect_err("redirect outside the exact loopback grant must be denied");
        assert!(
            format!("{error:?}").contains("redirect denied by engagement policy"),
            "unexpected redirect denial: {error:?}"
        );
        redirect.assert_calls_async(1).await;
    }

    #[test]
    fn resolved_private_metadata_ipv4_and_ipv6_addresses_require_exact_grants() {
        let engine = authorized_loopback_engine();
        let engagement = engine.engagement().expect("test engagement");

        assert!(require_resolved_target(
            engagement,
            "127.0.0.1",
            Capability::DastScan,
            EffectClass::ActiveSafe
        )
        .is_ok());
        assert!(require_resolved_target(
            engagement,
            "::1",
            Capability::DastScan,
            EffectClass::ActiveSafe
        )
        .is_ok());
        for denied in ["10.0.0.1", "192.168.1.1", "169.254.169.254", "fd00::1"] {
            assert!(
                require_resolved_target(
                    engagement,
                    denied,
                    Capability::DastScan,
                    EffectClass::ActiveSafe
                )
                .is_err(),
                "resolved destination {denied} must not inherit the hostname grant"
            );
        }
    }

    #[test]
    fn dns_answer_changes_are_reauthorized_independently() {
        let engine = authorized_loopback_engine();
        let engagement = engine.engagement().expect("test engagement");
        let first = require_resolved_target(
            engagement,
            "127.0.0.1",
            Capability::DastScan,
            EffectClass::ActiveSafe,
        );
        let changed = require_resolved_target(
            engagement,
            "169.254.169.254",
            Capability::DastScan,
            EffectClass::ActiveSafe,
        );
        assert!(first.is_ok());
        assert!(changed.is_err(), "a later DNS answer must receive a fresh policy decision");
    }

    #[test]
    fn metadata_ip_is_denied_before_context_or_client_construction() {
        let engine = authorized_loopback_engine();
        let error = engine
            .dast_context("http://169.254.169.254/latest/meta-data", "quick")
            .expect_err("metadata service is outside the loopback engagement");
        assert!(matches!(error, ScorchError::Policy(_)));
    }

    #[test]
    fn pentest_profile_requires_credential_and_exploit_grants() {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.com").unwrap())
            .allow_capability(Capability::DastScan)
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::Intrusive);
        let engine = Engine::for_engagement(
            Arc::new(AppConfig::default()),
            Arc::new(Engagement::new("assessment-only", policy)),
        );
        let error = engine
            .dast_context("https://example.com", "pentest")
            .expect_err("assessment grants must not authorize credential or exploit effects");
        assert!(matches!(error, ScorchError::Policy(_)));
    }
}
