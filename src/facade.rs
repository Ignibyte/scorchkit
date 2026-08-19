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

use crate::config::AppConfig;
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
        validate_scan_profile(profile)?;
        let ctx = self.code_context(path, None)?;

        let mut orchestrator = CodeOrchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile(profile);
        orchestrator.run_quiet(true).await
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

        let mut orchestrator = CodeOrchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.filter_by_language(language);
        orchestrator.run_quiet(true).await
    }

    /// Run a combined DAST+SAST scan: web target and source code path.
    ///
    /// Runs DAST and SAST concurrently, then merges findings into a single
    /// `ScanResult`. The DAST target is the primary — SAST findings are
    /// appended. If SAST fails, only DAST results are returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the DAST scan fails. SAST failures are non-fatal.
    pub async fn full_scan(&self, url: &str, code_path: &Path) -> Result<ScanResult> {
        let (dast_result, sast_result) = tokio::join!(self.scan(url), self.code_scan(code_path));

        let mut result = dast_result?;

        if let Ok(code_result) = sast_result {
            result.merge(code_result);
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

        absorb_outcome(dast, &mut base, &mut first_err);
        absorb_outcome(sast, &mut base, &mut first_err);
        absorb_outcome(infra, &mut base, &mut first_err);
        absorb_outcome(cloud, &mut base, &mut first_err);

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
    outcome: Option<Result<ScanResult>>,
    base: &mut Option<ScanResult>,
    first_err: &mut Option<crate::engine::error::ScorchError>,
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
            tracing::warn!("assess: domain failed: {e}");
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
        let config = Arc::new(AppConfig::default());
        let scope = ScopeRule::path_prefix(dir.path())?;
        let policy = EngagementPolicy::default()
            .allow_scope(scope)
            .allow_capability(Capability::CodeScan)
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::Passive);
        let engine = Engine::for_engagement(config, Arc::new(Engagement::new("test", policy)));
        let result = engine.code_scan(dir.path()).await?;
        assert!(result.findings.is_empty());
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
