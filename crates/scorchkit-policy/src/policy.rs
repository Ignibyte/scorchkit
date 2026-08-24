//! Provider-neutral engagement authorization.
//!
//! This module is deliberately independent of CLI, MCP, storage, and agent
//! providers. It turns an engagement's target grants, capabilities, and effect
//! classes into a structured allow or deny decision that every host can audit.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use super::scope::ScopeRule;

/// The operational effect a scan or module may have on its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectClass {
    /// Reads already-available data without intentionally changing target state.
    Passive,
    /// Sends bounded probes that should not mutate persistent target state.
    ActiveSafe,
    /// Exercises inputs in ways that may trigger application behavior or alerts.
    Intrusive,
    /// Uses supplied credentials or tests authentication behavior.
    CredentialTest,
    /// Attempts exploitation or another explicitly high-impact action.
    Exploit,
}

/// A separately granted operation available to an execution host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// Run web DAST or reconnaissance modules.
    DastScan,
    /// Read and analyze a local codebase.
    CodeScan,
    /// Probe hosts, ports, protocols, or network ranges.
    InfraScan,
    /// Read cloud-provider or Kubernetes posture data.
    CloudScan,
    /// Launch an external scanner or tool process.
    ExternalTool,
    /// Execute a digest-bound isolated third-party extension.
    ExtensionExecute,
    /// Use credentials supplied for an engagement.
    CredentialUse,
    /// Execute an exploit capability.
    Exploit,
    /// Read or write an explicitly authorized local `ScorchKit` state path.
    LocalState,
    /// Retrieve a security-provider snapshot outside scan-time execution.
    ProviderRefresh,
    /// Deliver a redacted application event to a configured webhook destination.
    WebhookDelivery,
}

/// A normalized target presented to the policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PolicyTarget {
    /// HTTP or HTTPS target.
    Web(Url),
    /// Host, address, endpoint, or CIDR.
    Network(String),
    /// Canonical local code path.
    Code(PathBuf),
    /// Cloud account, project, subscription, or Kubernetes context.
    Cloud(String),
}

impl PolicyTarget {
    /// Parse and normalize an HTTP or HTTPS policy target.
    ///
    /// # Errors
    ///
    /// Returns a URL parse error or rejects non-HTTP schemes and hostless URLs.
    pub fn web(input: &str) -> Result<Self, PolicyTargetError> {
        let url = Url::parse(input).map_err(PolicyTargetError::Url)?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(PolicyTargetError::UnsupportedWebTarget(input.to_string()));
        }
        Ok(Self::Web(url))
    }

    /// Normalize an existing local path for policy comparison.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the target does not exist or cannot be canonicalized.
    pub fn code(path: &Path) -> Result<Self, PolicyTargetError> {
        path.canonicalize().map(Self::Code).map_err(PolicyTargetError::Path)
    }

    /// Create a network policy target after trimming operator input.
    #[must_use]
    pub fn network(input: impl Into<String>) -> Self {
        Self::Network(input.into().trim().to_string())
    }

    /// Create a cloud policy target after trimming operator input.
    #[must_use]
    pub fn cloud(input: impl Into<String>) -> Self {
        Self::Cloud(input.into().trim().to_string())
    }
}

impl std::fmt::Display for PolicyTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Web(url) => formatter.write_str(url.as_str()),
            Self::Network(target) | Self::Cloud(target) => formatter.write_str(target),
            Self::Code(path) => write!(formatter, "{}", path.display()),
        }
    }
}

/// Failure to normalize a target before authorization.
#[derive(Debug, thiserror::Error)]
pub enum PolicyTargetError {
    /// URL syntax is invalid.
    #[error("invalid URL: {0}")]
    Url(url::ParseError),
    /// The URL is not a host-bearing HTTP(S) target.
    #[error("unsupported web policy target '{0}'")]
    UnsupportedWebTarget(String),
    /// A code path is absent or cannot be resolved safely.
    #[error("cannot resolve code target: {0}")]
    Path(std::io::Error),
}

/// Fail-closed grants attached to an engagement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EngagementPolicy {
    /// Target rules that can grant access. An empty set grants nothing.
    pub allowed_scope: Vec<ScopeRule>,
    /// Target rules that override any matching allow rule.
    pub denied_scope: Vec<ScopeRule>,
    /// Operations that may be executed.
    pub capabilities: BTreeSet<Capability>,
    /// Effects that may be produced. Grants are exact, not ordinal.
    pub effects: BTreeSet<EffectClass>,
}

impl EngagementPolicy {
    /// Add an allowed target rule.
    #[must_use]
    pub fn allow_scope(mut self, rule: ScopeRule) -> Self {
        self.allowed_scope.push(rule);
        self
    }

    /// Add a denied target rule. Denials always override grants.
    #[must_use]
    pub fn deny_scope(mut self, rule: ScopeRule) -> Self {
        self.denied_scope.push(rule);
        self
    }

    /// Grant one operation capability.
    #[must_use]
    pub fn allow_capability(mut self, capability: Capability) -> Self {
        self.capabilities.insert(capability);
        self
    }

    /// Grant one exact effect class.
    #[must_use]
    pub fn allow_effect(mut self, effect: EffectClass) -> Self {
        self.effects.insert(effect);
        self
    }

    fn matching_rule(&self, target: &PolicyTarget) -> Option<&ScopeRule> {
        self.allowed_scope.iter().find(|rule| rule_matches(rule, target))
    }

    fn denied_rule(&self, target: &PolicyTarget) -> Option<&ScopeRule> {
        self.denied_scope.iter().find(|rule| rule_matches(rule, target))
    }
}

/// A bounded authorization context shared by all agent and human hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Engagement {
    /// Stable engagement identifier used in audit records.
    pub id: Uuid,
    /// Operator-facing engagement name.
    pub name: String,
    /// Whether new effects may be authorized.
    pub enabled: bool,
    /// Optional time after which all operations are denied.
    pub expires_at: Option<DateTime<Utc>>,
    /// Target, capability, and effect grants.
    pub policy: EngagementPolicy,
}

impl Engagement {
    /// Create an enabled engagement with a new identifier and no expiry.
    #[must_use]
    pub fn new(name: impl Into<String>, policy: EngagementPolicy) -> Self {
        Self { id: Uuid::new_v4(), name: name.into(), enabled: true, expires_at: None, policy }
    }

    /// Set the engagement expiry.
    #[must_use]
    pub const fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Evaluate one target/capability/effect tuple without producing side effects.
    #[must_use]
    pub fn authorize(
        &self,
        target: PolicyTarget,
        capability: Capability,
        effect: EffectClass,
    ) -> AuthorizationDecision {
        let denial = if !self.enabled {
            Some(DenialReason::EngagementDisabled)
        } else if self.expires_at.is_some_and(|expiry| expiry <= Utc::now()) {
            Some(DenialReason::EngagementExpired)
        } else if !self.policy.capabilities.contains(&capability) {
            Some(DenialReason::CapabilityNotGranted)
        } else if !self.policy.effects.contains(&effect) {
            Some(DenialReason::EffectNotGranted)
        } else if let Some(rule) = self.policy.denied_rule(&target) {
            Some(DenialReason::TargetExplicitlyDenied { rule: rule.clone() })
        } else if self.policy.matching_rule(&target).is_none() {
            Some(DenialReason::TargetOutOfScope)
        } else {
            None
        };

        let matched_scope =
            denial.is_none().then(|| self.policy.matching_rule(&target).cloned()).flatten();

        AuthorizationDecision {
            engagement_id: self.id,
            target,
            capability,
            effect,
            allowed: denial.is_none(),
            matched_scope,
            denial,
        }
    }
}

/// A structured reason for a denied operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DenialReason {
    /// The engagement has been administratively disabled.
    #[error("engagement is disabled")]
    EngagementDisabled,
    /// The engagement is past its expiry.
    #[error("engagement is expired")]
    EngagementExpired,
    /// The requested operation was not granted.
    #[error("capability is not granted")]
    CapabilityNotGranted,
    /// The requested effect class was not granted.
    #[error("effect class is not granted")]
    EffectNotGranted,
    /// A deny rule overrode any matching allow rule.
    #[error("target is explicitly denied by scope rule")]
    TargetExplicitlyDenied {
        /// The rule that denied the target.
        rule: ScopeRule,
    },
    /// No allowed scope rule covered the target.
    #[error("target is outside the engagement scope")]
    TargetOutOfScope,
}

/// Auditable result of an engagement-policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    /// Engagement that made the decision.
    pub engagement_id: Uuid,
    /// Normalized target evaluated by the policy.
    pub target: PolicyTarget,
    /// Requested capability.
    pub capability: Capability,
    /// Requested effect class.
    pub effect: EffectClass,
    /// Whether the operation is authorized.
    pub allowed: bool,
    /// Allow rule that matched, present only for successful decisions.
    pub matched_scope: Option<ScopeRule>,
    /// Denial reason, present only for rejected decisions.
    pub denial: Option<DenialReason>,
}

impl AuthorizationDecision {
    /// Return whether this decision is an exact successful grant for one tuple.
    #[must_use]
    pub(crate) fn grants_exactly(
        &self,
        target: &PolicyTarget,
        capability: Capability,
        effect: EffectClass,
    ) -> bool {
        self.allowed
            && self.capability == capability
            && self.effect == effect
            && self.target == *target
    }

    /// Convert a denial into a typed error while preserving allowed decisions.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyViolation`] when `allowed` is false.
    pub fn require(self) -> Result<Self, PolicyViolation> {
        if self.allowed {
            return Ok(self);
        }
        Err(PolicyViolation { decision: Box::new(self) })
    }
}

/// Error returned when an operation attempts to cross an engagement boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyViolation {
    /// Complete structured decision suitable for audit serialization.
    pub decision: Box<AuthorizationDecision>,
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "engagement {} denied {:?}/{:?} for {}",
            self.decision.engagement_id,
            self.decision.capability,
            self.decision.effect,
            self.decision.target
        )?;
        match &self.decision.denial {
            Some(reason) => write!(formatter, ": {reason}"),
            None => formatter.write_str(": policy denied the operation"),
        }
    }
}

impl std::error::Error for PolicyViolation {}

fn rule_matches(rule: &ScopeRule, target: &PolicyTarget) -> bool {
    match target {
        PolicyTarget::Web(url) => url.host_str().is_some_and(|host| rule.matches(host)),
        PolicyTarget::Network(target) => rule.matches_network(target),
        PolicyTarget::Code(path) => rule.matches_path(path),
        PolicyTarget::Cloud(resource) => rule.matches_cloud(resource),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn web_policy() -> EngagementPolicy {
        EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.com").unwrap())
            .allow_scope(ScopeRule::parse("*.example.com").unwrap())
            .deny_scope(ScopeRule::parse("admin.example.com").unwrap())
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::ActiveSafe)
    }

    #[test]
    fn policy_is_fail_closed_by_default() {
        let engagement = Engagement::new("empty", EngagementPolicy::default());
        let decision = engagement.authorize(
            PolicyTarget::web("https://example.com").unwrap(),
            Capability::DastScan,
            EffectClass::ActiveSafe,
        );
        assert!(!decision.allowed);
        assert_eq!(decision.denial, Some(DenialReason::CapabilityNotGranted));
    }

    #[test]
    fn policy_targets_reject_unsupported_schemes_and_display_canonically() {
        assert!(matches!(
            PolicyTarget::web("ftp://example.com"),
            Err(PolicyTargetError::UnsupportedWebTarget(_))
        ));

        let web = PolicyTarget::web("https://example.com/path").unwrap();
        assert_eq!(web.to_string(), "https://example.com/path");
        assert_eq!(PolicyTarget::network(" 10.0.0.1 ").to_string(), "10.0.0.1");
        assert_eq!(PolicyTarget::cloud(" gcp:project-a ").to_string(), "gcp:project-a");

        let root = tempfile::tempdir().unwrap();
        let code = PolicyTarget::code(root.path()).unwrap();
        assert_eq!(code.to_string(), root.path().canonicalize().unwrap().display().to_string());
    }

    #[test]
    fn policy_requires_scope_capability_and_exact_effect_grants() {
        let cases = [
            ("https://example.com", Capability::DastScan, EffectClass::ActiveSafe, true),
            ("https://api.example.com", Capability::DastScan, EffectClass::ActiveSafe, true),
            ("https://evil.test", Capability::DastScan, EffectClass::ActiveSafe, false),
            ("https://example.com", Capability::ExternalTool, EffectClass::ActiveSafe, false),
            ("https://example.com", Capability::DastScan, EffectClass::Intrusive, false),
        ];
        let engagement = Engagement::new("web", web_policy());

        for (target, capability, effect, expected) in cases {
            let decision =
                engagement.authorize(PolicyTarget::web(target).unwrap(), capability, effect);
            assert_eq!(decision.allowed, expected, "decision for {target}");
        }
    }

    #[test]
    fn explicit_deny_overrides_wildcard_allow() {
        let engagement = Engagement::new("web", web_policy());
        let decision = engagement.authorize(
            PolicyTarget::web("https://admin.example.com").unwrap(),
            Capability::DastScan,
            EffectClass::ActiveSafe,
        );
        assert!(matches!(decision.denial, Some(DenialReason::TargetExplicitlyDenied { .. })));
    }

    #[test]
    fn disabled_and_expired_engagements_deny_before_scope() {
        let mut disabled = Engagement::new("disabled", web_policy());
        disabled.enabled = false;
        let target = PolicyTarget::web("https://example.com").unwrap();
        assert_eq!(
            disabled
                .authorize(target.clone(), Capability::DastScan, EffectClass::ActiveSafe)
                .denial,
            Some(DenialReason::EngagementDisabled)
        );

        let expired =
            Engagement::new("expired", web_policy()).expires_at(Utc::now() - Duration::seconds(1));
        assert_eq!(
            expired.authorize(target, Capability::DastScan, EffectClass::ActiveSafe).denial,
            Some(DenialReason::EngagementExpired)
        );
    }

    #[test]
    fn path_and_cloud_scopes_are_target_kind_specific() {
        let root = tempfile::tempdir().unwrap();
        let code_rule = ScopeRule::path_prefix(root.path()).unwrap();
        let policy = EngagementPolicy::default()
            .allow_scope(code_rule)
            .allow_scope(ScopeRule::cloud("gcp:project-a"))
            .allow_capability(Capability::CodeScan)
            .allow_capability(Capability::CloudScan)
            .allow_effect(EffectClass::Passive);
        let engagement = Engagement::new("mixed", policy);

        assert!(
            engagement
                .authorize(
                    PolicyTarget::code(root.path()).unwrap(),
                    Capability::CodeScan,
                    EffectClass::Passive
                )
                .allowed
        );
        assert!(
            engagement
                .authorize(
                    PolicyTarget::cloud("gcp:project-a"),
                    Capability::CloudScan,
                    EffectClass::Passive
                )
                .allowed
        );
        assert!(
            !engagement
                .authorize(
                    PolicyTarget::cloud("gcp:project-b"),
                    Capability::CloudScan,
                    EffectClass::Passive
                )
                .allowed
        );
    }

    #[test]
    fn decision_round_trips_as_structured_json() {
        let engagement = Engagement::new("web", web_policy());
        let decision = engagement.authorize(
            PolicyTarget::web("https://example.com").unwrap(),
            Capability::DastScan,
            EffectClass::ActiveSafe,
        );
        let json = serde_json::to_string(&decision).unwrap();
        let decoded: AuthorizationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, decision);
    }

    #[test]
    fn denied_decision_becomes_policy_violation() {
        let engagement = Engagement::new("web", web_policy());
        let decision = engagement.authorize(
            PolicyTarget::web("https://outside.test").unwrap(),
            Capability::DastScan,
            EffectClass::ActiveSafe,
        );
        let error = decision.require().unwrap_err();
        assert!(error.to_string().contains("outside the engagement scope"));
    }

    #[test]
    fn exact_grant_matching_requires_every_decision_field() {
        let engagement = Engagement::new("web", web_policy());
        let target = PolicyTarget::web("https://example.com").unwrap();
        let decision =
            engagement.authorize(target.clone(), Capability::DastScan, EffectClass::ActiveSafe);

        assert!(decision.grants_exactly(&target, Capability::DastScan, EffectClass::ActiveSafe));

        let mut denied = decision.clone();
        denied.allowed = false;
        assert!(!denied.grants_exactly(&target, Capability::DastScan, EffectClass::ActiveSafe));

        assert!(!decision.grants_exactly(
            &target,
            Capability::ExternalTool,
            EffectClass::ActiveSafe
        ));
        assert!(!decision.grants_exactly(&target, Capability::DastScan, EffectClass::Intrusive));
        assert!(!decision.grants_exactly(
            &PolicyTarget::web("https://outside.test").unwrap(),
            Capability::DastScan,
            EffectClass::ActiveSafe
        ));
    }
}
