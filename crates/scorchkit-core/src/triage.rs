//! Append-only finding validation, triage, correlation, and suppression contracts.
//!
//! Scanner findings and evidence remain immutable inputs. These records describe later human or
//! deterministic system decisions and carry no execution or authorization capability.

use std::collections::BTreeSet;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::observation::{canonical_json_sha256, redact_text, CorrelationKey, FindingRecordV2};

/// Canonical triage projection schema.
pub const FINDING_TRIAGE_SCHEMA_V1: &str = "scorchkit.finding-triage/v1";
/// Append-only transition schema.
pub const FINDING_TRIAGE_TRANSITION_SCHEMA_V1: &str = "scorchkit.finding-triage-transition/v1";
/// Append-only correlation-decision schema.
pub const FINDING_CORRELATION_DECISION_SCHEMA_V1: &str =
    "scorchkit.finding-correlation-decision/v1";
/// Append-only suppression schema.
pub const FINDING_SUPPRESSION_SCHEMA_V1: &str = "scorchkit.finding-suppression/v1";

/// Maximum transitions reconstructed for one finding.
pub const MAX_TRIAGE_TRANSITIONS: usize = 1_000;
/// Maximum correlation decisions reconstructed for one finding.
pub const MAX_TRIAGE_CORRELATIONS: usize = 1_000;
/// Maximum suppressions in one project ledger or reconstructed finding projection.
pub const MAX_TRIAGE_SUPPRESSIONS: usize = 1_000;
/// Maximum identities in one transition or correlation dimension.
pub const MAX_TRIAGE_REFERENCES: usize = 256;
/// Maximum bytes in an actor identity.
pub const MAX_TRIAGE_ACTOR_BYTES: usize = 256;
/// Maximum bytes in a reason or explanation.
pub const MAX_TRIAGE_TEXT_BYTES: usize = 4_096;
/// Maximum bytes in a project or compatibility finding identity.
pub const MAX_TRIAGE_IDENTITY_BYTES: usize = 512;

/// Closed finding-validation and triage state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingTriageState {
    /// More application context or comparable proof is required.
    NeedsContext,
    /// Evidence likely represents a real issue but is not fully validated.
    Likely,
    /// Evidence validates the issue in the assessed application.
    Validated,
    /// Detector output does not represent the asserted issue.
    FalsePositive,
    /// The issue is real and an authorized actor accepted its bounded risk.
    AcceptedRisk,
    /// A fix was applied and accepted or verified.
    Fixed,
    /// A previously fixed finding reappeared under the same stable identity.
    Regressed,
}

impl FindingTriageState {
    /// Stable public label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeedsContext => "needs_context",
            Self::Likely => "likely",
            Self::Validated => "validated",
            Self::FalsePositive => "false_positive",
            Self::AcceptedRisk => "accepted_risk",
            Self::Fixed => "fixed",
            Self::Regressed => "regressed",
        }
    }
}

impl FromStr for FindingTriageState {
    type Err = TriageValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "needs_context" => Ok(Self::NeedsContext),
            "likely" => Ok(Self::Likely),
            "validated" => Ok(Self::Validated),
            "false_positive" => Ok(Self::FalsePositive),
            "accepted_risk" => Ok(Self::AcceptedRisk),
            "fixed" => Ok(Self::Fixed),
            "regressed" => Ok(Self::Regressed),
            _ => Err(TriageValidationError::Normalization),
        }
    }
}

/// Origin of an append-only decision. Identity is attribution, never authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageActorKind {
    /// Authenticated or local-process human/operator command.
    Human,
    /// Deterministic engine transition such as migration or rediscovery.
    System,
}

impl TriageActorKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::System => "system",
        }
    }
}

/// Safe attributed actor attached to a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageActor {
    /// Actor class.
    pub kind: TriageActorKind,
    /// Transport-established or engine-owned identity after redaction.
    pub identity: String,
}

impl TriageActor {
    /// Construct a canonically redacted actor.
    #[must_use]
    pub fn new(kind: TriageActorKind, identity: impl Into<String>) -> Self {
        Self { kind, identity: redact_text(identity.into().trim()) }
    }

    fn is_canonical(&self) -> bool {
        self == &Self::new(self.kind, self.identity.clone())
            && bounded_value(&self.identity, MAX_TRIAGE_ACTOR_BYTES)
    }
}

/// One canonical append-only state transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingTriageTransition {
    /// Transition schema.
    pub schema: String,
    /// Deterministic transition identity.
    pub identity: String,
    /// Parent stable finding identity.
    pub finding_identity: String,
    /// One-based causal position in this finding's history.
    pub sequence: u32,
    /// Previous state, absent only for the first transition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<FindingTriageState>,
    /// State after this decision.
    pub to: FindingTriageState,
    /// Attributed actor. Authorization is independently enforced by the host.
    pub actor: TriageActor,
    /// Required redacted rationale.
    pub reason: String,
    /// Sorted exact scanner-evidence identities supporting the decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<String>,
    /// Optional same-finding model-analysis identity used only as provenance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_analysis_identity: Option<String>,
    /// Trusted observation time.
    pub observed_at: DateTime<Utc>,
}

impl FindingTriageTransition {
    /// Construct a canonical transition.
    #[must_use]
    pub fn new(
        finding_identity: impl Into<String>,
        sequence: u32,
        from: Option<FindingTriageState>,
        to: FindingTriageState,
        actor: TriageActor,
        reason: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let finding_identity = finding_identity.into().trim().to_string();
        let actor = TriageActor::new(actor.kind, actor.identity);
        let reason = redact_text(reason.into().trim());
        let mut transition = Self {
            schema: FINDING_TRIAGE_TRANSITION_SCHEMA_V1.to_string(),
            identity: String::new(),
            finding_identity,
            sequence,
            from,
            to,
            actor,
            reason,
            evidence_ids: Vec::new(),
            model_analysis_identity: None,
            observed_at,
        };
        transition.refresh_identity();
        transition
    }

    /// Attach exact scanner-evidence and optional same-finding model-analysis identities.
    #[must_use]
    pub fn with_references(
        mut self,
        evidence_ids: Vec<String>,
        model_analysis_identity: Option<String>,
    ) -> Self {
        self.evidence_ids = normalized_digests(evidence_ids);
        self.model_analysis_identity = model_analysis_identity
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self.refresh_identity();
        self
    }

    fn refresh_identity(&mut self) {
        self.identity = transition_identity(self);
    }

    /// Validate a transition restored or supplied outside its constructor.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed, noncanonical, or impossible fields.
    pub fn validate(&self) -> Result<(), TriageValidationError> {
        if self.schema != FINDING_TRIAGE_TRANSITION_SCHEMA_V1 {
            return Err(TriageValidationError::Schema);
        }
        if self.sequence == 0
            || !bounded_value(&self.finding_identity, MAX_TRIAGE_IDENTITY_BYTES)
            || !self.actor.is_canonical()
            || !bounded_value(&self.reason, MAX_TRIAGE_TEXT_BYTES)
            || self.evidence_ids.len() > MAX_TRIAGE_REFERENCES
            || !ordered_unique_digests(&self.evidence_ids)
            || self.model_analysis_identity.as_ref().is_some_and(|value| !is_digest(value))
            || self.from == Some(self.to)
        {
            return Err(TriageValidationError::Normalization);
        }
        if self.from.is_none() != (self.sequence == 1) {
            return Err(TriageValidationError::History);
        }
        if self.sequence == 1 && self.to == FindingTriageState::Regressed {
            return Err(TriageValidationError::Transition);
        }
        if self.from.is_some_and(|from| !transition_allowed(from, self.to)) {
            return Err(TriageValidationError::Transition);
        }
        let rebuilt = Self::new(
            self.finding_identity.clone(),
            self.sequence,
            self.from,
            self.to,
            self.actor.clone(),
            self.reason.clone(),
            self.observed_at,
        )
        .with_references(self.evidence_ids.clone(), self.model_analysis_identity.clone());
        if self != &rebuilt {
            return Err(TriageValidationError::Identity);
        }
        Ok(())
    }
}

/// Canonical ordered state history for one finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingTriageHistory {
    /// Projection schema.
    pub schema: String,
    /// Parent stable finding identity.
    pub finding_identity: String,
    /// Current state reconstructed from the final transition.
    pub current_state: FindingTriageState,
    /// Complete causal history.
    pub transitions: Vec<FindingTriageTransition>,
}

impl FindingTriageHistory {
    /// Create a canonical first transition.
    #[must_use]
    pub fn initial(
        finding_identity: impl Into<String>,
        state: FindingTriageState,
        actor: TriageActor,
        reason: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let finding_identity = finding_identity.into();
        let transition = FindingTriageTransition::new(
            &finding_identity,
            1,
            None,
            state,
            actor,
            reason,
            observed_at,
        );
        Self {
            schema: FINDING_TRIAGE_SCHEMA_V1.to_string(),
            finding_identity,
            current_state: state,
            transitions: vec![transition],
        }
    }

    /// Append one exact next transition.
    ///
    /// # Errors
    ///
    /// Rejects a malformed transition, wrong parent/sequence/from state, or history overflow.
    pub fn append(
        &mut self,
        transition: FindingTriageTransition,
    ) -> Result<(), TriageValidationError> {
        self.validate()?;
        transition.validate()?;
        if self.transitions.len() >= MAX_TRIAGE_TRANSITIONS {
            return Err(TriageValidationError::Limit);
        }
        let expected_sequence = u32::try_from(self.transitions.len())
            .map_err(|_| TriageValidationError::Limit)?
            .checked_add(1)
            .ok_or(TriageValidationError::Limit)?;
        if transition.finding_identity != self.finding_identity
            || transition.sequence != expected_sequence
            || transition.from != Some(self.current_state)
        {
            return Err(TriageValidationError::History);
        }
        self.current_state = transition.to;
        self.transitions.push(transition);
        Ok(())
    }

    /// Validate the complete ordered history and current-state projection.
    ///
    /// # Errors
    ///
    /// Rejects malformed schema, parent, sequence, transition, ordering, or current state.
    pub fn validate(&self) -> Result<(), TriageValidationError> {
        if self.schema != FINDING_TRIAGE_SCHEMA_V1
            || !bounded_value(&self.finding_identity, MAX_TRIAGE_IDENTITY_BYTES)
        {
            return Err(TriageValidationError::Schema);
        }
        if self.transitions.is_empty() || self.transitions.len() > MAX_TRIAGE_TRANSITIONS {
            return Err(TriageValidationError::Limit);
        }
        let mut previous = None;
        for (index, transition) in self.transitions.iter().enumerate() {
            transition.validate()?;
            let sequence = u32::try_from(index)
                .map_err(|_| TriageValidationError::Limit)?
                .checked_add(1)
                .ok_or(TriageValidationError::Limit)?;
            if transition.finding_identity != self.finding_identity
                || transition.sequence != sequence
                || transition.from != previous
            {
                return Err(TriageValidationError::History);
            }
            previous = Some(transition.to);
        }
        if previous != Some(self.current_state) {
            return Err(TriageValidationError::History);
        }
        Ok(())
    }
}

/// One exact finding/scope subject used for suppression matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingTriageSubject {
    /// Owning project identity.
    pub project_identity: String,
    /// Stable finding identity.
    pub finding_identity: String,
    /// Exact scanner/rule/config identity digest when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_identity: Option<String>,
    /// Exact canonical affected-location digest.
    pub target_identity: String,
}

impl FindingTriageSubject {
    /// Derive safe exact identities from a canonical finding record.
    #[must_use]
    pub fn from_record(project_identity: impl Into<String>, record: &FindingRecordV2) -> Self {
        let project_identity = project_identity.into().trim().to_string();
        let rule_identity = record.provenance.rule_id.as_ref().map(|rule_id| {
            digest_parts(
                "scorchkit.triage-rule/v1",
                [
                    record.provenance.scanner_id.as_str(),
                    rule_id.as_str(),
                    record.provenance.rule_digest.as_deref().unwrap_or_default(),
                    record.provenance.config_identity.as_deref().unwrap_or_default(),
                ],
            )
        });
        let target_identity = canonical_json_sha256(
            &serde_json::to_value(&record.location).unwrap_or(serde_json::Value::Null),
        );
        Self {
            project_identity,
            finding_identity: record.identity.value.clone(),
            rule_identity,
            target_identity,
        }
    }

    /// Validate bounded canonical subject fields.
    ///
    /// # Errors
    ///
    /// Returns a normalization error when a project, finding, rule, or target identity is invalid.
    pub fn validate(&self) -> Result<(), TriageValidationError> {
        if !bounded_value(&self.project_identity, MAX_TRIAGE_IDENTITY_BYTES)
            || !bounded_value(&self.finding_identity, MAX_TRIAGE_IDENTITY_BYTES)
            || !is_digest(&self.target_identity)
            || self.rule_identity.as_ref().is_some_and(|value| !is_digest(value))
        {
            return Err(TriageValidationError::Normalization);
        }
        Ok(())
    }
}

/// Closed suppression scope shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSuppressionScopeKind {
    /// One stable finding identity.
    Finding,
    /// One scanner/rule/config identity in the project.
    Rule,
    /// One canonical target/location identity in the project.
    Target,
    /// One exact rule and target pair in the project.
    RuleTarget,
}

impl FindingSuppressionScopeKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Rule => "rule",
            Self::Target => "target",
            Self::RuleTarget => "rule_target",
        }
    }
}

impl FromStr for FindingSuppressionScopeKind {
    type Err = TriageValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "finding" => Ok(Self::Finding),
            "rule" => Ok(Self::Rule),
            "target" => Ok(Self::Target),
            "rule_target" => Ok(Self::RuleTarget),
            _ => Err(TriageValidationError::Scope),
        }
    }
}

/// Exact project-scoped suppression selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSuppressionScope {
    /// Closed scope shape.
    pub kind: FindingSuppressionScopeKind,
    /// Exact project identity.
    pub project_identity: String,
    /// Stable finding identity for finding scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_identity: Option<String>,
    /// Rule digest for rule or rule-target scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_identity: Option<String>,
    /// Target digest for target or rule-target scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_identity: Option<String>,
}

impl FindingSuppressionScope {
    /// Build a scope by selecting the exact required subject dimensions.
    #[must_use]
    pub fn for_subject(kind: FindingSuppressionScopeKind, subject: &FindingTriageSubject) -> Self {
        let (finding_identity, rule_identity, target_identity) = match kind {
            FindingSuppressionScopeKind::Finding => {
                (Some(subject.finding_identity.clone()), None, None)
            }
            FindingSuppressionScopeKind::Rule => (None, subject.rule_identity.clone(), None),
            FindingSuppressionScopeKind::Target => {
                (None, None, Some(subject.target_identity.clone()))
            }
            FindingSuppressionScopeKind::RuleTarget => {
                (None, subject.rule_identity.clone(), Some(subject.target_identity.clone()))
            }
        };
        Self {
            kind,
            project_identity: subject.project_identity.clone(),
            finding_identity,
            rule_identity,
            target_identity,
        }
    }

    /// Validate the exact field presence for the closed scope shape.
    ///
    /// # Errors
    ///
    /// Returns a scope error when fields do not exactly match the declared scope kind.
    pub fn validate(&self) -> Result<(), TriageValidationError> {
        if !bounded_value(&self.project_identity, MAX_TRIAGE_IDENTITY_BYTES) {
            return Err(TriageValidationError::Scope);
        }
        let shape_matches = match self.kind {
            FindingSuppressionScopeKind::Finding => {
                self.finding_identity
                    .as_ref()
                    .is_some_and(|value| bounded_value(value, MAX_TRIAGE_IDENTITY_BYTES))
                    && self.rule_identity.is_none()
                    && self.target_identity.is_none()
            }
            FindingSuppressionScopeKind::Rule => {
                self.finding_identity.is_none()
                    && self.rule_identity.as_ref().is_some_and(|value| is_digest(value))
                    && self.target_identity.is_none()
            }
            FindingSuppressionScopeKind::Target => {
                self.finding_identity.is_none()
                    && self.rule_identity.is_none()
                    && self.target_identity.as_ref().is_some_and(|value| is_digest(value))
            }
            FindingSuppressionScopeKind::RuleTarget => {
                self.finding_identity.is_none()
                    && self.rule_identity.as_ref().is_some_and(|value| is_digest(value))
                    && self.target_identity.as_ref().is_some_and(|value| is_digest(value))
            }
        };
        if !shape_matches {
            return Err(TriageValidationError::Scope);
        }
        Ok(())
    }

    /// Return whether every declared scope dimension exactly matches a subject.
    #[must_use]
    pub fn matches(&self, subject: &FindingTriageSubject) -> bool {
        self.validate().is_ok()
            && subject.validate().is_ok()
            && self.project_identity == subject.project_identity
            && self.finding_identity.as_ref().is_none_or(|value| value == &subject.finding_identity)
            && self
                .rule_identity
                .as_ref()
                .is_none_or(|value| subject.rule_identity.as_ref() == Some(value))
            && self.target_identity.as_ref().is_none_or(|value| value == &subject.target_identity)
    }
}

/// One immutable time-bounded suppression decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSuppression {
    /// Suppression schema.
    pub schema: String,
    /// Deterministic suppression identity.
    pub identity: String,
    /// Exact scope.
    pub scope: FindingSuppressionScope,
    /// Attributed actor.
    pub actor: TriageActor,
    /// Required redacted rationale.
    pub reason: String,
    /// Trusted creation time.
    pub created_at: DateTime<Utc>,
    /// Optional hard expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional mandatory review boundary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_at: Option<DateTime<Utc>>,
}

impl FindingSuppression {
    /// Construct a canonical suppression.
    #[must_use]
    pub fn new(
        scope: FindingSuppressionScope,
        actor: TriageActor,
        reason: impl Into<String>,
        created_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        review_at: Option<DateTime<Utc>>,
    ) -> Self {
        let actor = TriageActor::new(actor.kind, actor.identity);
        let reason = redact_text(reason.into().trim());
        let identity =
            suppression_identity(&scope, &actor, &reason, created_at, expires_at, review_at);
        Self {
            schema: FINDING_SUPPRESSION_SCHEMA_V1.to_string(),
            identity,
            scope,
            actor,
            reason,
            created_at,
            expires_at,
            review_at,
        }
    }

    /// Validate shape, canonical content, identity, and finite lifetime.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed scope, actor, rationale, time, or identity.
    pub fn validate(&self) -> Result<(), TriageValidationError> {
        if self.schema != FINDING_SUPPRESSION_SCHEMA_V1 {
            return Err(TriageValidationError::Schema);
        }
        self.scope.validate()?;
        if !self.actor.is_canonical()
            || !bounded_value(&self.reason, MAX_TRIAGE_TEXT_BYTES)
            || (self.expires_at.is_none() && self.review_at.is_none())
            || self.expires_at.is_some_and(|value| value <= self.created_at)
            || self.review_at.is_some_and(|value| value <= self.created_at)
        {
            return Err(TriageValidationError::Time);
        }
        let rebuilt = Self::new(
            self.scope.clone(),
            self.actor.clone(),
            self.reason.clone(),
            self.created_at,
            self.expires_at,
            self.review_at,
        );
        if self != &rebuilt {
            return Err(TriageValidationError::Identity);
        }
        Ok(())
    }

    /// Return whether this suppression is currently active for the exact subject.
    #[must_use]
    pub fn is_active_for(&self, subject: &FindingTriageSubject, at: DateTime<Utc>) -> bool {
        self.validate().is_ok()
            && at >= self.created_at
            && self.expires_at.is_none_or(|expiry| at < expiry)
            && self.review_at.is_none_or(|review| at < review)
            && self.scope.matches(subject)
    }
}

/// One immutable explanation of a deduplication or correlation decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingCorrelationDecision {
    /// Decision schema.
    pub schema: String,
    /// Deterministic decision identity.
    pub identity: String,
    /// Parent stable finding identity.
    pub finding_identity: String,
    /// Sorted contributing stable finding identities.
    pub contributing_finding_identities: Vec<String>,
    /// Sorted contributing scanner identities.
    pub scanner_ids: Vec<String>,
    /// Sorted contributing evidence identities.
    pub evidence_ids: Vec<String>,
    /// Sorted normalized facets that explain the relation.
    pub facets: Vec<CorrelationKey>,
    /// Bounded redacted human-readable explanation.
    pub explanation: String,
    /// Attributed authorized actor or deterministic engine owner.
    pub actor: TriageActor,
    /// Trusted decision time.
    pub created_at: DateTime<Utc>,
}

/// Exact bounded identities and facets contributing to one correlation decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingCorrelationContributors {
    /// Stable finding identities.
    pub finding_identities: Vec<String>,
    /// Scanner identities.
    pub scanner_ids: Vec<String>,
    /// Scanner-evidence identities.
    pub evidence_ids: Vec<String>,
    /// Exact normalized correlation facets.
    pub facets: Vec<CorrelationKey>,
}

impl FindingCorrelationDecision {
    /// Construct a canonical correlation decision.
    #[must_use]
    pub fn new(
        finding_identity: impl Into<String>,
        contributors: FindingCorrelationContributors,
        explanation: impl Into<String>,
        actor: TriageActor,
        created_at: DateTime<Utc>,
    ) -> Self {
        let finding_identity = finding_identity.into().trim().to_string();
        let contributing_finding_identities = normalized_values(contributors.finding_identities);
        let scanner_ids: Vec<String> = normalized_values(contributors.scanner_ids)
            .into_iter()
            .map(|value| redact_text(&value))
            .collect();
        let evidence_ids = normalized_digests(contributors.evidence_ids);
        let facets = normalized_facets(contributors.facets);
        let explanation = redact_text(explanation.into().trim());
        let actor = TriageActor::new(actor.kind, actor.identity);
        let mut decision = Self {
            schema: FINDING_CORRELATION_DECISION_SCHEMA_V1.to_string(),
            identity: String::new(),
            finding_identity,
            contributing_finding_identities,
            scanner_ids,
            evidence_ids,
            facets,
            explanation,
            actor,
            created_at,
        };
        decision.identity = correlation_identity(&decision);
        decision
    }

    /// Validate canonical ordering, limits, redaction, and identity.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed schema, contributors, ordering, text, or identity.
    pub fn validate(&self) -> Result<(), TriageValidationError> {
        if self.schema != FINDING_CORRELATION_DECISION_SCHEMA_V1 {
            return Err(TriageValidationError::Schema);
        }
        if !bounded_value(&self.finding_identity, MAX_TRIAGE_IDENTITY_BYTES)
            || self.contributing_finding_identities.is_empty()
            || self.scanner_ids.is_empty()
            || self.evidence_ids.is_empty()
            || self.contributing_finding_identities.len() > MAX_TRIAGE_REFERENCES
            || self.scanner_ids.len() > MAX_TRIAGE_REFERENCES
            || self.evidence_ids.len() > MAX_TRIAGE_REFERENCES
            || self.facets.len() > MAX_TRIAGE_REFERENCES
            || !ordered_unique_values(&self.contributing_finding_identities)
            || !ordered_unique_values(&self.scanner_ids)
            || !ordered_unique_digests(&self.evidence_ids)
            || normalized_facets(self.facets.clone()) != self.facets
            || self.facets.iter().any(|facet| {
                !bounded_value(&facet.namespace, MAX_TRIAGE_IDENTITY_BYTES)
                    || !bounded_value(&facet.value, MAX_TRIAGE_IDENTITY_BYTES)
            })
            || !bounded_value(&self.explanation, MAX_TRIAGE_TEXT_BYTES)
            || !self.actor.is_canonical()
            || (self.contributing_finding_identities.len() < 2 && self.scanner_ids.len() < 2)
        {
            return Err(TriageValidationError::Normalization);
        }
        let rebuilt = Self::new(
            self.finding_identity.clone(),
            FindingCorrelationContributors {
                finding_identities: self.contributing_finding_identities.clone(),
                scanner_ids: self.scanner_ids.clone(),
                evidence_ids: self.evidence_ids.clone(),
                facets: self.facets.clone(),
            },
            self.explanation.clone(),
            self.actor.clone(),
            self.created_at,
        );
        if self != &rebuilt {
            return Err(TriageValidationError::Identity);
        }
        Ok(())
    }
}

/// Complete canonical triage projection attached to a validated public finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingTriage {
    /// Projection schema.
    pub schema: String,
    /// Complete transition history.
    pub history: FindingTriageHistory,
    /// Ordered append-preserved correlation decisions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub correlations: Vec<FindingCorrelationDecision>,
    /// Ordered append-preserved suppressions, including inactive history.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressions: Vec<FindingSuppression>,
}

impl FindingTriage {
    /// Construct a projection from independently loaded canonical children.
    #[must_use]
    pub fn new(
        history: FindingTriageHistory,
        mut correlations: Vec<FindingCorrelationDecision>,
        mut suppressions: Vec<FindingSuppression>,
    ) -> Self {
        correlations.sort_by(|left, right| {
            (left.created_at, &left.identity).cmp(&(right.created_at, &right.identity))
        });
        suppressions.sort_by(|left, right| {
            (left.created_at, &left.identity).cmp(&(right.created_at, &right.identity))
        });
        Self { schema: FINDING_TRIAGE_SCHEMA_V1.to_string(), history, correlations, suppressions }
    }

    /// Validate the complete projection and every child.
    ///
    /// # Errors
    ///
    /// Returns a typed error for any malformed history, correlation, suppression, or ordering.
    pub fn validate(&self) -> Result<(), TriageValidationError> {
        if self.schema != FINDING_TRIAGE_SCHEMA_V1 {
            return Err(TriageValidationError::Schema);
        }
        self.history.validate()?;
        if self.correlations.len() > MAX_TRIAGE_CORRELATIONS
            || self.suppressions.len() > MAX_TRIAGE_SUPPRESSIONS
            || !self.correlations.windows(2).all(|pair| {
                (pair[0].created_at, pair[0].identity.as_str())
                    < (pair[1].created_at, pair[1].identity.as_str())
            })
            || !self.suppressions.windows(2).all(|pair| {
                (pair[0].created_at, pair[0].identity.as_str())
                    < (pair[1].created_at, pair[1].identity.as_str())
            })
        {
            return Err(TriageValidationError::Limit);
        }
        for correlation in &self.correlations {
            correlation.validate()?;
            if correlation.finding_identity != self.history.finding_identity {
                return Err(TriageValidationError::History);
            }
        }
        for suppression in &self.suppressions {
            suppression.validate()?;
        }
        Ok(())
    }

    /// Return all exact active suppression identities without hiding historical rows.
    #[must_use]
    pub fn active_suppression_ids(
        &self,
        subject: &FindingTriageSubject,
        at: DateTime<Utc>,
    ) -> Vec<String> {
        self.suppressions
            .iter()
            .filter(|suppression| suppression.is_active_for(subject, at))
            .map(|suppression| suppression.identity.clone())
            .collect()
    }
}

/// Return the new canonical state represented by a legacy lifecycle status.
#[must_use]
pub fn triage_state_from_legacy(status: &str) -> Option<FindingTriageState> {
    match status {
        "new" => Some(FindingTriageState::NeedsContext),
        "acknowledged" => Some(FindingTriageState::Validated),
        "false_positive" => Some(FindingTriageState::FalsePositive),
        "wont_fix" | "accepted_risk" => Some(FindingTriageState::AcceptedRisk),
        "remediated" | "verified" => Some(FindingTriageState::Fixed),
        _ => None,
    }
}

/// Return the compatibility status projected from a canonical triage state.
#[must_use]
pub const fn legacy_status_for_triage(state: FindingTriageState) -> &'static str {
    match state {
        FindingTriageState::NeedsContext | FindingTriageState::Regressed => "new",
        FindingTriageState::Likely | FindingTriageState::Validated => "acknowledged",
        FindingTriageState::FalsePositive => "false_positive",
        FindingTriageState::AcceptedRisk => "accepted_risk",
        FindingTriageState::Fixed => "verified",
    }
}

/// Digest material scanner proof while excluding observation timestamps and derived identities.
///
/// This is used only to decide whether a prior disposition needs review. It does not replace the
/// canonical evidence identity or finding identity.
#[must_use]
pub fn material_finding_evidence_identity(record: &FindingRecordV2) -> String {
    let evidence: Vec<_> = record
        .evidence
        .iter()
        .map(|item| {
            serde_json::json!({
                "scanner_id": item.provenance.scanner_id,
                "scanner_version": item.provenance.scanner_version,
                "rule_id": item.provenance.rule_id,
                "rule_digest": item.provenance.rule_digest,
                "config_identity": item.provenance.config_identity,
                "target_revision": item.provenance.target_revision,
                "redaction": item.redaction,
                "payload": item.payload,
            })
        })
        .collect();
    canonical_json_sha256(&serde_json::json!({
        "location": record.location,
        "scanner_id": record.provenance.scanner_id,
        "scanner_version": record.provenance.scanner_version,
        "rule_id": record.provenance.rule_id,
        "rule_digest": record.provenance.rule_digest,
        "config_identity": record.provenance.config_identity,
        "target_revision": record.provenance.target_revision,
        "correlation_keys": record.correlation_keys,
        "code_flows": record.code_flows,
        "evidence": evidence,
    }))
}

/// Canonical validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TriageValidationError {
    /// Unsupported or inconsistent schema.
    #[error("triage schema is unsupported")]
    Schema,
    /// A value, collection, or redaction form is noncanonical.
    #[error("triage value is not canonical")]
    Normalization,
    /// Deterministic identity does not match the content.
    #[error("triage identity does not match content")]
    Identity,
    /// Transition is not allowed by the closed state machine.
    #[error("triage state transition is not allowed")]
    Transition,
    /// Ordered history, parent, sequence, or current state is inconsistent.
    #[error("triage history is inconsistent")]
    History,
    /// A collection exceeds its hard limit.
    #[error("triage collection exceeds its limit")]
    Limit,
    /// Suppression scope is malformed or incomplete.
    #[error("triage suppression scope is invalid")]
    Scope,
    /// Suppression lifetime is absent or invalid.
    #[error("triage suppression time boundary is invalid")]
    Time,
}

fn transition_allowed(from: FindingTriageState, to: FindingTriageState) -> bool {
    from != to && (to != FindingTriageState::Regressed || from == FindingTriageState::Fixed)
}

fn bounded_value(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && redact_text(value) == value
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn normalized_digests(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalized_values(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalized_facets(values: Vec<CorrelationKey>) -> Vec<CorrelationKey> {
    values
        .into_iter()
        .map(|value| CorrelationKey::new(value.namespace, value.value))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn ordered_unique_digests(values: &[String]) -> bool {
    values.iter().all(|value| is_digest(value)) && ordered_unique_values(values)
}

fn ordered_unique_values(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
        && values.iter().all(|value| bounded_value(value, MAX_TRIAGE_IDENTITY_BYTES))
}

fn transition_identity(transition: &FindingTriageTransition) -> String {
    let sequence = transition.sequence.to_string();
    let from = transition.from.map_or("", FindingTriageState::as_str);
    let evidence = transition.evidence_ids.join("\0");
    let micros = transition.observed_at.timestamp_micros().to_string();
    digest_parts(
        "scorchkit.finding-triage-transition/v1",
        [
            &transition.finding_identity,
            &sequence,
            from,
            transition.to.as_str(),
            transition.actor.kind.as_str(),
            &transition.actor.identity,
            &transition.reason,
            &evidence,
            transition.model_analysis_identity.as_deref().unwrap_or_default(),
            &micros,
        ],
    )
}

fn suppression_identity(
    scope: &FindingSuppressionScope,
    actor: &TriageActor,
    reason: &str,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    review_at: Option<DateTime<Utc>>,
) -> String {
    let created = created_at.timestamp_micros().to_string();
    let expires = expires_at.map(|value| value.timestamp_micros().to_string()).unwrap_or_default();
    let review = review_at.map(|value| value.timestamp_micros().to_string()).unwrap_or_default();
    digest_parts(
        "scorchkit.finding-suppression/v1",
        [
            scope.kind.as_str(),
            &scope.project_identity,
            scope.finding_identity.as_deref().unwrap_or_default(),
            scope.rule_identity.as_deref().unwrap_or_default(),
            scope.target_identity.as_deref().unwrap_or_default(),
            actor.kind.as_str(),
            &actor.identity,
            reason,
            &created,
            &expires,
            &review,
        ],
    )
}

fn correlation_identity(decision: &FindingCorrelationDecision) -> String {
    let findings = decision.contributing_finding_identities.join("\0");
    let scanners = decision.scanner_ids.join("\0");
    let evidence = decision.evidence_ids.join("\0");
    let facets = decision
        .facets
        .iter()
        .map(|facet| format!("{}\0{}", facet.namespace, facet.value))
        .collect::<Vec<_>>()
        .join("\0");
    let created = decision.created_at.timestamp_micros().to_string();
    digest_parts(
        "scorchkit.finding-correlation-decision/v1",
        [
            &decision.finding_identity,
            &findings,
            &scanners,
            &evidence,
            &facets,
            &decision.explanation,
            decision.actor.kind.as_str(),
            &decision.actor.identity,
            &created,
        ],
    )
}

fn digest_parts<'a>(domain: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    add_hash_part(&mut hasher, domain);
    for part in parts {
        add_hash_part(&mut hasher, part);
    }
    format!("{:x}", hasher.finalize())
}

fn add_hash_part(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::observation::{EvidenceRecord, ObservationLocation, ScannerProvenance};

    fn time(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 24, 1, 2, second).single().unwrap_or_else(Utc::now)
    }

    fn actor() -> TriageActor {
        TriageActor::new(TriageActorKind::Human, "operator@example.test")
    }

    fn record() -> FindingRecordV2 {
        let mut record = FindingRecordV2::from_legacy(
            "scanner",
            "finding",
            "https://example.test/path",
            Some(79),
            time(1),
        );
        record.provenance = ScannerProvenance::new("scanner", time(1))
            .with_version("1")
            .with_rule("rule-1", Some("digest-1".to_string()))
            .with_config("config-1")
            .with_target_revision("revision-1");
        record.location = ObservationLocation::infer("https://example.test/path");
        record.evidence.push(EvidenceRecord::text("proof", record.provenance.clone()));
        record
    }

    fn history_with_two_transitions() -> FindingTriageHistory {
        let finding = "a".repeat(64);
        let mut history = FindingTriageHistory::initial(
            &finding,
            FindingTriageState::NeedsContext,
            actor(),
            "Initial review",
            time(1),
        );
        history
            .append(FindingTriageTransition::new(
                finding,
                2,
                Some(FindingTriageState::NeedsContext),
                FindingTriageState::Validated,
                actor(),
                "Validated independently",
                time(2),
            ))
            .expect("append fixture transition");
        history
    }

    fn correlation() -> FindingCorrelationDecision {
        FindingCorrelationDecision::new(
            "a".repeat(64),
            FindingCorrelationContributors {
                finding_identities: vec!["a".repeat(64), "b".repeat(64)],
                scanner_ids: vec!["runtime".to_string(), "semgrep".to_string()],
                evidence_ids: vec!["c".repeat(64), "d".repeat(64)],
                facets: vec![CorrelationKey::new("CWE", "79"), CorrelationKey::new("route", "/x")],
            },
            "Source and runtime proof agree",
            actor(),
            time(2),
        )
    }

    fn subject() -> FindingTriageSubject {
        FindingTriageSubject::from_record("project-1", &record())
    }

    fn suppression() -> FindingSuppression {
        FindingSuppression::new(
            FindingSuppressionScope::for_subject(FindingSuppressionScopeKind::Finding, &subject()),
            actor(),
            "Time-bounded fixture",
            time(1),
            Some(time(5)),
            Some(time(4)),
        )
    }

    fn digests(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("{index:064x}")).collect()
    }

    fn assert_correlation_normalization(decision: &FindingCorrelationDecision) {
        assert_eq!(decision.validate(), Err(TriageValidationError::Normalization));
    }

    #[test]
    fn state_and_legacy_mappings_are_exact() {
        let mappings = [
            ("new", FindingTriageState::NeedsContext, "new"),
            ("acknowledged", FindingTriageState::Validated, "acknowledged"),
            ("false_positive", FindingTriageState::FalsePositive, "false_positive"),
            ("wont_fix", FindingTriageState::AcceptedRisk, "accepted_risk"),
            ("accepted_risk", FindingTriageState::AcceptedRisk, "accepted_risk"),
            ("remediated", FindingTriageState::Fixed, "verified"),
            ("verified", FindingTriageState::Fixed, "verified"),
        ];
        for (legacy, state, projected) in mappings {
            assert_eq!(triage_state_from_legacy(legacy), Some(state));
            assert_eq!(legacy_status_for_triage(state), projected);
        }
        assert_eq!(triage_state_from_legacy("unknown"), None);
        assert_eq!(legacy_status_for_triage(FindingTriageState::Likely), "acknowledged");
        assert_eq!(legacy_status_for_triage(FindingTriageState::Regressed), "new");
    }

    #[test]
    fn every_triage_state_and_scope_kind_round_trips_exactly() {
        for state in [
            FindingTriageState::NeedsContext,
            FindingTriageState::Likely,
            FindingTriageState::Validated,
            FindingTriageState::FalsePositive,
            FindingTriageState::AcceptedRisk,
            FindingTriageState::Fixed,
            FindingTriageState::Regressed,
        ] {
            assert_eq!(FindingTriageState::from_str(state.as_str()), Ok(state));
        }
        assert_eq!(
            FindingTriageState::from_str("unknown"),
            Err(TriageValidationError::Normalization)
        );

        for kind in [
            FindingSuppressionScopeKind::Finding,
            FindingSuppressionScopeKind::Rule,
            FindingSuppressionScopeKind::Target,
            FindingSuppressionScopeKind::RuleTarget,
        ] {
            assert_eq!(FindingSuppressionScopeKind::from_str(kind.as_str()), Ok(kind));
        }
        assert_eq!(
            FindingSuppressionScopeKind::from_str("unknown"),
            Err(TriageValidationError::Scope)
        );
    }

    #[test]
    fn actor_canonicality_requires_normalization_and_the_exact_bound() {
        assert!(actor().is_canonical());
        let empty = TriageActor { kind: TriageActorKind::Human, identity: String::new() };
        assert!(!empty.is_canonical());
        let oversized = TriageActor {
            kind: TriageActorKind::System,
            identity: "a".repeat(MAX_TRIAGE_ACTOR_BYTES + 1),
        };
        assert!(!oversized.is_canonical());
    }

    #[test]
    fn transition_history_pins_sequence_parent_and_closed_edges() {
        let finding = "a".repeat(64);
        let mut history = FindingTriageHistory::initial(
            &finding,
            FindingTriageState::NeedsContext,
            TriageActor::new(TriageActorKind::System, "initial"),
            "Initial review required",
            time(1),
        );
        history.validate().expect("initial history");
        history
            .append(
                FindingTriageTransition::new(
                    &finding,
                    2,
                    Some(FindingTriageState::NeedsContext),
                    FindingTriageState::Validated,
                    actor(),
                    "Reproduced against exact evidence",
                    time(2),
                )
                .with_references(vec!["b".repeat(64)], Some("c".repeat(64))),
            )
            .expect("valid transition");
        assert_eq!(history.current_state, FindingTriageState::Validated);
        assert!(history.validate().is_ok());

        let direct_fix = FindingTriageTransition::new(
            &finding,
            2,
            Some(FindingTriageState::NeedsContext),
            FindingTriageState::Fixed,
            actor(),
            "Legacy-compatible direct fix",
            time(2),
        );
        assert!(direct_fix.validate().is_ok());

        let rejected = FindingTriageTransition::new(
            &finding,
            3,
            Some(FindingTriageState::Validated),
            FindingTriageState::Regressed,
            actor(),
            "cannot regress before a fix",
            time(3),
        );
        assert_eq!(rejected.validate(), Err(TriageValidationError::Transition));
        let initial_regression = FindingTriageTransition::new(
            &finding,
            1,
            None,
            FindingTriageState::Regressed,
            actor(),
            "cannot regress without a prior fix",
            time(3),
        );
        assert_eq!(initial_regression.validate(), Err(TriageValidationError::Transition));

        let mut wrong = history.clone();
        wrong.transitions[1].sequence = 3;
        assert!(wrong.validate().is_err());
        let mut wrong = history.clone();
        wrong.current_state = FindingTriageState::Likely;
        assert_eq!(wrong.validate(), Err(TriageValidationError::History));
    }

    #[test]
    fn canonical_transition_rejects_public_field_mutations_independently() {
        let valid = FindingTriageTransition::new(
            "a".repeat(64),
            2,
            Some(FindingTriageState::NeedsContext),
            FindingTriageState::Likely,
            actor(),
            "Evidence supports likely",
            time(2),
        )
        .with_references(vec!["b".repeat(64)], None);
        valid.validate().expect("valid");
        let mut changed = valid.clone();
        changed.schema = "future".to_string();
        assert_eq!(changed.validate(), Err(TriageValidationError::Schema));
        let mut changed = valid.clone();
        changed.identity = "0".repeat(64);
        assert_eq!(changed.validate(), Err(TriageValidationError::Identity));
        let mut changed = valid.clone();
        changed.reason = "password=secret".to_string();
        assert_eq!(changed.validate(), Err(TriageValidationError::Normalization));
        let mut changed = valid.clone();
        changed.evidence_ids = vec!["not-a-digest".to_string()];
        assert_eq!(changed.validate(), Err(TriageValidationError::Normalization));
        let mut changed = valid;
        changed.model_analysis_identity = Some("not-a-digest".to_string());
        assert_eq!(changed.validate(), Err(TriageValidationError::Normalization));
    }

    #[test]
    fn transition_normalization_and_reference_boundaries_are_independent() {
        let valid = FindingTriageTransition::new(
            "a".repeat(64),
            2,
            Some(FindingTriageState::NeedsContext),
            FindingTriageState::Likely,
            actor(),
            "Independent transition",
            time(2),
        );

        let mut changed = valid.clone();
        changed.finding_identity.clear();
        assert_eq!(changed.validate(), Err(TriageValidationError::Normalization));

        let mut changed = valid;
        changed.actor.identity = "a".repeat(MAX_TRIAGE_ACTOR_BYTES + 1);
        assert_eq!(changed.validate(), Err(TriageValidationError::Normalization));

        let exact = FindingTriageTransition::new(
            "a".repeat(64),
            2,
            Some(FindingTriageState::NeedsContext),
            FindingTriageState::Likely,
            actor(),
            "Exact reference limit",
            time(2),
        )
        .with_references(digests(MAX_TRIAGE_REFERENCES), None);
        assert!(exact.validate().is_ok());
    }

    #[test]
    fn history_append_and_reconstruction_reject_each_mismatch_independently() {
        let initial = FindingTriageHistory::initial(
            "a".repeat(64),
            FindingTriageState::NeedsContext,
            actor(),
            "Initial review",
            time(1),
        );
        let mut history = initial.clone();
        assert_eq!(
            history.append(FindingTriageTransition::new(
                "b".repeat(64),
                2,
                Some(FindingTriageState::NeedsContext),
                FindingTriageState::Likely,
                actor(),
                "Wrong parent",
                time(2),
            )),
            Err(TriageValidationError::History)
        );
        let mut history = initial.clone();
        assert_eq!(
            history.append(FindingTriageTransition::new(
                "a".repeat(64),
                3,
                Some(FindingTriageState::NeedsContext),
                FindingTriageState::Likely,
                actor(),
                "Wrong sequence",
                time(2),
            )),
            Err(TriageValidationError::History)
        );
        let mut history = initial;
        assert_eq!(
            history.append(FindingTriageTransition::new(
                "a".repeat(64),
                2,
                Some(FindingTriageState::Likely),
                FindingTriageState::Validated,
                actor(),
                "Wrong prior state",
                time(2),
            )),
            Err(TriageValidationError::History)
        );

        let mut empty = history_with_two_transitions();
        empty.transitions.clear();
        assert_eq!(empty.validate(), Err(TriageValidationError::Limit));

        let mut wrong = history_with_two_transitions();
        wrong.finding_identity.clear();
        assert_eq!(wrong.validate(), Err(TriageValidationError::Schema));

        let mut wrong = history_with_two_transitions();
        wrong.transitions[1].finding_identity = "b".repeat(64);
        wrong.transitions[1].refresh_identity();
        assert_eq!(wrong.validate(), Err(TriageValidationError::History));

        let mut wrong = history_with_two_transitions();
        wrong.transitions[1].sequence = 3;
        wrong.transitions[1].refresh_identity();
        assert_eq!(wrong.validate(), Err(TriageValidationError::History));

        let mut wrong = history_with_two_transitions();
        wrong.transitions[1].from = Some(FindingTriageState::Likely);
        wrong.transitions[1].refresh_identity();
        assert_eq!(wrong.validate(), Err(TriageValidationError::History));
    }

    #[test]
    fn subject_validation_rejects_each_identity_independently() {
        let valid = subject();
        valid.validate().expect("valid subject");

        let mut changed = valid.clone();
        changed.project_identity.clear();
        assert_eq!(changed.validate(), Err(TriageValidationError::Normalization));
        let mut changed = valid.clone();
        changed.finding_identity.clear();
        assert_eq!(changed.validate(), Err(TriageValidationError::Normalization));
        let mut changed = valid.clone();
        changed.target_identity = "not-a-digest".to_string();
        assert_eq!(changed.validate(), Err(TriageValidationError::Normalization));
        let mut changed = valid;
        changed.rule_identity = Some("not-a-digest".to_string());
        assert_eq!(changed.validate(), Err(TriageValidationError::Normalization));
    }

    #[test]
    fn every_suppression_scope_matches_only_its_exact_dimensions() {
        let subject = FindingTriageSubject::from_record("project-1", &record());
        subject.validate().expect("subject");
        for kind in [
            FindingSuppressionScopeKind::Finding,
            FindingSuppressionScopeKind::Rule,
            FindingSuppressionScopeKind::Target,
            FindingSuppressionScopeKind::RuleTarget,
        ] {
            let scope = FindingSuppressionScope::for_subject(kind, &subject);
            scope.validate().expect("scope");
            assert!(scope.matches(&subject));
            let mut other = subject.clone();
            other.project_identity = "project-2".to_string();
            assert!(!scope.matches(&other));
            if scope.finding_identity.is_some() {
                let mut other = subject.clone();
                other.finding_identity = "other".to_string();
                assert!(!scope.matches(&other));
            }
            if scope.rule_identity.is_some() {
                let mut other = subject.clone();
                other.rule_identity = Some("f".repeat(64));
                assert!(!scope.matches(&other));
            }
            if scope.target_identity.is_some() {
                let mut other = subject.clone();
                other.target_identity = "f".repeat(64);
                assert!(!scope.matches(&other));
            }
        }
    }

    #[test]
    fn suppression_scope_shapes_require_every_declared_dimension() {
        let subject = subject();
        let digest = "a".repeat(64);

        let valid =
            FindingSuppressionScope::for_subject(FindingSuppressionScopeKind::Rule, &subject);
        valid.validate().expect("valid rule scope");
        let mut changed = valid.clone();
        changed.finding_identity = Some("finding".to_string());
        assert_eq!(changed.validate(), Err(TriageValidationError::Scope));
        let mut changed = valid.clone();
        changed.rule_identity = None;
        assert_eq!(changed.validate(), Err(TriageValidationError::Scope));
        let mut changed = valid;
        changed.target_identity = Some(digest.clone());
        assert_eq!(changed.validate(), Err(TriageValidationError::Scope));

        let valid =
            FindingSuppressionScope::for_subject(FindingSuppressionScopeKind::Target, &subject);
        valid.validate().expect("valid target scope");
        let mut changed = valid.clone();
        changed.finding_identity = Some("finding".to_string());
        assert_eq!(changed.validate(), Err(TriageValidationError::Scope));
        let mut changed = valid.clone();
        changed.rule_identity = Some(digest);
        assert_eq!(changed.validate(), Err(TriageValidationError::Scope));
        let mut changed = valid;
        changed.target_identity = None;
        assert_eq!(changed.validate(), Err(TriageValidationError::Scope));

        let valid =
            FindingSuppressionScope::for_subject(FindingSuppressionScopeKind::RuleTarget, &subject);
        valid.validate().expect("valid rule-target scope");
        let mut changed = valid.clone();
        changed.finding_identity = Some("finding".to_string());
        assert_eq!(changed.validate(), Err(TriageValidationError::Scope));
        let mut changed = valid.clone();
        changed.rule_identity = None;
        assert_eq!(changed.validate(), Err(TriageValidationError::Scope));
        let mut changed = valid;
        changed.target_identity = None;
        assert_eq!(changed.validate(), Err(TriageValidationError::Scope));
    }

    #[test]
    fn suppression_expiry_review_and_public_construction_are_fail_closed() {
        let subject = FindingTriageSubject::from_record("project-1", &record());
        let valid = FindingSuppression::new(
            FindingSuppressionScope::for_subject(FindingSuppressionScopeKind::Finding, &subject),
            actor(),
            "Known fixture behavior",
            time(1),
            Some(time(3)),
            Some(time(4)),
        );
        valid.validate().expect("valid");
        assert!(!valid.is_active_for(&subject, time(0)));
        assert!(valid.is_active_for(&subject, time(2)));
        assert!(!valid.is_active_for(&subject, time(3)));

        let mut no_boundary = valid.clone();
        no_boundary.expires_at = None;
        no_boundary.review_at = None;
        assert_eq!(no_boundary.validate(), Err(TriageValidationError::Time));
        let mut invalid_shape = valid;
        invalid_shape.scope.rule_identity = Some("a".repeat(64));
        assert_eq!(invalid_shape.validate(), Err(TriageValidationError::Scope));
    }

    #[test]
    fn suppression_reason_review_and_activity_boundaries_are_exact() {
        let valid = suppression();
        valid.validate().expect("valid suppression");

        let mut changed = valid.clone();
        changed.reason.clear();
        assert_eq!(changed.validate(), Err(TriageValidationError::Time));

        let mut changed = valid.clone();
        changed.review_at = Some(changed.created_at);
        assert_eq!(changed.validate(), Err(TriageValidationError::Time));

        assert!(valid.is_active_for(&subject(), time(3)));
        assert!(!valid.is_active_for(&subject(), time(4)));
    }

    #[test]
    fn correlation_preserves_all_inputs_and_rejects_weak_single_source_claims() {
        let valid = FindingCorrelationDecision::new(
            "a".repeat(64),
            FindingCorrelationContributors {
                finding_identities: vec!["b".repeat(64), "a".repeat(64)],
                scanner_ids: vec!["semgrep".to_string(), "runtime".to_string()],
                evidence_ids: vec!["d".repeat(64), "c".repeat(64)],
                facets: vec![CorrelationKey::new("CWE", "79"), CorrelationKey::new("route", "/x")],
            },
            "Source and runtime proof share route and weakness",
            actor(),
            time(2),
        );
        valid.validate().expect("valid correlation");
        assert_eq!(valid.contributing_finding_identities[0], "a".repeat(64));
        assert_eq!(valid.evidence_ids[0], "c".repeat(64));

        let weak = FindingCorrelationDecision::new(
            "a".repeat(64),
            FindingCorrelationContributors {
                finding_identities: vec!["a".repeat(64)],
                scanner_ids: vec!["one".to_string()],
                evidence_ids: vec!["c".repeat(64)],
                facets: Vec::new(),
            },
            "one source is not correlation",
            actor(),
            time(2),
        );
        assert_eq!(weak.validate(), Err(TriageValidationError::Normalization));

        let mut malformed_facet = valid;
        malformed_facet.facets[0].value = "bad\nfacet".to_string();
        assert_eq!(malformed_facet.validate(), Err(TriageValidationError::Normalization));
    }

    #[test]
    fn correlation_validation_is_independent_for_every_public_field() {
        let valid = correlation();
        valid.validate().expect("valid correlation");

        let mut changed = valid.clone();
        changed.finding_identity.clear();
        assert_correlation_normalization(&changed);
        let mut changed = valid.clone();
        changed.contributing_finding_identities.clear();
        assert_correlation_normalization(&changed);
        let mut changed = valid.clone();
        changed.scanner_ids.clear();
        assert_correlation_normalization(&changed);
        let mut changed = valid.clone();
        changed.evidence_ids.clear();
        assert_correlation_normalization(&changed);
        let mut changed = valid.clone();
        changed.contributing_finding_identities.reverse();
        assert_correlation_normalization(&changed);
        let mut changed = valid.clone();
        changed.scanner_ids.reverse();
        assert_correlation_normalization(&changed);
        let mut changed = valid.clone();
        changed.evidence_ids.reverse();
        assert_correlation_normalization(&changed);
        let mut changed = valid.clone();
        changed.facets.reverse();
        assert_correlation_normalization(&changed);
        let mut changed = valid.clone();
        changed.explanation.clear();
        assert_correlation_normalization(&changed);
        let mut changed = valid;
        changed.actor.identity = "a".repeat(MAX_TRIAGE_ACTOR_BYTES + 1);
        assert_correlation_normalization(&changed);
    }

    #[test]
    fn correlation_collection_limits_and_minimum_sources_are_exact() {
        let at_limit = |contributors: FindingCorrelationContributors| {
            FindingCorrelationDecision::new(
                "a".repeat(64),
                contributors,
                "Exact collection boundary",
                actor(),
                time(2),
            )
        };
        let base = FindingCorrelationContributors {
            finding_identities: vec!["a".repeat(64), "b".repeat(64)],
            scanner_ids: vec!["one".to_string(), "two".to_string()],
            evidence_ids: vec!["f".repeat(64)],
            facets: vec![CorrelationKey::new("CWE", "79")],
        };

        let mut values = base.clone();
        values.finding_identities =
            (0..MAX_TRIAGE_REFERENCES).map(|index| format!("finding-{index:04}")).collect();
        assert!(at_limit(values).validate().is_ok());

        let mut values = base.clone();
        values.scanner_ids =
            (0..MAX_TRIAGE_REFERENCES).map(|index| format!("scanner-{index:04}")).collect();
        assert!(at_limit(values).validate().is_ok());
        let mut values = base.clone();
        values.scanner_ids =
            (0..=MAX_TRIAGE_REFERENCES).map(|index| format!("scanner-{index:04}")).collect();
        assert_correlation_normalization(&at_limit(values));

        let mut values = base.clone();
        values.evidence_ids = digests(MAX_TRIAGE_REFERENCES);
        assert!(at_limit(values).validate().is_ok());
        let mut values = base.clone();
        values.evidence_ids = digests(MAX_TRIAGE_REFERENCES + 1);
        assert_correlation_normalization(&at_limit(values));

        let mut values = base.clone();
        values.facets = (0..MAX_TRIAGE_REFERENCES)
            .map(|index| CorrelationKey::new("fixture", format!("{index:04}")))
            .collect();
        assert!(at_limit(values).validate().is_ok());
        let mut values = base.clone();
        values.facets = (0..=MAX_TRIAGE_REFERENCES)
            .map(|index| CorrelationKey::new("fixture", format!("{index:04}")))
            .collect();
        assert_correlation_normalization(&at_limit(values));

        let mut one_finding = base.clone();
        one_finding.finding_identities = vec!["a".repeat(64)];
        assert!(at_limit(one_finding).validate().is_ok());
        let mut one_scanner = base;
        one_scanner.scanner_ids = vec!["one".to_string()];
        assert!(at_limit(one_scanner).validate().is_ok());
    }

    #[test]
    fn projection_ordering_rejects_equal_correlation_and_suppression_keys() {
        let history = FindingTriageHistory::initial(
            "a".repeat(64),
            FindingTriageState::NeedsContext,
            actor(),
            "Initial review",
            time(1),
        );
        let decision = correlation();
        let duplicate_correlations =
            FindingTriage::new(history.clone(), vec![decision.clone(), decision], Vec::new());
        assert_eq!(duplicate_correlations.validate(), Err(TriageValidationError::Limit));

        let suppression = suppression();
        let duplicate_suppressions =
            FindingTriage::new(history, Vec::new(), vec![suppression.clone(), suppression]);
        assert_eq!(duplicate_suppressions.validate(), Err(TriageValidationError::Limit));
    }

    #[test]
    fn digest_ordering_and_correlation_identity_helpers_are_exact() {
        assert!(is_digest(&"a".repeat(64)));
        assert!(!is_digest(&"a".repeat(63)));
        assert!(!is_digest(&"A".repeat(64)));
        assert!(!is_digest(&"g".repeat(64)));

        assert!(ordered_unique_values(&[]));
        assert!(ordered_unique_values(&["a".to_string()]));
        assert!(ordered_unique_values(&["a".to_string(), "b".to_string()]));
        assert!(!ordered_unique_values(&["b".to_string(), "a".to_string()]));
        assert!(!ordered_unique_values(&["a".to_string(), "a".to_string()]));

        let decision = correlation();
        let identity = correlation_identity(&decision);
        assert_eq!(identity, decision.identity);
        assert!(is_digest(&identity));
    }

    #[test]
    fn material_evidence_digest_ignores_only_collection_time() {
        let first = record();
        let mut later = first.clone();
        later.provenance.collected_at = time(3);
        for evidence in &mut later.evidence {
            evidence.provenance.collected_at = time(3);
            evidence.identity = "f".repeat(64);
        }
        assert_eq!(
            material_finding_evidence_identity(&first),
            material_finding_evidence_identity(&later)
        );

        let mut changed = later;
        changed.evidence[0].payload =
            crate::observation::EvidencePayload::Text { content: "different proof".to_string() };
        assert_ne!(
            material_finding_evidence_identity(&first),
            material_finding_evidence_identity(&changed)
        );
    }

    #[test]
    fn every_public_collection_accepts_its_exact_limit_and_rejects_one_more() {
        let finding = "a".repeat(64);
        let initial = FindingTriageHistory::initial(
            &finding,
            FindingTriageState::NeedsContext,
            actor(),
            "Initial review",
            time(1),
        );

        let mut current = FindingTriageState::NeedsContext;
        let mut transitions = initial.transitions.clone();
        for index in 1..MAX_TRIAGE_TRANSITIONS {
            let next = if current == FindingTriageState::NeedsContext {
                FindingTriageState::Likely
            } else {
                FindingTriageState::NeedsContext
            };
            transitions.push(FindingTriageTransition::new(
                &finding,
                u32::try_from(index + 1).unwrap_or(u32::MAX),
                Some(current),
                next,
                actor(),
                "Bounded transition",
                time(2) + chrono::Duration::microseconds(i64::try_from(index).unwrap_or(i64::MAX)),
            ));
            current = next;
        }
        let mut history = FindingTriageHistory {
            schema: FINDING_TRIAGE_SCHEMA_V1.to_string(),
            finding_identity: finding.clone(),
            current_state: current,
            transitions,
        };
        history.validate().expect("exact transition limit");
        let overflow = FindingTriageTransition::new(
            &finding,
            u32::try_from(MAX_TRIAGE_TRANSITIONS + 1).unwrap_or(u32::MAX),
            Some(current),
            FindingTriageState::Validated,
            actor(),
            "Transition overflow",
            time(3),
        );
        assert_eq!(history.append(overflow), Err(TriageValidationError::Limit));

        let correlation = |index: usize| {
            FindingCorrelationDecision::new(
                &finding,
                FindingCorrelationContributors {
                    finding_identities: vec![finding.clone(), "b".repeat(64)],
                    scanner_ids: vec!["one".to_string(), "two".to_string()],
                    evidence_ids: vec!["c".repeat(64)],
                    facets: Vec::new(),
                },
                "Bounded correlation",
                actor(),
                time(2) + chrono::Duration::microseconds(i64::try_from(index).unwrap_or(i64::MAX)),
            )
        };
        let correlations: Vec<_> = (0..MAX_TRIAGE_CORRELATIONS).map(correlation).collect();
        let mut projection = FindingTriage::new(initial.clone(), correlations, Vec::new());
        projection.validate().expect("exact correlation limit");
        projection.correlations.push(correlation(MAX_TRIAGE_CORRELATIONS));
        assert_eq!(projection.validate(), Err(TriageValidationError::Limit));

        let subject = FindingTriageSubject::from_record("project", &record());
        let suppression = |index: usize| {
            let created =
                time(2) + chrono::Duration::microseconds(i64::try_from(index).unwrap_or(i64::MAX));
            FindingSuppression::new(
                FindingSuppressionScope::for_subject(
                    FindingSuppressionScopeKind::Finding,
                    &subject,
                ),
                actor(),
                "Bounded suppression",
                created,
                Some(created + chrono::Duration::hours(1)),
                None,
            )
        };
        let suppressions: Vec<_> = (0..MAX_TRIAGE_SUPPRESSIONS).map(suppression).collect();
        let mut projection = FindingTriage::new(initial, Vec::new(), suppressions);
        projection.validate().expect("exact suppression limit");
        projection.suppressions.push(suppression(MAX_TRIAGE_SUPPRESSIONS));
        assert_eq!(projection.validate(), Err(TriageValidationError::Limit));
    }
}
