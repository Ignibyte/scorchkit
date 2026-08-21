//! Versioned source-to-runtime attack-path correlation contracts.
//!
//! Canonical attack paths are derived only from typed finding-v2 locations, scanner provenance,
//! correlation keys, code flows, and redacted scanner evidence. Legacy title/module heuristics and
//! agent analysis are deliberately outside this boundary.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::evidence::HttpEvidence;
use crate::finding::Finding;
use crate::observation::{
    redact_text, CorrelationKey, EvidencePayload, FindingRecordV2, HttpParameterIdentity,
    ObservationLocation, ScannerProvenance,
};
use crate::severity::Severity;

/// Canonical attack-path record schema.
pub const ATTACK_PATH_SCHEMA_V1: &str = "scorchkit.attack-path/v1";
/// Deterministic attack-path identity schema.
pub const ATTACK_PATH_IDENTITY_SCHEMA_V1: &str = "scorchkit.attack-path-identity/v1";
/// Correlation response schema.
pub const ATTACK_PATH_CORRELATION_SCHEMA_V1: &str = "scorchkit.attack-path-correlation/v1";
/// Focused verification selection schema.
pub const FOCUSED_VERIFICATION_SCHEMA_V1: &str = "scorchkit.focused-verification/v1";
/// Verification attempt schema.
pub const VERIFICATION_ATTEMPT_SCHEMA_V1: &str = "scorchkit.verification-attempt/v1";
/// Attack-path transition schema.
pub const ATTACK_PATH_TRANSITION_SCHEMA_V1: &str = "scorchkit.attack-path-transition/v1";

/// Hard ceiling for one correlation operation.
pub const MAX_CORRELATION_FINDINGS: usize = 4_096;
/// Hard ceiling for paths returned by one correlation operation.
pub const MAX_CORRELATED_PATHS: usize = 1_024;
/// Hard ceiling for one normalized facet value.
pub const MAX_CORRELATION_FACET_BYTES: usize = 512;
/// Hard ceiling for correlation-relevant keys, evidence records, flows, and nested flows on one
/// finding.
pub const MAX_CORRELATION_DETAILS_PER_FINDING: usize = 256;
/// Hard ceiling for source/runtime candidate-pair evaluations in one operation.
pub const MAX_CORRELATION_PAIR_EVALUATIONS: usize = 65_536;
/// Hard ceiling for append-preserved evidence records reconstructed by one project adapter call.
pub const MAX_CORRELATION_PROJECT_EVIDENCE: usize = 16_384;

/// Correlation completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackPathCorrelationStatus {
    /// Every supplied finding was considered within the resource ceilings.
    Complete,
    /// At least one input or output ceiling prevented complete consideration.
    Incomplete,
}

/// A typed reason the correlation inventory is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackPathCorrelationGapKind {
    /// The supplied finding inventory exceeds the hard ceiling.
    FindingLimitExceeded,
    /// The candidate path inventory exceeds the hard ceiling.
    PathLimitExceeded,
    /// A correlation key was empty or exceeded the value ceiling.
    InvalidFacet,
    /// A legacy location could not participate in typed correlation.
    UnsupportedLocation,
    /// A durable finding could not be decoded as its declared canonical record.
    MalformedFindingRecord,
    /// One finding exceeded a correlation-relevant detail ceiling.
    FindingDetailLimitExceeded,
    /// A finding had a non-finite confidence or another invalid canonical field.
    InvalidFindingRecord,
    /// The source/runtime cross-product exceeded the CPU-work ceiling.
    PairEvaluationLimitExceeded,
    /// The project adapter truncated append-preserved evidence at its read ceiling.
    ProjectEvidenceLimitExceeded,
}

/// One bounded correlation-coverage gap.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttackPathCorrelationGap {
    /// Stable reason code.
    pub kind: AttackPathCorrelationGapKind,
    /// Finding identity involved, when the gap is finding-specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_identity: Option<String>,
}

/// Canonical result of one project-scoped correlation operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackPathCorrelation {
    /// Record schema.
    pub schema: String,
    /// Completion status.
    pub status: AttackPathCorrelationStatus,
    /// Deterministically ordered canonical paths.
    pub paths: Vec<AttackPath>,
    /// Deterministically ordered coverage gaps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<AttackPathCorrelationGap>,
}

/// Typed correlation facet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationFacetKind {
    /// Application identity or runtime origin.
    Application,
    /// Deployment or source-revision identity.
    Deployment,
    /// Normalized HTTP route.
    Route,
    /// Schema operation identity.
    Operation,
    /// HTTP method.
    Method,
    /// HTTP parameter name and carrier.
    Parameter,
    /// Package, service, or application component identity.
    Component,
    /// CWE, OWASP, or equivalent weakness identity.
    Weakness,
    /// Explicit test identity for later focused verification.
    Test,
    /// Other exact scanner-supplied correlation identity.
    Explicit,
}

impl CorrelationFacetKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Deployment => "deployment",
            Self::Route => "route",
            Self::Operation => "operation",
            Self::Method => "method",
            Self::Parameter => "parameter",
            Self::Component => "component",
            Self::Weakness => "weakness",
            Self::Test => "test",
            Self::Explicit => "explicit",
        }
    }
}

/// One normalized cross-observation identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CorrelationFacet {
    /// Facet class.
    pub kind: CorrelationFacetKind,
    /// Lowercase namespace.
    pub namespace: String,
    /// Namespace-local normalized value.
    pub value: String,
}

impl CorrelationFacet {
    fn from_parts(
        kind: CorrelationFacetKind,
        namespace: impl Into<String>,
        value: impl Into<String>,
    ) -> Option<Self> {
        let supplied_namespace = namespace.into().trim().to_lowercase();
        if supplied_namespace.is_empty() || supplied_namespace.len() > MAX_CORRELATION_FACET_BYTES {
            return None;
        }
        let namespace = match kind {
            CorrelationFacetKind::Application => "application".to_string(),
            CorrelationFacetKind::Deployment => "deployment".to_string(),
            CorrelationFacetKind::Route => "http-route".to_string(),
            CorrelationFacetKind::Operation => "operation".to_string(),
            CorrelationFacetKind::Method => "http-method".to_string(),
            CorrelationFacetKind::Parameter => "http-parameter".to_string(),
            CorrelationFacetKind::Test => "test".to_string(),
            CorrelationFacetKind::Component
            | CorrelationFacetKind::Weakness
            | CorrelationFacetKind::Explicit => supplied_namespace,
        };
        let value = normalize_facet_value(kind, &value.into())?;
        if namespace.is_empty()
            || namespace.len() > MAX_CORRELATION_FACET_BYTES
            || value.len() > MAX_CORRELATION_FACET_BYTES
        {
            return None;
        }
        Some(Self { kind, namespace, value })
    }

    fn identity_part(&self) -> String {
        format!("{}\0{}\0{}", self.kind.as_str(), self.namespace, self.value)
    }
}

/// Evidence-supported path state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackPathState {
    /// Static and runtime evidence share only a weak identity.
    Suspected,
    /// A precise application surface is shared, but complete reproduction proof is absent.
    Reachable,
    /// Comparable source flow and runtime HTTP evidence reproduce the same deployed weakness.
    Reproduced,
    /// Complete comparable verification no longer reproduces a previously reproduced path.
    Mitigated,
    /// Later comparable evidence reproduced a mitigated path.
    Regressed,
}

impl AttackPathState {
    /// Stable public label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Suspected => "suspected",
            Self::Reachable => "reachable",
            Self::Reproduced => "reproduced",
            Self::Mitigated => "mitigated",
            Self::Regressed => "regressed",
        }
    }
}

/// Role of one finding in a canonical path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackPathMemberRole {
    /// Static source hypothesis.
    SourceHypothesis,
    /// Package or artifact component hypothesis.
    ComponentHypothesis,
    /// Runtime application surface and proof.
    RuntimeObservation,
}

impl AttackPathMemberRole {
    /// Stable public label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceHypothesis => "source_hypothesis",
            Self::ComponentHypothesis => "component_hypothesis",
            Self::RuntimeObservation => "runtime_observation",
        }
    }
}

/// Reference to one immutable finding and its evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackPathMember {
    /// Stable finding-v2 identity.
    pub finding_identity: String,
    /// Producing module identifier.
    pub module_id: String,
    /// Path role.
    pub role: AttackPathMemberRole,
    /// Typed location snapshot.
    pub location: ObservationLocation,
    /// Scanner provenance snapshot.
    pub provenance: ScannerProvenance,
    /// Sorted evidence identities referenced by this member.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<String>,
    /// Original scanner confidence. Correlation never changes it.
    pub scanner_confidence: f64,
}

/// Reason a candidate could not reach a stronger state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackPathGapKind {
    /// No shared CWE, OWASP, or explicit weakness identity.
    MissingSharedWeakness,
    /// No shared route, operation, parameter, component, or application identity.
    MissingPreciseApplicationFacet,
    /// Static analysis did not supply an ordered source-to-sink flow.
    MissingSourceFlow,
    /// Runtime analysis did not supply redacted HTTP request/response proof.
    MissingRuntimeHttpProof,
    /// Source and runtime evidence have no shared deployment or revision identity.
    RevisionUnbound,
    /// Source and runtime deployment or revision identities conflict.
    RevisionConflict,
    /// Runtime HTTP proof exists but is not bound to the shared deployment/revision.
    RuntimeProofRevisionUnbound,
}

/// One typed path-strength gap.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AttackPathGap {
    /// Stable reason code.
    pub kind: AttackPathGapKind,
}

/// Stable identity assigned to a canonical path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackPathIdentity {
    /// Identity algorithm schema.
    pub schema: String,
    /// Lowercase hexadecimal SHA-256 digest.
    pub value: String,
}

/// Exact static or runtime scanner input for focused verification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScannerVerificationSelector {
    /// Scanner or module identifier.
    pub scanner_id: String,
    /// Exact rule, query, check, or template identifier.
    pub rule_id: String,
    /// Exact rule/template digest, when supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_digest: Option<String>,
    /// Exact rule pack, template collection, or configuration identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_identity: Option<String>,
}

/// Redacted request selector for focused runtime verification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RequestVerificationSelector {
    /// HTTP method.
    pub method: String,
    /// Normalized application route.
    pub route: String,
    /// Parameter identity without a value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<HttpParameterIdentity>,
    /// Authentication persona label without credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_persona: Option<String>,
}

impl PartialOrd for HttpParameterIdentity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HttpParameterIdentity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.location, &self.name).cmp(&(&other.location, &other.name))
    }
}

/// Minimal inert follow-up selection for one path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FocusedVerificationSelection {
    /// Record schema.
    pub schema: String,
    /// Deterministic selection identity.
    pub identity: String,
    /// Parent path identity.
    pub path_identity: String,
    /// Exact static-analysis rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub static_rules: Vec<ScannerVerificationSelector>,
    /// Exact runtime probes or templates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_probes: Vec<ScannerVerificationSelector>,
    /// Redacted runtime requests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requests: Vec<RequestVerificationSelector>,
    /// Explicit test identities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tests: Vec<String>,
}

/// Verification coverage state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationCoverage {
    /// Same path, deployment, selector, and relevant conditions were fully exercised.
    CompleteComparable,
    /// At least one required condition was not exercised.
    Incomplete,
    /// Verification failed before a coverage verdict was possible.
    Failed,
}

impl VerificationCoverage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CompleteComparable => "complete_comparable",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
        }
    }
}

/// Verification observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    /// The path reproduced.
    Reproduced,
    /// The path did not reproduce under the recorded conditions.
    NotReproduced,
}

impl VerificationOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Reproduced => "reproduced",
            Self::NotReproduced => "not_reproduced",
        }
    }
}

/// Comparable conditions for one verification attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationConditions {
    /// Deployment/revision identity exercised by the attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_identity: Option<String>,
    /// Exact scanner configuration identities used by the attempt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_identities: Vec<String>,
}

/// One immutable focused verification attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationAttempt {
    /// Record schema.
    pub schema: String,
    /// Deterministic attempt identity.
    pub identity: String,
    /// Path being verified.
    pub path_identity: String,
    /// Exact focused selection exercised.
    pub selection_identity: String,
    /// Coverage state.
    pub coverage: VerificationCoverage,
    /// Observed result.
    pub outcome: VerificationOutcome,
    /// Comparable conditions.
    pub conditions: VerificationConditions,
    /// Sorted evidence identities produced by the attempt.
    pub evidence_ids: Vec<String>,
    /// Observation time.
    pub observed_at: DateTime<Utc>,
}

impl VerificationAttempt {
    /// Construct a canonical immutable attempt.
    #[must_use]
    pub fn new(
        path_identity: impl Into<String>,
        selection_identity: impl Into<String>,
        coverage: VerificationCoverage,
        outcome: VerificationOutcome,
        mut conditions: VerificationConditions,
        mut evidence_ids: Vec<String>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let path_identity = path_identity.into();
        let selection_identity = selection_identity.into();
        conditions.deployment_identity = conditions
            .deployment_identity
            .map(|value| redact_text(value.trim()))
            .filter(|value| bounded_nonempty(value));
        conditions.config_identities = normalized_strings(conditions.config_identities);
        evidence_ids = normalized_strings(evidence_ids);
        let identity = verification_attempt_identity(
            &path_identity,
            &selection_identity,
            coverage,
            outcome,
            &conditions,
            &evidence_ids,
            observed_at,
        );
        Self {
            schema: VERIFICATION_ATTEMPT_SCHEMA_V1.to_string(),
            identity,
            path_identity,
            selection_identity,
            coverage,
            outcome,
            conditions,
            evidence_ids,
            observed_at,
        }
    }

    fn is_canonical(&self) -> bool {
        let rebuilt = Self::new(
            &self.path_identity,
            &self.selection_identity,
            self.coverage,
            self.outcome,
            self.conditions.clone(),
            self.evidence_ids.clone(),
            self.observed_at,
        );
        self == &rebuilt
    }
}

/// Why a transition record exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackPathTransitionReason {
    /// Initial deterministic correlation.
    Correlated,
    /// Focused verification attempt.
    Verification,
}

impl AttackPathTransitionReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Correlated => "correlated",
            Self::Verification => "verification",
        }
    }
}

/// Append-only attack-path state history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackPathTransition {
    /// Record schema.
    pub schema: String,
    /// Deterministic transition identity.
    pub identity: String,
    /// Previous state, absent for initial correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<AttackPathState>,
    /// State after applying the evidence or attempt.
    pub to: AttackPathState,
    /// Transition cause.
    pub reason: AttackPathTransitionReason,
    /// Attempt identity for verification transitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_identity: Option<String>,
    /// Coverage for verification transitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<VerificationCoverage>,
    /// Observed outcome for verification transitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<VerificationOutcome>,
    /// Comparable deployment and scanner conditions for verification transitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<VerificationConditions>,
    /// Evidence referenced by this transition.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<String>,
    /// Path confidence after the transition, separate from scanner confidence.
    pub path_confidence: u8,
    /// Observation time.
    pub observed_at: DateTime<Utc>,
}

/// Canonical application attack path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackPath {
    /// Record schema.
    pub schema: String,
    /// Stable identity.
    pub identity: AttackPathIdentity,
    /// Evidence-supported state.
    pub state: AttackPathState,
    /// Path confidence from 0 to 100, separate from every scanner confidence.
    pub path_confidence: u8,
    /// Highest member severity.
    pub severity: Severity,
    /// Exact shared facets that created the candidate.
    pub shared_facets: Vec<CorrelationFacet>,
    /// Ordered source/component and runtime members.
    pub members: Vec<AttackPathMember>,
    /// Typed reasons the path could not reach a stronger state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<AttackPathGap>,
    /// Minimal inert verification selection.
    pub focused_verification: FocusedVerificationSelection,
    /// Append-only state history.
    pub transitions: Vec<AttackPathTransition>,
}

/// Validation error for a supplied verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationAttemptError {
    /// Attempt schema, identity, or normalized fields are invalid.
    NonCanonical,
    /// Attempt names a different path.
    PathMismatch,
    /// Attempt names a different focused selection.
    SelectionMismatch,
    /// Attempt predates the current path history.
    Stale,
    /// Complete-comparable coverage does not bind the shared deployment.
    DeploymentMismatch,
    /// Complete-comparable coverage does not use the exact selected scanner configurations.
    ConfigurationMismatch,
    /// Reproduction lacks source-flow, weakness, or precise application prerequisites.
    MissingProofPrerequisite,
    /// A complete attempt has no scanner evidence identity.
    MissingEvidence,
}

/// Validation error for a supplied or restored attack path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackPathValidationError {
    /// A record or nested record uses a different schema.
    Schema,
    /// Path, selection, or transition identity does not match canonical content.
    Identity,
    /// A facet, member, selector, gap, or evidence reference is not normalized and ordered.
    Normalization,
    /// Transition history is empty, unordered, discontinuous, or has an invalid reason shape.
    History,
    /// Current state or confidence disagrees with the final transition.
    State,
}

impl AttackPath {
    /// Validate a path restored across an adapter boundary.
    ///
    /// # Errors
    ///
    /// Returns a typed error if schema, identity, normalization, history, or current-state
    /// invariants do not match the canonical v1 contract.
    pub fn validate(&self) -> Result<(), AttackPathValidationError> {
        if self.schema != ATTACK_PATH_SCHEMA_V1
            || self.identity.schema != ATTACK_PATH_IDENTITY_SCHEMA_V1
            || self.focused_verification.schema != FOCUSED_VERIFICATION_SCHEMA_V1
            || self
                .transitions
                .iter()
                .any(|transition| transition.schema != ATTACK_PATH_TRANSITION_SCHEMA_V1)
        {
            return Err(AttackPathValidationError::Schema);
        }
        if self.identity != attack_path_identity(&self.members, &self.shared_facets)
            || self.focused_verification.path_identity != self.identity.value
            || self.focused_verification.identity
                != focused_selection_identity(&self.focused_verification)
        {
            return Err(AttackPathValidationError::Identity);
        }
        if self.shared_facets.is_empty()
            || !is_strictly_ordered(&self.shared_facets)
            || self.shared_facets.iter().any(|facet| {
                CorrelationFacet::from_parts(facet.kind, &facet.namespace, &facet.value).as_ref()
                    != Some(facet)
            })
            || !is_strictly_ordered(&self.gaps)
            || !self.members_are_normalized()
            || !self.selection_is_normalized()
        {
            return Err(AttackPathValidationError::Normalization);
        }
        self.validate_history()
    }

    fn members_are_normalized(&self) -> bool {
        if self.members.len() != 2
            || !matches!(
                self.members[0].role,
                AttackPathMemberRole::SourceHypothesis | AttackPathMemberRole::ComponentHypothesis
            )
            || self.members[1].role != AttackPathMemberRole::RuntimeObservation
        {
            return false;
        }
        self.members.iter().all(|member| {
            !member.finding_identity.is_empty()
                && !member.module_id.is_empty()
                && member.scanner_confidence.is_finite()
                && (0.0..=1.0).contains(&member.scanner_confidence)
                && member.location.clone().redacted() == member.location
                && normalized_strings(member.evidence_ids.clone()) == member.evidence_ids
        })
    }

    fn selection_is_normalized(&self) -> bool {
        let selection = &self.focused_verification;
        is_strictly_ordered(&selection.static_rules)
            && is_strictly_ordered(&selection.runtime_probes)
            && is_strictly_ordered(&selection.requests)
            && normalized_strings(selection.tests.clone()) == selection.tests
            && selection
                .static_rules
                .iter()
                .chain(&selection.runtime_probes)
                .all(scanner_selector_is_normalized)
            && selection.requests.iter().all(request_selector_is_normalized)
    }

    fn validate_history(&self) -> Result<(), AttackPathValidationError> {
        let Some(initial) = self.transitions.first() else {
            return Err(AttackPathValidationError::History);
        };
        if initial.from.is_some()
            || initial.reason != AttackPathTransitionReason::Correlated
            || initial.attempt_identity.is_some()
            || initial.coverage.is_some()
            || initial.outcome.is_some()
            || initial.conditions.is_some()
            || matches!(initial.to, AttackPathState::Mitigated | AttackPathState::Regressed)
        {
            return Err(AttackPathValidationError::History);
        }
        self.validate_initial_transition(initial)?;

        let mut identities = BTreeSet::new();
        let mut prior_state = None;
        let mut prior_confidence = None;
        let mut prior_time = None;
        for (index, transition) in self.transitions.iter().enumerate() {
            let reason_shape_valid = index == 0
                || (transition.reason == AttackPathTransitionReason::Verification
                    && transition.attempt_identity.as_ref().is_some_and(|value| !value.is_empty())
                    && transition.coverage.is_some()
                    && transition.outcome.is_some()
                    && transition.conditions.is_some());
            let rebuilt = build_transition(TransitionInput {
                path_identity: &self.identity.value,
                from: transition.from,
                to: transition.to,
                reason: transition.reason,
                attempt_identity: transition.attempt_identity.as_deref(),
                coverage: transition.coverage,
                outcome: transition.outcome,
                conditions: transition.conditions.clone(),
                evidence_ids: transition.evidence_ids.clone(),
                path_confidence: transition.path_confidence,
                observed_at: transition.observed_at,
            });
            if !reason_shape_valid
                || transition.from != prior_state
                || prior_time.is_some_and(|time| transition.observed_at < time)
                || !identities.insert(transition.identity.as_str())
                || transition.path_confidence > 100
                || transition.evidence_ids != normalized_strings(transition.evidence_ids.clone())
            {
                return Err(AttackPathValidationError::History);
            }
            if transition.identity != rebuilt.identity {
                return Err(AttackPathValidationError::Identity);
            }
            if index > 0 {
                self.validate_verification_transition(
                    transition,
                    prior_state.ok_or(AttackPathValidationError::History)?,
                    prior_confidence.ok_or(AttackPathValidationError::History)?,
                )?;
            } else if transition.path_confidence != initial_path_confidence(transition.to) {
                return Err(AttackPathValidationError::State);
            }
            prior_state = Some(transition.to);
            prior_confidence = Some(transition.path_confidence);
            prior_time = Some(transition.observed_at);
        }
        if prior_state != Some(self.state)
            || self.path_confidence > 100
            || self.transitions.last().map(|transition| transition.path_confidence)
                != Some(self.path_confidence)
        {
            return Err(AttackPathValidationError::State);
        }
        Ok(())
    }

    fn validate_initial_transition(
        &self,
        initial: &AttackPathTransition,
    ) -> Result<(), AttackPathValidationError> {
        let expected_evidence = normalized_strings(
            self.members.iter().flat_map(|member| member.evidence_ids.iter().cloned()).collect(),
        );
        let expected_time = self
            .members
            .iter()
            .map(|member| member.provenance.collected_at)
            .max()
            .ok_or(AttackPathValidationError::History)?;
        let state_matches_gaps = match initial.to {
            AttackPathState::Suspected => self
                .gaps
                .iter()
                .any(|gap| gap.kind == AttackPathGapKind::MissingPreciseApplicationFacet),
            AttackPathState::Reachable => {
                !self.gaps.is_empty()
                    && !self
                        .gaps
                        .iter()
                        .any(|gap| gap.kind == AttackPathGapKind::MissingPreciseApplicationFacet)
            }
            AttackPathState::Reproduced => self.gaps.is_empty(),
            AttackPathState::Mitigated | AttackPathState::Regressed => false,
        };
        if initial.evidence_ids != expected_evidence
            || initial.observed_at != expected_time
            || !state_matches_gaps
        {
            return Err(AttackPathValidationError::State);
        }
        Ok(())
    }

    fn validate_verification_transition(
        &self,
        transition: &AttackPathTransition,
        from: AttackPathState,
        confidence: u8,
    ) -> Result<(), AttackPathValidationError> {
        let coverage = transition.coverage.ok_or(AttackPathValidationError::History)?;
        let outcome = transition.outcome.ok_or(AttackPathValidationError::History)?;
        let conditions = transition.conditions.clone().ok_or(AttackPathValidationError::History)?;
        let rebuilt_attempt = VerificationAttempt::new(
            &self.identity.value,
            &self.focused_verification.identity,
            coverage,
            outcome,
            conditions.clone(),
            transition.evidence_ids.clone(),
            transition.observed_at,
        );
        if transition.attempt_identity.as_deref() != Some(rebuilt_attempt.identity.as_str()) {
            return Err(AttackPathValidationError::Identity);
        }
        let (expected_state, expected_confidence) =
            verification_transition_state(coverage, outcome, from, confidence);
        if transition.to != expected_state || transition.path_confidence != expected_confidence {
            return Err(AttackPathValidationError::State);
        }
        if coverage == VerificationCoverage::CompleteComparable {
            let deployment_matches = conditions.deployment_identity.as_ref().is_some_and(|value| {
                self.shared_facets.iter().any(|facet| {
                    facet.kind == CorrelationFacetKind::Deployment && facet.value == *value
                })
            });
            if transition.evidence_ids.is_empty()
                || !deployment_matches
                || conditions.config_identities
                    != required_config_identities(&self.focused_verification)
            {
                return Err(AttackPathValidationError::History);
            }
        }
        Ok(())
    }

    /// Append one canonical attempt and apply the strict state machine.
    ///
    /// Returns `Ok(false)` for an already-recorded attempt.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error when the attempt is non-canonical, names another path or
    /// selection, is stale, lacks comparable deployment/evidence, or cannot prove reproduction.
    pub fn apply_verification(
        &mut self,
        attempt: VerificationAttempt,
    ) -> Result<bool, VerificationAttemptError> {
        if !attempt.is_canonical() {
            return Err(VerificationAttemptError::NonCanonical);
        }
        if attempt.path_identity != self.identity.value {
            return Err(VerificationAttemptError::PathMismatch);
        }
        if attempt.selection_identity != self.focused_verification.identity {
            return Err(VerificationAttemptError::SelectionMismatch);
        }
        if self.transitions.iter().any(|transition| {
            transition.attempt_identity.as_deref() == Some(attempt.identity.as_str())
        }) {
            return Ok(false);
        }
        if self
            .transitions
            .last()
            .is_some_and(|transition| attempt.observed_at < transition.observed_at)
        {
            return Err(VerificationAttemptError::Stale);
        }
        if attempt.coverage == VerificationCoverage::CompleteComparable {
            if attempt.evidence_ids.is_empty() {
                return Err(VerificationAttemptError::MissingEvidence);
            }
            let comparable = attempt.conditions.deployment_identity.as_ref().is_some_and(|value| {
                self.shared_facets.iter().any(|facet| {
                    facet.kind == CorrelationFacetKind::Deployment && facet.value == *value
                })
            });
            if !comparable {
                return Err(VerificationAttemptError::DeploymentMismatch);
            }
            if attempt.conditions.config_identities
                != required_config_identities(&self.focused_verification)
            {
                return Err(VerificationAttemptError::ConfigurationMismatch);
            }
        }
        if attempt.coverage == VerificationCoverage::CompleteComparable
            && attempt.outcome == VerificationOutcome::Reproduced
            && !self.has_reproduction_prerequisites()
        {
            return Err(VerificationAttemptError::MissingProofPrerequisite);
        }

        let from = self.state;
        let (to, confidence) = verification_transition_state(
            attempt.coverage,
            attempt.outcome,
            self.state,
            self.path_confidence,
        );
        self.state = to;
        self.path_confidence = confidence;
        if matches!(to, AttackPathState::Reproduced | AttackPathState::Regressed) {
            self.gaps.retain(|gap| {
                !matches!(
                    gap.kind,
                    AttackPathGapKind::MissingRuntimeHttpProof
                        | AttackPathGapKind::RuntimeProofRevisionUnbound
                )
            });
        }
        let transition = build_transition(TransitionInput {
            path_identity: &self.identity.value,
            from: Some(from),
            to,
            reason: AttackPathTransitionReason::Verification,
            attempt_identity: Some(&attempt.identity),
            coverage: Some(attempt.coverage),
            outcome: Some(attempt.outcome),
            conditions: Some(attempt.conditions),
            evidence_ids: attempt.evidence_ids,
            path_confidence: confidence,
            observed_at: attempt.observed_at,
        });
        self.transitions.push(transition);
        Ok(true)
    }

    fn has_reproduction_prerequisites(&self) -> bool {
        !self.gaps.iter().any(|gap| {
            matches!(
                gap.kind,
                AttackPathGapKind::MissingSharedWeakness
                    | AttackPathGapKind::MissingPreciseApplicationFacet
                    | AttackPathGapKind::MissingSourceFlow
                    | AttackPathGapKind::RevisionUnbound
                    | AttackPathGapKind::RevisionConflict
            )
        })
    }
}

const fn initial_path_confidence(state: AttackPathState) -> u8 {
    match state {
        AttackPathState::Suspected => 30,
        AttackPathState::Reachable => 60,
        AttackPathState::Reproduced => 95,
        AttackPathState::Mitigated | AttackPathState::Regressed => 0,
    }
}

fn required_config_identities(selection: &FocusedVerificationSelection) -> Vec<String> {
    normalized_strings(
        selection
            .static_rules
            .iter()
            .chain(&selection.runtime_probes)
            .filter_map(|selector| selector.config_identity.clone())
            .collect(),
    )
}

const fn verification_transition_state(
    coverage: VerificationCoverage,
    outcome: VerificationOutcome,
    current: AttackPathState,
    current_confidence: u8,
) -> (AttackPathState, u8) {
    match (coverage, outcome, current) {
        (
            VerificationCoverage::CompleteComparable,
            VerificationOutcome::Reproduced,
            AttackPathState::Mitigated,
        ) => (AttackPathState::Regressed, 100),
        (VerificationCoverage::CompleteComparable, VerificationOutcome::Reproduced, _) => {
            (AttackPathState::Reproduced, 95)
        }
        (
            VerificationCoverage::CompleteComparable,
            VerificationOutcome::NotReproduced,
            AttackPathState::Reproduced | AttackPathState::Regressed,
        ) => (AttackPathState::Mitigated, 90),
        _ => (current, current_confidence),
    }
}

fn is_strictly_ordered<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn scanner_selector_is_normalized(selector: &ScannerVerificationSelector) -> bool {
    bounded_nonempty(&selector.scanner_id)
        && bounded_nonempty(&selector.rule_id)
        && redact_text(&selector.scanner_id) == selector.scanner_id
        && redact_text(&selector.rule_id) == selector.rule_id
        && selector
            .rule_digest
            .as_deref()
            .is_none_or(|value| bounded_nonempty(value) && redact_text(value) == value)
        && selector
            .config_identity
            .as_deref()
            .is_none_or(|value| bounded_nonempty(value) && redact_text(value) == value)
}

fn request_selector_is_normalized(selector: &RequestVerificationSelector) -> bool {
    normalize_method(&selector.method) == selector.method
        && normalize_route(&selector.route).as_deref() == Some(selector.route.as_str())
        && selector.parameter.as_ref().is_none_or(|parameter| {
            bounded_nonempty(&parameter.name)
                && bounded_nonempty(&parameter.location)
                && normalized_parameter(parameter) == *parameter
        })
        && selector
            .authentication_persona
            .as_deref()
            .is_none_or(|persona| bounded_nonempty(persona) && redact_text(persona) == persona)
}

const fn bounded_nonempty(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_CORRELATION_FACET_BYTES
}

struct Candidate<'a> {
    finding: &'a Finding,
    record: FindingRecordV2,
    role: AttackPathMemberRole,
    facets: BTreeSet<CorrelationFacet>,
    has_source_flow: bool,
    http_evidence: Vec<RuntimeHttpProof>,
}

struct RuntimeHttpProof {
    exchange: HttpEvidence,
    target_revision: Option<String>,
}

/// Correlate one project-scoped finding inventory into canonical application attack paths.
#[must_use]
pub fn correlate_attack_paths(findings: &[Finding]) -> AttackPathCorrelation {
    if findings.len() > MAX_CORRELATION_FINDINGS {
        return AttackPathCorrelation {
            schema: ATTACK_PATH_CORRELATION_SCHEMA_V1.to_string(),
            status: AttackPathCorrelationStatus::Incomplete,
            paths: Vec::new(),
            gaps: vec![AttackPathCorrelationGap {
                kind: AttackPathCorrelationGapKind::FindingLimitExceeded,
                finding_identity: None,
            }],
        };
    }

    let mut gaps = BTreeSet::new();
    let candidates: Vec<Candidate<'_>> =
        findings.iter().filter_map(|finding| candidate(finding, &mut gaps)).collect();
    let mut paths = BTreeMap::new();
    let mut path_limit_hit = false;
    let mut pair_limit_hit = false;
    let mut pairs_evaluated = 0_usize;

    'source: for source in candidates.iter().filter(|candidate| {
        matches!(
            candidate.role,
            AttackPathMemberRole::SourceHypothesis | AttackPathMemberRole::ComponentHypothesis
        )
    }) {
        for runtime in candidates
            .iter()
            .filter(|candidate| candidate.role == AttackPathMemberRole::RuntimeObservation)
        {
            if pairs_evaluated == MAX_CORRELATION_PAIR_EVALUATIONS {
                pair_limit_hit = true;
                break 'source;
            }
            pairs_evaluated += 1;
            let shared: Vec<CorrelationFacet> =
                source.facets.intersection(&runtime.facets).cloned().collect();
            if shared.is_empty()
                || shared.iter().all(|facet| facet.kind == CorrelationFacetKind::Method)
            {
                continue;
            }
            let path = build_path(source, runtime, shared);
            if let Some(existing) = paths.get_mut(&path.identity.value) {
                if path_is_preferred(&path, existing) {
                    *existing = path;
                }
                continue;
            }
            if paths.len() == MAX_CORRELATED_PATHS {
                path_limit_hit = true;
                break 'source;
            }
            paths.insert(path.identity.value.clone(), path);
        }
    }

    if path_limit_hit {
        gaps.insert(AttackPathCorrelationGap {
            kind: AttackPathCorrelationGapKind::PathLimitExceeded,
            finding_identity: None,
        });
    }
    if pair_limit_hit {
        gaps.insert(AttackPathCorrelationGap {
            kind: AttackPathCorrelationGapKind::PairEvaluationLimitExceeded,
            finding_identity: None,
        });
    }
    let paths = paths.into_values().collect();
    let gaps: Vec<AttackPathCorrelationGap> = gaps.into_iter().collect();
    AttackPathCorrelation {
        schema: ATTACK_PATH_CORRELATION_SCHEMA_V1.to_string(),
        status: if gaps.is_empty() {
            AttackPathCorrelationStatus::Complete
        } else {
            AttackPathCorrelationStatus::Incomplete
        },
        paths,
        gaps,
    }
}

fn candidate<'a>(
    finding: &'a Finding,
    gaps: &mut BTreeSet<AttackPathCorrelationGap>,
) -> Option<Candidate<'a>> {
    let record = finding.canonical_appsec();
    if !finding.confidence.is_finite() || !(0.0..=1.0).contains(&finding.confidence) {
        gaps.insert(AttackPathCorrelationGap {
            kind: AttackPathCorrelationGapKind::InvalidFindingRecord,
            finding_identity: Some(record.identity.value),
        });
        return None;
    }
    if finding_detail_limit_exceeded(&record) {
        gaps.insert(AttackPathCorrelationGap {
            kind: AttackPathCorrelationGapKind::FindingDetailLimitExceeded,
            finding_identity: Some(record.identity.value),
        });
        return None;
    }
    let role = match record.location {
        ObservationLocation::Source { .. } => AttackPathMemberRole::SourceHypothesis,
        ObservationLocation::Runtime { .. } => AttackPathMemberRole::RuntimeObservation,
        ObservationLocation::Package { .. } | ObservationLocation::Artifact { .. } => {
            AttackPathMemberRole::ComponentHypothesis
        }
        ObservationLocation::Legacy { .. } => {
            gaps.insert(AttackPathCorrelationGap {
                kind: AttackPathCorrelationGapKind::UnsupportedLocation,
                finding_identity: Some(record.identity.value),
            });
            return None;
        }
    };
    let (facets, invalid_facet) = finding_facets(finding, &record);
    if invalid_facet {
        gaps.insert(AttackPathCorrelationGap {
            kind: AttackPathCorrelationGapKind::InvalidFacet,
            finding_identity: Some(record.identity.value.clone()),
        });
    }
    let has_source_flow = record
        .code_flows
        .iter()
        .flat_map(|flow| &flow.thread_flows)
        .any(|flow| flow.steps.len() >= 2);
    let http_evidence = record
        .evidence
        .iter()
        .filter_map(|evidence| match &evidence.payload {
            EvidencePayload::Http { exchange } => Some(RuntimeHttpProof {
                exchange: (**exchange).clone().redacted(),
                target_revision: evidence.provenance.target_revision.clone(),
            }),
            EvidencePayload::Text { .. } | EvidencePayload::Structured { .. } => None,
        })
        .collect();
    Some(Candidate { finding, record, role, facets, has_source_flow, http_evidence })
}

fn path_is_preferred(candidate: &AttackPath, existing: &AttackPath) -> bool {
    let candidate_rank = path_state_rank(candidate.state);
    let existing_rank = path_state_rank(existing.state);
    candidate_rank > existing_rank
        || (candidate_rank == existing_rank
            && serde_json::to_string(candidate)
                .unwrap_or_else(|_| candidate.identity.value.clone())
                > serde_json::to_string(existing)
                    .unwrap_or_else(|_| existing.identity.value.clone()))
}

const fn path_state_rank(state: AttackPathState) -> u8 {
    match state {
        AttackPathState::Suspected => 0,
        AttackPathState::Reachable => 1,
        AttackPathState::Reproduced => 2,
        AttackPathState::Mitigated => 3,
        AttackPathState::Regressed => 4,
    }
}

fn finding_detail_limit_exceeded(record: &FindingRecordV2) -> bool {
    record.correlation_keys.len() > MAX_CORRELATION_DETAILS_PER_FINDING
        || record.evidence.len() > MAX_CORRELATION_DETAILS_PER_FINDING
        || record.code_flows.len() > MAX_CORRELATION_DETAILS_PER_FINDING
        || record.code_flows.iter().any(|flow| {
            flow.thread_flows.len() > MAX_CORRELATION_DETAILS_PER_FINDING
                || flow
                    .thread_flows
                    .iter()
                    .any(|thread| thread.steps.len() > MAX_CORRELATION_DETAILS_PER_FINDING)
        })
}

fn finding_facets(
    finding: &Finding,
    record: &FindingRecordV2,
) -> (BTreeSet<CorrelationFacet>, bool) {
    let mut facets = BTreeSet::new();
    let mut invalid = false;

    if let Some(cwe) = finding.cwe_id {
        insert_facet(
            &mut facets,
            &mut invalid,
            CorrelationFacetKind::Weakness,
            "cwe",
            format!("CWE-{cwe}"),
        );
    }
    if let Some(owasp) = &finding.owasp_category {
        insert_facet(
            &mut facets,
            &mut invalid,
            CorrelationFacetKind::Weakness,
            "owasp",
            owasp.clone(),
        );
    }
    if let Some(revision) = &record.provenance.target_revision {
        insert_facet(
            &mut facets,
            &mut invalid,
            CorrelationFacetKind::Deployment,
            "target-revision",
            revision.clone(),
        );
    }
    match &record.location {
        ObservationLocation::Runtime { uri, route, parameter } => {
            if let Ok(url) = Url::parse(uri) {
                let host = url.host_str().unwrap_or_default().to_lowercase();
                let port = url.port().map_or_else(String::new, |value| format!(":{value}"));
                insert_facet(
                    &mut facets,
                    &mut invalid,
                    CorrelationFacetKind::Application,
                    "runtime-origin",
                    format!("{}://{host}{port}", url.scheme()),
                );
            }
            if let Some(route) = route {
                insert_facet(
                    &mut facets,
                    &mut invalid,
                    CorrelationFacetKind::Route,
                    "http-route",
                    route.clone(),
                );
            }
            if let Some(parameter) = parameter {
                insert_parameter_facet(&mut facets, &mut invalid, parameter);
            }
        }
        ObservationLocation::Package { ecosystem, name, .. } => insert_facet(
            &mut facets,
            &mut invalid,
            CorrelationFacetKind::Component,
            ecosystem,
            name.clone(),
        ),
        ObservationLocation::Artifact { uri, digest } => insert_facet(
            &mut facets,
            &mut invalid,
            CorrelationFacetKind::Component,
            "artifact",
            digest.clone().unwrap_or_else(|| uri.clone()),
        ),
        ObservationLocation::Source { .. } | ObservationLocation::Legacy { .. } => {}
    }
    for evidence in &record.evidence {
        if let EvidencePayload::Http { exchange } = &evidence.payload {
            insert_facet(
                &mut facets,
                &mut invalid,
                CorrelationFacetKind::Method,
                "http-method",
                exchange.method.clone(),
            );
            if let Some(route) = &exchange.route {
                insert_facet(
                    &mut facets,
                    &mut invalid,
                    CorrelationFacetKind::Route,
                    "http-route",
                    route.clone(),
                );
            }
            if let Some(parameter) = &exchange.parameter {
                insert_parameter_facet(&mut facets, &mut invalid, parameter);
            }
        }
    }
    for key in &record.correlation_keys {
        let kind = facet_kind_for_key(key);
        insert_facet(&mut facets, &mut invalid, kind, &key.namespace, key.value.clone());
    }
    (facets, invalid)
}

fn facet_kind_for_key(key: &CorrelationKey) -> CorrelationFacetKind {
    match key.namespace.as_str() {
        "application" | "app" | "service" => CorrelationFacetKind::Application,
        "deployment" | "revision" | "target-revision" => CorrelationFacetKind::Deployment,
        "route" | "http-route" => CorrelationFacetKind::Route,
        "operation" | "dast-operation" => CorrelationFacetKind::Operation,
        "method" | "http-method" => CorrelationFacetKind::Method,
        "parameter" | "http-parameter" => CorrelationFacetKind::Parameter,
        "component" | "package" | "purl" => CorrelationFacetKind::Component,
        "cwe" | "owasp" | "weakness" => CorrelationFacetKind::Weakness,
        "test" | "test-case" => CorrelationFacetKind::Test,
        _ => CorrelationFacetKind::Explicit,
    }
}

fn insert_parameter_facet(
    facets: &mut BTreeSet<CorrelationFacet>,
    invalid: &mut bool,
    parameter: &HttpParameterIdentity,
) {
    insert_facet(
        facets,
        invalid,
        CorrelationFacetKind::Parameter,
        "http-parameter",
        format!("{}:{}", parameter.location, parameter.name),
    );
}

fn insert_facet(
    facets: &mut BTreeSet<CorrelationFacet>,
    invalid: &mut bool,
    kind: CorrelationFacetKind,
    namespace: impl Into<String>,
    value: impl Into<String>,
) {
    if let Some(facet) = CorrelationFacet::from_parts(kind, namespace, value) {
        facets.insert(facet);
    } else {
        *invalid = true;
    }
}

fn build_path(
    source: &Candidate<'_>,
    runtime: &Candidate<'_>,
    mut shared_facets: Vec<CorrelationFacet>,
) -> AttackPath {
    shared_facets.sort();
    shared_facets.dedup();
    let assessment = assess_path_proof(source, runtime, &shared_facets);
    let state = assessment.state;
    let path_confidence = assessment.path_confidence;
    let members = vec![path_member(source), path_member(runtime)];
    let identity = attack_path_identity(&members, &shared_facets);
    let focused_verification = derive_selection(&identity.value, source, runtime, &shared_facets);
    let evidence_ids = normalized_strings(
        members.iter().flat_map(|member| member.evidence_ids.iter().cloned()).collect(),
    );
    let observed_at =
        members.iter().map(|member| member.provenance.collected_at).max().unwrap_or_else(Utc::now);
    let transition = build_transition(TransitionInput {
        path_identity: &identity.value,
        from: None,
        to: state,
        reason: AttackPathTransitionReason::Correlated,
        attempt_identity: None,
        coverage: None,
        outcome: None,
        conditions: None,
        evidence_ids,
        path_confidence,
        observed_at,
    });
    AttackPath {
        schema: ATTACK_PATH_SCHEMA_V1.to_string(),
        identity,
        state,
        path_confidence,
        severity: source.finding.severity.max(runtime.finding.severity),
        shared_facets,
        members,
        gaps: assessment.gaps,
        focused_verification,
        transitions: vec![transition],
    }
}

struct PathProofAssessment {
    state: AttackPathState,
    path_confidence: u8,
    gaps: Vec<AttackPathGap>,
}

fn assess_path_proof(
    source: &Candidate<'_>,
    runtime: &Candidate<'_>,
    shared_facets: &[CorrelationFacet],
) -> PathProofAssessment {
    let has_weakness =
        shared_facets.iter().any(|facet| facet.kind == CorrelationFacetKind::Weakness);
    let has_precise = shared_facets.iter().any(|facet| {
        matches!(
            facet.kind,
            CorrelationFacetKind::Application
                | CorrelationFacetKind::Route
                | CorrelationFacetKind::Operation
                | CorrelationFacetKind::Parameter
                | CorrelationFacetKind::Component
        )
    });
    let source_deployments: BTreeSet<&CorrelationFacet> = source
        .facets
        .iter()
        .filter(|facet| facet.kind == CorrelationFacetKind::Deployment)
        .collect();
    let runtime_deployments: BTreeSet<&CorrelationFacet> = runtime
        .facets
        .iter()
        .filter(|facet| facet.kind == CorrelationFacetKind::Deployment)
        .collect();
    let has_shared_deployment =
        source_deployments.iter().any(|facet| runtime_deployments.contains(facet));
    let deployment_conflict =
        !source_deployments.is_empty() && !runtime_deployments.is_empty() && !has_shared_deployment;
    let has_http_evidence = !runtime.http_evidence.is_empty();
    let has_http_proof = runtime.http_evidence.iter().any(|proof| {
        proof.target_revision.as_ref().is_some_and(|revision| {
            source_deployments
                .iter()
                .any(|facet| facet.value == *revision && runtime_deployments.contains(facet))
        })
    });
    let reproduced = has_weakness
        && has_precise
        && source.has_source_flow
        && has_http_proof
        && has_shared_deployment;
    let state = if reproduced {
        AttackPathState::Reproduced
    } else if has_precise {
        AttackPathState::Reachable
    } else {
        AttackPathState::Suspected
    };
    let path_confidence = match state {
        AttackPathState::Suspected => 30,
        AttackPathState::Reachable => 60,
        AttackPathState::Reproduced => 95,
        AttackPathState::Mitigated | AttackPathState::Regressed => unreachable!(),
    };
    let mut gaps = BTreeSet::new();
    if !has_weakness {
        gaps.insert(AttackPathGap { kind: AttackPathGapKind::MissingSharedWeakness });
    }
    if !has_precise {
        gaps.insert(AttackPathGap { kind: AttackPathGapKind::MissingPreciseApplicationFacet });
    }
    if !source.has_source_flow {
        gaps.insert(AttackPathGap { kind: AttackPathGapKind::MissingSourceFlow });
    }
    if !has_http_evidence {
        gaps.insert(AttackPathGap { kind: AttackPathGapKind::MissingRuntimeHttpProof });
    } else if has_shared_deployment && !has_http_proof {
        gaps.insert(AttackPathGap { kind: AttackPathGapKind::RuntimeProofRevisionUnbound });
    }
    if deployment_conflict {
        gaps.insert(AttackPathGap { kind: AttackPathGapKind::RevisionConflict });
    } else if !has_shared_deployment {
        gaps.insert(AttackPathGap { kind: AttackPathGapKind::RevisionUnbound });
    }
    PathProofAssessment { state, path_confidence, gaps: gaps.into_iter().collect() }
}

fn path_member(candidate: &Candidate<'_>) -> AttackPathMember {
    let mut evidence_ids: Vec<String> =
        candidate.record.evidence.iter().map(|evidence| evidence.identity.clone()).collect();
    evidence_ids = normalized_strings(evidence_ids);
    AttackPathMember {
        finding_identity: candidate.record.identity.value.clone(),
        module_id: candidate.finding.module_id.clone(),
        role: candidate.role,
        location: candidate.record.location.clone(),
        provenance: candidate.record.provenance.clone(),
        evidence_ids,
        scanner_confidence: candidate.finding.confidence,
    }
}

fn attack_path_identity(
    members: &[AttackPathMember],
    shared_facets: &[CorrelationFacet],
) -> AttackPathIdentity {
    let mut parts = vec![ATTACK_PATH_SCHEMA_V1.to_string()];
    parts.extend(
        members
            .iter()
            .map(|member| format!("{}\0{}", member.role.as_str(), member.finding_identity)),
    );
    parts.extend(shared_facets.iter().map(CorrelationFacet::identity_part));
    AttackPathIdentity {
        schema: ATTACK_PATH_IDENTITY_SCHEMA_V1.to_string(),
        value: digest_parts(ATTACK_PATH_IDENTITY_SCHEMA_V1, &parts),
    }
}

fn derive_selection(
    path_identity: &str,
    source: &Candidate<'_>,
    runtime: &Candidate<'_>,
    shared_facets: &[CorrelationFacet],
) -> FocusedVerificationSelection {
    let static_rules = scanner_selectors(&source.record.provenance);
    let runtime_probes = scanner_selectors(&runtime.record.provenance);
    let mut requests = BTreeSet::new();
    for proof in &runtime.http_evidence {
        let evidence = &proof.exchange;
        let route = evidence
            .route
            .clone()
            .or_else(|| Url::parse(&evidence.url).ok().map(|url| url.path().to_string()));
        let Some(route) = route.and_then(|value| normalize_route(&value)) else {
            continue;
        };
        let method = normalize_method(&evidence.method);
        if method.is_empty() {
            continue;
        }
        requests.insert(RequestVerificationSelector {
            method,
            route,
            parameter: evidence.parameter.as_ref().map(normalized_parameter).filter(|parameter| {
                bounded_nonempty(&parameter.name) && bounded_nonempty(&parameter.location)
            }),
            authentication_persona: evidence
                .authentication_persona
                .as_deref()
                .map(redact_text)
                .filter(|value| bounded_nonempty(value)),
        });
    }
    let tests: Vec<String> = shared_facets
        .iter()
        .filter(|facet| facet.kind == CorrelationFacetKind::Test)
        .map(|facet| facet.value.clone())
        .collect();
    let requests: Vec<RequestVerificationSelector> = requests.into_iter().collect();
    let mut selection = FocusedVerificationSelection {
        schema: FOCUSED_VERIFICATION_SCHEMA_V1.to_string(),
        identity: String::new(),
        path_identity: path_identity.to_string(),
        static_rules,
        runtime_probes,
        requests,
        tests: normalized_strings(tests),
    };
    selection.identity = focused_selection_identity(&selection);
    selection
}

fn scanner_selectors(provenance: &ScannerProvenance) -> Vec<ScannerVerificationSelector> {
    let scanner_id = redact_text(&provenance.scanner_id);
    let Some(rule_id) = provenance.rule_id.as_deref().map(redact_text) else {
        return Vec::new();
    };
    if !bounded_nonempty(&scanner_id) || !bounded_nonempty(&rule_id) {
        return Vec::new();
    }
    vec![ScannerVerificationSelector {
        scanner_id,
        rule_id,
        rule_digest: provenance
            .rule_digest
            .as_deref()
            .map(redact_text)
            .filter(|value| bounded_nonempty(value)),
        config_identity: provenance
            .config_identity
            .as_deref()
            .map(redact_text)
            .filter(|value| bounded_nonempty(value)),
    }]
}

fn focused_selection_identity(selection: &FocusedVerificationSelection) -> String {
    let mut parts = vec![selection.path_identity.clone()];
    for selector in &selection.static_rules {
        parts.push(scanner_selector_identity_part("static", selector));
    }
    for selector in &selection.runtime_probes {
        parts.push(scanner_selector_identity_part("runtime", selector));
    }
    for request in &selection.requests {
        parts.push(format!(
            "request\0{}\0{}\0{}\0{}",
            request.method,
            request.route,
            request.parameter.as_ref().map_or_else(String::new, |parameter| {
                format!("{}:{}", parameter.location, parameter.name)
            }),
            request.authentication_persona.as_deref().unwrap_or_default()
        ));
    }
    parts.extend(selection.tests.iter().map(|test| format!("test\0{test}")));
    digest_parts(FOCUSED_VERIFICATION_SCHEMA_V1, &parts)
}

fn scanner_selector_identity_part(kind: &str, selector: &ScannerVerificationSelector) -> String {
    format!(
        "{kind}\0{}\0{}\0{}\0{}",
        selector.scanner_id,
        selector.rule_id,
        selector.rule_digest.as_deref().unwrap_or_default(),
        selector.config_identity.as_deref().unwrap_or_default()
    )
}

struct TransitionInput<'a> {
    path_identity: &'a str,
    from: Option<AttackPathState>,
    to: AttackPathState,
    reason: AttackPathTransitionReason,
    attempt_identity: Option<&'a str>,
    coverage: Option<VerificationCoverage>,
    outcome: Option<VerificationOutcome>,
    conditions: Option<VerificationConditions>,
    evidence_ids: Vec<String>,
    path_confidence: u8,
    observed_at: DateTime<Utc>,
}

fn build_transition(input: TransitionInput<'_>) -> AttackPathTransition {
    let TransitionInput {
        path_identity,
        from,
        to,
        reason,
        attempt_identity,
        coverage,
        outcome,
        conditions,
        evidence_ids,
        path_confidence,
        observed_at,
    } = input;
    let evidence_ids = normalized_strings(evidence_ids);
    let mut parts = vec![
        path_identity.to_string(),
        from.map_or_else(String::new, |state| state.as_str().to_string()),
        to.as_str().to_string(),
        reason.as_str().to_string(),
        attempt_identity.unwrap_or_default().to_string(),
        coverage.map_or_else(String::new, |value| value.as_str().to_string()),
        outcome.map_or_else(String::new, |value| value.as_str().to_string()),
        conditions.as_ref().and_then(|value| value.deployment_identity.clone()).unwrap_or_default(),
        path_confidence.to_string(),
        observed_at.to_rfc3339(),
    ];
    if let Some(conditions) = &conditions {
        parts.extend(conditions.config_identities.iter().cloned());
    }
    parts.extend(evidence_ids.iter().cloned());
    AttackPathTransition {
        schema: ATTACK_PATH_TRANSITION_SCHEMA_V1.to_string(),
        identity: digest_parts(ATTACK_PATH_TRANSITION_SCHEMA_V1, &parts),
        from,
        to,
        reason,
        attempt_identity: attempt_identity.map(str::to_string),
        coverage,
        outcome,
        conditions,
        evidence_ids,
        path_confidence,
        observed_at,
    }
}

fn verification_attempt_identity(
    path_identity: &str,
    selection_identity: &str,
    coverage: VerificationCoverage,
    outcome: VerificationOutcome,
    conditions: &VerificationConditions,
    evidence_ids: &[String],
    observed_at: DateTime<Utc>,
) -> String {
    let mut parts = vec![
        path_identity.to_string(),
        selection_identity.to_string(),
        coverage.as_str().to_string(),
        outcome.as_str().to_string(),
        conditions.deployment_identity.clone().unwrap_or_default(),
        observed_at.to_rfc3339(),
    ];
    parts.extend(conditions.config_identities.iter().cloned());
    parts.extend(evidence_ids.iter().cloned());
    digest_parts(VERIFICATION_ATTEMPT_SCHEMA_V1, &parts)
}

fn digest_parts(domain: &str, parts: &[String]) -> String {
    let mut hasher = Sha256::new();
    add_hash_part(&mut hasher, domain);
    for part in parts {
        add_hash_part(&mut hasher, part);
    }
    format!("{:x}", hasher.finalize())
}

fn add_hash_part(hasher: &mut Sha256, value: &str) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(value.as_bytes());
}

fn normalize_facet_value(kind: CorrelationFacetKind, value: &str) -> Option<String> {
    let value = redact_text(value.trim());
    if value.is_empty() || value.len() > MAX_CORRELATION_FACET_BYTES {
        return None;
    }
    let normalized = match kind {
        CorrelationFacetKind::Route => normalize_route(&value)?,
        CorrelationFacetKind::Method => normalize_method(&value),
        CorrelationFacetKind::Parameter
        | CorrelationFacetKind::Component
        | CorrelationFacetKind::Weakness
        | CorrelationFacetKind::Application => value.to_lowercase(),
        CorrelationFacetKind::Deployment
        | CorrelationFacetKind::Operation
        | CorrelationFacetKind::Test
        | CorrelationFacetKind::Explicit => value,
    };
    (!normalized.is_empty()).then_some(normalized)
}

fn normalize_route(value: &str) -> Option<String> {
    let route = Url::parse(value).map_or_else(
        |_| value.split(['?', '#']).next().unwrap_or_default().trim().to_string(),
        |url| url.path().to_string(),
    );
    if !route.starts_with('/') || route.len() > MAX_CORRELATION_FACET_BYTES {
        return None;
    }
    Some(route)
}

fn normalize_method(value: &str) -> String {
    let method = value.trim().to_ascii_uppercase();
    if method.bytes().all(|byte| byte.is_ascii_uppercase() || byte == b'-') {
        method
    } else {
        String::new()
    }
}

fn normalized_parameter(parameter: &HttpParameterIdentity) -> HttpParameterIdentity {
    HttpParameterIdentity::new(
        redact_text(parameter.name.trim()).to_lowercase(),
        redact_text(parameter.location.trim()).to_lowercase(),
    )
}

fn normalized_strings(values: Vec<String>) -> Vec<String> {
    let mut values: Vec<String> = values
        .into_iter()
        .map(|value| redact_text(value.trim()))
        .filter(|value| !value.is_empty() && value.len() <= MAX_CORRELATION_FACET_BYTES)
        .collect();
    values.sort();
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::TimeZone;

    use super::*;
    use crate::observation::{
        AgentAnalysisRecord, CodeFlow, CodeFlowStep, EvidenceRecord, SourceRegion, ThreadFlow,
    };

    fn collected_at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).single().expect("fixed timestamp")
    }

    fn source_finding(include_flow: bool, route: Option<&str>, revision: Option<&str>) -> Finding {
        let mut finding = Finding::new(
            "semgrep",
            Severity::High,
            "SQL construction from request input",
            "A request value reaches a query sink.",
            "src/routes/users.rs:18",
        )
        .with_location(ObservationLocation::Source {
            path: "src/routes/users.rs".to_string(),
            region: Some(SourceRegion::new(18)),
        })
        .with_cwe(89)
        .with_confidence(0.81)
        .with_provenance(
            ScannerProvenance::new("semgrep", collected_at())
                .with_version("1.145.0")
                .with_rule("rust.sql.user-input", Some("rule-digest".to_string()))
                .with_config("appsec-pack"),
        )
        .with_evidence("query sink");
        if include_flow {
            finding = finding.with_code_flows(vec![CodeFlow {
                message: Some("request to query".to_string()),
                thread_flows: vec![ThreadFlow {
                    message: None,
                    steps: vec![
                        CodeFlowStep::new(ObservationLocation::Source {
                            path: "src/routes/users.rs".to_string(),
                            region: Some(SourceRegion::new(11)),
                        }),
                        CodeFlowStep::new(ObservationLocation::Source {
                            path: "src/routes/users.rs".to_string(),
                            region: Some(SourceRegion::new(18)),
                        }),
                    ],
                }],
            }]);
        }
        if let Some(route) = route {
            finding = finding.with_correlation_key(CorrelationKey::new("route", route));
        }
        if let Some(revision) = revision {
            finding = finding
                .with_correlation_key(CorrelationKey::new("deployment", revision))
                .with_provenance(
                    ScannerProvenance::new("semgrep", collected_at())
                        .with_version("1.145.0")
                        .with_rule("rust.sql.user-input", Some("rule-digest".to_string()))
                        .with_config("appsec-pack")
                        .with_target_revision(revision),
                );
        }
        finding
    }

    fn runtime_finding(
        include_http: bool,
        route: Option<&str>,
        revision: Option<&str>,
        cwe: Option<u32>,
    ) -> Finding {
        let mut finding = Finding::new(
            "nuclei",
            Severity::Critical,
            "Runtime database behavior",
            "The approved probe reproduced database error behavior.",
            "https://app.example.test/users/42?id=42",
        )
        .with_location(ObservationLocation::Runtime {
            uri: "https://app.example.test/users/42?id=42".to_string(),
            route: route.map(str::to_string),
            parameter: Some(HttpParameterIdentity::new("id", "query")),
        })
        .with_confidence(0.93)
        .with_provenance(
            ScannerProvenance::new("nuclei", collected_at())
                .with_version("3.11.1")
                .with_rule("scorchkit-sqli", Some("template-digest".to_string()))
                .with_config("trusted-collection"),
        );
        if let Some(cwe) = cwe {
            finding = finding.with_cwe(cwe);
        }
        if let Some(route) = route {
            finding = finding.with_correlation_key(CorrelationKey::new("route", route));
        }
        if let Some(revision) = revision {
            finding = finding
                .with_correlation_key(CorrelationKey::new("deployment", revision))
                .with_provenance(
                    ScannerProvenance::new("nuclei", collected_at())
                        .with_version("3.11.1")
                        .with_rule("scorchkit-sqli", Some("template-digest".to_string()))
                        .with_config("trusted-collection")
                        .with_target_revision(revision),
                );
        }
        if include_http {
            let mut headers = HashMap::new();
            headers.insert("Authorization".to_string(), "Bearer fixture-secret".to_string());
            finding = finding.with_http_evidence(
                HttpEvidence::new(
                    "POST",
                    "https://app.example.test/users/42?id=fixture-secret",
                    500,
                )
                .with_route(route.unwrap_or("/users/{id}"))
                .with_parameter(HttpParameterIdentity::new("id", "query"))
                .with_authentication_persona("user")
                .with_request_headers(headers)
                .with_request_body("password=fixture-secret"),
            );
        }
        finding
    }

    fn correlated_path() -> AttackPath {
        let result = correlate_attack_paths(&[
            source_finding(true, Some("/users/{id}"), Some("rev-1")),
            runtime_finding(true, Some("/users/{id}"), Some("rev-1"), Some(89)),
        ]);
        assert_eq!(result.status, AttackPathCorrelationStatus::Complete);
        assert_eq!(result.paths.len(), 1);
        result.paths.into_iter().next().expect("one path")
    }

    fn rebuild_initial_path(path: &mut AttackPath) {
        path.identity = attack_path_identity(&path.members, &path.shared_facets);
        path.focused_verification.path_identity.clone_from(&path.identity.value);
        path.focused_verification.identity = focused_selection_identity(&path.focused_verification);
        let initial = path.transitions[0].clone();
        path.transitions[0] = build_transition(TransitionInput {
            path_identity: &path.identity.value,
            from: initial.from,
            to: initial.to,
            reason: initial.reason,
            attempt_identity: initial.attempt_identity.as_deref(),
            coverage: initial.coverage,
            outcome: initial.outcome,
            conditions: initial.conditions,
            evidence_ids: initial.evidence_ids,
            path_confidence: initial.path_confidence,
            observed_at: initial.observed_at,
        });
    }

    fn rebuild_transition(path: &mut AttackPath, index: usize) {
        let transition = path.transitions[index].clone();
        path.transitions[index] = build_transition(TransitionInput {
            path_identity: &path.identity.value,
            from: transition.from,
            to: transition.to,
            reason: transition.reason,
            attempt_identity: transition.attempt_identity.as_deref(),
            coverage: transition.coverage,
            outcome: transition.outcome,
            conditions: transition.conditions,
            evidence_ids: transition.evidence_ids,
            path_confidence: transition.path_confidence,
            observed_at: transition.observed_at,
        });
    }

    fn rebuild_verification_transition(path: &mut AttackPath, index: usize) {
        let mut transition = path.transitions[index].clone();
        let attempt = VerificationAttempt::new(
            &path.identity.value,
            &path.focused_verification.identity,
            transition.coverage.expect("verification coverage"),
            transition.outcome.expect("verification outcome"),
            transition.conditions.clone().expect("verification conditions"),
            transition.evidence_ids.clone(),
            transition.observed_at,
        );
        transition.attempt_identity = Some(attempt.identity);
        path.transitions[index] = transition;
        rebuild_transition(path, index);
    }

    #[test]
    fn complete_source_runtime_proof_is_reproduced_and_minimally_selected() {
        let path = correlated_path();
        assert_eq!(path.validate(), Ok(()));
        assert_eq!(path.schema, ATTACK_PATH_SCHEMA_V1);
        assert_eq!(path.identity.schema, ATTACK_PATH_IDENTITY_SCHEMA_V1);
        assert_eq!(path.state, AttackPathState::Reproduced);
        assert_eq!(path.path_confidence, 95);
        assert_eq!(path.severity, Severity::Critical);
        assert!(path.gaps.is_empty());
        assert_eq!(path.members.len(), 2);
        assert!((path.members[0].scanner_confidence - 0.81).abs() < f64::EPSILON);
        assert!((path.members[1].scanner_confidence - 0.93).abs() < f64::EPSILON);
        assert_eq!(path.focused_verification.static_rules.len(), 1);
        assert_eq!(path.focused_verification.runtime_probes.len(), 1);
        assert_eq!(path.focused_verification.requests.len(), 1);
        let request = &path.focused_verification.requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.route, "/users/{id}");
        assert_eq!(request.authentication_persona.as_deref(), Some("user"));
        let json = serde_json::to_string(&path).expect("serialize path");
        assert!(!json.contains("fixture-secret"));
        assert!(!json.contains("Authorization"));
        assert!(!json.contains("password"));
    }

    #[test]
    fn weakness_only_is_suspected_and_precise_without_weakness_is_reachable() {
        let weakness_only = correlate_attack_paths(&[
            source_finding(true, None, Some("rev-1")),
            runtime_finding(true, None, Some("rev-1"), Some(89)),
        ]);
        assert_eq!(weakness_only.paths.len(), 1);
        assert_eq!(weakness_only.paths[0].state, AttackPathState::Suspected);
        assert!(weakness_only.paths[0]
            .gaps
            .iter()
            .any(|gap| gap.kind == AttackPathGapKind::MissingPreciseApplicationFacet));
        assert_eq!(weakness_only.paths[0].validate(), Ok(()));

        let precise_only = correlate_attack_paths(&[
            source_finding(true, Some("/users/{id}"), Some("rev-1")),
            runtime_finding(true, Some("/users/{id}"), Some("rev-1"), Some(78)),
        ]);
        assert_eq!(precise_only.paths.len(), 1);
        assert_eq!(precise_only.paths[0].state, AttackPathState::Reachable);
        assert!(precise_only.paths[0]
            .gaps
            .iter()
            .any(|gap| gap.kind == AttackPathGapKind::MissingSharedWeakness));
    }

    #[test]
    fn every_reproduction_prerequisite_has_an_independent_gap() {
        let missing_flow = correlate_attack_paths(&[
            source_finding(false, Some("/users/{id}"), Some("rev-1")),
            runtime_finding(true, Some("/users/{id}"), Some("rev-1"), Some(89)),
        ]);
        assert_eq!(missing_flow.paths[0].state, AttackPathState::Reachable);
        assert!(missing_flow.paths[0]
            .gaps
            .iter()
            .any(|gap| gap.kind == AttackPathGapKind::MissingSourceFlow));

        let missing_http = correlate_attack_paths(&[
            source_finding(true, Some("/users/{id}"), Some("rev-1")),
            runtime_finding(false, Some("/users/{id}"), Some("rev-1"), Some(89)),
        ]);
        assert!(missing_http.paths[0]
            .gaps
            .iter()
            .any(|gap| gap.kind == AttackPathGapKind::MissingRuntimeHttpProof));

        let unbound = correlate_attack_paths(&[
            source_finding(true, Some("/users/{id}"), None),
            runtime_finding(true, Some("/users/{id}"), None, Some(89)),
        ]);
        assert!(unbound.paths[0]
            .gaps
            .iter()
            .any(|gap| gap.kind == AttackPathGapKind::RevisionUnbound));

        let conflict = correlate_attack_paths(&[
            source_finding(true, Some("/users/{id}"), Some("rev-source")),
            runtime_finding(true, Some("/users/{id}"), Some("rev-runtime"), Some(89)),
        ]);
        assert!(conflict.paths[0]
            .gaps
            .iter()
            .any(|gap| gap.kind == AttackPathGapKind::RevisionConflict));

        let mut stale_runtime =
            runtime_finding(false, Some("/users/{id}"), Some("rev-1"), Some(89));
        stale_runtime.appsec.evidence.push(EvidenceRecord::http(
            HttpEvidence::new("POST", "https://app.example.test/users/42", 500)
                .with_route("/users/{id}"),
            ScannerProvenance::new("nuclei", collected_at()).with_target_revision("rev-old"),
        ));
        let stale_proof = correlate_attack_paths(&[
            source_finding(true, Some("/users/{id}"), Some("rev-1")),
            stale_runtime,
        ]);
        assert_eq!(stale_proof.paths[0].state, AttackPathState::Reachable);
        assert!(stale_proof.paths[0]
            .gaps
            .iter()
            .any(|gap| gap.kind == AttackPathGapKind::RuntimeProofRevisionUnbound));
    }

    #[test]
    fn titles_and_agent_analysis_cannot_create_or_promote_a_path() {
        let mut source = source_finding(true, None, None);
        source.cwe_id = None;
        source.appsec.correlation_keys.clear();
        source.appsec.refresh_identity(&source.module_id, &source.title, None);
        let mut runtime = runtime_finding(true, Some("/unrelated"), None, None);
        runtime.title = "SQL injection confirmed by runtime".to_string();
        runtime = runtime.with_agent_analysis(AgentAnalysisRecord::new(
            "codex",
            Some("trusted-security".to_string()),
            "This looks confirmed.",
            Vec::new(),
            collected_at(),
        ));
        let result = correlate_attack_paths(&[source, runtime]);
        assert!(result.paths.is_empty());
    }

    #[test]
    fn correlation_is_order_stable_and_does_not_mutate_findings() {
        let source = source_finding(true, Some("/users/{id}"), Some("rev-1"));
        let runtime = runtime_finding(true, Some("/users/{id}"), Some("rev-1"), Some(89));
        let original = vec![source.clone(), runtime.clone()];
        let before = serde_json::to_value(&original).expect("serialize input");
        let forward = correlate_attack_paths(&original);
        let reverse = correlate_attack_paths(&[runtime, source]);
        let after = serde_json::to_value(&original).expect("serialize input after correlation");
        assert_eq!(before, after);
        assert_eq!(forward.paths[0].identity, reverse.paths[0].identity);
        assert_eq!(forward.paths[0].focused_verification, reverse.paths[0].focused_verification);

        let source_without_flow = source_finding(false, Some("/users/{id}"), Some("rev-1"));
        let source_with_flow = source_finding(true, Some("/users/{id}"), Some("rev-1"));
        let runtime = runtime_finding(true, Some("/users/{id}"), Some("rev-1"), Some(89));
        let first = correlate_attack_paths(&[
            source_without_flow.clone(),
            source_with_flow.clone(),
            runtime.clone(),
        ]);
        let second = correlate_attack_paths(&[runtime, source_with_flow, source_without_flow]);
        assert_eq!(first.paths, second.paths);
        assert_eq!(first.paths[0].state, AttackPathState::Reproduced);
    }

    #[test]
    fn invalid_facets_and_finding_ceiling_are_typed_incomplete_results() {
        let oversized = "x".repeat(MAX_CORRELATION_FACET_BYTES + 1);
        let source = source_finding(true, Some("/users/{id}"), Some("rev-1"))
            .with_correlation_key(CorrelationKey::new("route", oversized));
        let result = correlate_attack_paths(&[
            source,
            runtime_finding(true, Some("/users/{id}"), Some("rev-1"), Some(89)),
        ]);
        assert_eq!(result.status, AttackPathCorrelationStatus::Incomplete);
        assert!(result
            .gaps
            .iter()
            .any(|gap| gap.kind == AttackPathCorrelationGapKind::InvalidFacet));

        let too_many = vec![source_finding(false, None, None); MAX_CORRELATION_FINDINGS + 1];
        let limited = correlate_attack_paths(&too_many);
        assert_eq!(limited.status, AttackPathCorrelationStatus::Incomplete);
        assert!(limited.paths.is_empty());
        assert_eq!(limited.gaps[0].kind, AttackPathCorrelationGapKind::FindingLimitExceeded);

        let exact = vec![source_finding(false, None, None); MAX_CORRELATION_FINDINGS];
        let accepted = correlate_attack_paths(&exact);
        assert_eq!(accepted.status, AttackPathCorrelationStatus::Complete);
        assert!(accepted.paths.is_empty());
    }

    #[test]
    fn method_only_pairs_are_rejected_and_duplicate_pairs_do_not_consume_the_path_ceiling() {
        let source = source_finding(false, None, None)
            .with_correlation_key(CorrelationKey::new("method", "GET"));
        let runtime = runtime_finding(false, Some("/runtime-only"), None, None)
            .with_correlation_key(CorrelationKey::new("method", "GET"));
        assert!(correlate_attack_paths(&[source, runtime]).paths.is_empty());

        let source = source_finding(true, Some("/users/{id}"), Some("rev-1"));
        let runtime = runtime_finding(true, Some("/users/{id}"), Some("rev-1"), Some(89));
        let mut duplicates = vec![source; 100];
        duplicates.extend(vec![runtime; 100]);
        let result = correlate_attack_paths(&duplicates);
        assert_eq!(result.status, AttackPathCorrelationStatus::Complete);
        assert_eq!(result.paths.len(), 1);
    }

    #[test]
    fn exact_path_ceiling_is_complete() {
        let mut findings = Vec::new();
        for index in 0..32 {
            findings.push(source_finding(true, Some("/shared"), Some("rev-1")).with_location(
                ObservationLocation::Source {
                    path: format!("src/routes/source-{index}.rs"),
                    region: Some(SourceRegion::new(18)),
                },
            ));
        }
        for index in 0..32 {
            findings.push(
                runtime_finding(false, Some("/shared"), Some("rev-1"), Some(89)).with_location(
                    ObservationLocation::Runtime {
                        uri: format!("https://app.example.test/runtime-{index}"),
                        route: Some("/shared".to_string()),
                        parameter: None,
                    },
                ),
            );
        }
        let result = correlate_attack_paths(&findings);
        assert_eq!(result.paths.len(), MAX_CORRELATED_PATHS);
        assert_eq!(result.status, AttackPathCorrelationStatus::Complete);
        assert!(result
            .gaps
            .iter()
            .all(|gap| gap.kind != AttackPathCorrelationGapKind::PathLimitExceeded));
    }

    #[test]
    fn duplicate_path_preference_and_facet_aliases_are_exact() {
        let base = correlated_path();
        assert!(!path_is_preferred(&base, &base));

        let mut stronger = base.clone();
        let mut weaker = base.clone();
        stronger.state = AttackPathState::Reproduced;
        weaker.state = AttackPathState::Reachable;
        assert!(path_is_preferred(&stronger, &weaker));
        assert!(!path_is_preferred(&weaker, &stronger));

        let mut lexical_high = base.clone();
        let mut lexical_low = base;
        lexical_high.members[0].module_id = "z-scanner".to_string();
        lexical_low.members[0].module_id = "a-scanner".to_string();
        assert!(path_is_preferred(&lexical_high, &lexical_low));
        assert!(!path_is_preferred(&lexical_low, &lexical_high));

        for (namespace, expected) in [
            ("application", CorrelationFacetKind::Application),
            ("service", CorrelationFacetKind::Application),
            ("deployment", CorrelationFacetKind::Deployment),
            ("target-revision", CorrelationFacetKind::Deployment),
            ("route", CorrelationFacetKind::Route),
            ("dast-operation", CorrelationFacetKind::Operation),
            ("http-method", CorrelationFacetKind::Method),
            ("http-parameter", CorrelationFacetKind::Parameter),
            ("purl", CorrelationFacetKind::Component),
            ("owasp", CorrelationFacetKind::Weakness),
            ("test-case", CorrelationFacetKind::Test),
            ("vendor-specific", CorrelationFacetKind::Explicit),
        ] {
            assert_eq!(facet_kind_for_key(&CorrelationKey::new(namespace, "value")), expected);
        }
    }

    #[test]
    fn oversized_finding_detail_is_a_typed_incomplete_gap() {
        let mut source = source_finding(true, Some("/users/{id}"), Some("rev-1"));
        source.appsec.correlation_keys = (0..=MAX_CORRELATION_DETAILS_PER_FINDING)
            .map(|index| CorrelationKey::new("test", format!("case-{index}")))
            .collect();
        source.appsec.refresh_identity(&source.module_id, &source.title, source.cwe_id);
        let result = correlate_attack_paths(&[
            source,
            runtime_finding(true, Some("/users/{id}"), Some("rev-1"), Some(89)),
        ]);
        assert_eq!(result.status, AttackPathCorrelationStatus::Incomplete);
        assert!(result.paths.is_empty());
        assert_eq!(result.gaps[0].kind, AttackPathCorrelationGapKind::FindingDetailLimitExceeded);
    }

    #[test]
    fn source_runtime_pair_work_is_hard_bounded() {
        let mut findings =
            vec![source_finding(false, None, None); MAX_CORRELATION_DETAILS_PER_FINDING + 1];
        findings.extend(vec![
            runtime_finding(false, Some("/runtime-only"), None, None);
            MAX_CORRELATION_DETAILS_PER_FINDING + 1
        ]);
        let result = correlate_attack_paths(&findings);
        assert_eq!(result.status, AttackPathCorrelationStatus::Incomplete);
        assert!(result.paths.is_empty());
        assert!(result
            .gaps
            .iter()
            .any(|gap| { gap.kind == AttackPathCorrelationGapKind::PairEvaluationLimitExceeded }));
    }

    #[test]
    fn complete_negative_mitigates_and_later_reproduction_regresses() {
        let mut path = correlated_path();
        let original_confidences: Vec<f64> =
            path.members.iter().map(|member| member.scanner_confidence).collect();
        let incomplete = VerificationAttempt::new(
            &path.identity.value,
            &path.focused_verification.identity,
            VerificationCoverage::Incomplete,
            VerificationOutcome::NotReproduced,
            VerificationConditions {
                deployment_identity: Some("rev-1".to_string()),
                config_identities: vec![
                    "appsec-pack".to_string(),
                    "trusted-collection".to_string(),
                ],
            },
            vec!["coverage-incomplete".to_string()],
            collected_at() + chrono::Duration::minutes(1),
        );
        assert!(path.apply_verification(incomplete).expect("record incomplete attempt"));
        assert_eq!(path.state, AttackPathState::Reproduced);

        let negative = VerificationAttempt::new(
            &path.identity.value,
            &path.focused_verification.identity,
            VerificationCoverage::CompleteComparable,
            VerificationOutcome::NotReproduced,
            VerificationConditions {
                deployment_identity: Some("rev-1".to_string()),
                config_identities: vec![
                    "appsec-pack".to_string(),
                    "trusted-collection".to_string(),
                ],
            },
            vec!["negative-proof".to_string()],
            collected_at() + chrono::Duration::minutes(2),
        );
        assert!(path.apply_verification(negative.clone()).expect("record complete negative"));
        assert_eq!(path.state, AttackPathState::Mitigated);
        assert!(!path.apply_verification(negative).expect("duplicate is idempotent"));

        let reproduced = VerificationAttempt::new(
            &path.identity.value,
            &path.focused_verification.identity,
            VerificationCoverage::CompleteComparable,
            VerificationOutcome::Reproduced,
            VerificationConditions {
                deployment_identity: Some("rev-1".to_string()),
                config_identities: vec![
                    "appsec-pack".to_string(),
                    "trusted-collection".to_string(),
                ],
            },
            vec!["regression-proof".to_string()],
            collected_at() + chrono::Duration::minutes(3),
        );
        assert!(path.apply_verification(reproduced).expect("record regression"));
        assert_eq!(path.state, AttackPathState::Regressed);
        assert_eq!(
            path.members.iter().map(|member| member.scanner_confidence).collect::<Vec<_>>(),
            original_confidences
        );
        assert_eq!(path.transitions.len(), 4);
        assert_eq!(path.validate(), Ok(()));
    }

    #[test]
    fn attempts_require_canonical_identity_selection_time_deployment_and_evidence() {
        let mut path = correlated_path();
        let valid = VerificationAttempt::new(
            &path.identity.value,
            &path.focused_verification.identity,
            VerificationCoverage::CompleteComparable,
            VerificationOutcome::NotReproduced,
            VerificationConditions {
                deployment_identity: Some("wrong-revision".to_string()),
                config_identities: Vec::new(),
            },
            vec!["evidence".to_string()],
            collected_at() + chrono::Duration::minutes(1),
        );
        assert_eq!(
            path.apply_verification(valid),
            Err(VerificationAttemptError::DeploymentMismatch)
        );

        let wrong_configuration = VerificationAttempt::new(
            &path.identity.value,
            &path.focused_verification.identity,
            VerificationCoverage::CompleteComparable,
            VerificationOutcome::NotReproduced,
            VerificationConditions {
                deployment_identity: Some("rev-1".to_string()),
                config_identities: vec!["trusted-collection".to_string()],
            },
            vec!["evidence".to_string()],
            collected_at() + chrono::Duration::minutes(1),
        );
        assert_eq!(
            path.apply_verification(wrong_configuration),
            Err(VerificationAttemptError::ConfigurationMismatch)
        );

        let mut tampered = VerificationAttempt::new(
            &path.identity.value,
            &path.focused_verification.identity,
            VerificationCoverage::Incomplete,
            VerificationOutcome::NotReproduced,
            VerificationConditions { deployment_identity: None, config_identities: Vec::new() },
            Vec::new(),
            collected_at() + chrono::Duration::minutes(1),
        );
        tampered.identity = "tampered".to_string();
        assert_eq!(path.apply_verification(tampered), Err(VerificationAttemptError::NonCanonical));

        let stale = VerificationAttempt::new(
            &path.identity.value,
            &path.focused_verification.identity,
            VerificationCoverage::Incomplete,
            VerificationOutcome::NotReproduced,
            VerificationConditions { deployment_identity: None, config_identities: Vec::new() },
            Vec::new(),
            collected_at() - chrono::Duration::seconds(1),
        );
        assert_eq!(path.apply_verification(stale), Err(VerificationAttemptError::Stale));
    }

    #[test]
    fn path_and_attempt_round_trip_preserve_versioned_contracts() {
        let path = correlated_path();
        let encoded = serde_json::to_value(&path).expect("serialize path");
        let decoded: AttackPath = serde_json::from_value(encoded).expect("deserialize path");
        assert_eq!(decoded, path);
        assert_eq!(decoded.transitions[0].schema, ATTACK_PATH_TRANSITION_SCHEMA_V1);
        assert_eq!(decoded.focused_verification.schema, FOCUSED_VERIFICATION_SCHEMA_V1);
        assert_eq!(decoded.validate(), Ok(()));
    }

    #[test]
    fn boundary_validation_checks_each_schema_identity_and_normalization_clause() {
        let base = correlated_path();

        let mut path = base.clone();
        path.schema = "wrong-path-schema".to_string();
        assert_eq!(path.validate(), Err(AttackPathValidationError::Schema));
        let mut path = base.clone();
        path.identity.schema = "wrong-identity-schema".to_string();
        assert_eq!(path.validate(), Err(AttackPathValidationError::Schema));
        let mut path = base.clone();
        path.focused_verification.schema = "wrong-selection-schema".to_string();
        assert_eq!(path.validate(), Err(AttackPathValidationError::Schema));
        let mut path = base.clone();
        path.transitions[0].schema = "wrong-transition-schema".to_string();
        assert_eq!(path.validate(), Err(AttackPathValidationError::Schema));

        let mut path = base.clone();
        path.focused_verification.path_identity = "wrong-parent".to_string();
        path.focused_verification.identity = focused_selection_identity(&path.focused_verification);
        assert_eq!(path.validate(), Err(AttackPathValidationError::Identity));

        let mut path = base.clone();
        path.shared_facets.swap(0, 1);
        rebuild_initial_path(&mut path);
        assert_eq!(path.validate(), Err(AttackPathValidationError::Normalization));
        let mut path = base.clone();
        path.shared_facets[0].namespace = "UNNORMALIZED".to_string();
        path.shared_facets.sort();
        rebuild_initial_path(&mut path);
        assert_eq!(path.validate(), Err(AttackPathValidationError::Normalization));

        let mut path = correlate_attack_paths(&[
            source_finding(false, Some("/users/{id}"), None),
            runtime_finding(false, Some("/users/{id}"), None, Some(89)),
        ])
        .paths
        .remove(0);
        assert!(path.gaps.len() > 1);
        path.gaps.reverse();
        assert_eq!(path.validate(), Err(AttackPathValidationError::Normalization));

        let mut path = base.clone();
        path.members[0].scanner_confidence = f64::NAN;
        assert_eq!(path.validate(), Err(AttackPathValidationError::Normalization));
        let mut path = base;
        path.focused_verification.tests = vec!["z-test".to_string(), "a-test".to_string()];
        path.focused_verification.identity = focused_selection_identity(&path.focused_verification);
        assert_eq!(path.validate(), Err(AttackPathValidationError::Normalization));
    }

    #[test]
    fn boundary_validation_checks_each_history_shape_and_order_clause() {
        let base = correlated_path();
        let mut variants = Vec::new();

        let mut path = base.clone();
        path.transitions[0].reason = AttackPathTransitionReason::Verification;
        rebuild_transition(&mut path, 0);
        variants.push(path);
        let mut path = base.clone();
        path.transitions[0].attempt_identity = Some("attempt".to_string());
        rebuild_transition(&mut path, 0);
        variants.push(path);
        let mut path = base.clone();
        path.transitions[0].coverage = Some(VerificationCoverage::Incomplete);
        rebuild_transition(&mut path, 0);
        variants.push(path);
        let mut path = base.clone();
        path.transitions[0].outcome = Some(VerificationOutcome::NotReproduced);
        rebuild_transition(&mut path, 0);
        variants.push(path);
        let mut path = base.clone();
        path.transitions[0].conditions = Some(VerificationConditions {
            deployment_identity: None,
            config_identities: Vec::new(),
        });
        rebuild_transition(&mut path, 0);
        variants.push(path);
        let mut path = base.clone();
        path.transitions[0].to = AttackPathState::Mitigated;
        path.transitions[0].path_confidence = 0;
        path.state = AttackPathState::Mitigated;
        path.path_confidence = 0;
        rebuild_transition(&mut path, 0);
        variants.push(path);
        for path in variants {
            assert_eq!(path.validate(), Err(AttackPathValidationError::History));
        }

        let mut valid = base;
        let attempt = VerificationAttempt::new(
            &valid.identity.value,
            &valid.focused_verification.identity,
            VerificationCoverage::Incomplete,
            VerificationOutcome::NotReproduced,
            VerificationConditions { deployment_identity: None, config_identities: Vec::new() },
            Vec::new(),
            collected_at() + chrono::Duration::minutes(1),
        );
        assert!(valid.apply_verification(attempt).expect("append verification"));
        assert_eq!(valid.validate(), Ok(()));

        let mut variants = Vec::new();
        let mut path = valid.clone();
        path.transitions[1].reason = AttackPathTransitionReason::Correlated;
        rebuild_transition(&mut path, 1);
        variants.push(path);
        let mut path = valid.clone();
        path.transitions[1].attempt_identity = Some(String::new());
        rebuild_transition(&mut path, 1);
        variants.push(path);
        let mut path = valid.clone();
        path.transitions[1].coverage = None;
        rebuild_transition(&mut path, 1);
        variants.push(path);
        let mut path = valid.clone();
        path.transitions[1].outcome = None;
        rebuild_transition(&mut path, 1);
        variants.push(path);
        let mut path = valid.clone();
        path.transitions[1].conditions = None;
        rebuild_transition(&mut path, 1);
        variants.push(path);
        let mut path = valid.clone();
        path.transitions[1].from = None;
        rebuild_transition(&mut path, 1);
        variants.push(path);
        let mut path = valid.clone();
        path.transitions[1].observed_at =
            path.transitions[0].observed_at - chrono::Duration::microseconds(1);
        rebuild_transition(&mut path, 1);
        variants.push(path);
        let mut path = valid.clone();
        path.transitions.push(path.transitions[1].clone());
        variants.push(path);
        let mut path = valid.clone();
        path.transitions[1].path_confidence = 101;
        path.path_confidence = 101;
        rebuild_transition(&mut path, 1);
        variants.push(path);
        let mut path = valid.clone();
        path.transitions[1].evidence_ids = vec!["z-proof".to_string(), "a-proof".to_string()];
        variants.push(path);
        for path in variants {
            assert_eq!(path.validate(), Err(AttackPathValidationError::History));
        }

        let mut path = valid;
        path.path_confidence -= 1;
        assert_eq!(path.validate(), Err(AttackPathValidationError::State));
    }

    #[test]
    fn restored_verification_checks_each_state_and_comparability_clause() {
        let mut verified = correlated_path();
        let attempt = VerificationAttempt::new(
            &verified.identity.value,
            &verified.focused_verification.identity,
            VerificationCoverage::CompleteComparable,
            VerificationOutcome::NotReproduced,
            VerificationConditions {
                deployment_identity: Some("rev-1".to_string()),
                config_identities: required_config_identities(&verified.focused_verification),
            },
            vec!["negative-proof".to_string()],
            collected_at() + chrono::Duration::minutes(1),
        );
        assert!(verified.apply_verification(attempt).expect("append complete verification"));
        assert_eq!(verified.validate(), Ok(()));

        let mut path = verified.clone();
        path.transitions[1].to = AttackPathState::Reproduced;
        path.state = AttackPathState::Reproduced;
        rebuild_verification_transition(&mut path, 1);
        assert_eq!(path.validate(), Err(AttackPathValidationError::State));

        let mut path = verified.clone();
        path.transitions[1].evidence_ids.clear();
        rebuild_verification_transition(&mut path, 1);
        assert_eq!(path.validate(), Err(AttackPathValidationError::History));
        let mut path = verified.clone();
        path.transitions[1].conditions = Some(VerificationConditions {
            deployment_identity: Some("/users/{id}".to_string()),
            config_identities: required_config_identities(&path.focused_verification),
        });
        rebuild_verification_transition(&mut path, 1);
        assert_eq!(path.validate(), Err(AttackPathValidationError::History));
        let mut path = verified;
        path.transitions[1].conditions = Some(VerificationConditions {
            deployment_identity: Some("rev-1".to_string()),
            config_identities: vec!["wrong-config".to_string()],
        });
        rebuild_verification_transition(&mut path, 1);
        assert_eq!(path.validate(), Err(AttackPathValidationError::History));

        let mut incomplete = correlated_path();
        let attempt = VerificationAttempt::new(
            &incomplete.identity.value,
            &incomplete.focused_verification.identity,
            VerificationCoverage::Incomplete,
            VerificationOutcome::NotReproduced,
            VerificationConditions { deployment_identity: None, config_identities: Vec::new() },
            Vec::new(),
            collected_at() + chrono::Duration::minutes(1),
        );
        assert!(incomplete.apply_verification(attempt).expect("append incomplete verification"));
        assert_eq!(incomplete.validate(), Ok(()));
    }

    #[test]
    fn verification_exact_time_prerequisites_and_runtime_gap_removal_are_observable() {
        let mut equal_time = correlated_path();
        let attempt = VerificationAttempt::new(
            &equal_time.identity.value,
            &equal_time.focused_verification.identity,
            VerificationCoverage::CompleteComparable,
            VerificationOutcome::NotReproduced,
            VerificationConditions {
                deployment_identity: Some("rev-1".to_string()),
                config_identities: required_config_identities(&equal_time.focused_verification),
            },
            vec!["equal-time-proof".to_string()],
            equal_time.transitions[0].observed_at,
        );
        assert!(equal_time.apply_verification(attempt).expect("equal time is not stale"));
        assert_eq!(equal_time.validate(), Ok(()));

        let mut reachable = correlate_attack_paths(&[
            source_finding(true, Some("/users/{id}"), Some("rev-1")),
            runtime_finding(false, Some("/users/{id}"), Some("rev-1"), Some(89)),
        ])
        .paths
        .remove(0);
        assert_eq!(reachable.state, AttackPathState::Reachable);
        let attempt = VerificationAttempt::new(
            &reachable.identity.value,
            &reachable.focused_verification.identity,
            VerificationCoverage::CompleteComparable,
            VerificationOutcome::Reproduced,
            VerificationConditions {
                deployment_identity: Some("rev-1".to_string()),
                config_identities: required_config_identities(&reachable.focused_verification),
            },
            vec!["runtime-proof".to_string()],
            collected_at() + chrono::Duration::minutes(1),
        );
        assert!(reachable.apply_verification(attempt).expect("reproduce reachable path"));
        assert_eq!(reachable.state, AttackPathState::Reproduced);
        assert!(reachable.gaps.is_empty());

        let missing = correlate_attack_paths(&[
            source_finding(false, Some("/users/{id}"), Some("rev-1")),
            runtime_finding(false, Some("/users/{id}"), Some("rev-1"), Some(89)),
        ])
        .paths
        .remove(0);
        let conditions = VerificationConditions {
            deployment_identity: Some("rev-1".to_string()),
            config_identities: required_config_identities(&missing.focused_verification),
        };
        let mut complete_reproduction = missing.clone();
        let attempt = VerificationAttempt::new(
            &complete_reproduction.identity.value,
            &complete_reproduction.focused_verification.identity,
            VerificationCoverage::CompleteComparable,
            VerificationOutcome::Reproduced,
            conditions.clone(),
            vec!["proof".to_string()],
            collected_at() + chrono::Duration::minutes(1),
        );
        assert_eq!(
            complete_reproduction.apply_verification(attempt),
            Err(VerificationAttemptError::MissingProofPrerequisite)
        );

        let mut incomplete_reproduction = missing.clone();
        let attempt = VerificationAttempt::new(
            &incomplete_reproduction.identity.value,
            &incomplete_reproduction.focused_verification.identity,
            VerificationCoverage::Incomplete,
            VerificationOutcome::Reproduced,
            VerificationConditions { deployment_identity: None, config_identities: Vec::new() },
            Vec::new(),
            collected_at() + chrono::Duration::minutes(1),
        );
        assert!(incomplete_reproduction
            .apply_verification(attempt)
            .expect("incomplete reproduction is recorded"));

        let mut complete_negative = missing;
        let attempt = VerificationAttempt::new(
            &complete_negative.identity.value,
            &complete_negative.focused_verification.identity,
            VerificationCoverage::CompleteComparable,
            VerificationOutcome::NotReproduced,
            conditions,
            vec!["negative".to_string()],
            collected_at() + chrono::Duration::minutes(1),
        );
        assert!(complete_negative
            .apply_verification(attempt)
            .expect("complete negative does not need reproduction prerequisites"));
    }

    #[test]
    fn boundary_validation_rejects_tampered_identity_selection_history_and_state() {
        let path = correlated_path();

        let mut identity = path.clone();
        identity.identity.value = "tampered".to_string();
        assert_eq!(identity.validate(), Err(AttackPathValidationError::Identity));

        let mut selection = path.clone();
        selection.focused_verification.identity = "tampered".to_string();
        assert_eq!(selection.validate(), Err(AttackPathValidationError::Identity));

        let mut history = path.clone();
        history.transitions[0].identity = "tampered".to_string();
        assert_eq!(history.validate(), Err(AttackPathValidationError::Identity));

        let mut state = path.clone();
        state.state = AttackPathState::Reachable;
        assert_eq!(state.validate(), Err(AttackPathValidationError::State));

        let mut coherent_state = path.clone();
        coherent_state.state = AttackPathState::Reachable;
        coherent_state.path_confidence = 60;
        coherent_state.transitions[0] = build_transition(TransitionInput {
            path_identity: &coherent_state.identity.value,
            from: None,
            to: AttackPathState::Reachable,
            reason: AttackPathTransitionReason::Correlated,
            attempt_identity: None,
            coverage: None,
            outcome: None,
            conditions: None,
            evidence_ids: coherent_state.transitions[0].evidence_ids.clone(),
            path_confidence: 60,
            observed_at: coherent_state.transitions[0].observed_at,
        });
        assert_eq!(coherent_state.validate(), Err(AttackPathValidationError::State));

        let mut evidence = path.clone();
        evidence.transitions[0] = build_transition(TransitionInput {
            path_identity: &evidence.identity.value,
            from: None,
            to: AttackPathState::Reproduced,
            reason: AttackPathTransitionReason::Correlated,
            attempt_identity: None,
            coverage: None,
            outcome: None,
            conditions: None,
            evidence_ids: vec!["unrelated-proof".to_string()],
            path_confidence: 95,
            observed_at: evidence.transitions[0].observed_at,
        });
        assert_eq!(evidence.validate(), Err(AttackPathValidationError::State));

        let mut observed_at = path;
        observed_at.transitions[0] = build_transition(TransitionInput {
            path_identity: &observed_at.identity.value,
            from: None,
            to: AttackPathState::Reproduced,
            reason: AttackPathTransitionReason::Correlated,
            attempt_identity: None,
            coverage: None,
            outcome: None,
            conditions: None,
            evidence_ids: observed_at.transitions[0].evidence_ids.clone(),
            path_confidence: 95,
            observed_at: collected_at() + chrono::Duration::hours(1),
        });
        assert_eq!(observed_at.validate(), Err(AttackPathValidationError::State));
    }
}
