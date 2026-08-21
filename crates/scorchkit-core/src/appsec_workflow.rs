//! Provider-neutral application-security context and workflow planning contracts.
//!
//! Plans are inert descriptions. They do not authorize targets, execute tools, create evidence, or
//! change finding state. Hosts execute ready steps through the existing policy-gated boundaries.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use scorchkit_policy::policy::{Capability, EffectClass};
use serde::{Deserialize, Serialize};

use crate::attack_path::{validate_focused_verification_selection, FocusedVerificationSelection};
use crate::observation::{canonical_json_sha256, redact_text};

/// Schema for one canonical application-security context.
pub const APPLICATION_SECURITY_CONTEXT_SCHEMA_V1: &str = "scorchkit.application-context/v1";
/// Schema for one immutable Git change-set declaration.
pub const APPSEC_CHANGE_SET_SCHEMA_V1: &str = "scorchkit.appsec-change-set/v1";
/// Schema for one inert application-security workflow plan.
pub const APPSEC_WORKFLOW_PLAN_SCHEMA_V1: &str = "scorchkit.appsec-workflow-plan/v1";
/// Maximum changed paths accepted in one declared change set.
pub const MAX_APPSEC_CHANGED_PATHS: usize = 4_096;
/// Maximum manifests accepted in one context.
pub const MAX_APPSEC_MANIFESTS: usize = 4_096;
/// Maximum declared routes accepted in one context.
pub const MAX_APPSEC_ROUTES: usize = 1_024;
/// Maximum declared artifacts accepted in one context.
pub const MAX_APPSEC_ARTIFACTS: usize = 512;
/// Maximum registered targets accepted in one context.
pub const MAX_APPSEC_TARGETS: usize = 256;
/// Maximum persona labels accepted in one context.
pub const MAX_APPSEC_PERSONAS: usize = 64;
/// Maximum bytes accepted in one context string.
pub const MAX_APPSEC_VALUE_BYTES: usize = 1_024;

/// Source of one context field. None of these sources is authorization or scanner evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationContextProvenance {
    /// Produced by bounded `ScorchKit` code-context discovery.
    EngineDetected,
    /// Declared by the calling host and not independently verified by the core contract.
    HostDeclared,
    /// Loaded from `ScorchKit` project inventory.
    ProjectRegistered,
    /// Loaded as a non-secret label from `ScorchKit` configuration.
    Configuration,
}

/// One canonical path or route retained as application context.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ApplicationContextValue {
    /// Canonical root-relative path or normalized route.
    pub value: String,
    /// Source of the value.
    pub provenance: ApplicationContextProvenance,
}

/// One registered application target retained without URL credentials or query values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ApplicationContextTarget {
    /// Canonical HTTP(S) target.
    pub url: String,
    /// Optional redacted project label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Source of the target.
    pub provenance: ApplicationContextProvenance,
}

/// One immutable host-declared Git change set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationChangeSet {
    /// Change-set schema.
    pub schema: String,
    /// Stable identity over the two revisions and normalized paths.
    pub identity: String,
    /// Immutable base object ID.
    pub base_revision: String,
    /// Immutable head object ID.
    pub head_revision: String,
    /// Canonical root-relative changed paths.
    pub changed_paths: Vec<String>,
    /// The core records the declaration but does not execute Git to verify it.
    pub provenance: ApplicationContextProvenance,
}

/// Typed context incompleteness or trust-boundary marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationContextGapKind {
    /// The change set came from the host and was not independently read from Git by `ScorchKit`.
    ChangeSetNotEngineVerified,
    /// Routes came from the host and are not scanner observations.
    RoutesNotEngineVerified,
    /// Artifacts came from the host and are not scanner observations.
    ArtifactsNotEngineVerified,
    /// A selected project has no registered HTTP(S) target.
    NoRegisteredTargets,
}

/// One context gap.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ApplicationContextGap {
    /// Stable reason code.
    pub kind: ApplicationContextGapKind,
}

/// Inputs supplied by a policy-gated composition adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationSecurityContextInput {
    /// Canonical absolute code root.
    pub code_root: String,
    /// Bounded detected language labels.
    pub languages: Vec<String>,
    /// Detected root-relative manifests.
    pub manifests: Vec<String>,
    /// Optional host-declared immutable change set.
    pub change_set: Option<ApplicationChangeSet>,
    /// Host-declared application routes.
    pub routes: Vec<ApplicationContextValue>,
    /// Host-declared local artifact paths.
    pub artifacts: Vec<ApplicationContextValue>,
    /// Optional durable project name or identity.
    pub project: Option<String>,
    /// Project-registered targets.
    pub registered_targets: Vec<ApplicationContextTarget>,
    /// Configured non-secret persona labels.
    pub persona_labels: Vec<String>,
    /// Configured capability labels. Target scope is still checked at execution.
    pub configured_capabilities: Vec<Capability>,
    /// Configured exact effect labels. Target scope is still checked at execution.
    pub configured_effects: Vec<EffectClass>,
}

/// Canonical application context shared by every agent host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationSecurityContext {
    /// Context schema.
    pub schema: String,
    /// Stable identity over every canonical context field.
    pub identity: String,
    /// Canonical absolute code root.
    pub code_root: String,
    /// Detected language labels.
    pub languages: Vec<String>,
    /// Detected root-relative manifests.
    pub manifests: Vec<String>,
    /// Optional immutable declared change set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_set: Option<ApplicationChangeSet>,
    /// Declared application routes.
    pub routes: Vec<ApplicationContextValue>,
    /// Declared local artifacts.
    pub artifacts: Vec<ApplicationContextValue>,
    /// Optional project name or identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Project-registered targets.
    pub registered_targets: Vec<ApplicationContextTarget>,
    /// Configured persona labels without credential references or values.
    pub persona_labels: Vec<String>,
    /// Configured capability inventory; not an authorization decision.
    pub configured_capabilities: Vec<Capability>,
    /// Configured exact effect inventory; not an authorization decision.
    pub configured_effects: Vec<EffectClass>,
    /// Explicit context limitations.
    pub gaps: Vec<ApplicationContextGap>,
}

/// Application lifecycle profile. These are not scanner-depth aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationSecurityWorkflowProfile {
    /// One declared change set only.
    Commit,
    /// Change review plus explicit full-root fast deterministic analysis.
    PullRequest,
    /// Pull-request coverage plus registered-target application DAST.
    Staging,
    /// Staging coverage plus release-grade repository, artifact, and correlation work.
    Release,
    /// Release coverage plus repeated complete host repository review.
    Deep,
}

impl ApplicationSecurityWorkflowProfile {
    /// Parse the public profile label.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for an unknown profile.
    pub fn parse(value: &str) -> Result<Self, ApplicationSecurityWorkflowValidationError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "commit" => Ok(Self::Commit),
            "pull_request" | "pull-request" | "pr" => Ok(Self::PullRequest),
            "staging" => Ok(Self::Staging),
            "release" => Ok(Self::Release),
            "deep" => Ok(Self::Deep),
            _ => Err(ApplicationSecurityWorkflowValidationError::InvalidProfile),
        }
    }
}

/// Owner of one planned step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationSecurityWorkflowOwner {
    /// Provider-neutral semantic analysis performed by the host.
    HostAnalysis,
    /// Deterministic `ScorchKit` tool execution and evidence.
    ScorchkitEngine,
}

/// Closed workflow step inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationSecurityWorkflowStepKind {
    /// Semantic review of exactly one declared change set.
    SemanticChangeReview,
    /// Fast full-root application SAST, secrets, and supply-chain scan.
    FastApplicationScan,
    /// Registered-target application DAST.
    ApplicationDast,
    /// Complete host repository semantic review.
    SemanticRepositoryReview,
    /// Deep full-root deterministic application scan.
    DeepApplicationScan,
    /// One declared local artifact supply-chain scan.
    ArtifactSupplyChainScan,
    /// Correlate project evidence into attack paths and focused selectors.
    CorrelateProjectEvidence,
    /// Repeated complete independent host repository review.
    DeepSemanticRepositoryReview,
    /// Exact focused selection review that must not broaden on failure.
    FocusedVerification,
}

/// Scope represented by one workflow step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationSecurityWorkflowScope {
    /// Exactly one declared Git change set.
    ChangeSet,
    /// The complete canonical code root.
    CodeRoot,
    /// One project-registered application target.
    RegisteredTarget,
    /// One declared local application artifact.
    Artifact,
    /// Existing durable project evidence.
    Project,
    /// One exact attack-path focused selection.
    FocusedSelection,
}

/// Whether a planned step has all enforceable inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationSecurityWorkflowStepStatus {
    /// Required inputs are present; execution authorization remains separate.
    Ready,
    /// A required context input or configured grant is absent.
    Blocked,
    /// The current public tool contract cannot enforce the exact requested scope.
    Unsupported,
}

/// Typed workflow planning gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationSecurityWorkflowGapKind {
    /// Commit or pull-request semantic work has no declared immutable change set.
    MissingChangeSet,
    /// A project-bound step has no selected project.
    MissingProject,
    /// A runtime step has no registered target.
    MissingRegisteredTarget,
    /// A release artifact step has no declared artifact.
    MissingArtifact,
    /// The configured engagement lacks one definitely required capability label.
    ConfiguredCapabilityMissing,
    /// The configured engagement lacks one definitely required exact effect label.
    ConfiguredEffectMissing,
    /// The current public tools cannot enforce an exact focused static selector.
    FocusedStaticSelectorUnsupported,
    /// The current public tools cannot enforce an exact focused runtime selector.
    FocusedRuntimeSelectorUnsupported,
    /// The current public tools cannot enforce an exact focused request selector.
    FocusedRequestSelectorUnsupported,
    /// The current public tools cannot enforce an exact focused test selector.
    FocusedTestSelectorUnsupported,
    /// A focused selection contains no enforceable selector to verify.
    EmptyFocusedSelection,
}

/// One workflow gap, optionally naming the affected selector or requirement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ApplicationSecurityWorkflowGap {
    /// Stable reason code.
    pub kind: ApplicationSecurityWorkflowGapKind,
    /// Redacted bounded detail such as a capability, effect, or selector identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One inert ordered workflow step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationSecurityWorkflowStep {
    /// Stable identity over the complete step and its order.
    pub identity: String,
    /// Zero-based canonical order.
    pub order: usize,
    /// Closed step kind.
    pub kind: ApplicationSecurityWorkflowStepKind,
    /// Host-analysis or ScorchKit-engine ownership.
    pub owner: ApplicationSecurityWorkflowOwner,
    /// Exact planned scope class.
    pub scope: ApplicationSecurityWorkflowScope,
    /// Provider-neutral host capability or exact `ScorchKit` MCP tool name.
    pub operation: String,
    /// Optional exact scope identity such as a target URL, artifact path, or change-set identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_identity: Option<String>,
    /// True when the step covers more than the declared change or focused selection.
    pub broad: bool,
    /// Whether execution must pass the existing policy boundary after planning.
    pub requires_execution_authorization: bool,
    /// Required engine capabilities.
    pub required_capabilities: Vec<Capability>,
    /// Required exact engine effects.
    pub required_effects: Vec<EffectClass>,
    /// Planning-time input state.
    pub status: ApplicationSecurityWorkflowStepStatus,
    /// Exact planning gaps.
    pub gaps: Vec<ApplicationSecurityWorkflowGap>,
}

/// One inert, stable application-security workflow plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationSecurityWorkflowPlan {
    /// Plan schema.
    pub schema: String,
    /// Stable identity over the complete canonical plan.
    pub identity: String,
    /// Selected application workflow profile.
    pub profile: ApplicationSecurityWorkflowProfile,
    /// Exact application-context identity.
    pub context_identity: String,
    /// Optional exact focused selection. When present, no broad profile steps are compiled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focused_selection: Option<FocusedVerificationSelection>,
    /// Ordered closed plan.
    pub steps: Vec<ApplicationSecurityWorkflowStep>,
    /// Aggregate planning gaps.
    pub gaps: Vec<ApplicationSecurityWorkflowGap>,
}

/// Validation failure at the provider-neutral workflow boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApplicationSecurityWorkflowValidationError {
    /// A public string was empty, oversized, control-bearing, or otherwise malformed.
    #[error("application-security workflow contains an invalid value")]
    InvalidValue,
    /// An absolute, traversing, or otherwise noncanonical relative path was supplied.
    #[error("application-security workflow contains an invalid relative path")]
    InvalidPath,
    /// A route was not a normalized application path.
    #[error("application-security workflow contains an invalid route")]
    InvalidRoute,
    /// A change set was incomplete, mutable-looking, or internally inconsistent.
    #[error("application-security workflow contains an invalid change set")]
    InvalidChangeSet,
    /// A focused selection failed its canonical identity or normalization contract.
    #[error("application-security workflow contains an invalid focused selection")]
    InvalidFocusedSelection,
    /// The requested application workflow profile is unknown.
    #[error("unknown application-security workflow profile")]
    InvalidProfile,
    /// An input exceeded a hard collection ceiling.
    #[error("application-security workflow exceeds a collection limit")]
    Limit,
}

/// Compile one immutable change set from two object IDs and changed paths.
///
/// # Errors
///
/// Rejects mutable refs, equal revisions, missing paths, traversal, controls, duplicates above the
/// hard ceiling, and unsupported object-ID sizes.
pub fn compile_application_change_set(
    base_revision: &str,
    head_revision: &str,
    changed_paths: Vec<String>,
) -> Result<ApplicationChangeSet, ApplicationSecurityWorkflowValidationError> {
    let base_revision = normalized_revision(base_revision)?;
    let head_revision = normalized_revision(head_revision)?;
    if base_revision == head_revision || changed_paths.is_empty() {
        return Err(ApplicationSecurityWorkflowValidationError::InvalidChangeSet);
    }
    let changed_paths = normalize_relative_paths(changed_paths, MAX_APPSEC_CHANGED_PATHS)?;
    let identity = canonical_json_sha256(&serde_json::json!({
        "schema": APPSEC_CHANGE_SET_SCHEMA_V1,
        "base_revision": base_revision,
        "head_revision": head_revision,
        "changed_paths": changed_paths,
        "provenance": ApplicationContextProvenance::HostDeclared,
    }));
    Ok(ApplicationChangeSet {
        schema: APPSEC_CHANGE_SET_SCHEMA_V1.to_string(),
        identity,
        base_revision,
        head_revision,
        changed_paths,
        provenance: ApplicationContextProvenance::HostDeclared,
    })
}

/// Canonicalize one provider-neutral application context.
///
/// # Errors
///
/// Rejects malformed roots, paths, routes, targets, labels, collections, or change-set identities.
pub fn compile_application_security_context(
    input: ApplicationSecurityContextInput,
) -> Result<ApplicationSecurityContext, ApplicationSecurityWorkflowValidationError> {
    let code_root = normalized_root(&input.code_root)?;
    let languages = normalize_labels(input.languages, MAX_APPSEC_PERSONAS)?;
    let manifests = normalize_relative_paths(input.manifests, MAX_APPSEC_MANIFESTS)?;
    let change_set = input.change_set.as_ref().map(validate_change_set).transpose()?;
    let routes = normalize_context_routes(input.routes)?;
    let artifacts = normalize_context_paths(input.artifacts, MAX_APPSEC_ARTIFACTS)?;
    let project = input.project.map(|value| normalized_label(&value)).transpose()?;
    let registered_targets = normalize_targets(input.registered_targets)?;
    let persona_labels = normalize_labels(input.persona_labels, MAX_APPSEC_PERSONAS)?;
    let configured_capabilities = sorted_unique(input.configured_capabilities);
    let configured_effects = sorted_unique(input.configured_effects);
    let mut gaps = BTreeSet::new();
    if change_set.is_some() {
        gaps.insert(ApplicationContextGap {
            kind: ApplicationContextGapKind::ChangeSetNotEngineVerified,
        });
    }
    if !routes.is_empty() {
        gaps.insert(ApplicationContextGap {
            kind: ApplicationContextGapKind::RoutesNotEngineVerified,
        });
    }
    if !artifacts.is_empty() {
        gaps.insert(ApplicationContextGap {
            kind: ApplicationContextGapKind::ArtifactsNotEngineVerified,
        });
    }
    if project.is_some() && registered_targets.is_empty() {
        gaps.insert(ApplicationContextGap { kind: ApplicationContextGapKind::NoRegisteredTargets });
    }
    let gaps: Vec<_> = gaps.into_iter().collect();
    let identity = canonical_json_sha256(&serde_json::json!({
        "schema": APPLICATION_SECURITY_CONTEXT_SCHEMA_V1,
        "code_root": code_root,
        "languages": languages,
        "manifests": manifests,
        "change_set": change_set,
        "routes": routes,
        "artifacts": artifacts,
        "project": project,
        "registered_targets": registered_targets,
        "persona_labels": persona_labels,
        "configured_capabilities": configured_capabilities,
        "configured_effects": configured_effects,
        "gaps": gaps,
    }));
    Ok(ApplicationSecurityContext {
        schema: APPLICATION_SECURITY_CONTEXT_SCHEMA_V1.to_string(),
        identity,
        code_root,
        languages,
        manifests,
        change_set,
        routes,
        artifacts,
        project,
        registered_targets,
        persona_labels,
        configured_capabilities,
        configured_effects,
        gaps,
    })
}

/// Compile an inert ordered workflow. A focused selection suppresses every broad profile step.
///
/// # Errors
///
/// Rejects a noncanonical context or focused selection.
pub fn compile_application_security_workflow(
    context: &ApplicationSecurityContext,
    profile: ApplicationSecurityWorkflowProfile,
    focused_selection: Option<FocusedVerificationSelection>,
) -> Result<ApplicationSecurityWorkflowPlan, ApplicationSecurityWorkflowValidationError> {
    validate_application_security_context(context)?;
    let mut steps = Vec::new();
    if let Some(selection) = focused_selection.as_ref() {
        validate_focused_verification_selection(selection)
            .map_err(|_| ApplicationSecurityWorkflowValidationError::InvalidFocusedSelection)?;
        steps.push(focused_step(selection, 0));
    } else {
        profile_steps(context, profile, &mut steps);
    }
    let gaps = steps
        .iter()
        .flat_map(|step| step.gaps.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let identity = canonical_json_sha256(&serde_json::json!({
        "schema": APPSEC_WORKFLOW_PLAN_SCHEMA_V1,
        "profile": profile,
        "context_identity": context.identity,
        "focused_selection": focused_selection,
        "steps": steps,
        "gaps": gaps,
    }));
    Ok(ApplicationSecurityWorkflowPlan {
        schema: APPSEC_WORKFLOW_PLAN_SCHEMA_V1.to_string(),
        identity,
        profile,
        context_identity: context.identity.clone(),
        focused_selection,
        steps,
        gaps,
    })
}

fn profile_steps(
    context: &ApplicationSecurityContext,
    profile: ApplicationSecurityWorkflowProfile,
    steps: &mut Vec<ApplicationSecurityWorkflowStep>,
) {
    push_semantic_change_step(context, steps);
    if profile >= ApplicationSecurityWorkflowProfile::PullRequest {
        push_engine_step(
            context,
            steps,
            WorkflowStepDraft::engine(
                ApplicationSecurityWorkflowStepKind::FastApplicationScan,
                ApplicationSecurityWorkflowScope::CodeRoot,
                "scan_code",
            )
            .with_scope(context.code_root.clone())
            .broad()
            .with_requirements(
                vec![Capability::CodeScan, Capability::ExternalTool],
                vec![EffectClass::Passive],
            ),
        );
    }
    if profile >= ApplicationSecurityWorkflowProfile::Staging {
        push_runtime_steps(context, steps);
    }
    if profile >= ApplicationSecurityWorkflowProfile::Release {
        push_host_step(
            steps,
            WorkflowStepDraft::host(
                ApplicationSecurityWorkflowStepKind::SemanticRepositoryReview,
                ApplicationSecurityWorkflowScope::CodeRoot,
                "security_repository_review",
            )
            .with_scope(context.code_root.clone())
            .broad(),
        );
        push_engine_step(
            context,
            steps,
            WorkflowStepDraft::engine(
                ApplicationSecurityWorkflowStepKind::DeepApplicationScan,
                ApplicationSecurityWorkflowScope::CodeRoot,
                "scan_code",
            )
            .with_scope(context.code_root.clone())
            .broad()
            .with_requirements(
                vec![Capability::CodeScan, Capability::ExternalTool],
                vec![EffectClass::Passive],
            ),
        );
        push_artifact_steps(context, steps);
        let mut correlation_gaps = Vec::new();
        if context.project.is_none() {
            correlation_gaps.push(gap(ApplicationSecurityWorkflowGapKind::MissingProject, None));
        }
        push_engine_step(
            context,
            steps,
            WorkflowStepDraft::engine(
                ApplicationSecurityWorkflowStepKind::CorrelateProjectEvidence,
                ApplicationSecurityWorkflowScope::Project,
                "correlate_findings",
            )
            .with_optional_scope(context.project.clone())
            .with_gaps(correlation_gaps),
        );
    }
    if profile >= ApplicationSecurityWorkflowProfile::Deep {
        push_host_step(
            steps,
            WorkflowStepDraft::host(
                ApplicationSecurityWorkflowStepKind::DeepSemanticRepositoryReview,
                ApplicationSecurityWorkflowScope::CodeRoot,
                "deep_security_repository_review",
            )
            .with_scope(context.code_root.clone())
            .broad(),
        );
    }
}

fn push_semantic_change_step(
    context: &ApplicationSecurityContext,
    steps: &mut Vec<ApplicationSecurityWorkflowStep>,
) {
    let (scope_identity, status, gaps) = context.change_set.as_ref().map_or_else(
        || {
            (
                None,
                ApplicationSecurityWorkflowStepStatus::Blocked,
                vec![gap(ApplicationSecurityWorkflowGapKind::MissingChangeSet, None)],
            )
        },
        |change_set| {
            (
                Some(change_set.identity.clone()),
                ApplicationSecurityWorkflowStepStatus::Ready,
                Vec::new(),
            )
        },
    );
    push_host_step(
        steps,
        WorkflowStepDraft::host(
            ApplicationSecurityWorkflowStepKind::SemanticChangeReview,
            ApplicationSecurityWorkflowScope::ChangeSet,
            "security_change_review",
        )
        .with_optional_scope(scope_identity)
        .with_gaps(gaps)
        .with_status(status),
    );
}

fn push_runtime_steps(
    context: &ApplicationSecurityContext,
    steps: &mut Vec<ApplicationSecurityWorkflowStep>,
) {
    if context.registered_targets.is_empty() {
        let mut gaps = vec![gap(ApplicationSecurityWorkflowGapKind::MissingRegisteredTarget, None)];
        if context.project.is_none() {
            gaps.push(gap(ApplicationSecurityWorkflowGapKind::MissingProject, None));
        }
        push_engine_step(
            context,
            steps,
            WorkflowStepDraft::engine(
                ApplicationSecurityWorkflowStepKind::ApplicationDast,
                ApplicationSecurityWorkflowScope::RegisteredTarget,
                "application_dast",
            )
            .broad()
            .with_requirements(
                vec![Capability::DastScan, Capability::ExternalTool],
                vec![EffectClass::Intrusive],
            )
            .with_gaps(gaps),
        );
        return;
    }
    for target in &context.registered_targets {
        push_engine_step(
            context,
            steps,
            WorkflowStepDraft::engine(
                ApplicationSecurityWorkflowStepKind::ApplicationDast,
                ApplicationSecurityWorkflowScope::RegisteredTarget,
                "application_dast",
            )
            .with_scope(target.url.clone())
            .broad()
            .with_requirements(
                vec![Capability::DastScan, Capability::ExternalTool],
                vec![EffectClass::Intrusive],
            ),
        );
    }
}

fn push_artifact_steps(
    context: &ApplicationSecurityContext,
    steps: &mut Vec<ApplicationSecurityWorkflowStep>,
) {
    if context.artifacts.is_empty() {
        push_engine_step(
            context,
            steps,
            WorkflowStepDraft::engine(
                ApplicationSecurityWorkflowStepKind::ArtifactSupplyChainScan,
                ApplicationSecurityWorkflowScope::Artifact,
                "supply_chain_scan",
            )
            .broad()
            .with_requirements(
                vec![Capability::CodeScan, Capability::ExternalTool],
                vec![EffectClass::Passive],
            )
            .with_gaps(vec![gap(ApplicationSecurityWorkflowGapKind::MissingArtifact, None)]),
        );
        return;
    }
    for artifact in &context.artifacts {
        push_engine_step(
            context,
            steps,
            WorkflowStepDraft::engine(
                ApplicationSecurityWorkflowStepKind::ArtifactSupplyChainScan,
                ApplicationSecurityWorkflowScope::Artifact,
                "supply_chain_scan",
            )
            .with_scope(artifact.value.clone())
            .broad()
            .with_requirements(
                vec![Capability::CodeScan, Capability::ExternalTool],
                vec![EffectClass::Passive],
            ),
        );
    }
}

struct WorkflowStepDraft {
    kind: ApplicationSecurityWorkflowStepKind,
    owner: ApplicationSecurityWorkflowOwner,
    scope: ApplicationSecurityWorkflowScope,
    operation: &'static str,
    scope_identity: Option<String>,
    broad: bool,
    requires_execution_authorization: bool,
    required_capabilities: Vec<Capability>,
    required_effects: Vec<EffectClass>,
    status: ApplicationSecurityWorkflowStepStatus,
    gaps: Vec<ApplicationSecurityWorkflowGap>,
}

impl WorkflowStepDraft {
    const fn engine(
        kind: ApplicationSecurityWorkflowStepKind,
        scope: ApplicationSecurityWorkflowScope,
        operation: &'static str,
    ) -> Self {
        Self {
            kind,
            owner: ApplicationSecurityWorkflowOwner::ScorchkitEngine,
            scope,
            operation,
            scope_identity: None,
            broad: false,
            requires_execution_authorization: true,
            required_capabilities: Vec::new(),
            required_effects: Vec::new(),
            status: ApplicationSecurityWorkflowStepStatus::Ready,
            gaps: Vec::new(),
        }
    }

    const fn host(
        kind: ApplicationSecurityWorkflowStepKind,
        scope: ApplicationSecurityWorkflowScope,
        operation: &'static str,
    ) -> Self {
        let mut draft = Self::engine(kind, scope, operation);
        draft.owner = ApplicationSecurityWorkflowOwner::HostAnalysis;
        draft.requires_execution_authorization = false;
        draft
    }

    fn with_scope(mut self, scope_identity: String) -> Self {
        self.scope_identity = Some(scope_identity);
        self
    }

    fn with_optional_scope(mut self, scope_identity: Option<String>) -> Self {
        self.scope_identity = scope_identity;
        self
    }

    const fn broad(mut self) -> Self {
        self.broad = true;
        self
    }

    fn with_requirements(
        mut self,
        required_capabilities: Vec<Capability>,
        required_effects: Vec<EffectClass>,
    ) -> Self {
        self.required_capabilities = required_capabilities;
        self.required_effects = required_effects;
        self
    }

    fn with_gaps(mut self, gaps: Vec<ApplicationSecurityWorkflowGap>) -> Self {
        self.gaps = gaps;
        self
    }

    const fn with_status(mut self, status: ApplicationSecurityWorkflowStepStatus) -> Self {
        self.status = status;
        self
    }
}

fn push_engine_step(
    context: &ApplicationSecurityContext,
    steps: &mut Vec<ApplicationSecurityWorkflowStep>,
    mut draft: WorkflowStepDraft,
) {
    for capability in &draft.required_capabilities {
        if !context.configured_capabilities.contains(capability) {
            draft.gaps.push(gap(
                ApplicationSecurityWorkflowGapKind::ConfiguredCapabilityMissing,
                Some(format!("{capability:?}").to_ascii_lowercase()),
            ));
        }
    }
    for effect in &draft.required_effects {
        if !context.configured_effects.contains(effect) {
            draft.gaps.push(gap(
                ApplicationSecurityWorkflowGapKind::ConfiguredEffectMissing,
                Some(format!("{effect:?}").to_ascii_lowercase()),
            ));
        }
    }
    draft.gaps.sort();
    draft.gaps.dedup();
    draft.status = if draft.gaps.is_empty() {
        ApplicationSecurityWorkflowStepStatus::Ready
    } else {
        ApplicationSecurityWorkflowStepStatus::Blocked
    };
    push_step(steps, draft);
}

fn push_host_step(steps: &mut Vec<ApplicationSecurityWorkflowStep>, draft: WorkflowStepDraft) {
    push_step(steps, draft);
}

fn push_step(steps: &mut Vec<ApplicationSecurityWorkflowStep>, draft: WorkflowStepDraft) {
    let order = steps.len();
    let identity = step_identity(
        order,
        draft.kind,
        draft.owner,
        draft.scope,
        draft.operation,
        draft.scope_identity.as_deref(),
        draft.broad,
        draft.requires_execution_authorization,
        &draft.required_capabilities,
        &draft.required_effects,
        draft.status,
        &draft.gaps,
    );
    steps.push(ApplicationSecurityWorkflowStep {
        identity,
        order,
        kind: draft.kind,
        owner: draft.owner,
        scope: draft.scope,
        operation: draft.operation.to_string(),
        scope_identity: draft.scope_identity,
        broad: draft.broad,
        requires_execution_authorization: draft.requires_execution_authorization,
        required_capabilities: draft.required_capabilities,
        required_effects: draft.required_effects,
        status: draft.status,
        gaps: draft.gaps,
    });
}

fn focused_step(
    selection: &FocusedVerificationSelection,
    order: usize,
) -> ApplicationSecurityWorkflowStep {
    let mut gaps = Vec::new();
    for selector in &selection.static_rules {
        gaps.push(gap(
            ApplicationSecurityWorkflowGapKind::FocusedStaticSelectorUnsupported,
            Some(format!("{}:{}", selector.scanner_id, selector.rule_id)),
        ));
    }
    for selector in &selection.runtime_probes {
        gaps.push(gap(
            ApplicationSecurityWorkflowGapKind::FocusedRuntimeSelectorUnsupported,
            Some(format!("{}:{}", selector.scanner_id, selector.rule_id)),
        ));
    }
    for request in &selection.requests {
        gaps.push(gap(
            ApplicationSecurityWorkflowGapKind::FocusedRequestSelectorUnsupported,
            Some(format!("{} {}", request.method, request.route)),
        ));
    }
    for test in &selection.tests {
        gaps.push(gap(
            ApplicationSecurityWorkflowGapKind::FocusedTestSelectorUnsupported,
            Some(test.clone()),
        ));
    }
    if gaps.is_empty() {
        gaps.push(gap(ApplicationSecurityWorkflowGapKind::EmptyFocusedSelection, None));
    }
    gaps.sort();
    gaps.dedup();
    let status = ApplicationSecurityWorkflowStepStatus::Unsupported;
    let identity = step_identity(
        order,
        ApplicationSecurityWorkflowStepKind::FocusedVerification,
        ApplicationSecurityWorkflowOwner::ScorchkitEngine,
        ApplicationSecurityWorkflowScope::FocusedSelection,
        "focused_verification",
        Some(&selection.identity),
        false,
        true,
        &[],
        &[],
        status,
        &gaps,
    );
    ApplicationSecurityWorkflowStep {
        identity,
        order,
        kind: ApplicationSecurityWorkflowStepKind::FocusedVerification,
        owner: ApplicationSecurityWorkflowOwner::ScorchkitEngine,
        scope: ApplicationSecurityWorkflowScope::FocusedSelection,
        operation: "focused_verification".to_string(),
        scope_identity: Some(selection.identity.clone()),
        broad: false,
        requires_execution_authorization: true,
        required_capabilities: Vec::new(),
        required_effects: Vec::new(),
        status,
        gaps,
    }
}

// JUSTIFICATION: Step identity must bind every independently reviewed scope, authority, and gap
// field; grouping them would create a second mutable representation of the public step contract.
#[allow(clippy::too_many_arguments)]
fn step_identity(
    order: usize,
    kind: ApplicationSecurityWorkflowStepKind,
    owner: ApplicationSecurityWorkflowOwner,
    scope: ApplicationSecurityWorkflowScope,
    operation: &str,
    scope_identity: Option<&str>,
    broad: bool,
    requires_execution_authorization: bool,
    required_capabilities: &[Capability],
    required_effects: &[EffectClass],
    status: ApplicationSecurityWorkflowStepStatus,
    gaps: &[ApplicationSecurityWorkflowGap],
) -> String {
    canonical_json_sha256(&serde_json::json!({
        "order": order,
        "kind": kind,
        "owner": owner,
        "scope": scope,
        "operation": operation,
        "scope_identity": scope_identity,
        "broad": broad,
        "requires_execution_authorization": requires_execution_authorization,
        "required_capabilities": required_capabilities,
        "required_effects": required_effects,
        "status": status,
        "gaps": gaps,
    }))
}

fn gap(
    kind: ApplicationSecurityWorkflowGapKind,
    detail: Option<String>,
) -> ApplicationSecurityWorkflowGap {
    ApplicationSecurityWorkflowGap { kind, detail: detail.map(|value| redact_text(&value)) }
}

fn normalized_revision(value: &str) -> Result<String, ApplicationSecurityWorkflowValidationError> {
    let value = value.trim();
    if !matches!(value.len(), 40 | 64)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ApplicationSecurityWorkflowValidationError::InvalidChangeSet);
    }
    Ok(value.to_string())
}

fn validate_change_set(
    change_set: &ApplicationChangeSet,
) -> Result<ApplicationChangeSet, ApplicationSecurityWorkflowValidationError> {
    let rebuilt = compile_application_change_set(
        &change_set.base_revision,
        &change_set.head_revision,
        change_set.changed_paths.clone(),
    )?;
    if *change_set != rebuilt {
        return Err(ApplicationSecurityWorkflowValidationError::InvalidChangeSet);
    }
    Ok(rebuilt)
}

fn validate_application_security_context(
    context: &ApplicationSecurityContext,
) -> Result<(), ApplicationSecurityWorkflowValidationError> {
    let rebuilt = compile_application_security_context(ApplicationSecurityContextInput {
        code_root: context.code_root.clone(),
        languages: context.languages.clone(),
        manifests: context.manifests.clone(),
        change_set: context.change_set.clone(),
        routes: context.routes.clone(),
        artifacts: context.artifacts.clone(),
        project: context.project.clone(),
        registered_targets: context.registered_targets.clone(),
        persona_labels: context.persona_labels.clone(),
        configured_capabilities: context.configured_capabilities.clone(),
        configured_effects: context.configured_effects.clone(),
    })?;
    if rebuilt != *context {
        return Err(ApplicationSecurityWorkflowValidationError::InvalidValue);
    }
    Ok(())
}

fn normalized_root(value: &str) -> Result<String, ApplicationSecurityWorkflowValidationError> {
    let value = value.trim();
    let path = Path::new(value);
    let lexical = path.components().collect::<PathBuf>();
    let contains_relative_components = path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir));
    if value.is_empty()
        || value.len() > MAX_APPSEC_VALUE_BYTES
        || value.chars().any(char::is_control)
        || !path.is_absolute()
        || contains_relative_components
        || lexical.to_str() != Some(value)
    {
        return Err(ApplicationSecurityWorkflowValidationError::InvalidPath);
    }
    Ok(value.to_string())
}

fn normalize_relative_paths(
    values: Vec<String>,
    maximum: usize,
) -> Result<Vec<String>, ApplicationSecurityWorkflowValidationError> {
    if values.len() > maximum {
        return Err(ApplicationSecurityWorkflowValidationError::Limit);
    }
    let mut normalized = values
        .into_iter()
        .map(|value| normalized_relative_path(&value))
        .collect::<Result<Vec<_>, _>>()?;
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalized_relative_path(
    value: &str,
) -> Result<String, ApplicationSecurityWorkflowValidationError> {
    let value = value.trim();
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > MAX_APPSEC_VALUE_BYTES
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || path.is_absolute()
        || !path.components().all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ApplicationSecurityWorkflowValidationError::InvalidPath);
    }
    Ok(path.to_string_lossy().into_owned())
}

fn normalize_context_paths(
    values: Vec<ApplicationContextValue>,
    maximum: usize,
) -> Result<Vec<ApplicationContextValue>, ApplicationSecurityWorkflowValidationError> {
    if values.len() > maximum {
        return Err(ApplicationSecurityWorkflowValidationError::Limit);
    }
    let mut normalized = values
        .into_iter()
        .map(|value| {
            if value.provenance != ApplicationContextProvenance::HostDeclared {
                return Err(ApplicationSecurityWorkflowValidationError::InvalidValue);
            }
            Ok(ApplicationContextValue {
                value: normalized_relative_path(&value.value)?,
                provenance: value.provenance,
            })
        })
        .collect::<Result<Vec<_>, ApplicationSecurityWorkflowValidationError>>()?;
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalize_context_routes(
    values: Vec<ApplicationContextValue>,
) -> Result<Vec<ApplicationContextValue>, ApplicationSecurityWorkflowValidationError> {
    if values.len() > MAX_APPSEC_ROUTES {
        return Err(ApplicationSecurityWorkflowValidationError::Limit);
    }
    let mut normalized = values
        .into_iter()
        .map(|value| {
            if value.provenance != ApplicationContextProvenance::HostDeclared {
                return Err(ApplicationSecurityWorkflowValidationError::InvalidValue);
            }
            Ok(ApplicationContextValue {
                value: normalized_route(&value.value)?,
                provenance: value.provenance,
            })
        })
        .collect::<Result<Vec<_>, ApplicationSecurityWorkflowValidationError>>()?;
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalized_route(value: &str) -> Result<String, ApplicationSecurityWorkflowValidationError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_APPSEC_VALUE_BYTES
        || !value.starts_with('/')
        || value.contains(['?', '#'])
        || value.chars().any(char::is_control)
    {
        return Err(ApplicationSecurityWorkflowValidationError::InvalidRoute);
    }
    let normalized =
        value.split('/').filter(|part| !part.is_empty()).fold(String::new(), |mut route, part| {
            route.push('/');
            route.push_str(part);
            route
        });
    Ok(if normalized.is_empty() { "/".to_string() } else { normalized })
}

fn normalize_targets(
    values: Vec<ApplicationContextTarget>,
) -> Result<Vec<ApplicationContextTarget>, ApplicationSecurityWorkflowValidationError> {
    if values.len() > MAX_APPSEC_TARGETS {
        return Err(ApplicationSecurityWorkflowValidationError::Limit);
    }
    let mut normalized = values
        .into_iter()
        .map(|target| {
            if target.provenance != ApplicationContextProvenance::ProjectRegistered {
                return Err(ApplicationSecurityWorkflowValidationError::InvalidValue);
            }
            Ok(ApplicationContextTarget {
                url: crate::application_pentest::canonical_application_pentest_target(&target.url)
                    .map_err(|_| ApplicationSecurityWorkflowValidationError::InvalidValue)?,
                label: target.label.map(|label| normalized_label(&label)).transpose()?,
                provenance: target.provenance,
            })
        })
        .collect::<Result<Vec<_>, ApplicationSecurityWorkflowValidationError>>()?;
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalize_labels(
    values: Vec<String>,
    maximum: usize,
) -> Result<Vec<String>, ApplicationSecurityWorkflowValidationError> {
    if values.len() > maximum {
        return Err(ApplicationSecurityWorkflowValidationError::Limit);
    }
    let mut normalized =
        values.into_iter().map(|value| normalized_label(&value)).collect::<Result<Vec<_>, _>>()?;
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalized_label(value: &str) -> Result<String, ApplicationSecurityWorkflowValidationError> {
    let value = redact_text(value.trim());
    if value.is_empty()
        || value.len() > MAX_APPSEC_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ApplicationSecurityWorkflowValidationError::InvalidValue);
    }
    Ok(value)
}

fn sorted_unique<T: Ord>(values: Vec<T>) -> Vec<T> {
    values.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revision(byte: char) -> String {
        std::iter::repeat_n(byte, 40).collect()
    }

    fn input() -> ApplicationSecurityContextInput {
        ApplicationSecurityContextInput {
            code_root: "/workspace/app".to_string(),
            languages: vec!["rust".to_string(), "rust".to_string()],
            manifests: vec!["Cargo.toml".to_string()],
            change_set: Some(
                compile_application_change_set(
                    &revision('a'),
                    &revision('b'),
                    vec!["src/lib.rs".to_string()],
                )
                .unwrap_or_else(|error| panic!("change set: {error}")),
            ),
            routes: vec![ApplicationContextValue {
                value: "//api//items".to_string(),
                provenance: ApplicationContextProvenance::HostDeclared,
            }],
            artifacts: vec![ApplicationContextValue {
                value: "dist/app.tar".to_string(),
                provenance: ApplicationContextProvenance::HostDeclared,
            }],
            project: Some("fixture".to_string()),
            registered_targets: vec![ApplicationContextTarget {
                url: "https://example.com/app?token=secret".to_string(),
                label: Some("staging".to_string()),
                provenance: ApplicationContextProvenance::ProjectRegistered,
            }],
            persona_labels: vec!["member".to_string()],
            configured_capabilities: vec![
                Capability::CodeScan,
                Capability::ExternalTool,
                Capability::DastScan,
            ],
            configured_effects: vec![EffectClass::Passive, EffectClass::Intrusive],
        }
    }

    fn context() -> ApplicationSecurityContext {
        compile_application_security_context(input())
            .unwrap_or_else(|error| panic!("context: {error}"))
    }

    fn host_value(value: impl Into<String>) -> ApplicationContextValue {
        ApplicationContextValue {
            value: value.into(),
            provenance: ApplicationContextProvenance::HostDeclared,
        }
    }

    #[test]
    fn public_profile_labels_parse_to_their_exact_variants() {
        for (label, expected) in [
            ("commit", ApplicationSecurityWorkflowProfile::Commit),
            ("pull_request", ApplicationSecurityWorkflowProfile::PullRequest),
            ("pull-request", ApplicationSecurityWorkflowProfile::PullRequest),
            ("pr", ApplicationSecurityWorkflowProfile::PullRequest),
            ("staging", ApplicationSecurityWorkflowProfile::Staging),
            ("release", ApplicationSecurityWorkflowProfile::Release),
            ("deep", ApplicationSecurityWorkflowProfile::Deep),
        ] {
            assert_eq!(ApplicationSecurityWorkflowProfile::parse(label), Ok(expected));
        }
        assert_eq!(
            ApplicationSecurityWorkflowProfile::parse("repository"),
            Err(ApplicationSecurityWorkflowValidationError::InvalidProfile)
        );
    }

    #[test]
    fn change_set_requires_immutable_distinct_revisions_and_relative_paths() {
        let base = revision('a');
        let head = revision('b');
        let compiled = compile_application_change_set(
            &base,
            &head,
            vec!["src/b.rs".to_string(), "src/a.rs".to_string(), "src/a.rs".to_string()],
        )
        .unwrap_or_else(|error| panic!("valid change set: {error}"));
        assert_eq!(compiled.changed_paths, ["src/a.rs", "src/b.rs"]);
        assert!(
            compile_application_change_set("main", &head, vec!["src/a.rs".to_string()]).is_err()
        );
        assert!(compile_application_change_set(&base, &base, vec!["src/a.rs".to_string()]).is_err());
        assert!(
            compile_application_change_set(&base, &head, vec!["../secret".to_string()]).is_err()
        );
        assert!(compile_application_change_set(&base, &head, Vec::new()).is_err());
    }

    #[test]
    fn revisions_enforce_exact_lengths_and_lowercase_hex() {
        assert!(normalized_revision(&"a".repeat(40)).is_ok());
        assert!(normalized_revision(&"b".repeat(64)).is_ok());
        for invalid in [
            "a".repeat(39),
            "a".repeat(41),
            "b".repeat(63),
            "b".repeat(65),
            "g".repeat(40),
            "A".repeat(40),
        ] {
            assert_eq!(
                normalized_revision(&invalid),
                Err(ApplicationSecurityWorkflowValidationError::InvalidChangeSet)
            );
        }
    }

    #[test]
    fn roots_paths_routes_and_collections_enforce_exact_boundaries() {
        let exact_root = format!("/{}", "a".repeat(MAX_APPSEC_VALUE_BYTES - 1));
        let oversized_root = format!("/{}", "a".repeat(MAX_APPSEC_VALUE_BYTES));
        assert!(normalized_root(&exact_root).is_ok());
        assert_eq!(
            normalized_root(&oversized_root),
            Err(ApplicationSecurityWorkflowValidationError::InvalidPath)
        );

        let exact_path = "a".repeat(MAX_APPSEC_VALUE_BYTES);
        let oversized_path = "a".repeat(MAX_APPSEC_VALUE_BYTES + 1);
        assert!(normalized_relative_path(&exact_path).is_ok());
        for invalid in [
            String::new(),
            oversized_path,
            "src\\lib.rs".to_string(),
            "src/line\nbreak.rs".to_string(),
            "/absolute/path".to_string(),
        ] {
            assert_eq!(
                normalized_relative_path(&invalid),
                Err(ApplicationSecurityWorkflowValidationError::InvalidPath)
            );
        }

        assert!(normalize_relative_paths(
            vec!["src/lib.rs".to_string(); MAX_APPSEC_CHANGED_PATHS],
            MAX_APPSEC_CHANGED_PATHS,
        )
        .is_ok());
        assert_eq!(
            normalize_relative_paths(
                vec!["src/lib.rs".to_string(); MAX_APPSEC_CHANGED_PATHS + 1],
                MAX_APPSEC_CHANGED_PATHS,
            ),
            Err(ApplicationSecurityWorkflowValidationError::Limit)
        );

        assert!(normalize_context_paths(
            vec![host_value("dist/app.tar"); MAX_APPSEC_ARTIFACTS],
            MAX_APPSEC_ARTIFACTS,
        )
        .is_ok());
        assert_eq!(
            normalize_context_paths(
                vec![host_value("dist/app.tar"); MAX_APPSEC_ARTIFACTS + 1],
                MAX_APPSEC_ARTIFACTS,
            ),
            Err(ApplicationSecurityWorkflowValidationError::Limit)
        );

        assert!(normalize_context_routes(vec![host_value("/api"); MAX_APPSEC_ROUTES]).is_ok());
        assert_eq!(
            normalize_context_routes(vec![host_value("/api"); MAX_APPSEC_ROUTES + 1]),
            Err(ApplicationSecurityWorkflowValidationError::Limit)
        );
        let oversized_route = format!("/{}", "a".repeat(MAX_APPSEC_VALUE_BYTES));
        assert_eq!(
            normalized_route(&oversized_route),
            Err(ApplicationSecurityWorkflowValidationError::InvalidRoute)
        );
    }

    #[test]
    fn context_is_order_stable_redacted_and_provenance_explicit() {
        let first = context();
        let mut permuted = input();
        permuted.languages.reverse();
        permuted.configured_capabilities.reverse();
        let second = compile_application_security_context(permuted)
            .unwrap_or_else(|error| panic!("permuted context: {error}"));
        assert_eq!(first.identity, second.identity);
        assert_eq!(first.routes[0].value, "/api/items");
        assert_eq!(first.registered_targets[0].url, "https://example.com/app?token=");
        assert!(!serde_json::to_string(&first)
            .unwrap_or_else(|error| panic!("serialize: {error}"))
            .contains("secret"));
        assert!(first
            .gaps
            .iter()
            .any(|gap| { gap.kind == ApplicationContextGapKind::ChangeSetNotEngineVerified }));
        assert!(first
            .gaps
            .iter()
            .any(|gap| gap.kind == ApplicationContextGapKind::RoutesNotEngineVerified));
        assert!(first
            .gaps
            .iter()
            .any(|gap| gap.kind == ApplicationContextGapKind::ArtifactsNotEngineVerified));
        assert!(!first
            .gaps
            .iter()
            .any(|gap| gap.kind == ApplicationContextGapKind::NoRegisteredTargets));

        let mut missing_target = input();
        missing_target.registered_targets.clear();
        let missing_target = compile_application_security_context(missing_target)
            .unwrap_or_else(|error| panic!("missing target context: {error}"));
        assert!(missing_target
            .gaps
            .iter()
            .any(|gap| gap.kind == ApplicationContextGapKind::NoRegisteredTargets));

        let mut traversing_root = input();
        traversing_root.code_root = "/workspace/../secret".to_string();
        assert_eq!(
            compile_application_security_context(traversing_root),
            Err(ApplicationSecurityWorkflowValidationError::InvalidPath)
        );
    }

    #[test]
    fn every_profile_expands_in_exact_order_without_minting_authority() {
        let context = context();
        let profiles = [
            ApplicationSecurityWorkflowProfile::Commit,
            ApplicationSecurityWorkflowProfile::PullRequest,
            ApplicationSecurityWorkflowProfile::Staging,
            ApplicationSecurityWorkflowProfile::Release,
            ApplicationSecurityWorkflowProfile::Deep,
        ];
        let plans = profiles
            .into_iter()
            .map(|profile| {
                compile_application_security_workflow(&context, profile, None)
                    .unwrap_or_else(|error| panic!("profile: {error}"))
            })
            .collect::<Vec<_>>();
        assert_eq!(plans[0].steps.len(), 1);
        assert_eq!(plans[1].steps.len(), 2);
        assert_eq!(plans[2].steps.len(), 3);
        assert_eq!(plans[3].steps.len(), 7);
        assert_eq!(plans[4].steps.len(), 8);
        for pair in plans.windows(2) {
            assert!(pair[1].steps.starts_with(&pair[0].steps));
        }
        assert!(plans.iter().flat_map(|plan| &plan.steps).all(|step| {
            !step.required_effects.contains(&EffectClass::CredentialTest)
                && !step.required_effects.contains(&EffectClass::Exploit)
        }));
        assert!(plans[2].steps[2].requires_execution_authorization);
        let identities =
            plans[3].steps.iter().map(|step| step.identity.as_str()).collect::<BTreeSet<_>>();
        assert_eq!(identities.len(), plans[3].steps.len());
        assert!(identities.iter().all(|identity| {
            identity.len() == 64
                && identity
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }));
    }

    #[test]
    fn engine_steps_distinguish_present_and_missing_requirements() {
        let draft = || {
            WorkflowStepDraft::engine(
                ApplicationSecurityWorkflowStepKind::FastApplicationScan,
                ApplicationSecurityWorkflowScope::CodeRoot,
                "scan_code",
            )
            .with_requirements(vec![Capability::CodeScan], vec![EffectClass::Passive])
        };

        let mut ready_steps = Vec::new();
        push_engine_step(&context(), &mut ready_steps, draft());
        assert_eq!(ready_steps[0].status, ApplicationSecurityWorkflowStepStatus::Ready);
        assert!(ready_steps[0].gaps.is_empty());

        let mut missing_context = context();
        missing_context.configured_capabilities.clear();
        missing_context.configured_effects.clear();
        let mut blocked_steps = Vec::new();
        push_engine_step(&missing_context, &mut blocked_steps, draft());
        assert_eq!(blocked_steps[0].status, ApplicationSecurityWorkflowStepStatus::Blocked);
        assert!(
            blocked_steps[0]
                .gaps
                .iter()
                .any(|gap| gap.kind
                    == ApplicationSecurityWorkflowGapKind::ConfiguredCapabilityMissing)
        );
        assert!(blocked_steps[0]
            .gaps
            .iter()
            .any(|gap| gap.kind == ApplicationSecurityWorkflowGapKind::ConfiguredEffectMissing));
    }

    #[test]
    fn missing_inputs_and_configured_grants_remain_blocked_gaps() {
        let mut missing = input();
        missing.change_set = None;
        missing.project = None;
        missing.registered_targets.clear();
        missing.artifacts.clear();
        missing.configured_capabilities.clear();
        missing.configured_effects.clear();
        let context = compile_application_security_context(missing)
            .unwrap_or_else(|error| panic!("missing context: {error}"));
        let plan = compile_application_security_workflow(
            &context,
            ApplicationSecurityWorkflowProfile::Release,
            None,
        )
        .unwrap_or_else(|error| panic!("release plan: {error}"));
        assert!(plan.steps.iter().all(|step| {
            step.owner == ApplicationSecurityWorkflowOwner::HostAnalysis
                || step.status == ApplicationSecurityWorkflowStepStatus::Blocked
        }));
        assert!(plan
            .gaps
            .iter()
            .any(|gap| { gap.kind == ApplicationSecurityWorkflowGapKind::MissingChangeSet }));
        assert!(plan.gaps.iter().any(|gap| {
            gap.kind == ApplicationSecurityWorkflowGapKind::MissingRegisteredTarget
        }));
        assert!(plan
            .gaps
            .iter()
            .any(|gap| { gap.kind == ApplicationSecurityWorkflowGapKind::MissingArtifact }));
    }

    #[test]
    fn focused_selection_suppresses_broad_fallback_and_rejects_tampering() {
        let context = context();
        let selection = crate::attack_path::focused_verification_test_fixture();
        let plan = compile_application_security_workflow(
            &context,
            ApplicationSecurityWorkflowProfile::Deep,
            Some(selection.clone()),
        )
        .unwrap_or_else(|error| panic!("focused plan: {error}"));
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].kind, ApplicationSecurityWorkflowStepKind::FocusedVerification);
        assert_eq!(plan.steps[0].status, ApplicationSecurityWorkflowStepStatus::Unsupported);
        assert!(!plan.steps[0].broad);
        assert!(plan.steps[0].gaps.iter().any(|gap| {
            gap.kind == ApplicationSecurityWorkflowGapKind::FocusedStaticSelectorUnsupported
        }));

        let mut tampered = selection;
        tampered.static_rules[0].rule_id = "different".to_string();
        assert_eq!(
            compile_application_security_workflow(
                &context,
                ApplicationSecurityWorkflowProfile::Commit,
                Some(tampered),
            ),
            Err(ApplicationSecurityWorkflowValidationError::InvalidFocusedSelection)
        );

        let mut tampered_context = context;
        tampered_context.code_root = "/different".to_string();
        assert_eq!(
            compile_application_security_workflow(
                &tampered_context,
                ApplicationSecurityWorkflowProfile::Commit,
                None,
            ),
            Err(ApplicationSecurityWorkflowValidationError::InvalidValue)
        );
    }
}
