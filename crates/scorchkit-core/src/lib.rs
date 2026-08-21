//! Stable domain contracts shared by every `ScorchKit` host and scanner family.

pub mod adapter;
pub mod adapter_execution;
pub mod application_dast;
pub mod application_pentest;
pub mod attack_path;
pub mod compliance;
pub mod compliance_framework;
pub mod correlation;
pub mod cve;
pub mod error;
pub mod events;
pub mod evidence;
pub mod finding;
pub mod observation;
pub mod risk_score;
pub mod scan_result;
pub mod service_fingerprint;
pub mod severity;
pub mod shared_data;
pub mod supply_chain;
pub mod target;

/// Compatibility namespace used by extracted source modules and doctests.
pub mod engine {
    pub use crate::{
        adapter, adapter_execution, application_dast, application_pentest, attack_path, compliance,
        compliance_framework, correlation, cve, error, events, evidence, finding, observation,
        risk_score, scan_result, service_fingerprint, severity, shared_data, supply_chain, target,
    };
    pub use scorchkit_policy::{policy, scope};
}

/// Compatibility module for the unified error's policy variant.
pub mod policy {
    pub use scorchkit_policy::policy::*;
}

pub use adapter::{
    AdapterContractV1, AdapterOutputContract, AdapterParseOutcome, AdapterTargetKind,
    LifecycleStage, ProvenanceStrategy, SecurityDomain, TemporaryArtifactPolicy,
    ADAPTER_CONTRACT_V1,
};
pub use adapter_execution::{
    AdapterExecutionAssessment, AdapterExecutionGap, AdapterExecutionGapKind,
    AdapterExecutionStatus, AdapterInputIdentity, ADAPTER_EXECUTION_ASSESSMENT_SCHEMA_V1,
};
pub use application_dast::{
    ApplicationDastAssessment, ApplicationDastAuthenticationState, ApplicationDastCoverageGap,
    ApplicationDastCoverageStatus, ApplicationDastGapKind, ApplicationDastPersonaAssessment,
    ApplicationDastPhase, ApplicationDastPhaseOutcome, ApplicationDastPhaseStatus,
    ApplicationDastProfile, ApplicationDastRouteCoverage, ApplicationDastSchemaIdentity,
    ApplicationDastSchemaKind, APPLICATION_DAST_ASSESSMENT_SCHEMA_V1,
};
pub use application_pentest::{
    application_pentest_evidence_satisfies, canonical_application_pentest_target,
    ApplicationEvidenceFormat, ApplicationEvidenceImportAssessment, ApplicationEvidenceSourceKind,
    ApplicationPentestAccessExpectation, ApplicationPentestAssessment,
    ApplicationPentestAuthorizationRequirement, ApplicationPentestBlastRadius,
    ApplicationPentestCleanupDisposition, ApplicationPentestCoverageStatus,
    ApplicationPentestEvidenceRequirement, ApplicationPentestExecutorKind, ApplicationPentestGap,
    ApplicationPentestGapKind, ApplicationPentestInvariantResult, ApplicationPentestOperation,
    ApplicationPentestPayloadClass, ApplicationPentestPersonaExpectation, ApplicationPentestPlan,
    ApplicationPentestProposalKind, ApplicationPentestProposalSource, ApplicationPentestScenario,
    ApplicationPentestScenarioClass, ApplicationPentestScenarioOutcome,
    ApplicationPentestScenarioStatus, ApplicationPentestValidationError,
    PlannedApplicationPentestScenario, APPLICATION_EVIDENCE_IMPORT_SCHEMA_V1,
    APPLICATION_PENTEST_ASSESSMENT_SCHEMA_V1, APPLICATION_PENTEST_PLAN_SCHEMA_V1,
    APPLICATION_PENTEST_SCENARIO_SCHEMA_V1, MAX_APPLICATION_PENTEST_CONCURRENCY,
    MAX_APPLICATION_PENTEST_EVIDENCE_REQUIREMENTS, MAX_APPLICATION_PENTEST_PERSONAS,
    MAX_APPLICATION_PENTEST_PRECONDITIONS, MAX_APPLICATION_PENTEST_REFERENCES,
    MAX_APPLICATION_PENTEST_SCENARIOS, MAX_APPLICATION_PENTEST_SECONDS,
    MAX_APPLICATION_PENTEST_VALUE_BYTES,
};
pub use attack_path::{
    correlate_attack_paths, AttackPath, AttackPathCorrelation, AttackPathCorrelationGap,
    AttackPathCorrelationGapKind, AttackPathCorrelationStatus, AttackPathGap, AttackPathGapKind,
    AttackPathIdentity, AttackPathMember, AttackPathMemberRole, AttackPathState,
    AttackPathTransition, AttackPathTransitionReason, AttackPathValidationError, CorrelationFacet,
    CorrelationFacetKind, FocusedVerificationSelection, RequestVerificationSelector,
    ScannerVerificationSelector, VerificationAttempt, VerificationAttemptError,
    VerificationConditions, VerificationCoverage, VerificationOutcome,
    ATTACK_PATH_CORRELATION_SCHEMA_V1, ATTACK_PATH_IDENTITY_SCHEMA_V1, ATTACK_PATH_SCHEMA_V1,
    ATTACK_PATH_TRANSITION_SCHEMA_V1, FOCUSED_VERIFICATION_SCHEMA_V1, MAX_CORRELATED_PATHS,
    MAX_CORRELATION_DETAILS_PER_FINDING, MAX_CORRELATION_FACET_BYTES, MAX_CORRELATION_FINDINGS,
    MAX_CORRELATION_PAIR_EVALUATIONS, MAX_CORRELATION_PROJECT_EVIDENCE,
    VERIFICATION_ATTEMPT_SCHEMA_V1,
};
pub use error::{Result, ScorchError};
pub use evidence::HttpEvidence;
pub use finding::Finding;
pub use observation::{
    canonical_json_sha256, sha256_hex, AgentAnalysisRecord, CodeFlow, CodeFlowStep, CorrelationKey,
    EvidencePayload, EvidenceRecord, FindingIdentity, FindingRecordV2, HttpParameterIdentity,
    ObservationLocation, RedactionMetadata, ScannerProvenance, SourceRegion, ThreadFlow,
    AGENT_ANALYSIS_SCHEMA_V1, EVIDENCE_SCHEMA_V2, FINDING_IDENTITY_SCHEMA_V1, FINDING_SCHEMA_V2,
};
pub use scan_result::{
    ModuleOutcome, ModuleOutcomeReason, ModuleOutcomeStatus, ScanExecutionStatus, ScanResult,
    ScanSummary,
};
pub use severity::Severity;
pub use supply_chain::{
    correlate_observations, observation_counts_by_tool, AdvisoryIdentity, DependencyEvidenceKind,
    PackageIdentity, ProviderSnapshot, ProviderSnapshotState, SbomArtifact, SupplyChainAssessment,
    SupplyChainCorrelation, SupplyChainCoverageGap, SupplyChainCoverageStatus, SupplyChainGapKind,
    SupplyChainObservation, SupplyChainPhase, SupplyChainTarget, SupplyChainTargetKind,
    SUPPLY_CHAIN_ASSESSMENT_SCHEMA_V1,
};
pub use target::Target;
