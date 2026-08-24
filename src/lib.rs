//! `ScorchKit` — Web application security testing toolkit.
//!
//! `ScorchKit` is a modular security scanner with both DAST (Dynamic Application
//! Security Testing) and SAST (Static Application Security Testing) capabilities.
//!
//! # Quick Start
//!
//! Use the [`Engine`] facade for the simplest entry point:
//!
//! ```no_run
//! use std::sync::Arc;
//! use scorchkit::prelude::*;
//!
//! # async fn example() -> Result<()> {
//! let code = std::path::Path::new(".").canonicalize()?;
//! let policy = EngagementPolicy::default()
//!     .allow_scope(ScopeRule::parse("example.com").expect("web scope"))
//!     .allow_scope(ScopeRule::path_prefix(&code)?)
//!     .allow_capability(Capability::DastScan)
//!     .allow_capability(Capability::CodeScan)
//!     .allow_capability(Capability::ExternalTool)
//!     .allow_effect(EffectClass::Intrusive)
//!     .allow_effect(EffectClass::Passive);
//! let engine = Engine::for_engagement(
//!     Arc::new(AppConfig::default()),
//!     Arc::new(Engagement::new("authorized assessment", policy)),
//! );
//!
//! // DAST scan
//! let result = engine.scan("https://example.com").await?;
//!
//! // SAST scan
//! let code_result = engine.code_scan(&code).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Architecture
//!
//! - **[`engine`]** — Core types: [`Finding`], [`Severity`], [`Target`],
//!   [`ScanResult`], [`engine::module_trait::ScanModule`] trait,
//!   [`engine::code_module::CodeModule`] trait
//! - **[`runner`]** — Orchestrators for concurrent module execution
//! - **[`recon`]** / **[`scanner`]** / **[`tools`]** — DAST modules
//!   (reconnaissance, vulnerability scanning, external tool wrappers)
//! - **[`sast`]** / **[`sast_tools`]** — SAST modules (built-in analyzers
//!   and external tool wrappers)
//! - **[`config`]** — TOML configuration (`AppConfig`)
//! - **[`report`]** — Output formats (terminal, JSON, HTML, SARIF)
//! - **[`facade`]** — High-level [`Engine`] for library consumers
//! - **[`prelude`]** — Convenience re-exports

#[cfg(not(any(unix, windows)))]
compile_error!(
    "ScorchKit supports Unix process groups and Windows Job Objects; this target has no owned \
     descendant-process backend"
);

pub mod adapter_catalog;
pub mod agent;
pub mod ai;
pub mod application_dast;
pub mod application_pentest;
pub mod cli;
#[cfg(feature = "cloud")]
pub mod cloud;
pub mod config;
pub mod control;
pub mod engine;
pub mod facade;
#[cfg(feature = "infra")]
pub mod infra;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod prelude;
pub mod recon;
pub mod report;
pub mod runner;
pub mod sast;
pub mod sast_tools;
pub mod scanner;
#[cfg(feature = "storage")]
pub mod storage;
pub mod supply_chain;
pub mod tools;
mod trusted_nuclei;
pub mod webhooks;
#[cfg(windows)]
mod windows_support;

#[cfg(test)]
pub(crate) static TEST_ENVIRONMENT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Crate-root re-exports for the most common types.
// Library consumers can use `scorchkit::Finding` instead of
// `scorchkit::engine::finding::Finding`.
pub use application_dast::{ApplicationDastRequest, ApplicationDastSchemaRequest};
pub use application_pentest::{
    ApplicationEvidenceImportRequest, ManualApplicationFinding, PreparedApplicationEvidenceImport,
};
pub use engine::error::{Result, ScorchError};
pub use engine::finding::Finding;
pub use engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy, PolicyTarget};
pub use engine::scan_result::ScanResult;
pub use engine::scope::ScopeRule;
pub use engine::severity::Severity;
pub use engine::target::Target;
pub use facade::Engine;
pub use scorchkit_code::SupplyChainProfile;
pub use scorchkit_control as control_contract;
pub use scorchkit_core::{
    AdapterExecutionAssessment, AdapterExecutionGap, AdapterExecutionGapKind,
    AdapterExecutionStatus, AdapterInputIdentity, AdvisoryIdentity, ApplicationChangeSet,
    ApplicationContextGap, ApplicationContextGapKind, ApplicationContextProvenance,
    ApplicationContextTarget, ApplicationContextValue, ApplicationDastAssessment,
    ApplicationDastAuthenticationState, ApplicationDastCoverageGap, ApplicationDastCoverageStatus,
    ApplicationDastGapKind, ApplicationDastPersonaAssessment, ApplicationDastPhase,
    ApplicationDastPhaseOutcome, ApplicationDastPhaseStatus, ApplicationDastProfile,
    ApplicationDastRouteCoverage, ApplicationDastSchemaIdentity, ApplicationDastSchemaKind,
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
    ApplicationSecurityContext, ApplicationSecurityContextInput, ApplicationSecurityWorkflowGap,
    ApplicationSecurityWorkflowGapKind, ApplicationSecurityWorkflowOwner,
    ApplicationSecurityWorkflowPlan, ApplicationSecurityWorkflowProfile,
    ApplicationSecurityWorkflowScope, ApplicationSecurityWorkflowStep,
    ApplicationSecurityWorkflowStepKind, ApplicationSecurityWorkflowStepStatus,
    ApplicationSecurityWorkflowValidationError, AttackPath, AttackPathCorrelation,
    AttackPathCorrelationGap, AttackPathCorrelationGapKind, AttackPathCorrelationStatus,
    AttackPathGap, AttackPathGapKind, AttackPathIdentity, AttackPathMember, AttackPathMemberRole,
    AttackPathState, AttackPathTransition, AttackPathTransitionReason, AttackPathValidationError,
    CorrelationFacet, CorrelationFacetKind, DependencyEvidenceKind, FocusedVerificationSelection,
    PackageIdentity, ProviderSnapshot, ProviderSnapshotState, RequestVerificationSelector,
    SbomArtifact, ScannerVerificationSelector, SupplyChainAssessment, SupplyChainCorrelation,
    SupplyChainCoverageGap, SupplyChainCoverageStatus, SupplyChainGapKind, SupplyChainObservation,
    SupplyChainPhase, SupplyChainTarget, SupplyChainTargetKind, VerificationAttempt,
    VerificationAttemptError, VerificationConditions, VerificationCoverage, VerificationOutcome,
    ADAPTER_EXECUTION_ASSESSMENT_SCHEMA_V1, APPLICATION_DAST_ASSESSMENT_SCHEMA_V1,
    APPLICATION_EVIDENCE_IMPORT_SCHEMA_V1, APPLICATION_PENTEST_ASSESSMENT_SCHEMA_V1,
    APPLICATION_PENTEST_PLAN_SCHEMA_V1, APPLICATION_PENTEST_SCENARIO_SCHEMA_V1,
    APPLICATION_SECURITY_CONTEXT_SCHEMA_V1, APPSEC_CHANGE_SET_SCHEMA_V1,
    APPSEC_WORKFLOW_PLAN_SCHEMA_V1, ATTACK_PATH_CORRELATION_SCHEMA_V1,
    ATTACK_PATH_IDENTITY_SCHEMA_V1, ATTACK_PATH_SCHEMA_V1, ATTACK_PATH_TRANSITION_SCHEMA_V1,
    FOCUSED_VERIFICATION_SCHEMA_V1, SUPPLY_CHAIN_ASSESSMENT_SCHEMA_V1,
    VERIFICATION_ATTEMPT_SCHEMA_V1,
};
pub use supply_chain::{ProviderDownload, ProviderRefreshRequest, SupplyChainProvider};
