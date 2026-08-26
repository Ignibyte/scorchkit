//! Stable provider-neutral control API contracts.
//!
//! This package owns wire types, schemas, bounds, and pure configuration resolution. It performs
//! no I/O and has no dependency on `ScorchKit`'s composition, storage, CLI, MCP, or agent packages.

pub mod configuration;
pub mod contract;
pub mod error;
pub mod event;
pub mod resource;
pub mod schema;
pub mod team;

pub use configuration::{
    resolve_configuration, ConfigDecision, ConfigDecisionOutcome, ConfigLayerName, ConfigPatchV1,
    ConfigurationResolutionRequestV1, ControlBudgetsV1, ControlCapabilityV1, ControlEffectV1,
    ControlTargetKindV1, ControlTargetV1, ResolutionCeilingV1, ResolvedConfigurationV1,
};
pub use contract::{
    ControlCommandV1, ControlOperationV1, ControlPrincipalKindV1, ControlPrincipalV1,
    ControlQueryV1, ControlRequestV1, ControlResponseOutcomeV1, ControlResponseV1, EventCursorV1,
    FindingCorrelationFacetV1, PageRequestV1, CONTROL_API_SCHEMA_V1, CONTROL_MAX_CURSOR_BYTES,
    CONTROL_MAX_PAGE_SIZE, CONTROL_MAX_TRIAGE_REFERENCES,
};
pub use error::{ControlErrorCodeV1, ControlErrorV1};
pub use event::{ControlEventBatchV1, ControlEventKindV1, ControlEventV1};
pub use resource::{
    ControlResultV1, EngagementViewV1, EvidenceViewV1, FindingTriageSubjectViewV1,
    FindingTriageViewV1, FindingViewV1, JobProgressViewV1, JobViewV1, ModelReadinessViewV1,
    ModuleViewV1, PageV1, ProjectReportViewV1, ProjectViewV1, TargetViewV1,
};
pub use schema::{description_v1, ControlApiDescriptionV1, ControlOperationDescriptionV1};
pub use team::{
    TeamAuditEventV1, TeamAuditOutcomeV1, TeamControlResponseV1, TeamObjectKindV1,
    TeamObjectViewV1, TeamPermissionV1, TeamPrincipalV1, TeamRecoveryManifestV1,
    TeamRecoveryObjectV1, TeamRoleV1, TEAM_API_SCHEMA_V1, TEAM_OBJECT_SCHEMA_V1,
    TEAM_RECOVERY_SCHEMA_V1,
};
