//! Versioned public resource projections.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::configuration::ResolvedConfigurationV1;
use crate::event::ControlEventBatchV1;
use crate::schema::ControlApiDescriptionV1;

/// One deterministic bounded page.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageV1<T> {
    /// Current page values.
    pub items: Vec<T>,
    /// Opaque continuation cursor when more values exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Safe current-engagement projection.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngagementViewV1 {
    /// Engagement identifier.
    pub id: Uuid,
    /// Operator-facing name.
    pub name: String,
    /// Whether new effects are eligible.
    pub enabled: bool,
    /// Optional expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Stable capability names.
    pub capabilities: Vec<String>,
    /// Stable effect names.
    pub effects: Vec<String>,
}

/// Project projection independent of database rows.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectViewV1 {
    /// Project ID.
    pub id: Uuid,
    /// Project name.
    pub name: String,
    /// Project description.
    pub description: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

/// Registered target projection.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetViewV1 {
    /// Target ID.
    pub id: Uuid,
    /// Owning project.
    pub project_id: Uuid,
    /// Redacted canonical target URL.
    pub url: String,
    /// Optional display label.
    pub label: String,
    /// Registration time.
    pub created_at: DateTime<Utc>,
}

/// Bounded durable job progress.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobProgressViewV1 {
    /// Selected module count.
    pub total_modules: u32,
    /// Modules currently active.
    pub active_modules: Vec<String>,
    /// Modules completed with durable results.
    pub completed_modules: Vec<String>,
    /// Modules skipped.
    pub skipped_modules: Vec<String>,
    /// Modules that failed nonfatally.
    pub failed_modules: Vec<String>,
    /// Number of durably retained findings.
    pub finding_count: u32,
}

/// Provider-neutral durable job projection.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobViewV1 {
    /// Attempt ID.
    pub id: Uuid,
    /// Root attempt ID.
    pub root_job_id: Uuid,
    /// Parent attempt when resumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_job_id: Option<Uuid>,
    /// One-based attempt number.
    pub attempt: u32,
    /// Stable state string.
    pub state: String,
    /// Durable revision.
    pub revision: u64,
    /// Authorized target.
    pub target: String,
    /// Profile name.
    pub profile: String,
    /// Durable progress.
    pub progress: JobProgressViewV1,
    /// Safe terminal diagnostic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
    /// Terminal time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
}

/// Canonical validated finding projection.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingViewV1 {
    /// Storage identity.
    pub id: Uuid,
    /// Owning project.
    pub project_id: Uuid,
    /// Most recent scan.
    pub scan_id: Uuid,
    /// Legacy compatibility fingerprint after canonical validation.
    pub fingerprint: String,
    /// Canonical identity schema.
    pub identity_schema: String,
    /// Canonical stable identity.
    pub stable_identity: String,
    /// Canonical cross-scanner correlation keys.
    pub correlation_keys: serde_json::Value,
    /// Current lifecycle compatibility state.
    pub status: String,
    /// Redacted lifecycle rationale, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_note: Option<String>,
    /// Number of observations.
    pub seen_count: u32,
    /// First durable observation time.
    pub first_seen: DateTime<Utc>,
    /// Most recent durable observation time.
    pub last_seen: DateTime<Utc>,
    /// Initial detection timestamp retained by storage.
    pub found_at: DateTime<Utc>,
    /// Canonical redacted finding document.
    pub canonical: serde_json::Value,
}

/// Canonical validated evidence projection.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceViewV1 {
    /// Storage identity.
    pub id: Uuid,
    /// Parent finding.
    pub finding_id: Uuid,
    /// Source scan.
    pub scan_id: Uuid,
    /// Evidence schema.
    pub evidence_schema: String,
    /// Canonical evidence identity.
    pub evidence_identity: String,
    /// Canonical redacted evidence document.
    pub canonical: serde_json::Value,
}

/// Stable scanner module projection.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleViewV1 {
    /// Stable module ID.
    pub id: String,
    /// Module family.
    pub family: String,
    /// Display name.
    pub name: String,
    /// Behavior description.
    pub description: String,
    /// Application-security domain.
    pub security_domain: String,
    /// Lifecycle stage.
    pub lifecycle_stage: String,
    /// Strongest effect.
    pub strongest_effect: String,
    /// Whether a bounded external process is required.
    pub requires_external_tool: bool,
    /// Required executable, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_tool: Option<String>,
}

/// Stable project report projection.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectReportViewV1 {
    /// Report schema.
    pub schema_version: String,
    /// Project.
    pub project: ProjectViewV1,
    /// Registered target count.
    pub target_count: u32,
    /// Scan count.
    pub scan_count: u32,
    /// Finding count.
    pub finding_count: u32,
    /// Severity counts over validated findings.
    pub severity_counts: std::collections::BTreeMap<String, u32>,
    /// Report generation time.
    pub generated_at: DateTime<Utc>,
}

/// Every successful v1 result shape.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ControlResultV1 {
    /// Complete API self-description.
    Description(ControlApiDescriptionV1),
    /// Resolved run configuration.
    Configuration(ResolvedConfigurationV1),
    /// Current eligible engagement.
    Engagement(EngagementViewV1),
    /// Project page.
    Projects(PageV1<ProjectViewV1>),
    /// One project.
    Project(ProjectViewV1),
    /// Target page.
    Targets(PageV1<TargetViewV1>),
    /// One target.
    Target(TargetViewV1),
    /// Job page.
    Jobs(PageV1<JobViewV1>),
    /// One job.
    Job(JobViewV1),
    /// Finding page.
    Findings(PageV1<FindingViewV1>),
    /// One finding.
    Finding(FindingViewV1),
    /// Evidence page.
    Evidence(PageV1<EvidenceViewV1>),
    /// Module page.
    Modules(PageV1<ModuleViewV1>),
    /// Project report.
    Report(ProjectReportViewV1),
    /// Ordered event replay.
    Events(ControlEventBatchV1),
    /// Boolean mutation or recovery outcome.
    Acknowledged { changed: bool, affected: u32 },
}
