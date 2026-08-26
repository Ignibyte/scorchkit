//! Provider-neutral team-service wire, RBAC, object, audit, and recovery contracts.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ControlCommandV1, ControlOperationV1, ControlQueryV1, ControlResponseOutcomeV1};

/// Exact team-service schema version.
pub const TEAM_API_SCHEMA_V1: &str = "scorchkit.team.v1";
/// Exact encrypted-object envelope version.
pub const TEAM_OBJECT_SCHEMA_V1: &str = "scorchkit.team.object.v1";
/// Exact recovery-manifest version.
pub const TEAM_RECOVERY_SCHEMA_V1: &str = "scorchkit.team.recovery.v1";

/// One deployment role. Roles are a pre-dispatch narrowing layer, not an engagement grant.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, JsonSchema, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TeamRoleV1 {
    /// Read canonical control data, events, and team objects.
    Reader,
    /// Reader plus finding triage, suppression, and correlation.
    Analyst,
    /// Analyst plus registered-target and job lifecycle operations and object writes.
    Operator,
    /// Operator plus team audit, retention, key-rotation, and recovery administration.
    Administrator,
}

/// Team-only operations outside the existing control contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeamPermissionV1 {
    /// Read an encrypted team object as authenticated plaintext.
    ReadObject,
    /// Write one encrypted team object.
    WriteObject,
    /// Read the cell audit stream.
    ReadAudit,
    /// Expire retained objects.
    ApplyRetention,
    /// Re-encrypt an object with the configured write key.
    RotateObjectKey,
    /// Inspect or verify recovery evidence.
    VerifyRecovery,
}

impl TeamRoleV1 {
    /// Decide whether this role may submit one control operation.
    ///
    /// Project lifecycle is deliberately unavailable through the team transport because the
    /// deployment cell binds one pre-provisioned project identity.
    #[must_use]
    pub const fn allows_control(self, operation: &ControlOperationV1) -> bool {
        match operation {
            ControlOperationV1::Query(query) => Self::allows_query(query),
            ControlOperationV1::Command(command) => self.allows_command(command),
        }
    }

    const fn allows_query(query: &ControlQueryV1) -> bool {
        match query {
            ControlQueryV1::Describe
            | ControlQueryV1::ResolveConfiguration(_)
            | ControlQueryV1::GetEngagement
            | ControlQueryV1::GetModelReadiness
            | ControlQueryV1::ListProjects { .. }
            | ControlQueryV1::GetProject { .. }
            | ControlQueryV1::ListTargets { .. }
            | ControlQueryV1::ListJobs { .. }
            | ControlQueryV1::GetJob { .. }
            | ControlQueryV1::ListFindings { .. }
            | ControlQueryV1::GetFinding { .. }
            | ControlQueryV1::ListEvidence { .. }
            | ControlQueryV1::ListModules { .. }
            | ControlQueryV1::GetProjectReport { .. }
            | ControlQueryV1::ReadEvents { .. } => true,
        }
    }

    const fn allows_command(self, command: &ControlCommandV1) -> bool {
        match command {
            ControlCommandV1::CreateProject { .. } | ControlCommandV1::DeleteProject { .. } => {
                false
            }
            ControlCommandV1::TransitionFinding { .. }
            | ControlCommandV1::CreateFindingSuppression { .. }
            | ControlCommandV1::RecordFindingCorrelation { .. } => {
                matches!(self, Self::Analyst | Self::Operator | Self::Administrator)
            }
            ControlCommandV1::AddTarget { .. }
            | ControlCommandV1::RemoveTarget { .. }
            | ControlCommandV1::StartJob { .. }
            | ControlCommandV1::CancelJob { .. }
            | ControlCommandV1::ResumeJob { .. }
            | ControlCommandV1::RecoverJobs => {
                matches!(self, Self::Operator | Self::Administrator)
            }
        }
    }

    /// Decide whether this role may perform one team-only operation.
    #[must_use]
    pub const fn allows_team(self, permission: TeamPermissionV1) -> bool {
        match permission {
            TeamPermissionV1::ReadObject => true,
            TeamPermissionV1::WriteObject => {
                matches!(self, Self::Operator | Self::Administrator)
            }
            TeamPermissionV1::ReadAudit
            | TeamPermissionV1::ApplyRetention
            | TeamPermissionV1::RotateObjectKey
            | TeamPermissionV1::VerifyRecovery => matches!(self, Self::Administrator),
        }
    }
}

/// Safe authenticated team-principal projection.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamPrincipalV1 {
    /// Transport-established stable subject.
    pub subject: String,
    /// Server-configured organization identifier.
    pub organization_id: String,
    /// Server-configured deployment project UUID.
    pub project_id: Uuid,
    /// Server-configured cell identifier.
    pub cell_id: String,
    /// Server-configured role.
    pub role: TeamRoleV1,
    /// Exact engagement selected with the cell.
    pub engagement_id: Uuid,
}

/// Team wrapper around an existing control outcome.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamControlResponseV1 {
    /// Exact team API schema.
    pub schema_version: String,
    /// Correlated control request identity.
    pub request_id: Uuid,
    /// Transport-established team principal.
    pub principal: TeamPrincipalV1,
    /// Existing control application-service outcome.
    pub result: ControlResponseOutcomeV1,
}

/// Stored object categories with distinct retention meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamObjectKindV1 {
    /// Immutable scanner or imported evidence bytes.
    Evidence,
    /// Generated report bytes.
    Report,
    /// Digest-bound extension or extension-produced artifact bytes.
    ExtensionArtifact,
}

/// Credential-safe encrypted-object projection.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamObjectViewV1 {
    /// Lowercase SHA-256 identity of the plaintext.
    pub object_id: String,
    /// Object category.
    pub kind: TeamObjectKindV1,
    /// Plaintext byte count.
    pub plaintext_bytes: u64,
    /// Identifier of the encryption key, never its value.
    pub key_id: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Mandatory expiry time.
    pub expires_at: DateTime<Utc>,
}

/// Durable audit outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamAuditOutcomeV1 {
    /// Mutation intent persisted before dispatch.
    Pending,
    /// Operation completed successfully.
    Succeeded,
    /// Operation was denied before the protected effect.
    Denied,
    /// Operation failed or its integrity could not be established.
    Failed,
    /// A pending intent survived without a terminal record.
    OutcomeUnknown,
}

/// Credential-safe team audit projection.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamAuditEventV1 {
    /// Cell-local monotonic sequence.
    pub sequence: u64,
    /// Request or administrative operation identity.
    pub request_id: Uuid,
    /// Server-configured cell identity at admission.
    pub cell_id: String,
    /// Server-configured organization identity at admission.
    pub organization_id: String,
    /// Server-configured project identity at admission.
    pub project_id: Uuid,
    /// Exact engagement identity at admission.
    pub engagement_id: Uuid,
    /// Transport-established subject.
    pub subject: String,
    /// Bound role.
    pub role: TeamRoleV1,
    /// Stable bounded action identifier.
    pub action: String,
    /// Terminal or pending outcome.
    pub outcome: TeamAuditOutcomeV1,
    /// Event time.
    pub occurred_at: DateTime<Utc>,
}

/// One encrypted object included in a recovery manifest.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamRecoveryObjectV1 {
    /// Plaintext content identity.
    pub object_id: String,
    /// Digest of the exact stored ciphertext envelope.
    pub ciphertext_sha256: String,
    /// Stored ciphertext-envelope byte count.
    pub stored_bytes: u64,
    /// Non-secret key identifier needed for recovery.
    pub key_id: String,
}

/// Versioned recovery evidence. It contains no database URL, bearer, key, or plaintext object.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamRecoveryManifestV1 {
    /// Exact recovery schema.
    pub schema_version: String,
    /// Cell identity.
    pub cell_id: String,
    /// Organization identity.
    pub organization_id: String,
    /// Project identity.
    pub project_id: Uuid,
    /// Engagement identity.
    pub engagement_id: Uuid,
    /// Credential-safe source database identity digest.
    pub database_identity_sha256: String,
    /// Exact migration versions present at snapshot time.
    pub migration_versions: Vec<i64>,
    /// Digest of the database snapshot bytes.
    pub database_snapshot_sha256: String,
    /// Database snapshot byte count.
    pub database_snapshot_bytes: u64,
    /// Sorted encrypted object inventory.
    pub objects: Vec<TeamRecoveryObjectV1>,
    /// Sorted key identifiers required by the inventory.
    pub required_key_ids: Vec<String>,
    /// Snapshot creation time.
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConfigurationResolutionRequestV1, ControlBudgetsV1, EventCursorV1, PageRequestV1,
        ResolutionCeilingV1,
    };

    fn page() -> PageRequestV1 {
        PageRequestV1 { cursor: None, limit: 1 }
    }

    #[test]
    fn role_matrix_is_exact_for_every_control_operation() {
        let queries = [
            ControlQueryV1::Describe,
            ControlQueryV1::ResolveConfiguration(Box::new(ConfigurationResolutionRequestV1 {
                ceiling: ResolutionCeilingV1 {
                    targets: Vec::new(),
                    capabilities: Vec::new(),
                    effects: Vec::new(),
                    modules: Vec::new(),
                    budgets: ControlBudgetsV1 {
                        timeout_seconds: 1,
                        max_concurrent_modules: 1,
                        max_result_bytes: 1,
                        max_event_bytes: 1,
                    },
                },
                organization: None,
                project: None,
                run: None,
            })),
            ControlQueryV1::GetEngagement,
            ControlQueryV1::GetModelReadiness,
            ControlQueryV1::ListProjects { page: page() },
            ControlQueryV1::GetProject { id: Uuid::nil() },
            ControlQueryV1::ListTargets { project_id: Uuid::nil(), page: page() },
            ControlQueryV1::ListJobs { page: page() },
            ControlQueryV1::GetJob { id: Uuid::nil() },
            ControlQueryV1::ListFindings { project_id: Uuid::nil(), page: page() },
            ControlQueryV1::GetFinding { id: Uuid::nil() },
            ControlQueryV1::ListEvidence { finding_id: Uuid::nil(), page: page() },
            ControlQueryV1::ListModules { family: None, page: page() },
            ControlQueryV1::GetProjectReport { project_id: Uuid::nil() },
            ControlQueryV1::ReadEvents { cursor: EventCursorV1 { after_sequence: 0, limit: 1 } },
        ];
        for query in queries {
            assert!(TeamRoleV1::Reader.allows_control(&ControlOperationV1::Query(Box::new(query))));
        }

        let project_lifecycle = [
            ControlCommandV1::CreateProject { name: "x".into(), description: String::new() },
            ControlCommandV1::DeleteProject { id: Uuid::nil() },
        ];
        for command in project_lifecycle {
            for role in [
                TeamRoleV1::Reader,
                TeamRoleV1::Analyst,
                TeamRoleV1::Operator,
                TeamRoleV1::Administrator,
            ] {
                assert!(!role.allows_control(&ControlOperationV1::Command(command.clone())));
            }
        }
    }

    #[test]
    fn analyst_and_operator_command_tiers_are_exact() {
        let analyst_commands = [
            ControlCommandV1::TransitionFinding {
                finding_id: Uuid::nil(),
                state: "validated".into(),
                reason: "reason".into(),
                evidence_ids: Vec::new(),
                model_analysis_identity: None,
            },
            ControlCommandV1::CreateFindingSuppression {
                finding_id: Uuid::nil(),
                scope: "finding".into(),
                reason: "reason".into(),
                expires_at: None,
                review_at: None,
            },
            ControlCommandV1::RecordFindingCorrelation {
                finding_id: Uuid::nil(),
                contributing_finding_ids: Vec::new(),
                evidence_ids: Vec::new(),
                facets: Vec::new(),
                explanation: "reason".into(),
            },
        ];
        for command in analyst_commands {
            let operation = ControlOperationV1::Command(command);
            assert!(!TeamRoleV1::Reader.allows_control(&operation));
            assert!(TeamRoleV1::Analyst.allows_control(&operation));
            assert!(TeamRoleV1::Operator.allows_control(&operation));
            assert!(TeamRoleV1::Administrator.allows_control(&operation));
        }

        let operator_commands = [
            ControlCommandV1::AddTarget {
                project_id: Uuid::nil(),
                url: "https://example.test/".into(),
                label: String::new(),
            },
            ControlCommandV1::RemoveTarget { project_id: Uuid::nil(), target_id: Uuid::nil() },
            ControlCommandV1::StartJob {
                target: "https://example.test/".into(),
                profile: "quick".into(),
                modules: None,
                skip: Vec::new(),
            },
            ControlCommandV1::CancelJob { id: Uuid::nil() },
            ControlCommandV1::ResumeJob { id: Uuid::nil() },
            ControlCommandV1::RecoverJobs,
        ];
        for command in operator_commands {
            let operation = ControlOperationV1::Command(command);
            assert!(!TeamRoleV1::Reader.allows_control(&operation));
            assert!(!TeamRoleV1::Analyst.allows_control(&operation));
            assert!(TeamRoleV1::Operator.allows_control(&operation));
            assert!(TeamRoleV1::Administrator.allows_control(&operation));
        }
    }

    #[test]
    fn team_only_permissions_do_not_infer_administration() {
        assert!(TeamRoleV1::Reader.allows_team(TeamPermissionV1::ReadObject));
        assert!(!TeamRoleV1::Reader.allows_team(TeamPermissionV1::WriteObject));
        assert!(TeamRoleV1::Operator.allows_team(TeamPermissionV1::WriteObject));
        assert!(!TeamRoleV1::Operator.allows_team(TeamPermissionV1::ReadAudit));
        assert!(TeamRoleV1::Administrator.allows_team(TeamPermissionV1::VerifyRecovery));
    }

    #[test]
    fn readable_queries_remain_an_explicit_exhaustive_review_list() {
        let source = include_str!("team.rs");
        let start = source.find("const fn allows_query").expect("query policy");
        let end = source[start..]
            .find("const fn allows_command")
            .map(|offset| start + offset)
            .expect("command policy");
        let query_policy = &source[start..end];

        for variant in [
            "Describe",
            "ResolveConfiguration",
            "GetEngagement",
            "GetModelReadiness",
            "ListProjects",
            "GetProject",
            "ListTargets",
            "ListJobs",
            "GetJob",
            "ListFindings",
            "GetFinding",
            "ListEvidence",
            "ListModules",
            "GetProjectReport",
            "ReadEvents",
        ] {
            assert!(
                query_policy.contains(&format!("ControlQueryV1::{variant}")),
                "{variant} must remain explicitly reviewed by the team RBAC policy"
            );
        }
        assert!(query_policy.contains("match query"));
    }
}
