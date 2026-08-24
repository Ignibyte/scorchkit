//! Versioned request, principal, operation, and response envelope.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::configuration::ConfigurationResolutionRequestV1;
use crate::error::{ControlErrorCodeV1, ControlErrorV1};
use crate::resource::ControlResultV1;

/// Stable control request and response schema identity.
pub const CONTROL_API_SCHEMA_V1: &str = "scorchkit.control/v1";
/// Maximum page size accepted by v1.
pub const CONTROL_MAX_PAGE_SIZE: u16 = 200;
/// Maximum opaque cursor bytes.
pub const CONTROL_MAX_CURSOR_BYTES: usize = 512;
/// Maximum evidence, contributor, or facet references in one triage command.
pub const CONTROL_MAX_TRIAGE_REFERENCES: usize = 256;

/// One exact normalized correlation facet supplied to a decision command.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingCorrelationFacetV1 {
    /// Stable facet namespace.
    pub namespace: String,
    /// Exact facet value.
    pub value: String,
}

const fn default_page_limit() -> u16 {
    50
}

/// Bounded page request shared by list queries.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PageRequestV1 {
    /// Opaque continuation cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Requested item count.
    #[serde(default = "default_page_limit")]
    pub limit: u16,
}

impl Default for PageRequestV1 {
    fn default() -> Self {
        Self { cursor: None, limit: default_page_limit() }
    }
}

impl PageRequestV1 {
    /// Validate v1 cursor and page bounds.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid-request or limit error.
    pub fn validate(&self) -> Result<(), ControlErrorV1> {
        if !(1..=CONTROL_MAX_PAGE_SIZE).contains(&self.limit) {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::LimitExceeded,
                "control page limit must be 1-200",
            ));
        }
        if let Some(cursor) = &self.cursor {
            if cursor.is_empty()
                || cursor.len() > CONTROL_MAX_CURSOR_BYTES
                || !cursor.is_ascii()
                || cursor.bytes().any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            {
                return Err(ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "control page cursor is malformed",
                ));
            }
        }
        Ok(())
    }
}

/// Event replay position.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventCursorV1 {
    /// Return events strictly after this sequence.
    pub after_sequence: u64,
    /// Maximum replay values.
    #[serde(default = "default_page_limit")]
    pub limit: u16,
}

impl EventCursorV1 {
    /// Validate the replay page size.
    ///
    /// # Errors
    ///
    /// Returns a limit error outside 1–200.
    pub fn validate(self) -> Result<(), ControlErrorV1> {
        PageRequestV1 { cursor: None, limit: self.limit }.validate()
    }
}

/// Read-only v1 operations.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(tag = "name", content = "params", rename_all = "snake_case")]
pub enum ControlQueryV1 {
    /// Return versioned schema and operation discovery.
    Describe,
    /// Resolve one monotonic run configuration.
    ResolveConfiguration(Box<ConfigurationResolutionRequestV1>),
    /// Return the current engagement projection.
    GetEngagement,
    /// Return credential-safe readiness for every model-analysis role.
    GetModelReadiness,
    /// List projects.
    ListProjects { page: PageRequestV1 },
    /// Read one project.
    GetProject { id: Uuid },
    /// List one project's targets.
    ListTargets { project_id: Uuid, page: PageRequestV1 },
    /// List jobs.
    ListJobs { page: PageRequestV1 },
    /// Read one job.
    GetJob { id: Uuid },
    /// List validated findings.
    ListFindings { project_id: Uuid, page: PageRequestV1 },
    /// Read one validated finding.
    GetFinding { id: Uuid },
    /// List validated evidence for one finding.
    ListEvidence { finding_id: Uuid, page: PageRequestV1 },
    /// List application module descriptors.
    ListModules { family: Option<String>, page: PageRequestV1 },
    /// Build one validated project report.
    GetProjectReport { project_id: Uuid },
    /// Replay ordered job events.
    ReadEvents { cursor: EventCursorV1 },
}

/// State-changing v1 operations.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(tag = "name", content = "params", rename_all = "snake_case")]
pub enum ControlCommandV1 {
    /// Create a project.
    CreateProject { name: String, description: String },
    /// Delete a project and its contained state.
    DeleteProject { id: Uuid },
    /// Add one policy-authorized target.
    AddTarget { project_id: Uuid, url: String, label: String },
    /// Remove one target.
    RemoveTarget { project_id: Uuid, target_id: Uuid },
    /// Queue and start one DAST job.
    StartJob { target: String, profile: String, modules: Option<Vec<String>>, skip: Vec<String> },
    /// Persist and signal cancellation.
    CancelJob { id: Uuid },
    /// Resume one interrupted job.
    ResumeJob { id: Uuid },
    /// Recover abandoned nonterminal jobs.
    RecoverJobs,
    /// Append one canonical finding-triage transition.
    TransitionFinding {
        finding_id: Uuid,
        state: String,
        reason: String,
        evidence_ids: Vec<String>,
        model_analysis_identity: Option<String>,
    },
    /// Append one exact time-bounded finding suppression.
    CreateFindingSuppression {
        finding_id: Uuid,
        scope: String,
        reason: String,
        expires_at: Option<DateTime<Utc>>,
        review_at: Option<DateTime<Utc>>,
    },
    /// Append one evidence-owned finding correlation decision.
    RecordFindingCorrelation {
        finding_id: Uuid,
        contributing_finding_ids: Vec<Uuid>,
        evidence_ids: Vec<String>,
        facets: Vec<FindingCorrelationFacetV1>,
        explanation: String,
    },
}

/// Tagged command or query.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(tag = "class", content = "operation", rename_all = "snake_case")]
pub enum ControlOperationV1 {
    /// Read-only query.
    Query(Box<ControlQueryV1>),
    /// State-changing command.
    Command(ControlCommandV1),
}

/// One v1 request envelope.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlRequestV1 {
    /// Exact request schema.
    pub schema_version: String,
    /// Caller-generated correlation identity.
    pub request_id: Uuid,
    /// Expected immutable active engagement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engagement_id: Option<Uuid>,
    /// Requested operation.
    pub operation: ControlOperationV1,
}

impl ControlRequestV1 {
    /// Create a query request.
    #[must_use]
    pub fn query(query: ControlQueryV1, engagement_id: Option<Uuid>) -> Self {
        Self {
            schema_version: CONTROL_API_SCHEMA_V1.to_string(),
            request_id: Uuid::new_v4(),
            engagement_id,
            operation: ControlOperationV1::Query(Box::new(query)),
        }
    }

    /// Create a command request.
    #[must_use]
    pub fn command(command: ControlCommandV1, engagement_id: Uuid) -> Self {
        Self {
            schema_version: CONTROL_API_SCHEMA_V1.to_string(),
            request_id: Uuid::new_v4(),
            engagement_id: Some(engagement_id),
            operation: ControlOperationV1::Command(command),
        }
    }

    /// Validate the envelope and operation-local page bounds.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error without executing the request.
    pub fn validate(&self) -> Result<(), ControlErrorV1> {
        if self.schema_version != CONTROL_API_SCHEMA_V1 {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::UnsupportedSchema,
                "unsupported control API schema",
            ));
        }
        if matches!(self.operation, ControlOperationV1::Command(_)) && self.engagement_id.is_none()
        {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                "control commands require an explicit engagement binding",
            ));
        }
        match &self.operation {
            ControlOperationV1::Query(query) => validate_query(query),
            ControlOperationV1::Command(command) => validate_command(command),
        }
    }
}

fn validate_query(query: &ControlQueryV1) -> Result<(), ControlErrorV1> {
    match query {
        ControlQueryV1::ListProjects { page }
        | ControlQueryV1::ListJobs { page }
        | ControlQueryV1::ListTargets { page, .. }
        | ControlQueryV1::ListFindings { page, .. }
        | ControlQueryV1::ListEvidence { page, .. }
        | ControlQueryV1::ListModules { page, .. } => page.validate(),
        ControlQueryV1::ReadEvents { cursor } => cursor.validate(),
        ControlQueryV1::Describe
        | ControlQueryV1::ResolveConfiguration(..)
        | ControlQueryV1::GetEngagement
        | ControlQueryV1::GetModelReadiness
        | ControlQueryV1::GetProject { .. }
        | ControlQueryV1::GetJob { .. }
        | ControlQueryV1::GetFinding { .. }
        | ControlQueryV1::GetProjectReport { .. } => Ok(()),
    }
}

fn validate_command(command: &ControlCommandV1) -> Result<(), ControlErrorV1> {
    let values: &[(&str, &str, usize)] = match command {
        ControlCommandV1::CreateProject { name, description } => {
            &[("project name", name, 200), ("project description", description, 4_096)]
        }
        ControlCommandV1::AddTarget { url, label, .. } => {
            &[("target URL", url, 4_096), ("target label", label, 512)]
        }
        ControlCommandV1::StartJob { target, profile, .. } => {
            &[("job target", target, 4_096), ("job profile", profile, 64)]
        }
        ControlCommandV1::TransitionFinding { state, reason, .. } => {
            &[("triage state", state, 64), ("triage reason", reason, 4_096)]
        }
        ControlCommandV1::CreateFindingSuppression { scope, reason, .. } => {
            &[("suppression scope", scope, 64), ("suppression reason", reason, 4_096)]
        }
        ControlCommandV1::RecordFindingCorrelation { explanation, .. } => {
            &[("correlation explanation", explanation, 4_096)]
        }
        ControlCommandV1::DeleteProject { .. }
        | ControlCommandV1::RemoveTarget { .. }
        | ControlCommandV1::CancelJob { .. }
        | ControlCommandV1::ResumeJob { .. }
        | ControlCommandV1::RecoverJobs => &[],
    };
    for (label, value, maximum) in values {
        let may_be_empty = matches!(*label, "project description" | "target label");
        if (!may_be_empty && value.is_empty())
            || value.len() > *maximum
            || value.trim() != *value
            || value.chars().any(char::is_control)
        {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                format!("{label} is empty, oversized, padded, or contains controls"),
            ));
        }
    }
    if let ControlCommandV1::StartJob { modules, skip, .. } = command {
        validate_selectors(modules.as_deref(), skip)?;
    }
    match command {
        ControlCommandV1::TransitionFinding { evidence_ids, model_analysis_identity, .. } => {
            validate_digest_references(evidence_ids)?;
            if model_analysis_identity.as_ref().is_some_and(|identity| !is_digest(identity)) {
                return Err(invalid_triage_reference());
            }
        }
        ControlCommandV1::RecordFindingCorrelation {
            finding_id,
            contributing_finding_ids,
            evidence_ids,
            facets,
            ..
        } => validate_correlation_command(
            finding_id,
            contributing_finding_ids,
            evidence_ids,
            facets,
        )?,
        ControlCommandV1::CreateFindingSuppression { expires_at, review_at, .. }
            if expires_at.is_none() && review_at.is_none() =>
        {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                "finding suppression requires an expiry or review boundary",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn validate_correlation_command(
    finding_id: &Uuid,
    contributing_finding_ids: &[Uuid],
    evidence_ids: &[String],
    facets: &[FindingCorrelationFacetV1],
) -> Result<(), ControlErrorV1> {
    let unique_facets: std::collections::BTreeSet<_> =
        facets.iter().map(|facet| (facet.namespace.as_str(), facet.value.as_str())).collect();
    if contributing_finding_ids.is_empty()
        || contributing_finding_ids.len() > CONTROL_MAX_TRIAGE_REFERENCES
        || !contributing_finding_ids.contains(finding_id)
        || contributing_finding_ids.iter().collect::<std::collections::BTreeSet<_>>().len()
            != contributing_finding_ids.len()
        || facets.len() > CONTROL_MAX_TRIAGE_REFERENCES
        || unique_facets.len() != facets.len()
        || evidence_ids.is_empty()
    {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::InvalidRequest,
            "correlation contributors and facets must be unique bounded inputs",
        ));
    }
    validate_digest_references(evidence_ids)?;
    for facet in facets {
        if facet.namespace.is_empty()
            || facet.namespace.len() > 512
            || facet.namespace.trim() != facet.namespace
            || facet.namespace.chars().any(char::is_control)
            || facet.value.is_empty()
            || facet.value.len() > 512
            || facet.value.trim() != facet.value
            || facet.value.chars().any(char::is_control)
        {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                "correlation facets must contain bounded canonical values",
            ));
        }
    }
    Ok(())
}

fn validate_digest_references(values: &[String]) -> Result<(), ControlErrorV1> {
    if values.len() > CONTROL_MAX_TRIAGE_REFERENCES
        || values.iter().collect::<std::collections::BTreeSet<_>>().len() != values.len()
        || values.iter().any(|value| !is_digest(value))
    {
        return Err(invalid_triage_reference());
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn invalid_triage_reference() -> ControlErrorV1 {
    ControlErrorV1::new(
        ControlErrorCodeV1::InvalidRequest,
        "triage references must be unique lowercase SHA-256 identities",
    )
}

fn validate_selectors(modules: Option<&[String]>, skip: &[String]) -> Result<(), ControlErrorV1> {
    for values in [modules.unwrap_or_default(), skip] {
        if values.len() > 256 {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::LimitExceeded,
                "job module selector exceeds 256 entries",
            ));
        }
        let mut unique = std::collections::BTreeSet::new();
        for value in values {
            if value.is_empty()
                || value.len() > 256
                || value.trim() != value
                || value.chars().any(char::is_control)
                || !unique.insert(value)
            {
                return Err(ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "job module selectors must be unique bounded identifiers",
                ));
            }
        }
    }
    Ok(())
}

/// Transport-established principal kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPrincipalKindV1 {
    /// Same-process library or CLI/MCP adapter.
    LocalProcess,
    /// Explicit bearer-authenticated loopback HTTP caller.
    AuthenticatedBearer,
}

/// Safe principal projection. This type reports identity; constructing it does not establish it.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlPrincipalV1 {
    /// Authentication mechanism.
    pub kind: ControlPrincipalKindV1,
    /// Transport-owned subject.
    pub subject: String,
    /// Exact engagement selected by transport composition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engagement_id: Option<Uuid>,
}

/// Successful or failed response outcome.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "value", rename_all = "snake_case")]
pub enum ControlResponseOutcomeV1 {
    /// Successful result.
    Success(Box<ControlResultV1>),
    /// Typed safe failure.
    Error(ControlErrorV1),
}

/// One v1 response envelope.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlResponseV1 {
    /// Exact response schema.
    pub schema_version: String,
    /// Correlated request ID.
    pub request_id: Uuid,
    /// Transport-established caller projection.
    pub principal: ControlPrincipalV1,
    /// Operation result.
    pub result: ControlResponseOutcomeV1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_bounds_and_cursor_shape_are_exact() {
        assert!(PageRequestV1 { cursor: None, limit: 1 }.validate().is_ok());
        assert!(PageRequestV1 { cursor: None, limit: CONTROL_MAX_PAGE_SIZE }.validate().is_ok());
        for limit in [0, CONTROL_MAX_PAGE_SIZE + 1] {
            assert_eq!(
                PageRequestV1 { cursor: None, limit }.validate().expect_err("limit").code,
                ControlErrorCodeV1::LimitExceeded
            );
        }
        for cursor in ["", "has space", "has\ncontrol"] {
            assert_eq!(
                PageRequestV1 { cursor: Some(cursor.to_string()), limit: 1 }
                    .validate()
                    .expect_err("cursor")
                    .code,
                ControlErrorCodeV1::InvalidRequest
            );
        }
    }

    #[test]
    fn request_validation_dispatches_to_query_validation() {
        let request = ControlRequestV1::query(
            ControlQueryV1::ListProjects { page: PageRequestV1 { cursor: None, limit: 0 } },
            None,
        );
        assert_eq!(
            request.validate().expect_err("query page limit").code,
            ControlErrorCodeV1::LimitExceeded
        );
    }

    #[test]
    fn schema_version_and_command_identifiers_fail_before_dispatch() {
        let mut request = ControlRequestV1::query(ControlQueryV1::Describe, None);
        request.schema_version = "future".to_string();
        assert_eq!(
            request.validate().expect_err("schema").code,
            ControlErrorCodeV1::UnsupportedSchema
        );

        let mut missing_engagement =
            ControlRequestV1::command(ControlCommandV1::RecoverJobs, Uuid::new_v4());
        missing_engagement.engagement_id = None;
        assert_eq!(
            missing_engagement.validate().expect_err("engagement binding").code,
            ControlErrorCodeV1::InvalidRequest
        );

        let request = ControlRequestV1::command(
            ControlCommandV1::CreateProject {
                name: "bad\nname".to_string(),
                description: String::new(),
            },
            Uuid::new_v4(),
        );
        assert_eq!(
            request.validate().expect_err("control").code,
            ControlErrorCodeV1::InvalidRequest
        );
    }

    #[test]
    fn selector_duplicates_and_limits_are_rejected() {
        let engagement = Uuid::new_v4();
        let duplicate = ControlRequestV1::command(
            ControlCommandV1::StartJob {
                target: "https://example.test/".to_string(),
                profile: "quick".to_string(),
                modules: Some(vec!["headers".to_string(), "headers".to_string()]),
                skip: Vec::new(),
            },
            engagement,
        );
        assert_eq!(
            duplicate.validate().expect_err("duplicates").code,
            ControlErrorCodeV1::InvalidRequest
        );
    }

    #[test]
    fn triage_command_references_facets_and_time_shapes_are_exact() {
        let engagement = Uuid::new_v4();
        let finding = Uuid::new_v4();
        let digest = "a".repeat(64);
        let valid = ControlRequestV1::command(
            ControlCommandV1::TransitionFinding {
                finding_id: finding,
                state: "validated".to_string(),
                reason: "Exact evidence".to_string(),
                evidence_ids: vec![digest.clone()],
                model_analysis_identity: Some("b".repeat(64)),
            },
            engagement,
        );
        valid.validate().expect("valid triage command");

        for references in [vec!["A".repeat(64)], vec![digest.clone(), digest.clone()]] {
            let invalid = ControlRequestV1::command(
                ControlCommandV1::TransitionFinding {
                    finding_id: finding,
                    state: "validated".to_string(),
                    reason: "Exact evidence".to_string(),
                    evidence_ids: references,
                    model_analysis_identity: None,
                },
                engagement,
            );
            assert_eq!(
                invalid.validate().expect_err("invalid reference").code,
                ControlErrorCodeV1::InvalidRequest
            );
        }

        let no_boundary = ControlRequestV1::command(
            ControlCommandV1::CreateFindingSuppression {
                finding_id: finding,
                scope: "finding".to_string(),
                reason: "Temporary exception".to_string(),
                expires_at: None,
                review_at: None,
            },
            engagement,
        );
        assert_eq!(
            no_boundary.validate().expect_err("suppression boundary").code,
            ControlErrorCodeV1::InvalidRequest
        );

        let duplicate_facet = FindingCorrelationFacetV1 {
            namespace: "route".to_string(),
            value: "/fixture".to_string(),
        };
        for (contributors, evidence, facets) in [
            (Vec::new(), vec![digest.clone()], vec![duplicate_facet.clone()]),
            (vec![Uuid::new_v4()], vec![digest.clone()], vec![duplicate_facet.clone()]),
            (vec![finding], Vec::new(), vec![duplicate_facet.clone()]),
            (vec![finding], vec![digest], vec![duplicate_facet.clone(), duplicate_facet]),
        ] {
            let invalid = ControlRequestV1::command(
                ControlCommandV1::RecordFindingCorrelation {
                    finding_id: finding,
                    contributing_finding_ids: contributors,
                    evidence_ids: evidence,
                    facets,
                    explanation: "Exact relation".to_string(),
                },
                engagement,
            );
            assert_eq!(
                invalid.validate().expect_err("invalid correlation shape").code,
                ControlErrorCodeV1::InvalidRequest
            );
        }
    }

    #[test]
    fn correlation_command_shape_clauses_are_independently_enforced() {
        let parent = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        let evidence = vec!["a".repeat(64)];
        let facet = FindingCorrelationFacetV1 {
            namespace: "route".to_string(),
            value: "/fixture".to_string(),
        };
        let invalid =
            |contributors: &[Uuid], evidence: &[String], facets: &[FindingCorrelationFacetV1]| {
                assert_eq!(
                    validate_correlation_command(&parent, contributors, evidence, facets)
                        .expect_err("invalid correlation command")
                        .code,
                    ControlErrorCodeV1::InvalidRequest
                );
            };

        validate_correlation_command(
            &parent,
            &[parent, other],
            &evidence,
            std::slice::from_ref(&facet),
        )
        .expect("valid correlation command");
        invalid(&[], &evidence, std::slice::from_ref(&facet));
        invalid(&[other], &evidence, std::slice::from_ref(&facet));
        invalid(&[parent, parent], &evidence, std::slice::from_ref(&facet));
        invalid(&[parent, other], &[], std::slice::from_ref(&facet));
        invalid(&[parent, other], &evidence, &[facet.clone(), facet]);

        let contributors: Vec<_> = (1..=CONTROL_MAX_TRIAGE_REFERENCES)
            .map(|value| Uuid::from_u128(u128::try_from(value).expect("reference index fits u128")))
            .collect();
        validate_correlation_command(&parent, &contributors, &evidence, &[])
            .expect("exact contributor limit");
        let mut overflow = contributors;
        overflow.push(Uuid::from_u128(
            u128::try_from(CONTROL_MAX_TRIAGE_REFERENCES + 1).expect("overflow index fits u128"),
        ));
        invalid(&overflow, &evidence, &[]);

        let facets: Vec<_> = (0..CONTROL_MAX_TRIAGE_REFERENCES)
            .map(|index| FindingCorrelationFacetV1 {
                namespace: "fixture".to_string(),
                value: format!("value-{index:04}"),
            })
            .collect();
        validate_correlation_command(&parent, &[parent, other], &evidence, &facets)
            .expect("exact facet limit");
        let mut overflow = facets;
        overflow.push(FindingCorrelationFacetV1 {
            namespace: "fixture".to_string(),
            value: "overflow".to_string(),
        });
        invalid(&[parent, other], &evidence, &overflow);
    }

    #[test]
    fn correlation_facet_values_enforce_each_canonical_boundary() {
        let parent = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        let evidence = vec!["a".repeat(64)];
        let validate = |namespace: String, value: String| {
            validate_correlation_command(
                &parent,
                &[parent, other],
                &evidence,
                &[FindingCorrelationFacetV1 { namespace, value }],
            )
        };

        validate("a".repeat(512), "b".repeat(512)).expect("exact facet string limits");
        for (namespace, value) in [
            (String::new(), "value".to_string()),
            ("a".repeat(513), "value".to_string()),
            (" padded".to_string(), "value".to_string()),
            ("bad\nnamespace".to_string(), "value".to_string()),
            ("namespace".to_string(), String::new()),
            ("namespace".to_string(), "b".repeat(513)),
            ("namespace".to_string(), "padded ".to_string()),
            ("namespace".to_string(), "bad\nvalue".to_string()),
        ] {
            assert_eq!(
                validate(namespace, value).expect_err("invalid facet value").code,
                ControlErrorCodeV1::InvalidRequest
            );
        }
    }

    #[test]
    fn digest_reference_count_accepts_the_limit_and_rejects_one_more() {
        let exact: Vec<_> =
            (0..CONTROL_MAX_TRIAGE_REFERENCES).map(|index| format!("{index:064x}")).collect();
        validate_digest_references(&exact).expect("exact digest-reference limit");
        let mut overflow = exact;
        overflow.push(format!("{CONTROL_MAX_TRIAGE_REFERENCES:064x}"));
        assert_eq!(
            validate_digest_references(&overflow).expect_err("digest-reference overflow").code,
            ControlErrorCodeV1::InvalidRequest
        );
    }
}
