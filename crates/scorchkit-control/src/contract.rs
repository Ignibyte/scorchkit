//! Versioned request, principal, operation, and response envelope.

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
    Ok(())
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
}
