//! Runtime self-description generated from the package-owned v1 types.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::configuration::{ConfigPatchV1, ResolutionCeilingV1, ResolvedConfigurationV1};
use crate::contract::{
    ControlCommandV1, ControlQueryV1, ControlRequestV1, ControlResponseV1, CONTROL_API_SCHEMA_V1,
};
use crate::error::{ControlErrorCodeV1, ControlErrorV1};
use crate::event::{ControlEventV1, CONTROL_EVENT_SCHEMA_V1};
use crate::resource::{ControlResultV1, ModelReadinessViewV1, ModuleViewV1};

/// Stable self-description schema.
pub const CONTROL_DESCRIPTION_SCHEMA_V1: &str = "scorchkit.control.description/v1";

/// One operation in the exact v1 inventory.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlOperationDescriptionV1 {
    /// Stable operation name.
    pub name: String,
    /// `query` or `command`.
    pub class: String,
    /// Strongest behavior class.
    pub behavior: String,
    /// Whether an exact engagement binding is required.
    pub engagement_required: bool,
}

/// One named JSON Schema document.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlSchemaDescriptionV1 {
    /// Stable schema role.
    pub name: String,
    /// Generated JSON Schema.
    pub schema: serde_json::Value,
}

/// Complete v1 self-description.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlApiDescriptionV1 {
    /// Self-description schema.
    pub schema_version: String,
    /// Request/result API schema.
    pub api_schema_version: String,
    /// Event schema.
    pub event_schema_version: String,
    /// Exact sorted operation inventory.
    pub operations: Vec<ControlOperationDescriptionV1>,
    /// Generated public schemas.
    pub schemas: Vec<ControlSchemaDescriptionV1>,
}

/// Generate the complete v1 self-description.
///
/// # Errors
///
/// Returns an internal typed error if a generated schema cannot be serialized.
pub fn description_v1() -> Result<ControlApiDescriptionV1, ControlErrorV1> {
    let mut schemas = Vec::new();
    push_schema::<ControlRequestV1>(&mut schemas, "request")?;
    push_schema::<ControlResponseV1>(&mut schemas, "response")?;
    push_schema::<ControlQueryV1>(&mut schemas, "query")?;
    push_schema::<ControlCommandV1>(&mut schemas, "command")?;
    push_schema::<ControlResultV1>(&mut schemas, "result")?;
    push_schema::<ControlErrorV1>(&mut schemas, "error")?;
    push_schema::<ControlErrorCodeV1>(&mut schemas, "error_code")?;
    push_schema::<ControlEventV1>(&mut schemas, "event")?;
    push_schema::<ResolutionCeilingV1>(&mut schemas, "configuration_ceiling")?;
    push_schema::<ConfigPatchV1>(&mut schemas, "configuration_patch")?;
    push_schema::<ResolvedConfigurationV1>(&mut schemas, "configuration_result")?;
    push_schema::<ModuleViewV1>(&mut schemas, "module")?;
    push_schema::<ModelReadinessViewV1>(&mut schemas, "model_readiness")?;
    Ok(ControlApiDescriptionV1 {
        schema_version: CONTROL_DESCRIPTION_SCHEMA_V1.to_string(),
        api_schema_version: CONTROL_API_SCHEMA_V1.to_string(),
        event_schema_version: CONTROL_EVENT_SCHEMA_V1.to_string(),
        operations: operation_inventory(),
        schemas,
    })
}

fn push_schema<T: JsonSchema>(
    schemas: &mut Vec<ControlSchemaDescriptionV1>,
    name: &str,
) -> Result<(), ControlErrorV1> {
    let schema = serde_json::to_value(schemars::schema_for!(T)).map_err(|_| {
        ControlErrorV1::new(
            crate::error::ControlErrorCodeV1::Internal,
            "failed to serialize a generated control schema",
        )
    })?;
    schemas.push(ControlSchemaDescriptionV1 { name: name.to_string(), schema });
    Ok(())
}

fn operation_inventory() -> Vec<ControlOperationDescriptionV1> {
    const OPERATIONS: &[(&str, &str, &str, bool)] = &[
        ("add_target", "command", "local_state", true),
        ("cancel_job", "command", "local_state", true),
        ("create_project", "command", "local_state", true),
        ("delete_project", "command", "local_state", true),
        ("describe", "query", "read", false),
        ("get_engagement", "query", "read", false),
        ("get_finding", "query", "read", false),
        ("get_job", "query", "read", false),
        ("get_model_readiness", "query", "read", false),
        ("get_project", "query", "read", false),
        ("get_project_report", "query", "read", false),
        ("list_evidence", "query", "read", false),
        ("list_findings", "query", "read", false),
        ("list_jobs", "query", "read", false),
        ("list_modules", "query", "read", false),
        ("list_projects", "query", "read", false),
        ("list_targets", "query", "read", false),
        ("read_events", "query", "read", false),
        ("recover_jobs", "command", "local_state", true),
        ("remove_target", "command", "local_state", true),
        ("resolve_configuration", "query", "read", true),
        ("resume_job", "command", "external_effect", true),
        ("start_job", "command", "external_effect", true),
    ];
    OPERATIONS
        .iter()
        .map(|(name, class, behavior, engagement_required)| ControlOperationDescriptionV1 {
            name: (*name).to_string(),
            class: (*class).to_string(),
            behavior: (*behavior).to_string(),
            engagement_required: *engagement_required,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_versions_and_inventory_are_exact_sorted_and_unique() {
        let description = description_v1().expect("description");
        assert_eq!(description.schema_version, CONTROL_DESCRIPTION_SCHEMA_V1);
        assert_eq!(description.api_schema_version, CONTROL_API_SCHEMA_V1);
        assert_eq!(description.event_schema_version, CONTROL_EVENT_SCHEMA_V1);
        assert_eq!(description.operations.len(), 23);
        assert!(description.operations.windows(2).all(|pair| pair[0].name < pair[1].name));
        assert_eq!(description.schemas.len(), 13);
        assert!(description.schemas.iter().all(|entry| entry.schema.is_object()));
    }
}
