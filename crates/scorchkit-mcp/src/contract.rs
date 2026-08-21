//! Versioned MCP tool contracts, structured results, and caller attribution.

use rmcp::model::{JsonObject, Meta, ToolAnnotations};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Version of the structured MCP result envelope and advertised output schema.
pub const MCP_OUTPUT_SCHEMA_VERSION: &str = "scorchkit.mcp.tool-result/v1";

/// The strongest behavior a tool can perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum McpToolClass {
    /// Observes `ScorchKit` or local process state without changing it or starting external work.
    Read,
    /// Changes `ScorchKit`-owned state without starting new target or provider work.
    #[schemars(
        description = "Changes ScorchKit-owned state without starting new target or provider work."
    )]
    LocalState,
    /// May contact targets, launch tools/providers, or otherwise create external effects.
    ExternalEffect,
}

/// Stable outcome discriminator for structured MCP tool results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum McpToolOutcome {
    /// The routed tool completed successfully.
    Success,
    /// The routed tool returned a caller-visible business error.
    Error,
}

/// Untrusted MCP client implementation attribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct McpClientAttribution {
    /// Self-asserted implementation name from MCP initialization.
    pub name: String,
    /// Self-asserted implementation version from MCP initialization.
    pub version: String,
    /// Always false for initialization metadata; it is not authentication evidence.
    pub trusted: bool,
}

/// Caller context attached to every successfully routed local MCP call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct McpPrincipalContext {
    /// Transport-derived principal kind. SK-032 supports only `local_process`.
    pub kind: String,
    /// Stable subject for the local-process trust boundary.
    pub subject: String,
    /// Self-asserted client metadata, kept separate from the transport principal.
    pub client_attribution: Option<McpClientAttribution>,
}

/// Caller-visible details for a routed MCP tool failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct McpToolError {
    /// Stable machine-readable error category.
    pub code: String,
    /// Terminal-safe caller-visible error message.
    pub message: String,
}

/// Versioned object-root response returned through MCP `structuredContent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct McpToolEnvelope {
    /// Structured result schema version.
    pub schema_version: String,
    /// Exact routed MCP tool name.
    pub tool: String,
    /// Strongest behavior class for the routed tool.
    pub tool_class: McpToolClass,
    /// Transport-derived caller context; never an authorization grant.
    pub principal: McpPrincipalContext,
    /// Success or error discriminator.
    pub outcome: McpToolOutcome,
    /// Parsed legacy JSON result or plain string for a successful call.
    pub result: Option<Value>,
    /// Caller-visible error for a failed routed call.
    pub error: Option<McpToolError>,
}

impl McpToolEnvelope {
    #[doc(hidden)]
    #[must_use]
    pub(crate) fn success(
        tool: &str,
        tool_class: McpToolClass,
        principal: McpPrincipalContext,
        text: &str,
    ) -> Self {
        let result = serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string()));
        Self {
            schema_version: MCP_OUTPUT_SCHEMA_VERSION.to_string(),
            tool: tool.to_string(),
            tool_class,
            principal,
            outcome: McpToolOutcome::Success,
            result: Some(result),
            error: None,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub(crate) fn error(
        tool: &str,
        tool_class: McpToolClass,
        principal: McpPrincipalContext,
        message: String,
    ) -> Self {
        Self {
            schema_version: MCP_OUTPUT_SCHEMA_VERSION.to_string(),
            tool: tool.to_string(),
            tool_class,
            principal,
            outcome: McpToolOutcome::Error,
            result: None,
            error: Some(McpToolError { code: "tool_execution_failed".to_string(), message }),
        }
    }
}

/// Exhaustive static contract for one advertised MCP tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolContract {
    /// Exact MCP tool name.
    pub name: &'static str,
    /// Strongest behavior class.
    pub tool_class: McpToolClass,
    /// Whether the tool may perform destructive updates or effects.
    pub destructive: bool,
    /// Whether repeated calls cannot add another state change or external effect.
    pub idempotent: bool,
    /// Whether the tool can interact with external entities.
    pub open_world: bool,
}

impl McpToolContract {
    /// Build complete MCP annotations for this contract.
    #[must_use]
    pub fn annotations(self) -> ToolAnnotations {
        ToolAnnotations::with_title(tool_title(self.name))
            .read_only(self.tool_class == McpToolClass::Read)
            .destructive(self.destructive)
            .idempotent(self.idempotent)
            .open_world(self.open_world)
    }

    #[doc(hidden)]
    #[must_use]
    pub(crate) fn meta(self) -> Meta {
        let tool_class = match self.tool_class {
            McpToolClass::Read => "read",
            McpToolClass::LocalState => "local_state",
            McpToolClass::ExternalEffect => "external_effect",
        };
        let mut scorchkit = JsonObject::new();
        scorchkit.insert(
            "outputSchemaVersion".to_string(),
            Value::String(MCP_OUTPUT_SCHEMA_VERSION.to_string()),
        );
        scorchkit.insert("toolClass".to_string(), Value::String(tool_class.to_string()));
        let mut meta = JsonObject::new();
        meta.insert("scorchkit".to_string(), Value::Object(scorchkit));
        Meta(meta)
    }
}

const fn contract(
    name: &'static str,
    tool_class: McpToolClass,
    destructive: bool,
    idempotent: bool,
    open_world: bool,
) -> McpToolContract {
    McpToolContract { name, tool_class, destructive, idempotent, open_world }
}

#[doc(hidden)]
const TOOL_CONTRACTS: [McpToolContract; 39] = [
    contract("analyze_findings", McpToolClass::ExternalEffect, false, false, true),
    contract("application_context", McpToolClass::Read, false, true, false),
    contract("application_dast", McpToolClass::ExternalEffect, true, false, true),
    contract("application_pentest", McpToolClass::ExternalEffect, true, false, true),
    contract("auto_scan", McpToolClass::ExternalEffect, true, false, true),
    contract("check_tools", McpToolClass::Read, false, true, false),
    contract("correlate_findings", McpToolClass::Read, false, true, false),
    contract("db_migrate", McpToolClass::LocalState, true, true, false),
    contract("finding_show", McpToolClass::Read, false, true, false),
    contract("finding_update_status", McpToolClass::LocalState, true, true, false),
    contract("import_application_evidence", McpToolClass::LocalState, true, false, false),
    contract("list_code_modules", McpToolClass::Read, false, true, false),
    contract("list_modules", McpToolClass::Read, false, true, false),
    contract("plan_application_pentest", McpToolClass::Read, false, true, false),
    contract("plan_appsec_workflow", McpToolClass::Read, false, true, false),
    contract("plan_scan", McpToolClass::ExternalEffect, false, false, true),
    contract("project_create", McpToolClass::LocalState, false, true, false),
    contract("project_delete", McpToolClass::LocalState, true, true, false),
    contract("project_findings", McpToolClass::Read, false, true, false),
    contract("project_list", McpToolClass::Read, false, true, false),
    contract("project_scan", McpToolClass::ExternalEffect, true, false, true),
    contract("project_show", McpToolClass::Read, false, true, false),
    contract("project_status", McpToolClass::Read, false, true, false),
    contract("run_due_scans", McpToolClass::ExternalEffect, true, false, true),
    contract("scan", McpToolClass::ExternalEffect, true, false, true),
    contract("scan_code", McpToolClass::ExternalEffect, false, false, true),
    contract("scan_job_cancel", McpToolClass::LocalState, true, true, false),
    contract("scan_job_resume", McpToolClass::ExternalEffect, true, false, true),
    contract("scan_job_start", McpToolClass::ExternalEffect, true, false, true),
    contract("scan_job_status", McpToolClass::Read, false, true, false),
    contract("scan_progress", McpToolClass::Read, false, true, false),
    contract("schedule_scan", McpToolClass::LocalState, false, false, false),
    contract("supply_chain_cache_refresh", McpToolClass::ExternalEffect, true, false, true),
    contract("supply_chain_cache_status", McpToolClass::Read, false, true, false),
    contract("supply_chain_scan", McpToolClass::ExternalEffect, false, false, false),
    contract("target_add", McpToolClass::LocalState, false, false, false),
    contract("target_intelligence", McpToolClass::ExternalEffect, false, false, true),
    contract("target_list", McpToolClass::Read, false, true, false),
    contract("target_remove", McpToolClass::LocalState, true, true, false),
];

/// Return the canonical MCP tool-contract inventory.
#[must_use]
pub const fn tool_contracts() -> &'static [McpToolContract] {
    &TOOL_CONTRACTS
}

/// Look up one canonical tool contract.
#[must_use]
pub fn tool_contract(name: &str) -> Option<McpToolContract> {
    TOOL_CONTRACTS.iter().copied().find(|entry| entry.name == name)
}

#[doc(hidden)]
#[must_use]
pub(crate) fn tool_title(name: &str) -> String {
    name.split('_')
        .map(|part| {
            let mut characters = part.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(characters).collect::<String>()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_titles_preserve_every_name_component() {
        assert_eq!(tool_title("scan_job_start"), "Scan Job Start");
        assert_eq!(
            tool_contract("scan_job_start")
                .expect("scan job start contract")
                .annotations()
                .title
                .as_deref(),
            Some("Scan Job Start")
        );
    }
}
