//! Versioned MCP tool contracts, structured results, and caller attribution.

use std::sync::Arc;

use rmcp::handler::server::common::{schema_for_output, FromContextPart};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::{IntoCallToolResult, ToolCallContext};
use rmcp::model::{CallToolResult, Content, JsonObject, Meta, ToolAnnotations};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::server::ScorchKitServer;
use crate::report::terminal::escape_terminal_text;

/// Version of the structured MCP result envelope and advertised output schema.
pub const MCP_OUTPUT_SCHEMA_VERSION: &str = "scorchkit.mcp.tool-result/v1";

/// The strongest behavior a tool can perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum McpToolClass {
    /// Observes `ScorchKit` or local process state without changing it or starting external work.
    Read,
    /// Changes ScorchKit-owned state without starting new target or provider work.
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

impl McpPrincipalContext {
    fn local<S>(context: &ToolCallContext<'_, S>) -> Self {
        let client_attribution =
            context.request_context().peer.peer_info().map(|info| McpClientAttribution {
                name: info.client_info.name.clone(),
                version: info.client_info.version.clone(),
                trusted: false,
            });
        Self {
            kind: "local_process".to_string(),
            subject: "local-mcp-process".to_string(),
            client_attribution,
        }
    }
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
    fn success(
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

    fn error(
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

    fn meta(self) -> Meta {
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

const TOOL_CONTRACTS: [McpToolContract; 30] = [
    contract("analyze_findings", McpToolClass::ExternalEffect, false, false, true),
    contract("auto_scan", McpToolClass::ExternalEffect, true, false, true),
    contract("check_tools", McpToolClass::Read, false, true, false),
    contract("correlate_findings", McpToolClass::Read, false, true, false),
    contract("db_migrate", McpToolClass::LocalState, true, true, false),
    contract("finding_show", McpToolClass::Read, false, true, false),
    contract("finding_update_status", McpToolClass::LocalState, true, true, false),
    contract("list_code_modules", McpToolClass::Read, false, true, false),
    contract("list_modules", McpToolClass::Read, false, true, false),
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

fn tool_title(name: &str) -> String {
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

/// Routed name and local principal extracted from rmcp's request context.
pub(crate) struct McpCallContext {
    tool: String,
    principal: McpPrincipalContext,
}

#[cfg(test)]
impl McpCallContext {
    pub(crate) fn test(tool: &str) -> Self {
        Self {
            tool: tool.to_string(),
            principal: McpPrincipalContext {
                kind: "local_process".to_string(),
                subject: "local-mcp-process".to_string(),
                client_attribution: None,
            },
        }
    }
}

impl<S> FromContextPart<ToolCallContext<'_, S>> for McpCallContext {
    fn from_context_part(context: &mut ToolCallContext<'_, S>) -> Result<Self, rmcp::ErrorData> {
        Ok(Self {
            tool: context.name().to_string(),
            principal: McpPrincipalContext::local(context),
        })
    }
}

/// Adapter that retains legacy text and adds the native structured envelope.
pub(crate) struct McpToolCallResult {
    text: String,
    envelope: McpToolEnvelope,
}

#[cfg(test)]
impl McpToolCallResult {
    pub(crate) fn legacy_text(&self) -> &str {
        &self.text
    }
}

impl IntoCallToolResult for McpToolCallResult {
    fn into_call_tool_result(self) -> Result<CallToolResult, rmcp::ErrorData> {
        let structured = serde_json::to_value(&self.envelope).map_err(|error| {
            rmcp::ErrorData::internal_error(
                format!("failed to serialize ScorchKit MCP result: {error}"),
                None,
            )
        })?;
        let mut result = match self.envelope.outcome {
            McpToolOutcome::Success => CallToolResult::structured(structured),
            McpToolOutcome::Error => CallToolResult::structured_error(structured),
        };
        result.content = vec![Content::text(self.text)];
        Ok(result)
    }
}

/// Decorate all macro-generated routes from the canonical contract inventory.
pub(crate) fn decorate_tool_router(router: &mut ToolRouter<ScorchKitServer>) -> Result<(), String> {
    if router.map.len() != TOOL_CONTRACTS.len() {
        return Err(format!(
            "MCP tool router has {} routes but contract inventory has {}",
            router.map.len(),
            TOOL_CONTRACTS.len()
        ));
    }
    let output_schema: Arc<JsonObject> = schema_for_output::<McpToolEnvelope>()?;
    for (name, route) in &mut router.map {
        let contract = tool_contract(name)
            .ok_or_else(|| format!("MCP tool '{name}' has no contract classification"))?;
        let annotations = contract.annotations();
        route.attr.title.clone_from(&annotations.title);
        route.attr.annotations = Some(annotations);
        route.attr.output_schema = Some(Arc::clone(&output_schema));
        route.attr.meta = Some(contract.meta());
    }
    for contract in TOOL_CONTRACTS {
        if !router.map.contains_key(contract.name) {
            return Err(format!("MCP contract '{}' has no routed tool", contract.name));
        }
    }
    Ok(())
}

impl ScorchKitServer {
    pub(crate) fn contract_tool_router() -> ToolRouter<Self> {
        let mut router = Self::tool_router();
        decorate_tool_router(&mut router)
            .unwrap_or_else(|error| panic!("invalid ScorchKit MCP tool contract: {error}"));
        router
    }

    pub(crate) fn mcp_tool_result(
        context: McpCallContext,
        result: Result<String, String>,
    ) -> McpToolCallResult {
        let contract = tool_contract(&context.tool)
            .unwrap_or_else(|| panic!("routed MCP tool '{}' has no contract", context.tool));
        match result {
            Ok(text) => McpToolCallResult {
                envelope: McpToolEnvelope::success(
                    &context.tool,
                    contract.tool_class,
                    context.principal,
                    &text,
                ),
                text,
            },
            Err(message) => {
                let message = escape_terminal_text(&message);
                McpToolCallResult {
                    envelope: McpToolEnvelope::error(
                        &context.tool,
                        contract.tool_class,
                        context.principal,
                        message.clone(),
                    ),
                    text: message,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_inventory_is_sorted_unique_and_classified() {
        assert_eq!(TOOL_CONTRACTS.len(), 30);
        assert_eq!(tool_title("scan_job_start"), "Scan Job Start");
        assert!(TOOL_CONTRACTS.windows(2).all(|pair| pair[0].name < pair[1].name));
        assert!(TOOL_CONTRACTS.iter().all(|entry| {
            let annotations = entry.annotations();
            annotations.read_only_hint == Some(entry.tool_class == McpToolClass::Read)
                && annotations.destructive_hint == Some(entry.destructive)
                && annotations.idempotent_hint == Some(entry.idempotent)
                && annotations.open_world_hint == Some(entry.open_world)
        }));
        let expected: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/mcp/tool-contract-v1.json"))
                .expect("decode MCP tool contract fixture");
        assert_eq!(serde_json::to_value(TOOL_CONTRACTS).expect("serialize contracts"), expected);
    }

    #[test]
    fn output_schema_matches_the_versioned_snapshot() {
        let expected: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/mcp/tool-output-schema-v1.json"
        ))
        .expect("decode MCP output schema fixture");
        let actual = serde_json::to_value(
            schema_for_output::<McpToolEnvelope>().expect("build MCP output schema"),
        )
        .expect("serialize MCP output schema");
        assert_eq!(actual, expected);
    }

    #[test]
    fn generated_router_is_decorated_without_a_transport() {
        let mut router = ScorchKitServer::tool_router();
        decorate_tool_router(&mut router).expect("decorate complete generated router");
        let tools = router.list_all();
        assert_eq!(tools.len(), TOOL_CONTRACTS.len());
        for tool in tools {
            let contract = tool_contract(&tool.name).expect("contract for generated route");
            assert_eq!(tool.annotations, Some(contract.annotations()));
            assert!(tool.output_schema.is_some());
            assert_eq!(
                tool.meta
                    .as_ref()
                    .and_then(|meta| meta.0.get("scorchkit"))
                    .and_then(|value| value.get("toolClass")),
                Some(&serde_json::to_value(contract.tool_class).expect("serialize tool class"))
            );
        }

        router.remove_route("scan");
        assert_eq!(
            decorate_tool_router(&mut router).expect_err("missing route must fail"),
            "MCP tool router has 29 routes but contract inventory has 30"
        );
    }

    #[test]
    fn direct_result_adapter_preserves_text_and_adds_the_structured_contract() {
        let server = ScorchKitServer::new_stateless(Arc::new(crate::config::AppConfig::default()));
        let legacy = server.do_list_modules();
        let result = ScorchKitServer::mcp_tool_result(
            McpCallContext::test("list_modules"),
            Ok(legacy.clone()),
        )
        .into_call_tool_result()
        .expect("adapt successful MCP tool result");
        assert_ne!(result.is_error, Some(true));
        assert_eq!(result.content[0].raw.as_text().expect("legacy text content").text, legacy);
        let structured = result.structured_content.expect("native structured content");
        assert_eq!(structured["schemaVersion"], MCP_OUTPUT_SCHEMA_VERSION);
        assert_eq!(structured["tool"], "list_modules");
        assert_eq!(structured["toolClass"], "read");
        assert_eq!(structured["principal"]["kind"], "local_process");
        assert_eq!(structured["outcome"], "success");
        assert!(structured["result"].is_array());
    }

    #[test]
    fn success_and_error_envelopes_are_exclusive_and_terminal_safe() {
        let principal = McpPrincipalContext {
            kind: "local_process".to_string(),
            subject: "local-mcp-process".to_string(),
            client_attribution: None,
        };
        let success = McpToolEnvelope::success(
            "list_modules",
            McpToolClass::Read,
            principal.clone(),
            r#"{"count":2}"#,
        );
        assert_eq!(success.outcome, McpToolOutcome::Success);
        assert_eq!(success.result, Some(serde_json::json!({"count": 2})));
        assert!(success.error.is_none());

        let error = McpToolEnvelope::error(
            "scan",
            McpToolClass::ExternalEffect,
            principal,
            escape_terminal_text("denied\u{1b}[31m"),
        );
        assert_eq!(error.outcome, McpToolOutcome::Error);
        assert!(error.result.is_none());
        assert_eq!(error.error.expect("error body").message, "denied\\u{1b}[31m");
    }
}
