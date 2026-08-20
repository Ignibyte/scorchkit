//! Router integration for package-owned MCP contracts.

use std::sync::Arc;

use rmcp::handler::server::common::{schema_for_output, FromContextPart};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::{IntoCallToolResult, ToolCallContext};
use rmcp::model::{CallToolResult, Content, JsonObject};
#[cfg(test)]
use serde_json::Value;

use super::server::ScorchKitServer;
use crate::report::terminal::escape_terminal_text;

pub use scorchkit_mcp::contract::{
    tool_contract, tool_contracts, McpClientAttribution, McpPrincipalContext, McpToolClass,
    McpToolContract, McpToolEnvelope, McpToolError, McpToolOutcome, MCP_OUTPUT_SCHEMA_VERSION,
};
#[cfg(test)]
use scorchkit_mcp::integration::tool_title;
use scorchkit_mcp::integration::{error_envelope, success_envelope, tool_contract_meta};

const TOOL_CONTRACTS: &[McpToolContract] = tool_contracts();

fn local_principal<S>(context: &ToolCallContext<'_, S>) -> McpPrincipalContext {
    let client_attribution =
        context.request_context().peer.peer_info().map(|info| McpClientAttribution {
            name: info.client_info.name.clone(),
            version: info.client_info.version.clone(),
            trusted: false,
        });
    McpPrincipalContext {
        kind: "local_process".to_string(),
        subject: "local-mcp-process".to_string(),
        client_attribution,
    }
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
        Ok(Self { tool: context.name().to_string(), principal: local_principal(context) })
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
        route.attr.meta = Some(tool_contract_meta(contract));
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
                envelope: success_envelope(
                    &context.tool,
                    contract.tool_class,
                    context.principal,
                    &text,
                ),
                text,
            },
            Err(message) => {
                let message =
                    escape_terminal_text(&crate::engine::observation::redact_text(&message));
                McpToolCallResult {
                    envelope: error_envelope(
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
        assert_eq!(TOOL_CONTRACTS.len(), 33);
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
            "MCP tool router has 32 routes but contract inventory has 33"
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
        let success = success_envelope(
            "list_modules",
            McpToolClass::Read,
            principal.clone(),
            r#"{"count":2}"#,
        );
        assert_eq!(success.outcome, McpToolOutcome::Success);
        assert_eq!(success.result, Some(serde_json::json!({"count": 2})));
        assert!(success.error.is_none());

        let error = error_envelope(
            "scan",
            McpToolClass::ExternalEffect,
            principal,
            escape_terminal_text("denied\u{1b}[31m"),
        );
        assert_eq!(error.outcome, McpToolOutcome::Error);
        assert!(error.result.is_none());
        assert_eq!(error.error.expect("error body").message, "denied\\u{1b}[31m");
    }

    #[test]
    fn error_adapter_redacts_secret_bearing_diagnostics() {
        let result = ScorchKitServer::mcp_tool_result(
            McpCallContext::test("scan_code"),
            Err("password = \"mcp-error-fixture-secret\"".to_string()),
        )
        .into_call_tool_result()
        .expect("adapt MCP error result");
        let text = result.content[0].raw.as_text().expect("error text").text.as_str();
        assert!(!text.contains("mcp-error-fixture-secret"));
        assert!(text.contains("REDACTED"));
    }
}
