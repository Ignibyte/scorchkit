//! Stable MCP input schemas, result envelopes, and host instructions.

pub mod contract;
pub mod instructions;
pub mod types;

/// Narrow cross-package helpers used by the root MCP transport adapter.
#[doc(hidden)]
pub mod integration {
    use rmcp::model::Meta;

    use crate::contract::{McpPrincipalContext, McpToolClass, McpToolContract, McpToolEnvelope};

    /// Build a successful structured result envelope.
    #[must_use]
    pub fn success_envelope(
        tool: &str,
        tool_class: McpToolClass,
        principal: McpPrincipalContext,
        text: &str,
    ) -> McpToolEnvelope {
        McpToolEnvelope::success(tool, tool_class, principal, text)
    }

    /// Build an error structured result envelope.
    #[must_use]
    pub fn error_envelope(
        tool: &str,
        tool_class: McpToolClass,
        principal: McpPrincipalContext,
        message: String,
    ) -> McpToolEnvelope {
        McpToolEnvelope::error(tool, tool_class, principal, message)
    }

    /// Build the MCP metadata attached to one routed tool.
    #[must_use]
    pub fn tool_contract_meta(contract: McpToolContract) -> Meta {
        contract.meta()
    }

    /// Build the presentation title used by generated MCP routes.
    #[must_use]
    pub fn tool_title(name: &str) -> String {
        crate::contract::tool_title(name)
    }
}
