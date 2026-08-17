//! Host-neutral agent support for autonomous security assessments.
//!
//! Provides configuration, system prompts, and manifest generation
//! for integrating `ScorchKit` with MCP-capable hosts. Codex is the
//! preferred host, while the protocol and manifest remain vendor-neutral.
//!
//! # Usage
//!
//! ```no_run
//! use scorchkit_agent::config::AgentConfig;
//! use scorchkit_agent::generate_manifest;
//!
//! let config = AgentConfig::new(vec!["example.com".to_string()])
//!     .with_depth("standard")
//!     .with_project("my-assessment");
//!
//! let manifest = generate_manifest(&config);
//! println!("{manifest}");
//! ```

pub mod config;
pub mod prompt;

/// Provider-neutral typed reasoning payloads and response decoding.
pub mod ai {
    pub mod prompts;
    pub mod response;
    pub mod types;
}
use config::AgentConfig;
use prompt::AGENT_SYSTEM_PROMPT;

/// Generate a host-neutral JSON manifest for MCP agent consumption.
///
/// The manifest contains everything an Agent SDK client needs to
/// connect to `ScorchKit`'s MCP server and run an autonomous pentest:
/// - MCP server connection command
/// - System prompt with pentest methodology
/// - Agent configuration (declared scope, depth, safety constraints)
/// - Tool permissions
#[must_use]
pub fn generate_manifest(config: &AgentConfig) -> String {
    let manifest = serde_json::json!({
        "name": "scorchkit-agent",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Autonomous penetration testing agent powered by ScorchKit",
        "host": {
            "preferred": "codex",
            "interface": "mcp",
            "vendor_lock_in": false,
        },
        "mcp_server": {
            "command": "scorchkit",
            "args": ["serve"],
            "transport": "stdio",
        },
        "system_prompt": AGENT_SYSTEM_PROMPT,
        "agent_config": config,
        "capabilities": {
            "tools": true,
            "resources": true,
            "prompts": true,
        },
        "safety": {
            "declared_targets": &config.authorized_targets,
            "max_depth": &config.max_depth,
            "require_project": config.require_project,
            "authorization_source": "engine_engagement_policy",
            "scope_enforcement": "fail_closed",
            "exploitation": "requires_explicit_engagement_grant",
            "rate_limiting": config.scan_delay_seconds > 0,
        },
    });

    serde_json::to_string_pretty(&manifest).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify manifest generation produces valid JSON with required fields.
    #[test]
    fn test_generate_manifest() {
        let config = AgentConfig::new(vec!["example.com".to_string()]).with_project("test-project");

        let manifest = generate_manifest(&config);
        let parsed: serde_json::Value = serde_json::from_str(&manifest).expect("valid JSON");

        assert_eq!(parsed["name"], "scorchkit-agent");
        assert!(parsed["mcp_server"]["command"].as_str().is_some());
        assert_eq!(parsed["mcp_server"]["args"][0], "serve");
        assert!(parsed["agent_config"]["authorized_targets"].is_array());
        assert_eq!(parsed["host"]["preferred"], "codex");
        assert_eq!(parsed["safety"]["scope_enforcement"], "fail_closed");
        assert_eq!(parsed["safety"]["authorization_source"], "engine_engagement_policy");
    }

    /// Verify manifest includes the system prompt.
    #[test]
    fn test_manifest_includes_prompt() {
        let config = AgentConfig::default();
        let manifest = generate_manifest(&config);
        let parsed: serde_json::Value = serde_json::from_str(&manifest).expect("valid JSON");

        let prompt = parsed["system_prompt"].as_str().expect("prompt is string");
        assert!(prompt.contains("ScorchKit Agent"));
        assert!(prompt.contains("PTES"));
    }
}
