//! Agent SDK support for autonomous pentest operations.
//!
//! Provides configuration, system prompts, and manifest generation
//! for integrating `ScorchKit` with the Claude Agent SDK. The agent
//! module does not run agents directly — it produces the configuration
//! that Agent SDK clients (Python/TypeScript) consume.
//!
//! # Usage
//!
//! ```no_run
//! use scorchkit::agent::config::AgentConfig;
//! use scorchkit::agent::generate_manifest;
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
pub mod runner;

use config::AgentConfig;
use prompt::AGENT_SYSTEM_PROMPT;

/// Generate a JSON manifest for Claude Agent SDK consumption.
///
/// The manifest contains everything an Agent SDK client needs to
/// connect to `ScorchKit`'s MCP server and run an autonomous pentest:
/// - MCP server connection command
/// - System prompt with pentest methodology
/// - Agent configuration (scope, depth, safety constraints)
/// - Tool permissions
#[must_use]
pub fn generate_manifest(config: &AgentConfig) -> String {
    let manifest = serde_json::json!({
        "name": "scorchkit-agent",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Autonomous penetration testing agent powered by ScorchKit",
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
            "authorized_targets": &config.authorized_targets,
            "max_depth": &config.max_depth,
            "require_project": config.require_project,
            "scope_enforcement": "strict",
            "exploitation": "disabled",
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
        assert_eq!(parsed["safety"]["scope_enforcement"], "strict");
        assert_eq!(parsed["safety"]["exploitation"], "disabled");
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
