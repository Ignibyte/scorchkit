//! Agent configuration for autonomous pentest operations.
//!
//! Defines safety constraints, authorized targets, and operational
//! parameters for `ScorchKit` agent integrations.

use serde::{Deserialize, Serialize};

/// Configuration for an autonomous pentest agent session.
///
/// Controls what the agent is allowed to scan, how deep to go,
/// and what safety constraints apply. Serialized to JSON for
/// consumption by MCP-capable agent hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Target patterns declared to the agent host (exact domains, wildcards, CIDRs).
    /// This is a preflight hint, not authorization. The engine's engagement
    /// policy is the authoritative, fail-closed enforcement boundary.
    pub authorized_targets: Vec<String>,
    /// Maximum scan depth: `quick`, `standard`, `thorough`, or `pentest`.
    /// Restricted credential and exploit modules require the `pentest`
    /// profile plus explicit engine engagement grants.
    #[serde(default = "default_depth")]
    pub max_depth: String,
    /// Whether to require project persistence for audit trails.
    #[serde(default = "default_true")]
    pub require_project: bool,
    /// Whether to enable AI analysis after scanning.
    #[serde(default = "default_true")]
    pub enable_analysis: bool,
    /// Maximum concurrent scan operations.
    #[serde(default = "default_max_scans")]
    pub max_concurrent_scans: usize,
    /// Delay in seconds between scan operations (rate limiting).
    #[serde(default)]
    pub scan_delay_seconds: u64,
    /// Project name to use (auto-generated if not specified).
    pub project_name: Option<String>,
    /// Database URL for project persistence.
    pub database_url: Option<String>,
}

fn default_depth() -> String {
    "standard".to_string()
}

const fn default_true() -> bool {
    true
}

const fn default_max_scans() -> usize {
    1
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            authorized_targets: Vec::new(),
            max_depth: default_depth(),
            require_project: default_true(),
            enable_analysis: default_true(),
            max_concurrent_scans: default_max_scans(),
            scan_delay_seconds: 0,
            project_name: None,
            database_url: None,
        }
    }
}

impl AgentConfig {
    /// Create a new agent config with the given authorized targets.
    #[must_use]
    pub fn new(targets: Vec<String>) -> Self {
        Self { authorized_targets: targets, ..Self::default() }
    }

    /// Set the maximum scan depth.
    #[must_use]
    pub fn with_depth(mut self, depth: impl Into<String>) -> Self {
        self.max_depth = depth.into();
        self
    }

    /// Set the project name.
    #[must_use]
    pub fn with_project(mut self, name: impl Into<String>) -> Self {
        self.project_name = Some(name.into());
        self
    }

    /// Set the database URL.
    #[must_use]
    pub fn with_database_url(mut self, url: impl Into<String>) -> Self {
        self.database_url = Some(url.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify agent config serializes to JSON correctly.
    #[test]
    fn test_agent_config_serialize() {
        let config = AgentConfig::new(vec!["example.com".to_string(), "*.example.com".to_string()])
            .with_depth("thorough")
            .with_project("test-assessment");

        let json = serde_json::to_string_pretty(&config).expect("serialize");
        assert!(json.contains("example.com"));
        assert!(json.contains("thorough"));
        assert!(json.contains("test-assessment"));
        assert!(json.contains("require_project"));
    }

    /// Verify agent config defaults are sensible.
    #[test]
    fn test_agent_config_defaults() {
        let config = AgentConfig::default();
        assert!(config.authorized_targets.is_empty());
        assert_eq!(config.max_depth, "standard");
        assert!(config.require_project);
        assert!(config.enable_analysis);
        assert_eq!(config.max_concurrent_scans, 1);
        assert_eq!(config.scan_delay_seconds, 0);
        assert!(config.project_name.is_none());
    }

    #[test]
    fn omitted_json_fields_use_the_documented_defaults() {
        let config: AgentConfig = serde_json::from_str(r#"{"authorized_targets":[]}"#)
            .expect("minimal agent config should deserialize");

        assert_eq!(config.max_depth, "standard");
        assert!(config.require_project);
        assert!(config.enable_analysis);
        assert_eq!(config.max_concurrent_scans, 1);
    }

    #[test]
    fn database_url_builder_preserves_the_existing_config() {
        let config = AgentConfig::new(vec!["owned.example".to_string()])
            .with_depth("quick")
            .with_project("assessment")
            .with_database_url("postgresql://localhost/scorchkit");

        assert_eq!(config.authorized_targets, ["owned.example"]);
        assert_eq!(config.max_depth, "quick");
        assert_eq!(config.project_name.as_deref(), Some("assessment"));
        assert_eq!(config.database_url.as_deref(), Some("postgresql://localhost/scorchkit"));
    }
}
