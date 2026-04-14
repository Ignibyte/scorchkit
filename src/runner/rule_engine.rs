//! YAML-based custom rule engine for HTTP response pattern matching.
//!
//! Loads rule definitions from YAML files in a configured rules directory
//! and runs them against scan targets. Each rule has request config
//! (method/path/headers), response matchers (body regex, header regex,
//! status), and a finding template.
//!
//! # Example Rule
//!
//! ```yaml
//! id: admin-panel-exposure
//! name: Admin panel exposed
//! severity: high
//! description: Admin panel accessible without authentication
//! request:
//!   path: "/admin"
//!   method: GET
//! matchers:
//!   status: 200
//!   body_regex: "(?i)admin (login|dashboard|panel)"
//! remediation: Restrict /admin to authenticated users
//! ```
//!
//! Complements the TOML command-plugin system in [`super::plugin`]:
//! commands wrap external CLIs; rules match HTTP response patterns
//! without requiring any installed binaries.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// A single rule definition loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleDef {
    /// Unique rule identifier.
    pub id: String,
    /// Human-readable rule name.
    pub name: String,
    /// Finding severity: "critical", "high", "medium", "low", "info".
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Rule description (becomes finding description).
    #[serde(default)]
    pub description: String,
    /// Optional remediation advice (supports `{target}` placeholder).
    #[serde(default)]
    pub remediation: String,
    /// Request configuration.
    #[serde(default)]
    pub request: RequestConfig,
    /// Response matchers — all must match for the rule to fire.
    pub matchers: MatcherConfig,
}

/// Request configuration for a rule.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RequestConfig {
    /// HTTP method (default: GET).
    #[serde(default = "default_method")]
    pub method: String,
    /// URL path to append to the target (default: `/`).
    #[serde(default = "default_path")]
    pub path: String,
    /// Additional request headers.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Request body (for POST/PUT).
    #[serde(default)]
    pub body: Option<String>,
}

/// Response matcher configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MatcherConfig {
    /// Expected HTTP status code (if set, must match exactly).
    #[serde(default)]
    pub status: Option<u16>,
    /// Regex pattern to match against response body.
    #[serde(default)]
    pub body_regex: Option<String>,
    /// Regex pattern to match against a specific response header value.
    /// Format: `"header-name: pattern"`.
    #[serde(default)]
    pub header_regex: Option<String>,
}

fn default_severity() -> String {
    "medium".to_string()
}

fn default_method() -> String {
    "GET".to_string()
}

fn default_path() -> String {
    "/".to_string()
}

/// Parse a severity string to a Severity enum value.
fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Load all rule definitions from a directory.
///
/// Discovers `.yaml` and `.yml` files, parses each as a [`RuleDef`],
/// and returns the valid ones. Invalid files are logged and skipped.
#[must_use]
pub fn load_rules(dir: &Path) -> Vec<RuleDef> {
    let mut rules = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!("Rules directory {}: {e}", dir.display());
            return rules;
        }
    };

    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();

        let ext = path.extension().and_then(|e| e.to_str());
        if ext != Some("yaml") && ext != Some("yml") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to read rule {}: {e}", path.display());
                continue;
            }
        };

        match serde_yaml::from_str::<RuleDef>(&content) {
            Ok(rule) => {
                tracing::info!("Loaded rule: {} ({})", rule.name, path.display());
                rules.push(rule);
            }
            Err(e) => tracing::warn!("Failed to parse rule {}: {e}", path.display()),
        }
    }

    rules
}

/// Evaluate a rule's matchers against an HTTP response.
///
/// Returns `true` if all configured matchers match. Unconfigured
/// matchers (None) are ignored. Invalid regex patterns cause the
/// matcher to not match (logged at debug level).
#[must_use]
pub fn matches_response<S: ::std::hash::BuildHasher>(
    matchers: &MatcherConfig,
    status: u16,
    body: &str,
    headers: &HashMap<String, String, S>,
) -> bool {
    if let Some(expected_status) = matchers.status {
        if status != expected_status {
            return false;
        }
    }

    if let Some(ref pattern) = matchers.body_regex {
        let Ok(re) = Regex::new(pattern) else {
            tracing::debug!("Invalid body_regex pattern: {pattern}");
            return false;
        };
        if !re.is_match(body) {
            return false;
        }
    }

    if let Some(ref header_match) = matchers.header_regex {
        // Format: "header-name: pattern"
        let Some((name, pattern)) = header_match.split_once(':') else {
            tracing::debug!(
                "Invalid header_regex format (expected 'name: pattern'): {header_match}"
            );
            return false;
        };
        let name = name.trim().to_lowercase();
        let pattern = pattern.trim();
        let Ok(re) = Regex::new(pattern) else {
            tracing::debug!("Invalid header_regex pattern: {pattern}");
            return false;
        };
        let header_value =
            headers.iter().find(|(k, _)| k.to_lowercase() == name).map_or("", |(_, v)| v.as_str());
        if !re.is_match(header_value) {
            return false;
        }
    }

    true
}

/// Scan module that loads and runs YAML rules against a target.
#[derive(Debug)]
pub struct RuleEngineModule {
    /// Loaded rule definitions.
    rules: Vec<RuleDef>,
}

impl RuleEngineModule {
    /// Create a new rule engine with the given rules.
    #[must_use]
    pub const fn new(rules: Vec<RuleDef>) -> Self {
        Self { rules }
    }

    /// Number of loaded rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[async_trait]
impl ScanModule for RuleEngineModule {
    fn name(&self) -> &'static str {
        "Custom Rule Engine"
    }

    fn id(&self) -> &'static str {
        "rule-engine"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Evaluates YAML-defined custom rules against HTTP responses"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        if self.rules.is_empty() {
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        let base_url = ctx.target.url.as_str().trim_end_matches('/');

        for rule in &self.rules {
            let path = rule.request.path.trim_start_matches('/');
            let url = format!("{base_url}/{path}");

            // Build request
            let method = reqwest::Method::from_bytes(rule.request.method.as_bytes())
                .unwrap_or(reqwest::Method::GET);
            let mut req = ctx.http_client.request(method, &url);
            for (k, v) in &rule.request.headers {
                req = req.header(k, v);
            }
            if let Some(ref body) = rule.request.body {
                req = req.body(body.clone());
            }
            req = req.timeout(Duration::from_secs(30));

            let Ok(response) = req.send().await else {
                continue;
            };

            let status = response.status().as_u16();
            let headers: HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let body = response.text().await.unwrap_or_default();

            if matches_response(&rule.matchers, status, &body, &headers) {
                let affected = url.clone();
                let remediation = if rule.remediation.is_empty() {
                    "Review and address the condition matched by this rule.".to_string()
                } else {
                    rule.remediation.replace("{target}", &url)
                };

                findings.push(
                    Finding::new(
                        "rule-engine",
                        parse_severity(&rule.severity),
                        rule.name.clone(),
                        if rule.description.is_empty() {
                            rule.name.clone()
                        } else {
                            rule.description.clone()
                        },
                        &affected,
                    )
                    .with_evidence(format!("Rule '{}' matched at {}", rule.id, url))
                    .with_remediation(remediation)
                    .with_confidence(0.7),
                );
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify YAML rule definition deserializes correctly.
    #[test]
    fn test_rule_def_deserialize() {
        let yaml = r#"
id: admin-panel
name: Admin Panel Exposed
severity: high
description: Admin panel found without auth
request:
  path: /admin
  method: GET
matchers:
  status: 200
  body_regex: "(?i)admin"
remediation: Restrict access
"#;
        let rule: RuleDef = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(rule.id, "admin-panel");
        assert_eq!(rule.severity, "high");
        assert_eq!(rule.request.path, "/admin");
        assert_eq!(rule.matchers.status, Some(200));
        assert_eq!(rule.matchers.body_regex.as_deref(), Some("(?i)admin"));
    }

    /// Verify status code matcher evaluates correctly.
    #[test]
    fn test_matcher_status() {
        let matchers = MatcherConfig { status: Some(200), body_regex: None, header_regex: None };
        let headers = HashMap::new();

        assert!(matches_response(&matchers, 200, "", &headers));
        assert!(!matches_response(&matchers, 404, "", &headers));
        assert!(!matches_response(&matchers, 301, "", &headers));
    }

    /// Verify body regex matcher evaluates correctly.
    #[test]
    fn test_matcher_body_regex() {
        let matchers = MatcherConfig {
            status: None,
            body_regex: Some("(?i)admin".to_string()),
            header_regex: None,
        };
        let headers = HashMap::new();

        assert!(matches_response(&matchers, 200, "Admin Panel", &headers));
        assert!(matches_response(&matchers, 200, "welcome ADMIN user", &headers));
        assert!(!matches_response(&matchers, 200, "home page", &headers));
    }

    /// Verify header regex matcher evaluates correctly.
    #[test]
    fn test_matcher_header_regex() {
        let matchers = MatcherConfig {
            status: None,
            body_regex: None,
            header_regex: Some("server: nginx".to_string()),
        };
        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "nginx/1.18.0".to_string());

        assert!(matches_response(&matchers, 200, "", &headers));

        headers.insert("Server".to_string(), "Apache/2.4".to_string());
        assert!(!matches_response(&matchers, 200, "", &headers));
    }

    /// Verify invalid regex pattern fails the matcher gracefully.
    #[test]
    fn test_matcher_invalid_regex() {
        let matchers = MatcherConfig {
            status: None,
            body_regex: Some("[unclosed".to_string()),
            header_regex: None,
        };
        let headers = HashMap::new();

        // Invalid regex should not match — no panic
        assert!(!matches_response(&matchers, 200, "anything", &headers));
    }

    /// Verify multiple matchers must ALL match (AND semantics).
    #[test]
    fn test_matcher_and_semantics() {
        let matchers = MatcherConfig {
            status: Some(200),
            body_regex: Some("(?i)error".to_string()),
            header_regex: None,
        };
        let headers = HashMap::new();

        // All match
        assert!(matches_response(&matchers, 200, "database error", &headers));
        // Status mismatch
        assert!(!matches_response(&matchers, 404, "database error", &headers));
        // Body mismatch
        assert!(!matches_response(&matchers, 200, "success", &headers));
    }

    /// Verify severity parsing handles all levels including unknown.
    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), Severity::Critical);
        assert_eq!(parse_severity("HIGH"), Severity::High);
        assert_eq!(parse_severity("medium"), Severity::Medium);
        assert_eq!(parse_severity("low"), Severity::Low);
        assert_eq!(parse_severity("info"), Severity::Info);
        assert_eq!(parse_severity("unknown"), Severity::Info);
    }

    /// Verify rule engine module metadata.
    #[test]
    fn test_rule_engine_metadata() {
        let engine = RuleEngineModule::new(vec![]);
        assert_eq!(engine.id(), "rule-engine");
        assert_eq!(engine.category(), ModuleCategory::Scanner);
        assert_eq!(engine.rule_count(), 0);
    }

    /// Verify loading from a nonexistent directory returns empty.
    #[test]
    fn test_load_rules_missing_dir() {
        let rules = load_rules(Path::new("/tmp/nonexistent-scorchkit-rules-xyz"));
        assert!(rules.is_empty());
    }

    /// Verify loading YAML rule files from a directory.
    #[test]
    fn test_load_rules_from_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let yaml = r#"
id: test-rule
name: Test Rule
severity: low
matchers:
  status: 200
"#;
        std::fs::write(dir.path().join("test.yaml"), yaml).expect("write");
        std::fs::write(dir.path().join("README.md"), "# Notes").expect("write"); // non-yaml

        let rules = load_rules(dir.path());
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "test-rule");
    }
}
