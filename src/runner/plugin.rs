//! Plugin system for user-defined scan modules.
//!
//! Loads custom scan modules from TOML definition files in a plugins
//! directory. Each plugin specifies a command to run, arguments (with
//! `{target}` placeholder substitution), output format, and default
//! severity. Plugins implement `ScanModule` and integrate seamlessly
//! with the orchestrator.

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Plugin definition deserialized from a TOML file.
///
/// Example plugin.toml:
/// ```toml
/// id = "custom-check"
/// name = "My Custom Check"
/// description = "Runs a custom security check"
/// category = "scanner"
/// command = "my-tool"
/// args = ["--json", "{target}"]
/// timeout_seconds = 120
/// output_format = "lines"
/// severity = "medium"
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct PluginDef {
    /// Unique module identifier.
    pub id: String,
    /// Human-readable module name.
    pub name: String,
    /// Module description.
    pub description: String,
    /// Module category: "recon" or "scanner".
    #[serde(default = "default_category")]
    pub category: String,
    /// Command to execute.
    pub command: String,
    /// Command arguments. Use `{target}` as placeholder for the scan target.
    #[serde(default)]
    pub args: Vec<String>,
    /// Command timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Output format: "lines" (consolidated finding), "`json_lines`" (JSON per line),
    /// or "json" (single JSON array).
    #[serde(default = "default_format")]
    pub output_format: String,
    /// Default severity for findings: "critical", "high", "medium", "low", "info".
    #[serde(default = "default_severity")]
    pub severity: String,
}

fn default_category() -> String {
    "scanner".to_string()
}

const fn default_timeout() -> u64 {
    120
}

fn default_format() -> String {
    "lines".to_string()
}

fn default_severity() -> String {
    "info".to_string()
}

/// A user-defined scan module loaded from a plugin definition file.
#[derive(Debug)]
pub struct PluginModule {
    /// The plugin definition.
    def: PluginDef,
    /// Leaked static strings for `ScanModule` trait (plugins live for program lifetime).
    id_static: &'static str,
    name_static: &'static str,
    desc_static: &'static str,
    cmd_static: &'static str,
}

impl PluginModule {
    /// Create a plugin module from a definition.
    #[must_use]
    pub fn new(def: PluginDef) -> Self {
        let id_static: &'static str = Box::leak(def.id.clone().into_boxed_str());
        let name_static: &'static str = Box::leak(def.name.clone().into_boxed_str());
        let desc_static: &'static str = Box::leak(def.description.clone().into_boxed_str());
        let cmd_static: &'static str = Box::leak(def.command.clone().into_boxed_str());
        Self { def, id_static, name_static, desc_static, cmd_static }
    }
}

/// Parse a severity string to a Severity enum value.
const fn parse_severity_const(s: &[u8]) -> Severity {
    // const-compatible matching on first byte
    match s {
        [b'c' | b'C', ..] => Severity::Critical,
        [b'h' | b'H', ..] => Severity::High,
        [b'm' | b'M', ..] => Severity::Medium,
        [b'l' | b'L', ..] => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse a severity string to a Severity enum value.
const fn parse_severity(s: &str) -> Severity {
    parse_severity_const(s.as_bytes())
}

#[async_trait]
impl ScanModule for PluginModule {
    fn name(&self) -> &'static str {
        self.name_static
    }

    fn id(&self) -> &'static str {
        self.id_static
    }

    fn category(&self) -> ModuleCategory {
        if self.def.category.eq_ignore_ascii_case("recon") {
            ModuleCategory::Recon
        } else {
            ModuleCategory::Scanner
        }
    }

    fn description(&self) -> &'static str {
        self.desc_static
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some(self.cmd_static)
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();

        #[allow(clippy::literal_string_with_formatting_args)]
        let args: Vec<String> =
            self.def.args.iter().map(|a| a.replace("{target}", target)).collect();
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();

        let output = subprocess::run_tool(
            &self.def.command,
            &arg_refs,
            Duration::from_secs(self.def.timeout_seconds),
        )
        .await?;

        Ok(parse_plugin_output(
            &output.stdout,
            target,
            &self.def.id,
            &self.def.output_format,
            &self.def.severity,
        ))
    }
}

/// Parse plugin command output into findings based on the output format.
#[must_use]
fn parse_plugin_output(
    stdout: &str,
    target_url: &str,
    plugin_id: &str,
    output_format: &str,
    default_severity: &str,
) -> Vec<Finding> {
    match output_format {
        "json_lines" => parse_json_lines(stdout, target_url, plugin_id, default_severity),
        "json" => parse_json_array(stdout, target_url, plugin_id, default_severity),
        _ => parse_lines(stdout, target_url, plugin_id, default_severity),
    }
}

/// Parse plain text output — consolidated into a single finding.
fn parse_lines(stdout: &str, target_url: &str, plugin_id: &str, severity: &str) -> Vec<Finding> {
    let lines: Vec<&str> = stdout.lines().map(str::trim).filter(|l| !l.is_empty()).collect();

    if lines.is_empty() {
        return Vec::new();
    }

    let count = lines.len();
    let sample: Vec<&str> = lines.iter().copied().take(10).collect();

    vec![Finding::new(
        plugin_id,
        parse_severity(severity),
        format!("{plugin_id}: {count} Results"),
        format!("Plugin '{plugin_id}' produced {count} results. Sample: {}", sample.join("; ")),
        target_url,
    )
    .with_evidence(format!("{count} lines of output"))
    .with_confidence(0.5)]
}

/// Parse JSON-lines output — each line is a JSON object.
fn parse_json_lines(
    stdout: &str,
    target_url: &str,
    plugin_id: &str,
    default_severity: &str,
) -> Vec<Finding> {
    stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let obj: serde_json::Value = serde_json::from_str(line).ok()?;
            Some(json_to_finding(&obj, target_url, plugin_id, default_severity))
        })
        .collect()
}

/// Parse a single JSON array — each element becomes a finding.
fn parse_json_array(
    stdout: &str,
    target_url: &str,
    plugin_id: &str,
    default_severity: &str,
) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) else {
        return Vec::new();
    };

    items.iter().map(|obj| json_to_finding(obj, target_url, plugin_id, default_severity)).collect()
}

/// Convert a JSON object to a Finding.
fn json_to_finding(
    obj: &serde_json::Value,
    target_url: &str,
    plugin_id: &str,
    default_severity: &str,
) -> Finding {
    let title = obj["title"].as_str().or_else(|| obj["name"].as_str()).unwrap_or("Plugin Finding");
    let description = obj["description"].as_str().or_else(|| obj["message"].as_str()).unwrap_or("");
    let severity = obj["severity"].as_str().unwrap_or(default_severity);

    Finding::new(plugin_id, parse_severity(severity), title, description, target_url)
        .with_evidence(obj.to_string())
        .with_confidence(0.5)
}

/// Load all plugin definitions from a directory.
///
/// Discovers `.toml` files in the given directory, parses each as a
/// `PluginDef`, and wraps them in `PluginModule`. Invalid files are
/// logged and skipped.
pub fn load_plugins(dir: &Path) -> Vec<Box<dyn ScanModule>> {
    let mut modules: Vec<Box<dyn ScanModule>> = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!("Plugin directory {}: {e}", dir.display());
            return modules;
        }
    };

    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to read plugin {}: {e}", path.display());
                continue;
            }
        };

        let def: PluginDef = match toml::from_str(&content) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("Failed to parse plugin {}: {e}", path.display());
                continue;
            }
        };

        tracing::info!("Loaded plugin: {} ({})", def.name, path.display());
        modules.push(Box::new(PluginModule::new(def)));
    }

    modules
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify plugin definition deserializes from TOML.
    #[test]
    fn test_plugin_def_deserialize() {
        let toml_str = r#"
            id = "custom-check"
            name = "My Custom Check"
            description = "A custom security check"
            category = "scanner"
            command = "my-tool"
            args = ["--json", "{target}"]
            timeout_seconds = 60
            output_format = "json_lines"
            severity = "high"
        "#;

        let def: PluginDef = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(def.id, "custom-check");
        assert_eq!(def.command, "my-tool");
        assert_eq!(def.args, vec!["--json", "{target}"]);
        assert_eq!(def.timeout_seconds, 60);
        assert_eq!(def.output_format, "json_lines");
        assert_eq!(def.severity, "high");
    }

    /// Verify plugin module implements ScanModule trait correctly.
    #[test]
    fn test_plugin_module_metadata() {
        let def = PluginDef {
            id: "test-plugin".to_string(),
            name: "Test Plugin".to_string(),
            description: "A test plugin".to_string(),
            category: "recon".to_string(),
            command: "test-cmd".to_string(),
            args: vec![],
            timeout_seconds: 30,
            output_format: "lines".to_string(),
            severity: "info".to_string(),
        };

        let module = PluginModule::new(def);
        assert_eq!(module.id(), "test-plugin");
        assert_eq!(module.name(), "Test Plugin");
        assert_eq!(module.category(), ModuleCategory::Recon);
        assert!(module.requires_external_tool());
        assert_eq!(module.required_tool(), Some("test-cmd"));
    }

    /// Verify {target} placeholder substitution in args.
    #[test]
    fn test_plugin_arg_substitution() {
        let args = vec![
            "--url".to_string(),
            "{target}".to_string(),
            "--output".to_string(),
            "json".to_string(),
        ];
        let target = "https://example.com";

        let substituted: Vec<String> = args.iter().map(|a| a.replace("{target}", target)).collect();

        assert_eq!(substituted[0], "--url");
        assert_eq!(substituted[1], "https://example.com");
        assert_eq!(substituted[2], "--output");
    }

    /// Verify line-based output parsing produces consolidated finding.
    #[test]
    fn test_plugin_parse_lines() {
        let output = "found issue 1\nfound issue 2\nfound issue 3\n";
        let findings =
            parse_plugin_output(output, "https://example.com", "test", "lines", "medium");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("3 Results"));
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    /// Verify JSON-lines output parsing produces individual findings.
    #[test]
    fn test_plugin_parse_json_lines() {
        let output = r#"{"title": "XSS Found", "severity": "high", "description": "Reflected XSS"}
{"title": "SQLi Found", "severity": "critical", "description": "SQL Injection"}"#;

        let findings =
            parse_plugin_output(output, "https://example.com", "test", "json_lines", "info");
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("XSS Found"));
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Critical);
    }

    /// Verify loading from a nonexistent directory returns empty vec.
    #[test]
    fn test_load_plugins_empty_dir() {
        let result = load_plugins(Path::new("/tmp/nonexistent-scorchkit-plugins-31"));
        assert!(result.is_empty());
    }
}
