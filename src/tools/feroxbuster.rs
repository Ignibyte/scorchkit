use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Recursive directory brute-forcing via feroxbuster.
#[derive(Debug)]
pub struct FeroxbusterModule;

#[async_trait]
impl ScanModule for FeroxbusterModule {
    fn name(&self) -> &'static str {
        "Feroxbuster Directory Scanner"
    }

    fn id(&self) -> &'static str {
        "feroxbuster"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Recursive directory and content discovery via feroxbuster"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("feroxbuster")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();

        let output = subprocess::run_tool(
            "feroxbuster",
            &[
                "-u",
                target,
                "--json",
                "-q",
                "--no-state",
                "-t",
                "20",
                "--time-limit",
                "5m",
                "-C",
                "404,403",
            ],
            Duration::from_secs(360),
        )
        .await?;

        Ok(parse_feroxbuster_output(&output.stdout, target))
    }
}

/// Parse feroxbuster JSON-lines output into findings.
fn parse_feroxbuster_output(output: &str, _target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let json: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // feroxbuster JSON format: {"type":"response", "url":"...", "status":200, ...}
        let entry_type = json["type"].as_str().unwrap_or("");
        if entry_type != "response" {
            continue;
        }

        let url = json["url"].as_str().unwrap_or("");
        let status = json["status"].as_u64().unwrap_or(0);
        let content_length = json["content_length"].as_u64().unwrap_or(0);

        if url.is_empty() || status == 0 {
            continue;
        }

        let (severity, category) = classify_discovered_path(url);

        findings.push(
            Finding::new(
                "feroxbuster",
                severity,
                format!("Discovered: {url}"),
                format!("feroxbuster discovered accessible path: {url}"),
                url,
            )
            .with_evidence(format!(
                "HTTP {status} | Size: {content_length} bytes | Category: {category}"
            ))
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_confidence(0.6),
        );
    }

    // Limit findings to most interesting ones
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings.truncate(50);

    findings
}

/// Classify discovered paths by severity and category.
fn classify_discovered_path(url: &str) -> (Severity, &'static str) {
    let lower = url.to_lowercase();

    // Critical: exposed secrets
    if lower.contains(".env")
        || lower.contains("backup")
        || lower.contains(".sql")
        || lower.contains("dump")
        || lower.contains(".key")
        || lower.contains("credentials")
    {
        return (Severity::Critical, "secrets/backup");
    }

    // High: source control, config
    if lower.contains(".git")
        || lower.contains(".svn")
        || lower.contains("config")
        || lower.contains("phpinfo")
        || lower.contains("server-status")
        || lower.contains("server-info")
    {
        return (Severity::High, "configuration/source");
    }

    // Medium: admin panels, debug
    if lower.contains("admin")
        || lower.contains("debug")
        || lower.contains("console")
        || lower.contains("dashboard")
        || lower.contains("manager")
    {
        return (Severity::Medium, "admin/management");
    }

    // Low: API docs, interesting paths
    if lower.contains("api")
        || lower.contains("swagger")
        || lower.contains("graphql")
        || lower.contains("docs")
    {
        return (Severity::Low, "api/docs");
    }

    (Severity::Info, "content")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for feroxbuster JSON-lines output parser.

    /// Verify that `parse_feroxbuster_output` correctly extracts discovered
    /// paths and classifies their severity.
    #[test]
    fn test_parse_feroxbuster_output() {
        let output = r#"{"type":"response","url":"https://example.com/.env","status":200,"content_length":512}
{"type":"response","url":"https://example.com/admin","status":200,"content_length":1024}
{"type":"response","url":"https://example.com/index.html","status":200,"content_length":4096}
{"type":"stats","requests":1000}"#;

        let findings = parse_feroxbuster_output(output, "https://example.com");
        assert_eq!(findings.len(), 3);
        // .env is critical (secrets)
        let env_finding = findings.iter().find(|f| f.title.contains(".env"));
        assert!(env_finding.is_some());
        assert_eq!(env_finding.expect("env finding should exist").severity, Severity::Critical);
    }

    /// Verify that `parse_feroxbuster_output` handles empty input gracefully.
    #[test]
    fn test_parse_feroxbuster_output_empty() {
        let findings = parse_feroxbuster_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
