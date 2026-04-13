use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;
use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug)]
pub struct DroopescanModule;

#[async_trait]
impl ScanModule for DroopescanModule {
    fn name(&self) -> &'static str {
        "Droopescan CMS Scanner"
    }
    fn id(&self) -> &'static str {
        "droopescan"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "CMS vulnerability scanning (Drupal, Joomla, WordPress, Silverstripe)"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("droopescan")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();
        let output = subprocess::run_tool(
            "droopescan",
            &["scan", "-u", target, "--output", "json"],
            Duration::from_secs(300),
        )
        .await?;

        Ok(parse_droopescan_output(&output.stdout, target))
    }
}

fn parse_droopescan_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
        // CMS version
        if let Some(version) = json["version"].as_str() {
            findings.push(
                Finding::new(
                    "droopescan",
                    Severity::Info,
                    format!("CMS Version: {version}"),
                    format!("Droopescan identified CMS version: {version}"),
                    target_url,
                )
                .with_evidence(format!("Version: {version}"))
                .with_confidence(0.7),
            );
        }

        // Plugins
        if let Some(plugins) = json["plugins"].as_array() {
            for plugin in plugins {
                let name = plugin["name"].as_str().unwrap_or("unknown");
                let version = plugin["version"].as_str().unwrap_or("unknown");
                findings.push(
                    Finding::new(
                        "droopescan",
                        Severity::Info,
                        format!("Plugin: {name} {version}"),
                        format!("CMS plugin detected: {name} version {version}"),
                        target_url,
                    )
                    .with_evidence(format!("{name} {version}"))
                    .with_confidence(0.7),
                );
            }
        }

        // Interesting URLs
        if let Some(urls) = json["interesting_urls"].as_array() {
            for url_entry in urls {
                let url = url_entry["url"].as_str().unwrap_or("");
                let desc = url_entry["description"].as_str().unwrap_or("");
                if !url.is_empty() {
                    findings.push(
                        Finding::new(
                            "droopescan",
                            Severity::Low,
                            format!("Interesting: {url}"),
                            desc,
                            url,
                        )
                        .with_owasp("A05:2021 Security Misconfiguration")
                        .with_confidence(0.7),
                    );
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for Droopescan JSON output parser.

    /// Verify that `parse_droopescan_output` correctly extracts CMS version,
    /// plugins, and interesting URLs from Droopescan JSON output.
    #[test]
    fn test_parse_droopescan_output() {
        let output = r#"{"version":"8.9.20","plugins":[{"name":"views","version":"8.x-3.14"}],"interesting_urls":[{"url":"https://example.com/CHANGELOG.txt","description":"Default changelog file"}]}"#;

        let findings = parse_droopescan_output(output, "https://example.com");
        assert_eq!(findings.len(), 3);
        let version = findings.iter().find(|f| f.title.contains("8.9.20"));
        assert!(version.is_some());
        let plugin = findings.iter().find(|f| f.title.contains("views"));
        assert!(plugin.is_some());
        let interesting = findings.iter().find(|f| f.title.contains("CHANGELOG"));
        assert!(interesting.is_some());
    }

    /// Verify that `parse_droopescan_output` handles empty input gracefully.
    #[test]
    fn test_parse_droopescan_output_empty() {
        let findings = parse_droopescan_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
