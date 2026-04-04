//! Katana web crawler wrapper for JS-rendered endpoint discovery.
//!
//! Wraps `ProjectDiscovery`'s Katana crawler which handles modern JS-heavy
//! SPAs via headless browser rendering. Outputs discovered URLs as JSON
//! lines (`JSONL`) for comprehensive endpoint discovery.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Web crawling with JS rendering via Katana.
#[derive(Debug)]
pub struct KatanaModule;

#[async_trait]
impl ScanModule for KatanaModule {
    fn name(&self) -> &'static str {
        "Katana Web Crawler"
    }

    fn id(&self) -> &'static str {
        "katana"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "JS-rendering web crawler for comprehensive endpoint discovery"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("katana")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();

        let output = subprocess::run_tool(
            "katana",
            &["-u", url, "-json", "-silent", "-depth", "3", "-no-color"],
            Duration::from_secs(300),
        )
        .await?;

        Ok(parse_katana_output(&output.stdout, url))
    }
}

/// Parse Katana JSON-lines output into a consolidated finding.
///
/// Each line is a JSON object with a `request.endpoint` field containing
/// the discovered URL. Returns a single Info finding with the count and
/// sample URLs.
#[must_use]
fn parse_katana_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let urls: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let json: serde_json::Value = serde_json::from_str(line).ok()?;
            json.pointer("/request/endpoint")
                .or_else(|| json.get("endpoint"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect();

    if urls.is_empty() {
        return Vec::new();
    }

    let count = urls.len();
    let sample: Vec<&str> = urls.iter().map(String::as_str).take(10).collect();

    vec![Finding::new(
        "katana",
        Severity::Info,
        format!("Katana: {count} Endpoints Discovered"),
        format!(
            "Katana crawler discovered {count} endpoints via JS-rendered browsing. \
             Sample URLs: {}",
            sample.join(", ")
        ),
        target_url,
    )
    .with_evidence(format!("{count} URLs discovered"))
    .with_owasp("A05:2021 Security Misconfiguration")
    .with_confidence(0.7)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for Katana tool wrapper.

    /// Verify Katana JSON-lines output parsing.
    #[test]
    fn test_parse_katana_output() {
        let output = r#"{"request":{"endpoint":"https://example.com/login"},"response":{"status_code":200}}
{"request":{"endpoint":"https://example.com/api/users"},"response":{"status_code":200}}
{"request":{"endpoint":"https://example.com/dashboard"},"response":{"status_code":302}}"#;

        let findings = parse_katana_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("3 Endpoints"));
    }

    /// Verify empty output produces no findings.
    #[test]
    fn test_parse_katana_empty() {
        let findings = parse_katana_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
