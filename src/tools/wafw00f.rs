use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// WAF detection via wafw00f.
#[derive(Debug)]
pub struct Wafw00fModule;

#[async_trait]
impl ScanModule for Wafw00fModule {
    fn name(&self) -> &'static str {
        "WAF Detection (wafw00f)"
    }
    fn id(&self) -> &'static str {
        "wafw00f"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Web Application Firewall detection via wafw00f"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("wafw00f")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();

        let output = subprocess::run_tool(
            "wafw00f",
            &[target, "-o", "-", "-f", "json"],
            Duration::from_secs(60),
        )
        .await?;

        Ok(parse_wafw00f_output(&output.stdout, target))
    }
}

fn parse_wafw00f_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
        if let Some(arr) = json.as_array() {
            for entry in arr {
                let waf = entry["firewall"].as_str().unwrap_or("Unknown");
                let manufacturer = entry["manufacturer"].as_str().unwrap_or("");

                if waf != "None" && !waf.is_empty() {
                    let desc = if manufacturer.is_empty() {
                        format!("WAF detected: {waf}")
                    } else {
                        format!("WAF detected: {waf} by {manufacturer}")
                    };

                    findings.push(
                        Finding::new(
                            "wafw00f",
                            Severity::Info,
                            format!("WAF Detected: {waf}"),
                            &desc,
                            target_url,
                        )
                        .with_evidence(desc)
                        .with_confidence(0.7),
                    );
                }
            }
        }
    }

    // Also try text output parsing
    if findings.is_empty() {
        for line in output.lines() {
            if line.contains("is behind") {
                findings.push(
                    Finding::new(
                        "wafw00f",
                        Severity::Info,
                        "WAF Detected",
                        line.trim(),
                        target_url,
                    )
                    .with_evidence(line.trim().to_string())
                    .with_confidence(0.7),
                );
            } else if line.contains("No WAF") {
                findings.push(
                    Finding::new(
                        "wafw00f",
                        Severity::Info,
                        "No WAF Detected",
                        "No Web Application Firewall was detected.",
                        target_url,
                    )
                    .with_confidence(0.7),
                );
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for wafw00f output parser (JSON and text fallback).

    /// Verify that `parse_wafw00f_output` correctly extracts WAF detection
    /// results from wafw00f JSON array output.
    #[test]
    fn test_parse_wafw00f_output() {
        let output = r#"[{"url":"https://example.com","detected":true,"firewall":"Cloudflare","manufacturer":"Cloudflare Inc."}]"#;

        let findings = parse_wafw00f_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Cloudflare"));
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// Verify that `parse_wafw00f_output` handles empty input gracefully.
    #[test]
    fn test_parse_wafw00f_output_empty() {
        let findings = parse_wafw00f_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
