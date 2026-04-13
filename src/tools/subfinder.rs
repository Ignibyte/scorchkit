use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Fast subdomain discovery via Subfinder.
#[derive(Debug)]
pub struct SubfinderModule;

#[async_trait]
impl ScanModule for SubfinderModule {
    fn name(&self) -> &'static str {
        "Subfinder"
    }
    fn id(&self) -> &'static str {
        "subfinder"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Fast passive subdomain discovery via Subfinder"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("subfinder")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let domain = ctx.target.domain.as_deref().ok_or_else(|| ScorchError::InvalidTarget {
            target: ctx.target.raw.clone(),
            reason: "no domain for subdomain discovery".to_string(),
        })?;

        let output = subprocess::run_tool(
            "subfinder",
            &["-d", domain, "-silent", "-json"],
            Duration::from_secs(120),
        )
        .await?;

        Ok(parse_subfinder_output(&output.stdout, ctx.target.url.as_str()))
    }
}

fn parse_subfinder_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut subdomains = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(host) = json["host"].as_str() {
                if !subdomains.contains(&host.to_string()) {
                    subdomains.push(host.to_string());
                }
            }
        } else if !trimmed.is_empty() && trimmed.contains('.') {
            // Plain text output (one subdomain per line)
            if !subdomains.contains(&trimmed.to_string()) {
                subdomains.push(trimmed.to_string());
            }
        }
    }

    let mut findings = Vec::new();
    if !subdomains.is_empty() {
        let count = subdomains.len();
        subdomains.sort();
        let list = subdomains.iter().take(100).cloned().collect::<Vec<_>>().join("\n    ");

        findings.push(
            Finding::new(
                "subfinder",
                Severity::Info,
                format!("{count} Subdomains Found (Subfinder)"),
                format!("Subfinder found {count} subdomains."),
                target_url,
            )
            .with_evidence(format!("Subdomains:\n    {list}"))
            .with_confidence(0.8),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for Subfinder output parser (JSON and plain text).

    /// Verify that `parse_subfinder_output` correctly aggregates subdomains
    /// from Subfinder JSON-lines output into a consolidated finding.
    #[test]
    fn test_parse_subfinder_output() {
        let output = r#"{"host":"api.example.com","source":"crtsh"}
{"host":"cdn.example.com","source":"dnsdumpster"}
{"host":"mail.example.com","source":"hackertarget"}"#;

        let findings = parse_subfinder_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("3 Subdomains"));
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// Verify that `parse_subfinder_output` handles empty input gracefully.
    #[test]
    fn test_parse_subfinder_output_empty() {
        let findings = parse_subfinder_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
