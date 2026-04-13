use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Advanced subdomain enumeration via OWASP Amass.
#[derive(Debug)]
pub struct AmassModule;

#[async_trait]
impl ScanModule for AmassModule {
    fn name(&self) -> &'static str {
        "Amass Subdomain Enumerator"
    }
    fn id(&self) -> &'static str {
        "amass"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Advanced subdomain enumeration via OWASP Amass"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("amass")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let domain = ctx.target.domain.as_deref().ok_or_else(|| ScorchError::InvalidTarget {
            target: ctx.target.raw.clone(),
            reason: "no domain for subdomain enumeration".to_string(),
        })?;

        let output = subprocess::run_tool(
            "amass",
            &["enum", "-passive", "-d", domain, "-json", "/dev/stdout", "-timeout", "5"],
            Duration::from_secs(360),
        )
        .await?;

        Ok(parse_amass_output(&output.stdout, ctx.target.url.as_str()))
    }
}

fn parse_amass_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut subdomains = Vec::new();

    for line in output.lines() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(name) = json["name"].as_str() {
                if !subdomains.contains(&name.to_string()) {
                    subdomains.push(name.to_string());
                }
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
                "amass",
                Severity::Info,
                format!("{count} Subdomains Found (Amass)"),
                format!("Amass found {count} subdomains via passive enumeration."),
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

    /// Tests for Amass JSON-lines output parser.

    /// Verify that `parse_amass_output` correctly aggregates subdomains
    /// from Amass JSON-lines output into a consolidated finding.
    #[test]
    fn test_parse_amass_output() {
        let output = r#"{"name":"api.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4"}]}
{"name":"mail.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.5"}]}
{"name":"api.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4"}]}"#;

        let findings = parse_amass_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("2 Subdomains"));
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// Verify that `parse_amass_output` handles empty input gracefully.
    #[test]
    fn test_parse_amass_output_empty() {
        let findings = parse_amass_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
