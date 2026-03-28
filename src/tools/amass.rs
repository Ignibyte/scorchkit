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

        parse_amass_output(&output.stdout, ctx.target.url.as_str())
    }
}

fn parse_amass_output(output: &str, target_url: &str) -> Result<Vec<Finding>> {
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
            .with_evidence(format!("Subdomains:\n    {list}")),
        );
    }

    Ok(findings)
}
