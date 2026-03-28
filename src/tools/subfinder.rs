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

        parse_subfinder_output(&output.stdout, ctx.target.url.as_str())
    }
}

fn parse_subfinder_output(output: &str, target_url: &str) -> Result<Vec<Finding>> {
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
            .with_evidence(format!("Subdomains:\n    {list}")),
        );
    }

    Ok(findings)
}
