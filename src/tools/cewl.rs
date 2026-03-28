use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;
use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug)]
pub struct CewlModule;

#[async_trait]
impl ScanModule for CewlModule {
    fn name(&self) -> &'static str {
        "CeWL Wordlist Generator"
    }
    fn id(&self) -> &'static str {
        "cewl"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Custom wordlist generation from target content via CeWL"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("cewl")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();
        let output = subprocess::run_tool(
            "cewl",
            &[target, "-d", "2", "-m", "5", "--with-numbers"],
            Duration::from_secs(120),
        )
        .await?;

        parse_cewl_output(&output.stdout, target)
    }
}

fn parse_cewl_output(output: &str, target_url: &str) -> Result<Vec<Finding>> {
    let words: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut findings = Vec::new();

    if !words.is_empty() {
        let count = words.len();
        let sample: Vec<&&str> = words.iter().take(20).collect();

        findings.push(
            Finding::new("cewl", Severity::Info, format!("{count} Words Extracted from Target"), format!("CeWL extracted {count} unique words from the target. These can be used for targeted password attacks."), target_url)
                .with_evidence(format!("Sample words: {}", sample.iter().map(|w| **w).collect::<Vec<_>>().join(", "))),
        );
    }

    Ok(findings)
}
