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

        Ok(parse_cewl_output(&output.stdout, target))
    }
}

fn parse_cewl_output(output: &str, target_url: &str) -> Vec<Finding> {
    let words: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut findings = Vec::new();

    if !words.is_empty() {
        let count = words.len();
        let sample: Vec<&&str> = words.iter().take(20).collect();

        findings.push(
            Finding::new("cewl", Severity::Info, format!("{count} Words Extracted from Target"), format!("CeWL extracted {count} unique words from the target. These can be used for targeted password attacks."), target_url)
                .with_evidence(format!("Sample words: {}", sample.iter().map(|w| **w).collect::<Vec<_>>().join(", ")))
                .with_confidence(0.5),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for CeWL wordlist output parser.

    /// Verify that `parse_cewl_output` correctly counts extracted words
    /// and includes a sample in the evidence.
    #[test]
    fn test_parse_cewl_output() {
        let output = "password\nadministrator\nexample\nlogin\nsecurity\n";

        let findings = parse_cewl_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("5 Words"));
        assert_eq!(findings[0].severity, Severity::Info);
        let evidence = findings[0].evidence.as_deref().unwrap_or("");
        assert!(evidence.contains("password"));
    }

    /// Verify that `parse_cewl_output` handles empty input gracefully.
    #[test]
    fn test_parse_cewl_output_empty() {
        let findings = parse_cewl_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
