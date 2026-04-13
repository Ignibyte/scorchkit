//! `Gau` (`GetAllUrls`) wrapper for passive URL discovery.
//!
//! Wraps the `gau` tool which discovers historical URLs from Wayback
//! Machine, Common Crawl, `URLScan`, and other passive sources. Does not
//! actively crawl — purely passive reconnaissance.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Passive URL discovery via Gau (Wayback Machine, Common Crawl).
#[derive(Debug)]
pub struct GauModule;

#[async_trait]
impl ScanModule for GauModule {
    fn name(&self) -> &'static str {
        "Gau Passive URLs"
    }

    fn id(&self) -> &'static str {
        "gau"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Passive URL discovery from Wayback Machine, Common Crawl, and other sources"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("gau")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let domain = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());

        let output =
            subprocess::run_tool("gau", &["--subs", domain], Duration::from_secs(120)).await?;

        Ok(parse_gau_output(&output.stdout, ctx.target.url.as_str()))
    }
}

/// Parse Gau plain-text output (one URL per line) into a consolidated finding.
#[must_use]
fn parse_gau_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let urls: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && line.starts_with("http"))
        .collect();

    if urls.is_empty() {
        return Vec::new();
    }

    let count = urls.len();
    let sample: Vec<&str> = urls.iter().copied().take(10).collect();

    vec![Finding::new(
        "gau",
        Severity::Info,
        format!("Gau: {count} Historical URLs Discovered"),
        format!(
            "Gau discovered {count} historical URLs from passive sources \
             (Wayback Machine, Common Crawl, etc.). Sample: {}",
            sample.join(", ")
        ),
        target_url,
    )
    .with_evidence(format!("{count} passive URLs discovered"))
    .with_owasp("A05:2021 Security Misconfiguration")
    .with_confidence(0.6)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Gau plain-text output parsing.
    #[test]
    fn test_parse_gau_output() {
        let output = "https://example.com/login\n\
                       https://example.com/api/v1/users\n\
                       https://example.com/old-admin\n\
                       https://example.com/backup.zip\n";

        let findings = parse_gau_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("4 Historical"));
    }

    /// Verify empty output produces no findings.
    #[test]
    fn test_parse_gau_empty() {
        let findings = parse_gau_output("", "https://example.com");
        assert!(findings.is_empty());

        let findings = parse_gau_output("\n\n", "https://example.com");
        assert!(findings.is_empty());
    }
}
