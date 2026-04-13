//! `DNSx` wrapper for fast DNS resolution and record queries.
//!
//! Wraps `ProjectDiscovery`'s `dnsx` tool for fast DNS resolution,
//! wildcard detection, and multi-record-type queries. Complements
//! the built-in subdomain module and amass/subfinder wrappers.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Fast DNS resolution and record queries via `DNSx`.
#[derive(Debug)]
pub struct DnsxModule;

#[async_trait]
impl ScanModule for DnsxModule {
    fn name(&self) -> &'static str {
        "DNSx DNS Toolkit"
    }

    fn id(&self) -> &'static str {
        "dnsx"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Fast DNS resolution, wildcard detection, and record queries via DNSx"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("dnsx")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let domain = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());

        let output = subprocess::run_tool(
            "dnsx",
            &["-silent", "-resp", "-d", domain],
            Duration::from_secs(120),
        )
        .await?;

        Ok(parse_dnsx_output(&output.stdout, ctx.target.url.as_str()))
    }
}

/// Parse `DNSx` plain-text output into a consolidated finding.
///
/// `DNSx` outputs one line per resolved record in the format:
/// `domain [IP/record]`. Results are consolidated into a single
/// finding with count and sample records.
#[must_use]
fn parse_dnsx_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let records: Vec<&str> =
        stdout.lines().map(str::trim).filter(|line| !line.is_empty()).collect();

    if records.is_empty() {
        return Vec::new();
    }

    let count = records.len();
    let sample: Vec<&str> = records.iter().copied().take(10).collect();

    vec![Finding::new(
        "dnsx",
        Severity::Info,
        format!("DNSx: {count} DNS Records Resolved"),
        format!(
            "DNSx resolved {count} DNS records for the target domain. \
             Sample: {}",
            sample.join(", ")
        ),
        target_url,
    )
    .with_evidence(format!("{count} DNS records resolved"))
    .with_owasp("A05:2021 Security Misconfiguration")
    .with_confidence(0.8)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify DNSx plain-text output parsing into consolidated finding.
    #[test]
    fn test_parse_dnsx_output() {
        let output = "example.com [93.184.216.34]\n\
                       www.example.com [93.184.216.34]\n\
                       mail.example.com [93.184.216.35]\n";

        let findings = parse_dnsx_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("3 DNS Records"));
    }

    /// Verify empty output produces no findings.
    #[test]
    fn test_parse_dnsx_empty() {
        let findings = parse_dnsx_output("", "https://example.com");
        assert!(findings.is_empty());

        let findings = parse_dnsx_output("\n\n", "https://example.com");
        assert!(findings.is_empty());
    }
}
