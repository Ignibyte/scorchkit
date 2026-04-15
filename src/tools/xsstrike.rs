//! `xsstrike` wrapper — advanced XSS scanner.
//!
//! Wraps [XSStrike](https://github.com/s0md3v/XSStrike) for
//! advanced XSS detection (DOM, reflected, stored, blind, WAF
//! bypass). Alternative to `dalfox`.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// XSS scanner via `XSStrike`.
#[derive(Debug)]
pub struct XsstrikeModule;

#[async_trait]
impl ScanModule for XsstrikeModule {
    fn name(&self) -> &'static str {
        "XSStrike XSS Scanner"
    }
    fn id(&self) -> &'static str {
        "xsstrike"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Advanced XSS scanning (reflected / DOM / blind) via XSStrike"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("xsstrike")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let output = subprocess::run_tool_lenient(
            "xsstrike",
            &["-u", url, "--skip"],
            Duration::from_secs(180),
        )
        .await?;
        Ok(parse_xsstrike_output(&output.stdout, url))
    }
}

#[must_use]
fn parse_xsstrike_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let payloads: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("Payload:") || l.contains("Vulnerable webpage:"))
        .collect();
    if !payloads.is_empty() {
        findings.push(
            Finding::new(
                "xsstrike",
                Severity::High,
                format!("XSStrike: XSS payload landed on {target_url}"),
                "XSStrike confirmed a cross-site scripting vulnerability with at least one \
                 working payload."
                    .to_string(),
                target_url,
            )
            .with_evidence(payloads.join(" | "))
            .with_remediation(
                "Encode all user-controlled output context-appropriately; deploy a strict CSP.",
            )
            .with_owasp("A03:2021 Injection")
            .with_cwe(79)
            .with_confidence(0.9),
        );
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xsstrike_output_with_payload() {
        let stdout = "[*] Checking for DOM XSS\n\
                      [+] Vulnerable webpage: https://example.com/?q=foo\n\
                      [+] Payload: <script>alert(1)</script>\n";
        let findings = parse_xsstrike_output(stdout, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn parse_xsstrike_output_clean() {
        let stdout = "[*] Checking for DOM XSS\n[*] No XSS vectors found\n";
        assert!(parse_xsstrike_output(stdout, "https://example.com").is_empty());
    }
}
