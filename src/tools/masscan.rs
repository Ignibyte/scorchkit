//! `masscan` wrapper — high-speed TCP port scanner.
//!
//! Wraps [masscan](https://github.com/robertdavidgraham/masscan) for
//! large-CIDR port sweeps. Orders of magnitude faster than `nmap`
//! when probing `/16` or larger ranges. Default rate is conservative
//! (1k pps) to stay polite — operators who own the target network
//! can tune it via the `--rate` arg if they invoke the tool directly.
//!
//!
//! Pairs naturally with the v2.0 infra modules: feed masscan's open
//! ports into the existing nmap (fingerprint) + `cve_match` pipeline.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Mass TCP port scanner via masscan.
#[derive(Debug)]
pub struct MasscanModule;

#[async_trait]
impl ScanModule for MasscanModule {
    fn name(&self) -> &'static str {
        "masscan Port Scanner"
    }

    fn id(&self) -> &'static str {
        "masscan"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "High-speed TCP port scan against the target host (top 1000 ports)"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("masscan")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let host = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());
        let output = subprocess::run_tool(
            "masscan",
            &[host, "-p0-1023", "--rate", "1000", "-oG", "-"],
            Duration::from_secs(180),
        )
        .await?;
        Ok(parse_masscan_output(&output.stdout, ctx.target.url.as_str(), host))
    }
}

/// Parse masscan's `-oG` (greppable) output into findings.
///
/// Format per-line: `Host: <ip> ()  Ports: <port>/open/tcp//<service>///`
/// Ignores comment lines starting with `#`.
#[must_use]
fn parse_masscan_output(stdout: &str, target_url: &str, host: &str) -> Vec<Finding> {
    let ports: Vec<u16> = stdout
        .lines()
        .filter(|line| !line.trim().starts_with('#') && line.contains("Ports:"))
        .filter_map(|line| {
            let after = line.split("Ports:").nth(1)?.trim();
            let token = after.split('/').next()?;
            token.parse::<u16>().ok()
        })
        .collect();
    if ports.is_empty() {
        return Vec::new();
    }
    let count = ports.len();
    let sample: Vec<String> = ports.iter().take(20).map(u16::to_string).collect();
    vec![Finding::new(
        "masscan",
        Severity::Info,
        format!("masscan: {count} TCP port(s) open on {host}"),
        format!("masscan reported {count} open TCP port(s). Sample: {}", sample.join(", ")),
        target_url,
    )
    .with_evidence(format!("Open ports: {}", sample.join(", ")))
    .with_remediation("Audit each exposed service; close ports that don't need to be public.")
    .with_owasp("A05:2021 Security Misconfiguration")
    .with_confidence(0.9)]
}

#[cfg(test)]
mod tests {
    //! Coverage for the greppable-output parser. Pins the wire format
    //! masscan emits with `-oG -`.
    use super::*;

    /// Real-shape masscan output with two open ports yields one
    /// consolidated finding listing both.
    #[test]
    fn parse_masscan_output_extracts_ports() {
        let stdout = "# Masscan 1.3.2 scan output\n\
            Host: 1.2.3.4 () Ports: 22/open/tcp//ssh///\n\
            Host: 1.2.3.4 () Ports: 443/open/tcp//https///\n\
            # end\n";
        let findings = parse_masscan_output(stdout, "https://example.com", "example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("2 TCP port"));
        assert!(findings[0].evidence.as_ref().unwrap().contains("22"));
        assert!(findings[0].evidence.as_ref().unwrap().contains("443"));
    }

    /// Empty output (no open ports) yields zero findings.
    #[test]
    fn parse_masscan_output_empty() {
        assert!(parse_masscan_output("", "https://example.com", "example.com").is_empty());
        assert!(parse_masscan_output(
            "# nothing\n# more comments\n",
            "https://example.com",
            "example.com"
        )
        .is_empty());
    }
}
