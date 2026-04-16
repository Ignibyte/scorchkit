//! `naabu` wrapper — `ProjectDiscovery` port scanner.
//!
//! Wraps [naabu](https://github.com/projectdiscovery/naabu) — the
//! `ProjectDiscovery` port scanner that pairs naturally with the
//! existing wrappers we ship for `httpx`, `katana`, and `nuclei`.
//! Use over `masscan` when you want a smaller dependency footprint
//! and the standard top-1000-port sweep.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Port scanner via naabu.
#[derive(Debug)]
pub struct NaabuModule;

#[async_trait]
impl ScanModule for NaabuModule {
    fn name(&self) -> &'static str {
        "naabu Port Scanner"
    }

    fn id(&self) -> &'static str {
        "naabu"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Port scanner (top 1000 ports) against target host"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("naabu")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let host = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());
        let output = subprocess::run_tool(
            "naabu",
            &["-host", host, "-top-ports", "1000", "-silent", "-json"],
            Duration::from_secs(180),
        )
        .await?;
        Ok(parse_naabu_output(&output.stdout, ctx.target.url.as_str(), host))
    }
}

/// Parse naabu JSON-Lines output into findings.
///
/// Each line is a JSON object like `{"host":"x","ip":"y","port":80,
/// "protocol":"tcp"}`. Aggregates into a single Info finding listing
/// the open ports.
#[must_use]
fn parse_naabu_output(stdout: &str, target_url: &str, host: &str) -> Vec<Finding> {
    let ports: Vec<u16> = stdout
        .lines()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
            v["port"].as_u64().and_then(|n| u16::try_from(n).ok())
        })
        .collect();
    if ports.is_empty() {
        return Vec::new();
    }
    let count = ports.len();
    let sample: Vec<String> = ports.iter().take(20).map(u16::to_string).collect();
    vec![Finding::new(
        "naabu",
        Severity::Info,
        format!("naabu: {count} TCP port(s) open on {host}"),
        format!("naabu reported {count} open TCP port(s). Sample: {}", sample.join(", ")),
        target_url,
    )
    .with_evidence(format!("Open ports: {}", sample.join(", ")))
    .with_remediation("Audit each exposed service; close ports that don't need to be public.")
    .with_owasp("A05:2021 Security Misconfiguration")
    .with_confidence(0.9)]
}

#[cfg(test)]
mod tests {
    //! Coverage for naabu JSON-Lines parser.
    use super::*;

    /// Real-shape naabu output with three ports yields one consolidated
    /// finding.
    #[test]
    fn parse_naabu_output_extracts_ports() {
        let stdout = "{\"host\":\"example.com\",\"ip\":\"1.2.3.4\",\"port\":22,\"protocol\":\"tcp\"}\n\
                      {\"host\":\"example.com\",\"ip\":\"1.2.3.4\",\"port\":80,\"protocol\":\"tcp\"}\n\
                      {\"host\":\"example.com\",\"ip\":\"1.2.3.4\",\"port\":443,\"protocol\":\"tcp\"}\n";
        let findings = parse_naabu_output(stdout, "https://example.com", "example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("3 TCP port"));
    }

    /// Empty output yields no findings.
    #[test]
    fn parse_naabu_output_empty() {
        assert!(parse_naabu_output("", "https://example.com", "example.com").is_empty());
    }
}
