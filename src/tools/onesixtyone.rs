//! `onesixtyone` wrapper — fast SNMP scanner.
//!
//! Wraps [onesixtyone](https://github.com/trailofbits/onesixtyone) to
//! probe the target host for SNMP v1/v2c with a small built-in
//! community-string list (`public`, `private`, `community`,
//! `manager`, `admin`). Successful auth surfaces as a High finding —
//! SNMP read access leaks routing tables, ARP caches, running
//! processes, and (with write) is a direct foothold.

use std::io::Write as _;
use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Built-in community-string list. Operators with their own lists
/// invoke onesixtyone directly.
const DEFAULT_COMMUNITIES: &[&str] = &["public", "private", "community", "manager", "admin"];

/// SNMP scanner via onesixtyone.
#[derive(Debug)]
pub struct OnesixtyoneModule;

#[async_trait]
impl ScanModule for OnesixtyoneModule {
    fn name(&self) -> &'static str {
        "onesixtyone SNMP Scanner"
    }

    fn id(&self) -> &'static str {
        "onesixtyone"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Probe SNMP v1/v2c with a small default community-string list"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("onesixtyone")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let host = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());
        let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
            return Ok(Vec::new());
        };
        for c in DEFAULT_COMMUNITIES {
            if writeln!(tmp, "{c}").is_err() {
                return Ok(Vec::new());
            }
        }
        let path = tmp.path().to_string_lossy().to_string();
        // onesixtyone -c <community-file> <host>
        let output =
            subprocess::run_tool("onesixtyone", &["-c", &path, host], Duration::from_secs(45))
                .await?;
        Ok(parse_onesixtyone_output(&output.stdout, ctx.target.url.as_str(), host))
    }
}

/// Parse onesixtyone output into findings.
///
/// Each successful response prints a line like
/// `1.2.3.4 [public] System description ...`. We collect every
/// successful community string and emit one High finding listing
/// them all.
#[must_use]
fn parse_onesixtyone_output(stdout: &str, target_url: &str, host: &str) -> Vec<Finding> {
    let communities: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.contains('[') || !trimmed.contains(']') {
                return None;
            }
            let start = trimmed.find('[')? + 1;
            let end = trimmed.find(']')?;
            if start >= end {
                return None;
            }
            Some(trimmed[start..end].to_string())
        })
        .collect();
    if communities.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "onesixtyone",
        Severity::High,
        format!("SNMP accessible with default community string(s) on {host}"),
        format!(
            "onesixtyone successfully queried SNMP using {} default community string(s). \
             SNMP read access leaks system info, routing tables, ARP caches, and running \
             processes; write access is a direct foothold.",
            communities.len()
        ),
        target_url,
    )
    .with_evidence(format!("Working communities: {}", communities.join(", ")))
    .with_remediation(
        "Disable SNMP v1/v2c; if SNMP is required, use SNMPv3 with auth + privacy and \
         a strong, random community string.",
    )
    .with_owasp("A05:2021 Security Misconfiguration")
    .with_cwe(521)
    .with_confidence(0.95)]
}

#[cfg(test)]
mod tests {
    //! Coverage for onesixtyone output parser.
    use super::*;

    /// Output with two working communities yields one consolidated
    /// High finding listing both.
    #[test]
    fn parse_onesixtyone_output_default_communities() {
        let stdout = "1.2.3.4 [public] Linux router 5.10.0\n\
                      1.2.3.4 [private] Linux router 5.10.0\n";
        let findings = parse_onesixtyone_output(stdout, "https://example.com", "example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].evidence.as_ref().unwrap().contains("public"));
        assert!(findings[0].evidence.as_ref().unwrap().contains("private"));
    }

    /// No-response output yields zero findings.
    #[test]
    fn parse_onesixtyone_output_empty() {
        assert!(parse_onesixtyone_output("", "https://example.com", "example.com").is_empty());
        assert!(parse_onesixtyone_output(
            "Scanning 1 hosts...\n",
            "https://example.com",
            "example.com"
        )
        .is_empty());
    }

    /// Default community list invariant: at least 5 names.
    #[test]
    fn default_communities_invariant() {
        assert!(DEFAULT_COMMUNITIES.len() >= 5);
        assert!(DEFAULT_COMMUNITIES.contains(&"public"));
        assert!(DEFAULT_COMMUNITIES.contains(&"private"));
    }
}
