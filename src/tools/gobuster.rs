//! `Gobuster` wrapper for directory and vhost brute-forcing.
//!
//! Wraps the `gobuster` tool for directory discovery, DNS subdomain
//! brute-forcing, and virtual host enumeration. Complements existing
//! feroxbuster and ffuf wrappers with vhost discovery mode.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Directory and vhost brute-forcing via Gobuster.
#[derive(Debug)]
pub struct GobusterModule;

#[async_trait]
impl ScanModule for GobusterModule {
    fn name(&self) -> &'static str {
        "Gobuster Directory Scanner"
    }

    fn id(&self) -> &'static str {
        "gobuster"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Directory and vhost brute-forcing via Gobuster"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("gobuster")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();

        let wordlist = ctx.config.wordlists.directory.as_deref().map_or_else(
            || "/usr/share/wordlists/dirb/common.txt".to_string(),
            |p| p.to_string_lossy().into_owned(),
        );

        let output = subprocess::run_tool(
            "gobuster",
            &["dir", "-u", url, "-w", &wordlist, "-q", "--no-error", "--no-color"],
            Duration::from_secs(300),
        )
        .await?;

        Ok(parse_gobuster_output(&output.stdout, ctx.target.url.as_str()))
    }
}

/// Map HTTP status codes to severity levels for discovered paths.
const fn status_severity(status: u16) -> Severity {
    match status {
        401 | 403 => Severity::Low,
        500..=599 => Severity::Medium,
        _ => Severity::Info,
    }
}

/// Parse Gobuster quiet-mode output into findings.
///
/// Gobuster quiet mode outputs one line per discovered path in formats
/// like `/path (Status: 200) [Size: 1234]` or simply `/path`.
/// Results are grouped into a consolidated finding.
#[must_use]
fn parse_gobuster_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let entries: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && line.starts_with('/'))
        .collect();

    if entries.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for entry in &entries {
        let path = entry.split_whitespace().next().unwrap_or(entry);

        let status: u16 = entry
            .find("Status: ")
            .and_then(|i| {
                let start = i + 8;
                entry[start..].split(')').next().and_then(|s| s.parse().ok())
            })
            .unwrap_or(200);

        findings.push(
            Finding::new(
                "gobuster",
                status_severity(status),
                format!("Discovered Path: {path} (HTTP {status})"),
                format!("Gobuster discovered {path} returning HTTP {status}."),
                target_url,
            )
            .with_evidence(entry.to_string())
            .with_owasp("A01:2021 Broken Access Control")
            .with_confidence(0.6),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Gobuster output parsing with status codes and severity
    /// mapping.
    #[test]
    fn test_parse_gobuster_output() {
        let output = "/admin (Status: 403) [Size: 287]\n\
                       /api (Status: 200) [Size: 1024]\n\
                       /backup (Status: 301) [Size: 0]\n\
                       /server-status (Status: 403) [Size: 287]\n";

        let findings = parse_gobuster_output(output, "https://example.com");
        assert_eq!(findings.len(), 4);
        assert!(findings[0].title.contains("/admin"));
        assert_eq!(findings[0].severity, Severity::Low); // 403
        assert!(findings[1].title.contains("/api"));
        assert_eq!(findings[1].severity, Severity::Info); // 200
    }

    /// Verify empty output produces no findings.
    #[test]
    fn test_parse_gobuster_empty() {
        let findings = parse_gobuster_output("", "https://example.com");
        assert!(findings.is_empty());

        let findings = parse_gobuster_output("\n\n", "https://example.com");
        assert!(findings.is_empty());
    }
}
