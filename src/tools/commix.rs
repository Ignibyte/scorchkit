//! `commix` wrapper — advanced command-injection scanner.
//!
//! Wraps [commix](https://github.com/commixproject/commix) — the
//! go-to tool for command-injection exploitation. Complements
//! `ScorchKit`'s built-in `cmdi` scanner (which performs detection
//! only) with deeper exploitation primitives.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Command-injection scanner via commix.
#[derive(Debug)]
pub struct CommixModule;

#[async_trait]
impl ScanModule for CommixModule {
    fn name(&self) -> &'static str {
        "commix Command-Injection Scanner"
    }
    fn id(&self) -> &'static str {
        "commix"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Advanced command-injection detection + exploitation via commix"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("commix")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let output = subprocess::run_tool_lenient(
            "commix",
            &["-u", url, "--batch", "--skip-waf"],
            Duration::from_secs(180),
        )
        .await?;
        Ok(parse_commix_output(&output.stdout, url))
    }
}

/// Parse commix text output for vulnerability indicators.
///
/// commix prints `[+]` lines on success: `(!) Vulnerable parameter`,
/// `[+] Type:`, `[+] Technique:`. We aggregate any positive
/// detection into a single High finding (commix is high-confidence
/// when it says vulnerable).
#[must_use]
fn parse_commix_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let vuln_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("[+]") && l.to_lowercase().contains("vulnerable"))
        .collect();
    if vuln_lines.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "commix",
        Severity::High,
        format!("commix: command injection confirmed on {target_url}"),
        "commix successfully demonstrated command-injection exploitation against the target. \
         An attacker can execute arbitrary commands on the underlying host."
            .to_string(),
        target_url,
    )
    .with_evidence(vuln_lines.join(" | "))
    .with_remediation(
        "Treat all user input as untrusted; never pass it to a shell. Use parameterised \
         APIs and strict allow-lists for external command invocations.",
    )
    .with_owasp("A03:2021 Injection")
    .with_cwe(78)
    .with_confidence(0.95)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_commix_output_vulnerable() {
        let stdout = "[*] Testing parameters\n\
                      [+] The (POST) parameter 'cmd' seems vulnerable\n\
                      [+] Type: results-based command injection\n";
        let findings = parse_commix_output(stdout, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn parse_commix_output_not_vulnerable() {
        let stdout = "[*] Testing parameters\n[*] No vulnerabilities detected\n";
        assert!(parse_commix_output(stdout, "https://example.com").is_empty());
    }

    #[test]
    fn parse_commix_output_empty() {
        assert!(parse_commix_output("", "https://example.com").is_empty());
    }
}
