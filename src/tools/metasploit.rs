use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Exploit validation via Metasploit auxiliary scanners.
#[derive(Debug)]
pub struct MetasploitModule;

#[async_trait]
impl ScanModule for MetasploitModule {
    fn name(&self) -> &'static str {
        "Metasploit Scanner"
    }
    fn id(&self) -> &'static str {
        "metasploit"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Exploit validation via Metasploit auxiliary modules"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("msfconsole")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());
        let port = ctx.target.port.to_string();

        // Run a set of safe auxiliary scanner modules
        let rc_commands = format!(
            "use auxiliary/scanner/http/http_version; set RHOSTS {target}; set RPORT {port}; set SSL {ssl}; run;\
             use auxiliary/scanner/http/options; set RHOSTS {target}; set RPORT {port}; set SSL {ssl}; run;\
             use auxiliary/scanner/http/robots_txt; set RHOSTS {target}; set RPORT {port}; set SSL {ssl}; run;\
             exit",
            ssl = if ctx.target.is_https { "true" } else { "false" },
        );

        let output = subprocess::run_tool(
            "msfconsole",
            &["-q", "-x", &rc_commands],
            Duration::from_secs(120),
        )
        .await?;

        Ok(parse_msf_output(&output.stdout, ctx.target.url.as_str()))
    }
}

fn parse_msf_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        // Metasploit uses [+] for positive results, [*] for info, [-] for negative
        if trimmed.starts_with("[+]") {
            let msg = trimmed.trim_start_matches("[+]").trim();
            let severity = if msg.to_lowercase().contains("vulnerable") {
                Severity::Critical
            } else {
                Severity::Medium
            };

            findings.push(
                Finding::new("metasploit", severity, format!("MSF: {msg}"), msg, target_url)
                    .with_evidence(trimmed.to_string())
                    .with_confidence(0.9),
            );
        } else if trimmed.starts_with("[*]") && trimmed.len() > 10 {
            let msg = trimmed.trim_start_matches("[*]").trim();

            // Only include interesting info lines
            let lower = msg.to_lowercase();
            if lower.contains("detected")
                || lower.contains("found")
                || lower.contains("version")
                || lower.contains("server")
            {
                findings.push(
                    Finding::new(
                        "metasploit",
                        Severity::Info,
                        format!("MSF: {msg}"),
                        msg,
                        target_url,
                    )
                    .with_evidence(trimmed.to_string())
                    .with_confidence(0.9),
                );
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for Metasploit console output parser.

    /// Verify that `parse_msf_output` correctly extracts positive results
    /// and informational lines from Metasploit output.
    #[test]
    fn test_parse_msf_output() {
        let output = "\
[*] Detected Apache/2.4.49 on port 80\n\
[+] Found vulnerable endpoint\n\
[-] No session created\n\
[*] Scanned 1 host\n";

        let findings = parse_msf_output(output, "https://example.com");
        assert_eq!(findings.len(), 2);
        // [+] line -> Medium (contains "vulnerable" -> Critical)
        let positive = findings.iter().find(|f| f.title.contains("vulnerable"));
        assert!(positive.is_some());
        assert_eq!(positive.expect("positive finding should exist").severity, Severity::Critical);
        // [*] Detected -> Info
        let info = findings.iter().find(|f| f.title.contains("Detected"));
        assert!(info.is_some());
        assert_eq!(info.expect("info finding should exist").severity, Severity::Info);
    }

    /// Verify that `parse_msf_output` handles empty input gracefully.
    #[test]
    fn test_parse_msf_output_empty() {
        let findings = parse_msf_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
