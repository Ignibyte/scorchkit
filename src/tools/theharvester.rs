use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;
use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug)]
pub struct TheHarvesterModule;

#[async_trait]
impl ScanModule for TheHarvesterModule {
    fn name(&self) -> &'static str {
        "theHarvester OSINT"
    }
    fn id(&self) -> &'static str {
        "theharvester"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Email and subdomain harvesting via theHarvester"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("theHarvester")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let domain = ctx.target.domain.as_deref().ok_or_else(|| ScorchError::InvalidTarget {
            target: ctx.target.raw.clone(),
            reason: "no domain".to_string(),
        })?;

        let output = subprocess::run_tool(
            "theHarvester",
            &["-d", domain, "-b", "crtsh,dnsdumpster,hackertarget", "-f", "/dev/stdout"],
            Duration::from_secs(120),
        )
        .await?;

        Ok(parse_harvester_output(&output.stdout, ctx.target.url.as_str()))
    }
}

fn parse_harvester_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut emails = Vec::new();
    let mut hosts = Vec::new();

    let mut section = "";
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains("[*] Emails found:") {
            section = "emails";
            continue;
        }
        if trimmed.contains("[*] Hosts found:") {
            section = "hosts";
            continue;
        }
        if trimmed.starts_with("[*]") {
            section = "";
            continue;
        }

        if !trimmed.is_empty() && !trimmed.starts_with('-') {
            match section {
                "emails" => {
                    if trimmed.contains('@') {
                        emails.push(trimmed.to_string());
                    }
                }
                "hosts" => {
                    hosts.push(trimmed.to_string());
                }
                _ => {}
            }
        }
    }

    if !emails.is_empty() {
        findings.push(
            Finding::new(
                "theharvester",
                Severity::Info,
                format!("{} Emails Found", emails.len()),
                "theHarvester found publicly exposed email addresses.",
                target_url,
            )
            .with_evidence(format!("Emails:\n    {}", emails.join("\n    ")))
            .with_confidence(0.6),
        );
    }
    if !hosts.is_empty() {
        findings.push(
            Finding::new(
                "theharvester",
                Severity::Info,
                format!("{} Hosts Found", hosts.len()),
                "theHarvester found associated hosts.",
                target_url,
            )
            .with_evidence(format!("Hosts:\n    {}", hosts.join("\n    ")))
            .with_confidence(0.6),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for theHarvester section-based text output parser.

    /// Verify that `parse_harvester_output` correctly extracts emails and
    /// hosts from theHarvester section-delimited text output.
    #[test]
    fn test_parse_harvester_output() {
        let output = "\
[*] Emails found:\n\
admin@example.com\n\
contact@example.com\n\
[*] Hosts found:\n\
www.example.com:1.2.3.4\n\
mail.example.com:1.2.3.5\n\
[*] Done\n";

        let findings = parse_harvester_output(output, "https://example.com");
        assert_eq!(findings.len(), 2);
        let emails = findings.iter().find(|f| f.title.contains("Emails"));
        assert!(emails.is_some());
        assert!(emails.expect("email finding should exist").title.contains("2 Emails"));
        let hosts = findings.iter().find(|f| f.title.contains("Hosts"));
        assert!(hosts.is_some());
    }

    /// Verify that `parse_harvester_output` handles empty input gracefully.
    #[test]
    fn test_parse_harvester_output_empty() {
        let findings = parse_harvester_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
