//! `dnsrecon` wrapper for comprehensive DNS enumeration.
//!
//! Wraps the `dnsrecon` tool for DNS enumeration including zone transfers,
//! reverse lookups, SRV record discovery, and brute-force subdomain
//! enumeration. Complements the built-in DNS recon module with deeper
//! DNS analysis capabilities.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Comprehensive DNS enumeration via dnsrecon.
#[derive(Debug)]
pub struct DnsreconModule;

#[async_trait]
impl ScanModule for DnsreconModule {
    fn name(&self) -> &'static str {
        "dnsrecon DNS Enumerator"
    }

    fn id(&self) -> &'static str {
        "dnsrecon"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Comprehensive DNS enumeration: zone transfers, reverse lookups, SRV records via dnsrecon"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("dnsrecon")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let domain = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());

        let output = subprocess::run_tool(
            "dnsrecon",
            &["-d", domain, "-t", "std", "--json", "-"],
            Duration::from_secs(180),
        )
        .await?;

        Ok(parse_dnsrecon_output(&output.stdout, ctx.target.url.as_str()))
    }
}

/// Parse dnsrecon JSON output into findings.
///
/// dnsrecon outputs a JSON array of record objects, each with a `type`
/// field (A, AAAA, MX, NS, SOA, TXT, CNAME, SRV) and record-specific
/// fields like `name`, `address`, and `target`. Zone transfer results
/// are flagged as Medium severity.
#[must_use]
fn parse_dnsrecon_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(records) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) else {
        return Vec::new();
    };

    if records.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Check for zone transfer results
    let has_zone_transfer = records.iter().any(|r| {
        r["type"].as_str() == Some("info") && {
            let info = r["info"].as_str().unwrap_or("");
            info.contains("Zone Transfer") || info.contains("AXFR")
        }
    });

    if has_zone_transfer {
        findings.push(
            Finding::new(
                "dnsrecon",
                Severity::Medium,
                "DNS Zone Transfer Possible".to_string(),
                "dnsrecon detected that DNS zone transfer (AXFR) is allowed. \
                 This exposes all DNS records for the domain."
                    .to_string(),
                target_url,
            )
            .with_evidence("Zone transfer (AXFR) succeeded")
            .with_remediation("Restrict zone transfers to authorized secondary nameservers only.")
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(200)
            .with_confidence(0.8),
        );
    }

    // Consolidate regular DNS records
    let dns_records: Vec<&serde_json::Value> = records
        .iter()
        .filter(|r| {
            matches!(
                r["type"].as_str(),
                Some("A" | "AAAA" | "MX" | "NS" | "SOA" | "TXT" | "CNAME" | "SRV" | "PTR")
            )
        })
        .collect();

    if !dns_records.is_empty() {
        let count = dns_records.len();
        let sample: Vec<String> = dns_records
            .iter()
            .take(10)
            .map(|r| {
                let rtype = r["type"].as_str().unwrap_or("?");
                let name = r["name"].as_str().unwrap_or("?");
                let addr = r["address"].as_str().or_else(|| r["target"].as_str()).unwrap_or("?");
                format!("{rtype}: {name} -> {addr}")
            })
            .collect();

        findings.push(
            Finding::new(
                "dnsrecon",
                Severity::Info,
                format!("dnsrecon: {count} DNS Records Enumerated"),
                format!("dnsrecon enumerated {count} DNS records. Sample: {}", sample.join("; ")),
                target_url,
            )
            .with_evidence(format!("{count} DNS records enumerated"))
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_confidence(0.8),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify dnsrecon JSON output parsing with DNS records and zone
    /// transfer detection.
    #[test]
    fn test_parse_dnsrecon_output() {
        let output = r#"[
            {"type": "A", "name": "example.com", "address": "93.184.216.34"},
            {"type": "MX", "name": "example.com", "target": "mail.example.com", "address": "10"},
            {"type": "NS", "name": "example.com", "target": "ns1.example.com", "address": "1.2.3.4"},
            {"type": "TXT", "name": "example.com", "address": "v=spf1 include:example.com ~all"}
        ]"#;

        let findings = parse_dnsrecon_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("4 DNS Records"));
    }

    /// Verify empty output produces no findings.
    #[test]
    fn test_parse_dnsrecon_empty() {
        let findings = parse_dnsrecon_output("", "https://example.com");
        assert!(findings.is_empty());

        let findings = parse_dnsrecon_output("[]", "https://example.com");
        assert!(findings.is_empty());
    }
}
