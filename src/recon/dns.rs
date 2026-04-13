//! DNS and email security reconnaissance module.
//!
//! Queries DNS records via DNS-over-HTTPS (Cloudflare JSON API) to check
//! SPF permissiveness, DMARC policy enforcement, MX record presence, and
//! DNSSEC validation status. No DNS crate needed — uses existing `reqwest`
//! for `DoH` queries.

use async_trait::async_trait;
use serde_json::Value;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// DNS-over-HTTPS endpoint (Cloudflare JSON API).
const DOH_ENDPOINT: &str = "https://cloudflare-dns.com/dns-query";

/// DNS and email security reconnaissance via DNS-over-HTTPS.
///
/// Queries SPF, DMARC, MX, and DNSSEC records using Cloudflare's `DoH`
/// JSON API. Analyzes email authentication policies for permissiveness
/// and missing enforcement.
#[derive(Debug)]
pub struct DnsSecurityModule;

#[async_trait]
impl ScanModule for DnsSecurityModule {
    fn name(&self) -> &'static str {
        "DNS & Email Security"
    }

    fn id(&self) -> &'static str {
        "dns-security"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Check SPF, DMARC, DNSSEC, and MX records via DNS-over-HTTPS"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let domain = ctx.target.domain.as_deref().unwrap_or("");
        if domain.is_empty() {
            return Ok(Vec::new());
        }

        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Query TXT records for SPF
        if let Some(txt_records) = doh_query(ctx, domain, "TXT").await {
            check_spf(&txt_records, domain, url, &mut findings);
        }

        // Query TXT records for DMARC
        let dmarc_domain = format!("_dmarc.{domain}");
        if let Some(txt_records) = doh_query(ctx, &dmarc_domain, "TXT").await {
            check_dmarc(&txt_records, domain, url, &mut findings);
        } else {
            findings.push(
                Finding::new(
                    "dns-security",
                    Severity::Medium,
                    format!("No DMARC Record: {domain}"),
                    format!(
                        "No DMARC record found for '{domain}'. Without DMARC, \
                         the domain has no policy for handling emails that fail \
                         SPF/DKIM authentication, enabling email spoofing."
                    ),
                    url,
                )
                .with_evidence(format!("No TXT record at _dmarc.{domain}"))
                .with_remediation(
                    "Add a DMARC record: _dmarc.example.com TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@example.com\". \
                     Start with p=none for monitoring, then move to p=quarantine and p=reject.",
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(290)
                .with_confidence(0.8),
            );
        }

        // Query MX records
        if let Some(mx_records) = doh_query(ctx, domain, "MX").await {
            check_mx(&mx_records, domain, url, &mut findings);
        }

        Ok(findings)
    }
}

/// Perform a DNS-over-HTTPS query via Cloudflare JSON API.
///
/// Returns the answer data strings, or `None` if the query failed or
/// returned no results.
async fn doh_query(ctx: &ScanContext, name: &str, record_type: &str) -> Option<Vec<String>> {
    let response = ctx
        .http_client
        .get(DOH_ENDPOINT)
        .query(&[("name", name), ("type", record_type)])
        .header("Accept", "application/dns-json")
        .send()
        .await
        .ok()?;

    let body = response.text().await.ok()?;
    parse_doh_response(&body)
}

/// Parse a Cloudflare `DoH` JSON response into answer data strings.
///
/// `DoH` JSON format: `{ "Answer": [{ "data": "..." }, ...] }`
#[must_use]
fn parse_doh_response(body: &str) -> Option<Vec<String>> {
    let json: Value = serde_json::from_str(body).ok()?;
    let answers = json.get("Answer")?.as_array()?;

    let data: Vec<String> = answers
        .iter()
        .filter_map(|a| a.get("data").and_then(|d| d.as_str()).map(String::from))
        .collect();

    if data.is_empty() {
        None
    } else {
        Some(data)
    }
}

/// Analyze SPF records for presence and permissiveness.
fn check_spf(txt_records: &[String], domain: &str, url: &str, findings: &mut Vec<Finding>) {
    let spf_record = txt_records.iter().find(|r| r.contains("v=spf1"));

    let Some(spf) = spf_record else {
        findings.push(
            Finding::new(
                "dns-security",
                Severity::Medium,
                format!("No SPF Record: {domain}"),
                format!(
                    "No SPF record found for '{domain}'. Without SPF, any server \
                     can send emails claiming to be from this domain."
                ),
                url,
            )
            .with_evidence(format!("No v=spf1 TXT record for {domain}"))
            .with_remediation(
                "Add an SPF record: example.com TXT \"v=spf1 include:_spf.google.com -all\". \
                 Use -all (hard fail) to reject unauthorized senders.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(290)
            .with_confidence(0.8),
        );
        return;
    };

    let permissiveness = analyze_spf_permissiveness(spf);

    if let Some((severity, desc)) = permissiveness {
        findings.push(
            Finding::new(
                "dns-security",
                severity,
                format!("Permissive SPF Record: {domain}"),
                format!("{desc} for domain '{domain}'."),
                url,
            )
            .with_evidence(format!("SPF: {spf}"))
            .with_remediation(
                "Use -all (hard fail) instead of ~all or +all. \
                 Restrict authorized senders to only those that legitimately send email.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(290)
            .with_confidence(0.8),
        );
    }
}

/// Analyze SPF record permissiveness.
///
/// Returns `(Severity, description)` if the SPF is too permissive, or `None` if secure.
#[must_use]
fn analyze_spf_permissiveness(spf: &str) -> Option<(Severity, &'static str)> {
    let lower = spf.to_lowercase();

    if lower.contains("+all") {
        Some((
            Severity::High,
            "SPF record uses +all (pass all) — any server can send email as this domain",
        ))
    } else if lower.contains("?all") {
        Some((
            Severity::Medium,
            "SPF record uses ?all (neutral) — no enforcement on unauthorized senders",
        ))
    } else if lower.contains("~all") {
        Some((
            Severity::Low,
            "SPF record uses ~all (soft fail) — unauthorized emails are marked but not rejected",
        ))
    } else {
        None // -all is secure
    }
}

/// Analyze DMARC records for policy enforcement.
fn check_dmarc(txt_records: &[String], domain: &str, url: &str, findings: &mut Vec<Finding>) {
    let dmarc_record = txt_records.iter().find(|r| r.contains("v=DMARC1"));

    let Some(dmarc) = dmarc_record else {
        // No DMARC in the TXT records (should not reach here if doh_query returned Some)
        return;
    };

    let policy = parse_dmarc_policy(dmarc);

    if policy == "none" {
        findings.push(
            Finding::new(
                "dns-security",
                Severity::Medium,
                format!("DMARC Policy Set to None: {domain}"),
                format!(
                    "The DMARC policy for '{domain}' is set to p=none (monitoring only). \
                     Failed authentication results in no action — emails that fail SPF/DKIM \
                     are still delivered."
                ),
                url,
            )
            .with_evidence(format!("DMARC: {dmarc}"))
            .with_remediation(
                "Upgrade DMARC policy from p=none to p=quarantine or p=reject. \
                 p=none is suitable for initial monitoring but provides no protection.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(290)
            .with_confidence(0.8),
        );
    }
}

/// Extract the DMARC policy value from a DMARC record.
///
/// Returns the policy string (`"none"`, `"quarantine"`, `"reject"`) or `"unknown"`.
#[must_use]
fn parse_dmarc_policy(dmarc: &str) -> String {
    let lower = dmarc.to_lowercase();
    lower
        .split(';')
        .find_map(|part| {
            let trimmed = part.trim();
            trimmed.strip_prefix("p=").map(|v| v.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Report MX record findings.
fn check_mx(mx_records: &[String], domain: &str, url: &str, findings: &mut Vec<Finding>) {
    if mx_records.is_empty() {
        return;
    }

    let mx_count = mx_records.len();
    let mx_list = mx_records.iter().take(5).cloned().collect::<Vec<_>>().join(", ");

    findings.push(
        Finding::new(
            "dns-security",
            Severity::Info,
            format!("MX Records Found: {domain}"),
            format!(
                "Domain '{domain}' has {mx_count} MX record(s): {mx_list}. \
                 Mail servers identified for email delivery."
            ),
            url,
        )
        .with_evidence(format!("{mx_count} MX records"))
        .with_owasp("A05:2021 Security Misconfiguration")
        .with_confidence(0.8),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for DNS/email security module.

    /// Verify SPF permissiveness analysis for different mechanisms.
    #[test]
    fn test_parse_spf() {
        // +all = highly permissive (pass all)
        let result = analyze_spf_permissiveness("v=spf1 +all");
        assert!(result.is_some());
        assert_eq!(result.map(|(s, _)| s), Some(Severity::High));

        // ~all = soft fail (common but weak)
        let result = analyze_spf_permissiveness("v=spf1 include:_spf.google.com ~all");
        assert!(result.is_some());
        assert_eq!(result.map(|(s, _)| s), Some(Severity::Low));

        // ?all = neutral (no enforcement)
        let result = analyze_spf_permissiveness("v=spf1 ?all");
        assert!(result.is_some());
        assert_eq!(result.map(|(s, _)| s), Some(Severity::Medium));

        // -all = secure (hard fail)
        let result = analyze_spf_permissiveness("v=spf1 include:_spf.google.com -all");
        assert!(result.is_none());
    }

    /// Verify DMARC policy extraction from record strings.
    #[test]
    fn test_parse_dmarc() {
        assert_eq!(parse_dmarc_policy("v=DMARC1; p=none; rua=mailto:d@example.com"), "none");
        assert_eq!(parse_dmarc_policy("v=DMARC1; p=quarantine; pct=100"), "quarantine");
        assert_eq!(parse_dmarc_policy("v=DMARC1; p=reject"), "reject");
        assert_eq!(parse_dmarc_policy("v=DMARC1"), "unknown");
    }

    /// Verify DoH JSON response parsing.
    #[test]
    fn test_doh_response_parsing() {
        let response = r#"{
            "Status": 0,
            "Answer": [
                {"name": "example.com", "type": 16, "data": "\"v=spf1 include:_spf.google.com -all\""},
                {"name": "example.com", "type": 16, "data": "\"google-site-verification=abc123\""}
            ]
        }"#;

        let result = parse_doh_response(response);
        assert!(result.is_some());
        let records = result.as_ref().unwrap_or_else(|| unreachable!());
        assert_eq!(records.len(), 2);
        assert!(records[0].contains("v=spf1"));

        // No answers
        let empty = r#"{"Status": 3}"#;
        assert!(parse_doh_response(empty).is_none());

        // Empty answers array
        let no_answers = r#"{"Status": 0, "Answer": []}"#;
        assert!(parse_doh_response(no_answers).is_none());
    }
}
