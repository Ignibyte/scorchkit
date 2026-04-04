//! CNAME takeover and certificate transparency recon module.
//!
//! Detects dangling CNAME records pointing to deprovisioned services and
//! enumerates subdomains via certificate transparency logs (`crt.sh`).

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects CNAME takeover risks and enumerates subdomains via cert transparency.
#[derive(Debug)]
pub struct CnameTakeoverModule;

#[async_trait]
impl ScanModule for CnameTakeoverModule {
    fn name(&self) -> &'static str {
        "CNAME Takeover & Cert Transparency"
    }

    fn id(&self) -> &'static str {
        "cname_takeover"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Detect dangling CNAME records and enumerate subdomains via crt.sh"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        let domain = ctx.target.url.host_str().unwrap_or("");
        if domain.is_empty() {
            return Ok(findings);
        }

        // 1. Query crt.sh for subdomains via certificate transparency
        query_crt_sh(ctx, domain, url, &mut findings).await?;

        // 2. Check known takeover fingerprints on the target domain
        check_takeover_fingerprints(ctx, url, &mut findings).await?;

        Ok(findings)
    }
}

/// Service fingerprints that indicate a deprovisioned/claimable CNAME target.
const TAKEOVER_FINGERPRINTS: &[(&str, &str)] = &[
    ("There isn't a GitHub Pages site here", "GitHub Pages"),
    ("herokucdn.com/error-pages/no-such-app", "Heroku"),
    ("NoSuchBucket", "AWS S3"),
    ("The specified bucket does not exist", "AWS S3"),
    ("No settings were found for this company", "Help Scout"),
    ("We could not find what you're looking for", "Help Juice"),
    ("No such app", "Heroku"),
    ("is not a registered InCloud YouTrack", "JetBrains YouTrack"),
    ("Unrecognized domain", "Shopify"),
    ("Sorry, this shop is currently unavailable", "Shopify"),
    ("The feed has not been found", "Feedpress"),
    ("project not found", "Surge.sh"),
    ("This domain is not connected", "Tumblr"),
    ("Whatever you were looking for doesn't currently exist", "Fly.io"),
    ("InvalidBucketName", "AWS S3"),
    ("Domain is not configured", "Fastly"),
];

/// Check the target response for CNAME takeover fingerprints.
async fn check_takeover_fingerprints(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let Ok(response) = ctx.http_client.get(url_str).send().await else {
        return Ok(());
    };

    let body = response.text().await.unwrap_or_default();

    for &(fingerprint, service) in TAKEOVER_FINGERPRINTS {
        if body.contains(fingerprint) {
            findings.push(
                Finding::new(
                    "cname_takeover",
                    Severity::High,
                    format!("Potential CNAME Takeover: {service}"),
                    format!(
                        "The response contains a {service} error fingerprint indicating \
                         the CNAME target may be deprovisioned and claimable by an attacker.",
                    ),
                    url_str,
                )
                .with_evidence(format!("Fingerprint: `{fingerprint}` | Service: {service}"))
                .with_remediation(
                    "Remove the dangling CNAME DNS record or reclaim the service. \
                     Verify all CNAME targets are active and owned.",
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(923)
                .with_confidence(0.7),
            );
            return Ok(());
        }
    }

    Ok(())
}

/// Query crt.sh certificate transparency logs for subdomains.
async fn query_crt_sh(
    ctx: &ScanContext,
    domain: &str,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let crt_url = format!("https://crt.sh/?q=%25.{domain}&output=json");

    let Ok(response) = ctx.http_client.get(&crt_url).send().await else {
        return Ok(());
    };

    if !response.status().is_success() {
        return Ok(());
    }

    let body = response.text().await.unwrap_or_default();

    // Parse subdomain names from the JSON response
    let subdomains = extract_crt_sh_subdomains(&body, domain);

    if !subdomains.is_empty() {
        findings.push(
            Finding::new(
                "cname_takeover",
                Severity::Info,
                format!("Certificate Transparency: {} subdomains found", subdomains.len()),
                format!(
                    "Found {} unique subdomains for `{domain}` via certificate transparency \
                     logs (crt.sh). These subdomains should be tested for active services \
                     and potential takeover vulnerabilities.",
                    subdomains.len(),
                ),
                url_str,
            )
            .with_evidence(format!(
                "Subdomains (first 20): {}",
                subdomains.iter().take(20).cloned().collect::<Vec<_>>().join(", ")
            ))
            .with_remediation(
                "Review discovered subdomains for active services. Remove DNS records \
                 for decommissioned services. Test each for CNAME takeover risk.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(200)
            .with_confidence(0.7),
        );
    }

    Ok(())
}

/// Extract unique subdomain names from crt.sh JSON response.
fn extract_crt_sh_subdomains(body: &str, domain: &str) -> Vec<String> {
    let mut subdomains = Vec::new();
    let domain_lower = domain.to_lowercase();

    // Simple JSON parsing — look for "common_name" and "name_value" fields
    for line in body.lines() {
        let lower = line.to_lowercase();
        if lower.contains(&domain_lower) {
            // Extract subdomain values between quotes
            for part in line.split('"') {
                let trimmed = part.trim().to_lowercase();
                if trimmed.ends_with(&domain_lower)
                    && trimmed != domain_lower
                    && !trimmed.starts_with('*')
                    && !trimmed.contains(' ')
                {
                    subdomains.push(trimmed);
                }
            }
        }
    }

    subdomains.sort();
    subdomains.dedup();
    subdomains
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the CNAME takeover and cert transparency module.

    /// Verify module metadata.
    #[test]
    fn test_module_metadata_cname_takeover() {
        let module = CnameTakeoverModule;
        assert_eq!(module.id(), "cname_takeover");
        assert_eq!(module.category(), ModuleCategory::Recon);
    }

    /// Verify takeover fingerprint database.
    #[test]
    fn test_takeover_fingerprints_not_empty() {
        assert!(!TAKEOVER_FINGERPRINTS.is_empty());
        let services: Vec<&str> = TAKEOVER_FINGERPRINTS.iter().map(|&(_, s)| s).collect();
        assert!(services.contains(&"GitHub Pages"));
        assert!(services.contains(&"AWS S3"));
        assert!(services.contains(&"Heroku"));
    }

    /// Verify crt.sh subdomain extraction.
    #[test]
    fn test_extract_crt_sh_subdomains() {
        let body = r#"[{"common_name":"www.example.com"},{"name_value":"api.example.com"},{"common_name":"mail.example.com"},{"common_name":"*.example.com"}]"#;
        let subs = extract_crt_sh_subdomains(body, "example.com");
        assert!(subs.contains(&"www.example.com".to_string()));
        assert!(subs.contains(&"mail.example.com".to_string()));
        // Wildcards should be excluded
        assert!(!subs.iter().any(|s| s.starts_with('*')));
    }

    /// Verify no subdomains extracted from unrelated content.
    #[test]
    fn test_extract_crt_sh_negative() {
        let body = r#"[{"common_name":"other-domain.com"}]"#;
        let subs = extract_crt_sh_subdomains(body, "example.com");
        assert!(subs.is_empty());
    }
}
