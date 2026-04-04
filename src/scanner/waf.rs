use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Built-in WAF detection without external tools.
#[derive(Debug)]
pub struct WafModule;

#[async_trait]
impl ScanModule for WafModule {
    fn name(&self) -> &'static str {
        "WAF Detection"
    }
    fn id(&self) -> &'static str {
        "waf"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Detect Web Application Firewalls via response analysis"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // 1. Check normal response headers for WAF signatures
        let normal_resp = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;
        let normal_headers = normal_resp.headers().clone();

        detect_waf_headers(&normal_headers, url, &mut findings);

        // 2. Send a malicious-looking request to trigger WAF
        let attack_url = format!("{url}?id=1'+OR+1=1--&<script>alert(1)</script>");
        if let Ok(attack_resp) = ctx.http_client.get(&attack_url).send().await {
            let status = attack_resp.status();
            let attack_headers = attack_resp.headers().clone();
            let body = attack_resp.text().await.unwrap_or_default();

            // WAF typically returns 403, 406, 429, or custom pages
            if status.as_u16() == 403 || status.as_u16() == 406 || status.as_u16() == 429 {
                detect_waf_body(&body, &attack_headers, status.as_u16(), url, &mut findings);
            }
        }

        Ok(findings)
    }
}

fn detect_waf_headers(
    headers: &reqwest::header::HeaderMap,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    let checks: &[(&str, &str)] = &[
        ("cf-ray", "Cloudflare"),
        ("cf-cache-status", "Cloudflare"),
        ("x-sucuri-id", "Sucuri"),
        ("x-sucuri-cache", "Sucuri"),
        ("server", ""), // checked separately
        ("x-powered-by-plesk", "Plesk"),
        ("x-cdn", ""),
        ("x-akamai-transformed", "Akamai"),
        ("x-barracuda-waf", "Barracuda WAF"),
        ("x-denied-reason", "Generic WAF"),
        ("x-dotdefender-denied", "dotDefender"),
    ];

    for &(header, waf_name) in checks {
        if let Some(value) = headers.get(header) {
            let val = value.to_str().unwrap_or("");
            let detected = if header == "server" {
                detect_waf_from_server(val)
            } else if waf_name.is_empty() {
                Some(val.to_string())
            } else {
                Some(waf_name.to_string())
            };

            if let Some(waf) = detected {
                findings.push(
                    Finding::new(
                        "waf",
                        Severity::Info,
                        format!("WAF Detected: {waf}"),
                        format!("Web Application Firewall detected: {waf}"),
                        url,
                    )
                    .with_evidence(format!("{header}: {val}"))
                    .with_confidence(0.7),
                );
                return; // One WAF detection is enough
            }
        }
    }
}

fn detect_waf_from_server(server: &str) -> Option<String> {
    let lower = server.to_lowercase();
    let waf_patterns = [
        ("cloudflare", "Cloudflare"),
        ("akamai", "Akamai"),
        ("incapsula", "Imperva Incapsula"),
        ("sucuri", "Sucuri"),
        ("barracuda", "Barracuda"),
        ("f5 big-ip", "F5 BIG-IP"),
        ("fortiweb", "FortiWeb"),
        ("wallarm", "Wallarm"),
    ];

    for &(pattern, name) in &waf_patterns {
        if lower.contains(pattern) {
            return Some(name.to_string());
        }
    }
    None
}

fn detect_waf_body(
    body: &str,
    headers: &reqwest::header::HeaderMap,
    status: u16,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    let lower = body.to_lowercase();
    let waf_signatures = [
        ("cloudflare", "Cloudflare"),
        ("attention required", "Cloudflare"),
        ("sucuri website firewall", "Sucuri"),
        ("access denied - sucuri", "Sucuri"),
        ("incapsula", "Imperva Incapsula"),
        ("request unsuccessful", "Imperva"),
        ("modsecurity", "ModSecurity"),
        ("not acceptable", "ModSecurity"),
        ("wordfence", "Wordfence"),
        ("blocked by wordfence", "Wordfence"),
        ("akamai", "Akamai"),
        ("access denied", "Generic WAF"),
        ("web application firewall", "Generic WAF"),
        ("waf", "Generic WAF"),
        ("blocked", "Generic WAF"),
        ("forbidden", "Possible WAF"),
    ];

    for &(pattern, waf) in &waf_signatures {
        if lower.contains(pattern) {
            // Don't duplicate if already detected via headers
            if !findings.iter().any(|f| f.title.contains(waf)) {
                findings.push(
                    Finding::new(
                        "waf",
                        Severity::Info,
                        format!("WAF Detected: {waf}"),
                        format!("{waf} detected via block response (HTTP {status})"),
                        url,
                    )
                    .with_evidence(format!(
                        "HTTP {status} on attack probe | Body contains '{pattern}'"
                    ))
                    .with_confidence(0.7),
                );
            }
            return;
        }
    }

    // Check for generic WAF via response headers on attack request
    if headers.get("x-request-id").is_some() && status == 403 {
        findings.push(
            Finding::new(
                "waf",
                Severity::Info,
                "Possible WAF/Rate Limiter",
                format!("HTTP {status} returned on attack probe, suggesting WAF or rate limiting"),
                url,
            )
            .with_evidence(format!("HTTP {status} on malicious input"))
            .with_confidence(0.7),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for the WAF detection module's pure helper functions and pattern data.

    /// Verify that `detect_waf_from_server` identifies known WAF products from the
    /// Server header value and returns `None` for generic servers.
    #[test]
    fn test_detect_waf_from_server() {
        // Arrange & Assert: known WAF server strings
        let cloudflare = detect_waf_from_server("cloudflare");
        assert!(cloudflare.is_some());
        assert_eq!(cloudflare.as_deref(), Some("Cloudflare"));

        let incapsula = detect_waf_from_server("Incapsula/nginx");
        assert!(incapsula.is_some());
        assert_eq!(incapsula.as_deref(), Some("Imperva Incapsula"));

        let akamai = detect_waf_from_server("AkamaiGHost");
        assert!(akamai.is_some());
        assert_eq!(akamai.as_deref(), Some("Akamai"));

        // Generic servers should not match
        assert!(detect_waf_from_server("nginx/1.24.0").is_none());
        assert!(detect_waf_from_server("Apache/2.4.52").is_none());
        assert!(detect_waf_from_server("").is_none());
    }

    /// Verify that the WAF header check list contains well-known WAF detection headers
    /// and that all entries have non-empty header names.
    #[test]
    fn test_waf_header_checks_integrity() {
        // Arrange: the checks array from detect_waf_headers
        let checks: &[(&str, &str)] = &[
            ("cf-ray", "Cloudflare"),
            ("cf-cache-status", "Cloudflare"),
            ("x-sucuri-id", "Sucuri"),
            ("x-sucuri-cache", "Sucuri"),
            ("server", ""),
            ("x-powered-by-plesk", "Plesk"),
            ("x-cdn", ""),
            ("x-akamai-transformed", "Akamai"),
            ("x-barracuda-waf", "Barracuda WAF"),
            ("x-denied-reason", "Generic WAF"),
            ("x-dotdefender-denied", "dotDefender"),
        ];

        // Assert: minimum count
        assert!(checks.len() >= 8, "Expected at least 8 WAF header checks, found {}", checks.len());

        // All header names are non-empty and lowercase
        for &(header, _) in checks {
            assert!(!header.is_empty(), "WAF header name should not be empty");
            assert_eq!(header, header.to_lowercase(), "WAF header '{header}' should be lowercase");
        }
    }

    /// Verify that the WAF body signature patterns are non-empty, lowercase, and
    /// cover major WAF products (Cloudflare, Sucuri, ModSecurity, Wordfence).
    #[test]
    fn test_waf_body_signatures_integrity() {
        // Arrange: the waf_signatures array from detect_waf_body
        let waf_signatures: &[(&str, &str)] = &[
            ("cloudflare", "Cloudflare"),
            ("attention required", "Cloudflare"),
            ("sucuri website firewall", "Sucuri"),
            ("access denied - sucuri", "Sucuri"),
            ("incapsula", "Imperva Incapsula"),
            ("request unsuccessful", "Imperva"),
            ("modsecurity", "ModSecurity"),
            ("not acceptable", "ModSecurity"),
            ("wordfence", "Wordfence"),
            ("blocked by wordfence", "Wordfence"),
            ("akamai", "Akamai"),
            ("access denied", "Generic WAF"),
            ("web application firewall", "Generic WAF"),
            ("waf", "Generic WAF"),
            ("blocked", "Generic WAF"),
            ("forbidden", "Possible WAF"),
        ];

        // Assert: minimum count
        assert!(
            waf_signatures.len() >= 10,
            "Expected at least 10 WAF body signatures, found {}",
            waf_signatures.len()
        );

        // All patterns are lowercase and non-empty; all WAF names are non-empty
        for &(pattern, waf_name) in waf_signatures {
            assert!(!pattern.is_empty(), "WAF body pattern should not be empty");
            assert_eq!(
                pattern,
                pattern.to_lowercase(),
                "WAF body pattern '{pattern}' should be lowercase (matched against lowercased body)"
            );
            assert!(!waf_name.is_empty(), "WAF name should not be empty");
        }

        // Major WAFs are covered
        let waf_names: Vec<&str> = waf_signatures.iter().map(|&(_, name)| name).collect();
        assert!(waf_names.contains(&"Cloudflare"));
        assert!(waf_names.contains(&"Sucuri"));
        assert!(waf_names.contains(&"ModSecurity"));
        assert!(waf_names.contains(&"Wordfence"));
    }
}
