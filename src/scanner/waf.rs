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
                    .with_evidence(format!("{header}: {val}")),
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
                    )),
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
            .with_evidence(format!("HTTP {status} on malicious input")),
        );
    }
}
