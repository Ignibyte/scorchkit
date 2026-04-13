//! HTTP request smuggling scanner module.
//!
//! Detects HTTP request smuggling risk by identifying multi-tier proxy
//! architectures, testing `Transfer-Encoding` obfuscation handling, and
//! checking for `Content-Length` / `Transfer-Encoding` handling inconsistencies.
//!
//! Note: `reqwest` normalizes HTTP headers, so this module uses heuristic
//! detection rather than sending actual CL.TE/TE.CL desync payloads.
//! For confirmed exploitation testing, use purpose-built tools like
//! `smuggler.py` or the Burp HTTP Request Smuggler extension.

use async_trait::async_trait;
use reqwest::header::HeaderMap;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects HTTP request smuggling risk via heuristic analysis.
#[derive(Debug)]
pub struct SmugglingModule;

#[async_trait]
impl ScanModule for SmugglingModule {
    fn name(&self) -> &'static str {
        "HTTP Request Smuggling Detection"
    }

    fn id(&self) -> &'static str {
        "smuggling"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect HTTP request smuggling risk via proxy detection and TE handling analysis"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // 1. Fetch baseline response and check for proxy indicators
        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let headers = response.headers().clone();
        let has_proxy = detect_proxy_indicators(&headers);

        if !has_proxy.is_empty() {
            // Multi-tier architecture detected — smuggling prerequisite met
            // 2. Test TE obfuscation handling
            test_te_obfuscation(ctx, url, &has_proxy, &mut findings).await?;

            // 3. Test CL handling inconsistency
            test_cl_handling(ctx, url, &has_proxy, &mut findings).await?;
        }

        // 4. Check for HTTP/1.1 with proxy headers even without confirmed proxy
        check_smuggling_headers(&headers, url, &mut findings);

        Ok(findings)
    }
}

/// Headers that indicate a multi-tier proxy/CDN/load-balancer architecture.
const PROXY_INDICATOR_HEADERS: &[&str] = &[
    "via",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
    "x-cache",
    "x-cache-hits",
    "x-served-by",
    "x-timer",
    "cf-ray",
    "x-amz-cf-id",
    "x-azure-ref",
    "x-varnish",
    "x-cdn",
    "x-edge-ip",
    "x-akamai-transformed",
    "fastly-io-info",
];

/// `Transfer-Encoding` obfuscation variants for TE.TE testing.
const TE_OBFUSCATION_VARIANTS: &[(&str, &str)] = &[
    ("chunked", "Standard chunked (baseline)"),
    (" chunked", "Leading space"),
    ("chunked ", "Trailing space"),
    ("\tchunked", "Leading tab"),
    ("Chunked", "Mixed case (capital C)"),
    ("CHUNKED", "All uppercase"),
    ("chunked\r\nTransfer-Encoding: x", "Double TE header"),
    ("xchunked", "Invalid variant (xchunked)"),
    ("x]chunked", "Invalid variant with bracket"),
];

/// Detect proxy/CDN/load-balancer indicators in response headers.
///
/// Returns a list of detected indicator header names.
fn detect_proxy_indicators(headers: &HeaderMap) -> Vec<&'static str> {
    let mut found = Vec::new();
    for &indicator in PROXY_INDICATOR_HEADERS {
        if headers.contains_key(indicator) {
            found.push(indicator);
        }
    }
    found
}

/// Check response headers for smuggling-relevant misconfigurations.
fn check_smuggling_headers(headers: &HeaderMap, url: &str, findings: &mut Vec<Finding>) {
    // Check for HTTP/1.0 downgrade (servers that don't support HTTP/1.1 TE properly)
    if let Some(connection) = headers.get("connection") {
        let conn_val = connection.to_str().unwrap_or("");
        if conn_val.to_lowercase().contains("close") {
            // Connection: close on a proxy setup suggests potential issues
            let proxy_indicators = detect_proxy_indicators(headers);
            if !proxy_indicators.is_empty() {
                findings.push(
                    Finding::new(
                        "smuggling",
                        Severity::Info,
                        "Proxy with Connection: close header",
                        format!(
                            "The server responds with `Connection: close` while proxy \
                             indicators are present ({indicators}). This may indicate \
                             HTTP/1.0 downgrade between proxy tiers, which can affect \
                             request smuggling behavior.",
                            indicators = proxy_indicators.join(", "),
                        ),
                        url,
                    )
                    .with_evidence(format!(
                        "Connection: {conn_val} | Proxy headers: {}",
                        proxy_indicators.join(", ")
                    ))
                    .with_remediation(
                        "Ensure all tiers in the proxy chain use HTTP/1.1 with consistent \
                         Transfer-Encoding handling. Consider upgrading to HTTP/2 end-to-end.",
                    )
                    .with_owasp("A05:2021 Security Misconfiguration")
                    .with_cwe(444)
                    .with_confidence(0.5),
                );
            }
        }
    }
}

/// Test `Transfer-Encoding` obfuscation variants to detect inconsistent handling.
async fn test_te_obfuscation(
    ctx: &ScanContext,
    url_str: &str,
    proxy_indicators: &[&str],
    findings: &mut Vec<Finding>,
) -> Result<()> {
    // Send requests with obfuscated TE headers and compare responses
    let mut response_statuses: Vec<(u16, &str)> = Vec::new();

    for &(te_value, description) in TE_OBFUSCATION_VARIANTS {
        let Ok(response) = ctx
            .http_client
            .post(url_str)
            .header("Transfer-Encoding", te_value)
            .header("Content-Length", "0")
            .body("")
            .send()
            .await
        else {
            continue;
        };

        response_statuses.push((response.status().as_u16(), description));
    }

    // Analyze: different status codes for different TE variants = inconsistent handling
    if response_statuses.len() >= 2 {
        let first_status = response_statuses[0].0;
        let has_inconsistency = response_statuses.iter().any(|(status, _)| *status != first_status);

        if has_inconsistency {
            let evidence_lines: Vec<String> = response_statuses
                .iter()
                .map(|(status, desc)| format!("{desc}: HTTP {status}"))
                .collect();

            findings.push(
                Finding::new(
                    "smuggling",
                    Severity::High,
                    "HTTP Request Smuggling Risk: TE handling inconsistency",
                    format!(
                        "The server returns different status codes for different \
                         `Transfer-Encoding` header obfuscation variants. This indicates \
                         inconsistent TE parsing between proxy tiers ({proxy}), which is \
                         a precondition for HTTP request smuggling (CL.TE / TE.CL / TE.TE). \
                         Manual testing with purpose-built tools is recommended.",
                        proxy = proxy_indicators.join(", "),
                    ),
                    url_str,
                )
                .with_evidence(evidence_lines.join(" | "))
                .with_remediation(
                    "Normalize Transfer-Encoding handling across all proxy tiers. \
                     Reject ambiguous or obfuscated TE headers. Consider upgrading \
                     to HTTP/2 end-to-end to eliminate request smuggling risk.",
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(444)
                .with_confidence(0.5),
            );
        }
    }

    Ok(())
}

/// Test `Content-Length` handling to detect CL being ignored.
async fn test_cl_handling(
    ctx: &ScanContext,
    url_str: &str,
    proxy_indicators: &[&str],
    findings: &mut Vec<Finding>,
) -> Result<()> {
    // Send POST with Content-Length: 0 but non-empty body
    // If the body is processed, CL may be ignored in favor of actual body length
    let Ok(response_cl0) = ctx
        .http_client
        .post(url_str)
        .header("Content-Length", "0")
        .body("X=test_smuggling_probe")
        .send()
        .await
    else {
        return Ok(());
    };

    let status_cl0 = response_cl0.status().as_u16();

    // Send POST with correct Content-Length
    let Ok(response_correct) =
        ctx.http_client.post(url_str).body("X=test_smuggling_probe").send().await
    else {
        return Ok(());
    };

    let status_correct = response_correct.status().as_u16();

    // If both return the same non-error status, the CL:0 was likely ignored
    if status_cl0 == status_correct && status_cl0 < 400 {
        findings.push(
            Finding::new(
                "smuggling",
                Severity::Medium,
                "Content-Length may be ignored by backend",
                format!(
                    "The server returned the same status (HTTP {status_cl0}) when \
                     `Content-Length: 0` was sent with a non-empty body. This suggests \
                     the backend may ignore Content-Length in favor of the actual body, \
                     creating a desync risk with the front-end proxy ({proxy}).",
                    proxy = proxy_indicators.join(", "),
                ),
                url_str,
            )
            .with_evidence(format!(
                "CL:0 with body → HTTP {status_cl0} | Correct CL → HTTP {status_correct}"
            ))
            .with_remediation(
                "Ensure the backend strictly respects Content-Length. Configure the proxy \
                 to reject requests with mismatched Content-Length and body size.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(444)
            .with_confidence(0.5),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the HTTP request smuggling scanner module's pure helper
    /// functions and constant data integrity.

    /// Verify that the module metadata returns correct values.
    #[test]
    fn test_module_metadata_smuggling() {
        let module = SmugglingModule;

        assert_eq!(module.id(), "smuggling");
        assert_eq!(module.name(), "HTTP Request Smuggling Detection");
        assert_eq!(module.category(), ModuleCategory::Scanner);
        assert!(!module.description().is_empty());
        assert!(!module.requires_external_tool());
    }

    /// Verify that `detect_proxy_indicators` finds the Via header as a proxy indicator.
    #[test]
    fn test_detect_proxy_indicators_via() {
        let mut headers = HeaderMap::new();
        headers.insert("via", "1.1 varnish".parse().expect("valid header value"));
        headers.insert("server", "nginx".parse().expect("valid header value"));

        let indicators = detect_proxy_indicators(&headers);

        assert!(!indicators.is_empty(), "should detect Via as proxy indicator");
        assert!(indicators.contains(&"via"), "should contain 'via'");
    }

    /// Verify that `detect_proxy_indicators` returns empty for a direct server
    /// with no proxy headers.
    #[test]
    fn test_detect_proxy_indicators_negative() {
        let mut headers = HeaderMap::new();
        headers.insert("server", "nginx".parse().expect("valid header value"));
        headers.insert("content-type", "text/html".parse().expect("valid header value"));

        let indicators = detect_proxy_indicators(&headers);

        assert!(indicators.is_empty(), "should not detect proxy indicators on direct server");
    }

    /// Verify that the proxy indicator header database is non-empty.
    #[test]
    fn test_proxy_indicator_headers_not_empty() {
        assert!(!PROXY_INDICATOR_HEADERS.is_empty(), "proxy indicator database must not be empty");

        for (i, &header) in PROXY_INDICATOR_HEADERS.iter().enumerate() {
            assert!(!header.is_empty(), "header {i} is empty");
        }

        // Must cover common CDN/proxy headers
        assert!(PROXY_INDICATOR_HEADERS.contains(&"via"), "must include Via header");
        assert!(
            PROXY_INDICATOR_HEADERS.contains(&"x-forwarded-for"),
            "must include X-Forwarded-For"
        );
        assert!(PROXY_INDICATOR_HEADERS.contains(&"cf-ray"), "must include Cloudflare cf-ray");
    }

    /// Verify that the TE obfuscation variants database is non-empty and covers
    /// key obfuscation techniques.
    #[test]
    fn test_te_obfuscation_variants_not_empty() {
        assert!(!TE_OBFUSCATION_VARIANTS.is_empty(), "TE obfuscation database must not be empty");

        for (i, &(variant, desc)) in TE_OBFUSCATION_VARIANTS.iter().enumerate() {
            assert!(!variant.is_empty(), "variant {i} has empty value");
            assert!(!desc.is_empty(), "variant {i} has empty description");
        }

        let variants: Vec<&str> = TE_OBFUSCATION_VARIANTS.iter().map(|&(v, _)| v).collect();

        // Must include standard baseline
        assert!(variants.contains(&"chunked"), "must include standard chunked");

        // Must include case variations
        assert!(
            variants.iter().any(|v| *v == "CHUNKED" || *v == "Chunked"),
            "must include case-variant chunked"
        );

        // Must include whitespace variants
        assert!(
            variants.iter().any(|v| v.starts_with(' ') || v.starts_with('\t')),
            "must include leading whitespace variant"
        );
    }
}
