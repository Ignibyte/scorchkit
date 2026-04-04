use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects potential Server-Side Request Forgery vulnerabilities.
#[derive(Debug)]
pub struct SsrfModule;

#[async_trait]
impl ScanModule for SsrfModule {
    fn name(&self) -> &'static str {
        "SSRF Detection"
    }

    fn id(&self) -> &'static str {
        "ssrf"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect Server-Side Request Forgery (SSRF) via URL parameter injection"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Spider for URL-like parameters
        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let body = response.text().await.unwrap_or_default();

        // Find parameters that look like they accept URLs
        let links = extract_url_params(&body, &ctx.target.url);
        for (link, param_name) in &links {
            test_ssrf_param(ctx, link, param_name, &mut findings).await?;
        }

        // Test the target URL's own parameters
        test_own_params(ctx, url, &mut findings).await?;

        Ok(findings)
    }
}

/// Test a URL parameter for SSRF by injecting internal addresses.
async fn test_ssrf_param(
    ctx: &ScanContext,
    url_str: &str,
    param_name: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let Ok(parsed) = Url::parse(url_str) else {
        return Ok(());
    };

    let params: Vec<(String, String)> =
        parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    for &(payload, desc) in SSRF_PAYLOADS {
        let mut test_url = parsed.clone();
        {
            let mut query_pairs = test_url.query_pairs_mut();
            query_pairs.clear();
            for (k, v) in &params {
                if k == param_name {
                    query_pairs.append_pair(k, payload);
                } else {
                    query_pairs.append_pair(k, v);
                }
            }
        }

        let Ok(response) = ctx.http_client.get(test_url.as_str()).send().await else {
            continue;
        };

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        // Check for indicators that the server fetched the internal resource
        if contains_ssrf_indicator(&body, payload) {
            findings.push(
                Finding::new(
                    "ssrf",
                    Severity::Critical,
                    format!("Potential SSRF in Parameter: {param_name}"),
                    format!(
                        "The parameter '{param_name}' may be vulnerable to SSRF. \
                         Injecting {desc} produced a response indicating server-side fetch."
                    ),
                    url_str,
                )
                .with_evidence(format!(
                    "Payload: {payload} | HTTP {status} | Response indicates internal access"
                ))
                .with_remediation(
                    "Validate and sanitize URL parameters. Use allowlists for permitted \
                     domains. Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, \
                     172.16.0.0/12, 192.168.0.0/16, 169.254.169.254).",
                )
                .with_owasp("A10:2021 Server-Side Request Forgery")
                .with_cwe(918)
                .with_confidence(0.7),
            );
            return Ok(());
        }

        // Check for different response than baseline (timing-based would be better)
        if status.as_u16() == 500 {
            findings.push(
                Finding::new(
                    "ssrf",
                    Severity::Medium,
                    format!("SSRF Probe Caused Server Error: {param_name}"),
                    format!(
                        "Injecting an internal URL into '{param_name}' caused a 500 error, \
                         suggesting the server may attempt to fetch the provided URL."
                    ),
                    url_str,
                )
                .with_evidence(format!("Payload: {payload} | HTTP 500"))
                .with_remediation("Investigate whether this parameter processes URLs server-side")
                .with_owasp("A10:2021 Server-Side Request Forgery")
                .with_cwe(918)
                .with_confidence(0.7),
            );
            return Ok(());
        }
    }

    Ok(())
}

/// Test the target URL's own query params for URL-like values.
async fn test_own_params(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let Ok(parsed) = Url::parse(url_str) else {
        return Ok(());
    };

    let params: Vec<(String, String)> =
        parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    for (name, value) in &params {
        if looks_like_url_param(name, value) {
            test_ssrf_param(ctx, url_str, name, findings).await?;
        }
    }

    Ok(())
}

/// Extract links with URL-like parameter values from the page.
fn extract_url_params(body: &str, base_url: &Url) -> Vec<(String, String)> {
    let document = Html::parse_document(body);
    let mut results = Vec::new();

    let Ok(selector) = Selector::parse("a[href]") else {
        return results;
    };

    for element in document.select(&selector) {
        if let Some(href) = element.value().attr("href") {
            if let Ok(resolved) = base_url.join(href) {
                if resolved.host() == base_url.host() {
                    for (name, value) in resolved.query_pairs() {
                        if looks_like_url_param(&name, &value) {
                            results.push((resolved.to_string(), name.to_string()));
                        }
                    }
                }
            }
        }
    }

    results.truncate(10);
    results
}

/// Heuristic: does this parameter name/value look like it accepts a URL?
fn looks_like_url_param(name: &str, value: &str) -> bool {
    let name_lower = name.to_lowercase();
    let url_param_names = [
        "url",
        "uri",
        "link",
        "href",
        "src",
        "source",
        "dest",
        "destination",
        "redirect",
        "return",
        "next",
        "target",
        "rurl",
        "return_url",
        "redirect_uri",
        "callback",
        "continue",
        "image",
        "img",
        "fetch",
        "proxy",
        "load",
    ];

    if url_param_names.iter().any(|p| name_lower.contains(p)) {
        return true;
    }

    // Value looks like a URL
    value.starts_with("http://") || value.starts_with("https://") || value.starts_with("//")
}

/// Check if the response indicates the server fetched an internal resource.
fn contains_ssrf_indicator(body: &str, payload: &str) -> bool {
    let lower = body.to_lowercase();

    // Cloud metadata indicators
    if payload.contains("169.254.169.254")
        && (lower.contains("ami-id")
            || lower.contains("instance-id")
            || lower.contains("security-credentials")
            || lower.contains("iam"))
    {
        return true;
    }

    // Internal service indicators
    if lower.contains("root:x:0:0") || lower.contains("[global]") {
        return true;
    }

    false
}

/// SSRF test payloads.
const SSRF_PAYLOADS: &[(&str, &str)] = &[
    ("http://127.0.0.1", "localhost"),
    ("http://localhost", "localhost"),
    ("http://[::1]", "IPv6 localhost"),
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance", "Azure metadata"),
    ("http://127.0.0.1:22", "localhost SSH port"),
    ("http://127.0.0.1:3306", "localhost MySQL port"),
    ("http://10.0.0.1", "internal 10.x range"),
    ("http://192.168.1.1", "internal 192.168.x range"),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for the SSRF detection module's pure helper functions.

    /// Verify that `looks_like_url_param` identifies parameters whose names
    /// match common URL/redirect parameter patterns.
    #[test]
    fn test_looks_like_url_param_by_name() {
        assert!(looks_like_url_param("redirect_uri", ""));
        assert!(looks_like_url_param("return_url", ""));
        assert!(looks_like_url_param("callback", ""));
        assert!(looks_like_url_param("src", ""));
        assert!(looks_like_url_param("destination", ""));
    }

    /// Verify that `looks_like_url_param` identifies parameters whose values
    /// start with URL schemes, even when the name is generic.
    #[test]
    fn test_looks_like_url_param_by_value() {
        assert!(looks_like_url_param("data", "https://example.com"));
        assert!(looks_like_url_param("data", "http://example.com"));
        assert!(looks_like_url_param("ref", "//cdn.example.com/img.png"));
    }

    /// Verify that `looks_like_url_param` rejects parameters that do not look
    /// like URLs by either name or value.
    #[test]
    fn test_looks_like_url_param_rejects_non_url() {
        assert!(!looks_like_url_param("username", "alice"));
        assert!(!looks_like_url_param("age", "30"));
        assert!(!looks_like_url_param("color", "blue"));
    }

    /// Verify that `contains_ssrf_indicator` detects AWS metadata indicators
    /// when the payload targets the metadata IP address.
    #[test]
    fn test_contains_ssrf_indicator_aws_metadata() {
        let body = r#"{"ami-id": "ami-12345", "instance-id": "i-abcdef"}"#;
        let payload = "http://169.254.169.254/latest/meta-data/";

        assert!(contains_ssrf_indicator(body, payload));
    }

    /// Verify that `contains_ssrf_indicator` returns false when the response
    /// body contains no internal resource indicators.
    #[test]
    fn test_contains_ssrf_indicator_absent() {
        let body = "<html><body>Normal web page content</body></html>";
        let payload = "http://169.254.169.254/latest/meta-data/";

        assert!(!contains_ssrf_indicator(body, payload));
    }

    /// Verify that `extract_url_params` finds links whose query parameters
    /// contain URL-like values from HTML anchor elements.
    #[test]
    fn test_extract_url_params() -> std::result::Result<(), url::ParseError> {
        // Arrange
        let base = Url::parse("https://example.com/")?;
        let body = r#"
            <html><body>
                <a href="/proxy?url=https://other.com/page">External</a>
                <a href="/search?q=test">Search</a>
            </body></html>
        "#;

        // Act
        let results = extract_url_params(body, &base);

        // Assert: only the link with a URL-like param value should match
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, "url");

        Ok(())
    }
}
