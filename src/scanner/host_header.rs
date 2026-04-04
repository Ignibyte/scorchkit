//! Host header injection scanner module.
//!
//! Detects host header injection vulnerabilities by sending requests with
//! manipulated Host, `X-Forwarded-Host`, and related headers, then checking
//! response bodies for reflection of the injected canary value. This can
//! indicate password reset poisoning, cache poisoning, or web cache deception.

use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects host header injection vulnerabilities.
#[derive(Debug)]
pub struct HostHeaderModule;

#[async_trait]
impl ScanModule for HostHeaderModule {
    fn name(&self) -> &'static str {
        "Host Header Injection Detection"
    }

    fn id(&self) -> &'static str {
        "host_header"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect host header injection for cache poisoning and password reset attacks"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Test host header manipulation on the target URL
        test_host_header_injection(ctx, url, &mut findings).await?;

        // Test duplicate Host header via X-Forwarded-Host
        test_forwarded_host(ctx, url, &mut findings).await?;

        Ok(findings)
    }
}

/// The canary value injected via host headers to detect reflection.
const HOST_CANARY: &str = "scorch-evil-host.example.com";

/// Headers used to override or supplement the Host header.
const HOST_OVERRIDE_HEADERS: &[(&str, &str)] = &[
    ("X-Forwarded-Host", "X-Forwarded-Host"),
    ("X-Host", "X-Host"),
    ("X-Forwarded-Server", "X-Forwarded-Server"),
    ("X-Original-URL", "X-Original-URL"),
    ("X-Rewrite-URL", "X-Rewrite-URL"),
];

/// Check if a canary host value is reflected in the response body.
///
/// Returns `true` if the canary appears in the body, indicating the server
/// uses the injected host value in generated content (links, redirects, etc.).
fn check_host_reflected(body: &str, canary: &str) -> bool {
    body.contains(canary)
}

/// Test host header injection by sending requests with override headers.
async fn test_host_header_injection(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    // Get baseline response for comparison
    let baseline = ctx
        .http_client
        .get(url_str)
        .send()
        .await
        .map_err(|e| ScorchError::Http { url: url_str.to_string(), source: e })?;

    let baseline_body = baseline.text().await.unwrap_or_default();

    // Ensure our canary doesn't naturally appear in the response
    if check_host_reflected(&baseline_body, HOST_CANARY) {
        return Ok(());
    }

    // Test each override header
    for &(header_name, header_desc) in HOST_OVERRIDE_HEADERS {
        let Ok(response) =
            ctx.http_client.get(url_str).header(header_name, HOST_CANARY).send().await
        else {
            continue;
        };

        let resp_body = response.text().await.unwrap_or_default();

        if check_host_reflected(&resp_body, HOST_CANARY) {
            findings.push(
                Finding::new(
                    "host_header",
                    Severity::High,
                    format!("Host Header Injection via {header_desc}"),
                    format!(
                        "The server reflects the value of the `{header_desc}` header \
                         in the response body. The canary value `{HOST_CANARY}` was \
                         injected via `{header_desc}` and appeared in the response. \
                         This can enable password reset poisoning, cache poisoning, \
                         or web cache deception attacks.",
                    ),
                    url_str,
                )
                .with_evidence(format!(
                    "Header: {header_name}: {HOST_CANARY} | Reflected in response body"
                ))
                .with_remediation(
                    "Ignore X-Forwarded-Host and similar override headers unless \
                     from a trusted reverse proxy. Configure the application to use \
                     a hardcoded server name for link generation. Validate the Host \
                     header against an allowlist of expected values.",
                )
                .with_owasp("A03:2021 Injection")
                .with_cwe(644)
                .with_confidence(0.8),
            );
            // One finding per header type is enough
        }
    }

    Ok(())
}

/// Test host reflection via `X-Forwarded-Host` specifically for cache poisoning indicators.
///
/// This sends `X-Forwarded-Host` alongside a normal request and checks if the
/// response includes the injected value in URLs, link tags, or script sources.
async fn test_forwarded_host(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let Ok(response) = ctx
        .http_client
        .get(url_str)
        .header("X-Forwarded-Host", HOST_CANARY)
        .header("X-Forwarded-Proto", "https")
        .send()
        .await
    else {
        return Ok(());
    };

    let resp_body = response.text().await.unwrap_or_default();

    // Check if canary appears in link/script/meta tags (cache poisoning vector)
    let link_patterns = [
        format!("href=\"https://{HOST_CANARY}"),
        format!("href=\"http://{HOST_CANARY}"),
        format!("src=\"https://{HOST_CANARY}"),
        format!("src=\"http://{HOST_CANARY}"),
        format!("action=\"https://{HOST_CANARY}"),
        format!("action=\"http://{HOST_CANARY}"),
        format!("content=\"https://{HOST_CANARY}"),
        format!("content=\"http://{HOST_CANARY}"),
    ];

    for pattern in &link_patterns {
        if resp_body.contains(pattern.as_str()) {
            findings.push(
                Finding::new(
                    "host_header",
                    Severity::Critical,
                    "Cache Poisoning via Host Header Injection",
                    format!(
                        "The server uses the `X-Forwarded-Host` header value to generate \
                         URLs in HTML attributes (href, src, action, or meta content). \
                         The canary `{HOST_CANARY}` was reflected in a link or resource \
                         reference. If the response is cached, all subsequent visitors \
                         will load resources from the attacker-controlled host.",
                    ),
                    url_str,
                )
                .with_evidence(format!(
                    "Header: X-Forwarded-Host: {HOST_CANARY} | Reflected in: {pattern}"
                ))
                .with_remediation(
                    "Do not use X-Forwarded-Host for URL generation unless the reverse \
                     proxy is explicitly trusted. Use a hardcoded canonical URL for all \
                     generated links. Add Vary: Host to cache responses to prevent \
                     cache poisoning.",
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(644)
                .with_confidence(0.8),
            );
            return Ok(());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the host header injection scanner module's pure helper
    /// functions and constant data integrity.

    /// Verify that the module metadata returns correct values.
    #[test]
    fn test_module_metadata_host_header() {
        let module = HostHeaderModule;

        assert_eq!(module.id(), "host_header");
        assert_eq!(module.name(), "Host Header Injection Detection");
        assert_eq!(module.category(), ModuleCategory::Scanner);
        assert!(!module.description().is_empty());
        assert!(!module.requires_external_tool());
    }

    /// Verify that the host override header database is non-empty and all
    /// entries have non-empty fields.
    #[test]
    fn test_host_header_payloads_not_empty() {
        assert!(!HOST_OVERRIDE_HEADERS.is_empty(), "override header database must not be empty");

        for (i, &(header, desc)) in HOST_OVERRIDE_HEADERS.iter().enumerate() {
            assert!(!header.is_empty(), "header {i} has empty name");
            assert!(!desc.is_empty(), "header {i} has empty description");
        }

        // Canary must also be non-empty
        assert!(!HOST_CANARY.is_empty(), "canary must not be empty");
    }

    /// Verify that `check_host_reflected` detects the canary value in a
    /// response body that reflects the host header.
    #[test]
    fn test_check_host_reflected_positive() {
        let body = format!(
            "<html><head><link rel=\"canonical\" href=\"https://{HOST_CANARY}/page\">\
             </head><body>Welcome</body></html>"
        );

        assert!(check_host_reflected(&body, HOST_CANARY), "should detect canary in response body");
    }

    /// Verify that `check_host_reflected` returns false for a normal response
    /// body that does not contain the canary.
    #[test]
    fn test_check_host_reflected_negative() {
        let body = "<html><head><link rel=\"canonical\" href=\"https://example.com/page\">\
                     </head><body>Welcome to example.com</body></html>";

        assert!(!check_host_reflected(body, HOST_CANARY), "should not match normal response body");
    }

    /// Verify that the override headers cover all the important host-override
    /// header variants.
    #[test]
    fn test_host_header_covers_all_headers() {
        let headers: Vec<&str> = HOST_OVERRIDE_HEADERS.iter().map(|&(h, _)| h).collect();

        assert!(headers.contains(&"X-Forwarded-Host"), "must include X-Forwarded-Host");
        assert!(headers.contains(&"X-Host"), "must include X-Host");
        assert!(headers.contains(&"X-Forwarded-Server"), "must include X-Forwarded-Server");
    }
}
