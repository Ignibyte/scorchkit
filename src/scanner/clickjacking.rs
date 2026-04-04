//! Clickjacking scanner module.
//!
//! Detects clickjacking vulnerabilities by checking for the absence of
//! both `X-Frame-Options` and `Content-Security-Policy frame-ancestors`
//! protections. Only flags when BOTH defenses are missing.

use async_trait::async_trait;
use reqwest::header::HeaderMap;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects clickjacking vulnerabilities via missing frame protection.
#[derive(Debug)]
pub struct ClickjackingModule;

#[async_trait]
impl ScanModule for ClickjackingModule {
    fn name(&self) -> &'static str {
        "Clickjacking Detection"
    }

    fn id(&self) -> &'static str {
        "clickjacking"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect clickjacking via missing X-Frame-Options and CSP frame-ancestors"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Test the main page
        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let headers = response.headers().clone();
        let content_type = headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");

        // Only check HTML pages (not APIs, images, etc.)
        if content_type.contains("text/html") || content_type.contains("application/xhtml") {
            check_frame_protection(&headers, url, &mut findings);
        }

        Ok(findings)
    }
}

/// Check if a page has frame protection (X-Frame-Options or CSP `frame-ancestors`).
///
/// Returns `true` if the page has at least one frame protection mechanism.
fn has_frame_protection(headers: &HeaderMap) -> bool {
    // Check X-Frame-Options
    if headers.contains_key("x-frame-options") {
        return true;
    }

    // Check CSP frame-ancestors
    if let Some(csp) = headers.get("content-security-policy") {
        if let Ok(csp_val) = csp.to_str() {
            if csp_val.to_lowercase().contains("frame-ancestors") {
                return true;
            }
        }
    }

    false
}

/// Check frame protection and generate findings.
fn check_frame_protection(headers: &HeaderMap, url: &str, findings: &mut Vec<Finding>) {
    if has_frame_protection(headers) {
        return;
    }

    let has_xfo = headers.contains_key("x-frame-options");
    let has_csp_fa = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_lowercase().contains("frame-ancestors"));

    findings.push(
        Finding::new(
            "clickjacking",
            Severity::Medium,
            "Clickjacking: Missing Frame Protection",
            format!(
                "The page lacks both `X-Frame-Options` and CSP `frame-ancestors` \
                 directives. Without either protection, the page can be embedded \
                 in an attacker-controlled iframe for clickjacking attacks. \
                 X-Frame-Options: {xfo} | CSP frame-ancestors: {csp}",
                xfo = if has_xfo { "present" } else { "missing" },
                csp = if has_csp_fa { "present" } else { "missing" },
            ),
            url,
        )
        .with_evidence("X-Frame-Options: missing | CSP frame-ancestors: missing")
        .with_remediation(
            "Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN` header. \
             Additionally, set `Content-Security-Policy: frame-ancestors 'self'` \
             for modern browser support. Both headers should be set for defense in depth.",
        )
        .with_owasp("A05:2021 Security Misconfiguration")
        .with_cwe(1021)
        .with_confidence(0.9),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the clickjacking scanner module.

    /// Verify module metadata.
    #[test]
    fn test_module_metadata_clickjacking() {
        let module = ClickjackingModule;
        assert_eq!(module.id(), "clickjacking");
        assert_eq!(module.name(), "Clickjacking Detection");
        assert_eq!(module.category(), ModuleCategory::Scanner);
        assert!(!module.description().is_empty());
    }

    /// Verify `has_frame_protection` returns true when `X-Frame-Options` is present.
    #[test]
    fn test_has_frame_protection_xfo() {
        let mut headers = HeaderMap::new();
        headers.insert("x-frame-options", "DENY".parse().expect("valid value"));

        assert!(has_frame_protection(&headers));
    }

    /// Verify `has_frame_protection` returns true when CSP `frame-ancestors` is present.
    #[test]
    fn test_has_frame_protection_csp() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-security-policy",
            "frame-ancestors 'self'".parse().expect("valid value"),
        );

        assert!(has_frame_protection(&headers));
    }

    /// Verify `has_frame_protection` returns false when neither protection exists.
    #[test]
    fn test_has_frame_protection_none() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/html".parse().expect("valid value"));

        assert!(!has_frame_protection(&headers));
    }

    /// Verify that CSP without `frame-ancestors` is not considered frame protection.
    #[test]
    fn test_has_frame_protection_csp_without_frame_ancestors() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-security-policy",
            "default-src 'self'; script-src 'unsafe-inline'".parse().expect("valid value"),
        );

        assert!(!has_frame_protection(&headers));
    }
}
