//! JavaScript file analysis recon module.
//!
//! Discovers and analyzes JavaScript files from the target to extract
//! API endpoints, secrets (AWS keys, API tokens), internal URLs, and
//! source map references. Finds JS files via HTML `<script>` tags.

use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Extracts secrets, API endpoints, and internal URLs from JavaScript files.
#[derive(Debug)]
pub struct JsAnalysisModule;

#[async_trait]
impl ScanModule for JsAnalysisModule {
    fn name(&self) -> &'static str {
        "JavaScript File Analysis"
    }

    fn id(&self) -> &'static str {
        "js_analysis"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Extract secrets, API endpoints, and internal URLs from JavaScript files"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let body = response.text().await.unwrap_or_default();
        let js_urls = extract_js_urls(&body, &ctx.target.url);

        // Analyze inline scripts
        analyze_js_content(&body, url, "inline script", &mut findings);

        // Fetch and analyze each JS file
        for js_url in &js_urls {
            let Ok(js_response) = ctx.http_client.get(js_url.as_str()).send().await else {
                continue;
            };
            let js_body = js_response.text().await.unwrap_or_default();
            analyze_js_content(&js_body, js_url.as_str(), "external JS file", &mut findings);
            check_source_map(&js_body, js_url.as_str(), &mut findings);
        }

        Ok(findings)
    }
}

/// Secret patterns: (pattern, description, severity).
const SECRET_PATTERNS: &[(&str, &str, Severity)] = &[
    ("AKIA", "AWS Access Key ID", Severity::Critical),
    ("ASIA", "AWS Temporary Access Key", Severity::Critical),
    ("sk_live_", "Stripe live secret key", Severity::Critical),
    ("sk_test_", "Stripe test secret key", Severity::High),
    ("ghp_", "GitHub personal access token", Severity::Critical),
    ("gho_", "GitHub OAuth token", Severity::Critical),
    ("glpat-", "GitLab personal access token", Severity::Critical),
    ("xoxb-", "Slack bot token", Severity::Critical),
    ("xoxp-", "Slack user token", Severity::Critical),
    ("AIzaSy", "Google API key", Severity::High),
    ("Bearer ", "Bearer token in source", Severity::High),
    ("api_key", "API key reference", Severity::Medium),
    ("api_secret", "API secret reference", Severity::High),
    ("client_secret", "OAuth client secret", Severity::High),
    ("private_key", "Private key reference", Severity::Critical),
    ("-----BEGIN RSA PRIVATE KEY", "RSA private key", Severity::Critical),
    ("-----BEGIN PRIVATE KEY", "Private key (PKCS8)", Severity::Critical),
];

/// API endpoint patterns to detect.
const ENDPOINT_PATTERNS: &[&str] = &[
    "/api/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/rest/",
    "/graphql",
    "/admin/",
    "/internal/",
    "/debug/",
    "/swagger",
    "/openapi",
    "/_debug",
    "/_admin",
];

/// Extract JavaScript file URLs from HTML `<script>` tags.
fn extract_js_urls(body: &str, base_url: &Url) -> Vec<Url> {
    let document = Html::parse_document(body);
    let mut urls = Vec::new();

    let Ok(selector) = Selector::parse("script[src]") else {
        return urls;
    };

    for element in document.select(&selector) {
        if let Some(src) = element.value().attr("src") {
            if let Ok(resolved) = base_url.join(src) {
                urls.push(resolved);
            }
        }
    }

    urls.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    urls.dedup_by(|a, b| a.as_str() == b.as_str());
    urls.truncate(30);
    urls
}

/// Analyze JavaScript content for secrets and API endpoints.
fn analyze_js_content(
    content: &str,
    source_url: &str,
    source_type: &str,
    findings: &mut Vec<Finding>,
) {
    for &(pattern, description, severity) in SECRET_PATTERNS {
        if content.contains(pattern) {
            findings.push(
                Finding::new(
                    "js_analysis",
                    severity,
                    format!("Secret in JS: {description}"),
                    format!(
                        "A potential {description} was found in {source_type} at {source_url}.",
                    ),
                    source_url,
                )
                .with_evidence(format!("Pattern: `{pattern}` | Source: {source_type}"))
                .with_remediation(
                    "Remove secrets from client-side JavaScript. Use environment variables \
                     and server-side configuration. Rotate any exposed credentials.",
                )
                .with_owasp("A01:2021 Broken Access Control")
                .with_cwe(540)
                .with_confidence(0.6),
            );
        }
    }

    let found_endpoints: Vec<&str> =
        ENDPOINT_PATTERNS.iter().filter(|p| content.contains(**p)).copied().collect();

    if !found_endpoints.is_empty() {
        findings.push(
            Finding::new(
                "js_analysis",
                Severity::Info,
                format!("API endpoints discovered in {source_type}"),
                format!(
                    "Found {} endpoint patterns in {source_type} at {source_url}: {}",
                    found_endpoints.len(),
                    found_endpoints.join(", "),
                ),
                source_url,
            )
            .with_evidence(format!("Endpoints: {}", found_endpoints.join(", ")))
            .with_remediation("Ensure all discovered API endpoints require proper authentication.")
            .with_owasp("A01:2021 Broken Access Control")
            .with_cwe(615)
            .with_confidence(0.6),
        );
    }
}

/// Check for source map references.
fn check_source_map(content: &str, js_url: &str, findings: &mut Vec<Finding>) {
    if content.contains("//# sourceMappingURL=") || content.contains("//@ sourceMappingURL=") {
        findings.push(
            Finding::new(
                "js_analysis",
                Severity::Medium,
                "Source map reference detected",
                format!(
                    "The JavaScript file at {js_url} contains a source map reference, \
                     exposing original source code and file structure.",
                ),
                js_url,
            )
            .with_evidence(format!("sourceMappingURL found in {js_url}"))
            .with_remediation("Remove source map references from production JavaScript.")
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(540)
            .with_confidence(0.6),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the JS analysis recon module.

    /// Verify module metadata.
    #[test]
    fn test_module_metadata_js_analysis() {
        let module = JsAnalysisModule;
        assert_eq!(module.id(), "js_analysis");
        assert_eq!(module.category(), ModuleCategory::Recon);
    }

    /// Verify secret detection finds AWS keys.
    #[test]
    fn test_analyze_js_secrets() {
        let mut findings = Vec::new();
        // nosemgrep: hardcoded-secret
        let content = "var key = 'AKIAIOSFODNN7EXAMPLE';";
        analyze_js_content(content, "https://example.com/app.js", "test", &mut findings);
        assert!(findings.iter().any(|f| f.title.contains("AWS")));
    }

    /// Verify API endpoint detection.
    #[test]
    fn test_analyze_js_endpoints() {
        let mut findings = Vec::new();
        let content = "fetch('/api/v1/users')";
        analyze_js_content(content, "https://example.com/app.js", "test", &mut findings);
        assert!(findings.iter().any(|f| f.title.contains("API endpoints")));
    }

    /// Verify source map detection.
    #[test]
    fn test_check_source_map() {
        let mut findings = Vec::new();
        check_source_map("var x=1;\n//# sourceMappingURL=app.js.map", "test.js", &mut findings);
        assert!(findings.iter().any(|f| f.title.contains("Source map")));
    }

    /// Verify `extract_js_urls` finds script tags.
    #[test]
    fn test_extract_js_urls() -> std::result::Result<(), url::ParseError> {
        let base = Url::parse("https://example.com/")?;
        let html = r#"<script src="/js/app.js"></script><script src="/js/lib.js"></script>"#;
        let urls = extract_js_urls(html, &base);
        assert_eq!(urls.len(), 2);
        Ok(())
    }

    /// Verify pattern databases.
    #[test]
    fn test_pattern_databases() {
        assert!(!SECRET_PATTERNS.is_empty());
        assert!(!ENDPOINT_PATTERNS.is_empty());
    }
}
