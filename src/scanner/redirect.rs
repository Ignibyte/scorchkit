use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects open redirect vulnerabilities.
#[derive(Debug)]
pub struct RedirectModule;

#[async_trait]
impl ScanModule for RedirectModule {
    fn name(&self) -> &'static str {
        "Open Redirect Detection"
    }
    fn id(&self) -> &'static str {
        "redirect"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Detect open redirect vulnerabilities in URL parameters"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Build a non-following client to see redirects
        let no_redirect_client = reqwest::Client::builder()
            .user_agent(&ctx.config.scan.user_agent)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| ScorchError::Config(format!("client build error: {e}")))?;

        // 1. Test the target URL's own parameters
        test_url_params_redirect(&no_redirect_client, url, &mut findings).await?;

        // 2. Spider for redirect-like parameters
        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;
        let body = response.text().await.unwrap_or_default();
        let links = extract_redirect_links(&body, &ctx.target.url);

        for link in &links {
            test_url_params_redirect(&no_redirect_client, link, &mut findings).await?;
        }

        Ok(findings)
    }
}

async fn test_url_params_redirect(
    client: &reqwest::Client,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let Ok(parsed) = Url::parse(url_str) else {
        return Ok(());
    };

    let params: Vec<(String, String)> =
        parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    for (param_name, _) in &params {
        let lower = param_name.to_lowercase();
        if !REDIRECT_PARAM_NAMES.iter().any(|p| lower.contains(p)) {
            continue;
        }

        // Inject an external URL
        let evil_url = "https://evil-attacker.com/pwned";
        let mut test_url = parsed.clone();
        {
            let mut q = test_url.query_pairs_mut();
            q.clear();
            for (k, v) in &params {
                if k == param_name {
                    q.append_pair(k, evil_url);
                } else {
                    q.append_pair(k, v);
                }
            }
        }

        if let Ok(resp) = client.get(test_url.as_str()).send().await {
            let status = resp.status();
            if status.is_redirection() {
                if let Some(location) = resp.headers().get("location") {
                    let loc = location.to_str().unwrap_or("");
                    if loc.contains("evil-attacker.com") {
                        findings.push(
                            Finding::new("redirect", Severity::Medium, format!("Open Redirect: {param_name}"), format!("The parameter '{param_name}' redirects to arbitrary external URLs."), url_str)
                                .with_evidence(format!("Parameter: {param_name} | Payload: {evil_url} | Location: {loc}"))
                                .with_remediation("Validate redirect destinations against an allowlist of trusted domains")
                                .with_owasp("A01:2021 Broken Access Control")
                                .with_cwe(601)
                                .with_confidence(0.8),
                        );
                        return Ok(());
                    }
                }
            }
        }
    }

    Ok(())
}

fn extract_redirect_links(body: &str, base_url: &Url) -> Vec<String> {
    let document = Html::parse_document(body);
    let mut links = Vec::new();
    let Ok(selector) = Selector::parse("a[href]") else { return links };

    for el in document.select(&selector) {
        if let Some(href) = el.value().attr("href") {
            if let Ok(resolved) = base_url.join(href) {
                if resolved.host() == base_url.host() {
                    let has_redirect_param = resolved.query_pairs().any(|(k, _)| {
                        REDIRECT_PARAM_NAMES.iter().any(|p| k.to_lowercase().contains(p))
                    });
                    if has_redirect_param {
                        links.push(resolved.to_string());
                    }
                }
            }
        }
    }

    links.truncate(10);
    links
}

const REDIRECT_PARAM_NAMES: &[&str] = &[
    "url",
    "redirect",
    "return",
    "next",
    "dest",
    "destination",
    "rurl",
    "return_url",
    "redirect_uri",
    "redirect_url",
    "continue",
    "forward",
    "goto",
    "target",
    "redir",
    "returnto",
    "return_to",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for the open redirect detection module's helpers and constant data.

    /// Verify that `REDIRECT_PARAM_NAMES` is non-empty, contains well-known redirect
    /// parameter names, and all entries are lowercase without whitespace.
    #[test]
    fn test_redirect_param_names_integrity() {
        // Arrange & Assert: minimum count
        assert!(
            REDIRECT_PARAM_NAMES.len() >= 10,
            "Expected at least 10 redirect param names, found {}",
            REDIRECT_PARAM_NAMES.len()
        );

        // Well-known redirect parameters are present
        assert!(REDIRECT_PARAM_NAMES.contains(&"redirect"));
        assert!(REDIRECT_PARAM_NAMES.contains(&"url"));
        assert!(REDIRECT_PARAM_NAMES.contains(&"next"));
        assert!(REDIRECT_PARAM_NAMES.contains(&"redirect_uri"));

        // All entries are well-formed
        for name in REDIRECT_PARAM_NAMES {
            assert!(!name.is_empty(), "Param name should not be empty");
            assert_eq!(*name, name.to_lowercase(), "Param name '{name}' should be lowercase");
            assert!(!name.contains(' '), "Param name '{name}' should not contain spaces");
        }
    }

    /// Verify that `extract_redirect_links` extracts links with redirect-like parameters
    /// from HTML and filters to same-host links only.
    #[test]
    fn test_extract_redirect_links_finds_redirect_params() {
        // Arrange
        let base = Url::parse("https://example.com/").expect("valid base URL");
        let html = r#"
            <html><body>
                <a href="/login?redirect=https://example.com/dashboard">Login</a>
                <a href="/page?next=/home">Next page</a>
                <a href="https://evil.com/?url=foo">External</a>
                <a href="/about">No redirect param</a>
            </body></html>
        "#;

        // Act
        let links = extract_redirect_links(html, &base);

        // Assert: should find same-host links with redirect-like params
        assert!(!links.is_empty(), "Expected at least one redirect link extracted");
        // All extracted links should be on the same host
        for link in &links {
            let parsed = Url::parse(link).expect("extracted link should be a valid URL");
            assert_eq!(parsed.host(), base.host(), "Extracted link should be same-host");
        }
    }

    /// Verify that `extract_redirect_links` returns an empty list when no links
    /// have redirect-related query parameters.
    #[test]
    fn test_extract_redirect_links_empty_when_no_redirect_params() {
        // Arrange
        let base = Url::parse("https://example.com/").expect("valid base URL");
        let html = r#"
            <html><body>
                <a href="/about">About</a>
                <a href="/contact?subject=hello">Contact</a>
            </body></html>
        "#;

        // Act
        let links = extract_redirect_links(html, &base);

        // Assert
        assert!(links.is_empty(), "No redirect links expected from HTML without redirect params");
    }
}
