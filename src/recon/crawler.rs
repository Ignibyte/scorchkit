use std::collections::HashSet;

use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::engine::shared_data::keys;

/// Crawls the target to discover all endpoints, forms, and parameters.
#[derive(Debug)]
pub struct CrawlerModule;

#[async_trait]
impl ScanModule for CrawlerModule {
    fn name(&self) -> &'static str {
        "Web Crawler"
    }
    fn id(&self) -> &'static str {
        "crawler"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Crawl the target to discover endpoints, forms, and parameters"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let start_url = ctx.target.url.clone();
        let base_domain = ctx.target.domain.as_deref().unwrap_or("");
        let max_depth = 3;
        let max_pages = 100;

        let mut visited: HashSet<String> = HashSet::new();
        let mut to_visit: Vec<(String, u32)> = vec![(start_url.to_string(), 0)];
        let mut discovered_urls: HashSet<String> = HashSet::new();
        let mut discovered_forms: Vec<FormInfo> = Vec::new();
        let mut discovered_params: HashSet<String> = HashSet::new();
        let mut discovered_js: HashSet<String> = HashSet::new();

        while let Some((url_str, depth)) = to_visit.pop() {
            if depth > max_depth || visited.len() >= max_pages {
                break;
            }
            if visited.contains(&url_str) {
                continue;
            }

            // Scope check
            let Ok(parsed) = Url::parse(&url_str) else {
                continue;
            };
            if parsed.host_str() != Some(base_domain) {
                continue;
            }

            // Exclude common traps
            let path = parsed.path().to_lowercase();
            if path.contains("logout") || path.contains("signout") || path.contains("delete") {
                continue;
            }

            visited.insert(url_str.clone());

            let Ok(response) = ctx.http_client.get(&url_str).send().await else {
                continue;
            };

            let content_type =
                response.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");

            if !content_type.contains("html") && !content_type.contains("javascript") {
                continue;
            }

            let Ok(body) = response.text().await else {
                continue;
            };

            extract_page_content(
                &body,
                &parsed,
                &url_str,
                base_domain,
                depth,
                max_depth,
                &visited,
                &mut to_visit,
                &mut discovered_urls,
                &mut discovered_forms,
                &mut discovered_params,
                &mut discovered_js,
            );
        }

        // Publish discovered data for downstream modules
        ctx.shared_data.publish(keys::URLS, discovered_urls.iter().cloned().collect());
        ctx.shared_data
            .publish(keys::FORMS, discovered_forms.iter().map(|f| f.url.clone()).collect());
        ctx.shared_data.publish(keys::PARAMS, discovered_params.iter().cloned().collect());

        Ok(build_crawl_findings(
            &visited,
            &discovered_urls,
            &discovered_forms,
            &discovered_params,
            &discovered_js,
            ctx.target.url.as_str(),
        ))
    }
}

/// Extract links, forms, parameters, and JS references from a crawled page.
// JUSTIFICATION: extracted helper receives all crawl state from caller; bundling into
// a struct would add unnecessary indirection for a private function.
#[allow(clippy::too_many_arguments)]
fn extract_page_content(
    body: &str,
    parsed: &Url,
    url_str: &str,
    base_domain: &str,
    depth: u32,
    max_depth: u32,
    visited: &HashSet<String>,
    to_visit: &mut Vec<(String, u32)>,
    discovered_urls: &mut HashSet<String>,
    discovered_forms: &mut Vec<FormInfo>,
    discovered_params: &mut HashSet<String>,
    discovered_js: &mut HashSet<String>,
) {
    let document = Html::parse_document(body);

    // Extract links
    if let Ok(sel) = Selector::parse("a[href]") {
        for el in document.select(&sel) {
            if let Some(href) = el.value().attr("href") {
                if let Ok(resolved) = parsed.join(href) {
                    let resolved_str = resolved.to_string();
                    if resolved.host_str() == Some(base_domain) {
                        discovered_urls.insert(resolved_str.clone());
                        if !visited.contains(&resolved_str) && depth < max_depth {
                            to_visit.push((resolved_str, depth + 1));
                        }
                    }
                }
            }
        }
    }

    // Extract forms
    if let Ok(form_sel) = Selector::parse("form") {
        if let Ok(input_sel) = Selector::parse("input[name], textarea[name], select[name]") {
            for form in document.select(&form_sel) {
                let action = form.value().attr("action").unwrap_or("");
                let method = form.value().attr("method").unwrap_or("GET").to_uppercase();
                let resolved_action = if action.is_empty() {
                    url_str.to_owned()
                } else {
                    parsed.join(action).map_or_else(|_| url_str.to_owned(), |u| u.to_string())
                };

                let inputs: Vec<String> = form
                    .select(&input_sel)
                    .filter_map(|i| i.value().attr("name").map(String::from))
                    .collect();

                discovered_forms.push(FormInfo { url: resolved_action, method, fields: inputs });
            }
        }
    }

    // Extract URL parameters
    for (key, _) in parsed.query_pairs() {
        discovered_params.insert(key.to_string());
    }

    // Extract JS files
    if let Ok(script_sel) = Selector::parse("script[src]") {
        for script in document.select(&script_sel) {
            if let Some(src) = script.value().attr("src") {
                if let Ok(resolved) = parsed.join(src) {
                    discovered_js.insert(resolved.to_string());
                }
            }
        }
    }

    // Extract inline JS for API routes
    if let Ok(script_sel) = Selector::parse("script:not([src])") {
        for script in document.select(&script_sel) {
            let text = script.text().collect::<String>();
            extract_js_routes(&text, parsed, discovered_urls);
        }
    }
}

/// Build findings from crawl results.
fn build_crawl_findings(
    visited: &HashSet<String>,
    discovered_urls: &HashSet<String>,
    discovered_forms: &[FormInfo],
    discovered_params: &HashSet<String>,
    discovered_js: &HashSet<String>,
    target_url: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.push(
        Finding::new("crawler", Severity::Info, format!("Crawled {} Pages", visited.len()), format!("Web crawler visited {} pages and discovered {} unique URLs, {} forms, {} JS files.", visited.len(), discovered_urls.len(), discovered_forms.len(), discovered_js.len()), target_url)
            .with_evidence(format!("Pages: {} | URLs: {} | Forms: {} | Parameters: {} | JS files: {}", visited.len(), discovered_urls.len(), discovered_forms.len(), discovered_params.len(), discovered_js.len()))
            .with_confidence(0.5),
    );

    // Report forms with notable characteristics
    for form in discovered_forms {
        if form.method == "POST" && form.fields.len() > 1 {
            let fields = form.fields.join(", ");
            findings.push(
                Finding::new(
                    "crawler",
                    Severity::Info,
                    format!("Form Discovered: {} {}", form.method, form.url),
                    format!("POST form with fields: {fields}"),
                    &form.url,
                )
                .with_evidence(format!("{} {} | Fields: {fields}", form.method, form.url))
                .with_confidence(0.5),
            );
        }
    }

    // Report interesting URL parameters
    if !discovered_params.is_empty() {
        let param_list: Vec<&String> = discovered_params.iter().take(30).collect();
        findings.push(
            Finding::new(
                "crawler",
                Severity::Info,
                format!("{} URL Parameters Discovered", discovered_params.len()),
                "URL parameters found during crawling that may be testable for injection.",
                target_url,
            )
            .with_evidence(format!(
                "Parameters: {}",
                param_list.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ))
            .with_confidence(0.5),
        );
    }

    findings
}

#[derive(Debug)]
struct FormInfo {
    url: String,
    method: String,
    fields: Vec<String>,
}

/// Extract API routes from inline JavaScript.
fn extract_js_routes(js: &str, base_url: &Url, urls: &mut HashSet<String>) {
    // Look for fetch/axios/XMLHttpRequest URL patterns
    let route_patterns = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"];

    for line in js.lines() {
        let trimmed = line.trim();
        for pattern in &route_patterns {
            if let Some(pos) = trimmed.find(pattern) {
                // Extract the route string
                let route_start = trimmed[..pos].rfind(['"', '\'', '`']).map_or(pos, |p| p + 1);
                let route_end =
                    trimmed[pos..].find(['"', '\'', '`', ' ']).map_or(trimmed.len(), |p| p + pos);

                let route = &trimmed[route_start..route_end];
                if route.starts_with('/') {
                    if let Ok(resolved) = base_url.join(route) {
                        urls.insert(resolved.to_string());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// Unit tests for the web crawler module helpers.
    use super::*;

    /// Verify `extract_js_routes` finds fetch/axios-style API route patterns in JavaScript.
    #[test]
    fn test_extract_js_routes_fetch_patterns() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // Arrange
        let base_url = Url::parse("https://example.com")?;
        let js = r#"
            fetch("/api/users/list");
            axios.get("/v1/products");
        "#;
        let mut urls = HashSet::new();

        // Act
        extract_js_routes(js, &base_url, &mut urls);

        // Assert
        assert!(
            urls.contains("https://example.com/api/users/list"),
            "should extract /api/users/list route"
        );
        assert!(
            urls.contains("https://example.com/v1/products"),
            "should extract /v1/products route"
        );
        Ok(())
    }

    /// Verify `extract_js_routes` finds API route string literals.
    #[test]
    fn test_extract_js_routes_api_routes() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Arrange
        let base_url = Url::parse("https://example.com")?;
        let js = r#"const endpoint = "/rest/v2/resource";"#;
        let mut urls = HashSet::new();

        // Act
        extract_js_routes(js, &base_url, &mut urls);

        // Assert
        assert!(
            urls.contains("https://example.com/rest/v2/resource"),
            "should extract /rest/v2/resource route"
        );
        Ok(())
    }

    /// Verify `extract_js_routes` produces no results from empty JavaScript.
    #[test]
    fn test_extract_js_routes_empty_js() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Arrange
        let base_url = Url::parse("https://example.com")?;
        let js = "";
        let mut urls = HashSet::new();

        // Act
        extract_js_routes(js, &base_url, &mut urls);

        // Assert
        assert!(urls.is_empty(), "empty JS should yield no routes");
        Ok(())
    }

    /// Verify `extract_page_content` extracts links and forms from HTML.
    #[test]
    fn test_extract_page_content_links_and_forms(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Arrange
        let html = r#"<html><body>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
            <form method="POST" action="/login">
                <input name="username" type="text">
                <input name="password" type="password">
            </form>
        </body></html>"#;
        let parsed = Url::parse("https://example.com/page")?;
        let url_str = "https://example.com/page";
        let base_domain = "example.com";
        let visited: HashSet<String> = HashSet::new();
        let mut to_visit: Vec<(String, u32)> = Vec::new();
        let mut discovered_urls: HashSet<String> = HashSet::new();
        let mut discovered_forms: Vec<FormInfo> = Vec::new();
        let mut discovered_params: HashSet<String> = HashSet::new();
        let mut discovered_js: HashSet<String> = HashSet::new();

        // Act
        extract_page_content(
            html,
            &parsed,
            url_str,
            base_domain,
            0,
            3,
            &visited,
            &mut to_visit,
            &mut discovered_urls,
            &mut discovered_forms,
            &mut discovered_params,
            &mut discovered_js,
        );

        // Assert
        assert!(
            discovered_urls.contains("https://example.com/about"),
            "should discover /about link"
        );
        assert!(
            discovered_urls.contains("https://example.com/contact"),
            "should discover /contact link"
        );
        assert_eq!(discovered_forms.len(), 1, "should discover one form");
        assert_eq!(discovered_forms[0].method, "POST");
        assert!(discovered_forms[0].fields.contains(&"username".to_string()));
        assert!(discovered_forms[0].fields.contains(&"password".to_string()));
        Ok(())
    }

    /// Verify `build_crawl_findings` returns a summary finding even with empty results.
    #[test]
    fn test_build_crawl_findings_empty() {
        // Arrange
        let visited: HashSet<String> = HashSet::new();
        let discovered_urls: HashSet<String> = HashSet::new();
        let discovered_forms: Vec<FormInfo> = Vec::new();
        let discovered_params: HashSet<String> = HashSet::new();
        let discovered_js: HashSet<String> = HashSet::new();

        // Act
        let findings = build_crawl_findings(
            &visited,
            &discovered_urls,
            &discovered_forms,
            &discovered_params,
            &discovered_js,
            "https://example.com",
        );

        // Assert — always produces at least the summary finding
        assert_eq!(findings.len(), 1, "empty crawl should produce exactly one summary finding");
    }

    /// Verify `build_crawl_findings` includes form and parameter findings when data is present.
    #[test]
    fn test_build_crawl_findings_with_data() {
        // Arrange
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert("https://example.com/".to_string());
        let mut discovered_urls: HashSet<String> = HashSet::new();
        discovered_urls.insert("https://example.com/about".to_string());
        let discovered_forms = vec![FormInfo {
            url: "https://example.com/login".to_string(),
            method: "POST".to_string(),
            fields: vec!["user".to_string(), "pass".to_string()],
        }];
        let mut discovered_params: HashSet<String> = HashSet::new();
        discovered_params.insert("q".to_string());
        let discovered_js: HashSet<String> = HashSet::new();

        // Act
        let findings = build_crawl_findings(
            &visited,
            &discovered_urls,
            &discovered_forms,
            &discovered_params,
            &discovered_js,
            "https://example.com",
        );

        // Assert — summary + form + parameters = 3 findings
        assert!(
            findings.len() >= 3,
            "crawl with forms and params should produce multiple findings, got {}",
            findings.len()
        );
    }
}
