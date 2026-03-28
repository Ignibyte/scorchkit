use std::collections::HashSet;

use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

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
            let parsed = match Url::parse(&url_str) {
                Ok(u) => u,
                Err(_) => continue,
            };
            if parsed.host_str().map_or(true, |h| h != base_domain) {
                continue;
            }

            // Exclude common traps
            let path = parsed.path().to_lowercase();
            if path.contains("logout") || path.contains("signout") || path.contains("delete") {
                continue;
            }

            visited.insert(url_str.clone());

            let response = match ctx.http_client.get(&url_str).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let content_type =
                response.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");

            if !content_type.contains("html") && !content_type.contains("javascript") {
                continue;
            }

            let body = match response.text().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            let document = Html::parse_document(&body);

            // Extract links
            if let Ok(sel) = Selector::parse("a[href]") {
                for el in document.select(&sel) {
                    if let Some(href) = el.value().attr("href") {
                        if let Ok(resolved) = parsed.join(href) {
                            let resolved_str = resolved.to_string();
                            if resolved.host_str().map_or(false, |h| h == base_domain) {
                                discovered_urls.insert(resolved_str.clone());
                                if !visited.contains(&resolved_str) && depth + 1 <= max_depth {
                                    to_visit.push((resolved_str, depth + 1));
                                }
                            }
                        }
                    }
                }
            }

            // Extract forms
            if let Ok(form_sel) = Selector::parse("form") {
                if let Ok(input_sel) = Selector::parse("input[name], textarea[name], select[name]")
                {
                    for form in document.select(&form_sel) {
                        let action = form.value().attr("action").unwrap_or("");
                        let method = form.value().attr("method").unwrap_or("GET").to_uppercase();
                        let resolved_action = if action.is_empty() {
                            url_str.clone()
                        } else {
                            parsed.join(action).map_or(url_str.clone(), |u| u.to_string())
                        };

                        let inputs: Vec<String> = form
                            .select(&input_sel)
                            .filter_map(|i| i.value().attr("name").map(String::from))
                            .collect();

                        discovered_forms.push(FormInfo {
                            url: resolved_action,
                            method,
                            fields: inputs,
                        });
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
                    extract_js_routes(&text, &parsed, &mut discovered_urls);
                }
            }
        }

        // Build findings
        let mut findings = Vec::new();

        findings.push(
            Finding::new("crawler", Severity::Info, format!("Crawled {} Pages", visited.len()), format!("Web crawler visited {} pages and discovered {} unique URLs, {} forms, {} JS files.", visited.len(), discovered_urls.len(), discovered_forms.len(), discovered_js.len()), ctx.target.url.as_str())
                .with_evidence(format!("Pages: {} | URLs: {} | Forms: {} | Parameters: {} | JS files: {}", visited.len(), discovered_urls.len(), discovered_forms.len(), discovered_params.len(), discovered_js.len())),
        );

        // Report forms with notable characteristics
        for form in &discovered_forms {
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
                    .with_evidence(format!("{} {} | Fields: {fields}", form.method, form.url)),
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
                    ctx.target.url.as_str(),
                )
                .with_evidence(format!(
                    "Parameters: {}",
                    param_list.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                )),
            );
        }

        Ok(findings)
    }
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
                let route_start = trimmed[..pos]
                    .rfind(|c: char| c == '"' || c == '\'' || c == '`')
                    .map_or(pos, |p| p + 1);
                let route_end = trimmed[pos..]
                    .find(|c: char| c == '"' || c == '\'' || c == '`' || c == ' ')
                    .map_or(trimmed.len(), |p| p + pos);

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
