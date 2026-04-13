use async_trait::async_trait;
use scraper::{Html, Selector};

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Fingerprints technologies used by the target web application.
#[derive(Debug)]
pub struct TechModule;

#[async_trait]
impl ScanModule for TechModule {
    fn name(&self) -> &'static str {
        "Technology Fingerprinting"
    }

    fn id(&self) -> &'static str {
        "tech"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Detect server technologies, frameworks, and CMS platforms"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();

        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let headers = response.headers().clone();
        let body = response
            .text()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let mut findings = Vec::new();

        detect_server_tech(&headers, url, &mut findings);
        detect_powered_by(&headers, url, &mut findings);
        detect_meta_generator(&body, url, &mut findings);
        detect_cookie_tech(&headers, url, &mut findings);
        detect_framework_signatures(&headers, &body, url, &mut findings);
        detect_cms_indicators(&body, url, &mut findings);

        // Publish detected technologies for downstream modules
        let techs: Vec<String> = findings.iter().map(|f| f.title.clone()).collect();
        ctx.shared_data.publish(crate::engine::shared_data::keys::TECHNOLOGIES, techs);

        Ok(findings)
    }
}

/// Detect technology from the Server header.
fn detect_server_tech(
    headers: &reqwest::header::HeaderMap,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    if let Some(value) = headers.get("server") {
        let val = value.to_str().unwrap_or("");
        if !val.is_empty() {
            let techs = identify_server(val);
            let tech_list = if techs.is_empty() { val.to_string() } else { techs.join(", ") };

            findings.push(
                Finding::new(
                    "tech",
                    Severity::Info,
                    "Server Technology Detected",
                    format!("Server technology identified: {tech_list}"),
                    url,
                )
                .with_evidence(format!("Server: {val}"))
                .with_confidence(0.7),
            );
        }
    }
}

/// Detect technology from X-Powered-By header.
fn detect_powered_by(headers: &reqwest::header::HeaderMap, url: &str, findings: &mut Vec<Finding>) {
    if let Some(value) = headers.get("x-powered-by") {
        let val = value.to_str().unwrap_or("");
        if !val.is_empty() {
            findings.push(
                Finding::new(
                    "tech",
                    Severity::Info,
                    "Framework/Runtime Detected via X-Powered-By",
                    format!("The X-Powered-By header reveals: {val}"),
                    url,
                )
                .with_evidence(format!("X-Powered-By: {val}"))
                .with_confidence(0.7),
            );
        }
    }

    // Also check X-AspNet-Version, X-AspNetMvc-Version
    for header_name in &["x-aspnet-version", "x-aspnetmvc-version"] {
        if let Some(value) = headers.get(*header_name) {
            let val = value.to_str().unwrap_or("");
            findings.push(
                Finding::new(
                    "tech",
                    Severity::Info,
                    "ASP.NET Version Detected",
                    format!("{header_name} header reveals version: {val}"),
                    url,
                )
                .with_evidence(format!("{header_name}: {val}"))
                .with_confidence(0.7),
            );
        }
    }
}

/// Detect CMS/framework from <meta name="generator"> tags.
fn detect_meta_generator(body: &str, url: &str, findings: &mut Vec<Finding>) {
    let document = Html::parse_document(body);

    let Ok(selector) = Selector::parse("meta[name='generator']") else {
        return;
    };

    for element in document.select(&selector) {
        if let Some(content) = element.value().attr("content") {
            if !content.is_empty() {
                findings.push(
                    Finding::new(
                        "tech",
                        Severity::Info,
                        "CMS/Framework Detected via Meta Generator",
                        format!("The page declares its generator: {content}"),
                        url,
                    )
                    .with_evidence(format!("<meta name=\"generator\" content=\"{content}\">"))
                    .with_confidence(0.7),
                );
            }
        }
    }
}

/// Detect technology from cookie names.
fn detect_cookie_tech(
    headers: &reqwest::header::HeaderMap,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    let cookie_headers: Vec<&str> =
        headers.get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()).collect();

    if cookie_headers.is_empty() {
        return;
    }

    let all_cookies = cookie_headers.join("; ");

    let mut detected: Vec<(&str, &str)> = Vec::new();

    for &(pattern, tech) in COOKIE_PATTERNS {
        if all_cookies.to_lowercase().contains(pattern.to_lowercase().as_str()) {
            detected.push((pattern, tech));
        }
    }

    if !detected.is_empty() {
        let tech_list: Vec<String> =
            detected.iter().map(|(cookie, tech)| format!("{tech} (cookie: {cookie})")).collect();

        findings.push(
            Finding::new(
                "tech",
                Severity::Info,
                "Technology Detected via Cookie Names",
                format!("Cookie names suggest: {}", tech_list.join(", ")),
                url,
            )
            .with_evidence(format!(
                "Cookies: {}",
                detected.iter().map(|(c, _)| *c).collect::<Vec<_>>().join(", ")
            ))
            .with_confidence(0.7),
        );
    }
}

/// Detect frameworks from response headers and body patterns.
fn detect_framework_signatures(
    headers: &reqwest::header::HeaderMap,
    body: &str,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    let mut detected: Vec<&str> = Vec::new();

    // Header-based detection
    if headers.get("x-drupal-cache").is_some()
        || headers
            .get("x-generator")
            .is_some_and(|v| v.to_str().unwrap_or("").to_lowercase().contains("drupal"))
    {
        detected.push("Drupal");
    }
    if headers.get("x-shopify-stage").is_some() {
        detected.push("Shopify");
    }
    if headers.get("x-wix-request-id").is_some() {
        detected.push("Wix");
    }
    if headers.get("x-vercel-id").is_some() {
        detected.push("Vercel");
    }
    if headers.get("x-netlify-request-id").is_some() || headers.get("x-nf-request-id").is_some() {
        detected.push("Netlify");
    }
    if headers.get("cf-ray").is_some() {
        detected.push("Cloudflare");
    }
    if headers.get("x-amz-cf-id").is_some() || headers.get("x-amz-request-id").is_some() {
        detected.push("AWS");
    }
    if headers.get("x-firebase-hosting").is_some() {
        detected.push("Firebase Hosting");
    }

    // Body-based detection
    let body_lower = body.to_lowercase();
    for &(pattern, tech) in BODY_SIGNATURES {
        if body_lower.contains(pattern) && !detected.contains(&tech) {
            detected.push(tech);
        }
    }

    for tech in &detected {
        findings.push(
            Finding::new(
                "tech",
                Severity::Info,
                format!("{tech} Detected"),
                format!("The target appears to use {tech}"),
                url,
            )
            .with_evidence("Detected via response signatures".to_string())
            .with_confidence(0.7),
        );
    }
}

/// Detect CMS-specific indicators in the HTML body.
fn detect_cms_indicators(body: &str, url: &str, findings: &mut Vec<Finding>) {
    let document = Html::parse_document(body);

    // Check for common CSS/JS paths that reveal CMS
    let Ok(link_selector) = Selector::parse("link[href], script[src]") else {
        return;
    };

    let mut detected_cms: Vec<&str> = Vec::new();

    for element in document.select(&link_selector) {
        let attr =
            element.value().attr("href").or_else(|| element.value().attr("src")).unwrap_or("");

        let attr_lower = attr.to_lowercase();

        for &(pattern, cms) in ASSET_PATH_PATTERNS {
            if attr_lower.contains(pattern) && !detected_cms.contains(&cms) {
                detected_cms.push(cms);
            }
        }
    }

    for cms in &detected_cms {
        findings.push(
            Finding::new(
                "tech",
                Severity::Info,
                format!("{cms} Detected via Asset Paths"),
                format!("Asset paths in the HTML suggest {cms} is in use"),
                url,
            )
            .with_evidence("Detected via CSS/JS resource paths".to_string())
            .with_confidence(0.7),
        );
    }
}

// --- Detection databases ---

fn identify_server(server_header: &str) -> Vec<String> {
    let lower = server_header.to_lowercase();
    let mut techs = Vec::new();

    let patterns: &[(&str, &str)] = &[
        ("nginx", "Nginx"),
        ("apache", "Apache"),
        ("iis", "Microsoft IIS"),
        ("litespeed", "LiteSpeed"),
        ("caddy", "Caddy"),
        ("cloudflare", "Cloudflare"),
        ("openresty", "OpenResty"),
        ("gunicorn", "Gunicorn (Python)"),
        ("uvicorn", "Uvicorn (Python)"),
        ("express", "Express.js"),
        ("kestrel", "Kestrel (ASP.NET)"),
        ("cowboy", "Cowboy (Erlang)"),
        ("envoy", "Envoy Proxy"),
        ("traefik", "Traefik"),
        ("jetty", "Jetty (Java)"),
        ("tomcat", "Apache Tomcat"),
        ("werkzeug", "Werkzeug (Python/Flask)"),
        ("phusion passenger", "Phusion Passenger"),
        ("thin", "Thin (Ruby)"),
        ("puma", "Puma (Ruby)"),
    ];

    for &(pattern, name) in patterns {
        if lower.contains(pattern) {
            techs.push(name.to_string());
        }
    }

    techs
}

/// Cookie name → technology mapping.
const COOKIE_PATTERNS: &[(&str, &str)] = &[
    ("JSESSIONID", "Java"),
    ("PHPSESSID", "PHP"),
    ("ASP.NET_SessionId", "ASP.NET"),
    ("ASPSESSIONID", "Classic ASP"),
    ("laravel_session", "Laravel (PHP)"),
    ("ci_session", "CodeIgniter (PHP)"),
    ("connect.sid", "Express.js (Node.js)"),
    ("_rails_session", "Ruby on Rails"),
    ("rack.session", "Rack (Ruby)"),
    ("SERVERID", "HAProxy"),
    ("AWSALB", "AWS ALB"),
    ("AWSALBCORS", "AWS ALB"),
    ("__cfduid", "Cloudflare"),
    ("cf_clearance", "Cloudflare"),
    ("wp-settings-", "WordPress"),
    ("wordpress_logged_in", "WordPress"),
    ("Drupal.visitor", "Drupal"),
    ("SSESS", "Drupal"),
    ("csrftoken", "Django (Python)"),
    ("sessionid", "Django (Python)"),
    ("_ga", "Google Analytics"),
    ("_gid", "Google Analytics"),
    ("__stripe_mid", "Stripe"),
];

/// Body content patterns → technology.
const BODY_SIGNATURES: &[(&str, &str)] = &[
    ("wp-content/", "WordPress"),
    ("wp-includes/", "WordPress"),
    ("wp-json/", "WordPress"),
    ("/sites/default/files/", "Drupal"),
    ("drupal.js", "Drupal"),
    ("jquery.once", "Drupal"),
    ("joomla", "Joomla"),
    ("/media/system/js/", "Joomla"),
    ("shopify.com/s/files", "Shopify"),
    ("cdn.shopify.com", "Shopify"),
    ("squarespace.com", "Squarespace"),
    ("static.squarespace.com", "Squarespace"),
    ("_next/static", "Next.js"),
    ("__next", "Next.js"),
    ("__nuxt", "Nuxt.js"),
    ("_sveltekit", "SvelteKit"),
    ("gatsby-", "Gatsby"),
    ("data-reactroot", "React"),
    ("ng-version", "Angular"),
    ("data-v-", "Vue.js"),
    ("ember-view", "Ember.js"),
    ("ghost.io", "Ghost CMS"),
    ("ghost-url", "Ghost CMS"),
    ("typo3temp/", "TYPO3"),
    ("magento/", "Magento"),
    ("skin/frontend/", "Magento"),
];

/// Asset path patterns → CMS/framework.
const ASSET_PATH_PATTERNS: &[(&str, &str)] = &[
    ("/wp-content/", "WordPress"),
    ("/wp-includes/", "WordPress"),
    ("/sites/all/", "Drupal"),
    ("/sites/default/", "Drupal"),
    ("/core/misc/", "Drupal"),
    ("/modules/", "Drupal"),
    ("/media/system/", "Joomla"),
    ("/components/com_", "Joomla"),
    ("/_next/", "Next.js"),
    ("/__nuxt/", "Nuxt.js"),
    ("/static/js/main.", "Create React App"),
    ("/build/", "Laravel Mix"),
    ("/bundles/", "Symfony"),
    ("/typo3conf/", "TYPO3"),
    ("/skin/frontend/", "Magento"),
    ("/static/version", "Magento 2"),
];

#[cfg(test)]
mod tests {
    /// Unit tests for technology fingerprinting helpers.
    use super::*;

    /// Verify `identify_server` detects Nginx from a server header.
    #[test]
    fn test_identify_server_nginx() {
        // Arrange
        let header = "nginx/1.24.0";

        // Act
        let techs = identify_server(header);

        // Assert
        assert_eq!(techs.len(), 1);
        assert_eq!(techs[0], "Nginx");
    }

    /// Verify `identify_server` detects Apache from a server header.
    #[test]
    fn test_identify_server_apache() {
        // Arrange
        let header = "Apache/2.4.52 (Ubuntu)";

        // Act
        let techs = identify_server(header);

        // Assert
        assert_eq!(techs.len(), 1);
        assert_eq!(techs[0], "Apache");
    }

    /// Verify `identify_server` detects Microsoft IIS from a server header.
    #[test]
    fn test_identify_server_iis() {
        // Arrange
        let header = "Microsoft-IIS/10.0";

        // Act
        let techs = identify_server(header);

        // Assert
        assert_eq!(techs.len(), 1);
        assert_eq!(techs[0], "Microsoft IIS");
    }

    /// Verify `identify_server` returns an empty list for an unknown server header.
    #[test]
    fn test_identify_server_unknown() {
        // Arrange
        let header = "MyCustomServer/3.0";

        // Act
        let techs = identify_server(header);

        // Assert
        assert!(techs.is_empty());
    }

    /// Verify `identify_server` performs case-insensitive matching.
    #[test]
    fn test_identify_server_case_insensitive() {
        // Arrange
        let header = "NGINX";

        // Act
        let techs = identify_server(header);

        // Assert
        assert_eq!(techs.len(), 1);
        assert_eq!(techs[0], "Nginx");
    }
}
