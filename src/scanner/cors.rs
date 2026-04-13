//! Deep CORS policy analysis module.
//!
//! Tests CORS configurations beyond the basic origin reflection checks in
//! [`super::misconfig`]. Analyzes subdomain wildcard patterns, preflight
//! cache duration, overly permissive method/header allowlists, sensitive
//! header exposure, and internal network origin acceptance.

use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Deep CORS policy analysis beyond basic origin reflection.
///
/// Complements [`super::misconfig`] (which tests origin reflection, wildcard,
/// null origin) with deeper policy analysis: subdomain wildcards, preflight
/// caching abuse, method allowlists, header exposure, and internal origin bypass.
#[derive(Debug)]
pub struct CorsModule;

#[async_trait]
impl ScanModule for CorsModule {
    fn name(&self) -> &'static str {
        "CORS Deep Analysis"
    }

    fn id(&self) -> &'static str {
        "cors-deep"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Deep CORS testing: subdomain wildcards, preflight cache, method allowlists, internal origins"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let domain = ctx.target.domain.as_deref().unwrap_or("");
        let mut findings = Vec::new();

        // Test subdomain origin reflection
        let subdomain_origin = format!("https://evil.{domain}");
        test_origin(
            ctx,
            url,
            &subdomain_origin,
            &mut findings,
            |acao| acao == subdomain_origin,
            "Subdomain CORS Bypass",
            Severity::High,
            "The server reflects subdomain origins in CORS, allowing any subdomain \
             (including attacker-controlled ones via subdomain takeover) to make \
             cross-origin requests.",
            "Validate origins against an exact allowlist. Do not accept \
             arbitrary subdomains unless each is trusted.",
        )
        .await?;

        // Test internal network origins
        for internal in INTERNAL_ORIGINS {
            test_origin(
                ctx,
                url,
                internal,
                &mut findings,
                |acao| acao == *internal,
                "Internal Network CORS Bypass",
                Severity::High,
                &format!(
                    "The server reflects the internal origin '{internal}' in CORS. \
                     An attacker on the internal network or via SSRF can make \
                     authenticated cross-origin requests."
                ),
                "Never allow internal/private network origins in CORS for \
                 public-facing endpoints.",
            )
            .await?;
        }

        // Analyze preflight response headers
        let preflight_response = ctx
            .http_client
            .request(reqwest::Method::OPTIONS, url)
            .header("Origin", format!("https://{domain}"))
            .header("Access-Control-Request-Method", "POST")
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let headers = preflight_response.headers();

        // Check preflight cache duration
        if let Some(max_age) = headers
            .get("access-control-max-age")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        {
            check_preflight_max_age(max_age, url, &mut findings);
        }

        // Check method allowlist
        if let Some(methods) =
            headers.get("access-control-allow-methods").and_then(|v| v.to_str().ok())
        {
            check_method_allowlist(methods, url, &mut findings);
        }

        // Check exposed headers
        if let Some(exposed) =
            headers.get("access-control-expose-headers").and_then(|v| v.to_str().ok())
        {
            check_exposed_headers(exposed, url, &mut findings);
        }

        Ok(findings)
    }
}

/// Send a request with a specific Origin and check the CORS response.
#[allow(clippy::too_many_arguments)] // CORS test parameters are all distinct and required
async fn test_origin(
    ctx: &ScanContext,
    url: &str,
    origin: &str,
    findings: &mut Vec<Finding>,
    matches: impl Fn(&str) -> bool,
    title: &str,
    severity: Severity,
    description: &str,
    remediation: &str,
) -> Result<()> {
    let Ok(response) = ctx.http_client.get(url).header("Origin", origin).send().await else {
        return Ok(());
    };

    if let Some(acao) =
        response.headers().get("access-control-allow-origin").and_then(|v| v.to_str().ok())
    {
        if matches(acao) {
            findings.push(
                Finding::new("cors-deep", severity, title, description, url)
                    .with_evidence(format!(
                        "Origin: {origin} → Access-Control-Allow-Origin: {acao}"
                    ))
                    .with_remediation(remediation)
                    .with_owasp("A05:2021 Security Misconfiguration")
                    .with_cwe(942)
                    .with_confidence(0.9),
            );
        }
    }

    Ok(())
}

/// Check if preflight cache duration is excessively long.
///
/// A long `Access-Control-Max-Age` allows attackers to cache a permissive
/// preflight response, extending the window for CORS exploitation.
fn check_preflight_max_age(max_age: u64, url: &str, findings: &mut Vec<Finding>) {
    // 2 hours = 7200 seconds — anything longer is suspicious
    if max_age > 7200 {
        #[allow(clippy::cast_precision_loss)] // Display only — precision irrelevant
        let hours = max_age as f64 / 3600.0;
        findings.push(
            Finding::new(
                "cors-deep",
                Severity::Low,
                "Excessive Preflight Cache Duration",
                format!(
                    "The CORS preflight response has Access-Control-Max-Age of \
                     {max_age} seconds ({hours:.1} hours). Long preflight caching extends \
                     the exploitation window if CORS is misconfigured."
                ),
                url,
            )
            .with_evidence(format!("Access-Control-Max-Age: {max_age}"))
            .with_remediation(
                "Set Access-Control-Max-Age to a reasonable value (600-3600 seconds). \
                 Shorter values allow faster recovery from CORS misconfigurations.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(525)
            .with_confidence(0.9),
        );
    }
}

/// Check if the method allowlist is overly permissive.
///
/// Allowing dangerous methods like PUT, DELETE, PATCH in CORS when they're
/// not needed increases the attack surface.
fn check_method_allowlist(methods: &str, url: &str, findings: &mut Vec<Finding>) {
    let dangerous = ["PUT", "DELETE", "PATCH"];
    let allowed: Vec<&str> = methods.split(',').map(str::trim).collect();

    let found_dangerous: Vec<&&str> =
        dangerous.iter().filter(|d| allowed.iter().any(|a| a.eq_ignore_ascii_case(d))).collect();

    if found_dangerous.len() >= 2 {
        findings.push(
            Finding::new(
                "cors-deep",
                Severity::Low,
                "Overly Permissive CORS Methods",
                format!(
                    "The CORS policy allows dangerous HTTP methods: {}. Unless your \
                     API requires cross-origin PUT/DELETE/PATCH, these should be restricted.",
                    found_dangerous.iter().map(|d| **d).collect::<Vec<_>>().join(", ")
                ),
                url,
            )
            .with_evidence(format!("Access-Control-Allow-Methods: {methods}"))
            .with_remediation(
                "Only allow HTTP methods that are actually needed for cross-origin \
                 requests. Typically only GET and POST are required.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(942)
            .with_confidence(0.9),
        );
    }
}

/// Check if sensitive headers are exposed via CORS.
///
/// `Access-Control-Expose-Headers` makes response headers readable by
/// cross-origin JavaScript. Exposing auth-related headers is dangerous.
fn check_exposed_headers(exposed: &str, url: &str, findings: &mut Vec<Finding>) {
    let sensitive =
        ["authorization", "set-cookie", "x-csrf-token", "x-api-key", "www-authenticate"];

    let exposed_lower = exposed.to_lowercase();
    let leaked: Vec<&str> =
        sensitive.iter().filter(|s| exposed_lower.contains(*s)).copied().collect();

    if !leaked.is_empty() {
        findings.push(
            Finding::new(
                "cors-deep",
                Severity::Medium,
                "Sensitive Headers Exposed via CORS",
                format!(
                    "The CORS policy exposes sensitive headers to cross-origin JavaScript: {}. \
                     This may leak authentication tokens or session data.",
                    leaked.join(", ")
                ),
                url,
            )
            .with_evidence(format!("Access-Control-Expose-Headers: {exposed}"))
            .with_remediation(
                "Only expose headers that cross-origin clients genuinely need. \
                 Never expose Authorization, Set-Cookie, or API key headers.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(200)
            .with_confidence(0.9),
        );
    }
}

/// Internal network origins to test.
const INTERNAL_ORIGINS: &[&str] = &[
    "http://localhost",
    "http://127.0.0.1",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for deep CORS analysis.

    /// Check if an origin is an internal/private network address.
    fn is_internal_origin(origin: &str) -> bool {
        let lower = origin.to_lowercase();
        let host = lower
            .strip_prefix("http://")
            .or_else(|| lower.strip_prefix("https://"))
            .unwrap_or(&lower);
        let host = host.split(':').next().unwrap_or(host);

        host == "localhost"
            || host == "127.0.0.1"
            || host == "[::1]"
            || host.starts_with("10.")
            || host.starts_with("192.168.")
            || (host.starts_with("172.")
                && host
                    .split('.')
                    .nth(1)
                    .and_then(|s| s.parse::<u8>().ok())
                    .is_some_and(|n| (16..=31).contains(&n)))
            || host.ends_with(".local")
            || host.ends_with(".internal")
    }

    /// Verify internal origin detection for RFC 1918 and localhost addresses.
    #[test]
    fn test_is_internal_origin() {
        assert!(is_internal_origin("http://localhost"));
        assert!(is_internal_origin("http://127.0.0.1"));
        assert!(is_internal_origin("https://192.168.1.1"));
        assert!(is_internal_origin("http://10.0.0.1"));
        assert!(is_internal_origin("http://172.16.0.1"));
        assert!(is_internal_origin("http://172.31.255.255"));
        assert!(is_internal_origin("http://app.local"));
        assert!(is_internal_origin("http://api.internal"));

        // Not internal
        assert!(!is_internal_origin("https://example.com"));
        assert!(!is_internal_origin("http://172.32.0.1")); // Outside 172.16-31 range
        assert!(!is_internal_origin("https://google.com"));
    }

    /// Verify preflight max-age threshold detection.
    #[test]
    fn test_preflight_max_age() {
        let mut findings = Vec::new();

        // Under threshold — no finding
        check_preflight_max_age(3600, "https://example.com", &mut findings);
        assert!(findings.is_empty());

        // Over threshold — finding
        check_preflight_max_age(86400, "https://example.com", &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Excessive Preflight"));
    }

    /// Verify method allowlist analysis.
    #[test]
    fn test_method_allowlist() {
        let mut findings = Vec::new();

        // Safe methods only — no finding
        check_method_allowlist("GET, POST", "https://example.com", &mut findings);
        assert!(findings.is_empty());

        // Single dangerous method — no finding (threshold is 2)
        check_method_allowlist("GET, POST, PUT", "https://example.com", &mut findings);
        assert!(findings.is_empty());

        // Multiple dangerous — finding
        check_method_allowlist(
            "GET, POST, PUT, DELETE, PATCH",
            "https://example.com",
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Permissive CORS Methods"));
    }

    /// Verify sensitive header exposure detection.
    #[test]
    fn test_exposed_headers() {
        let mut findings = Vec::new();

        // Safe headers — no finding
        check_exposed_headers("Content-Length, X-Request-Id", "https://example.com", &mut findings);
        assert!(findings.is_empty());

        // Sensitive headers — finding
        check_exposed_headers(
            "Content-Length, Authorization, X-Api-Key",
            "https://example.com",
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Sensitive Headers"));
    }

    /// Verify internal origins list covers key private ranges.
    #[test]
    fn test_internal_origins_list() {
        assert!(INTERNAL_ORIGINS.len() >= 5);
        for origin in INTERNAL_ORIGINS {
            assert!(
                is_internal_origin(origin),
                "Listed origin '{origin}' not detected as internal"
            );
        }
    }
}
