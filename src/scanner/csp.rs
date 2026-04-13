//! CSP bypass detection module.
//!
//! Analyzes Content-Security-Policy headers for bypass-prone configurations
//! beyond the basic checks in [`crate::recon::headers`] (which tests for CSP
//! presence, `unsafe-inline`, `unsafe-eval`, and wildcard). This module
//! tests for missing critical directives, overly permissive `script-src`,
//! `report-uri` information leaks, and weak `default-src` fallbacks.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// CSP bypass detection via deep directive analysis.
///
/// Complements [`crate::recon::headers`] (which tests CSP presence and
/// `unsafe-inline`/`unsafe-eval`) with bypass-focused analysis: missing
/// critical directives, permissive `script-src`, `report-uri` leaks, and
/// weak `default-src`.
#[derive(Debug)]
pub struct CspModule;

#[async_trait]
impl ScanModule for CspModule {
    fn name(&self) -> &'static str {
        "CSP Bypass Detection"
    }

    fn id(&self) -> &'static str {
        "csp-deep"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Deep CSP analysis: missing directives, permissive script-src, report-uri leaks"
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

        let csp_header = response
            .headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let Some(csp) = csp_header else {
            return Ok(findings); // No CSP — handled by recon/headers.rs
        };

        let directives = parse_csp_directives(&csp);

        // Check missing critical directives
        check_missing_directives(&directives, url, &mut findings);

        // Check permissive script-src
        check_permissive_script_src(&directives, url, &mut findings);

        // Check overly permissive default-src
        check_permissive_default_src(&directives, url, &mut findings);

        // Check report-uri/report-to information leak
        check_report_uri_leak(&directives, &csp, url, &mut findings);

        Ok(findings)
    }
}

/// Parse a CSP header value into a map of directive → sources.
///
/// CSP format: `directive1 source1 source2; directive2 source3`
/// Returns `HashMap<"directive1", vec!["source1", "source2"]>`.
#[must_use]
fn parse_csp_directives(csp: &str) -> HashMap<String, Vec<String>> {
    csp.split(';')
        .filter_map(|directive| {
            let parts: Vec<&str> = directive.split_whitespace().collect();
            let name = parts.first()?;
            let sources = parts[1..].iter().map(|s| s.to_lowercase()).collect();
            Some((name.to_lowercase(), sources))
        })
        .collect()
}

/// Check for missing critical CSP directives.
///
/// Without `base-uri`, `object-src`, or `frame-ancestors`, specific XSS
/// and clickjacking bypass techniques remain viable.
fn check_missing_directives(
    directives: &HashMap<String, Vec<String>>,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    let critical_missing = [
        (
            "base-uri",
            "Missing base-uri Directive in CSP",
            "Without base-uri, an attacker can inject a <base> tag to redirect \
             relative URLs to a malicious server, bypassing CSP for script loading.",
            693_u32,
        ),
        (
            "object-src",
            "Missing object-src Directive in CSP",
            "Without object-src (and no restrictive default-src), plugins like \
             Flash or Java applets can be embedded for XSS bypass.",
            693,
        ),
        (
            "frame-ancestors",
            "Missing frame-ancestors Directive in CSP",
            "Without frame-ancestors, the page can be framed by any origin, \
             enabling clickjacking attacks. X-Frame-Options alone is insufficient.",
            1021,
        ),
    ];

    let has_restrictive_default = directives
        .get("default-src")
        .is_some_and(|sources| sources.iter().any(|s| s == "'none'" || s == "'self'"));

    for (directive, title, description, cwe) in &critical_missing {
        if !directives.contains_key(*directive) {
            // object-src missing is only an issue if default-src doesn't cover it
            if *directive == "object-src" && has_restrictive_default {
                continue;
            }
            // frame-ancestors is independent of default-src
            findings.push(
                Finding::new("csp-deep", Severity::Medium, *title, *description, url)
                    .with_evidence(format!("CSP lacks '{directive}' directive"))
                    .with_remediation(format!(
                        "Add `{directive}: 'none'` (or `{directive}: 'self'`) to your CSP policy."
                    ))
                    .with_owasp("A05:2021 Security Misconfiguration")
                    .with_cwe(*cwe)
                    .with_confidence(0.9),
            );
        }
    }
}

/// Check if `script-src` allows bypass-prone sources.
///
/// Sources like `data:`, `blob:`, or blanket `https:` in `script-src`
/// enable XSS bypass despite having a CSP.
fn check_permissive_script_src(
    directives: &HashMap<String, Vec<String>>,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    let script_sources = directives.get("script-src").or_else(|| directives.get("default-src"));

    let Some(sources) = script_sources else {
        return;
    };

    let dangerous_sources = [
        ("data:", "data: URIs allow inline script execution via <script src=\"data:text/javascript,...\">"),
        ("blob:", "blob: URIs allow dynamic script creation that bypasses CSP"),
        ("https:", "Blanket https: allows scripts from ANY HTTPS origin, including attacker-controlled CDNs"),
        ("http:", "Blanket http: allows scripts from ANY HTTP origin — completely negates CSP"),
    ];

    for (source, explanation) in &dangerous_sources {
        if sources.iter().any(|s| s == *source) {
            findings.push(
                Finding::new(
                    "csp-deep",
                    Severity::High,
                    format!("Permissive script-src: {source}"),
                    format!("The CSP script-src allows '{source}'. {explanation}."),
                    url,
                )
                .with_evidence(format!("script-src includes '{source}'"))
                .with_remediation(format!(
                    "Remove '{source}' from script-src. Use nonces or hashes for \
                     inline scripts, and specify exact trusted domains instead of \
                     protocol-based allowlists."
                ))
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(693)
                .with_confidence(0.9),
            );
        }
    }
}

/// Check if `default-src` is overly permissive.
///
/// `default-src *` or `default-src 'self' *` effectively negates the CSP,
/// allowing resources from any origin.
fn check_permissive_default_src(
    directives: &HashMap<String, Vec<String>>,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    let Some(sources) = directives.get("default-src") else {
        return;
    };

    // default-src contains bare * (not *.specific.com)
    if sources.iter().any(|s| s == "*") {
        findings.push(
            Finding::new(
                "csp-deep",
                Severity::High,
                "Permissive default-src: wildcard",
                "The CSP default-src includes '*', allowing resources from any \
                 origin. This effectively negates the Content-Security-Policy, \
                 providing no meaningful protection against XSS or data injection.",
                url,
            )
            .with_evidence("default-src includes '*'")
            .with_remediation(
                "Replace `default-src *` with `default-src 'self'` and add \
                 specific source directives (script-src, style-src, etc.) \
                 for each resource type that needs external origins.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(693)
            .with_confidence(0.9),
        );
    }
}

/// Check for `report-uri` or `report-to` information leaks.
///
/// Report endpoints reveal internal infrastructure URLs (monitoring systems,
/// security tooling paths) that attackers can use for reconnaissance.
fn check_report_uri_leak(
    directives: &HashMap<String, Vec<String>>,
    raw_csp: &str,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    let report_uri = directives.get("report-uri");
    let has_report_to = raw_csp.to_lowercase().contains("report-to");

    if let Some(uris) = report_uri {
        if !uris.is_empty() {
            findings.push(
                Finding::new(
                    "csp-deep",
                    Severity::Low,
                    "CSP Report URI Reveals Internal Infrastructure",
                    format!(
                        "The CSP report-uri directive exposes the reporting endpoint: {}. \
                         This reveals internal infrastructure (monitoring systems, \
                         security tooling) useful for attacker reconnaissance.",
                        uris.join(", ")
                    ),
                    url,
                )
                .with_evidence(format!("report-uri: {}", uris.join(" ")))
                .with_remediation(
                    "Use a third-party CSP reporting service or a generic endpoint \
                     that doesn't reveal internal hostnames or paths.",
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(200)
                .with_confidence(0.9),
            );
        }
    } else if has_report_to {
        findings.push(
            Finding::new(
                "csp-deep",
                Severity::Low,
                "CSP Report-To Endpoint Configured",
                "The CSP uses the report-to directive, which references a \
                 Reporting-API endpoint. While more modern than report-uri, \
                 it may still expose internal infrastructure in the \
                 Report-To HTTP header.",
                url,
            )
            .with_evidence("CSP contains report-to directive")
            .with_remediation(
                "Ensure the Report-To endpoint URL doesn't reveal internal \
                 hostnames or infrastructure details.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(200)
            .with_confidence(0.9),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for CSP bypass detection.

    /// Verify CSP directive parsing from realistic header strings.
    ///
    /// Directives are semicolon-separated, sources are space-separated.
    /// All keys and values should be lowercased.
    #[test]
    fn test_parse_csp_directives() {
        let csp = "default-src 'self'; script-src 'self' https://cdn.example.com; \
                    style-src 'self' 'unsafe-inline'; report-uri /csp-report";

        let directives = parse_csp_directives(csp);

        assert_eq!(directives.len(), 4);
        assert_eq!(directives.get("default-src"), Some(&vec!["'self'".to_string()]));
        assert_eq!(
            directives.get("script-src"),
            Some(&vec!["'self'".to_string(), "https://cdn.example.com".to_string()])
        );
        assert_eq!(directives.get("report-uri"), Some(&vec!["/csp-report".to_string()]));
    }

    /// Verify missing directive detection for base-uri, object-src, frame-ancestors.
    #[test]
    fn test_missing_directives() {
        let mut findings = Vec::new();

        // CSP with all critical directives present — no findings
        let complete = parse_csp_directives(
            "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'",
        );
        check_missing_directives(&complete, "https://example.com", &mut findings);
        assert!(findings.is_empty(), "Complete CSP should produce no findings");

        // CSP missing all three critical directives
        let minimal = parse_csp_directives("default-src 'self'");
        check_missing_directives(&minimal, "https://example.com", &mut findings);
        // base-uri + frame-ancestors (object-src covered by restrictive default-src)
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.title.contains("base-uri")));
        assert!(findings.iter().any(|f| f.title.contains("frame-ancestors")));
    }

    /// Verify permissive script-src detection for dangerous sources.
    #[test]
    fn test_permissive_script_src() {
        let mut findings = Vec::new();

        // Safe script-src
        let safe = parse_csp_directives("script-src 'self' https://cdn.example.com");
        check_permissive_script_src(&safe, "https://example.com", &mut findings);
        assert!(findings.is_empty());

        // Dangerous: data: in script-src
        let dangerous = parse_csp_directives("script-src 'self' data: blob:");
        check_permissive_script_src(&dangerous, "https://example.com", &mut findings);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.title.contains("data:")));
        assert!(findings.iter().any(|f| f.title.contains("blob:")));
    }

    /// Verify report-uri information leak detection.
    #[test]
    fn test_report_uri_detection() {
        let mut findings = Vec::new();

        // Has report-uri
        let with_report = parse_csp_directives(
            "default-src 'self'; report-uri https://monitor.internal.corp/csp",
        );
        check_report_uri_leak(
            &with_report,
            "default-src 'self'; report-uri https://monitor.internal.corp/csp",
            "https://example.com",
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Report URI"));

        // No report — no finding
        findings.clear();
        let no_report = parse_csp_directives("default-src 'self'");
        check_report_uri_leak(
            &no_report,
            "default-src 'self'",
            "https://example.com",
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    /// Verify edge cases: empty CSP, malformed directives.
    #[test]
    fn test_csp_edge_cases() {
        // Empty CSP
        let empty = parse_csp_directives("");
        assert!(empty.is_empty());

        // Single directive without sources
        let minimal = parse_csp_directives("upgrade-insecure-requests");
        assert_eq!(minimal.len(), 1);
        assert_eq!(minimal.get("upgrade-insecure-requests"), Some(&Vec::<String>::new()));

        // Multiple semicolons / whitespace
        let messy = parse_csp_directives("  default-src  'self' ;; script-src 'none' ;  ");
        assert!(messy.contains_key("default-src"));
        assert!(messy.contains_key("script-src"));
    }

    /// Verify permissive default-src wildcard detection.
    #[test]
    fn test_permissive_default_src() {
        let mut findings = Vec::new();

        // Restrictive — no finding
        let good = parse_csp_directives("default-src 'self'");
        check_permissive_default_src(&good, "https://example.com", &mut findings);
        assert!(findings.is_empty());

        // Wildcard — finding
        let bad = parse_csp_directives("default-src *");
        check_permissive_default_src(&bad, "https://example.com", &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("wildcard"));
    }

    /// Verify script-src falls back to default-src when not specified.
    #[test]
    fn test_script_src_falls_back_to_default() {
        let mut findings = Vec::new();

        // No script-src, but default-src has data:
        let fallback = parse_csp_directives("default-src 'self' data:");
        check_permissive_script_src(&fallback, "https://example.com", &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("data:"));
    }
}
