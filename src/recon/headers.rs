use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Checks HTTP security headers on the target.
#[derive(Debug)]
pub struct HeadersModule;

#[async_trait]
impl ScanModule for HeadersModule {
    fn name(&self) -> &'static str {
        "HTTP Security Headers"
    }

    fn id(&self) -> &'static str {
        "headers"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Analyze HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)"
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
        let mut findings = Vec::new();

        // Check each security header
        check_hsts(&headers, url, &mut findings);
        check_csp(&headers, url, &mut findings);
        check_x_frame_options(&headers, url, &mut findings);
        check_x_content_type_options(&headers, url, &mut findings);
        check_referrer_policy(&headers, url, &mut findings);
        check_permissions_policy(&headers, url, &mut findings);
        check_x_xss_protection(&headers, url, &mut findings);
        check_server_disclosure(&headers, url, &mut findings);
        check_x_powered_by(&headers, url, &mut findings);

        Ok(findings)
    }
}

fn check_hsts(headers: &reqwest::header::HeaderMap, url: &str, findings: &mut Vec<Finding>) {
    let header_value = headers.get("strict-transport-security");

    match header_value {
        None => {
            findings.push(
                Finding::new(
                    "headers",
                    Severity::High,
                    "Missing Strict-Transport-Security (HSTS) Header",
                    "The server does not set the Strict-Transport-Security header. \
                     This allows man-in-the-middle attacks by downgrading HTTPS to HTTP.",
                    url,
                )
                .with_remediation(
                    "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(319)
                .with_confidence(0.9),
            );
        }
        Some(value) => {
            let val = value.to_str().unwrap_or("");
            // Check for weak max-age
            if let Some(max_age) = extract_max_age(val) {
                if max_age < 31_536_000 {
                    findings.push(
                        Finding::new(
                            "headers",
                            Severity::Low,
                            "Weak HSTS max-age Value",
                            format!(
                                "HSTS max-age is {max_age} seconds (less than 1 year). \
                                 A longer duration provides better protection."
                            ),
                            url,
                        )
                        .with_evidence(format!("Strict-Transport-Security: {val}"))
                        .with_remediation("Set max-age to at least 31536000 (1 year)")
                        .with_owasp("A05:2021 Security Misconfiguration")
                        .with_confidence(0.9),
                    );
                }
            }

            if !val.to_lowercase().contains("includesubdomains") {
                findings.push(
                    Finding::new(
                        "headers",
                        Severity::Info,
                        "HSTS Missing includeSubDomains Directive",
                        "HSTS does not include the includeSubDomains directive. \
                         Subdomains are not protected by this policy.",
                        url,
                    )
                    .with_evidence(format!("Strict-Transport-Security: {val}"))
                    .with_owasp("A05:2021 Security Misconfiguration")
                    .with_confidence(0.9),
                );
            }
        }
    }
}

fn check_csp(headers: &reqwest::header::HeaderMap, url: &str, findings: &mut Vec<Finding>) {
    let header_value = headers.get("content-security-policy");

    match header_value {
        None => {
            findings.push(
                Finding::new(
                    "headers",
                    Severity::Medium,
                    "Missing Content-Security-Policy (CSP) Header",
                    "No Content-Security-Policy header is set. CSP helps prevent XSS, \
                     clickjacking, and other code injection attacks.",
                    url,
                )
                .with_remediation(
                    "Implement a Content-Security-Policy header. Start with: \
                     Content-Security-Policy: default-src 'self'",
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(693)
                .with_confidence(0.9),
            );
        }
        Some(value) => {
            let val = value.to_str().unwrap_or("");

            if val.contains("unsafe-inline") {
                findings.push(
                    Finding::new(
                        "headers",
                        Severity::Medium,
                        "CSP Contains 'unsafe-inline'",
                        "The CSP policy allows 'unsafe-inline', which significantly \
                         weakens XSS protection.",
                        url,
                    )
                    .with_evidence(format!("Content-Security-Policy: {val}"))
                    .with_remediation(
                        "Remove 'unsafe-inline' and use nonces or hashes for inline scripts",
                    )
                    .with_owasp("A05:2021 Security Misconfiguration")
                    .with_cwe(693)
                    .with_confidence(0.9),
                );
            }

            if val.contains("unsafe-eval") {
                findings.push(
                    Finding::new(
                        "headers",
                        Severity::Medium,
                        "CSP Contains 'unsafe-eval'",
                        "The CSP policy allows 'unsafe-eval', enabling dynamic code execution.",
                        url,
                    )
                    .with_evidence(format!("Content-Security-Policy: {val}"))
                    .with_remediation("Remove 'unsafe-eval' from the CSP policy")
                    .with_owasp("A05:2021 Security Misconfiguration")
                    .with_cwe(693)
                    .with_confidence(0.9),
                );
            }

            if val.contains('*') && !val.contains("*.") {
                findings.push(
                    Finding::new(
                        "headers",
                        Severity::Medium,
                        "CSP Contains Wildcard Source",
                        "The CSP policy contains a wildcard (*) source, which allows \
                         loading resources from any origin.",
                        url,
                    )
                    .with_evidence(format!("Content-Security-Policy: {val}"))
                    .with_remediation("Replace wildcard sources with specific trusted domains")
                    .with_owasp("A05:2021 Security Misconfiguration")
                    .with_confidence(0.9),
                );
            }
        }
    }
}

fn check_x_frame_options(
    headers: &reqwest::header::HeaderMap,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    if headers.get("x-frame-options").is_none() && !has_csp_frame_ancestors(headers) {
        findings.push(
            Finding::new(
                "headers",
                Severity::Medium,
                "Missing X-Frame-Options Header",
                "Neither X-Frame-Options nor CSP frame-ancestors is set. \
                 The page may be vulnerable to clickjacking attacks.",
                url,
            )
            .with_remediation("Add header: X-Frame-Options: DENY (or SAMEORIGIN)")
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(1021)
            .with_confidence(0.9),
        );
    }
}

fn check_x_content_type_options(
    headers: &reqwest::header::HeaderMap,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    if headers.get("x-content-type-options").is_none() {
        findings.push(
            Finding::new(
                "headers",
                Severity::Low,
                "Missing X-Content-Type-Options Header",
                "The X-Content-Type-Options header is not set. Browsers may \
                 MIME-sniff the response, potentially leading to XSS.",
                url,
            )
            .with_remediation("Add header: X-Content-Type-Options: nosniff")
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(693)
            .with_confidence(0.9),
        );
    }
}

fn check_referrer_policy(
    headers: &reqwest::header::HeaderMap,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    match headers.get("referrer-policy") {
        None => {
            findings.push(
                Finding::new(
                    "headers",
                    Severity::Low,
                    "Missing Referrer-Policy Header",
                    "No Referrer-Policy header is set. Full URLs including query \
                     parameters may be leaked to third-party sites.",
                    url,
                )
                .with_remediation("Add header: Referrer-Policy: strict-origin-when-cross-origin")
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_confidence(0.9),
            );
        }
        Some(value) => {
            let val = value.to_str().unwrap_or("").to_lowercase();
            if val == "unsafe-url" || val == "no-referrer-when-downgrade" {
                findings.push(
                    Finding::new(
                        "headers",
                        Severity::Low,
                        "Weak Referrer-Policy Value",
                        format!(
                            "Referrer-Policy is set to '{val}', which may leak \
                             sensitive URL information to third-party sites."
                        ),
                        url,
                    )
                    .with_evidence(format!("Referrer-Policy: {val}"))
                    .with_remediation(
                        "Use a stricter policy: strict-origin-when-cross-origin or no-referrer",
                    )
                    .with_owasp("A05:2021 Security Misconfiguration")
                    .with_confidence(0.9),
                );
            }
        }
    }
}

fn check_permissions_policy(
    headers: &reqwest::header::HeaderMap,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    if headers.get("permissions-policy").is_none() && headers.get("feature-policy").is_none() {
        findings.push(
            Finding::new(
                "headers",
                Severity::Info,
                "Missing Permissions-Policy Header",
                "No Permissions-Policy header is set. Browser features like \
                 camera, microphone, and geolocation are not explicitly restricted.",
                url,
            )
            .with_remediation(
                "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_confidence(0.9),
        );
    }
}

fn check_x_xss_protection(
    headers: &reqwest::header::HeaderMap,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    if let Some(value) = headers.get("x-xss-protection") {
        let val = value.to_str().unwrap_or("");
        // X-XSS-Protection is deprecated and can introduce vulnerabilities in older browsers
        if val != "0" {
            findings.push(
                Finding::new(
                    "headers",
                    Severity::Info,
                    "Deprecated X-XSS-Protection Header Active",
                    "X-XSS-Protection is set to a value other than '0'. This header \
                     is deprecated and can introduce vulnerabilities in older browsers. \
                     Use CSP instead.",
                    url,
                )
                .with_evidence(format!("X-XSS-Protection: {val}"))
                .with_remediation(
                    "Set X-XSS-Protection: 0 and rely on Content-Security-Policy instead",
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_confidence(0.9),
            );
        }
    }
}

fn check_server_disclosure(
    headers: &reqwest::header::HeaderMap,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    if let Some(value) = headers.get("server") {
        let val = value.to_str().unwrap_or("");
        // Check if version info is disclosed
        if val.contains('/') || val.chars().any(|c| c.is_ascii_digit()) {
            findings.push(
                Finding::new(
                    "headers",
                    Severity::Low,
                    "Server Version Disclosure",
                    format!(
                        "The Server header discloses version information: '{val}'. \
                         This helps attackers identify known vulnerabilities."
                    ),
                    url,
                )
                .with_evidence(format!("Server: {val}"))
                .with_remediation("Remove or minimize the Server header value")
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(200)
                .with_confidence(0.9),
            );
        }
    }
}

fn check_x_powered_by(
    headers: &reqwest::header::HeaderMap,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    if let Some(value) = headers.get("x-powered-by") {
        let val = value.to_str().unwrap_or("");
        findings.push(
            Finding::new(
                "headers",
                Severity::Low,
                "X-Powered-By Header Disclosure",
                format!(
                    "The X-Powered-By header reveals technology information: '{val}'. \
                     This assists attackers in targeting known framework vulnerabilities."
                ),
                url,
            )
            .with_evidence(format!("X-Powered-By: {val}"))
            .with_remediation("Remove the X-Powered-By header")
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(200)
            .with_confidence(0.9),
        );
    }
}

// Helper functions

fn extract_max_age(hsts_value: &str) -> Option<u64> {
    hsts_value.to_lowercase().split(';').find_map(|part| {
        let part = part.trim();
        if part.starts_with("max-age") {
            part.split('=').nth(1).and_then(|v| v.trim().parse::<u64>().ok())
        } else {
            None
        }
    })
}

fn has_csp_frame_ancestors(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|csp| csp.contains("frame-ancestors"))
}

#[cfg(test)]
mod tests {
    /// Unit tests for HTTP security header analysis helpers.
    use super::*;
    use reqwest::header::HeaderMap;

    /// Verify `extract_max_age` parses a valid max-age value from an HSTS header.
    #[test]
    fn test_extract_max_age_valid() {
        // Arrange
        let hsts = "max-age=31536000";

        // Act
        let result = extract_max_age(hsts);

        // Assert
        assert_eq!(result, Some(31_536_000));
    }

    /// Verify `extract_max_age` handles extra directives alongside max-age.
    #[test]
    fn test_extract_max_age_with_extra_directives() {
        // Arrange
        let hsts = "max-age=63072000; includeSubDomains; preload";

        // Act
        let result = extract_max_age(hsts);

        // Assert
        assert_eq!(result, Some(63_072_000));
    }

    /// Verify `extract_max_age` returns `None` for an invalid (non-numeric) max-age.
    #[test]
    fn test_extract_max_age_invalid() {
        // Arrange
        let hsts = "max-age=abc";

        // Act
        let result = extract_max_age(hsts);

        // Assert
        assert_eq!(result, None);
    }

    /// Verify `extract_max_age` returns `None` when max-age is absent from the value.
    #[test]
    fn test_extract_max_age_missing() {
        // Arrange
        let hsts = "includeSubDomains; preload";

        // Act
        let result = extract_max_age(hsts);

        // Assert
        assert_eq!(result, None);
    }

    /// Verify `has_csp_frame_ancestors` returns true when CSP contains frame-ancestors.
    #[test]
    fn test_has_csp_frame_ancestors_present() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // Arrange
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-security-policy",
            "default-src 'self'; frame-ancestors 'none'".parse()?,
        );

        // Act
        let result = has_csp_frame_ancestors(&headers);

        // Assert
        assert!(result);
        Ok(())
    }

    /// Verify `has_csp_frame_ancestors` returns false when CSP lacks frame-ancestors.
    #[test]
    fn test_has_csp_frame_ancestors_absent() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // Arrange
        let mut headers = HeaderMap::new();
        headers.insert("content-security-policy", "default-src 'self'; script-src 'self'".parse()?);

        // Act
        let result = has_csp_frame_ancestors(&headers);

        // Assert
        assert!(!result);
        Ok(())
    }

    /// Verify `has_csp_frame_ancestors` returns false when no CSP header is present.
    #[test]
    fn test_has_csp_frame_ancestors_no_header() {
        // Arrange
        let headers = HeaderMap::new();

        // Act
        let result = has_csp_frame_ancestors(&headers);

        // Assert
        assert!(!result);
    }
}
