//! Subdomain takeover detection module.
//!
//! Probes common subdomains of the target domain and checks HTTP responses
//! against known cloud provider "unclaimed resource" fingerprints. A match
//! indicates the subdomain's DNS points to a service that can be claimed
//! by an attacker.

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Subdomain takeover detection via HTTP fingerprinting.
///
/// Generates common subdomain URLs from the target domain, fetches each,
/// and checks response bodies against known cloud provider error pages
/// that indicate an unclaimed resource available for takeover.
#[derive(Debug)]
pub struct SubdomainTakeoverModule;

#[async_trait]
impl ScanModule for SubdomainTakeoverModule {
    fn name(&self) -> &'static str {
        "Subdomain Takeover"
    }

    fn id(&self) -> &'static str {
        "subtakeover"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect subdomain takeover via cloud provider fingerprint matching"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let domain = ctx.target.domain.as_deref().unwrap_or("");
        if domain.is_empty() {
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        let fingerprints = takeover_fingerprints();
        let subdomains = generate_subdomains(domain);

        for subdomain in &subdomains {
            // Try HTTPS first, then HTTP
            for scheme in &["https", "http"] {
                let url = format!("{scheme}://{subdomain}");

                let Ok(response) = ctx.http_client.get(&url).send().await else {
                    continue;
                };

                let Ok(body) = response.text().await else {
                    continue;
                };

                if let Some(fp) = check_fingerprint(&body, &fingerprints) {
                    findings.push(
                        Finding::new(
                            "subtakeover",
                            fp.severity,
                            format!("Subdomain Takeover: {} ({})", subdomain, fp.provider),
                            format!(
                                "The subdomain '{subdomain}' appears to point to an unclaimed \
                                 {provider} resource. An attacker can claim this resource and \
                                 serve arbitrary content on your domain, enabling phishing, \
                                 cookie theft, and reputation damage.",
                                provider = fp.provider
                            ),
                            &url,
                        )
                        .with_evidence(format!(
                            "Provider: {} | Fingerprint matched in response body",
                            fp.provider
                        ))
                        .with_remediation(
                            "Remove the dangling DNS record pointing to the unclaimed resource, \
                             or reclaim the resource on the cloud provider. Audit all CNAME \
                             records regularly to prevent future takeovers.",
                        )
                        .with_owasp("A05:2021 Security Misconfiguration")
                        .with_cwe(200)
                        .with_confidence(0.8),
                    );
                    break; // Found takeover on this subdomain, no need to try other scheme
                }
            }
        }

        Ok(findings)
    }
}

/// A cloud provider takeover fingerprint.
#[derive(Debug)]
struct TakeoverFingerprint {
    /// Cloud provider name.
    provider: &'static str,
    /// Strings to look for in the HTTP response body (any match = positive).
    body_patterns: &'static [&'static str],
    /// Finding severity.
    severity: Severity,
}

/// Generate common subdomain prefixes for a domain.
#[must_use]
fn generate_subdomains(domain: &str) -> Vec<String> {
    let prefixes = [
        "www", "mail", "admin", "staging", "dev", "api", "cdn", "assets", "blog", "docs", "app",
        "test", "beta", "old", "new",
    ];
    prefixes.iter().map(|p| format!("{p}.{domain}")).collect()
}

/// Return the database of known takeover fingerprints.
#[must_use]
fn takeover_fingerprints() -> Vec<TakeoverFingerprint> {
    vec![
        TakeoverFingerprint {
            provider: "GitHub Pages",
            body_patterns: &["There isn't a GitHub Pages site here"],
            severity: Severity::High,
        },
        TakeoverFingerprint {
            provider: "Heroku",
            body_patterns: &["No such app", "herokucdn.com/error-pages"],
            severity: Severity::High,
        },
        TakeoverFingerprint {
            provider: "AWS S3",
            body_patterns: &["NoSuchBucket", "The specified bucket does not exist"],
            severity: Severity::Critical,
        },
        TakeoverFingerprint {
            provider: "Azure",
            body_patterns: &["404 Web Site not found"],
            severity: Severity::High,
        },
        TakeoverFingerprint {
            provider: "Shopify",
            body_patterns: &["Sorry, this shop is currently unavailable"],
            severity: Severity::Medium,
        },
        TakeoverFingerprint {
            provider: "Fastly",
            body_patterns: &["Fastly error: unknown domain"],
            severity: Severity::High,
        },
        TakeoverFingerprint {
            provider: "Pantheon",
            body_patterns: &["404 error unknown site"],
            severity: Severity::Medium,
        },
        TakeoverFingerprint {
            provider: "Tumblr",
            body_patterns: &["There's nothing here"],
            severity: Severity::Medium,
        },
    ]
}

/// Check a response body against all takeover fingerprints.
///
/// Returns the first matching fingerprint, or `None` if no match.
fn check_fingerprint<'a>(
    body: &str,
    fingerprints: &'a [TakeoverFingerprint],
) -> Option<&'a TakeoverFingerprint> {
    fingerprints.iter().find(|fp| fp.body_patterns.iter().any(|pattern| body.contains(pattern)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for subdomain takeover detection.

    /// Verify fingerprint matching against known provider error pages.
    #[test]
    fn test_check_fingerprint() {
        let fps = takeover_fingerprints();

        // GitHub Pages
        let github =
            "<!DOCTYPE html><html><body><p>There isn't a GitHub Pages site here.</p></body></html>";
        let result = check_fingerprint(github, &fps);
        assert!(result.is_some());
        assert_eq!(result.map(|f| f.provider), Some("GitHub Pages"));

        // AWS S3
        let s3 = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>";
        let result = check_fingerprint(s3, &fps);
        assert!(result.is_some());
        assert_eq!(result.map(|f| f.provider), Some("AWS S3"));

        // Heroku
        let heroku = "<html><body>No such app</body></html>";
        let result = check_fingerprint(heroku, &fps);
        assert!(result.is_some());
        assert_eq!(result.map(|f| f.provider), Some("Heroku"));
    }

    /// Verify no false positives on normal web pages.
    #[test]
    fn test_no_false_positive() {
        let fps = takeover_fingerprints();

        let normal_200 = "<html><body><h1>Welcome to our site</h1></body></html>";
        assert!(check_fingerprint(normal_200, &fps).is_none());

        let normal_404 = "<html><body><h1>404 Not Found</h1><p>The page you requested was not found.</p></body></html>";
        assert!(check_fingerprint(normal_404, &fps).is_none());

        let empty = "";
        assert!(check_fingerprint(empty, &fps).is_none());
    }

    /// Verify subdomain generation produces expected prefixes.
    #[test]
    fn test_generate_subdomains() {
        let subs = generate_subdomains("example.com");

        assert!(subs.len() >= 15);
        assert!(subs.contains(&"www.example.com".to_string()));
        assert!(subs.contains(&"admin.example.com".to_string()));
        assert!(subs.contains(&"staging.example.com".to_string()));
        assert!(subs.contains(&"api.example.com".to_string()));
        assert!(subs.contains(&"cdn.example.com".to_string()));

        // All should end with the domain
        for sub in &subs {
            assert!(sub.ends_with(".example.com"), "'{sub}' doesn't end with domain");
        }
    }

    /// Verify fingerprint database has entries for all expected providers.
    #[test]
    fn test_fingerprint_database() {
        let fps = takeover_fingerprints();

        assert!(fps.len() >= 8, "Expected at least 8 providers, got {}", fps.len());

        // All providers should have non-empty patterns
        for fp in &fps {
            assert!(
                !fp.body_patterns.is_empty(),
                "Provider '{}' has no fingerprint patterns",
                fp.provider
            );
        }

        // Check specific providers exist
        let providers: Vec<&str> = fps.iter().map(|f| f.provider).collect();
        assert!(providers.contains(&"GitHub Pages"));
        assert!(providers.contains(&"AWS S3"));
        assert!(providers.contains(&"Heroku"));
        assert!(providers.contains(&"Azure"));
    }
}
