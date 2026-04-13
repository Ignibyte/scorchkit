//! Access control testing module.
//!
//! Probes for common authorization bypass patterns: admin path discovery,
//! HTTP method override bypass, verb tampering, path traversal bypass
//! variants, and forced browsing to predictable resource IDs. All tests
//! are non-destructive — they probe for access without modifying data.

use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Access control and authorization bypass testing.
///
/// Tests for missing or bypassable access controls via admin path probing,
/// HTTP method override headers, verb tampering, path normalization bypasses,
/// and forced browsing to sequential resource IDs.
#[derive(Debug)]
pub struct AclModule;

#[async_trait]
impl ScanModule for AclModule {
    fn name(&self) -> &'static str {
        "Access Control Testing"
    }

    fn id(&self) -> &'static str {
        "acl"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Test for admin path exposure, method override bypass, and forced browsing"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let base = ctx.target.base_url();
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Test 1: Admin path discovery
        test_admin_paths(ctx, &base, &mut findings).await;

        // Test 2: Method override bypass
        test_method_override(ctx, url, &mut findings).await?;

        // Test 3: Path traversal bypass variants
        test_path_bypass(ctx, &base, &mut findings).await;

        // Test 4: Forced browsing to sequential IDs
        test_forced_browsing(ctx, &base, &mut findings).await;

        Ok(findings)
    }
}

/// Probe common admin/management paths for unauthorized access.
async fn test_admin_paths(ctx: &ScanContext, base: &str, findings: &mut Vec<Finding>) {
    let admin_paths = generate_admin_paths();

    for path in &admin_paths {
        let url = format!("{base}{path}");

        let Ok(response) = ctx.http_client.get(&url).send().await else {
            continue;
        };

        let status = response.status().as_u16();

        // 200 or 302 (redirect to login) on admin paths = path exists
        if status == 200 {
            findings.push(
                Finding::new(
                    "acl",
                    Severity::Medium,
                    format!("Admin Path Accessible: {path}"),
                    format!(
                        "The administrative path '{path}' returned HTTP 200, indicating \
                         it is accessible without authentication. This may expose admin \
                         functionality, configuration panels, or sensitive data."
                    ),
                    &url,
                )
                .with_evidence(format!("GET {path} → HTTP {status}"))
                .with_remediation(
                    "Restrict administrative paths behind authentication and \
                     authorization. Return 403 or 404 for unauthorized requests \
                     rather than exposing the interface.",
                )
                .with_owasp("A01:2021 Broken Access Control")
                .with_cwe(425)
                .with_confidence(0.6),
            );
        }
    }
}

/// Test for HTTP method override bypass.
///
/// Sends a GET request with `X-HTTP-Method-Override: DELETE` to detect
/// servers that honor method override headers without authorization checks.
async fn test_method_override(
    ctx: &ScanContext,
    url: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let override_headers = method_override_headers();

    for header_name in &override_headers {
        let response = ctx
            .http_client
            .get(url)
            .header(*header_name, "DELETE")
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let status = response.status().as_u16();

        // If server responds differently to method override (405 Method Not Allowed
        // suggests it processed the override), it may be vulnerable
        if status == 405 || status == 200 {
            let body = response.text().await.unwrap_or_default();
            let lower = body.to_lowercase();

            // Check for signs the override was processed
            if status == 405
                || lower.contains("delete")
                || lower.contains("method not allowed")
                || lower.contains("deleted")
            {
                findings.push(
                    Finding::new(
                        "acl",
                        Severity::High,
                        format!("HTTP Method Override Accepted: {header_name}"),
                        format!(
                            "The server processes the '{header_name}: DELETE' header, \
                             potentially allowing attackers to bypass method-based \
                             access controls by sending GET requests with override headers."
                        ),
                        url,
                    )
                    .with_evidence(format!("GET with {header_name}: DELETE → HTTP {status}"))
                    .with_remediation(
                        "Disable HTTP method override headers in production. If method \
                         override is required, ensure the overridden method is subject \
                         to the same authorization checks as the actual HTTP method.",
                    )
                    .with_owasp("A01:2021 Broken Access Control")
                    .with_cwe(650)
                    .with_confidence(0.6),
                );
                return Ok(()); // Found one, no need to test all headers
            }
        }
    }

    Ok(())
}

/// Test path traversal bypass variants for admin paths.
///
/// Some path-based authorization checks can be bypassed with URL
/// normalization tricks like `//admin`, `/./admin`, `/%2e/admin`.
async fn test_path_bypass(ctx: &ScanContext, base: &str, findings: &mut Vec<Finding>) {
    let bypasses = generate_acl_bypass_paths();

    for (bypass_path, technique) in &bypasses {
        let url = format!("{base}{bypass_path}");

        let Ok(response) = ctx.http_client.get(&url).send().await else {
            continue;
        };

        let status = response.status().as_u16();

        if status == 200 {
            findings.push(
                Finding::new(
                    "acl",
                    Severity::High,
                    format!("Path-Based Auth Bypass: {technique}"),
                    format!(
                        "The path '{bypass_path}' returned HTTP 200, suggesting the \
                         server's path-based authorization can be bypassed using {technique}. \
                         An attacker can access restricted resources without proper authorization."
                    ),
                    &url,
                )
                .with_evidence(format!("GET {bypass_path} → HTTP 200"))
                .with_remediation(
                    "Normalize URLs before applying authorization checks. Use \
                     framework-level authorization middleware rather than path-based \
                     string matching. Test authorization at the controller/handler level.",
                )
                .with_owasp("A01:2021 Broken Access Control")
                .with_cwe(22)
                .with_confidence(0.6),
            );
        }
    }
}

/// Test forced browsing to predictable sequential resource IDs.
async fn test_forced_browsing(ctx: &ScanContext, base: &str, findings: &mut Vec<Finding>) {
    let api_paths = ["/api/users/", "/api/user/", "/api/accounts/", "/api/profile/"];

    for api_path in &api_paths {
        // Try accessing IDs 1 and 2
        for id in &["1", "2"] {
            let url = format!("{base}{api_path}{id}");

            let Ok(response) = ctx.http_client.get(&url).send().await else {
                continue;
            };

            let status = response.status().as_u16();

            if status == 200 {
                let body = response.text().await.unwrap_or_default();

                // Check if it looks like a real data response (JSON with user-like fields)
                let lower = body.to_lowercase();
                if lower.contains("\"email\"")
                    || lower.contains("\"username\"")
                    || lower.contains("\"name\"")
                    || lower.contains("\"id\"")
                {
                    findings.push(
                        Finding::new(
                            "acl",
                            Severity::Medium,
                            format!("Forced Browsing: {api_path}{id}"),
                            format!(
                                "The API endpoint '{api_path}{id}' returned user data \
                                 without requiring authentication. Sequential ID enumeration \
                                 may expose other users' data (IDOR)."
                            ),
                            &url,
                        )
                        .with_evidence(format!("GET {api_path}{id} → HTTP 200 with user data"))
                        .with_remediation(
                            "Require authentication for all API endpoints returning user data. \
                             Use UUIDs instead of sequential IDs. Implement object-level \
                             authorization checks (verify the requesting user owns the resource).",
                        )
                        .with_owasp("A01:2021 Broken Access Control")
                        .with_cwe(425)
                        .with_confidence(0.6),
                    );
                    return; // Found one IDOR indicator, no need to keep probing
                }
            }
        }
    }
}

/// Generate common admin/management paths to probe.
#[must_use]
fn generate_admin_paths() -> Vec<&'static str> {
    vec![
        "/admin",
        "/admin/",
        "/administrator",
        "/dashboard",
        "/management",
        "/manager",
        "/config",
        "/configuration",
        "/internal",
        "/debug",
        "/console",
        "/panel",
        "/cp",
        "/controlpanel",
        "/phpmyadmin",
        "/adminer",
        "/wp-admin",
        "/_admin",
        "/backstage",
        "/portal",
    ]
}

/// Generate path traversal bypass variants for admin paths.
///
/// Returns tuples of `(bypass_path, technique_description)`.
#[must_use]
fn generate_acl_bypass_paths() -> Vec<(&'static str, &'static str)> {
    vec![
        ("//admin", "double slash"),
        ("/./admin", "dot segment"),
        ("/%2e/admin", "URL-encoded dot"),
        ("/admin;", "semicolon suffix"),
        ("/admin..;/", "dot-dot-semicolon"),
        ("/ADMIN", "case variation"),
        ("/admin%20", "trailing space"),
        ("/admin/.", "trailing dot segment"),
    ]
}

/// HTTP method override header names to test.
#[must_use]
fn method_override_headers() -> Vec<&'static str> {
    vec!["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override", "_method"]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for access control testing.

    /// Verify admin path list covers common frameworks and patterns.
    #[test]
    fn test_generate_admin_paths() {
        let paths = generate_admin_paths();

        assert!(paths.len() >= 15, "Expected at least 15 admin paths, got {}", paths.len());
        assert!(paths.contains(&"/admin"));
        assert!(paths.contains(&"/dashboard"));
        assert!(paths.contains(&"/wp-admin"));
        assert!(paths.contains(&"/phpmyadmin"));

        for path in &paths {
            assert!(path.starts_with('/'), "Path '{path}' doesn't start with /");
        }
    }

    /// Verify path traversal bypass variants produce expected techniques.
    #[test]
    fn test_generate_bypass_paths() {
        let bypasses = generate_acl_bypass_paths();

        assert!(bypasses.len() >= 6, "Expected at least 6 bypass variants");

        // Check specific techniques
        assert!(bypasses.iter().any(|(p, _)| *p == "//admin"), "Missing double slash bypass");
        assert!(bypasses.iter().any(|(p, _)| *p == "/%2e/admin"), "Missing URL-encoded dot bypass");
        assert!(bypasses.iter().any(|(p, _)| *p == "/ADMIN"), "Missing case variation bypass");

        // All bypass paths should contain "admin" (case-insensitive)
        for (path, _desc) in &bypasses {
            assert!(
                path.to_lowercase().contains("admin"),
                "Bypass path '{path}' doesn't target admin"
            );
        }
    }

    /// Verify method override header list is complete.
    #[test]
    fn test_method_override_headers() {
        let headers = method_override_headers();

        assert!(headers.len() >= 3);
        assert!(headers.contains(&"X-HTTP-Method-Override"));
        assert!(headers.contains(&"X-HTTP-Method"));
        assert!(headers.contains(&"X-Method-Override"));
    }
}
