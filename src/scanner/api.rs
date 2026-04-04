//! REST API security testing module (OWASP API Top 10).
//!
//! Tests API-specific vulnerabilities: mass assignment, excessive data
//! exposure, shadow API discovery, API rate limiting, and content
//! negotiation confusion. Complements [`super::acl`] (BOLA/forced browsing)
//! and [`super::injection`] (generic SQL/command injection).

use async_trait::async_trait;
use serde_json::json;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// REST API security testing based on OWASP API Top 10.
///
/// Tests for mass assignment, excessive data exposure, shadow APIs,
/// missing rate limiting, and content negotiation issues. Complements
/// existing ACL (BOLA) and injection modules.
#[derive(Debug)]
pub struct ApiSecurityModule;

#[async_trait]
impl ScanModule for ApiSecurityModule {
    fn name(&self) -> &'static str {
        "API Security (OWASP Top 10)"
    }

    fn id(&self) -> &'static str {
        "api-security"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Test REST APIs for mass assignment, data exposure, shadow APIs, and rate limiting"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let base = ctx.target.base_url();
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Test 1: Excessive data exposure — check API responses for sensitive fields
        test_data_exposure(ctx, url, &mut findings).await;

        // Test 2: Shadow API discovery — probe versioned API paths
        test_shadow_apis(ctx, &base, &mut findings).await;

        // Test 3: Mass assignment — POST with extra privileged fields
        test_mass_assignment(ctx, &base, &mut findings).await;

        // Test 4: API rate limiting — rapid requests to auth endpoints
        test_rate_limiting(ctx, &base, &mut findings).await?;

        // Test 5: Content negotiation — request XML from JSON API
        test_content_negotiation(ctx, url, &mut findings).await;

        Ok(findings)
    }
}

/// Check API responses for excessive data exposure (sensitive field names).
async fn test_data_exposure(ctx: &ScanContext, _url: &str, findings: &mut Vec<Finding>) {
    let api_paths = ["/api/me", "/api/user", "/api/profile", "/api/account"];

    for path in &api_paths {
        let test_url = format!("{}{path}", ctx.target.base_url());

        let Ok(response) = ctx.http_client.get(&test_url).send().await else {
            continue;
        };

        if !response.status().is_success() {
            continue;
        }

        let Ok(body) = response.text().await else {
            continue;
        };

        let leaked = has_sensitive_fields(&body);
        if !leaked.is_empty() {
            findings.push(
                Finding::new(
                    "api-security",
                    Severity::Medium,
                    format!("Excessive Data Exposure: {path}"),
                    format!(
                        "The API endpoint '{path}' returns sensitive fields in the response: {}. \
                         APIs should only return fields the client explicitly needs.",
                        leaked.join(", ")
                    ),
                    &test_url,
                )
                .with_evidence(format!("Sensitive fields found: {}", leaked.join(", ")))
                .with_remediation(
                    "Implement response filtering — only return fields the client needs. \
                     Never expose internal fields like password hashes, tokens, or PII \
                     in API responses. Use DTOs/serializers to control output shape.",
                )
                .with_owasp("API3: Excessive Data Exposure")
                .with_cwe(213)
                .with_confidence(0.7),
            );
            return; // Found one, enough evidence
        }
    }
}

/// Probe for shadow/undocumented API versions.
async fn test_shadow_apis(ctx: &ScanContext, base: &str, findings: &mut Vec<Finding>) {
    let shadow_paths = generate_shadow_api_paths();
    let mut discovered = Vec::new();

    for path in &shadow_paths {
        let url = format!("{base}{path}");

        let Ok(response) = ctx.http_client.get(&url).send().await else {
            continue;
        };

        let status = response.status().as_u16();
        if status == 200 || status == 301 || status == 302 {
            discovered.push((*path, status));
        }
    }

    if discovered.len() >= 2 {
        let paths_str = discovered
            .iter()
            .map(|(p, s)| format!("{p} (HTTP {s})"))
            .collect::<Vec<_>>()
            .join(", ");

        findings.push(
            Finding::new(
                "api-security",
                Severity::Low,
                "Shadow API Versions Discovered",
                format!(
                    "Multiple API version paths are accessible: {paths_str}. \
                     Older API versions may lack security patches or have deprecated \
                     authentication mechanisms."
                ),
                base,
            )
            .with_evidence(format!("{} API paths responding", discovered.len()))
            .with_remediation(
                "Decommission old API versions. If multiple versions must coexist, \
                 ensure all versions have equivalent security controls. Monitor and \
                 restrict access to internal/deprecated API paths.",
            )
            .with_owasp("API9: Improper Assets Management")
            .with_cwe(912)
            .with_confidence(0.7),
        );
    }
}

/// Test for mass assignment by sending POST with extra privileged fields.
async fn test_mass_assignment(ctx: &ScanContext, base: &str, findings: &mut Vec<Finding>) {
    let register_paths = ["/api/register", "/api/signup", "/api/users", "/api/account"];
    let extra_fields = mass_assignment_fields();

    for path in &register_paths {
        let url = format!("{base}{path}");

        // Build payload with extra privileged fields
        let mut payload = json!({
            "username": "scorchkit_test",
            "email": "test@scorchkit.local",
            "password": "Test123!@#"
        });

        for field in &extra_fields {
            payload[field.0] = json!(field.1);
        }

        let Ok(response) = ctx
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
        else {
            continue;
        };

        let status = response.status().as_u16();

        // 200/201 with extra fields accepted suggests mass assignment
        if status == 200 || status == 201 {
            let body = response.text().await.unwrap_or_default();
            let accepted_fields: Vec<&str> = extra_fields
                .iter()
                .filter(|(field, _)| body.to_lowercase().contains(&field.to_lowercase()))
                .map(|(field, _)| *field)
                .collect();

            if !accepted_fields.is_empty() {
                findings.push(
                    Finding::new(
                        "api-security",
                        Severity::Medium,
                        format!("Potential Mass Assignment: {path}"),
                        format!(
                            "The API endpoint '{path}' accepted a request containing \
                             privileged fields ({}) in the response body. The server may \
                             be blindly binding request parameters to internal objects.",
                            accepted_fields.join(", ")
                        ),
                        &url,
                    )
                    .with_evidence(format!("POST with extra fields → HTTP {status}"))
                    .with_remediation(
                        "Use explicit allowlists for request binding — only accept fields \
                         the endpoint expects. Never bind request parameters directly to \
                         database models. Use separate DTOs for input validation.",
                    )
                    .with_owasp("API6: Mass Assignment")
                    .with_cwe(915)
                    .with_confidence(0.7),
                );
                return;
            }
        }
    }
}

/// Test for missing rate limiting on authentication endpoints.
async fn test_rate_limiting(
    ctx: &ScanContext,
    base: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let auth_paths = ["/api/login", "/api/auth", "/api/token", "/api/signin"];

    for path in &auth_paths {
        let url = format!("{base}{path}");
        let mut got_429 = false;

        // Send 10 rapid requests
        for _ in 0..10 {
            let response = ctx
                .http_client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(r#"{"username":"test","password":"test"}"#)
                .send()
                .await
                .map_err(|e| ScorchError::Http { url: url.clone(), source: e })?;

            if response.status().as_u16() == 429 {
                got_429 = true;
                break;
            }
        }

        // If we got a non-error response on all 10 but no 429 → no rate limit
        if !got_429 {
            // Verify the endpoint actually exists (not 404)
            let Ok(check) = ctx.http_client.post(&url).send().await else {
                continue;
            };
            let check_status = check.status().as_u16();
            if check_status != 404 && check_status != 405 {
                findings.push(
                    Finding::new(
                        "api-security",
                        Severity::Medium,
                        format!("No Rate Limiting on Auth Endpoint: {path}"),
                        format!(
                            "The authentication endpoint '{path}' accepted 10 rapid \
                             requests without returning HTTP 429 (Too Many Requests). \
                             This enables credential brute-force attacks."
                        ),
                        &url,
                    )
                    .with_evidence(format!("10 rapid POST requests to {path} — no 429 response"))
                    .with_remediation(
                        "Implement rate limiting on authentication endpoints. \
                         Return HTTP 429 after 5-10 failed attempts per IP/account. \
                         Consider progressive delays or account lockout.",
                    )
                    .with_owasp("API4: Lack of Resources & Rate Limiting")
                    .with_cwe(770)
                    .with_confidence(0.7),
                );
                return Ok(());
            }
        }
    }

    Ok(())
}

/// Test for content negotiation confusion.
async fn test_content_negotiation(ctx: &ScanContext, url: &str, findings: &mut Vec<Finding>) {
    let Ok(response) = ctx.http_client.get(url).header("Accept", "application/xml").send().await
    else {
        return;
    };

    if let Some(ct) = response.headers().get("content-type").and_then(|v| v.to_str().ok()) {
        if ct.contains("xml") && !ct.contains("html") {
            findings.push(
                Finding::new(
                    "api-security",
                    Severity::Low,
                    "Content Negotiation Returns XML",
                    "The API returns XML when requested via Accept: application/xml. \
                     If the server parses XML input, this may enable XXE attacks. \
                     APIs should enforce a single content type.",
                    url,
                )
                .with_evidence(format!("Accept: application/xml → Content-Type: {ct}"))
                .with_remediation(
                    "Enforce a single content type (typically application/json). \
                     Reject or ignore Accept headers requesting XML unless XML \
                     support is intentional and XXE protections are in place.",
                )
                .with_owasp("API8: Injection")
                .with_cwe(436)
                .with_confidence(0.7),
            );
        }
    }
}

/// Check a JSON response body for sensitive field names.
///
/// Returns a list of sensitive field names found in the response.
#[must_use]
fn has_sensitive_fields(body: &str) -> Vec<&'static str> {
    let sensitive = [
        "password",
        "password_hash",
        "secret",
        "ssn",
        "social_security",
        "credit_card",
        "card_number",
        "cvv",
        "token",
        "api_key",
        "private_key",
        "secret_key",
    ];

    let lower = body.to_lowercase();
    sensitive
        .iter()
        .filter(|field| {
            // Check for JSON key pattern: "field_name":
            let pattern = format!("\"{field}\"");
            lower.contains(&pattern)
        })
        .copied()
        .collect()
}

/// Generate shadow/versioned API paths to probe.
#[must_use]
fn generate_shadow_api_paths() -> Vec<&'static str> {
    vec![
        "/api/v1/",
        "/api/v2/",
        "/api/v3/",
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/api/internal/",
        "/api/internal",
        "/api/debug/",
        "/api/staging/",
        "/api/beta/",
        "/api/legacy/",
        "/v1/api/",
        "/v2/api/",
    ]
}

/// Fields to inject for mass assignment testing.
#[must_use]
fn mass_assignment_fields() -> Vec<(&'static str, &'static str)> {
    vec![
        ("admin", "true"),
        ("role", "admin"),
        ("is_admin", "true"),
        ("is_staff", "true"),
        ("is_superuser", "true"),
        ("verified", "true"),
        ("approved", "true"),
        ("privilege", "admin"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for REST API security module.

    /// Verify sensitive field detection in JSON responses.
    #[test]
    fn test_has_sensitive_fields() {
        let with_password =
            r#"{"id": 1, "username": "admin", "password": "hashed", "email": "a@b.com"}"#;
        let result = has_sensitive_fields(with_password);
        assert!(result.contains(&"password"));

        let with_token = r#"{"user": "test", "api_key": "sk-123", "secret_key": "abc"}"#;
        let result = has_sensitive_fields(with_token);
        assert!(result.contains(&"api_key"));
        assert!(result.contains(&"secret_key"));

        let safe = r#"{"id": 1, "username": "admin", "email": "a@b.com"}"#;
        let result = has_sensitive_fields(safe);
        assert!(result.is_empty());
    }

    /// Verify shadow API path generation covers expected versions.
    #[test]
    fn test_shadow_api_paths() {
        let paths = generate_shadow_api_paths();

        assert!(paths.len() >= 10);
        assert!(paths.contains(&"/api/v1/"));
        assert!(paths.contains(&"/api/v2/"));
        assert!(paths.contains(&"/api/internal/"));
        assert!(paths.contains(&"/api/legacy/"));
    }

    /// Verify mass assignment field list covers common privilege escalation fields.
    #[test]
    fn test_mass_assignment_fields() {
        let fields = mass_assignment_fields();

        assert!(fields.len() >= 6);

        let names: Vec<&str> = fields.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"admin"));
        assert!(names.contains(&"role"));
        assert!(names.contains(&"is_admin"));
        assert!(names.contains(&"is_staff"));
    }
}
