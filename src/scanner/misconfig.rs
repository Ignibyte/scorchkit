use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Checks for common security misconfigurations.
#[derive(Debug)]
pub struct MisconfigModule;

#[async_trait]
impl ScanModule for MisconfigModule {
    fn name(&self) -> &'static str {
        "Security Misconfiguration"
    }

    fn id(&self) -> &'static str {
        "misconfig"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Check CORS, cookie flags, error pages, and HTTP methods"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // CORS checks
        check_cors(ctx, url, &mut findings).await?;

        // Cookie security flags
        check_cookies(ctx, url, &mut findings).await?;

        // Error page information disclosure
        check_error_pages(ctx, &mut findings).await?;

        // Dangerous HTTP methods
        check_http_methods(ctx, url, &mut findings).await?;

        Ok(findings)
    }
}

/// Test for CORS misconfiguration by sending a request with a spoofed Origin.
async fn check_cors(ctx: &ScanContext, url: &str, findings: &mut Vec<Finding>) -> Result<()> {
    let evil_origin = "https://evil-attacker.com";

    let response = ctx
        .http_client
        .get(url)
        .header("Origin", evil_origin)
        .send()
        .await
        .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

    let headers = response.headers();

    if let Some(acao) = headers.get("access-control-allow-origin") {
        let acao_val = acao.to_str().unwrap_or("");

        // Reflects arbitrary origin
        if acao_val == evil_origin {
            let has_credentials = headers
                .get("access-control-allow-credentials")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v == "true");

            let severity = if has_credentials { Severity::Critical } else { Severity::High };

            let desc = if has_credentials {
                "CORS reflects arbitrary origins AND allows credentials. \
                 An attacker can make authenticated cross-origin requests \
                 and read responses, leading to full account takeover."
            } else {
                "CORS reflects arbitrary origins. An attacker can read \
                 cross-origin responses, potentially leaking sensitive data."
            };

            findings.push(
                Finding::new("misconfig", severity, "CORS Origin Reflection", desc, url)
                    .with_evidence(format!(
                        "Origin: {evil_origin} → Access-Control-Allow-Origin: {acao_val}{}",
                        if has_credentials {
                            " | Access-Control-Allow-Credentials: true"
                        } else {
                            ""
                        }
                    ))
                    .with_remediation(
                        "Configure CORS to only allow specific trusted origins. \
                         Never reflect the Origin header directly.",
                    )
                    .with_owasp("A05:2021 Security Misconfiguration")
                    .with_cwe(942)
                    .with_confidence(0.8),
            );
        }

        // Wildcard with credentials
        if acao_val == "*" {
            if let Some(creds) = headers.get("access-control-allow-credentials") {
                if creds.to_str().unwrap_or("") == "true" {
                    findings.push(
                        Finding::new(
                            "misconfig",
                            Severity::High,
                            "CORS Wildcard with Credentials",
                            "CORS is configured with Access-Control-Allow-Origin: * \
                             and Access-Control-Allow-Credentials: true. This is an \
                             invalid and dangerous combination.",
                            url,
                        )
                        .with_evidence(
                            "Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                        )
                        .with_remediation("Specify explicit allowed origins instead of using wildcard")
                        .with_owasp("A05:2021 Security Misconfiguration")
                        .with_cwe(942)
                        .with_confidence(0.8),
                    );
                }
            }
        }

        // Null origin allowed
        if acao_val == "null" {
            findings.push(
                Finding::new(
                    "misconfig",
                    Severity::Medium,
                    "CORS Allows Null Origin",
                    "CORS accepts the 'null' origin. Sandboxed iframes and \
                     data: URIs send null origin, enabling bypass.",
                    url,
                )
                .with_evidence("Access-Control-Allow-Origin: null")
                .with_remediation("Do not whitelist the null origin in CORS configuration")
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(942)
                .with_confidence(0.8),
            );
        }
    }

    Ok(())
}

/// Check Set-Cookie headers for missing security flags.
async fn check_cookies(ctx: &ScanContext, url: &str, findings: &mut Vec<Finding>) -> Result<()> {
    let response = ctx
        .http_client
        .get(url)
        .send()
        .await
        .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

    let cookie_headers: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(String::from)
        .collect();

    for cookie_str in &cookie_headers {
        let cookie_lower = cookie_str.to_lowercase();
        let cookie_name = cookie_str.split('=').next().unwrap_or("unknown").trim();

        // Skip non-session cookies (analytics, etc.)
        let is_likely_session = is_session_cookie(cookie_name);

        // Missing Secure flag
        if ctx.target.is_https && !cookie_lower.contains("secure") && is_likely_session {
            findings.push(
                Finding::new(
                    "misconfig",
                    Severity::Medium,
                    format!("Cookie Missing Secure Flag: {cookie_name}"),
                    format!(
                        "The cookie '{cookie_name}' is set without the Secure flag. \
                         It will be sent over unencrypted HTTP connections."
                    ),
                    url,
                )
                .with_evidence(truncate_cookie(cookie_str))
                .with_remediation("Add the Secure flag to all session cookies")
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(614)
                .with_confidence(0.8),
            );
        }

        // Missing HttpOnly flag
        if !cookie_lower.contains("httponly") && is_likely_session {
            findings.push(
                Finding::new(
                    "misconfig",
                    Severity::Medium,
                    format!("Cookie Missing HttpOnly Flag: {cookie_name}"),
                    format!(
                        "The cookie '{cookie_name}' is set without the HttpOnly flag. \
                         It can be accessed by JavaScript, enabling XSS-based session theft."
                    ),
                    url,
                )
                .with_evidence(truncate_cookie(cookie_str))
                .with_remediation("Add the HttpOnly flag to all session cookies")
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(1004)
                .with_confidence(0.8),
            );
        }

        // Missing SameSite attribute
        if !cookie_lower.contains("samesite") && is_likely_session {
            findings.push(
                Finding::new(
                    "misconfig",
                    Severity::Low,
                    format!("Cookie Missing SameSite Attribute: {cookie_name}"),
                    format!(
                        "The cookie '{cookie_name}' lacks a SameSite attribute. \
                         It may be sent with cross-site requests, enabling CSRF attacks."
                    ),
                    url,
                )
                .with_evidence(truncate_cookie(cookie_str))
                .with_remediation("Add SameSite=Lax or SameSite=Strict to session cookies")
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(1275)
                .with_confidence(0.8),
            );
        }

        // SameSite=None without Secure
        if cookie_lower.contains("samesite=none") && !cookie_lower.contains("secure") {
            findings.push(
                Finding::new(
                    "misconfig",
                    Severity::Medium,
                    format!("SameSite=None Without Secure: {cookie_name}"),
                    format!(
                        "The cookie '{cookie_name}' has SameSite=None but lacks the Secure flag. \
                         Modern browsers will reject this cookie."
                    ),
                    url,
                )
                .with_evidence(truncate_cookie(cookie_str))
                .with_remediation("SameSite=None requires the Secure flag")
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_confidence(0.8),
            );
        }
    }

    Ok(())
}

/// Check error pages for information disclosure.
async fn check_error_pages(ctx: &ScanContext, findings: &mut Vec<Finding>) -> Result<()> {
    let base_url = ctx.target.base_url();

    // Request a path that definitely doesn't exist
    let random_path = format!("{}/scorchkit-nonexistent-{}", base_url, uuid::Uuid::new_v4());

    let response = ctx
        .http_client
        .get(&random_path)
        .send()
        .await
        .map_err(|e| ScorchError::Http { url: random_path.clone(), source: e })?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let body_lower = body.to_lowercase();

    // Check for stack traces
    let stack_trace_patterns = [
        ("at java.", "Java stack trace"),
        ("at org.", "Java stack trace"),
        ("traceback (most recent call last)", "Python traceback"),
        ("file \"", "Python traceback"),
        ("in /var/www/", "PHP file path disclosure"),
        ("in /home/", "Server path disclosure"),
        ("stack trace:", "Stack trace"),
        ("stacktrace", "Stack trace"),
        ("microsoft.net", "ASP.NET error"),
        ("unhandled exception", "Unhandled exception"),
        ("runtime error", "Runtime error"),
        ("syntax error", "Syntax error"),
        ("fatal error", "Fatal error"),
        ("parse error", "Parse error"),
        ("warning:</b>", "PHP warning"),
        ("notice:</b>", "PHP notice"),
        ("on line <b>", "PHP error with line number"),
    ];

    for (pattern, desc) in &stack_trace_patterns {
        if body_lower.contains(pattern) {
            findings.push(
                Finding::new(
                    "misconfig",
                    Severity::Medium,
                    "Error Page Information Disclosure",
                    format!(
                        "The error page (HTTP {}) reveals internal information: {desc}. \
                         This helps attackers understand the technology stack and find vulnerabilities.",
                        status.as_u16()
                    ),
                    &random_path,
                )
                .with_evidence(extract_error_snippet(&body, pattern))
                .with_remediation(
                    "Configure custom error pages that don't reveal internal details",
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(209)
                .with_confidence(0.8),
            );
            break; // One finding per error page is enough
        }
    }

    Ok(())
}

/// Check for dangerous HTTP methods.
async fn check_http_methods(
    ctx: &ScanContext,
    url: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let response = ctx
        .http_client
        .request(reqwest::Method::OPTIONS, url)
        .send()
        .await
        .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

    if let Some(allow) = response.headers().get("allow") {
        let allow_str = allow.to_str().unwrap_or("");
        let methods: Vec<&str> = allow_str.split(',').map(str::trim).collect();

        let dangerous = ["PUT", "DELETE", "TRACE", "CONNECT"];
        let found_dangerous: Vec<&str> = methods
            .iter()
            .filter(|m| dangerous.contains(&m.to_uppercase().as_str()))
            .copied()
            .collect();

        if !found_dangerous.is_empty() {
            findings.push(
                Finding::new(
                    "misconfig",
                    Severity::Medium,
                    "Dangerous HTTP Methods Enabled",
                    format!(
                        "The server allows potentially dangerous HTTP methods: {}. \
                         These could enable unauthorized data modification or information leakage.",
                        found_dangerous.join(", ")
                    ),
                    url,
                )
                .with_evidence(format!("Allow: {allow_str}"))
                .with_remediation(
                    "Disable unnecessary HTTP methods (PUT, DELETE, TRACE) in the web server configuration",
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(749)
                .with_confidence(0.8),
            );
        }

        // TRACE specifically enables XST (Cross-Site Tracing)
        if methods.iter().any(|m| m.to_uppercase() == "TRACE") {
            findings.push(
                Finding::new(
                    "misconfig",
                    Severity::Medium,
                    "TRACE Method Enabled (Cross-Site Tracing)",
                    "The TRACE HTTP method is enabled. This can be exploited \
                     for Cross-Site Tracing (XST) attacks to steal credentials.",
                    url,
                )
                .with_evidence(format!("Allow: {allow_str}"))
                .with_remediation("Disable the TRACE method in the web server configuration")
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(693)
                .with_confidence(0.8),
            );
        }
    }

    Ok(())
}

// --- Helpers ---

/// Heuristic to determine if a cookie is likely a session cookie.
fn is_session_cookie(name: &str) -> bool {
    let lower = name.to_lowercase();
    let session_indicators = [
        "session",
        "sess",
        "sid",
        "token",
        "auth",
        "login",
        "jwt",
        "csrf",
        "xsrf",
        "connect.sid",
        "phpsessid",
        "jsessionid",
        "asp.net",
    ];
    session_indicators.iter().any(|i| lower.contains(i))
}

/// Truncate a cookie value for evidence display (don't leak full values).
fn truncate_cookie(cookie_str: &str) -> String {
    cookie_str.find('=').map_or_else(
        || cookie_str.to_string(),
        |eq_pos| {
            let name = &cookie_str[..eq_pos];
            let rest = &cookie_str[eq_pos + 1..];
            // Show name + first few chars of value + flags
            rest.find(';').map_or_else(
                || {
                    let truncated = if rest.len() > 10 {
                        format!("{}...", &rest[..10])
                    } else {
                        rest.to_string()
                    };
                    format!("{name}={truncated}")
                },
                |semi_pos| {
                    let value = &rest[..semi_pos];
                    let flags = &rest[semi_pos..];
                    let truncated_value = if value.len() > 10 {
                        format!("{}...", &value[..10])
                    } else {
                        value.to_string()
                    };
                    format!("{name}={truncated_value}{flags}")
                },
            )
        },
    )
}

/// Extract a snippet around a pattern match for evidence.
fn extract_error_snippet(body: &str, pattern: &str) -> String {
    let lower = body.to_lowercase();
    lower.find(pattern).map_or_else(
        || format!("Pattern detected: {pattern}"),
        |pos| {
            let start = pos.saturating_sub(50);
            let end = (pos + pattern.len() + 100).min(body.len());
            let snippet: String = body[start..end]
                .chars()
                .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
                .collect();
            format!("...{snippet}...")
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for the security misconfiguration module's pure helper functions.

    /// Verify that `is_session_cookie` correctly identifies session-related cookies
    /// and rejects unrelated cookie names.
    #[test]
    fn test_is_session_cookie() {
        // Arrange & Assert: known session cookie names
        assert!(is_session_cookie("PHPSESSID"));
        assert!(is_session_cookie("JSESSIONID"));
        assert!(is_session_cookie("connect.sid"));
        assert!(is_session_cookie("auth_token"));
        assert!(is_session_cookie("csrf_token"));
        assert!(is_session_cookie("jwt_data"));

        // Non-session cookies
        assert!(!is_session_cookie("_ga"));
        assert!(!is_session_cookie("theme"));
        assert!(!is_session_cookie("lang"));
        assert!(!is_session_cookie("preferred_color"));
    }

    /// Verify that `truncate_cookie` truncates long cookie values while preserving
    /// the name and flags, and handles short values and missing equals signs.
    #[test]
    fn test_truncate_cookie() {
        // Arrange: long value with flags
        let long_cookie =
            "session_id=abcdefghijklmnopqrstuvwxyz; HttpOnly; Secure; SameSite=Strict";

        // Act
        let result = truncate_cookie(long_cookie);

        // Assert: name preserved, value truncated, flags preserved
        assert!(result.starts_with("session_id=abcdefghij..."));
        assert!(result.contains("HttpOnly"));
        assert!(result.contains("Secure"));

        // Arrange: short value without flags
        let short_cookie = "sid=abc";
        let short_result = truncate_cookie(short_cookie);
        assert_eq!(short_result, "sid=abc");

        // Arrange: no equals sign
        let no_eq = "malformed_cookie";
        let no_eq_result = truncate_cookie(no_eq);
        assert_eq!(no_eq_result, "malformed_cookie");
    }

    /// Verify that `extract_error_snippet` returns a context window around the matched
    /// pattern and falls back to a descriptive string when the pattern is absent.
    #[test]
    fn test_extract_error_snippet() {
        // Arrange: body with a known pattern
        let body = "Some prefix text. Fatal error: unexpected condition in /var/www/app.php on line 42. More text follows.";

        // Act
        let snippet = extract_error_snippet(body, "fatal error");

        // Assert: snippet contains surrounding context
        assert!(snippet.starts_with("..."));
        assert!(snippet.ends_with("..."));
        assert!(snippet.to_lowercase().contains("fatal error"));

        // Arrange: pattern not found
        let missing = extract_error_snippet(body, "never_matches_xyz");

        // Assert: fallback message
        assert!(missing.contains("Pattern detected: never_matches_xyz"));
    }
}
