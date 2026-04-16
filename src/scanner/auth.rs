//! Authentication and session management testing module.
//!
//! Tests session lifecycle security: session ID entropy, session fixation
//! (pre/post-auth cookie comparison), logout invalidation, session expiry
//! analysis, and multiple session cookie detection.
//!
//! Complementary to [`super::misconfig`] which tests cookie *attributes*
//! (`Secure`, `HttpOnly`, `SameSite`). This module tests session *behavior*.

use std::collections::HashSet;

use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Authentication and session management security testing.
///
/// Analyzes session cookies for entropy, fixation vulnerabilities, logout
/// invalidation, and expiry misconfigurations. Credential-gated tests
/// (fixation, logout) require [`AuthConfig`](crate::config::AuthConfig)
/// to be configured; passive checks run regardless.
#[derive(Debug)]
pub struct AuthSessionModule;

#[async_trait]
impl ScanModule for AuthSessionModule {
    fn name(&self) -> &'static str {
        "Auth & Session Management"
    }

    fn id(&self) -> &'static str {
        "auth-session"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Test session ID entropy, fixation, logout invalidation, and expiry"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Passive: fetch target and analyze Set-Cookie headers
        let cookies = fetch_session_cookies(ctx, url).await?;

        if cookies.is_empty() {
            return Ok(findings);
        }

        // Check session ID entropy
        for cookie in &cookies {
            check_entropy(cookie, url, &mut findings);
        }

        // Check expiry configuration
        for cookie in &cookies {
            check_expiry(cookie, url, &mut findings);
        }

        // Check for multiple session cookies (fragmented session management)
        if cookies.len() > 1 {
            findings.push(
                Finding::new(
                    "auth-session",
                    Severity::Low,
                    "Multiple Session Cookies Detected",
                    format!(
                        "The target sets {} session cookies ({}). Multiple session \
                         cookies can indicate fragmented session management, increasing \
                         the attack surface for session hijacking.",
                        cookies.len(),
                        cookies.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ")
                    ),
                    url,
                )
                .with_evidence(format!("Session cookies: {}", cookies.len()))
                .with_remediation(
                    "Consolidate session state into a single session cookie. \
                     Use server-side session storage to avoid multiple tracking cookies.",
                )
                .with_owasp("A07:2021 Identification and Authentication Failures")
                .with_cwe(613)
                .with_confidence(0.7),
            );
        }

        // Credential-gated: session fixation test
        if has_credentials(&ctx.config.auth) {
            check_session_fixation(ctx, url, &cookies, &mut findings).await?;
            check_logout_invalidation(ctx, url, &mut findings).await?;
        }

        // WORK-108b: probe each spec-discovered endpoint for missing
        // auth. A 200 response to an unauthenticated request to an
        // endpoint that should require auth is a Medium finding.
        // We only flag responses that contain content (Content-Length
        // > 0) to reduce false positives on liveness probes.
        if let Some(spec) = crate::engine::api_spec::read_api_spec(&ctx.shared_data) {
            for endpoint in &spec.endpoints {
                let request = match endpoint.method.as_str() {
                    "GET" | "HEAD" => ctx.http_client.get(&endpoint.url),
                    "POST" => ctx.http_client.post(&endpoint.url),
                    "PUT" => ctx.http_client.put(&endpoint.url),
                    "DELETE" => ctx.http_client.delete(&endpoint.url),
                    "PATCH" => ctx.http_client.patch(&endpoint.url),
                    _ => continue,
                };
                let Ok(response) = request.send().await else { continue };
                let status = response.status();
                if status.is_success() {
                    let body_len = response.content_length().unwrap_or(0);
                    if body_len > 32 {
                        findings.push(
                            Finding::new(
                                "auth-session",
                                Severity::Medium,
                                format!(
                                    "Discovered endpoint accepts unauthenticated request: {} {}",
                                    endpoint.method, endpoint.url
                                ),
                                format!(
                                    "An unauthenticated {} request to {} returned {} with \
                                     {body_len} bytes of body content. If this endpoint \
                                     should require authentication, the access-control check \
                                     is missing.",
                                    endpoint.method, endpoint.url, status
                                ),
                                endpoint.url.clone(),
                            )
                            .with_evidence(format!("status={status} body_len={body_len}"))
                            .with_remediation(
                                "Verify the endpoint enforces authentication. If it's \
                                 intentionally public, document it; otherwise add an auth \
                                 check.",
                            )
                            .with_owasp("A01:2021 Broken Access Control")
                            .with_cwe(306)
                            .with_confidence(0.6),
                        );
                    }
                }
            }
        }

        Ok(findings)
    }
}

/// A parsed session cookie from a `Set-Cookie` header.
#[derive(Debug, Clone)]
struct SessionCookie {
    /// Cookie name.
    name: String,
    /// Cookie value (the session ID).
    value: String,
    /// `Max-Age` directive in seconds, if present.
    max_age: Option<i64>,
    /// `Expires` directive raw string, if present.
    expires: Option<String>,
}

/// Fetch the target URL and extract session cookies from `Set-Cookie` headers.
async fn fetch_session_cookies(ctx: &ScanContext, url: &str) -> Result<Vec<SessionCookie>> {
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

    Ok(cookie_headers.iter().filter_map(|h| parse_session_cookie(h)).collect())
}

/// Parse a `Set-Cookie` header into a [`SessionCookie`] if it looks like a session cookie.
///
/// Returns `None` for non-session cookies (analytics, preferences, etc.).
fn parse_session_cookie(header: &str) -> Option<SessionCookie> {
    let parts: Vec<&str> = header.splitn(2, '=').collect();
    if parts.len() < 2 {
        return None;
    }

    let name = parts[0].trim().to_string();
    if !is_session_cookie(&name) {
        return None;
    }

    // Value is everything up to the first semicolon
    let rest = parts[1];
    let value = rest.split(';').next().unwrap_or("").trim().to_string();

    // Parse directives
    let lower = header.to_lowercase();
    let max_age = extract_directive(&lower, "max-age=").and_then(|v| v.parse::<i64>().ok());
    let expires = extract_directive(&lower, "expires=").map(String::from);

    Some(SessionCookie { name, value, max_age, expires })
}

/// Extract a directive value from a cookie header string.
///
/// Given `"...; max-age=3600; ..."` and prefix `"max-age="`, returns `"3600"`.
fn extract_directive<'a>(header: &'a str, prefix: &str) -> Option<&'a str> {
    header.split(';').find_map(|part| {
        let trimmed = part.trim();
        trimmed.strip_prefix(prefix).map(str::trim)
    })
}

/// Check session ID entropy (length and character diversity).
///
/// Short or low-diversity session IDs are susceptible to brute-force attacks.
fn check_entropy(cookie: &SessionCookie, url: &str, findings: &mut Vec<Finding>) {
    let value = &cookie.value;

    // Skip empty or very short values that might be flags, not session IDs
    if value.len() < 8 {
        findings.push(
            Finding::new(
                "auth-session",
                Severity::High,
                format!("Extremely Short Session ID: {}", cookie.name),
                format!(
                    "The session cookie '{}' has a value of only {} characters. \
                     Session IDs should be at least 128 bits (32 hex chars) to resist \
                     brute-force attacks.",
                    cookie.name,
                    value.len()
                ),
                url,
            )
            .with_evidence(format!("Length: {} chars", value.len()))
            .with_remediation(
                "Use a cryptographically secure random number generator to produce \
                 session IDs of at least 128 bits (32 hex characters or 22 base64 characters).",
            )
            .with_owasp("A07:2021 Identification and Authentication Failures")
            .with_cwe(330)
            .with_confidence(0.7),
        );
        return;
    }

    let entropy = compute_entropy_score(value);

    if entropy < 3.0 {
        findings.push(
            Finding::new(
                "auth-session",
                Severity::High,
                format!("Low Entropy Session ID: {}", cookie.name),
                format!(
                    "The session cookie '{}' has low entropy ({:.1} bits/char). \
                     This suggests predictable session ID generation, making \
                     session hijacking via brute-force feasible.",
                    cookie.name, entropy
                ),
                url,
            )
            .with_evidence(format!(
                "Entropy: {entropy:.1} bits/char | Length: {} | Unique chars: {}",
                value.len(),
                unique_char_count(value)
            ))
            .with_remediation(
                "Use a cryptographically secure PRNG (e.g., /dev/urandom, SecureRandom) \
                 to generate session IDs. Avoid sequential, timestamp-based, or \
                 user-derived session identifiers.",
            )
            .with_owasp("A07:2021 Identification and Authentication Failures")
            .with_cwe(330)
            .with_confidence(0.7),
        );
    }
}

/// Compute Shannon entropy in bits per character.
///
/// Higher values indicate more randomness. Typical good session IDs score > 4.0.
#[must_use]
fn compute_entropy_score(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }

    #[allow(clippy::cast_precision_loss)]
    // Session IDs are short strings; precision loss is negligible
    let len = value.len() as f64;
    let mut freq = [0u32; 256];

    for &byte in value.as_bytes() {
        freq[byte as usize] += 1;
    }

    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = f64::from(count) / len;
            -p * p.log2()
        })
        .sum()
}

/// Count unique characters in a string.
#[must_use]
fn unique_char_count(value: &str) -> usize {
    value.chars().collect::<HashSet<_>>().len()
}

/// Check session cookie expiry configuration.
///
/// Missing expiry creates session cookies (good for auth). Excessively long
/// expiry (> 24 hours) increases the window for session hijacking.
fn check_expiry(cookie: &SessionCookie, url: &str, findings: &mut Vec<Finding>) {
    // Max-Age takes precedence over Expires
    if let Some(max_age) = cookie.max_age {
        if max_age > 86400 {
            #[allow(clippy::cast_precision_loss)] // Days display — precision irrelevant
            let days = max_age as f64 / 86400.0;
            findings.push(
                Finding::new(
                    "auth-session",
                    Severity::Low,
                    format!("Excessive Session Lifetime: {}", cookie.name),
                    format!(
                        "The session cookie '{}' has a Max-Age of {} seconds ({days:.1} days). \
                         Long session lifetimes increase the window for session hijacking.",
                        cookie.name, max_age,
                    ),
                    url,
                )
                .with_evidence(format!("Max-Age: {max_age}s"))
                .with_remediation(
                    "Set session cookie lifetimes to the minimum required for your \
                     application. Consider 15-30 minutes for sensitive applications \
                     with idle timeout, or 8-24 hours maximum for remember-me tokens.",
                )
                .with_owasp("A07:2021 Identification and Authentication Failures")
                .with_cwe(613)
                .with_confidence(0.7),
            );
        }
        return;
    }

    // No Max-Age — check if Expires is far in the future
    // No Expires and no Max-Age = session cookie (expires when browser closes) — this is fine
    if cookie.expires.is_none() {
        return;
    }

    // Expires is present but we can't easily compare dates without a crate.
    // Flag if it contains a year far in the future as a heuristic.
    if let Some(ref expires) = cookie.expires {
        if expires.contains("2099") || expires.contains("2098") || expires.contains("9999") {
            findings.push(
                Finding::new(
                    "auth-session",
                    Severity::Medium,
                    format!("Effectively Permanent Session: {}", cookie.name),
                    format!(
                        "The session cookie '{}' has an Expires date far in the future, \
                         making it effectively permanent. This maximizes the window \
                         for session hijacking.",
                        cookie.name
                    ),
                    url,
                )
                .with_evidence(format!("Expires: {expires}"))
                .with_remediation("Set reasonable session expiry times (hours, not years)")
                .with_owasp("A07:2021 Identification and Authentication Failures")
                .with_cwe(613)
                .with_confidence(0.7),
            );
        }
    }
}

/// Check for session fixation by comparing cookies before and after authentication.
///
/// If any session cookie value remains unchanged after authenticating, the
/// application may be vulnerable to session fixation attacks.
async fn check_session_fixation(
    ctx: &ScanContext,
    url: &str,
    pre_auth_cookies: &[SessionCookie],
    findings: &mut Vec<Finding>,
) -> Result<()> {
    // Build an authenticated request
    let mut request = ctx.http_client.get(url);

    // Apply auth config credentials
    let auth = &ctx.config.auth;
    if let Some(ref token) = auth.bearer_token {
        request = request.header("Authorization", format!("Bearer {token}"));
    } else if let (Some(ref user), Some(ref pass)) = (&auth.username, &auth.password) {
        request = request.basic_auth(user, Some(pass));
    }
    if let Some(ref cookies) = auth.cookies {
        request = request.header("Cookie", cookies.as_str());
    }
    if let (Some(ref name), Some(ref value)) = (&auth.custom_header, &auth.custom_header_value) {
        request = request.header(name.as_str(), value.as_str());
    }

    let Ok(response) = request.send().await else {
        return Ok(()); // Auth request failed — skip test
    };

    // If we got 401/403, credentials are invalid — skip
    let status = response.status().as_u16();
    if status == 401 || status == 403 {
        return Ok(());
    }

    let post_auth_cookies: Vec<SessionCookie> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(parse_session_cookie)
        .collect();

    // Compare: if any pre-auth session cookie value matches a post-auth value → fixation
    let fixated = detect_fixation(pre_auth_cookies, &post_auth_cookies);

    for cookie_name in fixated {
        findings.push(
            Finding::new(
                "auth-session",
                Severity::High,
                format!("Session Fixation: {cookie_name}"),
                format!(
                    "The session cookie '{cookie_name}' retains the same value before \
                     and after authentication. An attacker can set a known session ID \
                     in the victim's browser, then hijack the session after the victim logs in."
                ),
                url,
            )
            .with_evidence(format!("Cookie '{cookie_name}' unchanged after authentication"))
            .with_remediation(
                "Regenerate the session ID after every authentication event. \
                 Invalidate the pre-authentication session and issue a new session \
                 cookie upon successful login.",
            )
            .with_owasp("A07:2021 Identification and Authentication Failures")
            .with_cwe(384)
            .with_confidence(0.7),
        );
    }

    Ok(())
}

/// Detect session fixation by comparing pre-auth and post-auth cookie values.
///
/// Returns the names of session cookies whose values did not change.
#[must_use]
fn detect_fixation(pre: &[SessionCookie], post: &[SessionCookie]) -> Vec<String> {
    pre.iter()
        .filter(|pre_cookie| {
            post.iter().any(|post_cookie| {
                pre_cookie.name == post_cookie.name
                    && pre_cookie.value == post_cookie.value
                    && !pre_cookie.value.is_empty()
            })
        })
        .map(|c| c.name.clone())
        .collect()
}

/// Test logout invalidation by requesting common logout paths then re-checking auth.
async fn check_logout_invalidation(
    ctx: &ScanContext,
    url: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let base = ctx.target.base_url();

    // Try common logout paths
    let logout_paths =
        ["/logout", "/signout", "/sign-out", "/api/logout", "/api/auth/logout", "/auth/logout"];

    let mut logout_hit = false;
    for path in &logout_paths {
        let logout_url = format!("{base}{path}");
        let Ok(response) = ctx.http_client.get(&logout_url).send().await else {
            continue;
        };

        let status = response.status().as_u16();
        // 200 or 302 (redirect) suggests the logout endpoint exists
        if status == 200 || status == 302 {
            logout_hit = true;
            break;
        }
    }

    if !logout_hit {
        return Ok(());
    }

    // After logout, re-request the original URL with the same auth
    let mut request = ctx.http_client.get(url);
    let auth = &ctx.config.auth;
    if let Some(ref token) = auth.bearer_token {
        request = request.header("Authorization", format!("Bearer {token}"));
    } else if let (Some(ref user), Some(ref pass)) = (&auth.username, &auth.password) {
        request = request.basic_auth(user, Some(pass));
    }
    if let Some(ref cookies) = auth.cookies {
        request = request.header("Cookie", cookies.as_str());
    }

    let Ok(response) = request.send().await else {
        return Ok(());
    };

    let status = response.status().as_u16();

    // If still authenticated (200 on a presumably protected resource), session wasn't invalidated
    // This is a heuristic — 200 after logout suggests the session is still valid
    if status == 200 {
        findings.push(
            Finding::new(
                "auth-session",
                Severity::Medium,
                "Session Not Invalidated After Logout",
                "After hitting a logout endpoint, the session token still appears \
                 to be valid. The server may not be invalidating sessions server-side \
                 on logout, allowing session reuse after the user believes they've logged out.",
                url,
            )
            .with_evidence(format!("POST-logout request returned HTTP {status}"))
            .with_remediation(
                "Invalidate the session server-side on logout. Delete or rotate \
                 the session record in the session store. Do not rely solely on \
                 client-side cookie deletion.",
            )
            .with_owasp("A07:2021 Identification and Authentication Failures")
            .with_cwe(613)
            .with_confidence(0.7),
        );
    }

    Ok(())
}

/// Heuristic to determine if a cookie name indicates a session cookie.
///
/// Matches common session cookie naming patterns used by popular frameworks.
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
        "connect.sid",
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid",
        "laravel_session",
        "_session",
    ];
    session_indicators.iter().any(|indicator| lower.contains(indicator))
}

/// Whether the `AuthConfig` has any credentials configured.
const fn has_credentials(auth: &crate::config::AuthConfig) -> bool {
    auth.bearer_token.is_some()
        || auth.cookies.is_some()
        || (auth.username.is_some() && auth.password.is_some())
        || (auth.custom_header.is_some() && auth.custom_header_value.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for authentication and session management analysis.
    ///
    /// Tests pure analysis functions (entropy, expiry, fixation, cookie parsing)
    /// without requiring a live HTTP target.

    /// Verify session cookie parsing from `Set-Cookie` header strings.
    ///
    /// Tests that name, value, `Max-Age`, and `Expires` directives are extracted
    /// correctly, and non-session cookies are filtered out.
    #[test]
    fn test_parse_session_cookies() {
        // Session cookie with directives
        let cookie =
            parse_session_cookie("PHPSESSID=abc123def; Max-Age=3600; Path=/; HttpOnly; Secure");
        assert!(cookie.is_some());
        let c = cookie.as_ref().unwrap_or_else(|| unreachable!());
        assert_eq!(c.name, "PHPSESSID");
        assert_eq!(c.value, "abc123def");
        assert_eq!(c.max_age, Some(3600));

        // Non-session cookie — should be None
        let analytics = parse_session_cookie("_ga=GA1.2.123456; Path=/");
        assert!(analytics.is_none());

        // Cookie with Expires
        let cookie2 =
            parse_session_cookie("session_token=xyz789; Expires=Thu, 01 Jan 2099 00:00:00 GMT");
        assert!(cookie2.is_some());
        let c2 = cookie2.as_ref().unwrap_or_else(|| unreachable!());
        assert_eq!(c2.name, "session_token");
        assert!(c2.expires.is_some());
    }

    /// Verify that high-entropy session IDs score above the detection threshold.
    ///
    /// A cryptographically random hex string should have entropy > 3.0 bits/char,
    /// avoiding false positive findings.
    #[test]
    fn test_entropy_high() {
        // 32-char hex string — typical good session ID
        let high_entropy = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        let score = compute_entropy_score(high_entropy);
        assert!(score > 3.0, "High entropy session ID scored {score:.1}, expected > 3.0");
    }

    /// Verify that low-entropy/predictable session IDs score below threshold.
    ///
    /// Sequential or repetitive values should trigger a finding.
    #[test]
    fn test_entropy_low() {
        // All same character — zero entropy
        let zero_entropy = "aaaaaaaaaaaaaaaa";
        let score = compute_entropy_score(zero_entropy);
        assert!(score < 1.0, "Zero entropy string scored {score:.1}, expected < 1.0");

        // Sequential — low entropy
        let sequential = "1234567890123456";
        let score2 = compute_entropy_score(sequential);
        assert!(score2 < 3.5, "Sequential string scored {score2:.1}, expected < 3.5");
    }

    /// Verify expiry analysis detects missing, excessive, and far-future expiry.
    ///
    /// Tests the pure `check_expiry` function against various cookie configurations.
    #[test]
    fn test_expiry_analysis() {
        let mut findings = Vec::new();

        // Session cookie (no expiry) — should produce no finding
        let session_cookie = SessionCookie {
            name: "sid".to_string(),
            value: "abc123".to_string(),
            max_age: None,
            expires: None,
        };
        check_expiry(&session_cookie, "https://example.com", &mut findings);
        assert!(findings.is_empty(), "Session cookie should not produce expiry finding");

        // Excessive Max-Age (> 24h)
        let long_lived = SessionCookie {
            name: "token".to_string(),
            value: "xyz789".to_string(),
            max_age: Some(604_800), // 7 days
            expires: None,
        };
        check_expiry(&long_lived, "https://example.com", &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Excessive Session Lifetime"));

        // Permanent cookie (year 2099)
        findings.clear();
        let permanent = SessionCookie {
            name: "auth_token".to_string(),
            value: "perm".to_string(),
            max_age: None,
            expires: Some("Thu, 01 Jan 2099 00:00:00 GMT".to_string()),
        };
        check_expiry(&permanent, "https://example.com", &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Effectively Permanent"));
    }

    /// Verify session fixation detection when pre/post-auth cookies match.
    ///
    /// If a session cookie value is identical before and after login, the
    /// application is vulnerable to session fixation.
    #[test]
    fn test_session_fixation_detected() {
        let pre = vec![SessionCookie {
            name: "PHPSESSID".to_string(),
            value: "fixed_session_123".to_string(),
            max_age: None,
            expires: None,
        }];

        let post = vec![SessionCookie {
            name: "PHPSESSID".to_string(),
            value: "fixed_session_123".to_string(), // Same value — fixation!
            max_age: None,
            expires: None,
        }];

        let fixated = detect_fixation(&pre, &post);
        assert_eq!(fixated, vec!["PHPSESSID"]);
    }

    /// Verify no false positive when session ID changes after authentication.
    ///
    /// A properly implemented application rotates the session ID on login.
    #[test]
    fn test_session_fixation_safe() {
        let pre = vec![SessionCookie {
            name: "PHPSESSID".to_string(),
            value: "old_session_abc".to_string(),
            max_age: None,
            expires: None,
        }];

        let post = vec![SessionCookie {
            name: "PHPSESSID".to_string(),
            value: "new_session_xyz".to_string(), // Different — safe
            max_age: None,
            expires: None,
        }];

        let fixated = detect_fixation(&pre, &post);
        assert!(fixated.is_empty());
    }

    /// Verify the session cookie name heuristic.
    ///
    /// Common session cookie names from popular frameworks should be identified,
    /// while analytics and tracking cookies should be excluded.
    #[test]
    fn test_is_session_cookie() {
        // Should match
        assert!(is_session_cookie("PHPSESSID"));
        assert!(is_session_cookie("JSESSIONID"));
        assert!(is_session_cookie("connect.sid"));
        assert!(is_session_cookie("auth_token"));
        assert!(is_session_cookie("session_id"));
        assert!(is_session_cookie("csrf_token"));
        assert!(is_session_cookie("laravel_session"));
        assert!(is_session_cookie("ASP.NET_SessionId"));

        // Should NOT match
        assert!(!is_session_cookie("_ga"));
        assert!(!is_session_cookie("_gid"));
        assert!(!is_session_cookie("theme"));
        assert!(!is_session_cookie("lang"));
        assert!(!is_session_cookie("cookie_consent"));
    }

    /// Verify entropy computation edge cases.
    ///
    /// Empty strings, single characters, and maximum-entropy strings should
    /// all produce correct scores.
    #[test]
    fn test_entropy_edge_cases() {
        // Empty string
        assert_eq!(compute_entropy_score(""), 0.0);

        // Single character repeated
        assert!(compute_entropy_score("aaaa") < 0.01);

        // Two alternating characters
        let two_char = compute_entropy_score("abababab");
        assert!(
            (0.9..=1.1).contains(&two_char),
            "Two-char alternating scored {two_char:.2}, expected ~1.0"
        );
    }

    /// Verify the `has_credentials` helper function.
    ///
    /// Each credential type (bearer, basic, cookie, custom header) should
    /// independently trigger `true`.
    #[test]
    fn test_has_credentials() {
        use crate::config::AuthConfig;

        let empty = AuthConfig::default();
        assert!(!has_credentials(&empty));

        let bearer = AuthConfig { bearer_token: Some("tok".to_string()), ..Default::default() };
        assert!(has_credentials(&bearer));

        let basic = AuthConfig {
            username: Some("u".to_string()),
            password: Some("p".to_string()),
            ..Default::default()
        };
        assert!(has_credentials(&basic));

        let cookie = AuthConfig { cookies: Some("sid=abc".to_string()), ..Default::default() };
        assert!(has_credentials(&cookie));

        let custom = AuthConfig {
            custom_header: Some("X-Api-Key".to_string()),
            custom_header_value: Some("key123".to_string()),
            ..Default::default()
        };
        assert!(has_credentials(&custom));
    }

    /// Verify unique character counting used in evidence strings.
    #[test]
    fn test_unique_char_count() {
        assert_eq!(unique_char_count("aaaa"), 1);
        assert_eq!(unique_char_count("abcd"), 4);
        assert_eq!(unique_char_count("aabbcc"), 3);
        assert_eq!(unique_char_count(""), 0);
    }

    /// Verify directive extraction from cookie header strings.
    ///
    /// Tests `Max-Age` and `Expires` directive parsing from `Set-Cookie` headers.
    #[test]
    fn test_extract_directive() {
        let header = "phpsessid=abc; max-age=3600; path=/; httponly";
        assert_eq!(extract_directive(header, "max-age="), Some("3600"));
        assert_eq!(extract_directive(header, "path="), Some("/"));
        assert_eq!(extract_directive(header, "expires="), None);
    }
}
