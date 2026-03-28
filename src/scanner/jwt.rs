use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Analyzes JWT tokens found in responses for security issues.
#[derive(Debug)]
pub struct JwtModule;

#[async_trait]
impl ScanModule for JwtModule {
    fn name(&self) -> &'static str {
        "JWT Analysis"
    }

    fn id(&self) -> &'static str {
        "jwt"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Analyze JWT tokens in responses for security weaknesses"
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
        let body = response.text().await.unwrap_or_default();

        let mut findings = Vec::new();

        // Collect JWTs from cookies and response body
        let mut tokens: Vec<(String, String)> = Vec::new(); // (source, token)

        // Check cookies
        for cookie in headers.get_all("set-cookie") {
            let val = cookie.to_str().unwrap_or("");
            let cookie_name = val.split('=').next().unwrap_or("");
            if let Some(token_val) = val.split('=').nth(1) {
                let token = token_val.split(';').next().unwrap_or("");
                if is_jwt(token) {
                    tokens.push((format!("cookie:{cookie_name}"), token.to_string()));
                }
            }
        }

        // Check Authorization response header (rare but possible)
        if let Some(auth) = headers.get("authorization") {
            let val = auth.to_str().unwrap_or("");
            if let Some(token) = val.strip_prefix("Bearer ") {
                if is_jwt(token) {
                    tokens.push(("header:Authorization".to_string(), token.to_string()));
                }
            }
        }

        // Search body for JWT patterns
        for token in extract_jwts_from_body(&body) {
            tokens.push(("body".to_string(), token));
        }

        // Analyze each JWT
        for (source, token) in &tokens {
            analyze_jwt(token, source, url, &mut findings);
        }

        Ok(findings)
    }
}

/// Check if a string looks like a JWT (three base64url-encoded parts separated by dots).
fn is_jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    // Each part should be valid base64url
    parts.iter().all(|p| {
        !p.is_empty()
            && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
    })
}

/// Extract JWT-like tokens from response body.
fn extract_jwts_from_body(body: &str) -> Vec<String> {
    let mut tokens = Vec::new();

    // Look for eyJ... patterns (base64-encoded JSON starting with `{`)
    for word in body.split_whitespace() {
        // Strip quotes and common delimiters
        let cleaned = word.trim_matches(|c: char| {
            c == '"' || c == '\'' || c == ',' || c == ';' || c == ')' || c == '('
        });
        if cleaned.starts_with("eyJ") && is_jwt(cleaned) {
            tokens.push(cleaned.to_string());
        }
    }

    // Also check in JSON string values
    if body.contains("eyJ") {
        for part in body.split("eyJ") {
            if part.is_empty() {
                continue;
            }
            // Try to reconstruct the token
            let candidate = format!("eyJ{}", part.split('"').next().unwrap_or(""));
            if is_jwt(&candidate) && !tokens.contains(&candidate) {
                tokens.push(candidate);
            }
        }
    }

    tokens.truncate(5);
    tokens
}

/// Analyze a JWT token for security issues.
fn analyze_jwt(token: &str, source: &str, url: &str, findings: &mut Vec<Finding>) {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return;
    }

    // Decode header
    let header_json = match decode_base64url(parts[0]) {
        Some(json) => json,
        None => return,
    };

    let header: serde_json::Value = match serde_json::from_str(&header_json) {
        Ok(v) => v,
        Err(_) => return,
    };

    let alg = header["alg"].as_str().unwrap_or("unknown");

    // Check for "none" algorithm
    if alg.eq_ignore_ascii_case("none") {
        findings.push(
            Finding::new(
                "jwt",
                Severity::Critical,
                "JWT Using 'none' Algorithm",
                format!(
                    "A JWT from {source} uses the 'none' algorithm. This means the token \
                     has no signature verification and can be freely forged by anyone."
                ),
                url,
            )
            .with_evidence(format!("Source: {source} | Algorithm: {alg}"))
            .with_remediation("Never allow the 'none' algorithm. Enforce HS256, RS256, or ES256.")
            .with_owasp("A02:2021 Cryptographic Failures")
            .with_cwe(327),
        );
    }

    // Check for weak algorithms
    if alg == "HS256" || alg == "HS384" || alg == "HS512" {
        findings.push(
            Finding::new(
                "jwt",
                Severity::Info,
                format!("JWT Using Symmetric Algorithm: {alg}"),
                format!(
                    "A JWT from {source} uses symmetric algorithm {alg}. If the signing \
                     secret is weak or leaked, tokens can be forged."
                ),
                url,
            )
            .with_evidence(format!("Source: {source} | Algorithm: {alg}"))
            .with_owasp("A02:2021 Cryptographic Failures"),
        );
    }

    // Decode payload
    if let Some(payload_json) = decode_base64url(parts[1]) {
        if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&payload_json) {
            // Check for sensitive data in payload
            check_sensitive_claims(&payload, source, url, findings);

            // Check expiration
            check_jwt_expiry(&payload, source, url, findings);
        }
    }

    // Check for empty signature
    if parts[2].is_empty() {
        findings.push(
            Finding::new(
                "jwt",
                Severity::High,
                "JWT Has Empty Signature",
                format!(
                    "A JWT from {source} has an empty signature. The token integrity \
                     cannot be verified."
                ),
                url,
            )
            .with_evidence(format!("Source: {source} | Signature segment is empty"))
            .with_remediation("Ensure all JWTs are properly signed")
            .with_owasp("A02:2021 Cryptographic Failures")
            .with_cwe(345),
        );
    }
}

fn check_sensitive_claims(
    payload: &serde_json::Value,
    source: &str,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    let sensitive_keys = [
        "password",
        "pwd",
        "secret",
        "ssn",
        "credit_card",
        "cc",
        "api_key",
        "apikey",
        "private_key",
    ];

    if let Some(obj) = payload.as_object() {
        for key in obj.keys() {
            let lower = key.to_lowercase();
            if sensitive_keys.iter().any(|s| lower.contains(s)) {
                findings.push(
                    Finding::new(
                        "jwt",
                        Severity::High,
                        "Sensitive Data in JWT Payload",
                        format!(
                            "JWT from {source} contains potentially sensitive claim: '{key}'. \
                             JWT payloads are base64-encoded (not encrypted) and readable by anyone."
                        ),
                        url,
                    )
                    .with_evidence(format!("Source: {source} | Claim: {key}"))
                    .with_remediation("Never store sensitive data in JWT payloads. Use encrypted tokens (JWE) or store in server-side sessions.")
                    .with_owasp("A02:2021 Cryptographic Failures")
                    .with_cwe(312),
                );
                break;
            }
        }
    }
}

fn check_jwt_expiry(
    payload: &serde_json::Value,
    source: &str,
    url: &str,
    findings: &mut Vec<Finding>,
) {
    // Check for missing exp claim
    if payload.get("exp").is_none() {
        findings.push(
            Finding::new(
                "jwt",
                Severity::Medium,
                "JWT Missing Expiration Claim",
                format!(
                    "JWT from {source} has no 'exp' (expiration) claim. The token never \
                     expires and could be used indefinitely if stolen."
                ),
                url,
            )
            .with_evidence(format!("Source: {source} | No 'exp' claim"))
            .with_remediation(
                "Always include an 'exp' claim in JWTs with a reasonable expiration time",
            )
            .with_owasp("A07:2021 Identification and Authentication Failures")
            .with_cwe(613),
        );
    } else if let Some(exp) = payload["exp"].as_i64() {
        let now = chrono::Utc::now().timestamp();
        let hours_until = (exp - now) / 3600;

        if hours_until > 24 * 30 {
            findings.push(
                Finding::new(
                    "jwt",
                    Severity::Low,
                    "JWT Has Long Expiration",
                    format!(
                        "JWT from {source} expires in ~{} days. Long-lived tokens \
                         increase the window for stolen token abuse.",
                        hours_until / 24
                    ),
                    url,
                )
                .with_evidence(format!("Source: {source} | Expires in ~{} days", hours_until / 24))
                .with_remediation(
                    "Use short-lived tokens (15 minutes to 1 hour) with refresh tokens",
                )
                .with_owasp("A07:2021 Identification and Authentication Failures"),
            );
        }
    }
}

fn decode_base64url(input: &str) -> Option<String> {
    use base64::Engine;
    let padded = match input.len() % 4 {
        2 => format!("{input}=="),
        3 => format!("{input}="),
        _ => input.to_string(),
    };
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(padded.trim_end_matches('='))
        .ok()?;
    String::from_utf8(decoded).ok()
}
