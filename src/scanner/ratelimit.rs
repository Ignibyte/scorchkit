use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Tests whether authentication endpoints have rate limiting / brute-force protection.
#[derive(Debug)]
pub struct RateLimitModule;

#[async_trait]
impl ScanModule for RateLimitModule {
    fn name(&self) -> &'static str {
        "Rate Limit Testing"
    }
    fn id(&self) -> &'static str {
        "ratelimit"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Test authentication endpoints for brute-force protection"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let base = ctx.target.base_url();
        let mut findings = Vec::new();

        // Find login endpoints
        for path in LOGIN_PATHS {
            let url = format!("{base}{path}");
            let initial = ctx.http_client.get(&url).send().await;

            let initial = match initial {
                Ok(r) if r.status().is_success() || r.status().as_u16() == 302 => r,
                _ => continue,
            };

            let initial_status = initial.status();

            // Found a login endpoint - test rate limiting by sending rapid requests
            let mut blocked = false;
            let mut request_count = 0;

            for _ in 0..10 {
                let resp = ctx
                    .http_client
                    .post(&url)
                    .form(&[("username", "admin"), ("password", "wrong_password_test")])
                    .send()
                    .await;

                if let Ok(r) = resp {
                    request_count += 1;
                    let status = r.status();
                    if status.as_u16() == 429 || status.as_u16() == 403 {
                        blocked = true;
                        break;
                    }
                    // Check for CAPTCHA or lockout indicators
                    let body = r.text().await.unwrap_or_default();
                    let lower = body.to_lowercase();
                    if lower.contains("captcha")
                        || lower.contains("rate limit")
                        || lower.contains("too many")
                        || lower.contains("locked")
                        || lower.contains("try again later")
                    {
                        blocked = true;
                        break;
                    }
                } else {
                    blocked = true;
                    break;
                }
            }

            if !blocked && request_count >= 10 {
                findings.push(
                    Finding::new("ratelimit", Severity::Medium, format!("No Rate Limiting on {path}"), format!("The login endpoint at {path} accepted {request_count} failed login attempts without any rate limiting, CAPTCHA, or account lockout."), &url)
                        .with_evidence(format!("Sent {request_count} POST requests with wrong credentials - all returned HTTP {}", initial_status.as_u16()))
                        .with_remediation("Implement rate limiting, account lockout, or CAPTCHA after 3-5 failed attempts")
                        .with_owasp("A07:2021 Identification and Authentication Failures")
                        .with_cwe(307)
                        .with_confidence(0.6),
                );
            } else if blocked {
                findings.push(
                    Finding::new("ratelimit", Severity::Info, format!("Rate Limiting Active on {path}"), format!("The login endpoint at {path} has brute-force protection (blocked after {request_count} attempts)."), &url)
                        .with_evidence(format!("Blocked after {request_count} failed login attempts"))
                        .with_confidence(0.6),
                );
            }

            break; // Only test the first login endpoint found
        }

        Ok(findings)
    }
}

const LOGIN_PATHS: &[&str] = &[
    "/login",
    "/signin",
    "/auth/login",
    "/user/login",
    "/admin/login",
    "/wp-login.php",
    "/administrator",
    "/api/auth/login",
    "/api/login",
    "/api/v1/auth/login",
    "/account/login",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for the rate limit testing module's constant data integrity.

    /// Verify that `LOGIN_PATHS` is non-empty and contains well-known authentication
    /// endpoint paths.
    #[test]
    fn test_login_paths_nonempty_and_contains_known_endpoints() {
        // Arrange & Assert: minimum count
        assert!(
            LOGIN_PATHS.len() >= 5,
            "Expected at least 5 login paths, found {}",
            LOGIN_PATHS.len()
        );

        // Assert: well-known paths are present
        assert!(LOGIN_PATHS.contains(&"/login"));
        assert!(LOGIN_PATHS.contains(&"/wp-login.php"));
        assert!(LOGIN_PATHS.contains(&"/admin/login"));
    }

    /// Verify that all login paths start with a forward slash, are non-empty,
    /// and contain no whitespace, ensuring well-formed URL path segments.
    #[test]
    fn test_login_paths_are_well_formed() {
        for path in LOGIN_PATHS {
            assert!(!path.is_empty(), "Login paths should not be empty");
            assert!(path.starts_with('/'), "Login path '{path}' should start with '/'");
            assert!(!path.contains(' '), "Login path '{path}' should not contain spaces");
        }
    }

    /// Verify that there are no duplicate entries in `LOGIN_PATHS`.
    #[test]
    fn test_login_paths_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for path in LOGIN_PATHS {
            assert!(seen.insert(path), "Duplicate login path found: '{path}'");
        }
    }
}
