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

                match resp {
                    Ok(r) => {
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
                    }
                    Err(_) => {
                        blocked = true;
                        break;
                    }
                }
            }

            if !blocked && request_count >= 10 {
                findings.push(
                    Finding::new("ratelimit", Severity::Medium, format!("No Rate Limiting on {path}"), format!("The login endpoint at {path} accepted {request_count} failed login attempts without any rate limiting, CAPTCHA, or account lockout."), &url)
                        .with_evidence(format!("Sent {request_count} POST requests with wrong credentials - all returned HTTP {}", initial_status.as_u16()))
                        .with_remediation("Implement rate limiting, account lockout, or CAPTCHA after 3-5 failed attempts")
                        .with_owasp("A07:2021 Identification and Authentication Failures")
                        .with_cwe(307),
                );
            } else if blocked {
                findings.push(
                    Finding::new("ratelimit", Severity::Info, format!("Rate Limiting Active on {path}"), format!("The login endpoint at {path} has brute-force protection (blocked after {request_count} attempts)."), &url)
                        .with_evidence(format!("Blocked after {request_count} failed login attempts")),
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
