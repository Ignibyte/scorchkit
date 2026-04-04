use async_trait::async_trait;
use scraper::{Html, Selector};

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects missing CSRF protection on forms.
#[derive(Debug)]
pub struct CsrfModule;

#[async_trait]
impl ScanModule for CsrfModule {
    fn name(&self) -> &'static str {
        "CSRF Detection"
    }
    fn id(&self) -> &'static str {
        "csrf"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Detect missing CSRF protection on state-changing forms"
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
        let body = response.text().await.unwrap_or_default();

        let document = Html::parse_document(&body);
        let Ok(form_selector) = Selector::parse("form") else { return Ok(findings) };
        let Ok(input_selector) = Selector::parse("input") else { return Ok(findings) };

        for form in document.select(&form_selector) {
            let method = form.value().attr("method").unwrap_or("get").to_lowercase();
            if method != "post" {
                continue;
            }

            let action = form.value().attr("action").unwrap_or("");

            // Check for CSRF token in form inputs
            let has_csrf_token = form.select(&input_selector).any(|input| {
                let name = input.value().attr("name").unwrap_or("").to_lowercase();
                let input_type = input.value().attr("type").unwrap_or("").to_lowercase();
                input_type == "hidden" && CSRF_TOKEN_NAMES.iter().any(|t| name.contains(t))
            });

            // Check for CSRF in meta tags (SPA pattern)
            let Ok(meta_selector) = Selector::parse("meta[name='csrf-token'], meta[name='_token']")
            else {
                continue;
            };
            let has_meta_csrf = document.select(&meta_selector).next().is_some();

            if !has_csrf_token && !has_meta_csrf {
                let form_desc = if action.is_empty() {
                    format!("POST form on {url}")
                } else {
                    format!("POST form action=\"{action}\"")
                };

                findings.push(
                    Finding::new("csrf", Severity::Medium, format!("Missing CSRF Token: {form_desc}"), "A POST form lacks CSRF token protection. An attacker could craft a page that submits this form on behalf of an authenticated user.".to_string(), url)
                        .with_evidence(format!("Form: method=POST action=\"{action}\" | No hidden CSRF token field found"))
                        .with_remediation("Add a CSRF token to all state-changing forms. Use your framework's built-in CSRF protection.")
                        .with_owasp("A05:2021 Security Misconfiguration")
                        .with_cwe(352)
                        .with_confidence(0.7),
                );
            }
        }

        Ok(findings)
    }
}

const CSRF_TOKEN_NAMES: &[&str] = &[
    "csrf",
    "xsrf",
    "_token",
    "token",
    "authenticity_token",
    "csrfmiddlewaretoken",
    "__requestverificationtoken",
    "antiforgery",
    "nonce",
    "_csrf",
    "csrf_token",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for the CSRF detection module's constant data integrity.

    /// Verify that `CSRF_TOKEN_NAMES` is non-empty and contains well-known CSRF token names.
    #[test]
    fn test_csrf_token_names_nonempty() {
        assert!(
            CSRF_TOKEN_NAMES.len() >= 5,
            "Expected at least 5 CSRF token names, found {}",
            CSRF_TOKEN_NAMES.len()
        );
        // Verify well-known names are present
        assert!(CSRF_TOKEN_NAMES.contains(&"csrf"));
        assert!(CSRF_TOKEN_NAMES.contains(&"_token"));
        assert!(CSRF_TOKEN_NAMES.contains(&"authenticity_token"));
    }

    /// Verify that all CSRF token names are lowercase and contain no whitespace,
    /// since the detection logic lowercases the input name before matching.
    #[test]
    fn test_csrf_token_names_are_lowercase_and_valid() {
        for name in CSRF_TOKEN_NAMES {
            assert_eq!(*name, name.to_lowercase(), "Token name '{name}' should be lowercase");
            assert!(!name.contains(' '), "Token name '{name}' should not contain spaces");
            assert!(!name.is_empty(), "Token names should not be empty");
        }
    }

    /// Verify that a POST form containing a hidden CSRF input is correctly recognized
    /// by the token-name matching logic used in the module.
    #[test]
    fn test_csrf_token_name_matching() {
        // Simulate the matching logic from the module's run() method:
        // input_type == "hidden" && CSRF_TOKEN_NAMES.iter().any(|t| name.contains(t))
        let test_cases = vec![
            ("csrf_token", true),
            ("_token", true),
            ("csrfmiddlewaretoken", true),
            ("username", false),
            ("submit", false),
        ];

        for (input_name, expected) in test_cases {
            let lower = input_name.to_lowercase();
            let matches = CSRF_TOKEN_NAMES.iter().any(|t| lower.contains(t));
            assert_eq!(
                matches,
                expected,
                "Input name '{input_name}' should{} match CSRF token pattern",
                if expected { "" } else { " not" }
            );
        }
    }
}
