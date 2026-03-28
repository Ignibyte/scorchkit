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
                    Finding::new("csrf", Severity::Medium, format!("Missing CSRF Token: {form_desc}"), format!("A POST form lacks CSRF token protection. An attacker could craft a page that submits this form on behalf of an authenticated user."), url)
                        .with_evidence(format!("Form: method=POST action=\"{action}\" | No hidden CSRF token field found"))
                        .with_remediation("Add a CSRF token to all state-changing forms. Use your framework's built-in CSRF protection.")
                        .with_owasp("A05:2021 Security Misconfiguration")
                        .with_cwe(352),
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
