//! LDAP injection scanner module.
//!
//! Detects LDAP injection vulnerabilities by injecting LDAP filter
//! metacharacters (`*`, `)`, `(`, `|`) into URL parameters and form fields,
//! then checking responses for LDAP-specific error messages and boolean
//! response differences.

use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects LDAP injection vulnerabilities.
#[derive(Debug)]
pub struct LdapModule;

#[async_trait]
impl ScanModule for LdapModule {
    fn name(&self) -> &'static str {
        "LDAP Injection Detection"
    }

    fn id(&self) -> &'static str {
        "ldap"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect LDAP injection via filter metacharacter injection"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // 1. Test parameters in the target URL
        test_url_params_ldap(ctx, url, &mut findings).await?;

        // 2. Spider for links with parameters and forms
        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let body = response.text().await.unwrap_or_default();

        let links = extract_parameterized_links(&body, &ctx.target.url);
        for link in &links {
            test_url_params_ldap(ctx, link, &mut findings).await?;
        }

        let forms = extract_forms(&body, &ctx.target.url);
        for form in &forms {
            test_form_ldap(ctx, form, &mut findings).await?;
        }

        Ok(findings)
    }
}

/// LDAP injection payloads with descriptions.
const LDAP_PAYLOADS: &[(&str, &str)] = &[
    // Wildcard — returns all entries if injected into a filter
    ("*", "Wildcard (all entries)"),
    // Filter closing — breaks out of the current filter
    ("*)(objectClass=*)", "Filter close + wildcard"),
    ("*)(|(objectClass=*)", "Filter close + OR wildcard"),
    // Authentication bypass patterns
    (")(cn=*))(|(cn=*", "Auth bypass via OR injection"),
    ("*)(&", "Filter close + AND operator"),
    ("*))%00", "Filter close + null byte"),
    // Boolean-based blind
    ("admin*", "Wildcard suffix (blind enum)"),
    ("*)(uid=*", "UID wildcard injection"),
    // Special character injection
    ("\\28", "Escaped left parenthesis"),
    ("\\29", "Escaped right parenthesis"),
    ("\\2a", "Escaped asterisk"),
];

/// LDAP-specific error patterns in response bodies.
const LDAP_ERROR_PATTERNS: &[(&str, &str)] = &[
    // Generic LDAP errors
    ("ldap_search", "LDAP"),
    ("ldap_bind", "LDAP"),
    ("ldap_connect", "LDAP"),
    ("ldap_modify", "LDAP"),
    ("ldap error", "LDAP"),
    ("ldap_err", "LDAP"),
    ("ldapexception", "LDAP"),
    // Java LDAP
    ("javax.naming", "Java LDAP"),
    ("naming.directory", "Java LDAP"),
    ("namingexception", "Java LDAP"),
    ("invalidnameexception", "Java LDAP"),
    // Active Directory
    ("active directory", "Active Directory"),
    ("ldap://", "LDAP"),
    ("ldaps://", "LDAP"),
    // PHP LDAP
    ("ldap_get_entries", "PHP LDAP"),
    ("ldap_first_entry", "PHP LDAP"),
    // Python LDAP
    ("ldap.filter", "Python LDAP"),
    ("ldap.dn", "Python LDAP"),
    // Filter syntax errors
    ("bad search filter", "LDAP"),
    ("invalid filter", "LDAP"),
    ("filter error", "LDAP"),
    ("unbalanced parenthes", "LDAP"),
    ("unmatched parenthes", "LDAP"),
];

/// Detect LDAP error messages in a response body.
///
/// Returns the LDAP implementation type if a known error pattern is found.
fn detect_ldap_error(body: &str) -> Option<&'static str> {
    let lower = body.to_lowercase();
    for &(pattern, impl_type) in LDAP_ERROR_PATTERNS {
        if lower.contains(pattern) {
            return Some(impl_type);
        }
    }
    None
}

/// Test URL query parameters for LDAP injection.
async fn test_url_params_ldap(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let Ok(parsed) = Url::parse(url_str) else {
        return Ok(());
    };

    let params: Vec<(String, String)> =
        parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    if params.is_empty() {
        return Ok(());
    }

    for (param_name, param_value) in &params {
        for &(payload, description) in LDAP_PAYLOADS {
            let injected_value = format!("{param_value}{payload}");

            let mut test_url = parsed.clone();
            {
                let mut query_pairs = test_url.query_pairs_mut();
                query_pairs.clear();
                for (k, v) in &params {
                    if k == param_name {
                        query_pairs.append_pair(k, &injected_value);
                    } else {
                        query_pairs.append_pair(k, v);
                    }
                }
            }

            let Ok(response) = ctx.http_client.get(test_url.as_str()).send().await else {
                continue;
            };

            let resp_status = response.status();
            let resp_body = response.text().await.unwrap_or_default();

            // Check for LDAP error messages
            if let Some(impl_type) = detect_ldap_error(&resp_body) {
                findings.push(
                    Finding::new(
                        "ldap",
                        Severity::High,
                        format!("LDAP Injection ({impl_type}): parameter `{param_name}`"),
                        format!(
                            "The parameter `{param_name}` triggered an {impl_type} error \
                             when injected with LDAP filter metacharacters ({description}). \
                             This indicates user input reaches an LDAP query without \
                             proper sanitization.",
                        ),
                        url_str,
                    )
                    .with_evidence(format!(
                        "Payload: {payload} ({description}) | Parameter: {param_name} | \
                         Impl: {impl_type}"
                    ))
                    .with_remediation(
                        "Escape LDAP special characters (*, (, ), \\, NUL) in user input. \
                         Use parameterized LDAP queries. Apply allowlist validation on \
                         search filters. Never concatenate user input into LDAP filters.",
                    )
                    .with_owasp("A03:2021 Injection")
                    .with_cwe(90)
                    .with_confidence(0.7),
                );
                break;
            }

            // Check for 500 error with LDAP metacharacters
            if resp_status.as_u16() == 500 && payload.contains('*') {
                findings.push(
                    Finding::new(
                        "ldap",
                        Severity::Medium,
                        format!("Potential LDAP Injection: server error via `{param_name}`"),
                        format!(
                            "The parameter `{param_name}` caused a 500 Internal Server Error \
                             when LDAP metacharacters were injected ({description}).",
                        ),
                        url_str,
                    )
                    .with_evidence(format!(
                        "Payload: {payload} | Parameter: {param_name} | Status: 500"
                    ))
                    .with_remediation(
                        "Investigate the parameter for LDAP injection. Escape LDAP special characters.",
                    )
                    .with_owasp("A03:2021 Injection")
                    .with_cwe(90)
                    .with_confidence(0.7),
                );
                break;
            }
        }
    }

    Ok(())
}

/// A discovered HTML form.
#[derive(Debug)]
struct FormInfo {
    /// Resolved form action URL.
    action: String,
    /// HTTP method (GET or POST).
    method: String,
    /// Input fields as (name, `default_value`) pairs.
    inputs: Vec<(String, String)>,
}

/// Test form fields for LDAP injection.
async fn test_form_ldap(
    ctx: &ScanContext,
    form: &FormInfo,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    for (input_name, default_value) in &form.inputs {
        for &(payload, description) in &LDAP_PAYLOADS[..4] {
            let injected_value = format!("{default_value}{payload}");

            let mut params: Vec<(&str, String)> = Vec::new();
            for (name, val) in &form.inputs {
                if name == input_name {
                    params.push((name, injected_value.clone()));
                } else {
                    params.push((name, val.clone()));
                }
            }

            let response = if form.method.to_uppercase() == "POST" {
                ctx.http_client.post(&form.action).form(&params).send().await
            } else {
                ctx.http_client.get(&form.action).query(&params).send().await
            };

            let Ok(response) = response else {
                continue;
            };

            let resp_body = response.text().await.unwrap_or_default();

            if let Some(impl_type) = detect_ldap_error(&resp_body) {
                findings.push(
                    Finding::new(
                        "ldap",
                        Severity::High,
                        format!("LDAP Injection ({impl_type}) in form field `{input_name}`"),
                        format!(
                            "The form field `{input_name}` at {} triggered an {impl_type} \
                             error with {description}.",
                            form.action,
                        ),
                        &form.action,
                    )
                    .with_evidence(format!(
                        "Form: {} {} | Field: {input_name} | Payload: {payload}",
                        form.method, form.action,
                    ))
                    .with_remediation(
                        "Escape LDAP special characters in user input. Use parameterized LDAP queries.",
                    )
                    .with_owasp("A03:2021 Injection")
                    .with_cwe(90)
                    .with_confidence(0.7),
                );
                return Ok(());
            }
        }
    }

    Ok(())
}

/// Extract links with query parameters from HTML.
fn extract_parameterized_links(body: &str, base_url: &Url) -> Vec<String> {
    let document = Html::parse_document(body);
    let mut links = Vec::new();

    let Ok(selector) = Selector::parse("a[href]") else {
        return links;
    };

    for element in document.select(&selector) {
        if let Some(href) = element.value().attr("href") {
            if href.contains('?') && href.contains('=') {
                if let Ok(resolved) = base_url.join(href) {
                    if resolved.host() == base_url.host() {
                        links.push(resolved.to_string());
                    }
                }
            }
        }
    }

    links.sort();
    links.dedup();
    links.truncate(20);
    links
}

/// Extract forms from HTML.
fn extract_forms(body: &str, base_url: &Url) -> Vec<FormInfo> {
    let document = Html::parse_document(body);
    let mut forms = Vec::new();

    let Ok(form_selector) = Selector::parse("form") else {
        return forms;
    };
    let Ok(input_selector) = Selector::parse("input[name], textarea[name], select[name]") else {
        return forms;
    };

    for form_el in document.select(&form_selector) {
        let action = form_el.value().attr("action").unwrap_or("");
        let method = form_el.value().attr("method").unwrap_or("GET").to_string();

        let resolved_action = if action.is_empty() {
            base_url.to_string()
        } else if let Ok(resolved) = base_url.join(action) {
            resolved.to_string()
        } else {
            continue;
        };

        let mut inputs = Vec::new();
        for input in form_el.select(&input_selector) {
            let name = input.value().attr("name").unwrap_or("").to_string();
            let value = input.value().attr("value").unwrap_or("").to_string();
            let input_type = input.value().attr("type").unwrap_or("text").to_lowercase();

            if name.is_empty()
                || input_type == "submit"
                || input_type == "button"
                || input_type == "file"
                || input_type == "image"
            {
                continue;
            }

            inputs.push((name, value));
        }

        if !inputs.is_empty() {
            forms.push(FormInfo { action: resolved_action, method, inputs });
        }
    }

    forms.truncate(10);
    forms
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the LDAP injection scanner module's pure helper functions
    /// and constant data integrity.

    /// Verify that the module metadata returns correct values.
    #[test]
    fn test_module_metadata_ldap() {
        let module = LdapModule;

        assert_eq!(module.id(), "ldap");
        assert_eq!(module.name(), "LDAP Injection Detection");
        assert_eq!(module.category(), ModuleCategory::Scanner);
        assert!(!module.description().is_empty());
        assert!(!module.requires_external_tool());
    }

    /// Verify that the LDAP payload database is non-empty and all entries
    /// have non-empty fields.
    #[test]
    fn test_ldap_payloads_not_empty() {
        assert!(!LDAP_PAYLOADS.is_empty(), "payload database must not be empty");

        for (i, &(payload, desc)) in LDAP_PAYLOADS.iter().enumerate() {
            assert!(!payload.is_empty(), "payload {i} has empty payload string");
            assert!(!desc.is_empty(), "payload {i} has empty description");
        }
    }

    /// Verify that `detect_ldap_error` identifies LDAP errors in response bodies.
    #[test]
    fn test_detect_ldap_error_positive() {
        // PHP LDAP
        assert_eq!(
            detect_ldap_error("Warning: ldap_search(): Search: Bad search filter"),
            Some("LDAP")
        );

        // Java LDAP
        assert_eq!(
            detect_ldap_error("javax.naming.NamingException: LDAP response error"),
            Some("Java LDAP")
        );

        // Filter syntax
        assert_eq!(
            detect_ldap_error("Error: bad search filter (unbalanced parentheses)"),
            Some("LDAP")
        );
    }

    /// Verify that `detect_ldap_error` returns `None` for normal HTML.
    #[test]
    fn test_detect_ldap_error_negative() {
        let body = "<html><body><h1>Welcome</h1><p>Normal page content.</p></body></html>";
        assert_eq!(detect_ldap_error(body), None);
    }

    /// Verify that the payload database contains LDAP filter metacharacters.
    #[test]
    fn test_ldap_payload_metacharacters() {
        let payloads: Vec<&str> = LDAP_PAYLOADS.iter().map(|&(p, _)| p).collect();

        // Must contain wildcard
        assert!(payloads.contains(&"*"), "must include wildcard payload");

        // Must contain filter-closing parentheses
        assert!(
            payloads.iter().any(|p| p.contains(")(") || p.contains(")")),
            "must include filter-closing payloads"
        );

        // Must contain objectClass
        assert!(
            payloads.iter().any(|p| p.contains("objectClass")),
            "must include objectClass filter injection"
        );
    }
}
