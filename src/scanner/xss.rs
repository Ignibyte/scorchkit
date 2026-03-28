use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects reflected XSS vulnerabilities by injecting canary strings.
#[derive(Debug)]
pub struct XssModule;

#[async_trait]
impl ScanModule for XssModule {
    fn name(&self) -> &'static str {
        "Reflected XSS Detection"
    }

    fn id(&self) -> &'static str {
        "xss"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect reflected cross-site scripting (XSS) via canary injection"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // 1. Test parameters already in the URL
        test_url_params_xss(ctx, url, &mut findings).await?;

        // 2. Spider for links with parameters
        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let body = response.text().await.unwrap_or_default();

        let links = extract_parameterized_links(&body, &ctx.target.url);
        for link in &links {
            test_url_params_xss(ctx, link, &mut findings).await?;
        }

        // 3. Test forms
        let forms = extract_forms(&body, &ctx.target.url);
        for form in &forms {
            test_form_xss(ctx, form, &mut findings).await?;
        }

        Ok(findings)
    }
}

/// Unique canary string unlikely to appear naturally.
const CANARY: &str = "scorch8x7k2";
const CANARY_HTML: &str = "scorch8x7k2<test>\"'";

/// XSS payloads to test if reflection is unescaped.
const XSS_PAYLOADS: &[(&str, &str)] = &[
    ("<scorch8x7k2>", "HTML tag injection"),
    ("\"onmouseover=\"alert(1)", "Event handler injection"),
    ("'onmouseover='alert(1)", "Event handler injection (single quote)"),
    ("<img src=x onerror=alert(1)>", "IMG tag injection"),
    ("<svg/onload=alert(1)>", "SVG injection"),
    ("javascript:alert(1)", "JavaScript URI injection"),
];

/// Test URL parameters for reflected XSS.
async fn test_url_params_xss(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let parsed = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return Ok(()),
    };

    let params: Vec<(String, String)> =
        parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    if params.is_empty() {
        return Ok(());
    }

    for (param_name, _) in &params {
        // Phase 1: Test if the canary is reflected at all
        let mut test_url = parsed.clone();
        {
            let mut query_pairs = test_url.query_pairs_mut();
            query_pairs.clear();
            for (k, v) in &params {
                if k == param_name {
                    query_pairs.append_pair(k, CANARY_HTML);
                } else {
                    query_pairs.append_pair(k, v);
                }
            }
        }

        let response = match ctx.http_client.get(test_url.as_str()).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let body = response.text().await.unwrap_or_default();

        // Check if canary is reflected
        if !body.contains(CANARY) {
            continue; // Parameter value not reflected, skip
        }

        // Check if HTML characters are reflected unescaped
        if body.contains("<test>") || body.contains("\"'") {
            // HTML is not being encoded - test with real payloads
            for &(payload, payload_desc) in XSS_PAYLOADS {
                let mut payload_url = parsed.clone();
                {
                    let mut query_pairs = payload_url.query_pairs_mut();
                    query_pairs.clear();
                    for (k, v) in &params {
                        if k == param_name {
                            query_pairs.append_pair(k, payload);
                        } else {
                            query_pairs.append_pair(k, v);
                        }
                    }
                }

                let resp = match ctx.http_client.get(payload_url.as_str()).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let resp_body = resp.text().await.unwrap_or_default();

                if is_payload_reflected(&resp_body, payload) {
                    findings.push(
                        Finding::new(
                            "xss",
                            Severity::High,
                            format!("Reflected XSS in Parameter: {param_name}"),
                            format!(
                                "The parameter '{param_name}' reflects user input without \
                                 proper encoding. XSS payload was reflected: {payload_desc}."
                            ),
                            url_str,
                        )
                        .with_evidence(format!(
                            "Parameter: {param_name} | Payload: {payload} | Type: {payload_desc}"
                        ))
                        .with_remediation(
                            "Encode all user input before rendering in HTML. \
                             Use context-appropriate encoding (HTML entity, JavaScript, URL).",
                        )
                        .with_owasp("A03:2021 Injection")
                        .with_cwe(79),
                    );
                    // Found confirmed XSS, no need to test more payloads
                    return Ok(());
                }
            }

            // Canary reflected with HTML chars but payloads didn't work exactly
            // Still worth reporting as the reflection is unencoded
            findings.push(
                Finding::new(
                    "xss",
                    Severity::Medium,
                    format!("Unencoded Reflection in Parameter: {param_name}"),
                    format!(
                        "The parameter '{param_name}' reflects HTML metacharacters \
                         without encoding. This may be exploitable for XSS depending \
                         on the reflection context."
                    ),
                    url_str,
                )
                .with_evidence(format!(
                    "Parameter: {param_name} | Canary '{CANARY_HTML}' reflected with HTML chars intact"
                ))
                .with_remediation(
                    "Encode all user input before rendering in HTML output.",
                )
                .with_owasp("A03:2021 Injection")
                .with_cwe(79),
            );
        } else {
            // Canary reflected but HTML is encoded - lower severity
            findings.push(
                Finding::new(
                    "xss",
                    Severity::Info,
                    format!("Parameter Reflection Detected: {param_name}"),
                    format!(
                        "The parameter '{param_name}' reflects user input in the response. \
                         HTML encoding appears to be applied, but context-specific bypasses \
                         may still be possible."
                    ),
                    url_str,
                )
                .with_evidence(format!(
                    "Parameter: {param_name} | Canary reflected but HTML-encoded"
                ))
                .with_owasp("A03:2021 Injection")
                .with_cwe(79),
            );
        }
    }

    Ok(())
}

/// A discovered HTML form.
#[derive(Debug)]
struct FormInfo {
    action: String,
    method: String,
    inputs: Vec<(String, String)>,
}

/// Test form fields for reflected XSS.
async fn test_form_xss(
    ctx: &ScanContext,
    form: &FormInfo,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    for (input_name, default_value) in &form.inputs {
        let injected_value = format!("{default_value}{CANARY_HTML}");

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

        let response = match response {
            Ok(r) => r,
            Err(_) => continue,
        };

        let body = response.text().await.unwrap_or_default();

        if body.contains(CANARY) && (body.contains("<test>") || body.contains("\"'")) {
            findings.push(
                Finding::new(
                    "xss",
                    Severity::High,
                    format!("Reflected XSS in Form Field: {input_name}"),
                    format!(
                        "The form field '{input_name}' at {} reflects HTML metacharacters \
                         without encoding, enabling cross-site scripting.",
                        form.action
                    ),
                    &form.action,
                )
                .with_evidence(format!(
                    "Form: {} {} | Field: {input_name} | Unencoded HTML reflection",
                    form.method, form.action
                ))
                .with_remediation("Encode all user input before rendering in HTML output.")
                .with_owasp("A03:2021 Injection")
                .with_cwe(79),
            );
            return Ok(()); // One finding per form
        }
    }

    Ok(())
}

/// Check if a payload is reflected in the response without encoding.
fn is_payload_reflected(body: &str, payload: &str) -> bool {
    // Direct reflection
    if body.contains(payload) {
        return true;
    }

    // Check for the key dangerous parts of the payload
    if payload.contains('<') && payload.contains('>') {
        // For tag-based payloads, check if the tag made it through
        let tag_content = payload.trim_start_matches('<').split('>').next().unwrap_or("");
        if !tag_content.is_empty() {
            let tag_check = format!("<{tag_content}");
            if body.contains(&tag_check) {
                return true;
            }
        }
    }

    false
}

/// Extract links with query parameters from the page.
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
    links.truncate(15);
    links
}

/// Extract forms from the page.
fn extract_forms(body: &str, base_url: &Url) -> Vec<FormInfo> {
    let document = Html::parse_document(body);
    let mut forms = Vec::new();

    let Ok(form_selector) = Selector::parse("form") else {
        return forms;
    };
    let Ok(input_selector) = Selector::parse("input[name], textarea[name]") else {
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
                || input_type == "hidden"
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
