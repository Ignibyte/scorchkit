//! Server-side template injection (SSTI) scanner module.
//!
//! Detects SSTI vulnerabilities across multiple template engines by injecting
//! mathematical expression payloads and engine-specific probes, then checking
//! responses for computed results or engine fingerprints.

use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects server-side template injection across multiple template engines.
#[derive(Debug)]
pub struct SstiModule;

#[async_trait]
impl ScanModule for SstiModule {
    fn name(&self) -> &'static str {
        "SSTI Detection"
    }

    fn id(&self) -> &'static str {
        "ssti"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect server-side template injection across multiple template engines"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // 1. Test any parameters already in the target URL
        test_url_params_ssti(ctx, url, &mut findings).await?;

        // 2. Spider the page for links with parameters and forms
        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let body = response.text().await.unwrap_or_default();

        let links = extract_parameterized_links(&body, &ctx.target.url);
        for link in &links {
            test_url_params_ssti(ctx, link, &mut findings).await?;
        }

        let forms = extract_forms(&body, &ctx.target.url);
        for form in &forms {
            test_form_ssti(ctx, form, &mut findings).await?;
        }

        // 3. Test injection via headers (User-Agent, Referer)
        test_header_ssti(ctx, url, &mut findings).await?;

        Ok(findings)
    }
}

/// An SSTI payload with expected output and engine identification.
#[derive(Debug)]
struct SstiPayload {
    /// The injection payload string.
    payload: &'static str,
    /// The expected computed output in the response.
    expected_output: &'static str,
    /// The template engine this payload targets.
    engine: &'static str,
}

/// SSTI payloads covering polyglot expressions and engine-specific probes.
///
/// All payloads use safe mathematical expressions — no RCE payloads.
const SSTI_PAYLOADS: &[SstiPayload] = &[
    // Polyglot — works across multiple engines
    SstiPayload { payload: "{{7*7}}", expected_output: "49", engine: "Jinja2/Twig" },
    SstiPayload { payload: "${7*7}", expected_output: "49", engine: "Freemarker/Mako" },
    SstiPayload { payload: "<%= 7*7 %>", expected_output: "49", engine: "ERB" },
    SstiPayload { payload: "#{7*7}", expected_output: "49", engine: "Pebble/Ruby" },
    // Jinja2-specific: string repetition produces "7777777" not "49"
    SstiPayload { payload: "{{7*'7'}}", expected_output: "7777777", engine: "Jinja2" },
    // Twig-specific
    SstiPayload { payload: "{{4*4}}{{7*7}}", expected_output: "1649", engine: "Twig/Jinja2" },
    // Freemarker-specific
    SstiPayload { payload: "${3+4}", expected_output: "7", engine: "Freemarker" },
    // Velocity-specific
    SstiPayload { payload: "#set($x=7*7)${x}", expected_output: "49", engine: "Velocity" },
    // Smarty — safe math payload (NOT {php} which is RCE)
    SstiPayload { payload: "{math equation=\"7*7\"}", expected_output: "49", engine: "Smarty" },
    // Mako-specific
    SstiPayload { payload: "${7*7}", expected_output: "49", engine: "Mako" },
];

/// Engine fingerprints found in error messages or specific responses.
const ENGINE_INDICATORS: &[(&str, &str)] = &[
    ("jinja2.exceptions", "Jinja2"),
    ("jinja2", "Jinja2"),
    ("twig_error", "Twig"),
    ("twig\\error", "Twig"),
    ("twig/error", "Twig"),
    ("freemarker.core", "Freemarker"),
    ("freemarker.template", "Freemarker"),
    ("velocity", "Velocity"),
    ("org.apache.velocity", "Velocity"),
    ("smarty_internal", "Smarty"),
    ("smarty/", "Smarty"),
    ("mako.exceptions", "Mako"),
    ("mako.lookup", "Mako"),
    ("pebble", "Pebble"),
    ("com.mitchellbosecke.pebble", "Pebble"),
    ("erb", "ERB"),
    ("eruby", "ERB"),
    ("templateerror", "Unknown Template Engine"),
    ("template error", "Unknown Template Engine"),
    ("template syntax error", "Unknown Template Engine"),
];

/// Check a response body for SSTI computed output with boundary awareness.
///
/// Returns `true` if `expected_output` appears in the body at a word boundary,
/// reducing false positives from CSS values, pixel sizes, or unrelated numbers.
fn check_ssti_response(body: &str, expected_output: &str) -> bool {
    // Find each occurrence and verify it has non-alphanumeric boundaries
    let search = expected_output;
    let chars: Vec<char> = body.chars().collect();
    let search_chars: Vec<char> = search.chars().collect();

    if search_chars.is_empty() {
        return false;
    }

    let mut start = 0;
    while start + search_chars.len() <= chars.len() {
        if let Some(pos) = body[start..].find(search) {
            let abs_pos = start + pos;
            let end_pos = abs_pos + search.len();

            // Check left boundary: start of string or non-alphanumeric
            let left_ok = abs_pos == 0 || !chars[abs_pos - 1].is_alphanumeric();

            // Check right boundary: end of string or non-alphanumeric
            let right_ok = end_pos >= chars.len() || !chars[end_pos].is_alphanumeric();

            if left_ok && right_ok {
                return true;
            }

            start = abs_pos + 1;
        } else {
            break;
        }
    }

    false
}

/// Identify a template engine from error messages in a response body.
///
/// Returns the engine name if a known fingerprint is found.
fn identify_template_engine(body: &str) -> Option<&'static str> {
    let lower = body.to_lowercase();
    for &(pattern, engine) in ENGINE_INDICATORS {
        if lower.contains(pattern) {
            return Some(engine);
        }
    }
    None
}

/// Test URL query parameters for SSTI.
async fn test_url_params_ssti(
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

    for (param_name, _) in &params {
        for ssti in SSTI_PAYLOADS {
            let mut test_url = parsed.clone();
            {
                let mut query_pairs = test_url.query_pairs_mut();
                query_pairs.clear();
                for (k, v) in &params {
                    if k == param_name {
                        query_pairs.append_pair(k, ssti.payload);
                    } else {
                        query_pairs.append_pair(k, v);
                    }
                }
            }

            let Ok(response) = ctx.http_client.get(test_url.as_str()).send().await else {
                continue;
            };

            let resp_body = response.text().await.unwrap_or_default();

            if check_ssti_response(&resp_body, ssti.expected_output) {
                let engine = identify_template_engine(&resp_body).unwrap_or(ssti.engine);

                findings.push(build_ssti_finding(
                    param_name,
                    ssti,
                    engine,
                    url_str,
                    "query parameter",
                ));
                // One finding per parameter is sufficient
                break;
            }

            // Also check for engine errors (even without computed output)
            if let Some(engine) = identify_template_engine(&resp_body) {
                findings.push(build_ssti_error_finding(
                    param_name,
                    ssti,
                    engine,
                    url_str,
                    "query parameter",
                ));
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

/// Test form fields for SSTI.
async fn test_form_ssti(
    ctx: &ScanContext,
    form: &FormInfo,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    for (input_name, _) in &form.inputs {
        // Test a subset of payloads per form field
        for ssti in &SSTI_PAYLOADS[..4] {
            let mut params: Vec<(&str, String)> = Vec::new();
            for (name, val) in &form.inputs {
                if name == input_name {
                    params.push((name, ssti.payload.to_string()));
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

            if check_ssti_response(&resp_body, ssti.expected_output) {
                let engine = identify_template_engine(&resp_body).unwrap_or(ssti.engine);

                findings.push(build_ssti_finding(
                    input_name,
                    ssti,
                    engine,
                    &form.action,
                    "form field",
                ));
                return Ok(());
            }
        }
    }

    Ok(())
}

/// Test SSTI via HTTP headers (User-Agent, Referer).
async fn test_header_ssti(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let headers_to_test = &[("User-Agent", "User-Agent header"), ("Referer", "Referer header")];

    for &(header_name, header_desc) in headers_to_test {
        // Use the primary polyglot payload
        let ssti = &SSTI_PAYLOADS[0]; // {{7*7}}

        let Ok(response) =
            ctx.http_client.get(url_str).header(header_name, ssti.payload).send().await
        else {
            continue;
        };

        let resp_body = response.text().await.unwrap_or_default();

        if check_ssti_response(&resp_body, ssti.expected_output) {
            let engine = identify_template_engine(&resp_body).unwrap_or(ssti.engine);

            findings.push(
                Finding::new(
                    "ssti",
                    Severity::Critical,
                    format!("SSTI ({engine}): via {header_desc}"),
                    format!(
                        "The {header_desc} is vulnerable to server-side template injection. \
                         The template expression `{payload}` was evaluated by the {engine} \
                         engine, producing `{expected}` in the response.",
                        payload = ssti.payload,
                        expected = ssti.expected_output,
                    ),
                    url_str,
                )
                .with_evidence(format!(
                    "Header: {header_name}: {payload} | Expected: {expected} | Engine: {engine}",
                    payload = ssti.payload,
                    expected = ssti.expected_output,
                ))
                .with_remediation(
                    "Never pass user-controlled input into template expressions. \
                     Use sandboxed template engines. Separate template logic from user data.",
                )
                .with_owasp("A03:2021 Injection")
                .with_cwe(1336)
                .with_confidence(0.8),
            );
        }
    }

    Ok(())
}

/// Build a finding for confirmed SSTI (computed output matched).
fn build_ssti_finding(
    param_name: &str,
    ssti: &SstiPayload,
    engine: &str,
    url_str: &str,
    injection_point: &str,
) -> Finding {
    Finding::new(
        "ssti",
        Severity::Critical,
        format!("SSTI ({engine}): via {injection_point} `{param_name}`"),
        format!(
            "The {injection_point} `{param_name}` is vulnerable to server-side template \
             injection. The template expression `{payload}` was evaluated by the {engine} \
             engine, producing `{expected}` in the response. SSTI can lead to remote \
             code execution.",
            payload = ssti.payload,
            expected = ssti.expected_output,
        ),
        url_str,
    )
    .with_evidence(format!(
        "Payload: {payload} | Parameter: {param_name} | \
         Expected: {expected} | Engine: {engine}",
        payload = ssti.payload,
        expected = ssti.expected_output,
    ))
    .with_remediation(
        "Never pass user-controlled input into template expressions. \
         Use sandboxed template engines. Separate template logic from user data.",
    )
    .with_owasp("A03:2021 Injection")
    .with_cwe(1336)
    .with_confidence(0.8)
}

/// Build a finding for SSTI error detection (engine error triggered but no computed output).
fn build_ssti_error_finding(
    param_name: &str,
    ssti: &SstiPayload,
    engine: &str,
    url_str: &str,
    injection_point: &str,
) -> Finding {
    Finding::new(
        "ssti",
        Severity::High,
        format!("Potential SSTI ({engine}): template error via {injection_point} `{param_name}`"),
        format!(
            "The {injection_point} `{param_name}` triggered a {engine} template engine \
             error when injected with `{payload}`. This strongly suggests the input is \
             being processed by a template engine and may be exploitable.",
            payload = ssti.payload,
        ),
        url_str,
    )
    .with_evidence(format!(
        "Payload: {payload} | Parameter: {param_name} | Engine: {engine} (detected from error)",
        payload = ssti.payload,
    ))
    .with_remediation(
        "Never pass user-controlled input into template expressions. \
         Use sandboxed template engines. Separate template logic from user data.",
    )
    .with_owasp("A03:2021 Injection")
    .with_cwe(1336)
    .with_confidence(0.8)
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

    /// Tests for the SSTI scanner module's pure helper functions and constant
    /// data integrity.

    /// Verify that the module metadata returns correct values for id, name,
    /// category, and description.
    #[test]
    fn test_module_metadata_ssti() {
        let module = SstiModule;

        assert_eq!(module.id(), "ssti");
        assert_eq!(module.name(), "SSTI Detection");
        assert_eq!(module.category(), ModuleCategory::Scanner);
        assert!(!module.description().is_empty());
        assert!(!module.requires_external_tool());
    }

    /// Verify that the SSTI payload database is non-empty and all entries have
    /// non-empty fields.
    #[test]
    fn test_ssti_payloads_not_empty() {
        assert!(!SSTI_PAYLOADS.is_empty(), "payload database must not be empty");

        for (i, payload) in SSTI_PAYLOADS.iter().enumerate() {
            assert!(!payload.payload.is_empty(), "payload {i} has empty payload string");
            assert!(!payload.expected_output.is_empty(), "payload {i} has empty expected_output");
            assert!(!payload.engine.is_empty(), "payload {i} has empty engine");
        }
    }

    /// Verify that `check_ssti_response` detects computed results with boundary
    /// awareness — `49` preceded by non-alphanumeric context should match.
    #[test]
    fn test_check_ssti_computed_result() {
        // Should match: result at boundary
        assert!(
            check_ssti_response("Result: 49 found", "49"),
            "should match '49' with space boundaries"
        );
        assert!(check_ssti_response("<p>49</p>", "49"), "should match '49' inside HTML tags");
        assert!(
            check_ssti_response("value=49&next", "49"),
            "should match '49' at URL param boundary"
        );

        // Should NOT match: embedded in larger numbers
        assert!(
            !check_ssti_response("page490results", "49"),
            "should NOT match '49' embedded in alphanumeric string"
        );
        assert!(!check_ssti_response("item1490", "49"), "should NOT match '49' preceded by digit");
    }

    /// Verify that `check_ssti_response` detects the Jinja2-specific string
    /// repetition output `7777777`.
    #[test]
    fn test_check_ssti_jinja2_specific() {
        assert!(
            check_ssti_response("output: 7777777 end", "7777777"),
            "should match Jinja2 string repetition output"
        );
        assert!(
            check_ssti_response("<div>7777777</div>", "7777777"),
            "should match 7777777 in HTML"
        );
    }

    /// Verify that `check_ssti_response` returns `false` for normal HTML
    /// content without computed template output.
    #[test]
    fn test_check_ssti_negative() {
        let body = "<html><body><h1>Welcome</h1><p>Normal page content.</p></body></html>";

        assert!(!check_ssti_response(body, "49"), "should not match normal HTML");
        assert!(
            !check_ssti_response(body, "7777777"),
            "should not match normal HTML for Jinja2 probe"
        );
    }

    /// Verify that `identify_template_engine` correctly identifies engines from
    /// error messages in response bodies.
    #[test]
    fn test_identify_template_engine() {
        // Jinja2
        assert_eq!(
            identify_template_engine("jinja2.exceptions.UndefinedError: 'foo' is undefined"),
            Some("Jinja2")
        );

        // Freemarker
        assert_eq!(
            identify_template_engine("freemarker.core.InvalidReferenceException"),
            Some("Freemarker")
        );

        // Twig
        assert_eq!(identify_template_engine("Twig_Error_Syntax: Unknown tag"), Some("Twig"));

        // Mako
        assert_eq!(
            identify_template_engine("mako.exceptions.SyntaxException: invalid syntax"),
            Some("Mako")
        );

        // No match
        assert_eq!(identify_template_engine("<html><body>Normal page</body></html>"), None);
    }

    /// Verify that the polyglot payloads cover all the listed template engines:
    /// Jinja2, Twig, Freemarker, ERB, Mako, Velocity, Smarty, Pebble.
    #[test]
    fn test_ssti_polyglot_coverage() {
        let engines: Vec<&str> = SSTI_PAYLOADS.iter().map(|p| p.engine).collect();

        let required =
            ["Jinja2", "Twig", "Freemarker", "ERB", "Mako", "Velocity", "Smarty", "Pebble"];

        for &engine in &required {
            assert!(
                engines.iter().any(|e| e.contains(engine)),
                "payloads must cover engine: {engine}"
            );
        }
    }
}
