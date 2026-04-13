//! `NoSQL` injection scanner module.
//!
//! Detects `NoSQL` injection vulnerabilities by injecting `MongoDB` operator
//! payloads (`$gt`, `$ne`, `$regex`, `$where`) into URL parameters and JSON
//! bodies, then checking responses for database error messages and boolean
//! response differences.

use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects `NoSQL` injection vulnerabilities (`MongoDB`, `CouchDB`).
#[derive(Debug)]
pub struct NosqlModule;

#[async_trait]
impl ScanModule for NosqlModule {
    fn name(&self) -> &'static str {
        "NoSQL Injection Detection"
    }

    fn id(&self) -> &'static str {
        "nosql"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect NoSQL injection via MongoDB operator and JSON body injection"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // 1. Test parameters in the target URL
        test_url_params_nosql(ctx, url, &mut findings).await?;

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
            test_url_params_nosql(ctx, link, &mut findings).await?;
        }

        let forms = extract_forms(&body, &ctx.target.url);
        for form in &forms {
            test_form_nosql(ctx, form, &mut findings).await?;
        }

        // 3. Test JSON body injection on the target URL
        test_json_body_nosql(ctx, url, &mut findings).await?;

        Ok(findings)
    }
}

/// `NoSQL` injection payloads for query parameter injection.
const NOSQL_PAYLOADS: &[(&str, &str)] = &[
    // MongoDB operator injection via query params
    ("{\"$gt\":\"\"}", "MongoDB $gt operator"),
    ("{\"$ne\":\"\"}", "MongoDB $ne operator"),
    ("{\"$regex\":\".*\"}", "MongoDB $regex operator"),
    ("{\"$exists\":true}", "MongoDB $exists operator"),
    // Operator injection via bracket notation (PHP/Express style)
    ("[$gt]=", "Bracket notation $gt"),
    ("[$ne]=", "Bracket notation $ne"),
    ("[$regex]=.*", "Bracket notation $regex"),
    // JavaScript injection in $where
    ("';return true;//", "JavaScript $where injection"),
    ("1;sleep(1000)", "JavaScript $where sleep"),
    // Boolean-based blind
    ("' || '1'=='1", "Boolean true (string)"),
    ("' && '1'=='2", "Boolean false (string)"),
    // CouchDB-style
    ("_all_docs", "CouchDB _all_docs"),
];

/// `NoSQL` error patterns and their database types.
const NOSQL_ERROR_PATTERNS: &[(&str, &str)] = &[
    // MongoDB
    ("mongoerror", "MongoDB"),
    ("mongo.error", "MongoDB"),
    ("mongoclient", "MongoDB"),
    ("bsonobj", "MongoDB"),
    ("bson", "MongoDB"),
    ("$where", "MongoDB"),
    ("mongodb", "MongoDB"),
    ("mongoose", "MongoDB"),
    ("mongocursor", "MongoDB"),
    // CouchDB
    ("couchdb", "CouchDB"),
    ("couchbase", "CouchDB"),
    ("_design/", "CouchDB"),
    // Cassandra
    ("cassandra", "Cassandra"),
    ("cqlexception", "Cassandra"),
    // Redis
    ("redis.exception", "Redis"),
    ("rediserror", "Redis"),
    // Generic NoSQL
    ("nosql", "NoSQL"),
    ("json parse error", "NoSQL"),
    ("unexpected token", "NoSQL"),
    ("syntaxerror: unexpected", "NoSQL"),
];

/// Detect `NoSQL` error messages in a response body.
///
/// Returns the database type if a known error pattern is found.
fn detect_nosql_error(body: &str) -> Option<&'static str> {
    let lower = body.to_lowercase();
    for &(pattern, db_type) in NOSQL_ERROR_PATTERNS {
        if lower.contains(pattern) {
            return Some(db_type);
        }
    }
    None
}

/// Analyze a `NoSQL` injection response for error indicators, status codes, and size anomalies.
fn analyze_nosql_response(
    resp_body: &str,
    resp_status: reqwest::StatusCode,
    baseline_len: usize,
    param_name: &str,
    payload: &str,
    description: &str,
    url_str: &str,
) -> Option<Finding> {
    // Check for NoSQL error messages
    if let Some(db_type) = detect_nosql_error(resp_body) {
        return Some(
            Finding::new(
                "nosql",
                Severity::High,
                format!("NoSQL Injection ({db_type}): parameter `{param_name}`"),
                format!(
                    "The parameter `{param_name}` triggered a {db_type} error \
                     when injected with NoSQL operator payload. This indicates \
                     user input reaches a NoSQL query without sanitization.",
                ),
                url_str,
            )
            .with_evidence(format!(
                "Payload: {payload} ({description}) | Parameter: {param_name} | DB: {db_type}"
            ))
            .with_remediation(
                "Sanitize user input before NoSQL queries. Use parameterized queries \
                 or an ODM that escapes operators. Reject JSON operators ($gt, $ne, etc.) \
                 in user input. Validate input types strictly.",
            )
            .with_owasp("A03:2021 Injection")
            .with_cwe(943)
            .with_confidence(0.7),
        );
    }

    // Check for 500 error (blind detection)
    if resp_status.as_u16() == 500 && payload.contains('$') {
        return Some(
            Finding::new(
                "nosql",
                Severity::Medium,
                format!("Potential NoSQL Injection: server error via `{param_name}`"),
                format!(
                    "The parameter `{param_name}` caused a 500 Internal Server Error \
                     when a NoSQL operator payload was injected ({description}). \
                     This suggests the input may reach a NoSQL query.",
                ),
                url_str,
            )
            .with_evidence(format!("Payload: {payload} | Parameter: {param_name} | Status: 500"))
            .with_remediation(
                "Investigate the parameter for NoSQL injection. Use parameterized queries.",
            )
            .with_owasp("A03:2021 Injection")
            .with_cwe(943)
            .with_confidence(0.7),
        );
    }

    // Check for significant response size difference (boolean-based blind)
    let resp_len = resp_body.len();
    // JUSTIFICATION: scanner math on small bounded values; precision loss is negligible
    #[allow(clippy::cast_precision_loss)]
    let len_diff = if baseline_len > 0 {
        ((resp_len as f64 - baseline_len as f64) / baseline_len as f64).abs()
    } else {
        0.0
    };

    if len_diff > 0.5 && payload.contains("||") {
        return Some(
            Finding::new(
                "nosql",
                Severity::Medium,
                format!("Possible Blind NoSQL Injection: `{param_name}`"),
                format!(
                    "The parameter `{param_name}` shows a {diff:.0}% response size \
                     difference when NoSQL boolean logic is injected.",
                    diff = len_diff * 100.0,
                ),
                url_str,
            )
            .with_evidence(format!(
                "Payload: {payload} | Baseline: {baseline_len} | Injected: {resp_len}"
            ))
            .with_remediation("Investigate with NoSQL-specific tools. Sanitize all query inputs.")
            .with_owasp("A03:2021 Injection")
            .with_cwe(943)
            .with_confidence(0.7),
        );
    }

    None
}

/// Test URL query parameters for `NoSQL` injection.
async fn test_url_params_nosql(
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

    // Get baseline
    let Ok(baseline) = ctx.http_client.get(url_str).send().await else {
        return Ok(());
    };
    let baseline_body = baseline.text().await.unwrap_or_default();
    let baseline_len = baseline_body.len();

    for (param_name, param_value) in &params {
        for &(payload, description) in NOSQL_PAYLOADS {
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

            if let Some(finding) = analyze_nosql_response(
                &resp_body,
                resp_status,
                baseline_len,
                param_name,
                payload,
                description,
                url_str,
            ) {
                findings.push(finding);
                break;
            }
        }
    }

    Ok(())
}

/// Test JSON body injection for `NoSQL` operators.
async fn test_json_body_nosql(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let json_payloads = [
        ("{\"username\":{\"$ne\":\"\"},\"password\":{\"$ne\":\"\"}}", "Auth bypass via $ne"),
        ("{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}", "Auth bypass via $gt"),
        (
            "{\"username\":{\"$regex\":\".*\"},\"password\":{\"$regex\":\".*\"}}",
            "Auth bypass via $regex",
        ),
    ];

    for &(payload, description) in &json_payloads {
        let Ok(response) = ctx
            .http_client
            .post(url_str)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await
        else {
            continue;
        };

        let resp_body = response.text().await.unwrap_or_default();

        if let Some(db_type) = detect_nosql_error(&resp_body) {
            findings.push(
                Finding::new(
                    "nosql",
                    Severity::Critical,
                    format!("NoSQL Injection ({db_type}): JSON body"),
                    format!(
                        "The endpoint accepts JSON body with NoSQL operators. \
                         A {db_type} error was triggered using {description}. \
                         This may allow authentication bypass or data extraction.",
                    ),
                    url_str,
                )
                .with_evidence(format!("Payload: {payload} | DB: {db_type}"))
                .with_remediation(
                    "Reject JSON objects containing MongoDB operators ($gt, $ne, $regex, etc.) \
                     in request bodies. Use schema validation on API inputs.",
                )
                .with_owasp("A03:2021 Injection")
                .with_cwe(943)
                .with_confidence(0.7),
            );
            return Ok(());
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

/// Test form fields for `NoSQL` injection.
async fn test_form_nosql(
    ctx: &ScanContext,
    form: &FormInfo,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    for (input_name, default_value) in &form.inputs {
        for &(payload, description) in &NOSQL_PAYLOADS[..4] {
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

            if let Some(db_type) = detect_nosql_error(&resp_body) {
                findings.push(
                    Finding::new(
                        "nosql",
                        Severity::High,
                        format!("NoSQL Injection ({db_type}) in form field `{input_name}`"),
                        format!(
                            "The form field `{input_name}` at {} triggered a {db_type} \
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
                        "Sanitize user input before NoSQL queries. Reject JSON operators.",
                    )
                    .with_owasp("A03:2021 Injection")
                    .with_cwe(943)
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

    /// Tests for the NoSQL injection scanner module's pure helper functions
    /// and constant data integrity.

    /// Verify that the module metadata returns correct values.
    #[test]
    fn test_module_metadata_nosql() {
        let module = NosqlModule;

        assert_eq!(module.id(), "nosql");
        assert_eq!(module.name(), "NoSQL Injection Detection");
        assert_eq!(module.category(), ModuleCategory::Scanner);
        assert!(!module.description().is_empty());
        assert!(!module.requires_external_tool());
    }

    /// Verify that the NoSQL payload database is non-empty and all entries
    /// have non-empty fields.
    #[test]
    fn test_nosql_payloads_not_empty() {
        assert!(!NOSQL_PAYLOADS.is_empty(), "payload database must not be empty");

        for (i, &(payload, desc)) in NOSQL_PAYLOADS.iter().enumerate() {
            assert!(!payload.is_empty(), "payload {i} has empty payload string");
            assert!(!desc.is_empty(), "payload {i} has empty description");
        }
    }

    /// Verify that `detect_nosql_error` identifies MongoDB errors in response bodies.
    #[test]
    fn test_detect_nosql_error_mongodb() {
        let body = "Error: MongoError: $where clause has invalid type";
        assert_eq!(detect_nosql_error(body), Some("MongoDB"));

        let body2 = "BSONObj type: invalid";
        assert_eq!(detect_nosql_error(body2), Some("MongoDB"));
    }

    /// Verify that `detect_nosql_error` returns `None` for normal HTML.
    #[test]
    fn test_detect_nosql_error_negative() {
        let body = "<html><body><h1>Welcome</h1><p>Normal page content.</p></body></html>";
        assert_eq!(detect_nosql_error(body), None);
    }

    /// Verify that the error pattern database covers MongoDB and CouchDB.
    #[test]
    fn test_nosql_error_patterns_cover_databases() {
        let db_types: Vec<&str> = NOSQL_ERROR_PATTERNS.iter().map(|&(_, db)| db).collect();

        assert!(db_types.contains(&"MongoDB"), "must cover MongoDB");
        assert!(db_types.contains(&"CouchDB"), "must cover CouchDB");
        assert!(db_types.contains(&"Redis"), "must cover Redis");
    }
}
