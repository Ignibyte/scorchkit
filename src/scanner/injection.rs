use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::api_spec::read_api_spec;
use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects potential SQL injection vulnerabilities via error-based testing.
#[derive(Debug)]
pub struct InjectionModule;

#[async_trait]
impl ScanModule for InjectionModule {
    fn name(&self) -> &'static str {
        "SQL Injection Detection"
    }

    fn id(&self) -> &'static str {
        "injection"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect SQL injection via error-based testing of URL parameters and forms"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // 1. Test any parameters already in the target URL
        test_url_params(ctx, url, &mut findings).await?;

        // 2. Spider the page for forms and links with parameters
        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let body = response.text().await.unwrap_or_default();

        // Extract links with query parameters from the page
        let links = extract_parameterized_links(&body, &ctx.target.url);
        for link in &links {
            test_url_params(ctx, link, &mut findings).await?;
        }

        // Extract form actions and test them
        let forms = extract_forms(&body, &ctx.target.url);
        for form in &forms {
            test_form(ctx, form, &mut findings).await?;
        }

        // Test URLs discovered by the crawler (inter-module sharing)
        let shared_urls = ctx.shared_data.get(crate::engine::shared_data::keys::URLS);
        for shared_url in &shared_urls {
            if shared_url != url && !links.contains(shared_url) {
                test_url_params(ctx, shared_url, &mut findings).await?;
            }
        }

        // WORK-108: consume the published API spec (typically from
        // `tools::vespasian`). For each discovered endpoint with
        // parameters, build a probe URL and run the same SQLi tests
        // we'd run on a crawled URL. No-op when no spec is published.
        if let Some(spec) = read_api_spec(&ctx.shared_data) {
            for endpoint in &spec.endpoints {
                if endpoint.parameters.is_empty() {
                    continue;
                }
                let probe_url = build_probe_url(&endpoint.url, &endpoint.parameters);
                test_url_params(ctx, &probe_url, &mut findings).await?;
            }
        }

        Ok(findings)
    }
}

/// Build a probe URL from an `ApiEndpoint` by appending each
/// parameter with a sentinel value. The injection tester then
/// substitutes its payloads for those values when probing.
fn build_probe_url(endpoint_url: &str, parameters: &[String]) -> String {
    if parameters.is_empty() {
        return endpoint_url.to_string();
    }
    let separator = if endpoint_url.contains('?') { '&' } else { '?' };
    let mut query = String::new();
    for (i, name) in parameters.iter().enumerate() {
        let sep = if i == 0 { separator } else { '&' };
        query.push(sep);
        query.push_str(name);
        query.push_str("=1");
    }
    format!("{endpoint_url}{query}")
}

/// Test URL parameters for SQL injection.
async fn test_url_params(
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

    // Get baseline response
    let baseline = ctx
        .http_client
        .get(url_str)
        .send()
        .await
        .map_err(|e| ScorchError::Http { url: url_str.to_string(), source: e })?;
    let baseline_status = baseline.status();
    let baseline_body = baseline.text().await.unwrap_or_default();
    let baseline_len = baseline_body.len();

    // Test each parameter with SQL injection payloads
    for (param_name, param_value) in &params {
        for &payload in SQL_PAYLOADS {
            let injected_value = format!("{param_value}{payload}");

            // Build URL with injected parameter
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

            if let Some(finding) = analyze_injection_response(
                &resp_body,
                resp_status,
                baseline_status,
                baseline_len,
                param_name,
                payload,
                url_str,
            ) {
                findings.push(finding);
                break;
            }
        }
    }

    Ok(())
}

/// Analyze an injection response for SQL error indicators, status changes, and size anomalies.
fn analyze_injection_response(
    resp_body: &str,
    resp_status: reqwest::StatusCode,
    baseline_status: reqwest::StatusCode,
    baseline_len: usize,
    param_name: &str,
    payload: &str,
    url_str: &str,
) -> Option<Finding> {
    // Check for SQL error patterns in response
    if let Some(db_type) = detect_sql_error(resp_body) {
        return Some(
            Finding::new(
                "injection",
                Severity::Critical,
                format!("Potential SQL Injection in Parameter: {param_name}"),
                format!(
                    "The parameter '{param_name}' appears vulnerable to SQL injection. \
                     A {db_type} error was triggered by injecting SQL metacharacters."
                ),
                url_str,
            )
            .with_evidence(format!(
                "Payload: {payload} | Parameter: {param_name} | Database: {db_type}"
            ))
            .with_remediation(
                "Use parameterized queries / prepared statements. \
                 Never concatenate user input into SQL queries.",
            )
            .with_owasp("A03:2021 Injection")
            .with_cwe(89)
            .with_confidence(0.8),
        );
    }

    // Check for significant response differences (blind SQLi indicator)
    if resp_status != baseline_status && resp_status.as_u16() == 500 && baseline_status.is_success()
    {
        let status_diff = format!(
            "Baseline: HTTP {} | Injected: HTTP {}",
            baseline_status.as_u16(),
            resp_status.as_u16()
        );
        return Some(
            Finding::new(
                "injection",
                Severity::High,
                format!("Server Error on SQL Injection Attempt: {param_name}"),
                format!(
                    "The parameter '{param_name}' caused a 500 Internal Server Error \
                     when SQL metacharacters were injected. This suggests the input \
                     reaches a SQL query without proper sanitization."
                ),
                url_str,
            )
            .with_evidence(format!("Payload: {payload} | {status_diff}"))
            .with_remediation("Use parameterized queries / prepared statements.")
            .with_owasp("A03:2021 Injection")
            .with_cwe(89)
            .with_confidence(0.8),
        );
    }

    // Check for significant body length changes (possible blind SQLi)
    let resp_len = resp_body.len();
    // JUSTIFICATION: scanner math on small bounded values; precision loss is negligible
    #[allow(clippy::cast_precision_loss)]
    let len_diff = if baseline_len > 0 {
        ((resp_len as f64 - baseline_len as f64) / baseline_len as f64).abs()
    } else {
        0.0
    };

    // More than 50% change in body size is suspicious with boolean payloads
    if len_diff > 0.5 && payload.contains("OR") {
        return Some(
            Finding::new(
                "injection",
                Severity::Medium,
                format!("Possible Blind SQL Injection: {param_name}"),
                format!(
                    "The parameter '{param_name}' shows a significant response \
                     size difference ({:.0}%) when SQL boolean logic is injected. \
                     This may indicate blind SQL injection.",
                    len_diff * 100.0
                ),
                url_str,
            )
            .with_evidence(format!(
                "Payload: {payload} | Baseline size: {baseline_len} | Injected size: {resp_len}"
            ))
            .with_remediation(
                "Investigate with sqlmap for confirmation. \
                 Use parameterized queries.",
            )
            .with_owasp("A03:2021 Injection")
            .with_cwe(89)
            .with_confidence(0.8),
        );
    }

    None
}

/// A discovered HTML form.
#[derive(Debug)]
struct FormInfo {
    action: String,
    method: String,
    inputs: Vec<(String, String)>, // (name, default_value)
}

/// Test a form for SQL injection.
async fn test_form(ctx: &ScanContext, form: &FormInfo, findings: &mut Vec<Finding>) -> Result<()> {
    for (input_name, default_value) in &form.inputs {
        for &payload in &SQL_PAYLOADS[..3] {
            // Test fewer payloads per form field
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

            if let Some(db_type) = detect_sql_error(&resp_body) {
                findings.push(
                    Finding::new(
                        "injection",
                        Severity::Critical,
                        format!("SQL Injection in Form Field: {input_name}"),
                        format!(
                            "The form field '{input_name}' at {} is vulnerable to SQL injection. \
                             A {db_type} error was triggered.",
                            form.action
                        ),
                        &form.action,
                    )
                    .with_evidence(format!(
                        "Form: {} {} | Field: {input_name} | Payload: {payload} | DB: {db_type}",
                        form.method, form.action
                    ))
                    .with_remediation("Use parameterized queries / prepared statements.")
                    .with_owasp("A03:2021 Injection")
                    .with_cwe(89)
                    .with_confidence(0.8),
                );
                return Ok(()); // One finding per form is enough
            }
        }
    }

    Ok(())
}

/// Detect SQL error messages in a response body.
fn detect_sql_error(body: &str) -> Option<&'static str> {
    let lower = body.to_lowercase();

    for &(pattern, db_type) in SQL_ERROR_PATTERNS {
        if lower.contains(pattern) {
            return Some(db_type);
        }
    }

    None
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
                // Resolve relative URLs
                if let Ok(resolved) = base_url.join(href) {
                    // Only test same-origin links
                    if resolved.host() == base_url.host() {
                        links.push(resolved.to_string());
                    }
                }
            }
        }
    }

    links.sort();
    links.dedup();

    // Limit to avoid scanning too many links
    links.truncate(20);
    links
}

/// Extract forms from the page.
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

            // Skip submit/hidden/file inputs
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

    // Limit forms tested
    forms.truncate(10);
    forms
}

// --- Detection databases ---

/// SQL injection payloads for error-based detection.
const SQL_PAYLOADS: &[&str] = &[
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "'; --",
    "1' AND '1'='1",
    "1 AND 1=1",
    "' UNION SELECT NULL--",
    "1; SELECT 1",
    "') OR ('1'='1",
];

/// SQL error patterns → database type.
const SQL_ERROR_PATTERNS: &[(&str, &str)] = &[
    // MySQL
    ("you have an error in your sql syntax", "MySQL"),
    ("warning: mysql", "MySQL"),
    ("unclosed quotation mark after the character string", "MySQL/MSSQL"),
    ("mysql_fetch", "MySQL"),
    ("mysql_num_rows", "MySQL"),
    ("mysql_query", "MySQL"),
    ("mysqli_", "MySQL"),
    // PostgreSQL
    ("pg_query", "PostgreSQL"),
    ("pg_exec", "PostgreSQL"),
    ("error: syntax error at or near", "PostgreSQL"),
    ("unterminated quoted string at or near", "PostgreSQL"),
    ("pgsql", "PostgreSQL"),
    // MSSQL
    ("microsoft sql server", "MSSQL"),
    ("mssql_query", "MSSQL"),
    ("odbc sql server driver", "MSSQL"),
    ("sqlsrv_", "MSSQL"),
    // SQLite
    ("sqlite_error", "SQLite"),
    ("sqlite3::", "SQLite"),
    ("sqlite.error", "SQLite"),
    ("unrecognized token", "SQLite"),
    // Oracle
    ("ora-", "Oracle"),
    ("oracle error", "Oracle"),
    ("oracleexception", "Oracle"),
    // Generic
    ("sql syntax", "Unknown SQL"),
    ("sql error", "Unknown SQL"),
    ("query failed", "Unknown SQL"),
    ("database error", "Unknown SQL"),
    ("jdbc.sqlex", "Java/JDBC"),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for the SQL injection detection module's pure helper functions.

    /// WORK-108: `build_probe_url` appends the parameters with sentinel
    /// values, using `?` for the first separator and `&` thereafter.
    #[test]
    fn build_probe_url_appends_query_string() {
        let url = build_probe_url(
            "https://example.com/api/users",
            &["page".to_string(), "limit".to_string()],
        );
        assert_eq!(url, "https://example.com/api/users?page=1&limit=1");
    }

    /// WORK-108: `build_probe_url` uses `&` when the URL already has
    /// a query string.
    #[test]
    fn build_probe_url_appends_to_existing_query() {
        let url = build_probe_url("https://example.com/api/users?fmt=json", &["page".to_string()]);
        assert_eq!(url, "https://example.com/api/users?fmt=json&page=1");
    }

    /// WORK-108: empty parameter list returns the URL unchanged.
    #[test]
    fn build_probe_url_no_parameters_returns_input() {
        let url = build_probe_url("https://example.com/api/users", &[]);
        assert_eq!(url, "https://example.com/api/users");
    }

    /// Verify that `detect_sql_error` identifies MySQL error strings in response bodies.
    #[test]
    fn test_detect_sql_error_mysql() {
        let body = "Error: You have an error in your SQL syntax near 'foo'";
        let result = detect_sql_error(body);

        assert_eq!(result, Some("MySQL"));
    }

    /// Verify that `detect_sql_error` identifies PostgreSQL error strings.
    #[test]
    fn test_detect_sql_error_postgresql() {
        let body = "ERROR: syntax error at or near \"SELECT\"";
        let result = detect_sql_error(body);

        assert_eq!(result, Some("PostgreSQL"));
    }

    /// Verify that `detect_sql_error` identifies MSSQL error strings.
    #[test]
    fn test_detect_sql_error_mssql() {
        let body = "ODBC SQL Server Driver error: invalid query";
        let result = detect_sql_error(body);

        assert_eq!(result, Some("MSSQL"));
    }

    /// Verify that `detect_sql_error` returns `None` when no SQL error pattern is found.
    #[test]
    fn test_detect_sql_error_none() {
        let body = "<html><body>Welcome to our site!</body></html>";
        let result = detect_sql_error(body);

        assert_eq!(result, None);
    }

    /// Verify that `analyze_injection_response` produces a Critical finding when a SQL
    /// error pattern is present in the response body.
    #[test]
    fn test_analyze_injection_response_sql_error() {
        // Arrange
        let body_with_error = "Warning: mysql_fetch error in /var/www/app.php";
        let status_200 = reqwest::StatusCode::OK;

        // Act
        let finding = analyze_injection_response(
            body_with_error,
            status_200,
            status_200,
            1000,
            "id",
            "'",
            "https://example.com/?id=1",
        );

        // Assert
        assert!(finding.is_some());
        let f = finding.expect("finding should be present");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.title.contains("SQL Injection"));
    }

    /// Verify that `analyze_injection_response` returns `None` when the response
    /// shows no SQL errors, no status change, and no significant size difference.
    #[test]
    fn test_analyze_injection_response_no_finding() {
        let body = "<html><body>Normal page</body></html>";
        let status = reqwest::StatusCode::OK;

        let finding = analyze_injection_response(
            body,
            status,
            status,
            body.len(),
            "id",
            "'",
            "https://x.com/?id=1",
        );

        assert!(finding.is_none());
    }

    /// Verify that `extract_parameterized_links` finds same-origin links with query parameters
    /// from HTML anchor elements.
    #[test]
    fn test_extract_parameterized_links() -> std::result::Result<(), url::ParseError> {
        // Arrange
        let base = Url::parse("https://example.com/")?;
        let body = r#"
            <html><body>
                <a href="/page?id=5&sort=asc">Link1</a>
                <a href="/about">Link2</a>
                <a href="https://external.com/?x=1">External</a>
            </body></html>
        "#;

        // Act
        let links = extract_parameterized_links(body, &base);

        // Assert
        assert_eq!(links.len(), 1);
        assert!(links[0].contains("page?id=5"));

        Ok(())
    }

    /// Verify that `extract_forms` correctly parses HTML form elements and their inputs,
    /// resolving the action URL and skipping submit/button/file/image input types.
    #[test]
    fn test_extract_forms() -> std::result::Result<(), url::ParseError> {
        // Arrange
        let base = Url::parse("https://example.com/")?;
        let body = r#"
            <html><body>
                <form action="/api/query" method="POST">
                    <input type="text" name="search" value="">
                    <select name="category"><option value="all">All</option></select>
                    <input type="submit" value="Go">
                    <input type="image" src="/btn.png" name="btn">
                </form>
            </body></html>
        "#;

        // Act
        let forms = extract_forms(body, &base);

        // Assert
        assert_eq!(forms.len(), 1);
        let form = &forms[0];
        assert!(form.action.contains("/api/query"));
        assert_eq!(form.method, "POST");
        // submit and image should be excluded; search and category remain
        assert_eq!(form.inputs.len(), 2);
        assert!(form.inputs.iter().any(|(n, _)| n == "search"));
        assert!(form.inputs.iter().any(|(n, _)| n == "category"));

        Ok(())
    }
}
