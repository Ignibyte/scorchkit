//! File upload vulnerability testing module.
//!
//! Discovers upload forms via HTML parsing (`<input type="file">`), then submits
//! test payloads to probe for unrestricted file type acceptance, double extension
//! bypass, content-type mismatch, polyglot files, null byte injection, path
//! traversal in filenames, and dangerous content uploads (SVG XSS, HTML).

use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// File upload vulnerability detection via form discovery and payload testing.
///
/// Parses HTML to find upload forms, then submits test files with various bypass
/// techniques to determine if the server accepts dangerous uploads.
#[derive(Debug)]
pub struct UploadModule;

#[async_trait]
impl ScanModule for UploadModule {
    fn name(&self) -> &'static str {
        "File Upload Testing"
    }

    fn id(&self) -> &'static str {
        "upload"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Test file upload endpoints for unrestricted types, bypasses, and dangerous content"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Fetch target and parse HTML for upload forms
        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let body = response.text().await.unwrap_or_default();
        let forms = discover_upload_forms(&body, &ctx.target.url);

        if forms.is_empty() {
            return Ok(findings);
        }

        let payloads = generate_upload_payloads();

        for form in &forms {
            for payload in &payloads {
                let accepted = test_upload(ctx, form, payload).await;
                if accepted {
                    findings.push(
                        Finding::new(
                            "upload",
                            payload.severity,
                            format!("Upload Accepted: {}", payload.title),
                            format!(
                                "The upload form at '{}' (field: '{}') accepted a {} upload. {}",
                                form.action_url,
                                form.field_name,
                                payload.title,
                                payload.description
                            ),
                            &form.action_url,
                        )
                        .with_evidence(format!(
                            "Filename: {} | Content-Type: {} | Form field: {}",
                            payload.filename, payload.content_type, form.field_name
                        ))
                        .with_remediation(payload.remediation)
                        .with_owasp("A04:2021 Insecure Design")
                        .with_cwe(payload.cwe)
                        .with_confidence(0.6),
                    );
                }
            }
        }

        Ok(findings)
    }
}

/// A discovered file upload form on the target page.
#[derive(Debug, Clone)]
struct UploadForm {
    /// Resolved URL for form submission.
    action_url: String,
    /// Name attribute of the file input field.
    field_name: String,
    /// Other form fields (hidden inputs) to include in submission.
    other_fields: Vec<(String, String)>,
}

/// A test payload for upload vulnerability detection.
#[derive(Debug, Clone)]
struct UploadPayload {
    /// Short title for the test (e.g., "PHP Script Upload").
    title: &'static str,
    /// Filename to use in the upload.
    filename: &'static str,
    /// MIME content type to declare.
    content_type: &'static str,
    /// File body content.
    body: &'static [u8],
    /// Detailed description of the vulnerability.
    description: &'static str,
    /// Remediation guidance.
    remediation: &'static str,
    /// Finding severity.
    severity: Severity,
    /// CWE identifier.
    cwe: u32,
}

/// Discover file upload forms in HTML by finding `<input type="file">` elements.
///
/// Parses the HTML document, finds forms containing file inputs, extracts
/// the form action URL (resolved against `base_url`), the file field name,
/// and any hidden input fields for form submission.
fn discover_upload_forms(html: &str, base_url: &Url) -> Vec<UploadForm> {
    let document = Html::parse_document(html);

    let Ok(form_selector) = Selector::parse("form") else {
        return Vec::new();
    };
    let Ok(file_input_selector) = Selector::parse("input[type='file'], input[type=\"file\"]")
    else {
        return Vec::new();
    };
    let Ok(hidden_input_selector) = Selector::parse("input[type='hidden'], input[type=\"hidden\"]")
    else {
        return Vec::new();
    };

    let mut forms = Vec::new();

    for form in document.select(&form_selector) {
        // Check if this form contains a file input
        let Some(file_input) = form.select(&file_input_selector).next() else {
            continue;
        };

        let field_name = file_input.value().attr("name").unwrap_or("file").to_string();

        // Resolve form action URL
        let action = form.value().attr("action").unwrap_or("");
        let action_url =
            base_url.join(action).map_or_else(|_| base_url.to_string(), |u| u.to_string());

        // Collect hidden fields
        let other_fields: Vec<(String, String)> = form
            .select(&hidden_input_selector)
            .filter_map(|input| {
                let name = input.value().attr("name")?.to_string();
                let value = input.value().attr("value").unwrap_or("").to_string();
                Some((name, value))
            })
            .collect();

        forms.push(UploadForm { action_url, field_name, other_fields });
    }

    forms
}

/// Generate the set of upload test payloads covering major bypass techniques.
#[must_use]
#[allow(clippy::too_many_lines)] // Data function: 9 payload structs, each 10 fields — cannot meaningfully split
fn generate_upload_payloads() -> Vec<UploadPayload> {
    vec![
        UploadPayload {
            title: "PHP Script Upload",
            filename: "scorchkit-test.php",
            content_type: "application/x-php",
            body: b"<?php echo 'scorchkit-upload-test'; ?>",
            description: "Server-side script files can lead to remote code execution \
                          if stored in a web-accessible directory.",
            remediation: "Restrict uploads to a whitelist of safe file extensions. \
                          Validate file content, not just the extension or Content-Type. \
                          Store uploads outside the web root.",
            severity: Severity::Critical,
            cwe: 434,
        },
        UploadPayload {
            title: "JSP Script Upload",
            filename: "scorchkit-test.jsp",
            content_type: "application/octet-stream",
            body: b"<% out.println(\"scorchkit-upload-test\"); %>",
            description: "JSP files can execute server-side Java code if stored in a \
                          web-accessible directory on a Java application server.",
            remediation: "Restrict uploads to a whitelist of safe file extensions. \
                          Never allow .jsp, .jspx, or .war uploads.",
            severity: Severity::Critical,
            cwe: 434,
        },
        UploadPayload {
            title: "Double Extension Bypass",
            filename: "scorchkit-test.php.jpg",
            content_type: "image/jpeg",
            body: b"<?php echo 'scorchkit-upload-test'; ?>",
            description: "Double extension bypass can trick servers that only check \
                          the final extension (.jpg) while Apache may execute based on \
                          the first (.php).",
            remediation: "Validate the entire filename, not just the last extension. \
                          Strip or reject filenames with multiple extensions.",
            severity: Severity::High,
            cwe: 434,
        },
        UploadPayload {
            title: "Content-Type Mismatch",
            filename: "scorchkit-test.php",
            content_type: "image/png",
            body: b"<?php echo 'scorchkit-upload-test'; ?>",
            description: "Declaring an image Content-Type while uploading a script can \
                          bypass Content-Type-only validation.",
            remediation: "Validate file content (magic bytes) in addition to \
                          Content-Type and extension. Use file type detection \
                          libraries, not client-declared MIME types.",
            severity: Severity::High,
            cwe: 434,
        },
        UploadPayload {
            title: "Polyglot GIF+PHP",
            filename: "scorchkit-test.gif",
            content_type: "image/gif",
            body: b"GIF89a<?php echo 'scorchkit-upload-test'; ?>",
            description: "A polyglot file with a valid GIF header followed by PHP code \
                          can bypass magic byte validation while remaining executable.",
            remediation: "Re-encode uploaded images using an image processing library. \
                          Strip non-image data after validation. Do not rely solely on \
                          magic byte checks.",
            severity: Severity::High,
            cwe: 434,
        },
        UploadPayload {
            title: "Null Byte Filename",
            filename: "scorchkit-test.php%00.jpg",
            content_type: "image/jpeg",
            body: b"<?php echo 'scorchkit-upload-test'; ?>",
            description: "Null byte injection in filenames can truncate the extension \
                          in languages/frameworks that use C-style string handling, \
                          causing .php%00.jpg to be stored as .php.",
            remediation: "Reject filenames containing null bytes or URL-encoded null \
                          bytes (%00). Sanitize filenames by stripping all non-alphanumeric \
                          characters except dots and hyphens.",
            severity: Severity::High,
            cwe: 434,
        },
        UploadPayload {
            title: "Path Traversal Filename",
            filename: "../../scorchkit-test.php",
            content_type: "application/x-php",
            body: b"<?php echo 'scorchkit-upload-test'; ?>",
            description: "Path traversal in filenames can write files outside the \
                          intended upload directory, potentially overwriting critical \
                          application files.",
            remediation: "Strip path separators (/ and \\) from uploaded filenames. \
                          Use a server-generated filename instead of the client-provided one.",
            severity: Severity::Critical,
            cwe: 22,
        },
        UploadPayload {
            title: "SVG XSS Upload",
            filename: "scorchkit-test.svg",
            content_type: "image/svg+xml",
            body: b"<svg xmlns=\"http://www.w3.org/2000/svg\" \
                   onload=\"alert('scorchkit-xss')\"><text>test</text></svg>",
            description: "SVG files can contain JavaScript that executes when the SVG \
                          is viewed in a browser, enabling stored XSS attacks.",
            remediation: "Sanitize SVG uploads by stripping event handlers and script \
                          elements. Consider converting SVGs to rasterized formats or \
                          serving them with Content-Disposition: attachment.",
            severity: Severity::Medium,
            cwe: 79,
        },
        UploadPayload {
            title: "HTML Upload",
            filename: "scorchkit-test.html",
            content_type: "text/html",
            body: b"<html><body><script>alert('scorchkit-xss')</script></body></html>",
            description: "HTML files uploaded and served from the same origin can \
                          execute JavaScript in the context of the application, \
                          enabling stored XSS and session hijacking.",
            remediation: "Block HTML and HTM file uploads. If HTML uploads are required, \
                          serve them from a separate domain with Content-Disposition: attachment.",
            severity: Severity::Medium,
            cwe: 79,
        },
    ]
}

/// Submit a test upload payload to a discovered form.
///
/// Returns `true` if the upload appears to have been accepted (heuristic
/// based on HTTP status and response body analysis).
async fn test_upload(ctx: &ScanContext, form: &UploadForm, payload: &UploadPayload) -> bool {
    let Ok(part) = reqwest::multipart::Part::bytes(payload.body.to_vec())
        .file_name(payload.filename.to_string())
        .mime_str(payload.content_type)
    else {
        return false;
    };

    let mut multipart_form = reqwest::multipart::Form::new().part(form.field_name.clone(), part);

    // Add hidden fields from the form
    for (name, value) in &form.other_fields {
        multipart_form = multipart_form.text(name.clone(), value.clone());
    }

    let Ok(response) =
        ctx.http_client.post(&form.action_url).multipart(multipart_form).send().await
    else {
        return false;
    };

    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    is_upload_accepted(status, &body)
}

/// Heuristic to determine if an upload was accepted by the server.
///
/// Considers a combination of HTTP status code and absence of error-indicating
/// keywords in the response body. This is a best-effort heuristic — a `true`
/// result means the server likely accepted the file, not that it was stored
/// or is executable.
#[must_use]
fn is_upload_accepted(status: u16, body: &str) -> bool {
    // Reject on clear error status codes
    if status == 400 || status == 403 || status == 415 || status == 422 || status >= 500 {
        return false;
    }

    // Accept on success status codes (200, 201, 302 redirect)
    if status == 200 || status == 201 || status == 302 {
        let lower = body.to_lowercase();

        // Check for error indicators in the response body
        let error_indicators = [
            "file type not allowed",
            "invalid file",
            "upload failed",
            "not permitted",
            "extension not allowed",
            "forbidden file",
            "rejected",
            "disallowed",
            "unsupported file type",
            "invalid content type",
        ];

        if error_indicators.iter().any(|indicator| lower.contains(indicator)) {
            return false;
        }

        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for file upload vulnerability detection.
    ///
    /// Tests form discovery via HTML parsing and payload generation without
    /// requiring a live HTTP target.

    /// Verify upload form discovery from HTML with file inputs.
    ///
    /// A form containing `<input type="file">` should be detected with the
    /// correct action URL, field name, and hidden fields.
    #[test]
    fn test_discover_upload_forms() {
        let html = r#"
            <html><body>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="hidden" name="csrf" value="tok123">
                <input type="file" name="document">
                <input type="submit" value="Upload">
            </form>
            </body></html>
        "#;
        let base = Url::parse("https://example.com/page").expect("valid URL");
        let forms = discover_upload_forms(html, &base);

        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].action_url, "https://example.com/upload");
        assert_eq!(forms[0].field_name, "document");
        assert_eq!(forms[0].other_fields.len(), 1);
        assert_eq!(forms[0].other_fields[0].0, "csrf");
        assert_eq!(forms[0].other_fields[0].1, "tok123");
    }

    /// Verify no false positives on forms without file inputs.
    ///
    /// Login forms, search forms, and other non-upload forms should not
    /// be detected as upload forms.
    #[test]
    fn test_discover_no_upload_forms() {
        let html = r#"
            <html><body>
            <form action="/login" method="post">
                <input type="text" name="username">
                <input type="password" name="password">
                <input type="submit" value="Login">
            </form>
            <form action="/search" method="get">
                <input type="text" name="q">
            </form>
            </body></html>
        "#;
        let base = Url::parse("https://example.com").expect("valid URL");
        let forms = discover_upload_forms(html, &base);

        assert!(forms.is_empty());
    }

    /// Verify all 9 payload types are generated with correct content.
    ///
    /// Each payload must have non-empty filename, content_type, body, and
    /// appropriate severity/CWE classification.
    #[test]
    fn test_generate_payloads() {
        let payloads = generate_upload_payloads();

        assert_eq!(payloads.len(), 9);

        // All payloads have non-empty fields
        for payload in &payloads {
            assert!(!payload.filename.is_empty(), "Payload '{}' has empty filename", payload.title);
            assert!(
                !payload.content_type.is_empty(),
                "Payload '{}' has empty content_type",
                payload.title
            );
            assert!(!payload.body.is_empty(), "Payload '{}' has empty body", payload.title);
            assert!(payload.cwe > 0, "Payload '{}' has zero CWE", payload.title);
        }

        // Check severity distribution
        let critical = payloads.iter().filter(|p| p.severity == Severity::Critical).count();
        let high = payloads.iter().filter(|p| p.severity == Severity::High).count();
        let medium = payloads.iter().filter(|p| p.severity == Severity::Medium).count();

        assert_eq!(critical, 3, "Expected 3 Critical payloads (PHP, JSP, path traversal)");
        assert_eq!(high, 4, "Expected 4 High payloads (double ext, CT mismatch, polyglot, null)");
        assert_eq!(medium, 2, "Expected 2 Medium payloads (SVG XSS, HTML)");
    }

    /// Verify the polyglot GIF+PHP payload has the correct magic bytes.
    ///
    /// The polyglot must start with `GIF89a` to pass magic byte validation
    /// while also containing PHP code.
    #[test]
    fn test_polyglot_payload() {
        let payloads = generate_upload_payloads();
        let polyglot = payloads.iter().find(|p| p.title == "Polyglot GIF+PHP");

        assert!(polyglot.is_some(), "Polyglot payload not found");
        let p = polyglot.expect("just asserted");
        assert!(p.body.starts_with(b"GIF89a"), "Polyglot missing GIF89a header");
        assert!(p.body.windows(5).any(|w| w == b"<?php"), "Polyglot missing PHP code");
    }

    /// Verify the upload acceptance heuristic on success/error responses.
    ///
    /// Tests both status-code-based and body-content-based acceptance detection.
    #[test]
    fn test_upload_accepted_heuristic() {
        // Accepted: 200 with success message
        assert!(is_upload_accepted(200, "File uploaded successfully"));

        // Accepted: 201 created
        assert!(is_upload_accepted(201, "{\"id\": 42}"));

        // Accepted: 302 redirect (common after upload)
        assert!(is_upload_accepted(302, ""));

        // Rejected: 403 forbidden
        assert!(!is_upload_accepted(403, "Access denied"));

        // Rejected: 415 unsupported media type
        assert!(!is_upload_accepted(415, "Unsupported file type"));

        // Rejected: 200 but body says error
        assert!(!is_upload_accepted(200, "Error: file type not allowed"));
        assert!(!is_upload_accepted(200, "Upload failed: invalid file extension"));

        // Rejected: 500 server error
        assert!(!is_upload_accepted(500, "Internal server error"));
    }

    /// Verify hidden form fields are extracted for submission.
    ///
    /// CSRF tokens and other hidden inputs must be included when submitting
    /// uploads, otherwise the server will reject the request.
    #[test]
    fn test_form_hidden_fields() {
        let html = r#"
            <form action="/api/upload" method="post">
                <input type="hidden" name="_token" value="csrf-abc-123">
                <input type="hidden" name="folder_id" value="42">
                <input type="file" name="attachment">
            </form>
        "#;
        let base = Url::parse("https://example.com").expect("valid URL");
        let forms = discover_upload_forms(html, &base);

        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].other_fields.len(), 2);

        let token = forms[0].other_fields.iter().find(|(n, _)| n == "_token");
        assert!(token.is_some());
        assert_eq!(token.expect("just asserted").1, "csrf-abc-123");

        let folder = forms[0].other_fields.iter().find(|(n, _)| n == "folder_id");
        assert!(folder.is_some());
        assert_eq!(folder.expect("just asserted").1, "42");
    }

    /// Verify form action URL resolution against base URL.
    ///
    /// Relative action URLs should resolve against the page's base URL.
    /// Missing action should default to the base URL.
    #[test]
    fn test_form_action_resolution() {
        // Relative action
        let html = r#"<form action="upload.php"><input type="file" name="f"></form>"#;
        let base = Url::parse("https://example.com/admin/page").expect("valid URL");
        let forms = discover_upload_forms(html, &base);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].action_url, "https://example.com/admin/upload.php");

        // Absolute action
        let html2 = r#"<form action="/api/files"><input type="file" name="f"></form>"#;
        let forms2 = discover_upload_forms(html2, &base);
        assert_eq!(forms2[0].action_url, "https://example.com/api/files");

        // No action — defaults to base URL
        let html3 = r#"<form><input type="file" name="f"></form>"#;
        let forms3 = discover_upload_forms(html3, &base);
        assert_eq!(forms3[0].action_url, "https://example.com/admin/page");
    }

    /// Verify default field name when input has no name attribute.
    ///
    /// Some forms omit the `name` attribute — the module should default to "file".
    #[test]
    fn test_file_input_no_name() {
        let html = r#"<form action="/up"><input type="file"></form>"#;
        let base = Url::parse("https://example.com").expect("valid URL");
        let forms = discover_upload_forms(html, &base);

        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].field_name, "file");
    }
}
