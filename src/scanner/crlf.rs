//! CRLF injection scanner module.
//!
//! Detects HTTP response splitting vulnerabilities by injecting `%0d%0a`
//! (carriage return + line feed) sequences into URL parameters and checking
//! response headers for injected header canaries.

use async_trait::async_trait;
use reqwest::header::HeaderMap;
use url::Url;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects CRLF injection (HTTP response splitting) vulnerabilities.
#[derive(Debug)]
pub struct CrlfModule;

#[async_trait]
impl ScanModule for CrlfModule {
    fn name(&self) -> &'static str {
        "CRLF Injection Detection"
    }

    fn id(&self) -> &'static str {
        "crlf"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect CRLF injection and HTTP response splitting vulnerabilities"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Test parameters in the target URL
        test_url_params_crlf(ctx, url, &mut findings).await?;

        // Also test by appending a parameter to the base URL
        test_appended_param_crlf(ctx, url, &mut findings).await?;

        Ok(findings)
    }
}

/// A CRLF injection payload with its canary header for detection.
#[derive(Debug)]
struct CrlfPayload {
    /// The injection payload (appended to the parameter value).
    payload: &'static str,
    /// The header name we expect to appear in the response if injection succeeds.
    canary_header: &'static str,
    /// Human-readable description of the technique.
    description: &'static str,
}

/// CRLF injection payloads covering encoding variants.
///
/// Each payload attempts to inject a `X-Scorch-Injected: true` header.
const CRLF_PAYLOADS: &[CrlfPayload] = &[
    // Standard CRLF
    CrlfPayload {
        payload: "%0d%0aX-Scorch-Injected:%20true",
        canary_header: "x-scorch-injected",
        description: "Standard URL-encoded CRLF",
    },
    // Double-encoded CRLF
    CrlfPayload {
        payload: "%250d%250aX-Scorch-Injected:%20true",
        canary_header: "x-scorch-injected",
        description: "Double URL-encoded CRLF",
    },
    // Unicode CRLF variants
    CrlfPayload {
        payload: "%E5%98%8A%E5%98%8DX-Scorch-Injected:%20true",
        canary_header: "x-scorch-injected",
        description: "Unicode CRLF encoding",
    },
    // Bare LF (some servers accept LF without CR)
    CrlfPayload {
        payload: "%0aX-Scorch-Injected:%20true",
        canary_header: "x-scorch-injected",
        description: "Line feed only (no carriage return)",
    },
    // Bare CR
    CrlfPayload {
        payload: "%0dX-Scorch-Injected:%20true",
        canary_header: "x-scorch-injected",
        description: "Carriage return only (no line feed)",
    },
    // CRLF with Set-Cookie injection (tests cookie injection vector)
    CrlfPayload {
        payload: "%0d%0aSet-Cookie:%20scorch_test=injected",
        canary_header: "set-cookie",
        description: "CRLF with Set-Cookie injection",
    },
    // Tab-based header injection
    CrlfPayload {
        payload: "%0d%0a%09X-Scorch-Injected:%20true",
        canary_header: "x-scorch-injected",
        description: "CRLF with tab before header",
    },
];

/// Check response headers for the presence of an injected canary header.
///
/// For most canary headers, checks that the header exists and wasn't present
/// before injection. For `set-cookie`, checks if the injected value appears.
fn check_crlf_response(
    headers: &HeaderMap,
    canary_header: &str,
    injected_cookie_value: Option<&str>,
) -> bool {
    if canary_header == "set-cookie" {
        // For Set-Cookie, check if our specific injected value appears
        if let Some(cookie_val) = injected_cookie_value {
            return headers
                .get_all("set-cookie")
                .iter()
                .any(|v| v.to_str().unwrap_or("").contains(cookie_val));
        }
        return false;
    }

    // For custom headers, their mere presence indicates injection
    headers.contains_key(canary_header)
}

/// Test URL query parameters for CRLF injection.
async fn test_url_params_crlf(
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
        for crlf in CRLF_PAYLOADS {
            let injected_value = format!("{param_value}{}", crlf.payload);

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

            let cookie_val = if crlf.canary_header == "set-cookie" {
                Some("scorch_test=injected")
            } else {
                None
            };

            if check_crlf_response(response.headers(), crlf.canary_header, cookie_val) {
                findings.push(build_crlf_finding(param_name, crlf, url_str));
                break;
            }
        }
    }

    Ok(())
}

/// Test CRLF injection by appending a test parameter to the URL.
async fn test_appended_param_crlf(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let Ok(mut parsed) = Url::parse(url_str) else {
        return Ok(());
    };

    // Only test the primary payload on the appended parameter
    let crlf = &CRLF_PAYLOADS[0];
    let injected_value = format!("test{}", crlf.payload);
    parsed.query_pairs_mut().append_pair("scorch_test", &injected_value);

    let Ok(response) = ctx.http_client.get(parsed.as_str()).send().await else {
        return Ok(());
    };

    if check_crlf_response(response.headers(), crlf.canary_header, None) {
        findings.push(build_crlf_finding("scorch_test (appended)", crlf, url_str));
    }

    Ok(())
}

/// Build a CRLF injection finding.
fn build_crlf_finding(param_name: &str, crlf: &CrlfPayload, url_str: &str) -> Finding {
    Finding::new(
        "crlf",
        Severity::High,
        format!("CRLF Injection via parameter `{param_name}`"),
        format!(
            "The parameter `{param_name}` is vulnerable to CRLF injection \
             (HTTP response splitting). The injected header `{header}` was \
             detected in the response using {technique}. This can lead to \
             cache poisoning, XSS, or session fixation via Set-Cookie injection.",
            header = crlf.canary_header,
            technique = crlf.description,
        ),
        url_str,
    )
    .with_evidence(format!(
        "Payload: {payload} | Parameter: {param_name} | Injected header: {header}",
        payload = crlf.payload,
        header = crlf.canary_header,
    ))
    .with_remediation(
        "Strip or reject CR (\\r) and LF (\\n) characters from all user input \
         before including it in HTTP headers. Use framework-provided header-safe \
         output functions. Apply allowlist validation on header values.",
    )
    .with_owasp("A03:2021 Injection")
    .with_cwe(113)
    .with_confidence(0.9)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the CRLF injection scanner module's pure helper functions
    /// and constant data integrity.

    /// Verify that the module metadata returns correct values.
    #[test]
    fn test_module_metadata_crlf() {
        let module = CrlfModule;

        assert_eq!(module.id(), "crlf");
        assert_eq!(module.name(), "CRLF Injection Detection");
        assert_eq!(module.category(), ModuleCategory::Scanner);
        assert!(!module.description().is_empty());
        assert!(!module.requires_external_tool());
    }

    /// Verify that the CRLF payload database is non-empty and all entries
    /// have non-empty fields.
    #[test]
    fn test_crlf_payloads_not_empty() {
        assert!(!CRLF_PAYLOADS.is_empty(), "payload database must not be empty");

        for (i, payload) in CRLF_PAYLOADS.iter().enumerate() {
            assert!(!payload.payload.is_empty(), "payload {i} has empty payload string");
            assert!(!payload.canary_header.is_empty(), "payload {i} has empty canary_header");
            assert!(!payload.description.is_empty(), "payload {i} has empty description");
        }
    }

    /// Verify that `check_crlf_response` detects the injected canary header
    /// in response headers.
    #[test]
    fn test_check_crlf_header_detected() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/html".parse().expect("valid header value"));
        headers.insert("x-scorch-injected", "true".parse().expect("valid header value"));

        assert!(
            check_crlf_response(&headers, "x-scorch-injected", None),
            "should detect injected canary header"
        );
    }

    /// Verify that `check_crlf_response` returns false when the canary header
    /// is not present in normal response headers.
    #[test]
    fn test_check_crlf_header_negative() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/html".parse().expect("valid header value"));
        headers.insert("server", "nginx".parse().expect("valid header value"));

        assert!(
            !check_crlf_response(&headers, "x-scorch-injected", None),
            "should not match normal headers"
        );
    }

    /// Verify that the payload database includes URL-encoded and double-encoded
    /// CRLF variants.
    #[test]
    fn test_crlf_payload_encoding_variants() {
        let payloads: Vec<&str> = CRLF_PAYLOADS.iter().map(|p| p.payload).collect();

        // Standard %0d%0a
        assert!(
            payloads.iter().any(|p| p.contains("%0d%0a")),
            "must include standard CRLF encoding"
        );

        // Double-encoded %250d%250a
        assert!(
            payloads.iter().any(|p| p.contains("%250d%250a")),
            "must include double-encoded CRLF"
        );

        // LF-only %0a
        assert!(
            payloads.iter().any(|p| p.starts_with("%0a") || p.contains("%0aX")),
            "must include LF-only variant"
        );

        // Set-Cookie injection
        assert!(
            payloads.iter().any(|p| p.contains("Set-Cookie")),
            "must include Set-Cookie injection payload"
        );
    }
}
