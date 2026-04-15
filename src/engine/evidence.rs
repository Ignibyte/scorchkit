//! HTTP evidence capture for security findings.
//!
//! Provides `HttpEvidence` for attaching full HTTP request/response
//! pairs to findings, enabling proof-of-concept replay and detailed
//! audit trails.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Maximum response body size to capture (10 KB).
const MAX_BODY_SIZE: usize = 10 * 1024;

/// Captured HTTP request/response pair for a finding.
///
/// Stores the full request and response data that triggered or
/// demonstrates a vulnerability. Response bodies are truncated
/// to a fixed maximum (10 KiB) to prevent memory bloat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpEvidence {
    /// HTTP method (GET, POST, PUT, etc.).
    pub method: String,
    /// Request URL.
    pub url: String,
    /// Request headers.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub request_headers: HashMap<String, String>,
    /// Request body (for POST/PUT).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    /// HTTP response status code.
    pub status_code: u16,
    /// Response headers.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub response_headers: HashMap<String, String>,
    /// Response body (truncated to 10KB max).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
    /// Whether the response body was truncated.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

impl HttpEvidence {
    /// Create a new HTTP evidence capture.
    #[must_use]
    pub fn new(method: impl Into<String>, url: impl Into<String>, status_code: u16) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            request_headers: HashMap::new(),
            request_body: None,
            status_code,
            response_headers: HashMap::new(),
            response_body: None,
            truncated: false,
        }
    }

    /// Add request headers.
    #[must_use]
    pub fn with_request_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.request_headers = headers;
        self
    }

    /// Add a request body.
    #[must_use]
    pub fn with_request_body(mut self, body: impl Into<String>) -> Self {
        self.request_body = Some(body.into());
        self
    }

    /// Add response headers.
    #[must_use]
    pub fn with_response_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.response_headers = headers;
        self
    }

    /// Add a response body, truncating to 10 KiB if needed.
    ///
    /// When the supplied body exceeds the maximum size, it is
    /// truncated at the byte boundary and [`Self::truncated`] is set
    /// to `true`.
    #[must_use]
    pub fn with_response_body(mut self, body: impl Into<String>) -> Self {
        let body = body.into();
        if body.len() > MAX_BODY_SIZE {
            self.response_body = Some(body[..MAX_BODY_SIZE].to_string());
            self.truncated = true;
        } else {
            self.response_body = Some(body);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify evidence builder creates complete struct.
    #[test]
    fn test_http_evidence_builder() {
        let evidence = HttpEvidence::new("GET", "https://example.com/api", 200)
            .with_request_body("test body")
            .with_response_body("<html>response</html>");

        assert_eq!(evidence.method, "GET");
        assert_eq!(evidence.url, "https://example.com/api");
        assert_eq!(evidence.status_code, 200);
        assert_eq!(evidence.request_body.as_deref(), Some("test body"));
        assert_eq!(evidence.response_body.as_deref(), Some("<html>response</html>"));
        assert!(!evidence.truncated);
    }

    /// Verify response body truncation at 10KB.
    #[test]
    fn test_http_evidence_truncation() {
        let large_body = "x".repeat(20_000);
        let evidence =
            HttpEvidence::new("POST", "https://example.com", 500).with_response_body(large_body);

        assert!(evidence.truncated);
        assert_eq!(evidence.response_body.as_ref().map(String::len), Some(MAX_BODY_SIZE));
    }

    /// Verify finding integration via with_http_evidence.
    #[test]
    fn test_finding_with_evidence() {
        use crate::engine::finding::Finding;
        use crate::engine::severity::Severity;

        let evidence = HttpEvidence::new("GET", "https://example.com/xss?q=<script>", 200)
            .with_response_body("<html><script>alert(1)</script></html>");

        let finding = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "Script tag reflected in response",
            "https://example.com/xss",
        )
        .with_http_evidence(evidence);

        assert!(finding.http_evidence.is_some());
        let ev = finding.http_evidence.as_ref().unwrap();
        assert_eq!(ev.status_code, 200);
    }
}
