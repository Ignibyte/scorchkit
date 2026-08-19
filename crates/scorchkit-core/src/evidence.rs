//! HTTP evidence capture for security findings.
//!
//! Provides `HttpEvidence` for attaching full HTTP request/response
//! pairs to findings, enabling proof-of-concept replay and detailed
//! audit trails.

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::observation::{
    is_sensitive_key, normalized_redaction_fields, redact_text, redact_url, HttpParameterIdentity,
};

/// Maximum response body size to capture (10 KB).
const MAX_BODY_SIZE: usize = 10 * 1024;

/// Captured HTTP request/response pair for a finding.
///
/// Stores the full request and response data that triggered or
/// demonstrates a vulnerability. Response bodies are truncated
/// to a fixed maximum (10 KiB) to prevent memory bloat.
#[derive(Debug, Clone)]
pub struct HttpEvidence {
    /// HTTP method (GET, POST, PUT, etc.).
    pub method: String,
    /// Request URL.
    pub url: String,
    /// Normalized application route without query values.
    pub route: Option<String>,
    /// Parameter involved in the observed behavior.
    pub parameter: Option<HttpParameterIdentity>,
    /// Operator-defined authentication persona label; never a credential.
    pub authentication_persona: Option<String>,
    /// Request headers.
    pub request_headers: HashMap<String, String>,
    /// Request body (for POST/PUT).
    pub request_body: Option<String>,
    /// HTTP response status code.
    pub status_code: u16,
    /// Response headers.
    pub response_headers: HashMap<String, String>,
    /// Response body (truncated to 10KB max).
    pub response_body: Option<String>,
    /// Whether the response body was truncated.
    pub truncated: bool,
    /// Names or paths whose values were redacted.
    pub redacted_fields: Vec<String>,
}

impl HttpEvidence {
    /// Create a new HTTP evidence capture.
    #[must_use]
    pub fn new(method: impl Into<String>, url: impl Into<String>, status_code: u16) -> Self {
        let url = url.into();
        let (url, fields) = redact_url(&url);
        let route = url::Url::parse(&url).ok().map(|url| url.path().to_string());
        Self {
            method: method.into(),
            url,
            route,
            parameter: None,
            authentication_persona: None,
            request_headers: HashMap::new(),
            request_body: None,
            status_code,
            response_headers: HashMap::new(),
            response_body: None,
            truncated: false,
            redacted_fields: fields,
        }
    }

    /// Attach the normalized application route.
    #[must_use]
    pub fn with_route(mut self, route: impl Into<String>) -> Self {
        self.route = Some(route.into());
        self
    }

    /// Attach the parameter identity without retaining its value.
    #[must_use]
    pub fn with_parameter(mut self, parameter: HttpParameterIdentity) -> Self {
        self.parameter = Some(parameter);
        self
    }

    /// Attach an operator-defined authentication persona label.
    #[must_use]
    pub fn with_authentication_persona(mut self, persona: impl Into<String>) -> Self {
        self.authentication_persona = Some(persona.into());
        self
    }

    /// Add request headers.
    #[must_use]
    pub fn with_request_headers(mut self, headers: HashMap<String, String>) -> Self {
        let (headers, fields) = redact_headers(headers, "request.header");
        self.request_headers = headers;
        self.redacted_fields.extend(fields);
        self.redacted_fields = normalized_redaction_fields(self.redacted_fields);
        self
    }

    /// Add a request body.
    #[must_use]
    pub fn with_request_body(mut self, body: impl Into<String>) -> Self {
        let body = body.into();
        let redacted = redact_text(&body);
        if redacted != body {
            self.redacted_fields.push("request.body".to_string());
        }
        self.request_body = Some(redacted);
        self.redacted_fields = normalized_redaction_fields(self.redacted_fields);
        self
    }

    /// Add response headers.
    #[must_use]
    pub fn with_response_headers(mut self, headers: HashMap<String, String>) -> Self {
        let (headers, fields) = redact_headers(headers, "response.header");
        self.response_headers = headers;
        self.redacted_fields.extend(fields);
        self.redacted_fields = normalized_redaction_fields(self.redacted_fields);
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
        let redacted = redact_text(&body);
        if redacted != body {
            self.redacted_fields.push("response.body".to_string());
        }
        if redacted.len() > MAX_BODY_SIZE {
            let boundary = floor_char_boundary(&redacted, MAX_BODY_SIZE);
            self.response_body = Some(redacted[..boundary].to_string());
            self.truncated = true;
        } else {
            self.response_body = Some(redacted);
        }
        self.redacted_fields = normalized_redaction_fields(self.redacted_fields);
        self
    }

    /// Return a clone whose public compatibility fields have been redacted again.
    #[must_use]
    pub fn redacted(mut self) -> Self {
        let (url, fields) = redact_url(&self.url);
        self.url = url;
        self.redacted_fields.extend(fields);
        let (request_headers, request_fields) =
            redact_headers(self.request_headers, "request.header");
        self.request_headers = request_headers;
        self.redacted_fields.extend(request_fields);
        let (response_headers, response_fields) =
            redact_headers(self.response_headers, "response.header");
        self.response_headers = response_headers;
        self.redacted_fields.extend(response_fields);
        if let Some(body) = self.request_body.take() {
            let redacted = redact_text(&body);
            if redacted != body {
                self.redacted_fields.push("request.body".to_string());
            }
            self.request_body = Some(redacted);
        }
        if let Some(body) = self.response_body.take() {
            let redacted = redact_text(&body);
            if redacted != body {
                self.redacted_fields.push("response.body".to_string());
            }
            if redacted.len() > MAX_BODY_SIZE {
                let boundary = floor_char_boundary(&redacted, MAX_BODY_SIZE);
                self.response_body = Some(redacted[..boundary].to_string());
                self.truncated = true;
            } else {
                self.response_body = Some(redacted);
            }
        }
        self.redacted_fields = normalized_redaction_fields(self.redacted_fields);
        self
    }

    /// Return the fields whose values were redacted.
    #[must_use]
    pub fn redacted_fields(&self) -> &[String] {
        &self.redacted_fields
    }
}

#[derive(Serialize, Deserialize)]
struct HttpEvidenceWire {
    method: String,
    url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parameter: Option<HttpParameterIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authentication_persona: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    request_headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_body: Option<String>,
    status_code: u16,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    response_headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    redacted_fields: Vec<String>,
}

impl From<HttpEvidence> for HttpEvidenceWire {
    fn from(evidence: HttpEvidence) -> Self {
        Self {
            method: evidence.method,
            url: evidence.url,
            route: evidence.route,
            parameter: evidence.parameter,
            authentication_persona: evidence.authentication_persona,
            request_headers: evidence.request_headers,
            request_body: evidence.request_body,
            status_code: evidence.status_code,
            response_headers: evidence.response_headers,
            response_body: evidence.response_body,
            truncated: evidence.truncated,
            redacted_fields: evidence.redacted_fields,
        }
    }
}

impl From<HttpEvidenceWire> for HttpEvidence {
    fn from(wire: HttpEvidenceWire) -> Self {
        Self {
            method: wire.method,
            url: wire.url,
            route: wire.route,
            parameter: wire.parameter,
            authentication_persona: wire.authentication_persona,
            request_headers: wire.request_headers,
            request_body: wire.request_body,
            status_code: wire.status_code,
            response_headers: wire.response_headers,
            response_body: wire.response_body,
            truncated: wire.truncated,
            redacted_fields: wire.redacted_fields,
        }
    }
}

impl Serialize for HttpEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        HttpEvidenceWire::from(self.clone().redacted()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HttpEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from(HttpEvidenceWire::deserialize(deserializer)?).redacted())
    }
}

fn redact_headers(
    headers: HashMap<String, String>,
    prefix: &str,
) -> (HashMap<String, String>, Vec<String>) {
    let mut fields = Vec::new();
    let headers = headers
        .into_iter()
        .map(|(name, value)| {
            if is_sensitive_key(&name) {
                fields.push(format!("{prefix}.{name}"));
                (name, "[REDACTED]".to_string())
            } else {
                (name, value)
            }
        })
        .collect();
    (headers, fields)
}

fn floor_char_boundary(value: &str, maximum: usize) -> usize {
    let mut boundary = maximum.min(value.len());
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
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

    #[test]
    fn http_evidence_redacts_secrets_and_retains_request_identity() {
        let mut request_headers = HashMap::new();
        request_headers.insert("Authorization".to_string(), "Bearer secret".to_string());
        request_headers.insert("Accept".to_string(), "application/json".to_string());
        let evidence = HttpEvidence::new(
            "POST",
            "https://example.com/login?next=%2Fhome&access_token=secret",
            401,
        )
        .with_route("/login")
        .with_parameter(HttpParameterIdentity::new("password", "body"))
        .with_authentication_persona("standard-user")
        .with_request_headers(request_headers)
        .with_request_body(r#"{"username":"alice","password":"secret"}"#)
        .with_response_body(r#"{"access_token":"secret"}"#);

        assert!(!evidence.url.contains("secret"));
        assert_eq!(
            evidence.request_headers.get("Authorization").map(String::as_str),
            Some("[REDACTED]")
        );
        assert!(evidence.request_body.as_deref().is_some_and(|body| !body.contains("secret")));
        assert_eq!(evidence.route.as_deref(), Some("/login"));
        assert_eq!(evidence.authentication_persona.as_deref(), Some("standard-user"));
        assert!(evidence.redacted_fields().contains(&"request.body".to_string()));
        assert!(evidence.redacted_fields().contains(&"response.body".to_string()));
    }

    #[test]
    fn response_truncation_respects_utf8_boundaries() {
        let body = format!("{}é", "a".repeat(MAX_BODY_SIZE - 1));
        let evidence =
            HttpEvidence::new("GET", "https://example.com", 200).with_response_body(body);
        assert!(evidence.truncated);
        assert_eq!(evidence.response_body.as_ref().map(String::len), Some(MAX_BODY_SIZE - 1));
    }

    #[test]
    fn redacted_rechecks_exact_truncation_boundaries() {
        let mut below = HttpEvidence::new("GET", "https://example.com", 200);
        below.response_body = Some("a".repeat(MAX_BODY_SIZE - 1));
        let below = below.redacted();
        assert!(!below.truncated);
        assert_eq!(below.response_body.as_ref().map(String::len), Some(MAX_BODY_SIZE - 1));

        let mut exact = HttpEvidence::new("GET", "https://example.com", 200);
        exact.response_body = Some("a".repeat(MAX_BODY_SIZE));
        let exact = exact.redacted();
        assert!(!exact.truncated);
        assert_eq!(exact.response_body.as_ref().map(String::len), Some(MAX_BODY_SIZE));

        let mut above = HttpEvidence::new("GET", "https://example.com", 200);
        above.response_body = Some("a".repeat(MAX_BODY_SIZE + 1));
        let above = above.redacted();
        assert!(above.truncated);
        assert_eq!(above.response_body.as_ref().map(String::len), Some(MAX_BODY_SIZE));
    }

    #[test]
    fn serde_reapplies_redaction_after_public_field_mutation() {
        let mut evidence = HttpEvidence::new("POST", "https://example.com/login", 401);
        evidence.url = "https://example.com/login?api_key=secret".to_string();
        evidence.request_headers.insert("Authorization".to_string(), "Bearer secret".to_string());
        evidence.request_body = Some(r#"{"password":"secret"}"#.to_string());
        evidence.response_body = Some(r#"{"access_token":"secret"}"#.to_string());

        let redacted = evidence.clone().redacted();
        assert!(redacted.request_body.as_deref().is_some_and(|body| !body.contains("secret")));
        assert!(redacted.response_body.as_deref().is_some_and(|body| !body.contains("secret")));
        assert!(redacted.redacted_fields().contains(&"request.body".to_string()));
        assert!(redacted.redacted_fields().contains(&"response.body".to_string()));

        let encoded = serde_json::to_string(&evidence).expect("serialize evidence");
        assert!(!encoded.contains("secret"));
        let restored: HttpEvidence = serde_json::from_str(&encoded).expect("deserialize evidence");
        assert!(restored.redacted_fields().contains(&"request.body".to_string()));
        assert!(restored.redacted_fields().contains(&"response.body".to_string()));
    }

    /// Verify finding integration via `with_http_evidence`.
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
