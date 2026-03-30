use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::evidence::HttpEvidence;
use super::severity::Severity;

/// A single finding from a scan module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Which module produced this finding.
    pub module_id: String,
    /// Severity classification.
    pub severity: Severity,
    /// Short title (e.g., "Missing HSTS Header").
    pub title: String,
    /// Detailed description of the issue.
    pub description: String,
    /// The affected URL, header, parameter, etc.
    pub affected_target: String,
    /// Raw evidence (response snippet, header value, tool output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Remediation suggestion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// OWASP category reference (e.g., "A05:2021").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp_category: Option<String>,
    /// CWE ID if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe_id: Option<u32>,
    /// Compliance framework control references (NIST, PCI-DSS, SOC2, HIPAA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<Vec<String>>,
    /// Captured HTTP request/response pair for PoC replay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_evidence: Option<HttpEvidence>,
    /// Timestamp when found.
    pub timestamp: DateTime<Utc>,
}

impl Finding {
    /// Create a new finding with required fields; optional fields default to `None`.
    pub fn new(
        module_id: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
        affected_target: impl Into<String>,
    ) -> Self {
        Self {
            module_id: module_id.into(),
            severity,
            title: title.into(),
            description: description.into(),
            affected_target: affected_target.into(),
            evidence: None,
            remediation: None,
            owasp_category: None,
            cwe_id: None,
            compliance: None,
            http_evidence: None,
            timestamp: Utc::now(),
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn with_owasp(mut self, category: impl Into<String>) -> Self {
        self.owasp_category = Some(category.into());
        self
    }

    #[must_use]
    pub const fn with_cwe(mut self, cwe_id: u32) -> Self {
        self.cwe_id = Some(cwe_id);
        self
    }

    /// Attach compliance framework control references to this finding.
    #[must_use]
    pub fn with_compliance(mut self, controls: Vec<String>) -> Self {
        self.compliance = Some(controls);
        self
    }

    /// Attach an HTTP request/response evidence capture to this finding.
    #[must_use]
    pub fn with_http_evidence(mut self, evidence: HttpEvidence) -> Self {
        self.http_evidence = Some(evidence);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_builder_chain() {
        let f = Finding::new("test", Severity::High, "Title", "Desc", "https://example.com")
            .with_evidence("evidence")
            .with_remediation("fix it")
            .with_owasp("A01:2021")
            .with_cwe(79);

        assert_eq!(f.module_id, "test");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.evidence.as_deref(), Some("evidence"));
        assert_eq!(f.remediation.as_deref(), Some("fix it"));
        assert_eq!(f.owasp_category.as_deref(), Some("A01:2021"));
        assert_eq!(f.cwe_id, Some(79));
    }

    #[test]
    fn finding_optional_fields_default_none() {
        let f = Finding::new("test", Severity::Info, "T", "D", "url");
        assert!(f.evidence.is_none());
        assert!(f.remediation.is_none());
        assert!(f.owasp_category.is_none());
        assert!(f.cwe_id.is_none());
        assert!(f.compliance.is_none());
    }

    #[test]
    fn finding_serializes_without_none_fields() {
        let f = Finding::new("test", Severity::Low, "T", "D", "url");
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("evidence"));
        assert!(!json.contains("remediation"));
        assert!(!json.contains("owasp_category"));
        assert!(!json.contains("cwe_id"));
    }
}
