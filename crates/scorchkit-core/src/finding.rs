use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::evidence::HttpEvidence;
use super::observation::{
    redact_text, redact_url, AgentAnalysisRecord, CorrelationKey, EvidenceRecord, FindingRecordV2,
    ObservationLocation, ScannerProvenance,
};
use super::severity::Severity;

/// Default confidence score for findings (medium — unknown detection strength).
const fn default_confidence() -> f64 {
    0.5
}

/// A single finding from a scan module.
#[derive(Debug, Clone)]
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
    pub evidence: Option<String>,
    /// Remediation suggestion.
    pub remediation: Option<String>,
    /// OWASP category reference (e.g., "A05:2021").
    pub owasp_category: Option<String>,
    /// CWE ID if applicable.
    pub cwe_id: Option<u32>,
    /// Compliance framework control references (NIST, PCI-DSS, SOC2, HIPAA).
    pub compliance: Option<Vec<String>>,
    /// Captured HTTP request/response pair for `PoC` replay.
    pub http_evidence: Option<HttpEvidence>,
    /// Confidence score (0.0–1.0) indicating false-positive likelihood.
    ///
    /// Higher values mean higher confidence the finding is a true positive.
    /// Defaults to 0.5 for unknown detection strength.
    pub confidence: f64,
    /// Timestamp when found.
    pub timestamp: DateTime<Utc>,
    /// Canonical versioned application-security observation.
    pub appsec: FindingRecordV2,
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
        let module_id = module_id.into();
        let title = title.into();
        let affected_target = redact_url(&affected_target.into()).0;
        let timestamp = Utc::now();
        let appsec =
            FindingRecordV2::from_legacy(&module_id, &title, &affected_target, None, timestamp);
        Self {
            module_id,
            severity,
            title,
            description: description.into(),
            affected_target,
            evidence: None,
            remediation: None,
            owasp_category: None,
            cwe_id: None,
            compliance: None,
            http_evidence: None,
            confidence: default_confidence(),
            timestamp,
            appsec,
        }
    }

    #[must_use]
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        let evidence = redact_text(&evidence.into());
        self.evidence = Some(evidence.clone());
        self.appsec.evidence.push(EvidenceRecord::text(evidence, self.appsec.provenance.clone()));
        self
    }

    #[must_use]
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    #[must_use]
    pub fn with_owasp(mut self, category: impl Into<String>) -> Self {
        self.owasp_category = Some(category.into());
        self
    }

    #[must_use]
    pub fn with_cwe(mut self, cwe_id: u32) -> Self {
        self.cwe_id = Some(cwe_id);
        self.appsec.refresh_identity(&self.module_id, &self.title, self.cwe_id);
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
        let evidence = evidence.redacted();
        self.appsec
            .evidence
            .push(EvidenceRecord::http(evidence.clone(), self.appsec.provenance.clone()));
        self.http_evidence = Some(evidence);
        self
    }

    /// Replace the conservatively inferred location with scanner-supplied precision.
    #[must_use]
    pub fn with_location(mut self, location: ObservationLocation) -> Self {
        self.appsec.location = location.redacted();
        self.appsec.refresh_identity(&self.module_id, &self.title, self.cwe_id);
        self
    }

    /// Attach scanner, rule, configuration, and target-revision provenance.
    #[must_use]
    pub fn with_provenance(mut self, provenance: ScannerProvenance) -> Self {
        self.appsec.evidence = self
            .appsec
            .evidence
            .into_iter()
            .map(|evidence| evidence.with_provenance(provenance.clone()))
            .collect();
        self.appsec.provenance = provenance;
        self.appsec.refresh_identity(&self.module_id, &self.title, self.cwe_id);
        self
    }

    /// Add an explicit cross-scanner correlation key.
    #[must_use]
    pub fn with_correlation_key(mut self, key: CorrelationKey) -> Self {
        self.appsec.correlation_keys.push(key);
        self.appsec.refresh_identity(&self.module_id, &self.title, self.cwe_id);
        self
    }

    /// Attach explicitly labeled agent interpretation without modifying scanner evidence.
    #[must_use]
    pub fn with_agent_analysis(mut self, analysis: AgentAnalysisRecord) -> Self {
        self.appsec.agent_analysis.push(analysis);
        self
    }

    /// Return a normalized v2 record derived from the current compatibility fields.
    ///
    /// This is the consumption boundary used by reports and storage. It protects callers that
    /// mutate public legacy fields after construction from producing stale identities.
    #[must_use]
    pub fn canonical_appsec(&self) -> FindingRecordV2 {
        let mut record = self.appsec.clone();
        if record.provenance.scanner_id.is_empty() {
            record.provenance.scanner_id.clone_from(&self.module_id);
        }
        if let ObservationLocation::Legacy { value } = &record.location {
            if value != &self.affected_target {
                record.location = ObservationLocation::infer(&self.affected_target);
            }
        }
        record.location = record.location.redacted();

        record.evidence = record.evidence.into_iter().map(EvidenceRecord::normalized).collect();
        if let Some(evidence) = &self.evidence {
            record.evidence.push(EvidenceRecord::text(evidence, record.provenance.clone()));
        }
        if let Some(evidence) = &self.http_evidence {
            record.evidence.push(EvidenceRecord::http(evidence.clone(), record.provenance.clone()));
        }
        record.evidence.sort_by(|left, right| left.identity.cmp(&right.identity));
        record.evidence.dedup_by(|left, right| left.identity == right.identity);
        record.agent_analysis =
            record.agent_analysis.into_iter().map(AgentAnalysisRecord::normalized).collect();
        record.agent_analysis.sort_by(|left, right| left.identity.cmp(&right.identity));
        record.agent_analysis.dedup_by(|left, right| left.identity == right.identity);
        record.refresh_identity(&self.module_id, &self.title, self.cwe_id);
        record
    }

    /// Set the confidence score (0.0–1.0) for this finding.
    ///
    /// Values are clamped to the valid range. Higher values indicate
    /// greater certainty the finding is a true positive.
    #[must_use]
    pub const fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

#[derive(Serialize)]
struct FindingSerialize<'a> {
    module_id: &'a str,
    severity: Severity,
    title: &'a str,
    description: &'a str,
    affected_target: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owasp_category: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwe_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compliance: Option<&'a Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_evidence: Option<HttpEvidence>,
    confidence: f64,
    timestamp: DateTime<Utc>,
    appsec: FindingRecordV2,
}

impl Serialize for Finding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let evidence = self.evidence.as_deref().map(redact_text);
        let affected_target = redact_url(&self.affected_target).0;
        FindingSerialize {
            module_id: &self.module_id,
            severity: self.severity,
            title: &self.title,
            description: &self.description,
            affected_target: &affected_target,
            evidence: evidence.as_deref(),
            remediation: self.remediation.as_deref(),
            owasp_category: self.owasp_category.as_deref(),
            cwe_id: self.cwe_id,
            compliance: self.compliance.as_ref(),
            http_evidence: self.http_evidence.clone().map(HttpEvidence::redacted),
            confidence: self.confidence,
            timestamp: self.timestamp,
            appsec: self.canonical_appsec(),
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
struct FindingDeserialize {
    module_id: String,
    severity: Severity,
    title: String,
    description: String,
    affected_target: String,
    evidence: Option<String>,
    remediation: Option<String>,
    owasp_category: Option<String>,
    cwe_id: Option<u32>,
    compliance: Option<Vec<String>>,
    http_evidence: Option<HttpEvidence>,
    #[serde(default = "default_confidence")]
    confidence: f64,
    timestamp: DateTime<Utc>,
    #[serde(default)]
    appsec: Option<FindingRecordV2>,
}

impl<'de> Deserialize<'de> for Finding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = FindingDeserialize::deserialize(deserializer)?;
        let evidence = wire.evidence.map(|value| redact_text(&value));
        let affected_target = redact_url(&wire.affected_target).0;
        let http_evidence = wire.http_evidence.map(HttpEvidence::redacted);
        let appsec = wire.appsec.unwrap_or_else(|| {
            FindingRecordV2::from_legacy(
                &wire.module_id,
                &wire.title,
                &affected_target,
                wire.cwe_id,
                wire.timestamp,
            )
        });
        let mut finding = Self {
            module_id: wire.module_id,
            severity: wire.severity,
            title: wire.title,
            description: wire.description,
            affected_target,
            evidence,
            remediation: wire.remediation,
            owasp_category: wire.owasp_category,
            cwe_id: wire.cwe_id,
            compliance: wire.compliance,
            http_evidence,
            confidence: wire.confidence,
            timestamp: wire.timestamp,
            appsec,
        };
        finding.appsec = finding.canonical_appsec();
        Ok(finding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the full builder chain sets all fields correctly,
    /// including the new confidence score.
    #[test]
    fn finding_builder_chain() {
        let f = Finding::new("test", Severity::High, "Title", "Desc", "https://example.com")
            .with_evidence("evidence")
            .with_remediation("fix it")
            .with_owasp("A01:2021")
            .with_cwe(79)
            .with_confidence(0.9);

        assert_eq!(f.module_id, "test");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.evidence.as_deref(), Some("evidence"));
        assert_eq!(f.remediation.as_deref(), Some("fix it"));
        assert_eq!(f.owasp_category.as_deref(), Some("A01:2021"));
        assert_eq!(f.cwe_id, Some(79));
        assert!((f.confidence - 0.9).abs() < f64::EPSILON);
    }

    /// Verify optional fields default to None and confidence defaults to 0.5.
    #[test]
    fn finding_optional_fields_default_none() {
        let f = Finding::new("test", Severity::Info, "T", "D", "url");
        assert!(f.evidence.is_none());
        assert!(f.remediation.is_none());
        assert!(f.owasp_category.is_none());
        assert!(f.cwe_id.is_none());
        assert!(f.compliance.is_none());
    }

    /// Verify JSON serialization skips None fields but includes confidence.
    #[test]
    fn finding_serializes_without_none_fields() {
        let f = Finding::new("test", Severity::Low, "T", "D", "url");
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("evidence"));
        assert!(!json.contains("remediation"));
        assert!(!json.contains("owasp_category"));
        assert!(!json.contains("cwe_id"));
        assert!(json.contains("confidence"));
    }

    /// Verify `Finding::new()` sets confidence to the default value of 0.5.
    #[test]
    fn finding_default_confidence() {
        let f = Finding::new("test", Severity::Info, "T", "D", "url");
        assert!((f.confidence - 0.5).abs() < f64::EPSILON);
    }

    /// Verify `.with_confidence()` sets the confidence score.
    #[test]
    fn finding_with_confidence_builder() {
        let f = Finding::new("test", Severity::High, "T", "D", "url").with_confidence(0.9);
        assert!((f.confidence - 0.9).abs() < f64::EPSILON);
    }

    /// Verify confidence values are clamped to the 0.0–1.0 range.
    #[test]
    fn finding_confidence_clamps() {
        let over = Finding::new("test", Severity::High, "T", "D", "url").with_confidence(1.5);
        assert!((over.confidence - 1.0).abs() < f64::EPSILON);

        let under = Finding::new("test", Severity::High, "T", "D", "url").with_confidence(-0.3);
        assert!(under.confidence.abs() < f64::EPSILON);
    }

    /// Verify JSON round-trip preserves the confidence score.
    #[test]
    fn finding_confidence_serialization() {
        let f = Finding::new("test", Severity::Medium, "T", "D", "url").with_confidence(0.8);
        let json = serde_json::to_string(&f).unwrap();
        let restored: Finding = serde_json::from_str(&json).unwrap();
        assert!((restored.confidence - 0.8).abs() < f64::EPSILON);
    }

    /// Verify deserializing old JSON without a confidence field defaults to 0.5.
    #[test]
    fn finding_confidence_deserialize_missing() {
        let json = r#"{
            "module_id": "test",
            "severity": "high",
            "title": "T",
            "description": "D",
            "affected_target": "url",
            "timestamp": "2026-01-01T00:00:00Z"
        }"#;
        let f: Finding = serde_json::from_str(json).unwrap();
        assert!((f.confidence - 0.5).abs() < f64::EPSILON);
        assert_eq!(f.appsec.schema, super::super::observation::FINDING_SCHEMA_V2);
    }

    #[test]
    fn legacy_json_upgrades_and_v2_round_trip_is_stable() {
        let json = r#"{
            "module_id": "semgrep",
            "severity": "high",
            "title": "Rule",
            "description": "Description",
            "affected_target": "src/main.rs:12",
            "evidence": "password=secret",
            "timestamp": "2026-01-01T00:00:00Z"
        }"#;
        let finding: Finding = serde_json::from_str(json).unwrap();
        assert!(matches!(finding.appsec.location, ObservationLocation::Source { .. }));
        assert_eq!(finding.evidence.as_deref(), Some("password=%5BREDACTED%5D"));

        let encoded = serde_json::to_string(&finding).unwrap();
        assert!(encoded.contains("scorchkit.finding/v2"));
        assert!(!encoded.contains("secret"));
        let restored: Finding = serde_json::from_str(&encoded).unwrap();
        assert_eq!(finding.appsec.identity, restored.appsec.identity);
    }

    #[test]
    fn agent_analysis_remains_separate_from_scanner_evidence() {
        let finding = Finding::new("scanner", Severity::High, "T", "D", "src/lib.rs:3")
            .with_evidence("scanner proof")
            .with_agent_analysis(AgentAnalysisRecord::new(
                "codex-security",
                Some("trusted-security".to_string()),
                "Validated source-to-sink path",
                Vec::new(),
                Utc::now(),
            ));
        assert_eq!(finding.appsec.evidence.len(), 1);
        assert_eq!(finding.appsec.agent_analysis.len(), 1);
        let value = serde_json::to_value(&finding).unwrap();
        assert!(value["appsec"]["evidence"].is_array());
        assert!(value["appsec"]["agent_analysis"].is_array());
    }

    #[test]
    fn canonical_appsec_repairs_mutated_legacy_location_and_provenance() {
        let mut finding = Finding::new("semgrep", Severity::High, "Rule", "Desc", "opaque");
        finding.appsec.provenance.scanner_id.clear();
        finding.affected_target = "src/app.rs:19".to_string();

        let canonical = finding.canonical_appsec();
        assert_eq!(canonical.provenance.scanner_id, "semgrep");
        assert!(matches!(
            canonical.location,
            ObservationLocation::Source {
                ref path,
                region: Some(super::super::observation::SourceRegion { start_line: 19, .. })
            } if path == "src/app.rs"
        ));
    }

    #[test]
    fn canonical_appsec_deduplicates_evidence_and_agent_analysis() {
        let analysis = AgentAnalysisRecord::new(
            "codex-security",
            Some("trusted-security".to_string()),
            "Validated source-to-sink path",
            Vec::new(),
            Utc::now(),
        );
        let mut finding = Finding::new("semgrep", Severity::High, "Rule", "Desc", "src/app.rs:19")
            .with_evidence("scanner proof")
            .with_agent_analysis(analysis.clone());
        finding
            .appsec
            .evidence
            .push(EvidenceRecord::text("scanner proof", finding.appsec.provenance.clone()));
        finding.appsec.agent_analysis.push(analysis);

        let canonical = finding.canonical_appsec();
        assert_eq!(canonical.evidence.len(), 1);
        assert_eq!(canonical.agent_analysis.len(), 1);
    }
}
