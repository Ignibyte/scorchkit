//! Provider-neutral external-adapter execution and coverage evidence.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Current adapter execution assessment schema.
pub const ADAPTER_EXECUTION_ASSESSMENT_SCHEMA_V1: &str =
    "scorchkit.adapter-execution-assessment/v1";

/// Terminal integrity state for one external adapter execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterExecutionStatus {
    /// Every selected input was verified and the adapter completed normally.
    Complete,
    /// An applicable prerequisite was absent before execution.
    Incomplete,
    /// Verification, execution, or output validation failed.
    Degraded,
}

/// Stable class for one adapter coverage gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterExecutionGapKind {
    ConfigurationUnavailable,
    InputRejected,
    SignatureRejected,
    UnsupportedCapability,
    VersionUnsupported,
    ExecutionFailed,
    OutputInvalid,
}

/// One exact approved input consumed by an external adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterInputIdentity {
    /// Input class such as `nuclei_template` or `rule_pack`.
    pub kind: String,
    /// Stable provider-defined input identifier.
    pub id: String,
    /// Lowercase SHA-256 of the exact consumed bytes.
    pub sha256: String,
    /// Trusted signing identity, when the input format supports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_identity: Option<String>,
}

impl AdapterInputIdentity {
    #[must_use]
    pub fn new(kind: impl Into<String>, id: impl Into<String>, sha256: impl Into<String>) -> Self {
        Self { kind: kind.into(), id: id.into(), sha256: sha256.into(), signer_identity: None }
    }

    #[must_use]
    pub fn with_signer(mut self, signer_identity: impl Into<String>) -> Self {
        self.signer_identity = Some(signer_identity.into());
        self
    }
}

/// One redacted explanation for incomplete or degraded adapter coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterExecutionGap {
    pub kind: AdapterExecutionGapKind,
    pub component: String,
    #[serde(
        serialize_with = "serialize_redacted_string",
        deserialize_with = "deserialize_redacted_string"
    )]
    pub detail: String,
}

impl AdapterExecutionGap {
    #[must_use]
    pub fn new(
        kind: AdapterExecutionGapKind,
        component: impl Into<String>,
        detail: impl AsRef<str>,
    ) -> Self {
        Self {
            kind,
            component: component.into(),
            detail: crate::observation::redact_text(detail.as_ref()),
        }
    }
}

/// Reproducible execution evidence for one external adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterExecutionAssessment {
    pub schema_version: String,
    pub adapter_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strongest_effect: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<AdapterInputIdentity>,
    pub status: AdapterExecutionStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<AdapterExecutionGap>,
}

impl AdapterExecutionAssessment {
    #[must_use]
    pub fn new(adapter_id: impl Into<String>) -> Self {
        Self {
            schema_version: ADAPTER_EXECUTION_ASSESSMENT_SCHEMA_V1.to_string(),
            adapter_id: adapter_id.into(),
            tool_version: None,
            configuration_identity: None,
            strongest_effect: None,
            inputs: Vec::new(),
            status: AdapterExecutionStatus::Complete,
            gaps: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_gap(mut self, status: AdapterExecutionStatus, gap: AdapterExecutionGap) -> Self {
        self.status = status;
        self.gaps.push(gap);
        self
    }
}

fn serialize_redacted_string<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&crate::observation::redact_text(value))
}

fn deserialize_redacted_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(|value| crate::observation::redact_text(&value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assessment_defaults_to_complete_and_keeps_exact_input_identity() {
        let mut assessment = AdapterExecutionAssessment::new("nuclei");
        assessment.inputs.push(
            AdapterInputIdentity::new("nuclei_template", "probe", "a".repeat(64))
                .with_signer("fixture-signer"),
        );

        assert_eq!(assessment.status, AdapterExecutionStatus::Complete);
        assert_eq!(assessment.inputs[0].id, "probe");
        assert_eq!(assessment.schema_version, ADAPTER_EXECUTION_ASSESSMENT_SCHEMA_V1);
    }

    #[test]
    fn gap_diagnostics_are_redacted_on_construction_and_round_trip() {
        let assessment = AdapterExecutionAssessment::new("nuclei").with_gap(
            AdapterExecutionStatus::Degraded,
            AdapterExecutionGap::new(
                AdapterExecutionGapKind::ExecutionFailed,
                "scan",
                "Authorization: Bearer fixture-secret",
            ),
        );
        let encoded = serde_json::to_string(&assessment).expect("serialize assessment");
        assert!(!encoded.contains("fixture-secret"));
        let decoded: AdapterExecutionAssessment =
            serde_json::from_str(&encoded).expect("deserialize assessment");
        assert_eq!(decoded.status, AdapterExecutionStatus::Degraded);
        assert!(!decoded.gaps[0].detail.contains("fixture-secret"));
    }
}
