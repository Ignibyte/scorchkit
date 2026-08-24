use serde::{Deserialize, Serialize};

use crate::EXTENSION_PROTOCOL_V1;

/// Input supplied by the engine under an opaque invocation-local identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionInvocationInputV1 {
    pub id: String,
    pub media_type: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

/// Initial bounded guest invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionInvocationV1 {
    pub protocol_version: String,
    pub invocation_id: String,
    pub extension_id: String,
    pub target: String,
    pub inputs: Vec<ExtensionInvocationInputV1>,
}

/// Credential-free HTTP methods supported by the v1 broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionHttpMethodV1 {
    Get,
    Head,
}

/// One guest effect request. Unsupported classes remain explicit typed denials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionEffectV1 {
    Http { method: ExtensionHttpMethodV1, url: String },
    Input { input_id: String },
    Filesystem { operation: String },
    Credential { operation: String },
    Subprocess { operation: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionEffectRequestV1 {
    pub request_id: String,
    pub effect: ExtensionEffectV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionEffectDecisionV1 {
    Allowed,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionEffectResultV1 {
    pub request_id: String,
    pub decision: ExtensionEffectDecisionV1,
    pub status: Option<u16>,
    pub media_type: Option<String>,
    pub body: Vec<u8>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionObservationV1 {
    pub kind: String,
    pub message: String,
    pub location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionEvidenceV1 {
    pub kind: String,
    pub value: serde_json::Value,
    pub source_artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionArtifactV1 {
    pub id: String,
    pub media_type: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionFindingV1 {
    pub title: String,
    pub description: String,
    pub affected_target: String,
    pub severity: String,
    pub confidence: f64,
    pub remediation: Option<String>,
    pub owasp_category: Option<String>,
    pub cwe_id: Option<u32>,
    pub observations: Vec<ExtensionObservationV1>,
    pub evidence: Vec<ExtensionEvidenceV1>,
    pub source_artifacts: Vec<ExtensionArtifactV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionOutputV1 {
    pub findings: Vec<ExtensionFindingV1>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionFailureV1 {
    pub code: String,
    pub message: String,
}

/// Input for one guest state-machine turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionTurnInputV1 {
    Start(ExtensionInvocationV1),
    EffectResult(ExtensionEffectResultV1),
}

/// Output from one guest state-machine turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionTurnOutputV1 {
    EffectRequest(ExtensionEffectRequestV1),
    Complete(ExtensionOutputV1),
    Failure(ExtensionFailureV1),
}

impl ExtensionInvocationV1 {
    #[must_use]
    pub fn new(
        invocation_id: impl Into<String>,
        extension_id: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: EXTENSION_PROTOCOL_V1.to_string(),
            invocation_id: invocation_id.into(),
            extension_id: extension_id.into(),
            target: target.into(),
            inputs: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_protocol_round_trips_without_host_handles() {
        let turn = ExtensionTurnInputV1::Start(ExtensionInvocationV1::new(
            "invocation-1",
            "fixture.extension",
            "http://127.0.0.1/",
        ));
        let encoded = serde_json::to_vec(&turn).expect("encode turn");
        let decoded: ExtensionTurnInputV1 = serde_json::from_slice(&encoded).expect("decode turn");
        assert_eq!(decoded, turn);
        let text = String::from_utf8(encoded).expect("json text");
        for forbidden in ["database", "postgres", "engagement", "canonical_path", "policy_memory"] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn turn_protocol_rejects_unknown_members_at_every_enum_boundary() {
        let unknown_effect = serde_json::json!({
            "kind": "http",
            "method": "get",
            "url": "http://127.0.0.1/",
            "credential": "forbidden"
        });
        assert!(serde_json::from_value::<ExtensionEffectV1>(unknown_effect).is_err());

        let unknown_turn = serde_json::json!({
            "kind": "failure",
            "value": {"code": "fixture", "message": "safe"},
            "host_handle": "forbidden"
        });
        assert!(serde_json::from_value::<ExtensionTurnOutputV1>(unknown_turn).is_err());
    }
}
