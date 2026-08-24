use std::sync::Arc;

use chrono::Utc;
use scorchkit::config::ModelAnalysisConfig;
use scorchkit::engine::events::EventBus;
use scorchkit::engine::policy::{Engagement, EngagementPolicy};
use scorchkit::model_analysis::ModelAnalysisService;
use scorchkit::{
    ModelAnalysisInput, ModelAnalysisProvenance, ModelAnalysisRequest, ModelAnalysisResponse,
    ModelExecutionLocation, ModelReadinessState, ModelResponsePayload, ModelRole,
    MODEL_ANALYSIS_CONTRACT_V1,
};

#[test]
fn public_model_contract_round_trip_preserves_exact_provenance() {
    let request = ModelAnalysisRequest::analysis(
        "host",
        "exact-model",
        ModelRole::FindingValidation,
        "workflow/v1",
        vec![ModelAnalysisInput::new("1".repeat(64), "scanner proof").expect("input")],
        "validate",
    )
    .expect("request");
    let response = ModelAnalysisResponse {
        schema: MODEL_ANALYSIS_CONTRACT_V1.to_string(),
        provider: "host".to_string(),
        model: "exact-model".to_string(),
        role: ModelRole::FindingValidation,
        payload: ModelResponsePayload::Analysis {
            summary: "Supported".to_string(),
            confidence_bps: 8_700,
            evidence_digests: vec!["1".repeat(64)],
        },
    };
    let provenance = ModelAnalysisProvenance::from_validated_response(
        &request,
        &response,
        ModelExecutionLocation::HostManaged,
        Utc::now(),
    )
    .expect("provenance");
    let encoded = serde_json::to_string(&provenance).expect("JSON");
    let decoded: ModelAnalysisProvenance = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded, provenance);
    decoded.validate().expect("valid provenance");
}

#[test]
fn public_service_reports_all_disabled_roles_without_executing_an_adapter() {
    let service = ModelAnalysisService::new(
        ModelAnalysisConfig::default(),
        Arc::new(Engagement::new("no model effects", EngagementPolicy::default())),
        EventBus::default(),
    );
    let readiness = service.readiness();
    assert_eq!(readiness.len(), ModelRole::ALL.len());
    assert!(readiness.iter().all(|item| item.state == ModelReadinessState::Disabled));
    assert_eq!(readiness[0].role, ModelRole::Planning);
    assert_eq!(readiness[5].role, ModelRole::Verification);
}
