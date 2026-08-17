//! Public compile and serde contracts for provider-neutral AI reasoning.

use std::sync::Arc;

use async_trait::async_trait;
use scorchkit::ai::contracts::{
    AiContractRequest, AiProviderError, AiProviderMetadata, AiProviderResponse, AiScanSummary,
    AiTask, AnalysisRequest, CorrelationRequest, PlanRequest, RemediationRequest,
    AI_CONTRACT_SCHEMA,
};
use scorchkit::ai::prompts::AnalysisFocus;
use scorchkit::ai::provider::{AiProvider, NoOpProvider};
use scorchkit::ai::types::{RemediationAnalysis, ScanPlan, StructuredAnalysis, SummaryAnalysis};
use scorchkit::engine::correlation::AttackChain;

#[derive(Debug)]
struct TypedFixtureProvider;

fn response<T>(task: AiTask, payload: T) -> AiProviderResponse<T> {
    AiProviderResponse {
        schema: AI_CONTRACT_SCHEMA,
        task,
        payload,
        metadata: AiProviderMetadata {
            model: Some("fixture-model".to_string()),
            cost_usd: Some(0.01),
        },
        raw_response: "fixture".to_string(),
    }
}

#[async_trait]
impl AiProvider for TypedFixtureProvider {
    fn id(&self) -> &'static str {
        "typed-fixture"
    }

    fn name(&self) -> &'static str {
        "Typed fixture"
    }

    fn is_available(&self) -> bool {
        true
    }

    async fn plan(
        &self,
        request: &PlanRequest,
    ) -> Result<AiProviderResponse<ScanPlan>, AiProviderError> {
        Ok(response(
            AiTask::Plan,
            ScanPlan {
                target: request.target.clone(),
                recommendations: Vec::new(),
                skipped_modules: Vec::new(),
                overall_strategy: "fixture".to_string(),
                estimated_scan_time: None,
            },
        ))
    }

    async fn analyze(
        &self,
        _request: &AnalysisRequest,
    ) -> Result<AiProviderResponse<StructuredAnalysis>, AiProviderError> {
        Ok(response(
            AiTask::Analyze,
            StructuredAnalysis::Summary(SummaryAnalysis {
                risk_score: 1.0,
                executive_summary: "fixture".to_string(),
                key_findings: Vec::new(),
                attack_surface: "fixture".to_string(),
                business_impact: "fixture".to_string(),
            }),
        ))
    }

    async fn correlate(
        &self,
        _request: &CorrelationRequest,
    ) -> Result<AiProviderResponse<Vec<AttackChain>>, AiProviderError> {
        Ok(response(AiTask::Correlate, Vec::new()))
    }

    async fn remediate(
        &self,
        _request: &RemediationRequest,
    ) -> Result<AiProviderResponse<RemediationAnalysis>, AiProviderError> {
        Ok(response(
            AiTask::Remediate,
            RemediationAnalysis {
                remediations: Vec::new(),
                quick_wins: Vec::new(),
                total_estimated_effort: "none".to_string(),
            },
        ))
    }
}

fn analysis_request() -> AnalysisRequest {
    AnalysisRequest {
        focus: AnalysisFocus::Summary,
        scan_id: "scan-1".to_string(),
        target: "https://example.com".to_string(),
        summary: AiScanSummary {
            total_findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            modules_run: 0,
        },
        findings: Vec::new(),
        project_context: None,
    }
}

#[tokio::test]
async fn typed_trait_dispatches_all_four_operations() -> Result<(), Box<dyn std::error::Error>> {
    let provider: Arc<dyn AiProvider> = Arc::new(TypedFixtureProvider);
    let plan_request = PlanRequest::new("https://example.com", &[], Vec::new(), None);

    let plan = provider.plan(&plan_request).await?;
    assert_eq!(plan.task, AiTask::Plan);
    assert_eq!(plan.payload.target, "https://example.com");

    let analysis = provider.analyze(&analysis_request()).await?;
    assert_eq!(analysis.task, AiTask::Analyze);
    assert!(matches!(analysis.payload, StructuredAnalysis::Summary(_)));

    let correlation = provider.correlate(&CorrelationRequest { findings: Vec::new() }).await?;
    assert_eq!(correlation.task, AiTask::Correlate);
    assert!(correlation.payload.is_empty());

    let remediation = provider.remediate(&RemediationRequest { findings: Vec::new() }).await?;
    assert_eq!(remediation.task, AiTask::Remediate);
    assert_eq!(remediation.payload.total_estimated_effort, "none");
    Ok(())
}

#[tokio::test]
async fn disabled_provider_returns_the_same_typed_error_for_every_task() {
    let provider = NoOpProvider;
    let plan = PlanRequest::new("https://example.com", &[], Vec::new(), None);
    let analysis = analysis_request();
    let correlation = CorrelationRequest { findings: Vec::new() };
    let remediation = RemediationRequest { findings: Vec::new() };

    assert_eq!(provider.plan(&plan).await.expect_err("disabled plan"), AiProviderError::Disabled);
    assert_eq!(
        provider.analyze(&analysis).await.expect_err("disabled analysis"),
        AiProviderError::Disabled
    );
    assert_eq!(
        provider.correlate(&correlation).await.expect_err("disabled correlation"),
        AiProviderError::Disabled
    );
    assert_eq!(
        provider.remediate(&remediation).await.expect_err("disabled remediation"),
        AiProviderError::Disabled
    );
}

#[test]
fn versioned_request_envelopes_round_trip_every_task() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (AiTask::Plan, serde_json::json!({"target":"https://example.com"})),
        (AiTask::Analyze, serde_json::json!({"focus":"summary"})),
        (AiTask::Correlate, serde_json::json!({"findings":[]})),
        (AiTask::Remediate, serde_json::json!({"findings":[]})),
    ];
    for (task, input) in cases {
        let request = AiContractRequest { schema: AI_CONTRACT_SCHEMA.to_string(), task, input };
        let encoded = serde_json::to_string(&request)?;
        let decoded: AiContractRequest<serde_json::Value> = serde_json::from_str(&encoded)?;
        assert_eq!(decoded.schema, AI_CONTRACT_SCHEMA);
        assert_eq!(decoded.task, task);
    }
    Ok(())
}

#[test]
fn provider_trait_has_no_raw_generation_method() {
    let source = include_str!("../src/ai/provider.rs");
    let forbidden = ["async fn ", "generate("].concat();
    assert!(!source.contains(&forbidden));
    for method in
        ["async fn plan(", "async fn analyze(", "async fn correlate(", "async fn remediate("]
    {
        assert!(source.contains(method), "provider trait omitted {method}");
    }
}
