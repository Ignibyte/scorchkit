//! Provider-neutral AI-guided scan planner.
//!
//! The internal `ScanPlanner` implements a two-phase approach: first runs reconnaissance
//! modules to gather target intelligence, then feeds those findings plus a
//! catalog of available scan modules to the configured provider. It returns a structured
//! [`ScanPlan`] specifying which modules to run and why.

use std::sync::Arc;

use crate::ai::contracts::{AiModuleInput, AiProviderError, AiTask, PlanRequest};
use crate::ai::provider::{provider_from_config, AiProvider};
use crate::ai::types::{validate_plan, ScanPlan};
use crate::config::AiConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::module_trait::ModuleCategory;
use crate::engine::target::Target;
use crate::facade::Engine;
use crate::runner::orchestrator::{application_modules, Orchestrator};
fn unknown_modules_for_warning(modules: &[String]) -> Option<&[String]> {
    (!modules.is_empty()).then_some(modules)
}

/// AI-powered scan planner that analyzes recon results to build a targeted strategy.
#[derive(Debug)]
pub(crate) struct ScanPlanner {
    provider: Arc<dyn AiProvider>,
}

impl ScanPlanner {
    /// Create a new planner from AI config.
    #[must_use]
    pub fn from_config(config: &AiConfig) -> Self {
        Self { provider: provider_from_config(config) }
    }

    /// Check if the configured AI provider is available.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.provider.is_available()
    }

    /// Human-readable configured provider name.
    #[must_use]
    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    /// Run recon, then ask the configured provider to build a scan plan.
    ///
    /// 1. Runs all recon modules against the target
    /// 2. Builds a module catalog from all available modules
    /// 3. Sends recon findings + catalog to the configured provider
    /// 4. Parses and validates the response into a [`ScanPlan`]
    ///
    /// # Errors
    ///
    /// Returns an error if the recon phase fails or the configured provider
    /// cannot be executed. Parse failures are handled gracefully by
    /// returning an empty plan.
    pub async fn plan(&self, target: &Target, engine: &Engine) -> Result<ScanPlan> {
        // Phase A: Run recon
        let ctx = engine.dast_context_for_target(target.clone(), "quick")?;

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile("quick");
        orchestrator.filter_by_category(ModuleCategory::Recon);

        let recon_result = orchestrator.run(true).await?;

        // Phase B: Build prompt and call the configured provider.
        let modules = application_modules();
        let request = PlanRequest::new(
            target.url.as_str(),
            &recon_result.findings,
            AiModuleInput::collect(&modules),
            None,
        );

        let raw_plan = self.run_provider(&request, &target.raw).await?;

        let known_ids: Vec<&str> = modules.iter().map(|m| m.id()).collect();
        let validation = validate_plan(&raw_plan, &known_ids);

        if let Some(unknown_modules) = unknown_modules_for_warning(&validation.unknown_modules) {
            tracing::warn!(
                unknown = ?unknown_modules,
                "scan plan contained unknown module IDs — these were removed"
            );
        }

        Ok(ScanPlan {
            target: raw_plan.target,
            recommendations: validation.valid_recommendations,
            skipped_modules: raw_plan.skipped_modules,
            overall_strategy: raw_plan.overall_strategy,
            estimated_scan_time: raw_plan.estimated_scan_time,
        })
    }

    /// Run the configured provider with a typed request.
    async fn run_provider(&self, request: &PlanRequest, scan_id: &str) -> Result<ScanPlan> {
        let response = self.provider.plan(request).await.map_err(|error| {
            ScorchError::AiAnalysis(format!("AI planning failed for scan {scan_id}: {error}"))
        })?;
        response.validate_envelope(AiTask::Plan).map_err(|error| {
            ScorchError::AiAnalysis(format!("AI planning failed for scan {scan_id}: {error}"))
        })?;
        if response.payload.target != request.target {
            return Err(ScorchError::AiAnalysis(format!(
                "AI planning failed for scan {scan_id}: {}",
                AiProviderError::InvalidPayload {
                    task: AiTask::Plan,
                    detail: "response target does not match request target".to_string(),
                }
            )));
        }
        Ok(response.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::contracts::{
        AiProviderError, AiProviderMetadata, AiProviderResponse, AiTask, AnalysisRequest,
        CorrelationRequest, RemediationRequest, AI_CONTRACT_SCHEMA,
    };
    use crate::ai::types::{RemediationAnalysis, StructuredAnalysis};
    use crate::engine::correlation::AttackChain;

    #[derive(Debug)]
    struct StubProvider {
        response: std::result::Result<AiProviderResponse<ScanPlan>, AiProviderError>,
    }

    #[async_trait::async_trait]
    impl AiProvider for StubProvider {
        fn id(&self) -> &'static str {
            "stub"
        }

        fn name(&self) -> &'static str {
            "Stub provider"
        }

        fn is_available(&self) -> bool {
            true
        }

        async fn plan(
            &self,
            _request: &PlanRequest,
        ) -> std::result::Result<AiProviderResponse<ScanPlan>, AiProviderError> {
            self.response.clone()
        }

        async fn analyze(
            &self,
            _request: &AnalysisRequest,
        ) -> std::result::Result<AiProviderResponse<StructuredAnalysis>, AiProviderError> {
            Err(AiProviderError::Disabled)
        }

        async fn correlate(
            &self,
            _request: &CorrelationRequest,
        ) -> std::result::Result<AiProviderResponse<Vec<AttackChain>>, AiProviderError> {
            Err(AiProviderError::Disabled)
        }

        async fn remediate(
            &self,
            _request: &RemediationRequest,
        ) -> std::result::Result<AiProviderResponse<RemediationAnalysis>, AiProviderError> {
            Err(AiProviderError::Disabled)
        }
    }

    fn plan_request() -> PlanRequest {
        PlanRequest::new("https://example.com", &[], Vec::new(), None)
    }

    fn plan_response() -> AiProviderResponse<ScanPlan> {
        AiProviderResponse {
            schema: AI_CONTRACT_SCHEMA,
            task: AiTask::Plan,
            payload: ScanPlan {
                target: "https://example.com".to_string(),
                recommendations: Vec::new(),
                skipped_modules: Vec::new(),
                overall_strategy: "exact plan".to_string(),
                estimated_scan_time: None,
            },
            metadata: AiProviderMetadata { model: Some("fixture".to_string()), cost_usd: None },
            raw_response: "fixture response".to_string(),
        }
    }

    #[test]
    fn configured_binary_controls_planner_availability() {
        let available_binary = std::env::current_exe()
            .unwrap_or_else(|error| panic!("failed to resolve current test executable: {error}"))
            .to_string_lossy()
            .into_owned();
        let available = AiConfig { binary: Some(available_binary), ..AiConfig::default() };
        let available_planner = ScanPlanner::from_config(&available);
        assert!(available_planner.is_available());
        assert_eq!(available_planner.provider_name(), "Codex CLI");

        let unavailable = AiConfig {
            binary: Some("scorchkit-ai-host-that-does-not-exist-31ce8fc1".to_string()),
            ..AiConfig::default()
        };
        assert!(!ScanPlanner::from_config(&unavailable).is_available());

        let disabled = AiConfig { enabled: false, ..AiConfig::default() };
        assert_eq!(ScanPlanner::from_config(&disabled).provider_name(), "No AI provider");
    }

    #[tokio::test]
    async fn run_provider_returns_content_and_labels_errors() {
        let planner =
            ScanPlanner { provider: Arc::new(StubProvider { response: Ok(plan_response()) }) };
        assert_eq!(
            planner
                .run_provider(&plan_request(), "scan-42")
                .await
                .expect("provider response")
                .overall_strategy,
            "exact plan"
        );

        let failing = ScanPlanner {
            provider: Arc::new(StubProvider {
                response: Err(AiProviderError::Execution {
                    provider: "Stub provider".to_string(),
                    detail: "fixture failure".to_string(),
                }),
            }),
        };
        let error = failing
            .run_provider(&plan_request(), "scan-42")
            .await
            .expect_err("provider error should be labeled");
        assert_eq!(
            error.to_string(),
            "AI analysis failed: AI planning failed for scan scan-42: Stub provider host failed: fixture failure"
        );

        let wrong_envelope = ScanPlanner {
            provider: Arc::new(StubProvider {
                response: Ok(AiProviderResponse { task: AiTask::Analyze, ..plan_response() }),
            }),
        };
        let error = wrong_envelope
            .run_provider(&plan_request(), "scan-42")
            .await
            .expect_err("cross-task provider response must fail");
        assert!(error.to_string().contains("does not match expected task plan"));
    }

    #[test]
    fn warning_selection_distinguishes_empty_and_unknown_modules() {
        assert_eq!(unknown_modules_for_warning(&[]), None);

        let unknown = vec!["invented-one".to_string(), "invented-two".to_string()];
        assert_eq!(unknown_modules_for_warning(&unknown), Some(unknown.as_slice()));
    }
}
