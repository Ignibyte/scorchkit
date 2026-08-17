//! Typed provider augmentation for deterministic attack-chain correlation.
//!
//! The rule engine remains authoritative and always runs. A valid typed AI
//! response may add chains, but provider failure cannot remove rule results or
//! change scan success.

use crate::ai::contracts::{AiTask, CorrelationRequest};
use crate::ai::provider::AiProvider;
use crate::engine::correlation::{correlate, AttackChain};
use crate::engine::finding::Finding;

/// Correlate findings with deterministic rules and optional typed AI augmentation.
///
/// Callers that use a process-backed provider must authorize its external-tool
/// effect before calling this function. An unavailable or failed provider is a
/// no-op over the deterministic rule result.
pub async fn correlate_with_provider(
    provider: &dyn AiProvider,
    findings: &[Finding],
) -> Vec<AttackChain> {
    let mut chains = correlate(findings);
    if !provider.is_available() {
        return chains;
    }

    let request = CorrelationRequest::new(findings);
    match provider.correlate(&request).await {
        Ok(response) if response.validate_envelope(AiTask::Correlate).is_ok() => {
            for candidate in response.payload {
                if !chains.iter().any(|chain| chain.name == candidate.name) {
                    chains.push(candidate);
                }
            }
        }
        Ok(_) | Err(_) => {}
    }
    chains
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::ai::contracts::{
        AiProviderError, AiProviderMetadata, AiProviderResponse, AiTask, AnalysisRequest,
        PlanRequest, RemediationRequest, AI_CONTRACT_SCHEMA,
    };
    use crate::ai::types::{RemediationAnalysis, ScanPlan, StructuredAnalysis};
    use crate::engine::correlation::ChainStep;
    use crate::engine::severity::Severity;

    #[derive(Debug)]
    struct CorrelationProvider {
        available: bool,
        response: Result<AiProviderResponse<Vec<AttackChain>>, AiProviderError>,
    }

    #[async_trait]
    impl AiProvider for CorrelationProvider {
        fn id(&self) -> &'static str {
            "correlation-fixture"
        }

        fn name(&self) -> &'static str {
            "Correlation fixture"
        }

        fn is_available(&self) -> bool {
            self.available
        }

        async fn plan(
            &self,
            _request: &PlanRequest,
        ) -> Result<AiProviderResponse<ScanPlan>, AiProviderError> {
            Err(AiProviderError::Disabled)
        }

        async fn analyze(
            &self,
            _request: &AnalysisRequest,
        ) -> Result<AiProviderResponse<StructuredAnalysis>, AiProviderError> {
            Err(AiProviderError::Disabled)
        }

        async fn correlate(
            &self,
            _request: &CorrelationRequest,
        ) -> Result<AiProviderResponse<Vec<AttackChain>>, AiProviderError> {
            self.response.clone()
        }

        async fn remediate(
            &self,
            _request: &RemediationRequest,
        ) -> Result<AiProviderResponse<RemediationAnalysis>, AiProviderError> {
            Err(AiProviderError::Disabled)
        }
    }

    fn finding(module_id: &str, title: &str, severity: Severity) -> Finding {
        Finding::new(module_id, severity, title, "desc", "https://example.com")
    }

    fn ai_chain(name: &str) -> AttackChain {
        AttackChain {
            name: name.to_string(),
            severity: Severity::High,
            description: "AI fixture".to_string(),
            steps: vec![ChainStep {
                module_id: "xss".to_string(),
                title: "Reflected XSS".to_string(),
                role: "entry".to_string(),
            }],
            remediation_priority: "high".to_string(),
        }
    }

    fn response(chains: Vec<AttackChain>) -> AiProviderResponse<Vec<AttackChain>> {
        AiProviderResponse {
            schema: AI_CONTRACT_SCHEMA,
            task: AiTask::Correlate,
            payload: chains,
            metadata: AiProviderMetadata::default(),
            raw_response: "fixture".to_string(),
        }
    }

    fn findings() -> Vec<Finding> {
        vec![
            finding("xss", "Reflected XSS", Severity::High),
            finding("headers", "Missing CSP", Severity::Medium),
        ]
    }

    #[tokio::test]
    async fn typed_provider_adds_unique_chains_and_preserves_rule_results() {
        let provider = CorrelationProvider {
            available: true,
            response: Ok(response(vec![ai_chain("AI-Discovered Chain")])),
        };
        let chains = correlate_with_provider(&provider, &findings()).await;
        assert!(chains.iter().any(|chain| chain.name.contains("Session Hijacking")));
        assert!(chains.iter().any(|chain| chain.name == "AI-Discovered Chain"));
    }

    #[tokio::test]
    async fn typed_provider_duplicate_is_not_appended() {
        let duplicate = "Session Hijacking via XSS + Weak CSP";
        let provider = CorrelationProvider {
            available: true,
            response: Ok(response(vec![ai_chain(duplicate)])),
        };
        let chains = correlate_with_provider(&provider, &findings()).await;
        assert_eq!(chains.iter().filter(|chain| chain.name == duplicate).count(), 1);
    }

    #[tokio::test]
    async fn unavailable_or_failed_provider_returns_exact_rule_fallback() {
        for provider in [
            CorrelationProvider {
                available: false,
                response: Ok(response(vec![ai_chain("must not appear")])),
            },
            CorrelationProvider {
                available: true,
                response: Err(AiProviderError::MalformedResponse { task: AiTask::Correlate }),
            },
            CorrelationProvider {
                available: true,
                response: Ok(AiProviderResponse {
                    task: AiTask::Plan,
                    ..response(vec![ai_chain("wrong-task")])
                }),
            },
        ] {
            let chains = correlate_with_provider(&provider, &findings()).await;
            assert_eq!(chains.len(), 1);
            assert!(chains[0].name.contains("Session Hijacking"));
        }
    }
}
