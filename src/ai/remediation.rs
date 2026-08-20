//! LLM-mediated remediation walks (WORK-141).
//!
//! Generates step-by-step remediation guidance for findings using
//! an AI provider. Produces ordered fix sequences prioritized by risk score
//! and dependency relationships (fix X before Y).

use std::fmt::Write;

use crate::ai::contracts::{AiProviderResponse, AiTask, RemediationRequest};
use crate::ai::provider::AiProvider;
use crate::ai::types::RemediationAnalysis;
use crate::engine::finding::Finding;
use crate::engine::risk_score::compute_risk_score;

/// A remediation step in a guided fix sequence.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RemediationStep {
    /// Step number (1-based).
    pub step: usize,
    /// Finding title being remediated.
    pub finding_title: String,
    /// Module that found the issue.
    pub module_id: String,
    /// Risk score of the finding.
    pub risk_score: f64,
    /// Remediation guidance.
    pub guidance: String,
    /// Estimated effort level.
    pub effort: &'static str,
}

/// Build a remediation walk — ordered steps to fix findings.
///
/// Prioritizes by risk score (highest first) and provides
/// the finding's built-in remediation guidance.
#[must_use]
pub fn build_remediation_walk(findings: &[Finding]) -> Vec<RemediationStep> {
    let mut scored: Vec<(usize, f64)> =
        findings.iter().enumerate().map(|(i, f)| (i, compute_risk_score(f))).collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    scored
        .iter()
        .enumerate()
        .map(|(step_num, (idx, score))| {
            let f = &findings[*idx];
            RemediationStep {
                step: step_num + 1,
                finding_title: crate::engine::observation::redact_text(&f.title),
                module_id: f.module_id.clone(),
                risk_score: *score,
                guidance: f.remediation.as_deref().map_or_else(
                    || "Review and remediate this finding.".into(),
                    crate::engine::observation::redact_text,
                ),
                effort: estimate_effort(f),
            }
        })
        .collect()
}

/// Provider guidance or the deterministic local fallback.
#[derive(Debug, Clone)]
pub enum RemediationOutcome {
    /// Valid typed provider guidance with labeled metadata.
    Provider(AiProviderResponse<RemediationAnalysis>),
    /// Risk-ordered scanner guidance used when AI cannot run or decode.
    Deterministic(Vec<RemediationStep>),
}

/// Request typed provider remediation with a deterministic fallback.
///
/// Callers that use a process-backed provider must authorize its external-tool
/// effect before calling this function.
pub async fn remediate_with_provider(
    provider: &dyn AiProvider,
    findings: &[Finding],
) -> RemediationOutcome {
    if provider.is_available() {
        let request = RemediationRequest::new(findings);
        match provider.remediate(&request).await {
            Ok(response) if response.validate_envelope(AiTask::Remediate).is_ok() => {
                return RemediationOutcome::Provider(response);
            }
            Ok(_) | Err(_) => {}
        }
    }
    RemediationOutcome::Deterministic(build_remediation_walk(findings))
}

/// Format a remediation walk as readable text.
#[must_use]
pub fn format_remediation_walk(steps: &[RemediationStep]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== Remediation Walk ({} steps) ===\n", steps.len());

    for step in steps {
        let _ = writeln!(
            out,
            "Step {} [Risk: {:.0}, Effort: {}]",
            step.step, step.risk_score, step.effort
        );
        let _ = writeln!(out, "  Finding: {} ({})", step.finding_title, step.module_id);
        let _ = writeln!(out, "  Action:  {}", step.guidance);
        out.push('\n');
    }

    out
}

/// Estimate effort based on finding characteristics.
fn estimate_effort(finding: &Finding) -> &'static str {
    if finding.module_id.contains("header") || finding.module_id == "misconfig" {
        "quick"
    } else if finding.module_id.contains("cloud")
        || finding.module_id.starts_with("aws-")
        || finding.module_id.starts_with("gcp-")
        || finding.module_id.starts_with("azure-")
    {
        "medium"
    } else {
        "significant"
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::ai::contracts::{
        AiProviderError, AiProviderMetadata, AiTask, AnalysisRequest, CorrelationRequest,
        PlanRequest, AI_CONTRACT_SCHEMA,
    };
    use crate::ai::types::{RemediationStep as TypedRemediationStep, ScanPlan, StructuredAnalysis};
    use crate::engine::correlation::AttackChain;
    use crate::engine::severity::Severity;

    #[derive(Debug)]
    struct RemediationProvider {
        available: bool,
        response: Result<AiProviderResponse<RemediationAnalysis>, AiProviderError>,
    }

    #[async_trait]
    impl AiProvider for RemediationProvider {
        fn id(&self) -> &'static str {
            "remediation-fixture"
        }

        fn name(&self) -> &'static str {
            "Remediation fixture"
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
            Err(AiProviderError::Disabled)
        }

        async fn remediate(
            &self,
            _request: &RemediationRequest,
        ) -> Result<AiProviderResponse<RemediationAnalysis>, AiProviderError> {
            self.response.clone()
        }
    }

    fn provider_response() -> AiProviderResponse<RemediationAnalysis> {
        AiProviderResponse {
            schema: AI_CONTRACT_SCHEMA,
            task: AiTask::Remediate,
            payload: RemediationAnalysis {
                remediations: vec![TypedRemediationStep {
                    finding_index: 1,
                    title: "XSS".to_string(),
                    severity: "high".to_string(),
                    fix_description: "Encode untrusted output".to_string(),
                    code_example: None,
                    effort: crate::ai::types::EffortLevel::Low,
                    priority: 1,
                    verification_steps: vec!["Run the XSS regression".to_string()],
                }],
                quick_wins: vec![1],
                total_estimated_effort: "two hours".to_string(),
            },
            metadata: AiProviderMetadata::default(),
            raw_response: "fixture".to_string(),
        }
    }

    fn finding(module_id: &str, title: &str, severity: Severity) -> Finding {
        Finding::new(module_id, severity, title, "desc", "https://example.com")
            .with_remediation("Fix this issue.")
            .with_confidence(0.8)
    }

    /// Remediation walk is ordered by risk score.
    #[test]
    fn test_build_remediation_walk_ordered() {
        let findings = vec![
            finding("headers", "Missing Header", Severity::Low),
            finding("injection", "SQL Injection", Severity::Critical),
            finding("ssl", "Weak TLS", Severity::Medium),
        ];
        let walk = build_remediation_walk(&findings);
        assert_eq!(walk.len(), 3);
        assert_eq!(walk.iter().map(|step| step.step).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(walk[0].finding_title, "SQL Injection"); // highest risk first
        assert!(walk[0].risk_score >= walk[1].risk_score);
    }

    /// Cloud findings get "medium" effort.
    #[test]
    fn test_effort_estimation() {
        for module_id in ["headers", "misconfig"] {
            assert_eq!(estimate_effort(&finding(module_id, "quick", Severity::Low)), "quick");
        }
        for module_id in ["cloud-posture", "aws-s3", "gcp-iam", "azure-storage"] {
            assert_eq!(estimate_effort(&finding(module_id, "medium", Severity::High)), "medium");
        }
        assert_eq!(estimate_effort(&finding("xss", "significant", Severity::High)), "significant");
    }

    /// Format produces readable output.
    #[test]
    fn test_format_remediation_walk() {
        let findings = vec![finding("xss", "XSS Found", Severity::High)];
        let walk = build_remediation_walk(&findings);
        let text = format_remediation_walk(&walk);
        assert!(text.contains("Remediation Walk"));
        assert!(text.contains("XSS Found"));
        assert!(text.contains("Fix this issue"));
    }

    #[test]
    fn deterministic_walk_redacts_mutated_finding_fields() {
        let mut finding = finding("xss", "safe", Severity::High);
        finding.title = "api_key=title-fixture-secret".to_string();
        finding.remediation = Some("token = 'guidance-fixture-secret'".to_string());
        let encoded = serde_json::to_string(&build_remediation_walk(&[finding]))
            .expect("serialize remediation walk");
        assert!(!encoded.contains("title-fixture-secret"));
        assert!(!encoded.contains("guidance-fixture-secret"));
        assert!(encoded.contains("REDACTED"));
    }

    #[tokio::test]
    async fn typed_provider_guidance_wins_when_valid() {
        let findings = vec![finding("xss", "XSS", Severity::High)];
        let provider = RemediationProvider { available: true, response: Ok(provider_response()) };
        let outcome = remediate_with_provider(&provider, &findings).await;
        match outcome {
            RemediationOutcome::Provider(response) => {
                assert_eq!(response.payload.remediations[0].title, "XSS");
            }
            RemediationOutcome::Deterministic(_) => panic!("valid provider response was ignored"),
        }
    }

    #[tokio::test]
    async fn unavailable_or_failed_provider_uses_deterministic_walk() {
        let findings = vec![finding("xss", "XSS", Severity::High)];
        for provider in [
            RemediationProvider { available: false, response: Ok(provider_response()) },
            RemediationProvider {
                available: true,
                response: Err(AiProviderError::MalformedResponse { task: AiTask::Remediate }),
            },
            RemediationProvider {
                available: true,
                response: Ok(AiProviderResponse {
                    schema: "scorchkit.ai/v0",
                    ..provider_response()
                }),
            },
        ] {
            match remediate_with_provider(&provider, &findings).await {
                RemediationOutcome::Deterministic(steps) => {
                    assert_eq!(steps.len(), 1);
                    assert_eq!(steps[0].finding_title, "XSS");
                }
                RemediationOutcome::Provider(_) => {
                    panic!("fallback branch returned provider guidance")
                }
            }
        }
    }
}
