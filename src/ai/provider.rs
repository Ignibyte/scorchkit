//! Provider-neutral typed AI task boundary.
//!
//! The built-in adapter favors Codex in non-interactive, read-only mode. A
//! Claude CLI adapter remains available for compatibility. Callers consume
//! typed responses and do not need to understand either CLI's response format.

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::ai::contracts::{
    decode_contract, render_contract, validate_analysis_payload, AiProviderError,
    AiProviderMetadata, AiProviderResponse, AiTask, AnalysisRequest, CorrelationRequest,
    PlanRequest, RemediationRequest, RenderedContract, AI_CONTRACT_SCHEMA,
};
use crate::ai::types::{RemediationAnalysis, ScanPlan, StructuredAnalysis};
use crate::config::{AiConfig, AiProviderKind};
use crate::engine::correlation::AttackChain;
use crate::runner::subprocess::{
    ExitPolicy, SystemToolExecutor, ToolExecutor, ToolInvocation, DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
};

const AI_PROCESS_TIMEOUT: Duration = Duration::from_mins(5);

/// An AI provider that implements `ScorchKit`'s four typed reasoning tasks.
#[async_trait]
pub trait AiProvider: Debug + Send + Sync {
    /// Stable provider identifier.
    fn id(&self) -> &'static str;

    /// Human-readable provider name.
    fn name(&self) -> &'static str;

    /// Whether this provider's configured host executable is available.
    fn is_available(&self) -> bool;

    /// Build a typed scan plan.
    async fn plan(
        &self,
        request: &PlanRequest,
    ) -> Result<AiProviderResponse<ScanPlan>, AiProviderError>;

    /// Analyze findings in a non-remediation focus mode.
    async fn analyze(
        &self,
        request: &AnalysisRequest,
    ) -> Result<AiProviderResponse<StructuredAnalysis>, AiProviderError>;

    /// Correlate findings into compound attack paths.
    async fn correlate(
        &self,
        request: &CorrelationRequest,
    ) -> Result<AiProviderResponse<Vec<AttackChain>>, AiProviderError>;

    /// Produce detailed remediation guidance.
    async fn remediate(
        &self,
        request: &RemediationRequest,
    ) -> Result<AiProviderResponse<RemediationAnalysis>, AiProviderError>;
}

/// Built-in, policy-constrained CLI adapter.
#[derive(Debug)]
pub(crate) struct CliAiProvider {
    kind: AiProviderKind,
    binary: String,
    model: Option<String>,
    max_budget_usd: Option<f64>,
    executor: Arc<dyn ToolExecutor>,
}

impl CliAiProvider {
    fn from_config(config: &AiConfig) -> Self {
        Self::with_executor(config, Arc::new(SystemToolExecutor))
    }

    fn with_executor(config: &AiConfig, executor: Arc<dyn ToolExecutor>) -> Self {
        Self {
            kind: config.provider,
            binary: config.resolved_binary().to_string(),
            model: config.model.clone().filter(|model| !model.trim().is_empty()),
            max_budget_usd: config.max_budget_usd,
            executor,
        }
    }

    fn invocation(&self, contract: &RenderedContract) -> ToolInvocation {
        match self.kind {
            AiProviderKind::Codex => self.codex_invocation(&contract.system, &contract.user),
            AiProviderKind::Claude => self.claude_invocation(&contract.system, &contract.user),
        }
    }

    fn codex_invocation(&self, system: &str, user: &str) -> ToolInvocation {
        let mut args = vec![
            "--ask-for-approval".to_string(),
            "never".to_string(),
            "exec".to_string(),
            "--sandbox".to_string(),
            "read-only".to_string(),
            "--ephemeral".to_string(),
            "--ignore-user-config".to_string(),
            "--ignore-rules".to_string(),
            "--color".to_string(),
            "never".to_string(),
        ];
        if let Some(model) = &self.model {
            args.extend(["--model".to_string(), model.clone()]);
        }
        args.push("-".to_string());

        ToolInvocation {
            program: self.binary.clone(),
            args,
            timeout: AI_PROCESS_TIMEOUT,
            exit_policy: ExitPolicy::RequireSuccess,
            output_limit_bytes: DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
            stdin: Some(combine_prompts(system, user).into_bytes()),
        }
    }

    fn claude_invocation(&self, system: &str, user: &str) -> ToolInvocation {
        let mut args = vec![
            "-p".to_string(),
            user.to_string(),
            "--system-prompt".to_string(),
            system.to_string(),
            "--output-format".to_string(),
            "json".to_string(),
            "--max-turns".to_string(),
            "1".to_string(),
        ];
        if let Some(model) = &self.model {
            args.extend(["--model".to_string(), model.clone()]);
        }
        if let Some(budget) = self.max_budget_usd.filter(|budget| *budget > 0.0) {
            args.extend(["--max-budget-usd".to_string(), budget.to_string()]);
        }

        ToolInvocation {
            program: self.binary.clone(),
            args,
            timeout: AI_PROCESS_TIMEOUT,
            exit_policy: ExitPolicy::RequireSuccess,
            output_limit_bytes: DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
            stdin: None,
        }
    }

    fn normalize_response(&self, stdout: &str) -> NormalizedProviderOutput {
        if self.kind == AiProviderKind::Claude {
            if let Ok(envelope) = serde_json::from_str::<serde_json::Value>(stdout) {
                let content = envelope["result"]
                    .as_str()
                    .or_else(|| envelope["content"].as_str())
                    .unwrap_or(stdout)
                    .to_string();
                return NormalizedProviderOutput {
                    content,
                    metadata: AiProviderMetadata {
                        model: envelope["model"]
                            .as_str()
                            .map(String::from)
                            .or_else(|| self.model.clone()),
                        cost_usd: envelope["cost_usd"].as_f64(),
                    },
                };
            }
        }

        NormalizedProviderOutput {
            content: stdout.to_string(),
            metadata: AiProviderMetadata { model: self.model.clone(), cost_usd: None },
        }
    }

    async fn execute_task<I, O>(
        &self,
        task: AiTask,
        request: &I,
    ) -> Result<AiProviderResponse<O>, AiProviderError>
    where
        I: Clone + Serialize + Sync,
        O: DeserializeOwned,
    {
        if !self.is_available() {
            return Err(AiProviderError::Unavailable { provider: self.name().to_string() });
        }
        let contract = render_contract(task, request)?;
        let output = self.executor.execute(self.invocation(&contract)).await.map_err(|error| {
            AiProviderError::Execution {
                provider: self.name().to_string(),
                detail: error.to_string(),
            }
        })?;
        let normalized = self.normalize_response(&output.stdout);
        let payload = decode_contract(task, &normalized.content)?;
        Ok(AiProviderResponse {
            schema: AI_CONTRACT_SCHEMA,
            task,
            payload,
            metadata: normalized.metadata,
            raw_response: normalized.content,
        })
    }
}

#[derive(Debug)]
struct NormalizedProviderOutput {
    content: String,
    metadata: AiProviderMetadata,
}

#[async_trait]
impl AiProvider for CliAiProvider {
    fn id(&self) -> &'static str {
        match self.kind {
            AiProviderKind::Codex => "codex-cli",
            AiProviderKind::Claude => "claude-cli",
        }
    }

    fn name(&self) -> &'static str {
        match self.kind {
            AiProviderKind::Codex => "Codex CLI",
            AiProviderKind::Claude => "Claude CLI",
        }
    }

    fn is_available(&self) -> bool {
        crate::runner::subprocess::is_tool_available(&self.binary)
    }

    async fn plan(
        &self,
        request: &PlanRequest,
    ) -> Result<AiProviderResponse<ScanPlan>, AiProviderError> {
        let response: AiProviderResponse<ScanPlan> =
            self.execute_task(AiTask::Plan, request).await?;
        if response.payload.target != request.target {
            return Err(AiProviderError::InvalidPayload {
                task: AiTask::Plan,
                detail: "response target does not match request target".to_string(),
            });
        }
        Ok(response)
    }

    async fn analyze(
        &self,
        request: &AnalysisRequest,
    ) -> Result<AiProviderResponse<StructuredAnalysis>, AiProviderError> {
        let response: AiProviderResponse<StructuredAnalysis> =
            self.execute_task(AiTask::Analyze, request).await?;
        validate_analysis_payload(request.focus, &response.payload)?;
        Ok(response)
    }

    async fn correlate(
        &self,
        request: &CorrelationRequest,
    ) -> Result<AiProviderResponse<Vec<AttackChain>>, AiProviderError> {
        self.execute_task(AiTask::Correlate, request).await
    }

    async fn remediate(
        &self,
        request: &RemediationRequest,
    ) -> Result<AiProviderResponse<RemediationAnalysis>, AiProviderError> {
        self.execute_task(AiTask::Remediate, request).await
    }
}

/// A no-op provider for disabled AI operation.
#[derive(Debug, Default)]
pub struct NoOpProvider;

#[async_trait]
impl AiProvider for NoOpProvider {
    fn id(&self) -> &'static str {
        "none"
    }

    fn name(&self) -> &'static str {
        "No AI provider"
    }

    fn is_available(&self) -> bool {
        false
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
        Err(AiProviderError::Disabled)
    }
}

pub(crate) fn provider_from_config(config: &AiConfig) -> Arc<dyn AiProvider> {
    if config.enabled {
        Arc::new(CliAiProvider::from_config(config))
    } else {
        Arc::new(NoOpProvider)
    }
}

fn combine_prompts(system: &str, user: &str) -> String {
    format!("SYSTEM INSTRUCTIONS:\n{system}\n\nUSER REQUEST:\n{user}")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use super::*;
    use crate::ai::contracts::AiScanSummary;
    use crate::ai::prompts::AnalysisFocus;
    use crate::ai::types::{EffortLevel, SummaryAnalysis};
    use crate::engine::error::Result;
    use crate::runner::subprocess::ToolOutput;

    fn available_binary() -> String {
        std::env::current_exe().expect("current test executable").to_string_lossy().into_owned()
    }

    fn plan_request() -> PlanRequest {
        PlanRequest::new("https://example.com", &[], Vec::new(), None)
    }

    fn plan_response() -> String {
        serde_json::json!({
            "schema": AI_CONTRACT_SCHEMA,
            "task": "plan",
            "payload": {
                "target": "https://example.com",
                "recommendations": [],
                "skipped_modules": [],
                "overall_strategy": "fixture",
                "estimated_scan_time": null
            }
        })
        .to_string()
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

    fn set_task_response(
        executor: &RecordingExecutor,
        kind: AiProviderKind,
        task: AiTask,
        payload: &serde_json::Value,
    ) {
        let contract = serde_json::json!({
            "schema": AI_CONTRACT_SCHEMA,
            "task": task,
            "payload": payload,
        })
        .to_string();
        let stdout = if kind == AiProviderKind::Claude {
            serde_json::json!({
                "result": contract,
                "model": "shared-fixture-model",
                "cost_usd": 0.01
            })
            .to_string()
        } else {
            contract
        };
        *executor.stdout.lock().expect("stdout lock") = stdout;
    }

    #[derive(Debug, Default)]
    struct RecordingExecutor {
        invocations: Mutex<Vec<ToolInvocation>>,
        stdout: Mutex<String>,
    }

    #[async_trait]
    impl ToolExecutor for RecordingExecutor {
        async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput> {
            self.invocations.lock().expect("invocation lock").push(invocation);
            Ok(ToolOutput {
                stdout: self.stdout.lock().expect("stdout lock").clone(),
                stderr: String::new(),
                exit_code: 0,
                duration: Duration::ZERO,
                resolved_program: PathBuf::from("/mock/provider"),
            })
        }
    }

    #[tokio::test]
    async fn codex_is_default_and_runs_ephemeral_read_only() {
        let executor = Arc::new(RecordingExecutor::default());
        *executor.stdout.lock().expect("stdout lock") = plan_response();
        let config = AiConfig { binary: Some(available_binary()), ..AiConfig::default() };
        let provider = CliAiProvider::with_executor(&config, executor.clone());

        let response = provider.plan(&plan_request()).await.expect("typed plan");
        assert_eq!(provider.id(), "codex-cli");
        assert_eq!(provider.name(), "Codex CLI");
        assert_eq!(response.payload.target, "https://example.com");
        assert_eq!(response.task, AiTask::Plan);

        let invocation = executor
            .invocations
            .lock()
            .expect("invocation lock")
            .first()
            .cloned()
            .expect("recorded invocation");
        assert_eq!(invocation.program, available_binary());
        assert!(invocation.args.windows(2).any(|pair| pair == ["--sandbox", "read-only"]));
        assert!(invocation.args.iter().any(|argument| argument == "--ephemeral"));
        assert!(invocation.args.iter().any(|argument| argument == "--ignore-user-config"));
        assert_eq!(invocation.args.last().map(String::as_str), Some("-"));
        let stdin = String::from_utf8(invocation.stdin.expect("Codex stdin")).expect("UTF-8");
        assert!(stdin.contains("SYSTEM INSTRUCTIONS:"));
        assert!(stdin.contains(AI_CONTRACT_SCHEMA));
        assert!(stdin.contains("\"task\": \"plan\""));
    }

    #[tokio::test]
    async fn claude_adapter_normalizes_legacy_envelope() {
        let executor = Arc::new(RecordingExecutor::default());
        *executor.stdout.lock().expect("stdout lock") = serde_json::json!({
            "result": plan_response(),
            "model": "compat-model",
            "cost_usd": 0.04
        })
        .to_string();
        let config = AiConfig {
            provider: AiProviderKind::Claude,
            binary: Some(available_binary()),
            model: Some("requested-model".to_string()),
            max_budget_usd: Some(0.5),
            ..AiConfig::default()
        };
        let provider = CliAiProvider::with_executor(&config, executor.clone());

        let response = provider.plan(&plan_request()).await.expect("typed plan");
        assert_eq!(provider.name(), "Claude CLI");
        assert_eq!(response.payload.overall_strategy, "fixture");
        assert_eq!(response.metadata.model.as_deref(), Some("compat-model"));
        assert_eq!(response.metadata.cost_usd, Some(0.04));

        let invocation = executor
            .invocations
            .lock()
            .expect("invocation lock")
            .first()
            .cloned()
            .expect("recorded invocation");
        assert_eq!(invocation.program, available_binary());
        assert!(invocation
            .args
            .windows(2)
            .any(|pair| { pair[0] == "--system-prompt" && pair[1].contains(AI_CONTRACT_SCHEMA) }));
        assert!(invocation
            .args
            .windows(2)
            .any(|pair| { pair[0] == "-p" && pair[1].contains("\"task\": \"plan\"") }));
        assert!(invocation.args.windows(2).any(|pair| pair == ["--model", "requested-model"]));
        assert!(invocation.args.windows(2).any(|pair| pair == ["--max-budget-usd", "0.5"]));
    }

    #[tokio::test]
    async fn codex_and_claude_share_all_four_typed_contracts() {
        for kind in [AiProviderKind::Codex, AiProviderKind::Claude] {
            let executor = Arc::new(RecordingExecutor::default());
            let config = AiConfig {
                provider: kind,
                binary: Some(available_binary()),
                ..AiConfig::default()
            };
            let provider = CliAiProvider::with_executor(&config, executor.clone());

            set_task_response(
                &executor,
                kind,
                AiTask::Plan,
                &serde_json::from_str::<serde_json::Value>(&plan_response())
                    .expect("plan envelope")["payload"],
            );
            assert_eq!(
                provider.plan(&plan_request()).await.expect("plan").payload.overall_strategy,
                "fixture"
            );

            set_task_response(
                &executor,
                kind,
                AiTask::Analyze,
                &serde_json::json!({
                    "type": "summary",
                    "risk_score": 2.0,
                    "executive_summary": "fixture",
                    "key_findings": [],
                    "attack_surface": "fixture",
                    "business_impact": "fixture"
                }),
            );
            let analysis = provider.analyze(&analysis_request()).await.expect("analysis");
            assert!(matches!(
                analysis.payload,
                StructuredAnalysis::Summary(SummaryAnalysis { .. })
            ));

            set_task_response(&executor, kind, AiTask::Correlate, &serde_json::json!([]));
            assert!(provider
                .correlate(&CorrelationRequest { findings: Vec::new() })
                .await
                .expect("correlation")
                .payload
                .is_empty());

            set_task_response(
                &executor,
                kind,
                AiTask::Remediate,
                &serde_json::json!({
                    "remediations": [{
                        "finding_index": 1,
                        "title": "fixture",
                        "severity": "low",
                        "fix_description": "fix",
                        "code_example": null,
                        "effort": "trivial",
                        "priority": 1,
                        "verification_steps": ["verify"]
                    }],
                    "quick_wins": [1],
                    "total_estimated_effort": "one hour"
                }),
            );
            let remediation = provider
                .remediate(&RemediationRequest { findings: Vec::new() })
                .await
                .expect("remediation");
            assert_eq!(remediation.payload.remediations[0].title, "fixture");
            assert_eq!(remediation.payload.remediations[0].effort, EffortLevel::Trivial);

            let invocations = executor.invocations.lock().expect("invocation lock");
            assert_eq!(invocations.len(), 4);
            for (task, invocation) in
                [AiTask::Plan, AiTask::Analyze, AiTask::Correlate, AiTask::Remediate]
                    .into_iter()
                    .zip(invocations.iter())
            {
                let contract = if kind == AiProviderKind::Codex {
                    String::from_utf8(invocation.stdin.clone().expect("Codex stdin"))
                        .expect("UTF-8")
                } else {
                    invocation
                        .args
                        .windows(2)
                        .find(|pair| pair[0] == "-p")
                        .map(|pair| pair[1].clone())
                        .expect("Claude prompt")
                };
                assert!(contract.contains(AI_CONTRACT_SCHEMA));
                assert!(contract.contains(&format!("\"task\": \"{task}\"")));
                assert!(contract.contains("\"input\""));
            }
        }
    }

    #[tokio::test]
    async fn unavailable_binary_fails_before_executor_effects() {
        let executor = Arc::new(RecordingExecutor::default());
        let config = AiConfig {
            binary: Some("scorchkit-missing-provider-binary-21f2c95f".to_string()),
            ..AiConfig::default()
        };
        let provider = CliAiProvider::with_executor(&config, executor.clone());
        let error = provider.plan(&plan_request()).await.expect_err("unavailable provider");
        assert_eq!(error, AiProviderError::Unavailable { provider: "Codex CLI".to_string() });
        assert!(executor.invocations.lock().expect("invocation lock").is_empty());
    }

    #[tokio::test]
    async fn plan_target_mismatch_is_not_typed_success() {
        let executor = Arc::new(RecordingExecutor::default());
        *executor.stdout.lock().expect("stdout lock") = serde_json::json!({
            "schema": AI_CONTRACT_SCHEMA,
            "task": "plan",
            "payload": {
                "target": "https://different.example",
                "recommendations": [],
                "skipped_modules": [],
                "overall_strategy": "fixture",
                "estimated_scan_time": null
            }
        })
        .to_string();
        let config = AiConfig { binary: Some(available_binary()), ..AiConfig::default() };
        let provider = CliAiProvider::with_executor(&config, executor);
        let error = provider.plan(&plan_request()).await.expect_err("target mismatch");
        assert_eq!(
            error,
            AiProviderError::InvalidPayload {
                task: AiTask::Plan,
                detail: "response target does not match request target".to_string(),
            }
        );
    }

    #[test]
    fn claude_budget_must_be_strictly_positive() {
        for budget in [0.0, -0.01] {
            let config = AiConfig {
                provider: AiProviderKind::Claude,
                max_budget_usd: Some(budget),
                ..AiConfig::default()
            };
            let contract = render_contract(AiTask::Plan, &plan_request()).expect("contract");
            let invocation =
                CliAiProvider::with_executor(&config, Arc::new(RecordingExecutor::default()))
                    .invocation(&contract);
            assert!(
                !invocation.args.iter().any(|argument| argument == "--max-budget-usd"),
                "non-positive budget {budget} must not reach the provider invocation"
            );
        }
    }

    #[test]
    fn disabled_config_uses_noop_provider() {
        let provider = provider_from_config(&AiConfig { enabled: false, ..AiConfig::default() });
        assert_eq!(provider.id(), "none");
        assert_eq!(provider.name(), "No AI provider");
        assert!(!provider.is_available());
    }
}
