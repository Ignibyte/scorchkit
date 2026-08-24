//! Typed, policy-sealed local lifecycle processor adapter.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use scorchkit_core::run_pipeline::{
    AcceptedPreprocess, FindingProposal, FindingProposalKind, ProcessorBudget,
    ProcessorDisposition, ProcessorFailureMode, RunAuthority, RunPhase, RunProcessorContract,
    RunProcessorInput, RunProcessorOutcome, RunProcessorRequest, RunProcessorResponse, RunProposal,
    MAX_RUN_INPUT_BYTES, MAX_RUN_OUTPUT_BYTES, PREPROCESS_PROPOSAL_SCHEMA_V1,
    PROCESSOR_CONTRACT_SCHEMA_V1, PROCESSOR_RESPONSE_SCHEMA_V1,
};
use tracing::warn;

use crate::config::HookConfig;
use crate::engine::finding::Finding;
use crate::runner::subprocess::ToolOutput;

use super::error::{Result, ScorchError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookPoint {
    PreScan,
    PostModule,
    PostScan,
}

impl HookPoint {
    const fn phase(self) -> RunPhase {
        match self {
            Self::PreScan => RunPhase::Preprocessing,
            Self::PostModule => RunPhase::Enrichment,
            Self::PostScan => RunPhase::Reporting,
        }
    }
}

impl std::fmt::Display for HookPoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreScan => formatter.write_str("pre_scan"),
            Self::PostModule => formatter.write_str("post_module"),
            Self::PostScan => formatter.write_str("post_scan"),
        }
    }
}

#[async_trait]
pub(crate) trait HookExecutor: Sync {
    async fn run_hook_script(
        &self,
        script: &Path,
        json_input: &str,
        timeout: Duration,
        output_limit_bytes: usize,
    ) -> Result<ToolOutput>;
}

#[async_trait]
impl HookExecutor for super::scan_context::ScanContext {
    async fn run_hook_script(
        &self,
        script: &Path,
        json_input: &str,
        timeout: Duration,
        output_limit_bytes: usize,
    ) -> Result<ToolOutput> {
        self.run_tool_with_stdin_limit(
            script.to_string_lossy().as_ref(),
            json_input.as_bytes(),
            timeout,
            output_limit_bytes,
        )
        .await
    }
}

#[async_trait]
impl HookExecutor for super::code_context::CodeContext {
    async fn run_hook_script(
        &self,
        script: &Path,
        json_input: &str,
        timeout: Duration,
        output_limit_bytes: usize,
    ) -> Result<ToolOutput> {
        self.run_pipeline_processor(
            script.to_string_lossy().as_ref(),
            json_input.as_bytes(),
            timeout,
            output_limit_bytes,
        )
        .await
    }
}

#[derive(Debug, Clone)]
struct ConfiguredProcessor {
    path: PathBuf,
    contract: RunProcessorContract,
    legacy: bool,
}

#[derive(Debug)]
struct ProcessorRunFailure {
    disposition: ProcessorDisposition,
    diagnostic: String,
}

impl ProcessorRunFailure {
    fn degraded(diagnostic: impl Into<String>) -> Self {
        Self { disposition: ProcessorDisposition::Degraded, diagnostic: diagnostic.into() }
    }

    fn rejected(diagnostic: impl Into<String>) -> Self {
        Self { disposition: ProcessorDisposition::Rejected, diagnostic: diagnostic.into() }
    }
}

#[derive(Debug, Default)]
pub(crate) struct HookExecution {
    pub outcomes: Vec<RunProcessorOutcome>,
    pub accepted_preprocess: Option<AcceptedPreprocess>,
}

pub(crate) struct HookRunner {
    config: HookConfig,
}

impl HookRunner {
    #[must_use]
    pub fn new(config: &HookConfig) -> Self {
        Self { config: config.clone() }
    }

    #[must_use]
    pub fn has_hooks(&self, point: HookPoint) -> bool {
        self.config.processors.iter().any(|processor| processor.phase == point.phase())
            || !self.legacy_scripts(point).is_empty()
    }

    /// Validate every configured processor before a scan publishes its start event.
    pub fn validate(&self) -> Result<()> {
        self.config.validate().map_err(|error| {
            ScorchError::Hook(format!("invalid run processor configuration: {error}"))
        })?;
        for point in [HookPoint::PreScan, HookPoint::PostModule, HookPoint::PostScan] {
            for processor in self.processors_for(point)? {
                processor.contract.validate().map_err(|error| {
                    ScorchError::Hook(format!(
                        "invalid run processor {}: {error}",
                        processor.contract.id
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Execute every processor at one phase in stable `(order, id)` order.
    pub async fn execute<E: HookExecutor>(
        &self,
        point: HookPoint,
        input: RunProcessorInput,
        legacy_input: &serde_json::Value,
        authority: &RunAuthority,
        executor: &E,
    ) -> Result<HookExecution> {
        self.validate()?;
        input
            .validate()
            .map_err(|error| ScorchError::Hook(format!("{point}: invalid input: {error}")))?;
        authority
            .validate()
            .map_err(|error| ScorchError::Hook(format!("{point}: invalid authority: {error}")))?;

        let processors = self.processors_for(point)?;
        let mut current_input = input;
        let mut current_authority = authority.clone();
        let mut execution = HookExecution::default();

        for mut processor in processors {
            if processor.legacy {
                processor.contract.capabilities.clone_from(&current_authority.capabilities);
            }
            if !processor.contract.capabilities.is_subset(&current_authority.capabilities) {
                let message = format!(
                    "{point}: processor {} declares capabilities outside the authorized ceiling",
                    processor.contract.id
                );
                Self::handle_failure(
                    &processor.contract,
                    ProcessorDisposition::Rejected,
                    &message,
                    &mut execution,
                )?;
                continue;
            }

            let request = RunProcessorRequest::new(&processor.contract, current_input.clone())
                .map_err(|error| ScorchError::Hook(format!("{point}: {error}")))?;
            let input_value = if processor.legacy {
                legacy_input.clone()
            } else {
                serde_json::to_value(request).map_err(|error| {
                    ScorchError::Hook(format!(
                        "{point}: failed to encode processor {} input: {error}",
                        processor.contract.id
                    ))
                })?
            };
            let json_input = serde_json::to_string(&input_value).map_err(|error| {
                ScorchError::Hook(format!(
                    "{point}: failed to encode processor {} input: {error}",
                    processor.contract.id
                ))
            })?;
            if json_input.len() > processor.contract.budget.max_input_bytes {
                let message = format!(
                    "{point}: processor {} input exceeds {} bytes",
                    processor.contract.id, processor.contract.budget.max_input_bytes
                );
                Self::handle_failure(
                    &processor.contract,
                    ProcessorDisposition::Degraded,
                    &message,
                    &mut execution,
                )?;
                continue;
            }

            let response = self
                .run_one(&processor, &json_input, &current_input, &current_authority, executor)
                .await;
            let (response, accepted) = match response {
                Ok(value) => value,
                Err(failure) => {
                    let message = format!(
                        "{point}: processor {} failed: {}",
                        processor.contract.id, failure.diagnostic
                    );
                    Self::handle_failure(
                        &processor.contract,
                        failure.disposition,
                        &message,
                        &mut execution,
                    )?;
                    continue;
                }
            };

            if let Some(accepted) = accepted {
                apply_preprocess(&mut current_input, &mut current_authority, &accepted);
                execution.accepted_preprocess = Some(accepted);
            }
            execution.outcomes.push(RunProcessorOutcome::success(response));
        }
        Ok(execution)
    }

    async fn run_one<E: HookExecutor>(
        &self,
        processor: &ConfiguredProcessor,
        json_input: &str,
        typed_input: &RunProcessorInput,
        authority: &RunAuthority,
        executor: &E,
    ) -> std::result::Result<(RunProcessorResponse, Option<AcceptedPreprocess>), ProcessorRunFailure>
    {
        let output = executor
            .run_hook_script(
                &processor.path,
                json_input,
                Duration::from_millis(processor.contract.budget.timeout_millis),
                processor.contract.budget.max_output_bytes,
            )
            .await
            .map_err(|_| ProcessorRunFailure::degraded("processor execution failed"))?;
        let trimmed = output.stdout.trim();
        let mut response = if trimmed.is_empty() {
            passthrough_response(&processor.contract)
        } else if processor.legacy {
            legacy_response(&processor.contract, typed_input, trimmed).map_err(|_| {
                ProcessorRunFailure::rejected("legacy processor produced an invalid proposal")
            })?
        } else {
            serde_json::from_str::<RunProcessorResponse>(trimmed).map_err(|_| {
                ProcessorRunFailure::rejected("processor produced invalid typed JSON")
            })?
        };
        let accepted = response
            .validate(
                &processor.contract,
                typed_input,
                (processor.contract.phase == RunPhase::Preprocessing).then_some(authority),
            )
            .map_err(|error| ProcessorRunFailure::rejected(error.to_string()))?;
        Ok((response, accepted))
    }

    fn handle_failure(
        contract: &RunProcessorContract,
        disposition: ProcessorDisposition,
        message: &str,
        execution: &mut HookExecution,
    ) -> Result<()> {
        let message = crate::engine::observation::redact_text(message);
        match contract.failure_mode {
            ProcessorFailureMode::Optional => {
                warn!("{}", crate::report::terminal::escape_terminal_text(&message));
                let outcome = match disposition {
                    ProcessorDisposition::Rejected => {
                        RunProcessorOutcome::rejected(contract, &message)
                    }
                    ProcessorDisposition::Degraded => {
                        RunProcessorOutcome::degraded(contract, &message)
                    }
                    ProcessorDisposition::Applied | ProcessorDisposition::NoChange => {
                        return Err(ScorchError::Hook(
                            "invalid processor failure disposition".to_string(),
                        ));
                    }
                };
                execution.outcomes.push(outcome);
                Ok(())
            }
            ProcessorFailureMode::Required => Err(ScorchError::Hook(message)),
        }
    }

    fn processors_for(&self, point: HookPoint) -> Result<Vec<ConfiguredProcessor>> {
        let mut processors = self
            .config
            .processors
            .iter()
            .filter(|processor| processor.phase == point.phase())
            .map(|processor| {
                processor
                    .contract()
                    .map(|contract| ConfiguredProcessor {
                        path: processor.path.clone(),
                        contract,
                        legacy: false,
                    })
                    .map_err(ScorchError::Hook)
            })
            .collect::<Result<Vec<_>>>()?;

        for (index, path) in self.legacy_scripts(point).iter().enumerate() {
            let index = u16::try_from(index)
                .map_err(|_| ScorchError::Hook(format!("{point}: too many legacy processors")))?;
            let phase = point.phase();
            processors.push(ConfiguredProcessor {
                path: path.clone(),
                contract: RunProcessorContract {
                    schema: PROCESSOR_CONTRACT_SCHEMA_V1.into(),
                    id: format!("legacy.{point}.{index:03}"),
                    phase,
                    input_schema: phase.input_schema().into(),
                    output_schema: phase.output_schema().into(),
                    capabilities: [scorchkit_policy::policy::Capability::ExternalTool].into(),
                    failure_mode: if self.config.fail_open {
                        ProcessorFailureMode::Optional
                    } else {
                        ProcessorFailureMode::Required
                    },
                    order: 50_000_u16.saturating_add(index),
                    budget: ProcessorBudget {
                        timeout_millis: self.config.timeout_seconds.saturating_mul(1_000),
                        max_input_bytes: MAX_RUN_INPUT_BYTES,
                        max_output_bytes: MAX_RUN_OUTPUT_BYTES,
                    },
                },
                legacy: true,
            });
        }
        processors.sort_by(|left, right| {
            (left.contract.order, left.contract.id.as_str())
                .cmp(&(right.contract.order, right.contract.id.as_str()))
        });
        Ok(processors)
    }

    fn legacy_scripts(&self, point: HookPoint) -> &[PathBuf] {
        match point {
            HookPoint::PreScan => &self.config.pre_scan,
            HookPoint::PostModule => &self.config.post_module,
            HookPoint::PostScan => &self.config.post_scan,
        }
    }
}

fn apply_preprocess(
    input: &mut RunProcessorInput,
    authority: &mut RunAuthority,
    accepted: &AcceptedPreprocess,
) {
    authority.modules.clone_from(&accepted.modules);
    authority.capabilities.clone_from(&accepted.capabilities);
    authority.max_effect = accepted.effect;
    authority.credential_use = accepted.credential_use;
    if let RunProcessorInput::Preprocess {
        modules, capabilities, max_effect, credential_use, ..
    } = input
    {
        *modules = accepted.modules.iter().cloned().collect();
        capabilities.clone_from(&accepted.capabilities);
        *max_effect = accepted.effect;
        *credential_use = accepted.credential_use;
    }
}

fn passthrough_response(contract: &RunProcessorContract) -> RunProcessorResponse {
    RunProcessorResponse {
        schema: PROCESSOR_RESPONSE_SCHEMA_V1.into(),
        processor_id: contract.id.clone(),
        phase: contract.phase,
        proposal: RunProposal::Passthrough,
        diagnostic: None,
    }
}

fn legacy_response(
    contract: &RunProcessorContract,
    input: &RunProcessorInput,
    output: &str,
) -> std::result::Result<RunProcessorResponse, String> {
    let value: serde_json::Value = serde_json::from_str(output)
        .map_err(|error| format!("legacy processor produced invalid JSON: {error}"))?;
    let proposal = match (contract.phase, input) {
        (
            RunPhase::Preprocessing,
            RunProcessorInput::Preprocess {
                target,
                modules,
                capabilities,
                max_effect,
                credential_use,
            },
        ) => {
            if value.get("modules").is_none() && value.get("target").is_none() {
                return Ok(passthrough_response(contract));
            }
            let proposed_modules = value.get("modules").map_or_else(
                || Ok(modules.clone()),
                |modules| {
                    serde_json::from_value::<Vec<String>>(modules.clone())
                        .map_err(|error| format!("legacy modules proposal is invalid: {error}"))
                },
            )?;
            let proposed_target = value
                .get("target")
                .and_then(serde_json::Value::as_str)
                .map(|candidate| {
                    if candidate == policy_target_text(target) {
                        Ok(target.clone())
                    } else {
                        Err("legacy processor cannot change the authorized target".to_string())
                    }
                })
                .transpose()?;
            RunProposal::Preprocess(scorchkit_core::run_pipeline::PreprocessProposal {
                schema: PREPROCESS_PROPOSAL_SCHEMA_V1.into(),
                target: proposed_target,
                modules: proposed_modules,
                capabilities: capabilities.clone(),
                effect: *max_effect,
                credential_use: *credential_use,
            })
        }
        (RunPhase::Enrichment, RunProcessorInput::Findings { findings, .. }) => {
            let Some(returned) = value.get("findings") else {
                return Ok(passthrough_response(contract));
            };
            let returned: Vec<Finding> = serde_json::from_value(returned.clone())
                .map_err(|error| format!("legacy findings proposal is invalid: {error}"))?;
            let source_ids: BTreeSet<_> =
                findings.iter().map(|finding| finding.finding_id.clone()).collect();
            let mut returned_ids = BTreeSet::new();
            for finding in returned {
                let identity = finding.canonical_appsec().identity.value;
                if !source_ids.contains(&identity) {
                    return Err("legacy processor proposed an unknown or modified finding".into());
                }
                if !returned_ids.insert(identity) {
                    return Err("legacy processor returned a duplicate finding".into());
                }
            }
            RunProposal::Findings(
                source_ids
                    .into_iter()
                    .map(|source_finding_id| FindingProposal {
                        kind: if returned_ids.contains(&source_finding_id) {
                            FindingProposalKind::Retain
                        } else {
                            FindingProposalKind::Filter
                        },
                        source_finding_id,
                        related_finding_ids: Vec::new(),
                        annotations: BTreeMap::new(),
                    })
                    .collect(),
            )
        }
        (RunPhase::Reporting, RunProcessorInput::Report { .. }) => {
            RunProposal::Report([("legacy_output".into(), "completed".into())].into())
        }
        _ => return Err("legacy processor phase/input mismatch".into()),
    };
    Ok(RunProcessorResponse {
        schema: PROCESSOR_RESPONSE_SCHEMA_V1.into(),
        processor_id: contract.id.clone(),
        phase: contract.phase,
        proposal,
        diagnostic: None,
    })
}

fn policy_target_text(target: &scorchkit_policy::policy::PolicyTarget) -> String {
    match target {
        scorchkit_policy::policy::PolicyTarget::Web(url) => url.as_str().to_string(),
        scorchkit_policy::policy::PolicyTarget::Code(path) => path.display().to_string(),
        scorchkit_policy::policy::PolicyTarget::Network(value)
        | scorchkit_policy::policy::PolicyTarget::Cloud(value) => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scorchkit_core::run_pipeline::{
        FindingSnapshot, ProcessorDisposition, FINDING_INPUT_SCHEMA_V1, FINDING_PROPOSAL_SCHEMA_V1,
        PREPROCESS_INPUT_SCHEMA_V1, PREPROCESS_PROPOSAL_SCHEMA_V1, REPORT_INPUT_SCHEMA_V1,
        REPORT_PROPOSAL_SCHEMA_V1,
    };
    use scorchkit_policy::policy::{Capability, EffectClass, PolicyTarget};

    #[derive(Debug)]
    struct StubExecutor {
        result: std::result::Result<String, String>,
    }

    #[async_trait]
    impl HookExecutor for StubExecutor {
        async fn run_hook_script(
            &self,
            _script: &Path,
            _json_input: &str,
            _timeout: Duration,
            _output_limit_bytes: usize,
        ) -> Result<ToolOutput> {
            match &self.result {
                Ok(stdout) => Ok(ToolOutput {
                    stdout: stdout.clone(),
                    stderr: String::new(),
                    exit_code: 0,
                    duration: Duration::ZERO,
                    resolved_program: PathBuf::from("/stub/hook"),
                }),
                Err(error) => Err(ScorchError::Hook(error.clone())),
            }
        }
    }

    fn authority() -> RunAuthority {
        RunAuthority {
            target: PolicyTarget::web("https://example.test").unwrap(),
            modules: ["headers".to_string(), "tls".to_string()].into(),
            capabilities: [Capability::DastScan, Capability::ExternalTool].into(),
            max_effect: EffectClass::ActiveSafe,
            credential_use: false,
        }
    }

    fn preprocessing_input() -> RunProcessorInput {
        RunProcessorInput::Preprocess {
            target: authority().target,
            modules: vec!["headers".into(), "tls".into()],
            capabilities: authority().capabilities,
            max_effect: EffectClass::ActiveSafe,
            credential_use: false,
        }
    }

    fn explicit_preprocessor() -> scorchkit_config::RunProcessorConfig {
        scorchkit_config::RunProcessorConfig {
            schema: PROCESSOR_CONTRACT_SCHEMA_V1.into(),
            id: "preprocessor".into(),
            path: PathBuf::from("/stub/hook"),
            phase: RunPhase::Preprocessing,
            input_schema: PREPROCESS_INPUT_SCHEMA_V1.into(),
            output_schema: PREPROCESS_PROPOSAL_SCHEMA_V1.into(),
            capabilities: vec![Capability::DastScan],
            failure_mode: ProcessorFailureMode::Required,
            order: 1,
            budget: ProcessorBudget {
                timeout_millis: 1_000,
                max_input_bytes: MAX_RUN_INPUT_BYTES,
                max_output_bytes: MAX_RUN_OUTPUT_BYTES,
            },
        }
    }

    fn legacy_contract(phase: RunPhase) -> RunProcessorContract {
        RunProcessorContract {
            schema: PROCESSOR_CONTRACT_SCHEMA_V1.into(),
            id: format!("legacy.{phase:?}"),
            phase,
            input_schema: phase.input_schema().into(),
            output_schema: phase.output_schema().into(),
            capabilities: [Capability::ExternalTool].into(),
            failure_mode: ProcessorFailureMode::Required,
            order: 50_000,
            budget: ProcessorBudget {
                timeout_millis: 1_000,
                max_input_bytes: MAX_RUN_INPUT_BYTES,
                max_output_bytes: MAX_RUN_OUTPUT_BYTES,
            },
        }
    }

    #[test]
    fn empty_configuration_has_no_processors() {
        let runner = HookRunner::new(&HookConfig::default());
        assert!(!runner.has_hooks(HookPoint::PreScan));
        assert!(!runner.has_hooks(HookPoint::PostModule));
        assert!(!runner.has_hooks(HookPoint::PostScan));
    }

    #[tokio::test]
    async fn legacy_preprocessor_may_only_narrow_modules() {
        let config = HookConfig {
            pre_scan: vec![PathBuf::from("/stub/hook")],
            fail_open: false,
            ..HookConfig::default()
        };
        let execution = HookRunner::new(&config)
            .execute(
                HookPoint::PreScan,
                preprocessing_input(),
                &serde_json::json!({
                    "target": "https://example.test/",
                    "profile": "standard",
                    "modules": ["headers", "tls"]
                }),
                &authority(),
                &StubExecutor {
                    result: Ok(serde_json::json!({
                        "target": "https://example.test/",
                        "modules": ["headers"]
                    })
                    .to_string()),
                },
            )
            .await
            .unwrap();
        let accepted = execution.accepted_preprocess.unwrap();
        assert_eq!(accepted.modules, ["headers".to_string()].into());
        assert_eq!(accepted.capabilities, authority().capabilities);
    }

    #[tokio::test]
    async fn optional_failure_is_degraded_and_required_failure_aborts() {
        let mut optional = HookConfig {
            pre_scan: vec![PathBuf::from("/stub/hook")],
            fail_open: true,
            ..HookConfig::default()
        };
        let executor =
            StubExecutor { result: Err("authorization=Bearer processor-secret failed".into()) };
        let execution = HookRunner::new(&optional)
            .execute(
                HookPoint::PreScan,
                preprocessing_input(),
                &serde_json::json!({}),
                &authority(),
                &executor,
            )
            .await
            .unwrap();
        assert_eq!(execution.outcomes[0].disposition, ProcessorDisposition::Degraded);
        let diagnostic = execution.outcomes[0].diagnostic.as_deref().unwrap();
        assert!(!diagnostic.contains("processor-secret"));
        assert!(!diagnostic.contains("/stub/hook"));

        optional.fail_open = false;
        let error = HookRunner::new(&optional)
            .execute(
                HookPoint::PreScan,
                preprocessing_input(),
                &serde_json::json!({}),
                &authority(),
                &executor,
            )
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("processor-secret"));
    }

    #[tokio::test]
    async fn optional_invalid_output_is_rejected_without_echoing_processor_bytes() {
        let config = HookConfig {
            pre_scan: vec![PathBuf::from("/stub/hook")],
            fail_open: true,
            ..HookConfig::default()
        };
        let execution = HookRunner::new(&config)
            .execute(
                HookPoint::PreScan,
                preprocessing_input(),
                &serde_json::json!({}),
                &authority(),
                &StubExecutor { result: Ok("not-json processor-output-secret".to_string()) },
            )
            .await
            .unwrap();

        assert_eq!(execution.outcomes[0].disposition, ProcessorDisposition::Rejected);
        let diagnostic = execution.outcomes[0].diagnostic.as_deref().unwrap();
        assert!(!diagnostic.contains("processor-output-secret"));
        assert!(!diagnostic.contains("/stub/hook"));
    }

    #[test]
    fn explicit_contract_uses_typed_schemas() {
        let config = scorchkit_config::RunProcessorConfig {
            schema: PROCESSOR_CONTRACT_SCHEMA_V1.into(),
            id: "preprocessor".into(),
            path: PathBuf::from("/stub/hook"),
            phase: RunPhase::Preprocessing,
            input_schema: PREPROCESS_INPUT_SCHEMA_V1.into(),
            output_schema: PREPROCESS_PROPOSAL_SCHEMA_V1.into(),
            capabilities: vec![Capability::DastScan],
            failure_mode: ProcessorFailureMode::Required,
            order: 1,
            budget: ProcessorBudget { timeout_millis: 1, max_input_bytes: 1, max_output_bytes: 1 },
        };
        assert!(config.contract().is_ok());
    }

    #[test]
    fn legacy_findings_output_becomes_dispositions_not_replacement() {
        let finding = Finding::new(
            "headers",
            crate::engine::severity::Severity::Low,
            "title",
            "description",
            "https://example.test",
        );
        let identity = finding.canonical_appsec().identity.value;
        let input = RunProcessorInput::Findings {
            module_id: "headers".into(),
            module_name: "Headers".into(),
            findings: vec![FindingSnapshot {
                finding_id: identity,
                module_id: "headers".into(),
                severity: crate::engine::severity::Severity::Low,
                title: "title".into(),
                affected_target: "https://example.test".into(),
            }],
        };
        let contract = RunProcessorContract {
            schema: PROCESSOR_CONTRACT_SCHEMA_V1.into(),
            id: "legacy.post_module.000".into(),
            phase: RunPhase::Enrichment,
            input_schema: FINDING_INPUT_SCHEMA_V1.into(),
            output_schema: FINDING_PROPOSAL_SCHEMA_V1.into(),
            capabilities: [Capability::ExternalTool].into(),
            failure_mode: ProcessorFailureMode::Required,
            order: 50_000,
            budget: ProcessorBudget { timeout_millis: 1, max_input_bytes: 1, max_output_bytes: 1 },
        };
        let response =
            legacy_response(&contract, &input, &serde_json::json!({"findings": []}).to_string())
                .unwrap();
        let RunProposal::Findings(proposals) = response.proposal else {
            panic!("expected finding proposals")
        };
        assert_eq!(proposals[0].kind, FindingProposalKind::Filter);
    }

    #[test]
    fn hook_point_labels_and_aggregate_validation_are_exact() {
        assert_eq!(HookPoint::PreScan.to_string(), "pre_scan");
        assert_eq!(HookPoint::PostModule.to_string(), "post_module");
        assert_eq!(HookPoint::PostScan.to_string(), "post_scan");

        let processor = explicit_preprocessor();
        let config =
            HookConfig { processors: vec![processor.clone(), processor], ..HookConfig::default() };
        assert!(HookRunner::new(&config).validate().is_err());
    }

    #[tokio::test]
    async fn typed_request_at_the_exact_input_limit_is_executed() {
        let input = preprocessing_input();
        let mut processor = explicit_preprocessor();
        let contract = processor.contract().expect("processor contract");
        let request = RunProcessorRequest::new(&contract, input.clone()).expect("typed request");
        processor.budget.max_input_bytes =
            serde_json::to_string(&request).expect("request JSON").len();
        let config = HookConfig { processors: vec![processor], ..HookConfig::default() };

        let execution = HookRunner::new(&config)
            .execute(
                HookPoint::PreScan,
                input,
                &serde_json::json!({}),
                &authority(),
                &StubExecutor { result: Ok(String::new()) },
            )
            .await
            .expect("exact-limit processor request");

        assert_eq!(execution.outcomes.len(), 1);
        assert_eq!(execution.outcomes[0].disposition, ProcessorDisposition::NoChange);
    }

    #[test]
    fn accepted_preprocessing_updates_the_next_input_and_authority() {
        let mut input = preprocessing_input();
        let mut current_authority = authority();
        let accepted = AcceptedPreprocess {
            target: current_authority.target.clone(),
            modules: ["headers".to_string()].into(),
            capabilities: [Capability::DastScan].into(),
            effect: EffectClass::Passive,
            credential_use: false,
        };

        apply_preprocess(&mut input, &mut current_authority, &accepted);

        assert_eq!(current_authority.modules, accepted.modules);
        assert_eq!(current_authority.capabilities, accepted.capabilities);
        assert_eq!(current_authority.max_effect, EffectClass::Passive);
        let RunProcessorInput::Preprocess { modules, capabilities, max_effect, .. } = input else {
            unreachable!()
        };
        assert_eq!(modules, ["headers"]);
        assert_eq!(capabilities, [Capability::DastScan].into());
        assert_eq!(max_effect, EffectClass::Passive);
    }

    #[test]
    fn legacy_preprocess_and_reporting_keep_each_compatibility_shape() {
        let preprocessor = legacy_contract(RunPhase::Preprocessing);
        let response = legacy_response(
            &preprocessor,
            &preprocessing_input(),
            &serde_json::json!({"target": "https://example.test/"}).to_string(),
        )
        .expect("target-only legacy proposal");
        assert!(matches!(response.proposal, RunProposal::Preprocess(_)));

        let reporter = legacy_contract(RunPhase::Reporting);
        let response = legacy_response(
            &reporter,
            &RunProcessorInput::Report {
                scan_id: "scan-one".into(),
                target: authority().target,
                total_findings: 0,
                severity_counts: [
                    ("critical".into(), 0),
                    ("high".into(), 0),
                    ("medium".into(), 0),
                    ("low".into(), 0),
                    ("info".into(), 0),
                ]
                .into(),
            },
            "{}",
        )
        .expect("legacy report proposal");
        assert!(matches!(response.proposal, RunProposal::Report(ref values)
            if values.get("legacy_output").map(String::as_str) == Some("completed")));
        assert_eq!(reporter.input_schema, REPORT_INPUT_SCHEMA_V1);
        assert_eq!(reporter.output_schema, REPORT_PROPOSAL_SCHEMA_V1);
    }

    #[test]
    fn legacy_finding_adapter_rejects_unknown_and_duplicate_returns() {
        let finding = Finding::new(
            "headers",
            crate::engine::severity::Severity::Low,
            "known title",
            "description",
            "https://example.test",
        );
        let input = RunProcessorInput::Findings {
            module_id: "headers".into(),
            module_name: "Headers".into(),
            findings: vec![FindingSnapshot {
                finding_id: finding.canonical_appsec().identity.value,
                module_id: "headers".into(),
                severity: crate::engine::severity::Severity::Low,
                title: "known title".into(),
                affected_target: "https://example.test".into(),
            }],
        };
        let contract = legacy_contract(RunPhase::Enrichment);
        let retained_output = serde_json::json!({"findings": [&finding]}).to_string();
        let response = legacy_response(&contract, &input, &retained_output)
            .expect("one known finding is a valid legacy proposal");
        assert!(matches!(response.proposal, RunProposal::Findings(ref proposals)
            if proposals.len() == 1 && proposals[0].kind == FindingProposalKind::Retain));

        let unknown = Finding::new(
            "headers",
            crate::engine::severity::Severity::Low,
            "unknown title",
            "description",
            "https://example.test",
        );
        let unknown_output = serde_json::json!({"findings": [unknown]}).to_string();
        assert!(legacy_response(&contract, &input, &unknown_output).is_err());

        let duplicate_output =
            serde_json::json!({"findings": [finding.clone(), finding]}).to_string();
        assert!(legacy_response(&contract, &input, &duplicate_output).is_err());
    }
}
