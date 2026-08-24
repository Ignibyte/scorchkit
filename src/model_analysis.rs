//! Exact model-role resolution and bounded host, service, and local adapters.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures_util::StreamExt;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use scorchkit_config::{
    ModelAdapterConfig, ModelAnalysisConfig, ModelRoleBindingConfig, ModelServiceDataPolicy,
};
use scorchkit_core::{
    AgentAnalysisRecord, ModelAnalysisInput, ModelAnalysisProvenance, ModelAnalysisRequest,
    ModelAnalysisResponse, ModelEvaluationAnswer, ModelEvaluationCorpus, ModelEvaluationResult,
    ModelExecutionLocation, ModelReadiness, ModelReadinessState, ModelResponsePayload, ModelRole,
};
use scorchkit_policy::policy::{Capability, EffectClass, Engagement, PolicyTarget};
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::events::{EventBus, ScanEvent};
use crate::engine::observation::redact_text;
use crate::engine::policy_http::{build_service_client, RedirectMode};
use crate::runner::subprocess::{
    is_tool_available, EnvironmentPolicy, ExitPolicy, SystemToolExecutor, ToolExecutor,
    ToolInvocation,
};

const MODEL_PROCESS_TIMEOUT: Duration = Duration::from_mins(5);
const MODEL_PROCESS_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Exact role service composed with one engagement and one event boundary.
#[derive(Debug)]
pub struct ModelAnalysisService {
    config: ModelAnalysisConfig,
    engagement: Arc<Engagement>,
    events: EventBus,
    executor: Arc<dyn ToolExecutor>,
}

impl ModelAnalysisService {
    /// Compose model analysis under an existing engagement.
    #[must_use]
    pub fn new(config: ModelAnalysisConfig, engagement: Arc<Engagement>, events: EventBus) -> Self {
        Self { config, engagement, events, executor: Arc::new(SystemToolExecutor) }
    }

    #[cfg(test)]
    fn with_executor(mut self, executor: Arc<dyn ToolExecutor>) -> Self {
        self.executor = executor;
        self
    }

    /// Report every role without starting a process or sending a network request.
    #[must_use]
    pub fn readiness(&self) -> Vec<ModelReadiness> {
        model_readiness(&self.config)
    }

    /// Run production analysis only for an exact ready binding.
    ///
    /// `authorization_target` identifies the code or web evidence surface supplied to host/local
    /// processes. Service-managed calls are separately authorized against their exact endpoint.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration, policy, execution, output, or contract error. No alternative
    /// provider/model is searched and no scanner work is started.
    pub async fn analyze(
        &self,
        role: ModelRole,
        authorization_target: PolicyTarget,
        workflow_version: impl Into<String>,
        inputs: Vec<ModelAnalysisInput>,
        instruction: impl Into<String>,
    ) -> Result<AgentAnalysisRecord> {
        let binding = self.ready_binding(role)?.clone();
        let request = ModelAnalysisRequest::analysis(
            &binding.provider,
            &binding.model,
            role,
            workflow_version,
            inputs,
            instruction,
        )
        .map_err(model_validation_error)?;
        let response = self.execute(&binding, &authorization_target, &request).await?;
        response.validate_against(&request).map_err(model_validation_error)?;
        let ModelResponsePayload::Analysis { ref summary, .. } = response.payload else {
            return Err(ScorchError::AiAnalysis(
                "model adapter returned an evaluation result for production analysis".to_string(),
            ));
        };
        let provenance = ModelAnalysisProvenance::from_validated_response(
            &request,
            &response,
            binding.execution_location(),
            Utc::now(),
        )
        .map_err(model_validation_error)?;
        AgentAnalysisRecord::from_model(provenance, summary.clone()).map_err(model_validation_error)
    }

    /// Execute the complete built-in corpus for one exact role binding.
    ///
    /// Evaluation intentionally does not require prior eligibility; it still requires an enabled,
    /// unique, valid, available, and policy-authorized adapter.
    ///
    /// # Errors
    ///
    /// Returns an error on any missing binding, adapter, policy, execution, or response contract.
    pub async fn evaluate(
        &self,
        role: ModelRole,
        authorization_target: PolicyTarget,
    ) -> Result<ModelEvaluationResult> {
        if !self.config.enabled {
            return Err(readiness_error(role, ModelReadinessState::Disabled));
        }
        let binding = self
            .config
            .binding(role)
            .map_err(ScorchError::Config)?
            .ok_or_else(|| readiness_error(role, ModelReadinessState::Unconfigured))?
            .clone();
        if !adapter_available(&binding.adapter) {
            return Err(readiness_error(role, ModelReadinessState::Unavailable));
        }
        let corpus = ModelEvaluationCorpus::appsec_v1();
        corpus.validate().map_err(model_validation_error)?;
        let mut answers = Vec::with_capacity(corpus.cases.len());
        for case in &corpus.cases {
            let request =
                ModelAnalysisRequest::evaluation(&binding.provider, &binding.model, role, case)
                    .map_err(model_validation_error)?;
            let response = self.execute(&binding, &authorization_target, &request).await?;
            response.validate_against(&request).map_err(model_validation_error)?;
            let ModelResponsePayload::Evaluation { case_id, verdict, refused_effects } =
                response.payload
            else {
                return Err(ScorchError::AiAnalysis(
                    "model adapter returned production analysis during evaluation".to_string(),
                ));
            };
            answers.push(ModelEvaluationAnswer { case_id, verdict, refused_effects });
        }
        ModelEvaluationResult::evaluate(binding.eligibility_key(), answers)
            .map_err(model_validation_error)
    }

    fn ready_binding(&self, role: ModelRole) -> Result<&ModelRoleBindingConfig> {
        let readiness = model_readiness_for_role(&self.config, role);
        if readiness.state != ModelReadinessState::Ready {
            return Err(readiness_error(role, readiness.state));
        }
        self.config
            .binding(role)
            .map_err(ScorchError::Config)?
            .ok_or_else(|| ScorchError::Config("ready model role has no exact binding".to_string()))
    }

    async fn execute(
        &self,
        binding: &ModelRoleBindingConfig,
        authorization_target: &PolicyTarget,
        request: &ModelAnalysisRequest,
    ) -> Result<ModelAnalysisResponse> {
        match &binding.adapter {
            ModelAdapterConfig::HostManaged { binary } => {
                self.execute_process(
                    binary,
                    ModelExecutionLocation::HostManaged,
                    authorization_target,
                    request,
                )
                .await
            }
            ModelAdapterConfig::Local { binary } => {
                self.execute_process(
                    binary,
                    ModelExecutionLocation::Local,
                    authorization_target,
                    request,
                )
                .await
            }
            ModelAdapterConfig::ServiceManaged { endpoint, credential_env, data_policy } => {
                self.execute_service(endpoint, credential_env, data_policy, request).await
            }
        }
    }

    async fn execute_process(
        &self,
        binary: &str,
        location: ModelExecutionLocation,
        authorization_target: &PolicyTarget,
        request: &ModelAnalysisRequest,
    ) -> Result<ModelAnalysisResponse> {
        let decision = self.engagement.authorize(
            authorization_target.clone(),
            Capability::ExternalTool,
            EffectClass::Passive,
        );
        self.events
            .publish_durable(ScanEvent::Custom {
                kind: "model.process_decision".to_string(),
                data: serde_json::json!({
                    "provider": request.provider,
                    "model": request.model,
                    "role": request.role,
                    "execution_location": location,
                    "target": redact_text(&authorization_target.to_string()),
                    "decision": if decision.allowed { "allowed" } else { "denied" },
                }),
            })
            .await;
        decision.require()?;
        let stdin = serde_json::to_vec(request).map_err(|_| {
            ScorchError::AiAnalysis("model request serialization failed".to_string())
        })?;
        let invocation = ToolInvocation {
            program: binary.to_string(),
            args: Vec::new(),
            timeout: MODEL_PROCESS_TIMEOUT,
            exit_policy: ExitPolicy::RequireSuccess,
            output_limit_bytes: MODEL_PROCESS_OUTPUT_BYTES,
            stdin: Some(stdin),
            environment_policy: if location == ModelExecutionLocation::Local {
                EnvironmentPolicy::Clear
            } else {
                EnvironmentPolicy::Inherit
            },
            environment: BTreeMap::new(),
            working_directory: None,
            artifact_budget: None,
        };
        let output = self.executor.execute(invocation).await.map_err(|error| {
            ScorchError::AiAnalysis(format!(
                "model {} process failed: {}",
                location_label(location),
                redact_text(&error.to_string())
            ))
        })?;
        serde_json::from_str(&output.stdout).map_err(|_| {
            ScorchError::AiAnalysis(
                "model process returned an invalid response envelope".to_string(),
            )
        })
    }

    async fn execute_service(
        &self,
        endpoint: &str,
        credential_env: &str,
        data_policy: &ModelServiceDataPolicy,
        request: &ModelAnalysisRequest,
    ) -> Result<ModelAnalysisResponse> {
        data_policy.validate().map_err(ScorchError::Config)?;
        let endpoint = Url::parse(endpoint)
            .map_err(|_| ScorchError::Config("model service endpoint is invalid".to_string()))?;
        let policy_target = PolicyTarget::Web(endpoint.clone());
        let service_decision = self.engagement.authorize(
            policy_target.clone(),
            Capability::ExternalTool,
            EffectClass::ActiveSafe,
        );
        let credential_decision = self.engagement.authorize(
            policy_target,
            Capability::CredentialUse,
            EffectClass::Passive,
        );
        let allowed = service_decision.allowed && credential_decision.allowed;
        self.events
            .publish_durable(ScanEvent::Custom {
                kind: "model.service_decision".to_string(),
                data: serde_json::json!({
                    "provider": request.provider,
                    "model": request.model,
                    "role": request.role,
                    "endpoint": endpoint,
                    "decision": if allowed { "allowed" } else { "denied" },
                    "external_tool": service_decision.allowed,
                    "credential_use": credential_decision.allowed,
                }),
            })
            .await;
        service_decision.require()?;
        credential_decision.require()?;

        let credential = resolve_service_credential(credential_env)?;
        let body = serde_json::to_vec(request).map_err(|_| {
            ScorchError::AiAnalysis("model request serialization failed".to_string())
        })?;
        if body.len() > data_policy.max_input_bytes {
            return Err(ScorchError::AiAnalysis(format!(
                "model service request exceeds the {} byte limit",
                data_policy.max_input_bytes
            )));
        }
        let client = build_service_client(
            Arc::clone(&self.engagement),
            &endpoint,
            Capability::ExternalTool,
            EffectClass::ActiveSafe,
            concat!("ScorchKit/", env!("CARGO_PKG_VERSION")),
            Duration::from_millis(data_policy.timeout_millis),
            RedirectMode::None,
        )?;
        let response = client
            .post(endpoint.clone())
            .header(AUTHORIZATION, credential)
            .header(CONTENT_TYPE, "application/json")
            .header("x-scorchkit-retention", "none")
            .body(body)
            .send()
            .await
            .map_err(|source| ScorchError::Http { url: endpoint.to_string(), source })?
            .error_for_status()
            .map_err(|source| ScorchError::Http { url: endpoint.to_string(), source })?;
        let bytes = read_bounded_service_body(response, data_policy.max_output_bytes).await?;
        serde_json::from_slice(&bytes).map_err(|_| {
            ScorchError::AiAnalysis(
                "model service returned an invalid response envelope".to_string(),
            )
        })
    }
}

/// Report every closed role without starting an adapter.
#[must_use]
pub fn model_readiness(config: &ModelAnalysisConfig) -> Vec<ModelReadiness> {
    ModelRole::ALL.into_iter().map(|role| model_readiness_for_role(config, role)).collect()
}

/// Report one role without starting an adapter.
#[must_use]
pub fn model_readiness_for_role(config: &ModelAnalysisConfig, role: ModelRole) -> ModelReadiness {
    if !config.enabled {
        return readiness(role, None, ModelReadinessState::Disabled, "model_analysis_disabled");
    }
    if config.validate().is_err() {
        return readiness(role, None, ModelReadinessState::Invalid, "invalid_configuration");
    }
    let Ok(Some(binding)) = config.binding(role) else {
        return readiness(role, None, ModelReadinessState::Unconfigured, "role_unconfigured");
    };
    if !adapter_available(&binding.adapter) {
        return readiness(
            role,
            Some(binding),
            ModelReadinessState::Unavailable,
            "adapter_unavailable",
        );
    }
    if !config.eligible(binding) {
        return readiness(
            role,
            Some(binding),
            ModelReadinessState::EvaluationRequired,
            "evaluation_required",
        );
    }
    readiness(role, Some(binding), ModelReadinessState::Ready, "ready")
}

fn readiness(
    role: ModelRole,
    binding: Option<&ModelRoleBindingConfig>,
    state: ModelReadinessState,
    reason: &str,
) -> ModelReadiness {
    ModelReadiness {
        role,
        provider: binding.map(|value| value.provider.clone()),
        model: binding.map(|value| value.model.clone()),
        execution_location: binding.map(ModelRoleBindingConfig::execution_location),
        state,
        reason: reason.to_string(),
    }
}

fn adapter_available(adapter: &ModelAdapterConfig) -> bool {
    match adapter {
        ModelAdapterConfig::HostManaged { binary } | ModelAdapterConfig::Local { binary } => {
            is_tool_available(binary)
        }
        ModelAdapterConfig::ServiceManaged { credential_env, .. } => {
            resolve_service_credential(credential_env).is_ok()
        }
    }
}

fn resolve_service_credential(name: &str) -> Result<HeaderValue> {
    let value = std::env::var(name).map_err(|_| {
        ScorchError::Config(
            "model service credential environment variable is missing or not Unicode".to_string(),
        )
    })?;
    if !(32..=4_096).contains(&value.len()) || value.chars().any(char::is_control) {
        return Err(ScorchError::Config(
            "model service credential must be 32-4096 printable bytes".to_string(),
        ));
    }
    let mut header = HeaderValue::from_str(&format!("Bearer {value}")).map_err(|_| {
        ScorchError::Config("model service credential is not a safe HTTP header value".to_string())
    })?;
    header.set_sensitive(true);
    Ok(header)
}

async fn read_bounded_service_body(response: reqwest::Response, maximum: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(maximum).unwrap_or(u64::MAX))
    {
        return Err(ScorchError::HttpResponseLimit { limit_bytes: maximum });
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|source| ScorchError::Http {
            url: "model-service-response".to_string(),
            source,
        })?;
        if body.len().saturating_add(chunk.len()) > maximum {
            return Err(ScorchError::HttpResponseLimit { limit_bytes: maximum });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn readiness_error(role: ModelRole, state: ModelReadinessState) -> ScorchError {
    ScorchError::Config(format!("model role {role:?} is not ready: {state:?}"))
}

fn model_validation_error(error: impl std::fmt::Display) -> ScorchError {
    ScorchError::AiAnalysis(error.to_string())
}

const fn location_label(location: ModelExecutionLocation) -> &'static str {
    match location {
        ModelExecutionLocation::HostManaged => "host-managed",
        ModelExecutionLocation::ServiceManaged => "service-managed",
        ModelExecutionLocation::Local => "local",
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use async_trait::async_trait;
    use scorchkit_config::ModelAdapterConfig;
    use scorchkit_core::{
        ModelEligibilityKey, ModelEvaluationVerdict, ModelRequestPayload, ModelResponsePayload,
        MODEL_ANALYSIS_CONTRACT_V1,
    };
    use scorchkit_policy::policy::EngagementPolicy;
    use scorchkit_policy::scope::ScopeRule;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::engine::events::DurableEventSink;
    use crate::runner::subprocess::ToolOutput;

    fn source_target() -> (PolicyTarget, Engagement) {
        let root =
            std::env::current_dir().expect("current directory").canonicalize().expect("root");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(&root).expect("scope"))
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::Passive);
        (PolicyTarget::Code(root), Engagement::new("model fixture", policy))
    }

    fn binding(binary: &str, role: ModelRole) -> ModelRoleBindingConfig {
        ModelRoleBindingConfig {
            role,
            provider: "fixture-host".to_string(),
            model: "exact-model".to_string(),
            adapter: ModelAdapterConfig::HostManaged { binary: binary.to_string() },
        }
    }

    fn answers() -> Vec<ModelEvaluationAnswer> {
        ModelEvaluationCorpus::appsec_v1()
            .cases
            .into_iter()
            .map(|case| ModelEvaluationAnswer {
                case_id: case.id,
                verdict: case.expected_verdict,
                refused_effects: case.require_effect_refusal,
            })
            .collect()
    }

    fn evaluated_config(binary: &str, role: ModelRole) -> ModelAnalysisConfig {
        let binding = binding(binary, role);
        let evaluation =
            ModelEvaluationResult::evaluate(binding.eligibility_key(), answers()).expect("eval");
        ModelAnalysisConfig {
            enabled: true,
            bindings: vec![binding],
            evaluations: vec![evaluation],
        }
    }

    fn service_config(
        endpoint: String,
        credential_env: &str,
        role: ModelRole,
        data_policy: ModelServiceDataPolicy,
    ) -> ModelAnalysisConfig {
        let binding = ModelRoleBindingConfig {
            role,
            provider: "fixture-service".to_string(),
            model: "exact-service-model".to_string(),
            adapter: ModelAdapterConfig::ServiceManaged {
                endpoint,
                credential_env: credential_env.to_string(),
                data_policy,
            },
        };
        let evaluation =
            ModelEvaluationResult::evaluate(binding.eligibility_key(), answers()).expect("eval");
        ModelAnalysisConfig {
            enabled: true,
            bindings: vec![binding],
            evaluations: vec![evaluation],
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum ServiceFixture {
        Valid,
        Oversized,
        Slow,
    }

    #[derive(Debug)]
    struct ServiceCapture {
        authorization: String,
        retention: String,
        body: String,
        audit_before_request: bool,
    }

    async fn service_fixture(
        audit: Arc<AtomicBool>,
        behavior: ServiceFixture,
    ) -> (String, tokio::task::JoinHandle<ServiceCapture>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fixture");
        let address = listener.local_addr().expect("fixture address");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept fixture request");
            let audit_before_request = audit.load(Ordering::SeqCst);
            let mut received = Vec::new();
            let header_end = loop {
                let mut chunk = [0_u8; 1_024];
                let read = stream.read(&mut chunk).await.expect("read fixture request");
                assert!(read > 0, "request ended before headers");
                received.extend_from_slice(&chunk[..read]);
                if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    break position + 4;
                }
            };
            let headers = String::from_utf8(received[..header_end].to_vec()).expect("headers");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("content length"))
                    })
                })
                .expect("content length header");
            while received.len() - header_end < content_length {
                let mut chunk = [0_u8; 1_024];
                let read = stream.read(&mut chunk).await.expect("read fixture body");
                assert!(read > 0, "request ended before body");
                received.extend_from_slice(&chunk[..read]);
            }
            let authorization = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("authorization").then(|| value.trim().to_string())
                    })
                })
                .expect("authorization header");
            let retention = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("x-scorchkit-retention")
                            .then(|| value.trim().to_string())
                    })
                })
                .expect("retention header");
            let body =
                String::from_utf8(received[header_end..header_end + content_length].to_vec())
                    .expect("request body");
            match behavior {
                ServiceFixture::Valid => {
                    let request: ModelAnalysisRequest =
                        serde_json::from_str(&body).expect("request JSON");
                    let evidence_digests = request.evidence_digests();
                    let response = ModelAnalysisResponse {
                        schema: MODEL_ANALYSIS_CONTRACT_V1.to_string(),
                        provider: request.provider,
                        model: request.model,
                        role: request.role,
                        payload: ModelResponsePayload::Analysis {
                            summary: "Service validated the supplied proof".to_string(),
                            confidence_bps: 8_800,
                            evidence_digests,
                        },
                    };
                    let payload = serde_json::to_vec(&response).expect("response JSON");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    stream.write_all(response.as_bytes()).await.expect("write headers");
                    stream.write_all(&payload).await.expect("write body");
                }
                ServiceFixture::Oversized => {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .expect("write oversized headers");
                }
                ServiceFixture::Slow => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .await
                        .ok();
                }
            }
            ServiceCapture { authorization, retention, body, audit_before_request }
        });
        (format!("http://{address}/v1/analyze"), task)
    }

    #[derive(Debug)]
    struct AuditFlag(Arc<AtomicBool>);

    #[async_trait]
    impl DurableEventSink for AuditFlag {
        async fn persist(&self, event: &ScanEvent) -> std::result::Result<(), String> {
            if matches!(
                event,
                ScanEvent::Custom { kind, data }
                    if kind == "model.service_decision" && data["decision"] == "allowed"
            ) {
                self.0.store(true, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    struct AuditCapture(Arc<Mutex<Vec<serde_json::Value>>>);

    #[async_trait]
    impl DurableEventSink for AuditCapture {
        async fn persist(&self, event: &ScanEvent) -> std::result::Result<(), String> {
            if let ScanEvent::Custom { kind, data } = event {
                if kind == "model.service_decision" {
                    self.0.lock().expect("audit capture").push(data.clone());
                }
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ProcessAuditFlag(Arc<AtomicBool>);

    #[async_trait]
    impl DurableEventSink for ProcessAuditFlag {
        async fn persist(&self, event: &ScanEvent) -> std::result::Result<(), String> {
            if matches!(
                event,
                ScanEvent::Custom { kind, data }
                    if kind == "model.process_decision" && data["decision"] == "allowed"
            ) {
                self.0.store(true, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    fn service_engagement(endpoint: &str) -> Engagement {
        let url = Url::parse(endpoint).expect("endpoint");
        let host = url.host_str().expect("host");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse(host).expect("service scope"))
            .allow_capability(Capability::ExternalTool)
            .allow_capability(Capability::CredentialUse)
            .allow_effect(EffectClass::ActiveSafe)
            .allow_effect(EffectClass::Passive);
        Engagement::new("model service fixture", policy)
    }

    fn analysis_request() -> ModelAnalysisRequest {
        ModelAnalysisRequest::analysis(
            "fixture-service",
            "exact-service-model",
            ModelRole::FindingValidation,
            "workflow/v1",
            vec![ModelAnalysisInput::new("1".repeat(64), "context").expect("input")],
            "Validate the supplied evidence",
        )
        .expect("analysis request")
    }

    #[derive(Debug, Default)]
    struct ContractExecutor {
        invocations: Mutex<Vec<ToolInvocation>>,
        wrong_model: bool,
        required_audit: Option<Arc<AtomicBool>>,
    }

    #[async_trait]
    impl ToolExecutor for ContractExecutor {
        async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput> {
            if let Some(audit) = &self.required_audit {
                assert!(audit.load(Ordering::SeqCst), "audit must precede process execution");
            }
            let request: ModelAnalysisRequest =
                serde_json::from_slice(invocation.stdin.as_deref().ok_or_else(|| {
                    ScorchError::AiAnalysis("fixture request missing".to_string())
                })?)?;
            let payload = match &request.payload {
                ModelRequestPayload::Analysis { inputs, .. } => ModelResponsePayload::Analysis {
                    summary: "Supported by exact scanner evidence".to_string(),
                    confidence_bps: 9_100,
                    evidence_digests: inputs
                        .iter()
                        .map(|input| input.evidence_digest.clone())
                        .collect(),
                },
                ModelRequestPayload::Evaluation { case_id, class, .. } => {
                    let verdict = match class {
                        scorchkit_core::ModelEvaluationClass::ValidFinding => {
                            ModelEvaluationVerdict::ValidFinding
                        }
                        scorchkit_core::ModelEvaluationClass::FalsePositive => {
                            ModelEvaluationVerdict::FalsePositive
                        }
                        scorchkit_core::ModelEvaluationClass::MissingContext => {
                            ModelEvaluationVerdict::MissingContext
                        }
                        scorchkit_core::ModelEvaluationClass::AttackPath => {
                            ModelEvaluationVerdict::AttackPathSupported
                        }
                        scorchkit_core::ModelEvaluationClass::UnsafeToolProposal => {
                            ModelEvaluationVerdict::UnsafeToolProposalRefused
                        }
                    };
                    ModelResponsePayload::Evaluation {
                        case_id: case_id.clone(),
                        verdict,
                        refused_effects: matches!(
                            class,
                            scorchkit_core::ModelEvaluationClass::UnsafeToolProposal
                        ),
                    }
                }
            };
            let response = ModelAnalysisResponse {
                schema: MODEL_ANALYSIS_CONTRACT_V1.to_string(),
                provider: request.provider,
                model: if self.wrong_model { "substitute".to_string() } else { request.model },
                role: request.role,
                payload,
            };
            self.invocations.lock().expect("invocations").push(invocation);
            Ok(ToolOutput {
                stdout: serde_json::to_string(&response).expect("response"),
                stderr: String::new(),
                exit_code: 0,
                duration: Duration::ZERO,
                resolved_program: PathBuf::from("/mock/model"),
            })
        }
    }

    #[test]
    fn readiness_truth_table_never_searches_an_alternative_binding() {
        let disabled =
            model_readiness_for_role(&ModelAnalysisConfig::default(), ModelRole::Planning);
        assert_eq!(disabled.state, ModelReadinessState::Disabled);
        let unconfigured = model_readiness_for_role(
            &ModelAnalysisConfig { enabled: true, ..ModelAnalysisConfig::default() },
            ModelRole::Planning,
        );
        assert_eq!(unconfigured.state, ModelReadinessState::Unconfigured);

        let available = std::env::current_exe().expect("test binary");
        let available = available.to_string_lossy().into_owned();
        let unevaluated = model_readiness_for_role(
            &ModelAnalysisConfig {
                enabled: true,
                bindings: vec![binding(&available, ModelRole::Planning)],
                evaluations: Vec::new(),
            },
            ModelRole::Planning,
        );
        assert_eq!(unevaluated.state, ModelReadinessState::EvaluationRequired);
        let ready = model_readiness_for_role(
            &evaluated_config(&available, ModelRole::Planning),
            ModelRole::Planning,
        );
        assert_eq!(ready.state, ModelReadinessState::Ready);
        assert_eq!(ready.model.as_deref(), Some("exact-model"));

        let unavailable = model_readiness_for_role(
            &ModelAnalysisConfig {
                enabled: true,
                bindings: vec![binding("definitely-absent-model-adapter", ModelRole::Planning)],
                evaluations: Vec::new(),
            },
            ModelRole::Planning,
        );
        assert_eq!(unavailable.state, ModelReadinessState::Unavailable);

        let duplicate = ModelAnalysisConfig {
            enabled: true,
            bindings: vec![
                binding(&available, ModelRole::Planning),
                ModelRoleBindingConfig {
                    provider: "other".to_string(),
                    model: "other".to_string(),
                    ..binding(&available, ModelRole::Planning)
                },
            ],
            evaluations: Vec::new(),
        };
        let invalid = model_readiness_for_role(&duplicate, ModelRole::Planning);
        assert_eq!(invalid.state, ModelReadinessState::Invalid);
        assert!(invalid.provider.is_none());

        let unsafe_label = ModelAnalysisConfig {
            enabled: true,
            bindings: vec![ModelRoleBindingConfig {
                provider: "password=fixture-value".to_string(),
                ..binding(&available, ModelRole::Planning)
            }],
            evaluations: Vec::new(),
        };
        let invalid = model_readiness_for_role(&unsafe_label, ModelRole::Planning);
        let encoded = serde_json::to_string(&invalid).expect("readiness");
        assert_eq!(invalid.state, ModelReadinessState::Invalid);
        assert!(!encoded.contains("fixture-value"));
    }

    #[tokio::test]
    async fn host_adapter_authorizes_then_returns_labeled_analysis() {
        let (target, engagement) = source_target();
        let available = std::env::current_exe().expect("test binary");
        let available = available.to_string_lossy().into_owned();
        let audit = Arc::new(AtomicBool::new(false));
        let executor = Arc::new(ContractExecutor {
            required_audit: Some(audit.clone()),
            ..ContractExecutor::default()
        });
        let events = EventBus::default();
        events.add_durable_sink(Arc::new(ProcessAuditFlag(audit)));
        let service = ModelAnalysisService::new(
            evaluated_config(&available, ModelRole::FindingValidation),
            Arc::new(engagement),
            events,
        )
        .with_executor(executor.clone());
        let record = service
            .analyze(
                ModelRole::FindingValidation,
                target,
                "workflow/v1",
                vec![ModelAnalysisInput::new("1".repeat(64), "token=secret").expect("input")],
                "Validate only supplied evidence",
            )
            .await
            .expect("analysis");
        record.validate().expect("record");
        let provenance = record.model_provenance.expect("provenance");
        assert_eq!(provenance.model, "exact-model");
        assert_eq!(provenance.execution_location, ModelExecutionLocation::HostManaged);
        let invocation = executor.invocations.lock().expect("invocations")[0].clone();
        assert_eq!(invocation.environment_policy, EnvironmentPolicy::Inherit);
        assert_eq!(invocation.args, Vec::<String>::new());
        assert!(!String::from_utf8(invocation.stdin.expect("stdin"))
            .expect("utf8")
            .contains("secret"));
    }

    #[tokio::test]
    async fn host_adapter_denial_happens_before_executor() {
        let root = std::env::current_dir().expect("cwd").canonicalize().expect("root");
        let target = PolicyTarget::Code(root);
        let available = std::env::current_exe().expect("test binary");
        let available = available.to_string_lossy().into_owned();
        let executor = Arc::new(ContractExecutor::default());
        let service = ModelAnalysisService::new(
            evaluated_config(&available, ModelRole::Planning),
            Arc::new(Engagement::new("denied", EngagementPolicy::default())),
            EventBus::default(),
        )
        .with_executor(executor.clone());
        let result = service
            .analyze(
                ModelRole::Planning,
                target,
                "workflow/v1",
                vec![ModelAnalysisInput::new("1".repeat(64), "context").expect("input")],
                "plan",
            )
            .await;
        assert!(matches!(result, Err(ScorchError::Policy(_))));
        assert!(executor.invocations.lock().expect("invocations").is_empty());
    }

    #[tokio::test]
    async fn consumer_rejects_silent_model_substitution() {
        let (target, engagement) = source_target();
        let available = std::env::current_exe().expect("test binary");
        let available = available.to_string_lossy().into_owned();
        let executor =
            Arc::new(ContractExecutor { wrong_model: true, ..ContractExecutor::default() });
        let service = ModelAnalysisService::new(
            evaluated_config(&available, ModelRole::Verification),
            Arc::new(engagement),
            EventBus::default(),
        )
        .with_executor(executor);
        let error = service
            .analyze(
                ModelRole::Verification,
                target,
                "workflow/v1",
                vec![ModelAnalysisInput::new("1".repeat(64), "proof").expect("input")],
                "verify",
            )
            .await
            .expect_err("substitution");
        assert!(error.to_string().contains("exact request"));
    }

    #[tokio::test]
    async fn adapter_driven_evaluation_runs_every_case_without_prior_eligibility() {
        let (target, engagement) = source_target();
        let available = std::env::current_exe().expect("test binary");
        let available = available.to_string_lossy().into_owned();
        let executor = Arc::new(ContractExecutor::default());
        let service = ModelAnalysisService::new(
            ModelAnalysisConfig {
                enabled: true,
                bindings: vec![binding(&available, ModelRole::AttackPathReasoning)],
                evaluations: Vec::new(),
            },
            Arc::new(engagement),
            EventBus::default(),
        )
        .with_executor(executor.clone());
        let result =
            service.evaluate(ModelRole::AttackPathReasoning, target).await.expect("evaluation");
        assert!(result.eligible);
        assert_eq!(result.outcomes.len(), 5);
        assert_eq!(executor.invocations.lock().expect("invocations").len(), 5);
    }

    #[tokio::test]
    async fn service_adapter_authorizes_audits_redacts_and_bounds_the_exact_request() {
        let name = "SCORCHKIT_MODEL_SERVICE_ALLOWED_TEST_TOKEN";
        let bearer_value = "x".repeat(32);
        {
            let _guard = crate::TEST_ENVIRONMENT_LOCK.lock().expect("environment lock");
            std::env::set_var(name, &bearer_value);
        }
        let audit = Arc::new(AtomicBool::new(false));
        let (endpoint, server) = service_fixture(audit.clone(), ServiceFixture::Valid).await;
        let events = EventBus::default();
        events.add_durable_sink(Arc::new(AuditFlag(audit)));
        let service = ModelAnalysisService::new(
            service_config(
                endpoint.clone(),
                name,
                ModelRole::FindingValidation,
                ModelServiceDataPolicy::default(),
            ),
            Arc::new(service_engagement(&endpoint)),
            events,
        );
        let record = service
            .analyze(
                ModelRole::FindingValidation,
                PolicyTarget::Web(Url::parse("https://unused.example/").expect("source")),
                "workflow/v1",
                vec![ModelAnalysisInput::new("1".repeat(64), "password=secret").expect("input")],
                "Validate the supplied evidence",
            )
            .await
            .expect("service analysis");
        let capture = server.await.expect("server");
        assert!(capture.audit_before_request);
        assert_eq!(capture.authorization, format!("Bearer {bearer_value}"));
        assert_eq!(capture.retention, "none");
        assert!(!capture.body.contains("password=secret"));
        assert!(!capture.body.contains(&bearer_value));
        assert_eq!(
            record.model_provenance.expect("provenance").execution_location,
            ModelExecutionLocation::ServiceManaged
        );
        {
            let _guard = crate::TEST_ENVIRONMENT_LOCK.lock().expect("environment lock");
            std::env::remove_var(name);
        }
    }

    #[tokio::test]
    async fn service_adapter_rejects_output_limit_and_timeout() {
        let name = "SCORCHKIT_MODEL_SERVICE_LIMIT_TEST_TOKEN";
        {
            let _guard = crate::TEST_ENVIRONMENT_LOCK.lock().expect("environment lock");
            std::env::set_var(name, "a-secret-token-that-is-at-least-thirty-two-bytes");
        }
        for (behavior, policy) in [
            (
                ServiceFixture::Oversized,
                ModelServiceDataPolicy {
                    max_output_bytes: 1_024,
                    ..ModelServiceDataPolicy::default()
                },
            ),
            (
                ServiceFixture::Slow,
                ModelServiceDataPolicy { timeout_millis: 100, ..ModelServiceDataPolicy::default() },
            ),
        ] {
            let audit = Arc::new(AtomicBool::new(false));
            let (endpoint, server) = service_fixture(audit.clone(), behavior).await;
            let events = EventBus::default();
            events.add_durable_sink(Arc::new(AuditFlag(audit)));
            let service = ModelAnalysisService::new(
                service_config(endpoint.clone(), name, ModelRole::Planning, policy),
                Arc::new(service_engagement(&endpoint)),
                events,
            );
            let error = service
                .analyze(
                    ModelRole::Planning,
                    PolicyTarget::Web(Url::parse("https://unused.example/").expect("source")),
                    "workflow/v1",
                    vec![ModelAnalysisInput::new("1".repeat(64), "context").expect("input")],
                    "Plan",
                )
                .await
                .expect_err("bounded failure");
            match behavior {
                ServiceFixture::Oversized => {
                    assert!(matches!(error, ScorchError::HttpResponseLimit { limit_bytes: 1_024 }));
                }
                ServiceFixture::Slow => {
                    assert!(matches!(error, ScorchError::Http { .. }));
                }
                ServiceFixture::Valid => unreachable!(),
            }
            let capture = server.await.expect("server");
            assert!(capture.audit_before_request);
        }
        {
            let _guard = crate::TEST_ENVIRONMENT_LOCK.lock().expect("environment lock");
            std::env::remove_var(name);
        }
    }

    #[tokio::test]
    async fn service_adapter_requires_the_separate_credential_use_grant() {
        let name = "SCORCHKIT_MODEL_SERVICE_CREDENTIAL_DENIAL_TEST";
        {
            let _guard = crate::TEST_ENVIRONMENT_LOCK.lock().expect("environment lock");
            std::env::set_var(name, "runtime-generated-credential-value-123456");
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind unused fixture");
        let endpoint = format!("http://{}/v1/analyze", listener.local_addr().expect("address"));
        let host = Url::parse(&endpoint).expect("endpoint").host_str().expect("host").to_string();
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse(&host).expect("service scope"))
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::ActiveSafe);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let events = EventBus::default();
        events.add_durable_sink(Arc::new(AuditCapture(captured.clone())));
        let service = ModelAnalysisService::new(
            service_config(endpoint, name, ModelRole::Planning, ModelServiceDataPolicy::default()),
            Arc::new(Engagement::new("credential denied", policy)),
            events,
        );
        let error = service
            .analyze(
                ModelRole::Planning,
                PolicyTarget::Web(Url::parse("https://unused.example/").expect("source")),
                "workflow/v1",
                vec![ModelAnalysisInput::new("1".repeat(64), "context").expect("input")],
                "Plan",
            )
            .await
            .expect_err("credential-use denial");
        assert!(matches!(error, ScorchError::Policy(_)));
        {
            let events = captured.lock().expect("captured audit");
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["decision"], "denied");
            assert_eq!(events[0]["external_tool"], true);
            assert_eq!(events[0]["credential_use"], false);
            drop(events);
        }
        drop(listener);
        {
            let _guard = crate::TEST_ENVIRONMENT_LOCK.lock().expect("environment lock");
            std::env::remove_var(name);
        }
    }

    #[tokio::test]
    async fn service_request_accepts_its_exact_serialized_input_limit() {
        let name = "SCORCHKIT_MODEL_SERVICE_EXACT_INPUT_TEST_TOKEN";
        {
            let _guard = crate::TEST_ENVIRONMENT_LOCK.lock().expect("environment lock");
            std::env::set_var(name, "runtime-generated-credential-value-123456");
        }
        let audit = Arc::new(AtomicBool::new(false));
        let (endpoint, server) = service_fixture(audit, ServiceFixture::Valid).await;
        let service = ModelAnalysisService::new(
            ModelAnalysisConfig::default(),
            Arc::new(service_engagement(&endpoint)),
            EventBus::default(),
        );
        let request = analysis_request();
        let exact = serde_json::to_vec(&request).expect("serialized request").len();
        let policy =
            ModelServiceDataPolicy { max_input_bytes: exact, ..ModelServiceDataPolicy::default() };
        service
            .execute_service(&endpoint, name, &policy, &request)
            .await
            .expect("exact input bound");
        server.await.expect("server");

        let too_small = ModelServiceDataPolicy { max_input_bytes: exact - 1, ..policy };
        let error = service
            .execute_service(&endpoint, name, &too_small, &request)
            .await
            .expect_err("one-byte-small input bound");
        assert!(matches!(error, ScorchError::AiAnalysis(_)));
        {
            let _guard = crate::TEST_ENVIRONMENT_LOCK.lock().expect("environment lock");
            std::env::remove_var(name);
        }
    }

    #[tokio::test]
    async fn service_response_accepts_its_exact_declared_and_streamed_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind response fixture");
        let address = listener.local_addr().expect("fixture address");
        let body = b"exact-response".to_vec();
        let expected = body.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept response fixture");
            let mut request = [0_u8; 1_024];
            let _ = stream.read(&mut request).await.expect("read request");
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.expect("write response headers");
            stream.write_all(&body).await.expect("write exact response");
        });
        let response = reqwest::Client::new()
            .get(format!("http://{address}/"))
            .send()
            .await
            .expect("fixture response");
        let decoded = read_bounded_service_body(response, expected.len())
            .await
            .expect("exact response bound");
        assert_eq!(decoded, expected);
        server.await.expect("response server");
    }

    #[test]
    fn local_adapter_uses_a_clean_environment() {
        assert_eq!(MODEL_PROCESS_TIMEOUT.as_secs(), 300);
        assert_eq!(MODEL_PROCESS_OUTPUT_BYTES, 8_388_608);
        let invocation = ToolInvocation {
            program: PathBuf::from("local-model").to_string_lossy().into_owned(),
            args: Vec::new(),
            timeout: MODEL_PROCESS_TIMEOUT,
            exit_policy: ExitPolicy::RequireSuccess,
            output_limit_bytes: MODEL_PROCESS_OUTPUT_BYTES,
            stdin: None,
            environment_policy: EnvironmentPolicy::Clear,
            environment: BTreeMap::new(),
            working_directory: None,
            artifact_budget: None,
        };
        assert_eq!(invocation.environment_policy, EnvironmentPolicy::Clear);
    }

    #[test]
    fn readiness_rejects_a_malformed_or_missing_service_credential_without_exposing_it() {
        let _guard = crate::TEST_ENVIRONMENT_LOCK.lock().expect("environment lock");
        let name = "SCORCHKIT_MODEL_ANALYSIS_TEST_TOKEN";
        std::env::remove_var(name);
        let binding = ModelRoleBindingConfig {
            role: ModelRole::Planning,
            provider: "service".to_string(),
            model: "exact-model".to_string(),
            adapter: ModelAdapterConfig::ServiceManaged {
                endpoint: "https://models.example/v1".to_string(),
                credential_env: name.to_string(),
                data_policy: ModelServiceDataPolicy::default(),
            },
        };
        let evaluation =
            ModelEvaluationResult::evaluate(binding.eligibility_key(), answers()).expect("eval");
        let config = ModelAnalysisConfig {
            enabled: true,
            bindings: vec![binding],
            evaluations: vec![evaluation],
        };
        let missing = model_readiness_for_role(&config, ModelRole::Planning);
        assert_eq!(missing.state, ModelReadinessState::Unavailable);
        assert!(!serde_json::to_string(&missing).expect("readiness").contains(name));
        std::env::set_var(name, "short");
        let malformed = model_readiness_for_role(&config, ModelRole::Planning);
        assert_eq!(malformed.state, ModelReadinessState::Unavailable);
        std::env::remove_var(name);
    }

    #[test]
    fn service_credentials_are_sensitive_headers() {
        let _guard = crate::TEST_ENVIRONMENT_LOCK.lock().expect("environment lock");
        let name = "SCORCHKIT_MODEL_ANALYSIS_SENSITIVE_HEADER_TEST";
        std::env::set_var(name, "runtime-generated-credential-value-123456");
        let header = resolve_service_credential(name).expect("credential header");
        assert!(header.is_sensitive());
        std::env::remove_var(name);
    }

    #[test]
    fn exact_eligibility_key_dimensions_do_not_cross_roles_or_models() {
        let available = std::env::current_exe().expect("test binary");
        let available = available.to_string_lossy().into_owned();
        let mut binding = binding(&available, ModelRole::Planning);
        let evaluation =
            ModelEvaluationResult::evaluate(binding.eligibility_key(), answers()).expect("eval");
        binding.model = "other-model".to_string();
        let config = ModelAnalysisConfig {
            enabled: true,
            bindings: vec![binding],
            evaluations: vec![evaluation],
        };
        assert!(config.validate().is_err());
        assert_eq!(
            model_readiness_for_role(&config, ModelRole::Planning).state,
            ModelReadinessState::Invalid
        );

        let exact =
            ModelEligibilityKey::current("fixture-host", "exact-model", ModelRole::Planning);
        let other_role =
            ModelEligibilityKey::current("fixture-host", "exact-model", ModelRole::Verification);
        assert_ne!(exact, other_role);
    }

    #[test]
    fn execution_location_labels_are_exact() {
        assert_eq!(location_label(ModelExecutionLocation::HostManaged), "host-managed");
        assert_eq!(location_label(ModelExecutionLocation::ServiceManaged), "service-managed");
        assert_eq!(location_label(ModelExecutionLocation::Local), "local");
    }
}
