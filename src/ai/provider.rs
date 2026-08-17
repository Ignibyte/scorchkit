//! Provider-neutral AI generation boundary.
//!
//! The built-in adapter favors Codex in non-interactive, read-only mode. A
//! Claude CLI adapter remains available for compatibility. Callers consume
//! normalized text and do not need to understand either CLI's response format.

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::config::{AiConfig, AiProviderKind};
use crate::runner::subprocess::{
    ExitPolicy, SystemToolExecutor, ToolExecutor, ToolInvocation, DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
};

const AI_PROCESS_TIMEOUT: Duration = Duration::from_mins(5);

/// Normalized response from an AI provider.
#[derive(Debug, Clone, PartialEq)]
pub struct AiProviderResponse {
    /// Provider's final response text.
    pub content: String,
    /// Provider-reported or configured model, when available.
    pub model: Option<String>,
    /// Provider-reported cost, when available.
    pub cost_usd: Option<f64>,
}

/// An AI provider that can generate text from prompts.
#[async_trait]
pub trait AiProvider: Debug + Send + Sync {
    /// Stable provider identifier.
    fn id(&self) -> &'static str;

    /// Human-readable provider name.
    fn name(&self) -> &'static str;

    /// Whether this provider's configured host executable is available.
    fn is_available(&self) -> bool;

    /// Generate a response from a system prompt and user prompt.
    async fn generate(
        &self,
        system: &str,
        user: &str,
    ) -> std::result::Result<AiProviderResponse, String>;
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

    fn invocation(&self, system: &str, user: &str) -> ToolInvocation {
        match self.kind {
            AiProviderKind::Codex => self.codex_invocation(system, user),
            AiProviderKind::Claude => self.claude_invocation(system, user),
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

    fn normalize_response(&self, stdout: &str) -> AiProviderResponse {
        if self.kind == AiProviderKind::Claude {
            if let Ok(envelope) = serde_json::from_str::<serde_json::Value>(stdout) {
                let content = envelope["result"]
                    .as_str()
                    .or_else(|| envelope["content"].as_str())
                    .unwrap_or(stdout)
                    .to_string();
                return AiProviderResponse {
                    content,
                    model: envelope["model"]
                        .as_str()
                        .map(String::from)
                        .or_else(|| self.model.clone()),
                    cost_usd: envelope["cost_usd"].as_f64(),
                };
            }
        }

        AiProviderResponse {
            content: stdout.to_string(),
            model: self.model.clone(),
            cost_usd: None,
        }
    }
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

    async fn generate(
        &self,
        system: &str,
        user: &str,
    ) -> std::result::Result<AiProviderResponse, String> {
        let output = self
            .executor
            .execute(self.invocation(system, user))
            .await
            .map_err(|error| format!("{} host failed: {error}", self.name()))?;
        Ok(self.normalize_response(&output.stdout))
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

    async fn generate(
        &self,
        _system: &str,
        _user: &str,
    ) -> std::result::Result<AiProviderResponse, String> {
        Err("AI is disabled".to_string())
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
    use crate::engine::error::Result;
    use crate::runner::subprocess::ToolOutput;

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
        *executor.stdout.lock().expect("stdout lock") = "{\"risk_score\":1}".to_string();
        let provider = CliAiProvider::with_executor(&AiConfig::default(), executor.clone());

        let response = provider.generate("system", "user").await.expect("generation");
        assert_eq!(provider.id(), "codex-cli");
        assert_eq!(provider.name(), "Codex CLI");
        assert_eq!(response.content, "{\"risk_score\":1}");

        let invocation = executor
            .invocations
            .lock()
            .expect("invocation lock")
            .first()
            .cloned()
            .expect("recorded invocation");
        assert_eq!(invocation.program, "codex");
        assert!(invocation.args.windows(2).any(|pair| pair == ["--sandbox", "read-only"]));
        assert!(invocation.args.iter().any(|argument| argument == "--ephemeral"));
        assert!(invocation.args.iter().any(|argument| argument == "--ignore-user-config"));
        assert_eq!(invocation.args.last().map(String::as_str), Some("-"));
        assert_eq!(
            invocation.stdin.as_deref(),
            Some(b"SYSTEM INSTRUCTIONS:\nsystem\n\nUSER REQUEST:\nuser".as_slice())
        );
    }

    #[tokio::test]
    async fn claude_adapter_normalizes_legacy_envelope() {
        let executor = Arc::new(RecordingExecutor::default());
        *executor.stdout.lock().expect("stdout lock") = serde_json::json!({
            "result": "final text",
            "model": "compat-model",
            "cost_usd": 0.04
        })
        .to_string();
        let config = AiConfig {
            provider: AiProviderKind::Claude,
            model: Some("requested-model".to_string()),
            max_budget_usd: Some(0.5),
            ..AiConfig::default()
        };
        let provider = CliAiProvider::with_executor(&config, executor.clone());

        let response = provider.generate("system", "user").await.expect("generation");
        assert_eq!(provider.name(), "Claude CLI");
        assert_eq!(response.content, "final text");
        assert_eq!(response.model.as_deref(), Some("compat-model"));
        assert_eq!(response.cost_usd, Some(0.04));

        let invocation = executor
            .invocations
            .lock()
            .expect("invocation lock")
            .first()
            .cloned()
            .expect("recorded invocation");
        assert_eq!(invocation.program, "claude");
        assert!(invocation.args.windows(2).any(|pair| pair == ["--system-prompt", "system"]));
        assert!(invocation.args.windows(2).any(|pair| pair == ["--model", "requested-model"]));
        assert!(invocation.args.windows(2).any(|pair| pair == ["--max-budget-usd", "0.5"]));
    }

    #[test]
    fn claude_budget_must_be_strictly_positive() {
        for budget in [0.0, -0.01] {
            let config = AiConfig {
                provider: AiProviderKind::Claude,
                max_budget_usd: Some(budget),
                ..AiConfig::default()
            };
            let invocation =
                CliAiProvider::with_executor(&config, Arc::new(RecordingExecutor::default()))
                    .invocation("system", "user");
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
