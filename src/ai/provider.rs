//! Abstract AI provider trait (WORK-142).
//!
//! Defines the [`AiProvider`] trait that abstracts over different LLM
//! backends. The default implementation wraps the Claude CLI, but
//! future providers could wrap `OpenAI`, local models, or other APIs.

use async_trait::async_trait;

/// An AI provider that can generate text from prompts.
///
/// Implementors handle the specifics of connecting to an LLM backend
/// (API key management, HTTP transport, response parsing).
#[async_trait]
pub trait AiProvider: Send + Sync {
    /// Provider identifier (e.g. `"claude"`, `"openai"`, `"local"`).
    fn id(&self) -> &'static str;

    /// Human-readable provider name.
    fn name(&self) -> &'static str;

    /// Whether this provider is currently available (credentials
    /// configured, binary installed, etc.).
    fn is_available(&self) -> bool;

    /// Generate a response from a system prompt + user prompt pair.
    ///
    /// # Errors
    ///
    /// Returns an error string if the generation fails.
    async fn generate(&self, system: &str, user: &str) -> Result<String, String>;
}

/// The default Claude CLI provider.
///
/// Wraps the `claude` binary for AI generation. Available when the
/// Claude CLI is installed and configured.
#[derive(Debug, Default)]
pub struct ClaudeCliProvider;

#[async_trait]
impl AiProvider for ClaudeCliProvider {
    fn id(&self) -> &'static str {
        "claude-cli"
    }

    fn name(&self) -> &'static str {
        "Claude CLI"
    }

    fn is_available(&self) -> bool {
        std::process::Command::new("claude").arg("--version").output().is_ok()
    }

    async fn generate(&self, _system: &str, _user: &str) -> Result<String, String> {
        // Actual implementation delegates to the existing ai::analyst module.
        // This is a trait definition — the concrete implementation lives in
        // ai::analyst::run_claude_analysis which handles subprocess execution.
        Err("Use ai::analyst for Claude CLI integration".to_string())
    }
}

/// A no-op provider for when AI is disabled.
#[derive(Debug, Default)]
pub struct NoOpProvider;

#[async_trait]
impl AiProvider for NoOpProvider {
    fn id(&self) -> &'static str {
        "none"
    }

    fn name(&self) -> &'static str {
        "No AI Provider"
    }

    fn is_available(&self) -> bool {
        false
    }

    async fn generate(&self, _system: &str, _user: &str) -> Result<String, String> {
        Err("AI is disabled".to_string())
    }
}

/// Select the best available AI provider.
///
/// Returns the Claude CLI provider if available, otherwise the no-op
/// provider for graceful degradation.
#[must_use]
pub fn default_provider() -> Box<dyn AiProvider> {
    let claude = ClaudeCliProvider;
    if claude.is_available() {
        Box::new(claude)
    } else {
        Box::new(NoOpProvider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Claude CLI provider metadata.
    #[test]
    fn test_claude_provider_metadata() {
        let p = ClaudeCliProvider;
        assert_eq!(p.id(), "claude-cli");
        assert_eq!(p.name(), "Claude CLI");
    }

    /// `NoOp` provider is never available.
    #[test]
    fn test_noop_provider() {
        let p = NoOpProvider;
        assert_eq!(p.id(), "none");
        assert!(!p.is_available());
    }

    /// `default_provider` returns a provider (either Claude or `NoOp`).
    #[test]
    fn test_default_provider() {
        let p = default_provider();
        // Either claude-cli or none depending on installation
        assert!(!p.id().is_empty());
    }
}
