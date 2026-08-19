//! Code scanning context — path-based alternative to `ScanContext`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use crate::runner::subprocess::{SystemToolExecutor, ToolExecutor, ToolInvocation, ToolOutput};

use super::error::Result;
use super::events::EventBus;
use super::policy::{AuthorizationDecision, Capability, EffectClass, PolicyTarget};
use super::shared_data::SharedData;

/// Known manifest filenames and their associated languages.
const MANIFEST_MAP: &[(&str, &str)] = &[
    ("Cargo.toml", "rust"),
    ("Cargo.lock", "rust"),
    ("package.json", "javascript"),
    ("package-lock.json", "javascript"),
    ("yarn.lock", "javascript"),
    ("pnpm-lock.yaml", "javascript"),
    ("go.mod", "go"),
    ("go.sum", "go"),
    ("requirements.txt", "python"),
    ("poetry.lock", "python"),
    ("Pipfile.lock", "python"),
    ("pyproject.toml", "python"),
    ("pom.xml", "java"),
    ("build.gradle", "java"),
    ("Gemfile.lock", "ruby"),
    ("composer.lock", "php"),
];

/// Shared context passed to every code scanning module.
#[derive(Clone, Debug)]
pub struct CodeContext {
    /// Root directory or file to scan.
    pub path: PathBuf,
    /// Detected or user-specified primary language.
    pub language: Option<String>,
    /// Discovered manifest files in the scan root.
    pub manifests: Vec<PathBuf>,
    /// Application configuration.
    pub config: Arc<AppConfig>,
    /// Shared data store for inter-module communication.
    pub shared_data: Arc<SharedData>,
    /// In-process event bus for scan lifecycle events.
    pub events: EventBus,
    /// External-process boundary used by tool-backed code modules.
    tool_executor: Arc<dyn ToolExecutor>,
    /// Opaque proof that the context was created by the policy-gated engine.
    authorization: Vec<AuthorizationDecision>,
}

impl CodeContext {
    /// Create a new code context, auto-detecting language and manifests.
    #[must_use]
    pub(crate) fn new(
        path: PathBuf,
        language: Option<String>,
        config: Arc<AppConfig>,
        authorization: Vec<AuthorizationDecision>,
    ) -> Self {
        let manifests = discover_manifests(&path);
        let detected_language = language.or_else(|| detect_language(&path));
        Self {
            path,
            language: detected_language,
            manifests,
            config,
            shared_data: Arc::new(SharedData::new()),
            events: EventBus::default(),
            tool_executor: Arc::new(SystemToolExecutor),
            authorization,
        }
    }

    /// Replace the production process executor, primarily for contract tests.
    #[must_use]
    pub fn with_tool_executor(mut self, tool_executor: Arc<dyn ToolExecutor>) -> Self {
        self.tool_executor = tool_executor;
        self
    }

    /// Execute an external tool and require a successful exit status.
    ///
    /// # Errors
    ///
    /// Returns executor errors for resolution, spawn, exit, timeout, or output limits.
    pub async fn run_tool(
        &self,
        tool_name: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<ToolOutput> {
        self.require_tool_authorization()?;
        self.tool_executor.execute(ToolInvocation::strict(tool_name, args, timeout)).await
    }

    /// Execute an external tool while accepting normal non-zero finding exits.
    ///
    /// # Errors
    ///
    /// Returns executor errors for resolution, spawn, timeout, or output limits.
    pub async fn run_tool_lenient(
        &self,
        tool_name: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<ToolOutput> {
        self.require_tool_authorization()?;
        self.tool_executor.execute(ToolInvocation::lenient(tool_name, args, timeout)).await
    }

    /// Execute a passive code-family compatibility tool that consumes ambient credentials.
    ///
    /// # Errors
    ///
    /// Returns an authorization error unless the context carries exact external-tool and
    /// credential-use grants for the canonical code target.
    pub(crate) async fn run_credential_tool_lenient(
        &self,
        tool_name: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<ToolOutput> {
        self.require_tool_authorization()?;
        self.require_credential_authorization()?;
        self.tool_executor.execute(ToolInvocation::lenient(tool_name, args, timeout)).await
    }

    /// Execute an authorized external tool with owned standard input.
    pub(crate) async fn run_tool_with_stdin(
        &self,
        tool_name: &str,
        stdin: &[u8],
        timeout: Duration,
    ) -> Result<ToolOutput> {
        self.require_tool_authorization()?;
        self.tool_executor
            .execute(ToolInvocation::strict(tool_name, &[], timeout).with_stdin(stdin))
            .await
    }

    fn require_tool_authorization(&self) -> Result<()> {
        if cfg!(test) && self.authorization.is_empty() {
            return Ok(());
        }
        let target = PolicyTarget::Code(self.path.clone());
        if self.authorization.iter().any(|decision| {
            super::policy::decision_grants_exactly(
                decision,
                &target,
                Capability::ExternalTool,
                EffectClass::Passive,
            )
        }) {
            return Ok(());
        }
        Err(crate::engine::error::ScorchError::Config(format!(
            "code tool denied: context has no ExternalTool/Passive grant for {target}"
        )))
    }

    fn require_credential_authorization(&self) -> Result<()> {
        let target = PolicyTarget::Code(self.path.clone());
        if self.authorization.iter().any(|decision| {
            super::policy::decision_grants_exactly(
                decision,
                &target,
                Capability::CredentialUse,
                EffectClass::Passive,
            )
        }) {
            return Ok(());
        }
        Err(crate::engine::error::ScorchError::Config(format!(
            "credential-bearing code tool denied: context has no CredentialUse/Passive grant for {target}"
        )))
    }
}

/// Detect the primary language by checking for manifest files at the root.
///
/// Returns the language associated with the first matching manifest file.
#[must_use]
pub fn detect_language(path: &Path) -> Option<String> {
    if !path.is_dir() {
        return None;
    }
    for &(manifest, language) in MANIFEST_MAP {
        if path.join(manifest).exists() {
            return Some(language.to_string());
        }
    }
    None
}

/// Discover manifest files in the scan root directory.
///
/// Checks for known manifest filenames (non-recursive, root only).
#[must_use]
pub fn discover_manifests(path: &Path) -> Vec<PathBuf> {
    if !path.is_dir() {
        return Vec::new();
    }
    MANIFEST_MAP.iter().map(|&(name, _)| path.join(name)).filter(|p| p.exists()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::policy::{AuthorizationDecision, DenialReason};
    use std::fs;
    use uuid::Uuid;

    /// Verify `Cargo.toml` is detected as Rust.
    #[test]
    fn test_detect_language_rust() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("Cargo.toml"), "[package]")?;
        assert_eq!(detect_language(dir.path()), Some("rust".to_string()));
        Ok(())
    }

    /// Verify `package.json` is detected as JavaScript.
    #[test]
    fn test_detect_language_javascript() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("package.json"), "{}")?;
        assert_eq!(detect_language(dir.path()), Some("javascript".to_string()));
        Ok(())
    }

    /// Verify empty directory returns `None`.
    #[test]
    fn test_detect_language_none() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        assert_eq!(detect_language(dir.path()), None);
        Ok(())
    }

    /// Verify manifest discovery finds expected files.
    #[test]
    fn test_discover_manifests() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("Cargo.toml"), "[package]")?;
        fs::write(dir.path().join("Cargo.lock"), "")?;
        let manifests = discover_manifests(dir.path());
        assert_eq!(manifests.len(), 2);
        Ok(())
    }

    #[test]
    fn code_tool_authorization_requires_an_exact_grant() -> std::io::Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().canonicalize()?;
        let target = PolicyTarget::Code(path.clone());
        let grant = AuthorizationDecision {
            engagement_id: Uuid::nil(),
            target: target.clone(),
            capability: Capability::ExternalTool,
            effect: EffectClass::Passive,
            allowed: true,
            matched_scope: None,
            denial: None,
        };
        let allowed =
            CodeContext::new(path.clone(), None, Arc::new(AppConfig::default()), vec![grant]);
        assert!(allowed.require_tool_authorization().is_ok());

        let denied = CodeContext::new(
            path,
            None,
            Arc::new(AppConfig::default()),
            vec![AuthorizationDecision {
                engagement_id: Uuid::nil(),
                target,
                capability: Capability::CodeScan,
                effect: EffectClass::Passive,
                allowed: false,
                matched_scope: None,
                denial: Some(DenialReason::CapabilityNotGranted),
            }],
        );
        assert!(denied.require_tool_authorization().is_err());
        Ok(())
    }

    #[test]
    fn credential_bearing_code_tool_requires_a_separate_exact_grant() -> std::io::Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().canonicalize()?;
        let target = PolicyTarget::Code(path.clone());
        let tool_grant = AuthorizationDecision {
            engagement_id: Uuid::nil(),
            target: target.clone(),
            capability: Capability::ExternalTool,
            effect: EffectClass::Passive,
            allowed: true,
            matched_scope: None,
            denial: None,
        };
        let credential_grant = AuthorizationDecision {
            engagement_id: Uuid::nil(),
            target,
            capability: Capability::CredentialUse,
            effect: EffectClass::Passive,
            allowed: true,
            matched_scope: None,
            denial: None,
        };

        let denied = CodeContext::new(
            path.clone(),
            None,
            Arc::new(AppConfig::default()),
            vec![tool_grant.clone()],
        );
        assert!(denied.require_credential_authorization().is_err());

        let allowed = CodeContext::new(
            path,
            None,
            Arc::new(AppConfig::default()),
            vec![tool_grant, credential_grant],
        );
        assert!(allowed.require_credential_authorization().is_ok());
        Ok(())
    }
}
