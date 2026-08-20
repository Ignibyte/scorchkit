//! Code scanning context — path-based alternative to `ScanContext`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use crate::runner::subprocess::{SystemToolExecutor, ToolExecutor, ToolInvocation, ToolOutput};

use super::error::Result;
use super::events::{EventBus, ScanEvent};
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
    ("Gemfile", "ruby"),
    ("composer.lock", "php"),
    ("composer.json", "php"),
    ("Dockerfile", "docker"),
    ("Dockerfile", "dockerfile"),
    ("docker-compose.yml", "yaml"),
    ("docker-compose.yaml", "yaml"),
    ("Chart.yaml", "yaml"),
    ("kustomization.yaml", "kubernetes"),
    ("kustomization.yml", "kubernetes"),
    ("foundry.toml", "solidity"),
    ("hardhat.config.js", "solidity"),
];

const LANGUAGE_ORDER: &[&str] = &[
    "rust",
    "javascript",
    "typescript",
    "go",
    "python",
    "java",
    "ruby",
    "php",
    "solidity",
    "terraform",
    "hcl",
    "yaml",
    "kubernetes",
    "docker",
    "dockerfile",
    "json",
    "c",
    "cpp",
    "csharp",
    "kotlin",
    "swift",
    "shell",
    "scala",
    "lua",
    "perl",
    "r",
    "dart",
];

const MAX_DISCOVERY_ENTRIES: usize = 200_000;
const DISCOVERY_SKIP_DIRECTORIES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "vendor",
    "dist",
    "build",
    ".gradle",
];

/// Shared context passed to every code scanning module.
#[derive(Clone, Debug)]
pub struct CodeContext {
    /// Root directory or file to scan.
    pub path: PathBuf,
    /// Detected or user-specified primary language.
    pub language: Option<String>,
    /// All explicitly selected or recursively detected project languages.
    pub languages: Vec<String>,
    /// Discovered manifest files in the bounded project tree.
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
        let languages = language.map_or_else(|| detect_languages(&path), |value| vec![value]);
        let detected_language = languages.first().cloned();
        Self {
            path,
            language: detected_language,
            languages,
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
        self.run_invocation(ToolInvocation::strict(tool_name, args, timeout)).await
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
        self.run_invocation(ToolInvocation::lenient(tool_name, args, timeout)).await
    }

    /// Execute a fully owned external-tool invocation after the code-tool authorization check.
    ///
    /// File-producing and multi-step adapters use this seam to set working directories and other
    /// bounded invocation fields without gaining access to the underlying executor.
    pub(crate) async fn run_invocation(&self, invocation: ToolInvocation) -> Result<ToolOutput> {
        self.require_tool_authorization()?;
        self.events.publish(ScanEvent::Custom {
            kind: "effect.subprocess_started".to_string(),
            data: serde_json::json!({
                "target": self.path,
                "program": crate::engine::observation::redact_text(&invocation.program),
                "capability": "external-tool",
                "effect": "passive",
            }),
        });
        self.tool_executor.execute(invocation).await
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

/// Detect the primary language from manifests, source files, and application deployment files.
#[must_use]
pub fn detect_language(path: &Path) -> Option<String> {
    detect_languages(path).into_iter().next()
}

/// Detect every language represented by the bounded project tree, preserving stable order.
#[must_use]
pub fn detect_languages(path: &Path) -> Vec<String> {
    let files = discover_project_files(path);
    let mut detected = std::collections::BTreeSet::new();
    for file in &files {
        let name = file.file_name().and_then(std::ffi::OsStr::to_str).unwrap_or_default();
        let mut is_known_manifest = false;
        for &(manifest, language) in MANIFEST_MAP {
            if name == manifest {
                is_known_manifest = true;
                detected.insert(language);
            }
        }
        if !is_known_manifest {
            for language in source_languages(file) {
                detected.insert(language);
            }
        }
    }

    let mut languages: Vec<String> = LANGUAGE_ORDER
        .iter()
        .filter(|language| detected.contains(**language))
        .map(|language| (*language).to_string())
        .collect();
    languages.extend(
        detected
            .iter()
            .filter(|language| !LANGUAGE_ORDER.contains(language))
            .map(|language| (*language).to_string()),
    );
    languages
}

/// Discover known manifest files in the bounded project tree.
#[must_use]
pub fn discover_manifests(path: &Path) -> Vec<PathBuf> {
    discover_project_files(path)
        .into_iter()
        .filter(|candidate| {
            candidate
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| MANIFEST_MAP.iter().any(|(manifest, _)| name == *manifest))
        })
        .collect()
}

fn discover_project_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    if !path.is_dir() {
        return Vec::new();
    }

    let mut files = Vec::new();
    let mut pending = vec![path.to_path_buf()];
    let mut inspected_entries = 0;
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        let mut entries: Vec<std::fs::DirEntry> =
            entries.filter_map(std::result::Result::ok).collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let mut child_directories = Vec::new();
        for entry in entries {
            inspected_entries += 1;
            if inspected_entries > MAX_DISCOVERY_ENTRIES {
                return files;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !DISCOVERY_SKIP_DIRECTORIES.contains(&name.as_ref()) {
                    child_directories.push(entry.path());
                }
            } else if file_type.is_file() {
                files.push(entry.path());
            }
        }
        pending.extend(child_directories.into_iter().rev());
    }
    files.sort();
    files
}

fn source_languages(path: &Path) -> &'static [&'static str] {
    let name = path.file_name().and_then(std::ffi::OsStr::to_str).unwrap_or_default();
    let lower_name = name.to_ascii_lowercase();
    if name == "Dockerfile" || lower_name.ends_with(".dockerfile") {
        return &["docker", "dockerfile"];
    }
    let extension =
        path.extension().and_then(std::ffi::OsStr::to_str).unwrap_or_default().to_ascii_lowercase();
    match extension.as_str() {
        "rs" => &["rust"],
        "js" | "jsx" | "mjs" | "cjs" => &["javascript"],
        "ts" | "tsx" | "mts" | "cts" => &["typescript"],
        "go" => &["go"],
        "py" | "pyw" => &["python"],
        "java" => &["java"],
        "rb" => &["ruby"],
        "php" | "phtml" => &["php"],
        "sol" => &["solidity"],
        "tf" | "tfvars" => &["terraform", "hcl"],
        "hcl" => &["hcl"],
        "yaml" | "yml" => &["yaml"],
        "json" => &["json"],
        "c" | "h" => &["c"],
        "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => &["cpp"],
        "cs" => &["csharp"],
        "kt" | "kts" => &["kotlin"],
        "swift" => &["swift"],
        "sh" | "bash" | "zsh" => &["shell"],
        "scala" => &["scala"],
        "lua" => &["lua"],
        "pl" | "pm" => &["perl"],
        "r" => &["r"],
        "dart" => &["dart"],
        _ => &[],
    }
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

    #[test]
    fn detects_every_distinct_root_manifest_language_in_stable_order() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("Cargo.toml"), "[package]")?;
        fs::write(dir.path().join("Cargo.lock"), "")?;
        fs::write(dir.path().join("package.json"), "{}")?;
        fs::write(dir.path().join("pyproject.toml"), "")?;
        assert_eq!(detect_languages(dir.path()), ["rust", "javascript", "python"]);

        let context = CodeContext::new(
            dir.path().to_path_buf(),
            None,
            Arc::new(AppConfig::default()),
            Vec::new(),
        );
        assert_eq!(context.language.as_deref(), Some("rust"));
        assert_eq!(context.languages, ["rust", "javascript", "python"]);
        Ok(())
    }

    #[test]
    fn detects_nested_source_only_and_application_iac_languages() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::create_dir_all(dir.path().join("services/api/src"))?;
        fs::create_dir_all(dir.path().join("deploy"))?;
        fs::write(dir.path().join("services/api/src/main.ts"), "export {};")?;
        fs::write(dir.path().join("deploy/main.tf"), "resource \"x\" \"y\" {}")?;
        fs::write(dir.path().join("deploy/workload.yaml"), "apiVersion: v1\nkind: Pod")?;
        fs::write(dir.path().join("deploy/Dockerfile"), "FROM scratch")?;
        fs::write(dir.path().join("Contract.sol"), "contract Fixture {}")?;

        assert_eq!(
            detect_languages(dir.path()),
            ["typescript", "solidity", "terraform", "hcl", "yaml", "docker", "dockerfile"]
        );
        Ok(())
    }

    #[test]
    fn detects_a_single_source_file_target() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("app.py");
        fs::write(&file, "print('ok')")?;
        assert_eq!(detect_languages(&file), ["python"]);
        assert!(discover_manifests(&file).is_empty());
        Ok(())
    }

    #[test]
    fn recursive_discovery_does_not_follow_symlinked_directories() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("main.py"), "print('outside')")?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), dir.path().join("linked"))?;

        #[cfg(unix)]
        assert!(detect_languages(dir.path()).is_empty());
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

    #[test]
    fn source_language_mapping_covers_every_declared_extension() {
        let cases: &[(&str, &[&str])] = &[
            ("Dockerfile", &["docker", "dockerfile"]),
            ("service.dockerfile", &["docker", "dockerfile"]),
            ("lib.rs", &["rust"]),
            ("app.js", &["javascript"]),
            ("main.go", &["go"]),
            ("Main.java", &["java"]),
            ("app.rb", &["ruby"]),
            ("index.php", &["php"]),
            ("variables.hcl", &["hcl"]),
            ("data.json", &["json"]),
            ("header.h", &["c"]),
            ("source.cpp", &["cpp"]),
            ("Program.cs", &["csharp"]),
            ("build.kts", &["kotlin"]),
            ("App.swift", &["swift"]),
            ("check.sh", &["shell"]),
            ("Main.scala", &["scala"]),
            ("script.lua", &["lua"]),
            ("module.pm", &["perl"]),
            ("analysis.r", &["r"]),
            ("main.dart", &["dart"]),
        ];

        for (name, expected) in cases {
            assert_eq!(source_languages(Path::new(name)), *expected, "language mapping for {name}");
        }
    }

    #[test]
    fn recursive_discovery_keeps_the_exact_safety_cap_contract() {
        assert_eq!(MAX_DISCOVERY_ENTRIES, 200_000);
        let production = include_str!("code_context.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        let compact: String = production.split_whitespace().collect();
        assert!(compact.contains(
            "inspected_entries+=1;ifinspected_entries>MAX_DISCOVERY_ENTRIES{returnfiles;}"
        ));
    }
}
