use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use scorchkit::config::AppConfig;
use scorchkit::engine::code_context::CodeContext;
use scorchkit::engine::code_module::CodeModule;
use scorchkit::engine::module_trait::ScanModule;
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::scan_context::ScanContext;
use scorchkit::runner::plugin::{PluginDef, PluginModule};
use scorchkit::runner::subprocess::{
    EnvironmentPolicy, ExitPolicy, ToolExecutor, ToolInvocation, ToolOutput,
    DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
};
use scorchkit::{Engine, Result, ScopeRule};

#[cfg(feature = "cloud")]
use scorchkit::engine::cloud_context::CloudContext;
#[cfg(feature = "cloud")]
use scorchkit::engine::cloud_module::CloudModule;
#[cfg(feature = "infra")]
use scorchkit::engine::infra_context::InfraContext;

#[derive(Debug, Default)]
struct RecordingToolExecutor {
    invocations: Mutex<Vec<ToolInvocation>>,
    emit_sast_outputs: bool,
}

impl RecordingToolExecutor {
    fn recorded(&self) -> MutexGuard<'_, Vec<ToolInvocation>> {
        self.invocations.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn len(&self) -> usize {
        self.recorded().len()
    }

    fn last(&self) -> ToolInvocation {
        self.recorded()
            .last()
            .cloned()
            .unwrap_or_else(|| panic!("expected a recorded tool invocation"))
    }

    const fn with_sast_outputs() -> Self {
        Self { invocations: Mutex::new(Vec::new()), emit_sast_outputs: true }
    }
}

#[async_trait]
impl ToolExecutor for RecordingToolExecutor {
    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput> {
        let resolved_program = PathBuf::from(format!("/mock/{}", invocation.program));
        let stdout = if self.emit_sast_outputs && invocation.program == "semgrep" {
            r#"{
                "version":"1.156.0",
                "errors":[],
                "results":[{
                    "check_id":"scorchkit.python.dangerous-eval",
                    "path":"app.py",
                    "start":{"line":2,"col":1},
                    "end":{"line":2,"col":12},
                    "extra":{
                        "severity":"ERROR",
                        "message":"Avoid dynamic evaluation",
                        "lines":"eval(user_input)"
                    }
                }]
            }"#
            .to_string()
        } else {
            String::new()
        };
        if self.emit_sast_outputs && invocation.program == "codeql" {
            if let Some(path) =
                invocation.args.iter().find_map(|argument| argument.strip_prefix("--output="))
            {
                std::fs::write(path, include_str!("fixtures/sast/codeql-path.sarif.json"))?;
            }
        }
        if self.emit_sast_outputs && invocation.program == "psalm" {
            if let Some(path) =
                invocation.args.iter().find_map(|argument| argument.strip_prefix("--report="))
            {
                std::fs::write(path, include_str!("fixtures/sast/psalm-taint.sarif.json"))?;
            }
        }
        self.recorded().push(invocation);
        Ok(ToolOutput {
            stdout,
            stderr: String::new(),
            exit_code: 0,
            duration: Duration::ZERO,
            resolved_program,
        })
    }
}

fn authorized_dast_context(target: &str) -> Result<ScanContext> {
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::Exact("example.com".to_string()))
        .allow_capability(Capability::DastScan)
        .allow_capability(Capability::ExternalTool)
        .allow_capability(Capability::CredentialUse)
        .allow_capability(Capability::Exploit)
        .allow_effect(EffectClass::Passive)
        .allow_effect(EffectClass::Intrusive)
        .allow_effect(EffectClass::CredentialTest)
        .allow_effect(EffectClass::Exploit);
    Engine::for_engagement(
        Arc::new(AppConfig::default()),
        Arc::new(Engagement::new("DAST contract", policy)),
    )
    .dast_context(target, "pentest")
}

fn dast_context_without_external_tool_grant(target: &str) -> Result<ScanContext> {
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::Exact("example.com".to_string()))
        .allow_capability(Capability::DastScan)
        .allow_effect(EffectClass::Intrusive);
    Engine::for_engagement(
        Arc::new(AppConfig::default()),
        Arc::new(Engagement::new("DAST no-tool contract", policy)),
    )
    .dast_context(target, "standard")
}

fn dast_context_without_credential_grant(target: &str) -> Result<ScanContext> {
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::Exact("example.com".to_string()))
        .allow_capability(Capability::DastScan)
        .allow_capability(Capability::ExternalTool)
        .allow_effect(EffectClass::Intrusive);
    Engine::for_engagement(
        Arc::new(AppConfig::default()),
        Arc::new(Engagement::new("DAST no-credential contract", policy)),
    )
    .dast_context(target, "thorough")
}

fn authorized_code_context(path: &std::path::Path) -> Result<CodeContext> {
    authorized_code_context_with(path, AppConfig::default(), None)
}

fn authorized_code_context_with(
    path: &std::path::Path,
    config: AppConfig,
    language: Option<&str>,
) -> Result<CodeContext> {
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::path_prefix(path)?)
        .allow_capability(Capability::CodeScan)
        .allow_capability(Capability::ExternalTool)
        .allow_capability(Capability::CredentialUse)
        .allow_effect(EffectClass::Passive);
    Engine::for_engagement(Arc::new(config), Arc::new(Engagement::new("SAST contract", policy)))
        .code_context(path, language)
}

fn code_context_without_credential_grant(path: &std::path::Path) -> Result<CodeContext> {
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::path_prefix(path)?)
        .allow_capability(Capability::CodeScan)
        .allow_capability(Capability::ExternalTool)
        .allow_effect(EffectClass::Passive);
    Engine::for_engagement(
        Arc::new(AppConfig::default()),
        Arc::new(Engagement::new("SAST no-credential contract", policy)),
    )
    .code_context(path, None)
}

#[cfg(feature = "infra")]
fn authorized_infra_context(target: &str) -> Result<InfraContext> {
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::Exact(target.to_string()))
        .allow_capability(Capability::InfraScan)
        .allow_capability(Capability::ExternalTool)
        .allow_effect(EffectClass::ActiveSafe);
    Engine::for_engagement(
        Arc::new(AppConfig::default()),
        Arc::new(Engagement::new("infra contract", policy)),
    )
    .infra_context(target)
}

#[cfg(feature = "cloud")]
fn authorized_cloud_context(target: &str) -> Result<CloudContext> {
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::cloud(target))
        .allow_capability(Capability::CloudScan)
        .allow_capability(Capability::ExternalTool)
        .allow_capability(Capability::CredentialUse)
        .allow_effect(EffectClass::Passive);
    Engine::for_engagement(
        Arc::new(AppConfig::default()),
        Arc::new(Engagement::new("cloud contract", policy)),
    )
    .cloud_context(target)
}

fn assert_invocation_contract(
    module_id: &str,
    declared_tool: Option<&str>,
    invocation: &ToolInvocation,
) {
    assert_eq!(
        Some(invocation.program.as_str()),
        declared_tool,
        "{module_id} must execute the tool it declares"
    );
    assert!(!invocation.timeout.is_zero(), "{module_id} must have a bounded timeout");
    assert_eq!(
        invocation.output_limit_bytes, DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
        "{module_id} must use the shared output limit"
    );
    assert!(
        matches!(
            &invocation.exit_policy,
            ExitPolicy::RequireSuccess | ExitPolicy::AllowNonZero | ExitPolicy::AcceptedCodes(_)
        ),
        "{module_id} must declare an exit policy"
    );
}

#[tokio::test]
async fn every_dast_tool_wrapper_executes_its_declared_invocation() -> Result<()> {
    let recorder = Arc::new(RecordingToolExecutor::default());
    let injected: Arc<dyn ToolExecutor> = recorder.clone();
    let context =
        authorized_dast_context("https://example.com/?id=1")?.with_tool_executor(injected);
    let modules = scorchkit::tools::register_modules();

    assert_eq!(modules.len(), 44, "DAST tool registry contract changed");
    let mut process_backed = 0usize;
    for module in modules {
        assert!(
            module.requires_external_tool(),
            "{} must declare its tool dependency",
            module.id()
        );
        if module.id() == "interactsh" {
            // Interactsh owns a long-lived callback session rather than one bounded invocation.
            continue;
        }

        let before = recorder.len();
        let _module_outcome = module.run(&context).await;
        assert_eq!(
            recorder.len(),
            before + 1,
            "{} returned without executing its external tool",
            module.id()
        );
        assert_invocation_contract(module.id(), module.required_tool(), &recorder.last());
        process_backed += 1;
    }

    assert_eq!(process_backed, 43, "all non-session DAST wrappers must use the shared executor");
    Ok(())
}

#[tokio::test]
async fn long_lived_interactsh_session_is_denied_before_process_start() -> Result<()> {
    let context = dast_context_without_external_tool_grant("https://example.com/?url=test")?;
    let error = scorchkit::tools::interactsh::InteractshModule::default()
        .run(&context)
        .await
        .expect_err("Interactsh must require an external-tool grant");
    assert!(error.to_string().contains("external tool denied"));
    Ok(())
}

#[tokio::test]
async fn prowler_is_denied_before_inheriting_ambient_credentials() -> Result<()> {
    use scorchkit::engine::module_trait::ScanModule;

    let recorder = Arc::new(RecordingToolExecutor::default());
    let injected: Arc<dyn ToolExecutor> = recorder.clone();
    let context =
        dast_context_without_credential_grant("https://example.com")?.with_tool_executor(injected);

    let error = scorchkit::tools::prowler::ProwlerModule
        .run(&context)
        .await
        .expect_err("Prowler must require credential-use authorization");
    assert!(error.to_string().contains("CredentialUse/Passive"));
    assert_eq!(recorder.len(), 0);
    Ok(())
}

#[tokio::test]
async fn every_sast_tool_wrapper_executes_its_declared_invocation() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("Dockerfile"), "FROM scratch\n")?;
    std::fs::write(root.path().join("package.json"), "{}\n")?;
    std::fs::write(root.path().join("composer.json"), "{}\n")?;
    let recorder = Arc::new(RecordingToolExecutor::default());
    let injected: Arc<dyn ToolExecutor> = recorder.clone();
    let context = authorized_code_context(root.path())?.with_tool_executor(injected);
    let modules = scorchkit::sast_tools::register_modules();

    assert_eq!(modules.len(), 21, "SAST tool registry contract changed");
    for module in modules {
        assert!(
            module.requires_external_tool(),
            "{} must declare its tool dependency",
            module.id()
        );
        let before = recorder.len();
        let _module_outcome = module.run(&context).await;
        let expected_invocations = if module.id() == "codeql" { 2 } else { 1 };
        assert_eq!(
            recorder.len(),
            before + expected_invocations,
            "{} did not execute its complete external-tool contract",
            module.id()
        );
        for invocation in &recorder.recorded()[before..] {
            assert_invocation_contract(module.id(), module.required_tool(), invocation);
        }
    }

    assert_eq!(recorder.len(), 22);
    Ok(())
}

#[tokio::test]
async fn semgrep_rejects_digest_mismatch_before_process_execution() -> Result<()> {
    let root = tempfile::tempdir()?;
    let rules = root.path().join("rules.yml");
    std::fs::write(
        &rules,
        "rules:\n  - id: fixture\n    languages: [python]\n    message: fixture\n    severity: ERROR\n    pattern: eval(...)\n",
    )?;
    let mut config = AppConfig::default();
    config.sast.semgrep.local_rule_file = Some(rules);
    config.sast.semgrep.local_rule_sha256 = Some("0".repeat(64));
    let recorder = Arc::new(RecordingToolExecutor::default());
    let injected: Arc<dyn ToolExecutor> = recorder.clone();
    let context = authorized_code_context_with(root.path(), config, Some("python"))?
        .with_tool_executor(injected);

    let error = scorchkit::sast_tools::semgrep::SemgrepModule
        .run(&context)
        .await
        .expect_err("digest mismatch must fail");

    assert!(error.to_string().contains("digest mismatch"));
    assert_eq!(recorder.len(), 0, "invalid rules must fail before the executor");
    Ok(())
}

#[tokio::test]
async fn semgrep_executes_the_owned_offline_rule_pack_and_records_its_digest() -> Result<()> {
    let root = tempfile::tempdir()?;
    let recorder = Arc::new(RecordingToolExecutor::with_sast_outputs());
    let injected: Arc<dyn ToolExecutor> = recorder.clone();
    let context = authorized_code_context_with(root.path(), AppConfig::default(), Some("python"))?
        .with_tool_executor(injected);

    let findings = scorchkit::sast_tools::semgrep::SemgrepModule.run(&context).await?;

    assert_eq!(findings.len(), 1);
    let identity =
        findings[0].appsec.provenance.config_identity.as_deref().expect("Semgrep config identity");
    assert!(identity.starts_with("scorchkit-semgrep-appsec/v1@sha256:"));
    assert_eq!(identity.len(), "scorchkit-semgrep-appsec/v1@sha256:".len() + 64);
    let invocation = recorder.last();
    assert_invocation_contract("semgrep", Some("semgrep"), &invocation);
    assert_eq!(invocation.args.first().map(String::as_str), Some("scan"));
    assert!(invocation.args.iter().any(|argument| argument == "--metrics=off"));
    assert!(invocation.args.iter().any(|argument| argument == "--disable-version-check"));
    assert!(invocation.args.iter().any(|argument| argument == "--dataflow-traces"));
    assert!(!invocation.args.iter().any(|argument| argument == "auto"));
    let config_index = invocation
        .args
        .iter()
        .position(|argument| argument == "--config")
        .expect("Semgrep config argument");
    let materialized = PathBuf::from(&invocation.args[config_index + 1]);
    assert!(materialized.is_absolute());
    assert!(!materialized.exists(), "owned rule file must be removed after the scan");
    Ok(())
}

#[tokio::test]
async fn codeql_executes_no_build_create_then_offline_analyze_and_cleans_artifacts() -> Result<()> {
    let root = tempfile::tempdir()?;
    let recorder = Arc::new(RecordingToolExecutor::with_sast_outputs());
    let injected: Arc<dyn ToolExecutor> = recorder.clone();
    let context = authorized_code_context_with(root.path(), AppConfig::default(), Some("python"))?
        .with_tool_executor(injected);

    let findings = scorchkit::sast_tools::codeql::CodeqlModule.run(&context).await?;

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].appsec.code_flows[0].thread_flows[0].steps.len(), 3);
    let invocations = recorder.recorded().clone();
    assert_eq!(invocations.len(), 2);
    let create = &invocations[0];
    assert_eq!(create.args.first().map(String::as_str), Some("database"));
    assert_eq!(create.args.get(1).map(String::as_str), Some("create"));
    assert!(create.args.iter().any(|argument| argument == "--language=python"));
    assert!(create.args.iter().any(|argument| argument == "--build-mode=none"));
    assert!(create.args.iter().any(|argument| argument == "--threads=2"));
    assert!(create.args.iter().any(|argument| argument == "--ram=4096"));
    assert_eq!(create.working_directory.as_deref(), Some(root.path()));

    let analyze = &invocations[1];
    assert_eq!(analyze.args.first().map(String::as_str), Some("database"));
    assert_eq!(analyze.args.get(1).map(String::as_str), Some("analyze"));
    assert!(analyze.args.iter().any(|argument| argument == "--no-download"));
    assert!(analyze.args.iter().any(|argument| {
        argument == "codeql/python-queries:codeql-suites/python-security-extended.qls"
    }));
    let report = analyze
        .args
        .iter()
        .find_map(|argument| argument.strip_prefix("--output="))
        .map(PathBuf::from)
        .expect("CodeQL report path");
    assert!(!report.exists(), "owned CodeQL report must be removed after the scan");
    assert!(
        !PathBuf::from(&create.args[2]).exists(),
        "owned CodeQL database must be removed after the scan"
    );
    Ok(())
}

#[tokio::test]
async fn psalm_executes_php_taint_analysis_and_cleans_its_report() -> Result<()> {
    let root = tempfile::tempdir()?;
    let recorder = Arc::new(RecordingToolExecutor::with_sast_outputs());
    let injected: Arc<dyn ToolExecutor> = recorder.clone();
    let context = authorized_code_context_with(root.path(), AppConfig::default(), Some("php"))?
        .with_tool_executor(injected);

    let findings = scorchkit::sast_tools::psalm::PsalmModule.run(&context).await?;

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].appsec.code_flows[0].thread_flows[0].steps.len(), 2);
    let invocation = recorder.last();
    assert_invocation_contract("psalm", Some("psalm"), &invocation);
    assert_eq!(invocation.exit_policy, ExitPolicy::AllowNonZero);
    assert_eq!(invocation.environment_policy, EnvironmentPolicy::Clear);
    assert_ne!(invocation.working_directory.as_deref(), Some(root.path()));
    assert!(invocation.args.iter().any(|argument| argument == "--taint-analysis"));
    let config = invocation
        .args
        .iter()
        .find_map(|argument| argument.strip_prefix("--config="))
        .map(PathBuf::from)
        .expect("Psalm config path");
    let report = invocation
        .args
        .iter()
        .find_map(|argument| argument.strip_prefix("--report="))
        .map(PathBuf::from)
        .expect("Psalm report path");
    assert_eq!(invocation.working_directory.as_deref(), config.parent());
    assert_eq!(config.parent(), report.parent());
    assert!(!config.exists(), "owned Psalm config must be removed after the scan");
    assert!(!report.exists(), "owned Psalm report must be removed after the scan");
    assert!(!invocation.environment.contains_key("COMPOSER_AUTH"));
    Ok(())
}

#[tokio::test]
async fn scoutsuite_is_denied_before_inheriting_ambient_credentials() -> Result<()> {
    let root = tempfile::tempdir()?;
    let recorder = Arc::new(RecordingToolExecutor::default());
    let injected: Arc<dyn ToolExecutor> = recorder.clone();
    let context = code_context_without_credential_grant(root.path())?.with_tool_executor(injected);

    let error = scorchkit::sast_tools::scoutsuite::ScoutsuiteModule
        .run(&context)
        .await
        .expect_err("ScoutSuite must require credential-use authorization");
    assert!(error.to_string().contains("CredentialUse/Passive"));
    assert_eq!(recorder.len(), 0);
    Ok(())
}

#[cfg(feature = "infra")]
#[tokio::test]
async fn every_infra_tool_wrapper_executes_its_declared_invocation() -> Result<()> {
    let recorder = Arc::new(RecordingToolExecutor::default());
    let injected: Arc<dyn ToolExecutor> = recorder.clone();
    let context = authorized_infra_context("127.0.0.1")?.with_tool_executor(injected);
    let modules = scorchkit::infra::register_modules();

    let tool_modules: Vec<_> =
        modules.into_iter().filter(|module| module.requires_external_tool()).collect();
    assert_eq!(tool_modules.len(), 1, "infra tool registry contract changed");
    for module in tool_modules {
        let before = recorder.len();
        let _module_outcome = module.run(&context).await;
        assert_eq!(recorder.len(), before + 1, "{} skipped its declared tool", module.id());
        assert_invocation_contract(module.id(), module.required_tool(), &recorder.last());
    }
    Ok(())
}

#[cfg(feature = "cloud")]
#[tokio::test]
async fn every_safe_cloud_tool_wrapper_executes_its_declared_invocation() -> Result<()> {
    let recorder = Arc::new(RecordingToolExecutor::default());
    let modules = scorchkit::cloud::register_modules();

    let tool_modules: Vec<_> =
        modules.into_iter().filter(|module| module.requires_external_tool()).collect();
    assert_eq!(tool_modules.len(), 5, "safe cloud tool registry contract changed");
    for module in tool_modules {
        let target = if module.id() == "kubescape-cloud" {
            "k8s:contract-cluster"
        } else {
            "aws:123456789012"
        };
        let injected: Arc<dyn ToolExecutor> = recorder.clone();
        let context = authorized_cloud_context(target)?.with_tool_executor(injected);
        let before = recorder.len();
        let _module_outcome = module.run(&context).await;
        assert_eq!(recorder.len(), before + 1, "{} skipped its declared tool", module.id());
        assert_invocation_contract(module.id(), module.required_tool(), &recorder.last());
    }
    Ok(())
}

#[cfg(feature = "cloud")]
#[tokio::test]
async fn pacu_is_quarantined_without_an_exploit_authorized_cloud_profile() -> Result<()> {
    let recorder = Arc::new(RecordingToolExecutor::default());
    let injected: Arc<dyn ToolExecutor> = recorder.clone();
    let context = authorized_cloud_context("aws:123456789012")?.with_tool_executor(injected);
    let error = scorchkit::cloud::pacu::PacuCloudModule
        .run(&context)
        .await
        .expect_err("Pacu must remain unavailable from the passive cloud context");

    assert!(error.to_string().contains("Exploit"));
    assert_eq!(recorder.len(), 0, "Pacu must be denied before process execution");
    Ok(())
}

#[tokio::test]
async fn user_plugin_executes_through_the_shared_contract() -> Result<()> {
    const TARGET_PLACEHOLDER: &str = "{target}";

    let recorder = Arc::new(RecordingToolExecutor::default());
    let injected: Arc<dyn ToolExecutor> = recorder.clone();
    let context =
        authorized_dast_context("https://example.com/path?id=1")?.with_tool_executor(injected);
    let module = PluginModule::new(PluginDef {
        id: "contract-plugin".to_string(),
        name: "Contract Plugin".to_string(),
        description: "Exercises the plugin process contract".to_string(),
        category: "scanner".to_string(),
        command: "plugin-fixture".to_string(),
        args: vec!["--target".to_string(), TARGET_PLACEHOLDER.to_string()],
        timeout_seconds: 17,
        output_format: "lines".to_string(),
        severity: "info".to_string(),
    });

    let findings = module.run(&context).await?;
    assert!(findings.is_empty());
    assert_eq!(recorder.len(), 1, "plugin returned without executing its command");
    let invocation = recorder.last();
    assert_invocation_contract(module.id(), module.required_tool(), &invocation);
    assert_eq!(invocation.timeout, Duration::from_secs(17));
    assert_eq!(invocation.args, ["--target", "https://example.com/path?id=1"]);
    Ok(())
}
