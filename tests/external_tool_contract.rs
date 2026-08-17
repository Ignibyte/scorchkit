use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use scorchkit::config::AppConfig;
use scorchkit::engine::code_context::CodeContext;
use scorchkit::engine::module_trait::ScanModule;
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::scan_context::ScanContext;
use scorchkit::runner::plugin::{PluginDef, PluginModule};
use scorchkit::runner::subprocess::{
    ExitPolicy, ToolExecutor, ToolInvocation, ToolOutput, DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
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
}

#[async_trait]
impl ToolExecutor for RecordingToolExecutor {
    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput> {
        let resolved_program = PathBuf::from(format!("/mock/{}", invocation.program));
        self.recorded().push(invocation);
        Ok(ToolOutput {
            stdout: String::new(),
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

fn authorized_code_context(path: &std::path::Path) -> Result<CodeContext> {
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::path_prefix(path)?)
        .allow_capability(Capability::CodeScan)
        .allow_capability(Capability::ExternalTool)
        .allow_effect(EffectClass::Passive);
    Engine::for_engagement(
        Arc::new(AppConfig::default()),
        Arc::new(Engagement::new("SAST contract", policy)),
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
        matches!(invocation.exit_policy, ExitPolicy::RequireSuccess | ExitPolicy::AllowNonZero),
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

    assert_eq!(modules.len(), 46, "DAST tool registry contract changed");
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

    assert_eq!(process_backed, 45, "all non-session DAST wrappers must use the shared executor");
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
async fn every_sast_tool_wrapper_executes_its_declared_invocation() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("Dockerfile"), "FROM scratch\n")?;
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
        assert_eq!(
            recorder.len(),
            before + 1,
            "{} returned without executing its external tool",
            module.id()
        );
        assert_invocation_contract(module.id(), module.required_tool(), &recorder.last());
    }

    assert_eq!(recorder.len(), 21);
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
