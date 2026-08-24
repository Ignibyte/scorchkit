use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use httpmock::Method::GET;
use httpmock::MockServer;
use scorchkit::control::ControlService;
use scorchkit::engine::events::ScanEvent;
use scorchkit::engine::module_trait::ScanModule;
use scorchkit::extension::{
    ExtensionAdapterV1, ExtensionBudgetsV1, ExtensionCapabilityV1, ExtensionCompatibilityV1,
    ExtensionManifestV1, ExtensionModuleV1, ExtensionRuntimeV1, EXTENSION_ABI_V1,
    EXTENSION_MANIFEST_SCHEMA_V1, EXTENSION_PROTOCOL_V1,
};
use scorchkit::runner::orchestrator::Orchestrator;
use scorchkit::{
    Capability, EffectClass, Engagement, EngagementPolicy, Engine, ScopeRule, Severity,
};
use scorchkit_control::{
    ControlQueryV1, ControlRequestV1, ControlResponseOutcomeV1, ControlResultV1, PageRequestV1,
};
use scorchkit_core::{
    sha256_hex, AdapterOutputContract, AdapterRuntime, AdapterTargetKind, AdapterTrust,
    LifecycleStage, ModuleOutcomeStatus, ProvenanceStrategy, ScanExecutionStatus, SecurityDomain,
    TemporaryArtifactPolicy,
};

fn wat_data(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    bytes.iter().try_fold(String::new(), |mut encoded, byte| {
        write!(&mut encoded, "\\{byte:02x}")?;
        Ok(encoded)
    })
}

fn completion_module(output: &serde_json::Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let output = serde_json::to_vec(output)?;
    let packed = (4096_u64 << 32) | u64::try_from(output.len())?;
    let wat = format!(
        r#"(module
            (memory (export "memory") 1)
            (func (export "scorchkit_abi_version") (result i32) i32.const 1)
            (func (export "scorchkit_reserve_input") (param i32) (result i32) i32.const 1024)
            (func (export "scorchkit_run") (param i32) (result i64) i64.const {packed})
            (data (i32.const 4096) "{}")
        )"#,
        wat_data(&output)?
    );
    Ok(wat::parse_str(wat)?)
}

fn effect_then_completion_module(
    effect: &serde_json::Value,
    completion: &serde_json::Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let effect = serde_json::to_vec(effect)?;
    let completion = serde_json::to_vec(completion)?;
    let effect_packed = (4096_u64 << 32) | u64::try_from(effect.len())?;
    let completion_packed = (8192_u64 << 32) | u64::try_from(completion.len())?;
    let wat = format!(
        r#"(module
            (memory (export "memory") 1)
            (global $turn (mut i32) (i32.const 0))
            (func (export "scorchkit_abi_version") (result i32) i32.const 1)
            (func (export "scorchkit_reserve_input") (param i32) (result i32) i32.const 1024)
            (func (export "scorchkit_run") (param i32) (result i64)
                global.get $turn
                i32.eqz
                if (result i64)
                    i32.const 1
                    global.set $turn
                    i64.const {effect_packed}
                else
                    i64.const {completion_packed}
                end)
            (data (i32.const 4096) "{}")
            (data (i32.const 8192) "{}")
        )"#,
        wat_data(&effect)?,
        wat_data(&completion)?,
    );
    Ok(wat::parse_str(wat)?)
}

fn manifest(module_bytes: &[u8]) -> ExtensionManifestV1 {
    ExtensionManifestV1 {
        schema_version: EXTENSION_MANIFEST_SCHEMA_V1.to_string(),
        id: "fixture.extension".to_string(),
        name: "Fixture extension".to_string(),
        description: "Digest-bound integration fixture".to_string(),
        version: "1.2.3".to_string(),
        compatibility: ExtensionCompatibilityV1 {
            minimum_engine_version: "3.0.0".to_string(),
            maximum_engine_version_exclusive: "4.0.0".to_string(),
        },
        module: ExtensionModuleV1 {
            runtime: ExtensionRuntimeV1::Wasm32UnknownUnknown,
            protocol_version: EXTENSION_PROTOCOL_V1.to_string(),
            abi_version: EXTENSION_ABI_V1,
            file: "fixture.wasm".to_string(),
            sha256: sha256_hex(module_bytes),
        },
        input_schema: "fixture.input/v1".to_string(),
        output_schema: "fixture.output/v1".to_string(),
        adapter: ExtensionAdapterV1 {
            security_domain: SecurityDomain::ApplicationRuntime,
            lifecycle_stage: LifecycleStage::Runtime,
            target_kinds: vec![AdapterTargetKind::WebApplication],
            strongest_effect: EffectClass::ActiveSafe,
            output_contract: AdapterOutputContract::Json,
            provenance: ProvenanceStrategy::PluginDefinition,
            temporary_artifacts: TemporaryArtifactPolicy::ScopedOwned,
        },
        capabilities: vec![ExtensionCapabilityV1::NetworkHttp],
        budgets: ExtensionBudgetsV1 {
            timeout_ms: 5_000,
            fuel: 1_000_000,
            memory_bytes: 4 * 1024 * 1024,
            input_bytes: 64 * 1024,
            output_bytes: 64 * 1024,
            effects: 4,
            artifact_bytes: 64 * 1024,
            artifacts: 4,
        },
    }
}

fn write_extension(
    directory: &Path,
    output: &serde_json::Value,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let module = completion_module(output)?;
    fs::write(directory.join("fixture.wasm"), &module)?;
    let manifest_path = directory.join("fixture.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest(&module))?)?;
    Ok(manifest_path)
}

fn write_module_and_manifest(
    directory: &Path,
    module: &[u8],
    manifest: &ExtensionManifestV1,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    fs::write(directory.join("fixture.wasm"), module)?;
    let manifest_path = directory.join("fixture.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(manifest)?)?;
    Ok(manifest_path)
}

fn engine(directory: &Path, extension_execute: bool) -> Result<Engine, std::io::Error> {
    let mut policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::Exact("127.0.0.1".to_string()))
        .allow_scope(ScopeRule::path_prefix(directory)?)
        .allow_capability(Capability::DastScan)
        .allow_capability(Capability::ExternalTool)
        .allow_capability(Capability::LocalState)
        .allow_effect(EffectClass::Passive)
        .allow_effect(EffectClass::ActiveSafe)
        .allow_effect(EffectClass::Intrusive);
    if extension_execute {
        policy = policy.allow_capability(Capability::ExtensionExecute);
    }
    Ok(Engine::for_engagement(
        Arc::new(scorchkit::config::AppConfig::default()),
        Arc::new(Engagement::new("extension-runtime-fixture", policy)),
    ))
}

#[tokio::test]
async fn digest_bound_worker_normalizes_extension_output() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let output = serde_json::json!({
        "kind": "complete",
        "value": {
            "findings": [{
                "title": "Extension finding",
                "description": "Bounded third-party output",
                "affected_target": "http://127.0.0.1/fixture",
                "severity": "medium",
                "confidence": 0.75,
                "remediation": "Use the engine boundary",
                "owasp_category": null,
                "cwe_id": 20,
                "observations": [],
                "evidence": [],
                "source_artifacts": []
            }],
            "diagnostics": []
        }
    });
    let manifest_path = write_extension(directory.path(), &output)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let extension = scorchkit::extension::WasmExtensionModule::load(
        &context,
        &manifest_path,
        env!("CARGO_BIN_EXE_scorchkit"),
    )?;
    let descriptor = extension.descriptor();
    assert_eq!(descriptor.adapter.trust, AdapterTrust::ThirdParty);
    assert_eq!(descriptor.adapter.runtime, AdapterRuntime::WasmWorker);
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.add_module(Box::new(extension));

    let result = orchestrator.run(true).await?;

    assert_eq!(result.findings.len(), 1);
    let finding = &result.findings[0];
    assert_eq!(finding.module_id, "fixture.extension");
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.appsec.provenance.scanner_id, "fixture.extension");
    assert_eq!(finding.appsec.provenance.scanner_version.as_deref(), Some("1.2.3"));
    let module_digest = sha256_hex(&fs::read(directory.path().join("fixture.wasm"))?);
    assert_eq!(finding.appsec.provenance.rule_digest.as_deref(), Some(module_digest.as_str()));
    assert!(finding
        .appsec
        .provenance
        .config_identity
        .as_deref()
        .is_some_and(|identity| identity.starts_with("extension-invocation:")));
    Ok(())
}

#[tokio::test]
async fn unsupported_declared_effect_is_denied_and_audited_before_guest_resumes(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let effect = serde_json::json!({
        "kind": "effect_request",
        "value": {
            "request_id": "effect-1",
            "effect": {"kind": "filesystem", "operation": "read"}
        }
    });
    let completion = serde_json::json!({
        "kind": "complete",
        "value": {"findings": [], "diagnostics": []}
    });
    let module = effect_then_completion_module(&effect, &completion)?;
    let mut extension_manifest = manifest(&module);
    extension_manifest.capabilities = vec![ExtensionCapabilityV1::Filesystem];
    let manifest_path = write_module_and_manifest(directory.path(), &module, &extension_manifest)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut events = context.events.subscribe();
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_extension(&manifest_path, env!("CARGO_BIN_EXE_scorchkit"))?;

    let result = orchestrator.run(true).await?;

    assert!(result.findings.is_empty());
    let mut audited_denial = false;
    while let Ok(event) = events.try_recv() {
        if let ScanEvent::Custom { kind, data } = event {
            audited_denial |= kind == "extension.effect_decision"
                && data["request_id"] == "effect-1"
                && data["effect_kind"] == "filesystem"
                && data["decision"] == "denied";
        }
    }
    assert!(audited_denial);
    Ok(())
}

#[tokio::test]
async fn effect_denial_matrix_blocks_undeclared_unauthorized_and_unsupported_requests(
) -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            "undeclared-http",
            Vec::new(),
            "http",
            serde_json::json!({
                "kind": "http",
                "method": "get",
                "url": "http://127.0.0.1/must-not-run"
            }),
        ),
        (
            "unauthorized-http",
            vec![ExtensionCapabilityV1::NetworkHttp],
            "http",
            serde_json::json!({
                "kind": "http",
                "method": "get",
                "url": "http://192.0.2.1/must-not-run"
            }),
        ),
        (
            "missing-input",
            vec![ExtensionCapabilityV1::InputRead],
            "input",
            serde_json::json!({"kind": "input", "input_id": "missing-input"}),
        ),
        (
            "unsupported-credential",
            vec![ExtensionCapabilityV1::Credential],
            "credential",
            serde_json::json!({"kind": "credential", "operation": "lookup"}),
        ),
        (
            "unsupported-subprocess",
            vec![ExtensionCapabilityV1::Subprocess],
            "subprocess",
            serde_json::json!({"kind": "subprocess", "operation": "spawn"}),
        ),
    ];
    for (request_id, capabilities, effect_kind, effect) in cases {
        let directory = tempfile::tempdir()?;
        let request = serde_json::json!({
            "kind": "effect_request",
            "value": {"request_id": request_id, "effect": effect}
        });
        let completion = serde_json::json!({
            "kind": "complete",
            "value": {"findings": [], "diagnostics": []}
        });
        let module = effect_then_completion_module(&request, &completion)?;
        let mut extension_manifest = manifest(&module);
        extension_manifest.capabilities = capabilities;
        let manifest_path =
            write_module_and_manifest(directory.path(), &module, &extension_manifest)?;
        let engine = engine(directory.path(), true)?;
        let context = engine.dast_context("http://127.0.0.1/", "standard")?;
        let mut events = context.events.subscribe();
        let mut orchestrator = Orchestrator::new(context);
        orchestrator.register_extension(&manifest_path, env!("CARGO_BIN_EXE_scorchkit"))?;

        let result = orchestrator.run(true).await?;

        assert_eq!(result.execution_status, ScanExecutionStatus::Complete, "{request_id}");
        assert!(result.findings.is_empty(), "{request_id}");
        let mut audited_denial = false;
        while let Ok(event) = events.try_recv() {
            if let ScanEvent::Custom { kind, data } = event {
                audited_denial |= kind == "extension.effect_decision"
                    && data["request_id"] == request_id
                    && data["effect_kind"] == effect_kind
                    && data["decision"] == "denied";
            }
        }
        assert!(audited_denial, "missing denied audit for {request_id}");
    }
    Ok(())
}

#[tokio::test]
async fn opaque_preopened_input_is_allowed_audited_and_resumes_the_guest(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let effect = serde_json::json!({
        "kind": "effect_request",
        "value": {
            "request_id": "input-1",
            "effect": {"kind": "input", "input_id": "fixture-input"}
        }
    });
    let completion = serde_json::json!({
        "kind": "complete",
        "value": {"findings": [], "diagnostics": []}
    });
    let module = effect_then_completion_module(&effect, &completion)?;
    let mut extension_manifest = manifest(&module);
    extension_manifest.capabilities = vec![ExtensionCapabilityV1::InputRead];
    let manifest_path = write_module_and_manifest(directory.path(), &module, &extension_manifest)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut events = context.events.subscribe();
    let extension = scorchkit::extension::WasmExtensionModule::load(
        &context,
        &manifest_path,
        env!("CARGO_BIN_EXE_scorchkit"),
    )?
    .with_input("fixture-input", "text/plain", b"bounded fixture".to_vec())?;
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.add_module(Box::new(extension));

    let result = orchestrator.run(true).await?;

    assert_eq!(result.execution_status, ScanExecutionStatus::Complete);
    assert!(result.findings.is_empty());
    let mut audited_allow = false;
    while let Ok(event) = events.try_recv() {
        if let ScanEvent::Custom { kind, data } = event {
            audited_allow |= kind == "extension.effect_decision"
                && data["request_id"] == "input-1"
                && data["effect_kind"] == "input"
                && data["decision"] == "allowed";
        }
    }
    assert!(audited_allow);
    Ok(())
}

#[tokio::test]
async fn policy_owned_http_effect_is_allowed_audited_and_resumes_the_guest(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start_async().await;
    let probe = server
        .mock_async(|when, then| {
            when.method(GET).path("/extension-probe");
            then.status(200).header("content-type", "text/plain").body("bounded response");
        })
        .await;
    let directory = tempfile::tempdir()?;
    let effect = serde_json::json!({
        "kind": "effect_request",
        "value": {
            "request_id": "http-1",
            "effect": {
                "kind": "http",
                "method": "get",
                "url": server.url("/extension-probe")
            }
        }
    });
    let completion = serde_json::json!({
        "kind": "complete",
        "value": {"findings": [], "diagnostics": []}
    });
    let module = effect_then_completion_module(&effect, &completion)?;
    let extension_manifest = manifest(&module);
    let manifest_path = write_module_and_manifest(directory.path(), &module, &extension_manifest)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut events = context.events.subscribe();
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_extension(&manifest_path, env!("CARGO_BIN_EXE_scorchkit"))?;

    let result = orchestrator.run(true).await?;

    assert_eq!(result.execution_status, ScanExecutionStatus::Complete);
    assert!(result.findings.is_empty());
    probe.assert_async().await;
    let mut audited_allow = false;
    while let Ok(event) = events.try_recv() {
        if let ScanEvent::Custom { kind, data } = event {
            audited_allow |= kind == "extension.effect_decision"
                && data["request_id"] == "http-1"
                && data["effect_kind"] == "http"
                && data["decision"] == "allowed";
        }
    }
    assert!(audited_allow);
    Ok(())
}

#[tokio::test]
async fn configured_extension_uses_the_shared_control_and_mcp_module_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let output = serde_json::json!({
        "kind": "complete",
        "value": {"findings": [], "diagnostics": []}
    });
    let manifest_path = write_extension(directory.path(), &output)?;
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::Exact("127.0.0.1".to_string()))
        .allow_scope(ScopeRule::path_prefix(directory.path())?)
        .allow_capability(Capability::DastScan)
        .allow_capability(Capability::ExternalTool)
        .allow_capability(Capability::ExtensionExecute)
        .allow_capability(Capability::LocalState)
        .allow_effect(EffectClass::Passive)
        .allow_effect(EffectClass::ActiveSafe)
        .allow_effect(EffectClass::Intrusive);
    let engagement = Engagement::new("extension-control-fixture", policy);
    let engagement_id = engagement.id;
    let config = scorchkit::config::AppConfig {
        engagement: Some(engagement),
        extensions: scorchkit::config::ExtensionConfig { manifests: vec![manifest_path] },
        ..scorchkit::config::AppConfig::default()
    };
    let service = ControlService::in_memory(Arc::new(config));

    let response = service
        .execute_local(ControlRequestV1::query(
            ControlQueryV1::ListModules {
                family: Some("web".to_string()),
                page: PageRequestV1 { cursor: None, limit: 50 },
            },
            Some(engagement_id),
        ))
        .await;

    let result = match response.result {
        ControlResponseOutcomeV1::Success(result) => result,
        ControlResponseOutcomeV1::Error(error) => {
            return Err(format!("control module query failed: {error:?}").into());
        }
    };
    let ControlResultV1::Modules(modules) = *result else {
        return Err("control module query returned the wrong resource".into());
    };
    let extension = modules
        .items
        .iter()
        .find(|module| module.id == "fixture.extension")
        .ok_or("configured extension is absent from the shared module projection")?;
    assert_eq!(extension.trust, "third_party");
    assert_eq!(extension.runtime, "wasm_worker");
    Ok(())
}

#[tokio::test]
async fn worker_rejects_every_guest_import_as_a_degraded_module_outcome(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let module = wat::parse_str(
        r#"(module
            (import "wasi_snapshot_preview1" "fd_write" (func $forbidden))
            (memory (export "memory") 1)
            (func (export "scorchkit_abi_version") (result i32) i32.const 1)
            (func (export "scorchkit_reserve_input") (param i32) (result i32) i32.const 1024)
            (func (export "scorchkit_run") (param i32) (result i64) i64.const 0)
        )"#,
    )?;
    let extension_manifest = manifest(&module);
    let manifest_path = write_module_and_manifest(directory.path(), &module, &extension_manifest)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_extension(&manifest_path, env!("CARGO_BIN_EXE_scorchkit"))?;

    let result = orchestrator.run(true).await?;

    assert_eq!(result.execution_status, ScanExecutionStatus::Degraded);
    assert_eq!(result.module_outcomes.len(), 1);
    assert_eq!(result.module_outcomes[0].status, ModuleOutcomeStatus::Failed);
    assert!(result.findings.is_empty());
    Ok(())
}

#[tokio::test]
async fn worker_rejects_an_oversized_guest_table_as_a_degraded_module_outcome(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let module = wat::parse_str(
        r#"(module
            (table 10001 funcref)
            (memory (export "memory") 1)
            (func (export "scorchkit_abi_version") (result i32) i32.const 1)
            (func (export "scorchkit_reserve_input") (param i32) (result i32) i32.const 1024)
            (func (export "scorchkit_run") (param i32) (result i64) i64.const 0)
        )"#,
    )?;
    let extension_manifest = manifest(&module);
    let manifest_path = write_module_and_manifest(directory.path(), &module, &extension_manifest)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_extension(&manifest_path, env!("CARGO_BIN_EXE_scorchkit"))?;

    let result = orchestrator.run(true).await?;

    assert_eq!(result.execution_status, ScanExecutionStatus::Degraded);
    assert_eq!(result.module_outcomes.len(), 1);
    assert_eq!(result.module_outcomes[0].status, ModuleOutcomeStatus::Failed);
    assert!(result.findings.is_empty());
    Ok(())
}

#[tokio::test]
async fn worker_fuel_exhaustion_is_a_degraded_module_outcome(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let module = wat::parse_str(
        r#"(module
            (memory (export "memory") 1)
            (func (export "scorchkit_abi_version") (result i32) i32.const 1)
            (func (export "scorchkit_reserve_input") (param i32) (result i32) i32.const 1024)
            (func (export "scorchkit_run") (param i32) (result i64)
                (loop $spin
                    br $spin)
                unreachable)
        )"#,
    )?;
    let mut extension_manifest = manifest(&module);
    extension_manifest.budgets.fuel = 1_000;
    let manifest_path = write_module_and_manifest(directory.path(), &module, &extension_manifest)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_extension(&manifest_path, env!("CARGO_BIN_EXE_scorchkit"))?;

    let result = orchestrator.run(true).await?;

    assert_eq!(result.execution_status, ScanExecutionStatus::Degraded);
    assert_eq!(result.module_outcomes.len(), 1);
    assert_eq!(result.module_outcomes[0].status, ModuleOutcomeStatus::Failed);
    assert!(result.findings.is_empty());
    Ok(())
}

#[tokio::test]
async fn worker_wall_time_exhaustion_is_a_degraded_module_outcome(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let module = wat::parse_str(
        r#"(module
            (memory (export "memory") 1)
            (func (export "scorchkit_abi_version") (result i32) i32.const 1)
            (func (export "scorchkit_reserve_input") (param i32) (result i32) i32.const 1024)
            (func (export "scorchkit_run") (param i32) (result i64)
                (loop $spin
                    br $spin)
                unreachable)
        )"#,
    )?;
    let mut extension_manifest = manifest(&module);
    extension_manifest.budgets.timeout_ms = 100;
    extension_manifest.budgets.fuel = 1_000_000_000;
    let manifest_path = write_module_and_manifest(directory.path(), &module, &extension_manifest)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_extension(&manifest_path, env!("CARGO_BIN_EXE_scorchkit"))?;

    let result = orchestrator.run(true).await?;

    assert_eq!(result.execution_status, ScanExecutionStatus::Degraded);
    assert_eq!(result.module_outcomes.len(), 1);
    assert_eq!(result.module_outcomes[0].status, ModuleOutcomeStatus::Failed);
    assert!(result.findings.is_empty());
    Ok(())
}

#[tokio::test]
async fn scan_cancellation_drops_the_active_owned_extension_worker(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let module = wat::parse_str(
        r#"(module
            (memory (export "memory") 1)
            (func (export "scorchkit_abi_version") (result i32) i32.const 1)
            (func (export "scorchkit_reserve_input") (param i32) (result i32) i32.const 1024)
            (func (export "scorchkit_run") (param i32) (result i64)
                (loop $spin
                    br $spin)
                unreachable)
        )"#,
    )?;
    let mut extension_manifest = manifest(&module);
    extension_manifest.budgets.timeout_ms = 5_000;
    extension_manifest.budgets.fuel = 1_000_000_000;
    let manifest_path = write_module_and_manifest(directory.path(), &module, &extension_manifest)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_extension(&manifest_path, env!("CARGO_BIN_EXE_scorchkit"))?;
    let cancellation = scorchkit::runner::job_executor::CancellationToken::new();
    let signal = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        signal.cancel();
    });
    let started = std::time::Instant::now();

    let result = orchestrator.run_with_cancellation(true, &cancellation).await;

    assert!(result.is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    Ok(())
}

#[tokio::test]
async fn hostile_output_target_is_reauthorized_before_any_finding_is_committed(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let output = serde_json::json!({
        "kind": "complete",
        "value": {
            "findings": [{
                "title": "Out of scope proposal",
                "description": "The guest cannot expand scope",
                "affected_target": "https://outside.invalid/",
                "severity": "high",
                "confidence": 0.9,
                "remediation": null,
                "owasp_category": null,
                "cwe_id": null,
                "observations": [],
                "evidence": [],
                "source_artifacts": []
            }],
            "diagnostics": []
        }
    });
    let manifest_path = write_extension(directory.path(), &output)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_extension(&manifest_path, env!("CARGO_BIN_EXE_scorchkit"))?;

    let result = orchestrator.run(true).await?;

    assert_eq!(result.execution_status, ScanExecutionStatus::Degraded);
    assert_eq!(result.module_outcomes[0].status, ModuleOutcomeStatus::Failed);
    assert!(result.findings.is_empty());
    Ok(())
}

#[tokio::test]
async fn nested_extension_output_is_redacted_and_artifacts_expose_only_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let artifact_bytes = b"raw-secret-artifact".to_vec();
    let artifact_digest = sha256_hex(&artifact_bytes);
    let output = serde_json::json!({
        "kind": "complete",
        "value": {
            "findings": [{
                "title": "Redaction fixture",
                "description": "password=hunter2",
                "affected_target": "http://127.0.0.1/fixture",
                "severity": "medium",
                "confidence": 0.75,
                "remediation": "Remove authorization=Bearer super-secret",
                "owasp_category": null,
                "cwe_id": 20,
                "observations": [{
                    "kind": "header",
                    "message": "api_key=nested-secret",
                    "location": null
                }],
                "evidence": [{
                    "kind": "json",
                    "value": {"authorization": "Bearer evidence-secret"},
                    "source_artifact_ids": ["artifact-1"]
                }],
                "source_artifacts": [{
                    "id": "artifact-1",
                    "media_type": "text/plain",
                    "sha256": artifact_digest,
                    "bytes": artifact_bytes
                }]
            }],
            "diagnostics": []
        }
    });
    let manifest_path = write_extension(directory.path(), &output)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_extension(&manifest_path, env!("CARGO_BIN_EXE_scorchkit"))?;

    let result = orchestrator.run(true).await?;

    assert_eq!(result.findings.len(), 1);
    let encoded = serde_json::to_string(&result.findings[0])?;
    for secret in
        ["hunter2", "super-secret", "nested-secret", "evidence-secret", "raw-secret-artifact"]
    {
        assert!(!encoded.contains(secret), "extension output leaked {secret}");
    }
    assert!(encoded.contains("artifact-1"));
    assert!(encoded.contains(&artifact_digest));
    Ok(())
}

#[tokio::test]
async fn guest_claimed_engine_provenance_rejects_the_complete_output(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let output = serde_json::json!({
        "kind": "complete",
        "value": {
            "findings": [{
                "title": "Spoofed trust",
                "description": "Must fail as one output",
                "affected_target": "http://127.0.0.1/fixture",
                "severity": "high",
                "confidence": 0.9,
                "remediation": null,
                "owasp_category": null,
                "cwe_id": null,
                "observations": [],
                "evidence": [],
                "source_artifacts": [],
                "provenance": {"trust": "first_party", "parser": "trusted"}
            }],
            "diagnostics": []
        }
    });
    let manifest_path = write_extension(directory.path(), &output)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_extension(&manifest_path, env!("CARGO_BIN_EXE_scorchkit"))?;

    let result = orchestrator.run(true).await?;

    assert_eq!(result.execution_status, ScanExecutionStatus::Degraded);
    assert_eq!(result.module_outcomes[0].status, ModuleOutcomeStatus::Failed);
    assert!(result.findings.is_empty());
    Ok(())
}

#[test]
fn missing_extension_execute_grant_denies_registration_before_worker_selection(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let output = serde_json::json!({
        "kind": "complete",
        "value": {"findings": [], "diagnostics": []}
    });
    let manifest_path = write_extension(directory.path(), &output)?;
    let engine = engine(directory.path(), false)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut orchestrator = Orchestrator::new(context);

    let result = orchestrator
        .register_extension(&manifest_path, directory.path().join("worker-that-must-not-start"));

    assert!(result.is_err());
    Ok(())
}

#[test]
fn digest_mismatch_is_rejected_during_registration() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let output = serde_json::json!({
        "kind": "complete",
        "value": {"findings": [], "diagnostics": []}
    });
    let manifest_path = write_extension(directory.path(), &output)?;
    let mut decoded: ExtensionManifestV1 = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    decoded.module.sha256 = "0".repeat(64);
    fs::write(&manifest_path, serde_json::to_vec_pretty(&decoded)?)?;
    let engine = engine(directory.path(), true)?;
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut orchestrator = Orchestrator::new(context);

    let result = orchestrator.register_extension(&manifest_path, env!("CARGO_BIN_EXE_scorchkit"));

    assert!(result.is_err());
    Ok(())
}

#[test]
fn v1_web_registration_rejects_mixed_targets_and_non_json_output(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = serde_json::json!({
        "kind": "complete",
        "value": {"findings": [], "diagnostics": []}
    });
    let module = completion_module(&output)?;

    let mixed_directory = tempfile::tempdir()?;
    let mut mixed = manifest(&module);
    mixed.adapter.target_kinds.push(AdapterTargetKind::SourceTree);
    let mixed_path = write_module_and_manifest(mixed_directory.path(), &module, &mixed)?;
    let mixed_engine = engine(mixed_directory.path(), true)?;
    let mixed_context = mixed_engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut mixed_orchestrator = Orchestrator::new(mixed_context);
    assert!(mixed_orchestrator
        .register_extension(&mixed_path, env!("CARGO_BIN_EXE_scorchkit"))
        .is_err());

    let sarif_directory = tempfile::tempdir()?;
    let mut sarif = manifest(&module);
    sarif.adapter.output_contract = AdapterOutputContract::Sarif;
    let sarif_path = write_module_and_manifest(sarif_directory.path(), &module, &sarif)?;
    let sarif_engine = engine(sarif_directory.path(), true)?;
    let sarif_context = sarif_engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut sarif_orchestrator = Orchestrator::new(sarif_context);
    assert!(sarif_orchestrator
        .register_extension(&sarif_path, env!("CARGO_BIN_EXE_scorchkit"))
        .is_err());
    Ok(())
}
