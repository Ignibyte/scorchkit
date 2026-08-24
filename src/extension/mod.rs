//! Digest-bound isolated extension registration and execution.

mod broker;
mod loader;
mod module;
mod runtime;
mod worker;

pub use loader::LoadedExtension;
pub use module::WasmExtensionModule;
pub use scorchkit_extension::*;

/// Exact internal argument used to enter the owned extension worker.
#[doc(hidden)]
pub const EXTENSION_WORKER_ARGUMENT: &str = "__scorchkit-extension-worker-v1";

/// Run the internal worker protocol on standard input/output.
///
/// This entry point is called only by the official binary after matching the exact hidden worker
/// argument. It performs no target or storage effect.
#[doc(hidden)]
pub async fn run_worker_stdio() -> crate::Result<()> {
    worker::run_stdio().await
}

#[cfg(test)]
pub(super) mod test_support {
    use std::path::PathBuf;
    use std::sync::Arc;

    use scorchkit_core::{
        sha256_hex, AdapterOutputContract, AdapterTargetKind, LifecycleStage, ProvenanceStrategy,
        SecurityDomain, TemporaryArtifactPolicy,
    };
    use scorchkit_extension::{
        ExtensionAdapterV1, ExtensionArtifactV1, ExtensionBudgetsV1, ExtensionCapabilityV1,
        ExtensionCompatibilityV1, ExtensionFindingV1, ExtensionInvocationV1, ExtensionManifestV1,
        ExtensionModuleV1, ExtensionRuntimeV1, EXTENSION_ABI_V1, EXTENSION_MANIFEST_SCHEMA_V1,
        EXTENSION_PROTOCOL_V1,
    };
    use uuid::Uuid;

    use crate::config::AppConfig;
    use crate::engine::policy::{AuthorizationDecision, Capability, EffectClass, PolicyTarget};
    use crate::engine::scan_context::ScanContext;
    use crate::engine::target::Target;

    use super::LoadedExtension;

    pub fn manifest(module_bytes: &[u8]) -> ExtensionManifestV1 {
        ExtensionManifestV1 {
            schema_version: EXTENSION_MANIFEST_SCHEMA_V1.to_string(),
            id: "fixture.extension".to_string(),
            name: "Fixture extension".to_string(),
            description: "Digest-bound test fixture".to_string(),
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

    pub fn loaded(module_bytes: Vec<u8>) -> LoadedExtension {
        LoadedExtension {
            manifest: manifest(&module_bytes),
            manifest_path: PathBuf::from("fixture.json"),
            module_path: PathBuf::from("fixture.wasm"),
            module_bytes,
        }
    }

    pub fn invocation() -> ExtensionInvocationV1 {
        ExtensionInvocationV1::new(
            "invocation-1",
            "fixture.extension",
            "https://example.com/fixture",
        )
    }

    pub fn context() -> ScanContext {
        let target = Target::parse("https://example.com/fixture").expect("fixture target");
        let authorization =
            [Capability::DastScan, Capability::ExternalTool, Capability::ExtensionExecute]
                .into_iter()
                .map(|capability| AuthorizationDecision {
                    engagement_id: Uuid::nil(),
                    target: PolicyTarget::Web(target.url.clone()),
                    capability,
                    effect: EffectClass::ActiveSafe,
                    allowed: true,
                    matched_scope: None,
                    denial: None,
                })
                .collect();
        ScanContext::new(
            target,
            Arc::new(AppConfig::default()),
            reqwest::Client::new(),
            authorization,
        )
    }

    pub fn finding() -> ExtensionFindingV1 {
        let bytes = b"artifact".to_vec();
        ExtensionFindingV1 {
            title: "Finding title".to_string(),
            description: "Finding description".to_string(),
            affected_target: "https://example.com/fixture".to_string(),
            severity: "medium".to_string(),
            confidence: 0.75,
            remediation: Some("Apply the fix".to_string()),
            owasp_category: Some("A01".to_string()),
            cwe_id: Some(79),
            observations: Vec::new(),
            evidence: Vec::new(),
            source_artifacts: vec![ExtensionArtifactV1 {
                id: "artifact-1".to_string(),
                media_type: "text/plain".to_string(),
                sha256: sha256_hex(&bytes),
                bytes,
            }],
        }
    }
}
