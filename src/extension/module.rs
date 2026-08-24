use std::path::Path;
use std::path::PathBuf;

use async_trait::async_trait;
use scorchkit_core::{
    sha256_hex, AdapterContractV1, AdapterRuntime, AdapterTrust, Finding, ADAPTER_CONTRACT_V1,
};
use scorchkit_extension::{ExtensionCapabilityV1, ExtensionInvocationInputV1};
use scorchkit_web::{ModuleCategory, WebModuleDescriptor};

use crate::engine::error::Result;
use crate::engine::module_trait::ScanModule;
use crate::engine::scan_context::ScanContext;

use super::loader::LoadedExtension;

/// One explicitly loaded isolated WebAssembly DAST extension.
#[derive(Debug, Clone)]
pub struct WasmExtensionModule {
    loaded: LoadedExtension,
    worker_program: PathBuf,
    inputs: Vec<ExtensionInvocationInputV1>,
}

impl WasmExtensionModule {
    /// Validate and retain one manifest/module pair using the supplied trusted worker binary.
    ///
    /// # Errors
    ///
    /// Returns an authorization, registration, compatibility, descriptor, or digest error.
    pub fn load(
        context: &ScanContext,
        manifest_path: &Path,
        worker_program: impl Into<PathBuf>,
    ) -> Result<Self> {
        let loaded = LoadedExtension::load(context, manifest_path)?;
        loaded.require_v1_web_adapter()?;
        Ok(Self { loaded, worker_program: worker_program.into(), inputs: Vec::new() })
    }

    /// Attach one invocation-local byte input under an opaque guest-visible identity.
    ///
    /// The host supplies already opened bytes, not a path or handle. The aggregate raw bytes must
    /// fit the manifest input budget and the manifest must declare `input_read`.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for an undeclared capability, invalid or duplicate identity,
    /// invalid media type, or aggregate input overflow.
    pub fn with_input(
        mut self,
        id: impl Into<String>,
        media_type: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<Self> {
        let id = id.into();
        let media_type = media_type.into();
        let valid_id = !id.is_empty()
            && id.len() <= 128
            && id.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.' | b'/')
            });
        if !self.loaded.manifest.capabilities.contains(&ExtensionCapabilityV1::InputRead)
            || !valid_id
            || media_type.trim().is_empty()
            || media_type.len() > 256
            || media_type.chars().any(char::is_control)
            || self.inputs.iter().any(|input| input.id == id)
        {
            return Err(crate::engine::error::ScorchError::Config(
                "extension invocation input is invalid or undeclared".to_string(),
            ));
        }
        let aggregate = self
            .inputs
            .iter()
            .try_fold(bytes.len(), |total, input| total.checked_add(input.bytes.len()));
        if aggregate
            .and_then(|total| u64::try_from(total).ok())
            .is_none_or(|total| total > self.loaded.manifest.budgets.input_bytes)
        {
            return Err(crate::engine::error::ScorchError::Config(
                "extension invocation inputs exceed the manifest budget".to_string(),
            ));
        }
        self.inputs.push(ExtensionInvocationInputV1 {
            id,
            media_type,
            sha256: sha256_hex(&bytes),
            bytes,
        });
        Ok(self)
    }

    #[must_use]
    pub const fn loaded(&self) -> &LoadedExtension {
        &self.loaded
    }
}

#[async_trait]
impl ScanModule for WasmExtensionModule {
    fn descriptor(&self) -> WebModuleDescriptor<'_> {
        let manifest = &self.loaded.manifest;
        WebModuleDescriptor {
            adapter: AdapterContractV1 {
                schema_version: ADAPTER_CONTRACT_V1,
                security_domain: manifest.adapter.security_domain,
                lifecycle_stage: manifest.adapter.lifecycle_stage,
                target_kinds: &manifest.adapter.target_kinds,
                strongest_effect: manifest.adapter.strongest_effect,
                output_contract: manifest.adapter.output_contract,
                provenance: manifest.adapter.provenance,
                temporary_artifacts: manifest.adapter.temporary_artifacts,
                trust: AdapterTrust::ThirdParty,
                runtime: AdapterRuntime::WasmWorker,
            },
            name: &manifest.name,
            id: &manifest.id,
            category: ModuleCategory::Scanner,
            description: &manifest.description,
            requires_external_tool: false,
            required_tool: None,
        }
    }

    fn name(&self) -> &str {
        &self.loaded.manifest.name
    }

    fn id(&self) -> &str {
        &self.loaded.manifest.id
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &str {
        &self.loaded.manifest.description
    }

    async fn run(&self, context: &ScanContext) -> Result<Vec<Finding>> {
        super::runtime::run(context, &self.loaded, &self.worker_program, &self.inputs).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extension::test_support;

    fn module(input_budget: u64, input_read: bool) -> WasmExtensionModule {
        let mut loaded = test_support::loaded(b"module".to_vec());
        loaded.manifest.budgets.input_bytes = input_budget;
        if input_read {
            loaded.manifest.capabilities = vec![ExtensionCapabilityV1::InputRead];
        }
        WasmExtensionModule { loaded, worker_program: PathBuf::from("worker"), inputs: Vec::new() }
    }

    #[test]
    fn module_metadata_is_the_exact_validated_manifest_identity() {
        let module = module(16, true);
        assert_eq!(module.name(), "Fixture extension");
        assert_eq!(module.id(), "fixture.extension");
        assert_eq!(module.description(), "Digest-bound test fixture");
    }

    #[test]
    fn invocation_inputs_require_declared_capability_and_exact_field_boundaries() {
        assert!(module(16, false).with_input("input", "text/plain", vec![1]).is_err());

        assert!(module(16, true).with_input("a".repeat(128), "m".repeat(256), vec![1]).is_ok());
        for id in [String::new(), "a".repeat(129), "INVALID".to_string(), "bad:id".to_string()] {
            assert!(module(16, true).with_input(id, "text/plain", vec![1]).is_err());
        }
        for media_type in
            [String::new(), " \t".to_string(), "m".repeat(257), "text/plain\n".to_string()]
        {
            assert!(module(16, true).with_input("input", media_type, vec![1]).is_err());
        }
    }

    #[test]
    fn invocation_input_identity_and_aggregate_byte_budget_are_exact() {
        let module = module(4, true)
            .with_input("first", "application/octet-stream", vec![1, 2])
            .expect("first input");
        assert!(module.clone().with_input("first", "text/plain", vec![3]).is_err());
        let exact = module
            .with_input("second", "application/octet-stream", vec![3, 4])
            .expect("exact aggregate budget");
        assert_eq!(exact.inputs.len(), 2);
        assert!(exact.with_input("third", "text/plain", vec![5]).is_err());
    }
}
