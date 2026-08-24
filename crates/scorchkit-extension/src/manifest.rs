use std::collections::BTreeSet;
use std::path::{Component, Path};

use scorchkit_core::{
    AdapterOutputContract, AdapterTargetKind, LifecycleStage, ProvenanceStrategy, SecurityDomain,
    TemporaryArtifactPolicy,
};
use scorchkit_policy::EffectClass;
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::constants::{
    EXTENSION_ABI_V1, EXTENSION_MANIFEST_SCHEMA_V1, EXTENSION_PROTOCOL_V1, MAX_EXTENSION_ARTIFACTS,
    MAX_EXTENSION_ARTIFACT_BYTES, MAX_EXTENSION_EFFECTS, MAX_EXTENSION_FUEL,
    MAX_EXTENSION_ID_BYTES, MAX_EXTENSION_INPUT_BYTES, MAX_EXTENSION_MEMORY_BYTES,
    MAX_EXTENSION_OUTPUT_BYTES, MAX_EXTENSION_TEXT_BYTES, MAX_EXTENSION_TIMEOUT_MS,
};

/// Runtime format accepted for an isolated third-party extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionRuntimeV1 {
    /// WebAssembly without WASI, hosted in a separate owned worker process.
    Wasm32UnknownUnknown,
}

/// Maximum effect classes a guest may request. Declarations never authorize an effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionCapabilityV1 {
    NetworkHttp,
    InputRead,
    Filesystem,
    Credential,
    Subprocess,
}

/// Engine version interval supported by an extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionCompatibilityV1 {
    pub minimum_engine_version: String,
    pub maximum_engine_version_exclusive: String,
}

/// Exact guest module identity and ABI selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionModuleV1 {
    pub runtime: ExtensionRuntimeV1,
    pub protocol_version: String,
    pub abi_version: u32,
    /// Manifest-relative `.wasm` filename. Nested or absolute paths are rejected.
    pub file: String,
    /// Lowercase SHA-256 of the exact module bytes.
    pub sha256: String,
}

/// Nonzero resource ceilings for one invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionBudgetsV1 {
    pub timeout_ms: u64,
    pub fuel: u64,
    pub memory_bytes: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub effects: u32,
    pub artifact_bytes: u64,
    pub artifacts: u32,
}

/// Owned form of the common provider-neutral adapter descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionAdapterV1 {
    pub security_domain: SecurityDomain,
    pub lifecycle_stage: LifecycleStage,
    pub target_kinds: Vec<AdapterTargetKind>,
    pub strongest_effect: EffectClass,
    pub output_contract: AdapterOutputContract,
    pub provenance: ProvenanceStrategy,
    pub temporary_artifacts: TemporaryArtifactPolicy,
}

/// Complete versioned registration manifest for one isolated extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionManifestV1 {
    pub schema_version: String,
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub compatibility: ExtensionCompatibilityV1,
    pub module: ExtensionModuleV1,
    pub input_schema: String,
    pub output_schema: String,
    pub adapter: ExtensionAdapterV1,
    pub capabilities: Vec<ExtensionCapabilityV1>,
    pub budgets: ExtensionBudgetsV1,
}

/// Fail-closed manifest validation error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtensionManifestError {
    #[error("unsupported extension manifest schema")]
    Schema,
    #[error("invalid extension field: {0}")]
    Field(&'static str),
    #[error("invalid extension engine compatibility range")]
    Compatibility,
    #[error("extension is incompatible with this engine version")]
    EngineVersion,
    #[error("extension budget is outside the v1 boundary: {0}")]
    Budget(&'static str),
    #[error("extension capability declarations are invalid")]
    Capabilities,
}

impl ExtensionManifestV1 {
    /// Validate canonical shape and all hard v1 ceilings.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for unsupported schemas, malformed fields,
    /// incompatible ranges, duplicate declarations, or out-of-bound budgets.
    pub fn validate(&self) -> Result<(), ExtensionManifestError> {
        if self.schema_version != EXTENSION_MANIFEST_SCHEMA_V1 {
            return Err(ExtensionManifestError::Schema);
        }
        validate_id(&self.id, "id")?;
        validate_text(&self.name, "name")?;
        validate_text(&self.description, "description")?;
        Version::parse(&self.version).map_err(|_| ExtensionManifestError::Field("version"))?;
        validate_id(&self.input_schema, "input_schema")?;
        validate_id(&self.output_schema, "output_schema")?;
        self.validate_compatibility()?;
        if self.module.protocol_version != EXTENSION_PROTOCOL_V1
            || self.module.abi_version != EXTENSION_ABI_V1
            || !valid_module_file(&self.module.file)
            || !is_lower_sha256(&self.module.sha256)
        {
            return Err(ExtensionManifestError::Field("module"));
        }
        if !self.adapter.security_domain.is_application_security()
            || self.adapter.target_kinds.is_empty()
            || !unique(&self.adapter.target_kinds)
            || self.adapter.provenance != ProvenanceStrategy::PluginDefinition
        {
            return Err(ExtensionManifestError::Field("adapter"));
        }
        let capabilities: BTreeSet<_> = self.capabilities.iter().copied().collect();
        if capabilities.len() != self.capabilities.len()
            || !self.capabilities.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(ExtensionManifestError::Capabilities);
        }
        self.budgets.validate()
    }

    /// Require this engine version to fall inside the manifest interval.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied version or manifest interval is invalid, or when the
    /// version falls outside the declared half-open interval.
    pub fn require_compatible_engine(&self, engine: &str) -> Result<(), ExtensionManifestError> {
        self.validate_compatibility()?;
        let engine = Version::parse(engine).map_err(|_| ExtensionManifestError::EngineVersion)?;
        let minimum = Version::parse(&self.compatibility.minimum_engine_version)
            .map_err(|_| ExtensionManifestError::Compatibility)?;
        let maximum = Version::parse(&self.compatibility.maximum_engine_version_exclusive)
            .map_err(|_| ExtensionManifestError::Compatibility)?;
        if engine < minimum || engine >= maximum {
            return Err(ExtensionManifestError::EngineVersion);
        }
        Ok(())
    }

    fn validate_compatibility(&self) -> Result<(), ExtensionManifestError> {
        let minimum = Version::parse(&self.compatibility.minimum_engine_version)
            .map_err(|_| ExtensionManifestError::Compatibility)?;
        let maximum = Version::parse(&self.compatibility.maximum_engine_version_exclusive)
            .map_err(|_| ExtensionManifestError::Compatibility)?;
        if minimum >= maximum {
            return Err(ExtensionManifestError::Compatibility);
        }
        Ok(())
    }
}

impl ExtensionBudgetsV1 {
    fn validate(&self) -> Result<(), ExtensionManifestError> {
        for (name, value, maximum) in [
            ("timeout_ms", self.timeout_ms, MAX_EXTENSION_TIMEOUT_MS),
            ("fuel", self.fuel, MAX_EXTENSION_FUEL),
            ("memory_bytes", self.memory_bytes, MAX_EXTENSION_MEMORY_BYTES),
            ("input_bytes", self.input_bytes, MAX_EXTENSION_INPUT_BYTES),
            ("output_bytes", self.output_bytes, MAX_EXTENSION_OUTPUT_BYTES),
            ("artifact_bytes", self.artifact_bytes, MAX_EXTENSION_ARTIFACT_BYTES),
        ] {
            if value == 0 || value > maximum {
                return Err(ExtensionManifestError::Budget(name));
            }
        }
        for (name, value, maximum) in [
            ("effects", self.effects, MAX_EXTENSION_EFFECTS),
            ("artifacts", self.artifacts, MAX_EXTENSION_ARTIFACTS),
        ] {
            if value == 0 || value > maximum {
                return Err(ExtensionManifestError::Budget(name));
            }
        }
        Ok(())
    }
}

fn validate_id(value: &str, field: &'static str) -> Result<(), ExtensionManifestError> {
    if value.is_empty()
        || value.len() > MAX_EXTENSION_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b'/')
        })
    {
        return Err(ExtensionManifestError::Field(field));
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ExtensionManifestError> {
    if value.trim().is_empty()
        || value.len() > MAX_EXTENSION_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ExtensionManifestError::Field(field));
    }
    Ok(())
}

fn valid_module_file(value: &str) -> bool {
    let path = Path::new(value);
    path.extension().and_then(|extension| extension.to_str()) == Some("wasm")
        && path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unique<T: PartialEq>(values: &[T]) -> bool {
    values.iter().enumerate().all(|(index, value)| !values[..index].contains(value))
}

/// JSON Schema for manifest v1. Enum fields are constrained by runtime validation as well.
#[must_use]
pub fn extension_manifest_schema_v1() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": EXTENSION_MANIFEST_SCHEMA_V1,
        "title": "ScorchKit isolated extension manifest v1",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "id", "name", "description", "version", "compatibility", "module", "input_schema", "output_schema", "adapter", "capabilities", "budgets"],
        "properties": {
            "schema_version": {"const": EXTENSION_MANIFEST_SCHEMA_V1},
            "id": id_schema(),
            "name": {"type": "string", "minLength": 1, "maxLength": MAX_EXTENSION_TEXT_BYTES},
            "description": {"type": "string", "minLength": 1, "maxLength": MAX_EXTENSION_TEXT_BYTES},
            "version": {"type": "string"},
            "compatibility": compatibility_schema(),
            "module": module_schema(),
            "input_schema": id_schema(),
            "output_schema": id_schema(),
            "adapter": adapter_schema(),
            "capabilities": {
                "type": "array",
                "uniqueItems": true,
                "maxItems": 5,
                "items": {"enum": ["network_http", "input_read", "filesystem", "credential", "subprocess"]}
            },
            "budgets": budgets_schema()
        }
    })
}

fn id_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_EXTENSION_ID_BYTES,
        "pattern": "^[a-z0-9._/-]+$"
    })
}

fn compatibility_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["minimum_engine_version", "maximum_engine_version_exclusive"],
        "properties": {
            "minimum_engine_version": {"type": "string", "minLength": 1},
            "maximum_engine_version_exclusive": {"type": "string", "minLength": 1}
        }
    })
}

fn module_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["runtime", "protocol_version", "abi_version", "file", "sha256"],
        "properties": {
            "runtime": {"const": "wasm32_unknown_unknown"},
            "protocol_version": {"const": EXTENSION_PROTOCOL_V1},
            "abi_version": {"const": EXTENSION_ABI_V1},
            "file": {"type": "string", "pattern": "^[^/\\\\]+[.]wasm$"},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        }
    })
}

fn adapter_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["security_domain", "lifecycle_stage", "target_kinds", "strongest_effect", "output_contract", "provenance", "temporary_artifacts"],
        "properties": {
            "security_domain": {"enum": ["application_source", "application_dependency", "application_artifact", "application_runtime", "application_attack_path"]},
            "lifecycle_stage": {"enum": ["source", "build", "runtime", "manual", "platform"]},
            "target_kinds": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": true,
                "items": {"enum": ["source_tree", "dependency_manifest", "application_artifact", "web_application", "api"]}
            },
            "strongest_effect": {"enum": ["passive", "active-safe", "intrusive", "credential-test", "exploit"]},
            "output_contract": {"enum": ["native_findings", "json", "json_lines", "sarif", "xml", "text", "file_artifacts"]},
            "provenance": {"const": "plugin_definition"},
            "temporary_artifacts": {"enum": ["none", "scoped_owned"]}
        }
    })
}

fn budgets_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["timeout_ms", "fuel", "memory_bytes", "input_bytes", "output_bytes", "effects", "artifact_bytes", "artifacts"],
        "properties": {
            "timeout_ms": {"type": "integer", "minimum": 1, "maximum": MAX_EXTENSION_TIMEOUT_MS},
            "fuel": {"type": "integer", "minimum": 1, "maximum": MAX_EXTENSION_FUEL},
            "memory_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_EXTENSION_MEMORY_BYTES},
            "input_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_EXTENSION_INPUT_BYTES},
            "output_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_EXTENSION_OUTPUT_BYTES},
            "effects": {"type": "integer", "minimum": 1, "maximum": MAX_EXTENSION_EFFECTS},
            "artifact_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_EXTENSION_ARTIFACT_BYTES},
            "artifacts": {"type": "integer", "minimum": 1, "maximum": MAX_EXTENSION_ARTIFACTS}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ExtensionManifestV1 {
        ExtensionManifestV1 {
            schema_version: EXTENSION_MANIFEST_SCHEMA_V1.to_string(),
            id: "fixture.extension".to_string(),
            name: "Fixture extension".to_string(),
            description: "A deterministic fixture".to_string(),
            version: "1.0.0".to_string(),
            compatibility: ExtensionCompatibilityV1 {
                minimum_engine_version: "3.0.0".to_string(),
                maximum_engine_version_exclusive: "4.0.0".to_string(),
            },
            module: ExtensionModuleV1 {
                runtime: ExtensionRuntimeV1::Wasm32UnknownUnknown,
                protocol_version: EXTENSION_PROTOCOL_V1.to_string(),
                abi_version: EXTENSION_ABI_V1,
                file: "fixture.wasm".to_string(),
                sha256: "a".repeat(64),
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
                timeout_ms: 1_000,
                fuel: 1_000_000,
                memory_bytes: 1_048_576,
                input_bytes: 65_536,
                output_bytes: 65_536,
                effects: 4,
                artifact_bytes: 65_536,
                artifacts: 4,
            },
        }
    }

    #[test]
    fn manifest_accepts_canonical_v1_and_exact_engine_interval() {
        let manifest = manifest();
        manifest.validate().expect("valid manifest");
        manifest.require_compatible_engine("3.0.0").expect("minimum inclusive");
        assert_eq!(
            manifest.require_compatible_engine("4.0.0"),
            Err(ExtensionManifestError::EngineVersion)
        );
    }

    #[test]
    fn manifest_rejects_duplicate_capabilities_and_compatibility_domains() {
        let mut duplicate = manifest();
        duplicate.capabilities.push(ExtensionCapabilityV1::NetworkHttp);
        assert_eq!(duplicate.validate(), Err(ExtensionManifestError::Capabilities));

        let mut compatibility = manifest();
        compatibility.adapter.security_domain = SecurityDomain::CompatibilityNetwork;
        assert_eq!(compatibility.validate(), Err(ExtensionManifestError::Field("adapter")));
    }

    #[test]
    fn every_budget_has_zero_exact_and_over_boundary_behavior() {
        macro_rules! assert_u64_budget {
            ($field:ident, $maximum:expr) => {{
                let mut zero = manifest();
                zero.budgets.$field = 0;
                assert_eq!(
                    zero.validate(),
                    Err(ExtensionManifestError::Budget(stringify!($field)))
                );
                let mut exact = manifest();
                exact.budgets.$field = $maximum;
                assert!(exact.validate().is_ok());
                let mut over = manifest();
                over.budgets.$field = $maximum + 1;
                assert_eq!(
                    over.validate(),
                    Err(ExtensionManifestError::Budget(stringify!($field)))
                );
            }};
        }
        macro_rules! assert_u32_budget {
            ($field:ident, $maximum:expr) => {{
                let mut zero = manifest();
                zero.budgets.$field = 0;
                assert_eq!(
                    zero.validate(),
                    Err(ExtensionManifestError::Budget(stringify!($field)))
                );
                let mut exact = manifest();
                exact.budgets.$field = $maximum;
                assert!(exact.validate().is_ok());
                let mut over = manifest();
                over.budgets.$field = $maximum + 1;
                assert_eq!(
                    over.validate(),
                    Err(ExtensionManifestError::Budget(stringify!($field)))
                );
            }};
        }

        assert_u64_budget!(timeout_ms, MAX_EXTENSION_TIMEOUT_MS);
        assert_u64_budget!(fuel, MAX_EXTENSION_FUEL);
        assert_u64_budget!(memory_bytes, MAX_EXTENSION_MEMORY_BYTES);
        assert_u64_budget!(input_bytes, MAX_EXTENSION_INPUT_BYTES);
        assert_u64_budget!(output_bytes, MAX_EXTENSION_OUTPUT_BYTES);
        assert_u64_budget!(artifact_bytes, MAX_EXTENSION_ARTIFACT_BYTES);
        assert_u32_budget!(effects, MAX_EXTENSION_EFFECTS);
        assert_u32_budget!(artifacts, MAX_EXTENSION_ARTIFACTS);
    }

    #[test]
    fn module_file_is_one_manifest_relative_wasm_name() {
        for invalid in ["../fixture.wasm", "/tmp/fixture.wasm", "nested/fixture.wasm", "fixture.so"]
        {
            let mut candidate = manifest();
            candidate.module.file = invalid.to_string();
            assert_eq!(candidate.validate(), Err(ExtensionManifestError::Field("module")));
        }
    }
}
