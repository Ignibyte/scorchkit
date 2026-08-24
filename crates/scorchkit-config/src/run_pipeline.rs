//! Explicit local processor configuration for the typed run pipeline.

use std::path::PathBuf;

use scorchkit_core::run_pipeline::{
    ProcessorBudget, ProcessorFailureMode, RunPhase, RunProcessorContract,
    PROCESSOR_CONTRACT_SCHEMA_V1,
};
use scorchkit_policy::policy::Capability;
use serde::{Deserialize, Serialize};

/// One explicitly configured local lifecycle processor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunProcessorConfig {
    pub schema: String,
    pub id: String,
    pub path: PathBuf,
    pub phase: RunPhase,
    pub input_schema: String,
    pub output_schema: String,
    pub capabilities: Vec<Capability>,
    pub failure_mode: ProcessorFailureMode,
    pub order: u16,
    pub budget: ProcessorBudget,
}

impl RunProcessorConfig {
    /// Compile and validate this serialized declaration as a core processor contract.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty path, reserved identity, duplicate capability, invalid order,
    /// or any invalid core contract field.
    pub fn contract(&self) -> Result<RunProcessorContract, String> {
        if self.path.as_os_str().is_empty() {
            return Err("run processor path must not be empty".into());
        }
        if self.id.starts_with("legacy.") {
            return Err("run processor ids beginning with 'legacy.' are reserved".into());
        }
        if self.order >= 50_000 {
            return Err("run processor order must be less than 50000".into());
        }
        let capabilities: std::collections::BTreeSet<_> =
            self.capabilities.iter().copied().collect();
        if capabilities.len() != self.capabilities.len() {
            return Err("run processor capabilities must be unique".into());
        }
        let contract = RunProcessorContract {
            schema: self.schema.clone(),
            id: self.id.clone(),
            phase: self.phase,
            input_schema: self.input_schema.clone(),
            output_schema: self.output_schema.clone(),
            capabilities,
            failure_mode: self.failure_mode,
            order: self.order,
            budget: self.budget,
        };
        contract.validate().map_err(|error| error.to_string())?;
        Ok(contract)
    }

    #[must_use]
    pub fn uses_current_contract(&self) -> bool {
        self.schema == PROCESSOR_CONTRACT_SCHEMA_V1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scorchkit_core::run_pipeline::{PREPROCESS_INPUT_SCHEMA_V1, PREPROCESS_PROPOSAL_SCHEMA_V1};

    fn config() -> RunProcessorConfig {
        RunProcessorConfig {
            schema: PROCESSOR_CONTRACT_SCHEMA_V1.into(),
            id: "preprocess.modules".into(),
            path: PathBuf::from("/opt/scorchkit/preprocess"),
            phase: RunPhase::Preprocessing,
            input_schema: PREPROCESS_INPUT_SCHEMA_V1.into(),
            output_schema: PREPROCESS_PROPOSAL_SCHEMA_V1.into(),
            capabilities: vec![Capability::DastScan],
            failure_mode: ProcessorFailureMode::Required,
            order: 100,
            budget: ProcessorBudget {
                timeout_millis: 1_000,
                max_input_bytes: 4_096,
                max_output_bytes: 4_096,
            },
        }
    }

    #[test]
    fn explicit_processor_requires_path_reserved_id_and_order_boundaries() {
        assert!(config().contract().is_ok());
        let mut candidate = config();
        candidate.path = PathBuf::new();
        assert!(candidate.contract().is_err());
        candidate = config();
        candidate.id = "legacy.pre_scan.000".into();
        assert!(candidate.contract().is_err());
        candidate = config();
        candidate.order = 49_999;
        assert!(candidate.contract().is_ok());
        candidate.order = 50_000;
        assert!(candidate.contract().is_err());
        candidate = config();
        candidate.capabilities.push(Capability::DastScan);
        assert!(candidate.contract().is_err());
    }

    #[test]
    fn explicit_processor_toml_requires_every_contract_field() {
        let serialized = toml::to_string(&config()).unwrap();
        let restored: RunProcessorConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(restored, config());
        assert!(restored.uses_current_contract());
        let mut stale = restored;
        stale.schema = "scorchkit.run-processor/v0".into();
        assert!(!stale.uses_current_contract());
        assert!(!serialized.contains("secret"));
        assert!(toml::from_str::<RunProcessorConfig>("id = 'missing'").is_err());
    }
}
