//! Disabled-by-default model-role bindings and service data policy.

use std::collections::BTreeSet;

use scorchkit_core::{
    ModelEligibilityKey, ModelEvaluationResult, ModelExecutionLocation, ModelRole,
    MAX_MODEL_ANALYSIS_REQUEST_BYTES,
};
use serde::{Deserialize, Serialize};
use url::Url;

/// Maximum service response size accepted by configuration.
pub const MAX_MODEL_SERVICE_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum model request timeout accepted by configuration.
pub const MAX_MODEL_TIMEOUT_MILLIS: u64 = 300_000;
/// Minimum model request timeout accepted by configuration.
pub const MIN_MODEL_TIMEOUT_MILLIS: u64 = 100;

/// Model-analysis configuration, separate from the legacy `[ai]` compatibility adapter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelAnalysisConfig {
    /// Enable role resolution and invocation.
    pub enabled: bool,
    /// At most one exact provider/model binding per role.
    pub bindings: Vec<ModelRoleBindingConfig>,
    /// Complete deterministic evaluation evidence for exact bindings.
    pub evaluations: Vec<ModelEvaluationResult>,
}

impl ModelAnalysisConfig {
    /// Validate bindings, adapters, and stored evaluation evidence.
    ///
    /// # Errors
    ///
    /// Returns a credential-safe reason when a bound, unique, or evaluation invariant fails.
    pub fn validate(&self) -> Result<(), String> {
        if self.bindings.len() > ModelRole::ALL.len() {
            return Err("model analysis bindings exceed the role count".to_string());
        }
        if self.evaluations.len() > ModelRole::ALL.len() {
            return Err("model analysis evaluations exceed the role count".to_string());
        }
        let mut roles = BTreeSet::new();
        for binding in &self.bindings {
            binding.validate()?;
            if !roles.insert(binding.role) {
                return Err("model analysis role binding is duplicated".to_string());
            }
        }
        let mut keys = BTreeSet::new();
        for evaluation in &self.evaluations {
            evaluation.validate().map_err(|error| error.to_string())?;
            if !keys.insert(evaluation.key.clone()) {
                return Err("model analysis evaluation key is duplicated".to_string());
            }
            if !self.bindings.iter().any(|binding| binding.eligibility_key() == evaluation.key) {
                return Err("model analysis evaluation does not match a configured exact binding"
                    .to_string());
            }
        }
        Ok(())
    }

    /// Find the unique configured role binding after full validation.
    ///
    /// # Errors
    ///
    /// Returns the configuration error before exposing a binding.
    pub fn binding(&self, role: ModelRole) -> Result<Option<&ModelRoleBindingConfig>, String> {
        self.validate()?;
        Ok(self.bindings.iter().find(|binding| binding.role == role))
    }

    /// Find a complete passing exact evaluation for the binding.
    #[must_use]
    pub fn eligible(&self, binding: &ModelRoleBindingConfig) -> bool {
        let key = binding.eligibility_key();
        self.evaluations.iter().any(|evaluation| {
            evaluation.key == key && evaluation.eligible && evaluation.validate().is_ok()
        })
    }
}

/// One exact role-to-provider/model binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRoleBindingConfig {
    /// Bound role.
    pub role: ModelRole,
    /// Provider identity expected in every response.
    pub provider: String,
    /// Exact model identity expected in every response.
    pub model: String,
    /// Concrete execution adapter.
    pub adapter: ModelAdapterConfig,
}

impl ModelRoleBindingConfig {
    /// Execution ownership projected without adapter details.
    #[must_use]
    pub const fn execution_location(&self) -> ModelExecutionLocation {
        self.adapter.execution_location()
    }

    /// Exact key required for production eligibility.
    #[must_use]
    pub fn eligibility_key(&self) -> ModelEligibilityKey {
        ModelEligibilityKey::current(&self.provider, &self.model, self.role)
    }

    /// Validate identity and adapter invariants.
    ///
    /// # Errors
    ///
    /// Returns a credential-safe configuration error.
    pub fn validate(&self) -> Result<(), String> {
        validate_identity("model provider", &self.provider)?;
        validate_identity("model", &self.model)?;
        self.adapter.validate()
    }
}

/// Concrete transport configuration for one exact binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelAdapterConfig {
    /// Agent-host-owned contract process.
    HostManaged {
        /// Contract-compatible executable path or command name.
        binary: String,
    },
    /// Policy-owned remote service request.
    ServiceManaged {
        /// Exact credential-free HTTP(S) endpoint.
        endpoint: String,
        /// Environment variable that contains the bearer credential.
        credential_env: String,
        /// Mandatory v1 data and resource policy.
        data_policy: ModelServiceDataPolicy,
    },
    /// Local contract-compatible model process.
    Local {
        /// Contract-compatible executable path or command name.
        binary: String,
    },
}

impl ModelAdapterConfig {
    /// Stable execution ownership for readiness and provenance.
    #[must_use]
    pub const fn execution_location(&self) -> ModelExecutionLocation {
        match self {
            Self::HostManaged { .. } => ModelExecutionLocation::HostManaged,
            Self::ServiceManaged { .. } => ModelExecutionLocation::ServiceManaged,
            Self::Local { .. } => ModelExecutionLocation::Local,
        }
    }

    /// Validate adapter-specific bounds without resolving a credential or executing an effect.
    ///
    /// # Errors
    ///
    /// Returns a credential-safe configuration reason.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::HostManaged { binary } | Self::Local { binary } => {
                validate_value("model adapter binary", binary, 4_096)
            }
            Self::ServiceManaged { endpoint, credential_env, data_policy } => {
                validate_environment_name(credential_env)?;
                let endpoint = Url::parse(endpoint)
                    .map_err(|_| "model service endpoint is invalid".to_string())?;
                if !matches!(endpoint.scheme(), "http" | "https")
                    || endpoint.host_str().is_none()
                    || !endpoint.username().is_empty()
                    || endpoint.password().is_some()
                    || endpoint.query().is_some()
                    || endpoint.fragment().is_some()
                {
                    return Err(
                        "model service endpoint must be credential-free HTTP(S) without query or fragment"
                            .to_string(),
                    );
                }
                data_policy.validate()
            }
        }
    }
}

/// Required service redaction policy. V1 has no permissive alternative.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelServiceRedactionPolicy {
    /// Redact every untrusted input before serialization.
    #[default]
    Required,
}

/// Required service retention declaration. V1 permits no provider retention.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelServiceRetentionPolicy {
    /// Provider is configured not to retain request or response content.
    #[default]
    None,
}

/// Explicit service-managed data and resource policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelServiceDataPolicy {
    /// Mandatory input redaction.
    pub redaction: ModelServiceRedactionPolicy,
    /// Mandatory no-retention declaration.
    pub retention: ModelServiceRetentionPolicy,
    /// Complete request wall-time limit.
    pub timeout_millis: u64,
    /// Serialized request body ceiling.
    pub max_input_bytes: usize,
    /// Decoded response body ceiling.
    pub max_output_bytes: usize,
}

impl Default for ModelServiceDataPolicy {
    fn default() -> Self {
        Self {
            redaction: ModelServiceRedactionPolicy::Required,
            retention: ModelServiceRetentionPolicy::None,
            timeout_millis: 60_000,
            max_input_bytes: MAX_MODEL_ANALYSIS_REQUEST_BYTES,
            max_output_bytes: 1024 * 1024,
        }
    }
}

impl ModelServiceDataPolicy {
    /// Validate every independent hard limit.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration reason for an invalid bound.
    pub fn validate(&self) -> Result<(), String> {
        if !(MIN_MODEL_TIMEOUT_MILLIS..=MAX_MODEL_TIMEOUT_MILLIS).contains(&self.timeout_millis) {
            return Err("model service timeout is outside the 100-300000 ms bound".to_string());
        }
        if !(1..=MAX_MODEL_ANALYSIS_REQUEST_BYTES).contains(&self.max_input_bytes) {
            return Err("model service input limit is outside the hard bound".to_string());
        }
        if !(1..=MAX_MODEL_SERVICE_OUTPUT_BYTES).contains(&self.max_output_bytes) {
            return Err("model service output limit is outside the hard bound".to_string());
        }
        Ok(())
    }
}

fn validate_identity(label: &str, value: &str) -> Result<(), String> {
    validate_value(label, value, 256)?;
    if scorchkit_core::observation::redact_text(value) != value {
        return Err(format!("{label} is not canonically redacted"));
    }
    Ok(())
}

fn validate_value(label: &str, value: &str, maximum: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(format!("{label} is empty, oversized, padded, or contains controls"));
    }
    Ok(())
}

fn validate_environment_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
    {
        return Err(
            "model service credential reference is not an environment-variable name".to_string()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use scorchkit_core::{ModelEvaluationAnswer, ModelEvaluationCorpus, ModelEvaluationVerdict};

    fn binding(role: ModelRole) -> ModelRoleBindingConfig {
        ModelRoleBindingConfig {
            role,
            provider: "fixture-host".to_string(),
            model: "exact-model".to_string(),
            adapter: ModelAdapterConfig::HostManaged { binary: "fixture-model".to_string() },
        }
    }

    fn passing_evaluation(binding: &ModelRoleBindingConfig) -> ModelEvaluationResult {
        let answers = ModelEvaluationCorpus::appsec_v1()
            .cases
            .into_iter()
            .map(|case| ModelEvaluationAnswer {
                case_id: case.id,
                verdict: case.expected_verdict,
                refused_effects: case.require_effect_refusal,
            })
            .collect();
        ModelEvaluationResult::evaluate(binding.eligibility_key(), answers).expect("evaluation")
    }

    #[test]
    fn model_analysis_is_disabled_and_empty_by_default() {
        assert_eq!(MAX_MODEL_SERVICE_OUTPUT_BYTES, 8_388_608);
        let config = ModelAnalysisConfig::default();
        assert!(!config.enabled);
        assert!(config.bindings.is_empty());
        assert!(config.evaluations.is_empty());
        config.validate().expect("default");
    }

    #[test]
    fn exact_binding_and_evaluation_validate() {
        let binding = binding(ModelRole::FindingValidation);
        let config = ModelAnalysisConfig {
            enabled: true,
            evaluations: vec![passing_evaluation(&binding)],
            bindings: vec![binding],
        };
        config.validate().expect("config");
        let selected =
            config.binding(ModelRole::FindingValidation).expect("valid").expect("binding");
        assert!(config.eligible(selected));
        assert_eq!(selected.execution_location(), ModelExecutionLocation::HostManaged);

        let mut unsafe_identity = selected.clone();
        unsafe_identity.provider = "password=secret".to_string();
        assert!(unsafe_identity.validate().is_err());
    }

    #[test]
    fn duplicate_role_and_evaluation_are_rejected_independently() {
        let first = binding(ModelRole::Planning);
        let duplicate = first.clone();
        let config = ModelAnalysisConfig {
            enabled: true,
            bindings: vec![first, duplicate],
            evaluations: Vec::new(),
        };
        assert_eq!(config.validate().unwrap_err(), "model analysis role binding is duplicated");

        let first = binding(ModelRole::Planning);
        let evaluation = passing_evaluation(&first);
        let config = ModelAnalysisConfig {
            enabled: true,
            bindings: vec![first],
            evaluations: vec![evaluation.clone(), evaluation],
        };
        assert_eq!(config.validate().unwrap_err(), "model analysis evaluation key is duplicated");
    }

    #[test]
    fn service_endpoint_policy_and_each_bound_fail_closed() {
        let valid = ModelAdapterConfig::ServiceManaged {
            endpoint: "https://models.example/v1/analyze".to_string(),
            credential_env: "SCORCHKIT_MODEL_TOKEN".to_string(),
            data_policy: ModelServiceDataPolicy::default(),
        };
        valid.validate().expect("service");
        for endpoint in [
            "ftp://models.example/v1",
            "https://user@models.example/v1",
            "https://:secret@models.example/v1",
            "https://user:secret@models.example/v1",
            "https://models.example/v1?token=secret",
            "https://models.example/v1#fragment",
        ] {
            let invalid = ModelAdapterConfig::ServiceManaged {
                endpoint: endpoint.to_string(),
                credential_env: "SCORCHKIT_MODEL_TOKEN".to_string(),
                data_policy: ModelServiceDataPolicy::default(),
            };
            assert!(invalid.validate().is_err(), "accepted {endpoint}");
        }
        let invalid_env = ModelAdapterConfig::ServiceManaged {
            endpoint: "https://models.example/v1".to_string(),
            credential_env: "1_BAD".to_string(),
            data_policy: ModelServiceDataPolicy::default(),
        };
        assert!(invalid_env.validate().is_err());

        for policy in [
            ModelServiceDataPolicy {
                timeout_millis: MIN_MODEL_TIMEOUT_MILLIS - 1,
                ..ModelServiceDataPolicy::default()
            },
            ModelServiceDataPolicy {
                timeout_millis: MAX_MODEL_TIMEOUT_MILLIS + 1,
                ..ModelServiceDataPolicy::default()
            },
            ModelServiceDataPolicy { max_input_bytes: 0, ..ModelServiceDataPolicy::default() },
            ModelServiceDataPolicy {
                max_input_bytes: MAX_MODEL_ANALYSIS_REQUEST_BYTES + 1,
                ..ModelServiceDataPolicy::default()
            },
            ModelServiceDataPolicy { max_output_bytes: 0, ..ModelServiceDataPolicy::default() },
            ModelServiceDataPolicy {
                max_output_bytes: MAX_MODEL_SERVICE_OUTPUT_BYTES + 1,
                ..ModelServiceDataPolicy::default()
            },
        ] {
            assert!(policy.validate().is_err());
        }
    }

    #[test]
    fn role_and_evaluation_counts_accept_the_exact_role_count_only() {
        let bindings: Vec<_> = ModelRole::ALL.into_iter().map(binding).collect();
        let evaluations = bindings.iter().map(passing_evaluation).collect::<Vec<_>>();
        ModelAnalysisConfig {
            enabled: true,
            bindings: bindings.clone(),
            evaluations: evaluations.clone(),
        }
        .validate()
        .expect("one binding and evaluation per role");

        let mut too_many_bindings = bindings.clone();
        too_many_bindings.push(bindings[0].clone());
        assert_eq!(
            ModelAnalysisConfig {
                enabled: true,
                bindings: too_many_bindings,
                evaluations: Vec::new(),
            }
            .validate()
            .unwrap_err(),
            "model analysis bindings exceed the role count"
        );

        let mut too_many_evaluations = evaluations;
        too_many_evaluations.push(too_many_evaluations[0].clone());
        assert_eq!(
            ModelAnalysisConfig { enabled: true, bindings, evaluations: too_many_evaluations }
                .validate()
                .unwrap_err(),
            "model analysis evaluations exceed the role count"
        );
    }

    #[test]
    fn private_value_and_environment_boundaries_are_independent() {
        validate_value("fixture", "x", 1).expect("exact value limit");
        assert!(validate_value("fixture", "", 1).is_err());
        assert!(validate_value("fixture", "xx", 1).is_err());
        assert!(validate_value("fixture", " x", 2).is_err());
        assert!(validate_value("fixture", "x\0", 2).is_err());

        validate_environment_name(&format!("A{}", "_".repeat(255)))
            .expect("exact environment-name limit");
        validate_environment_name("A1_B2").expect("non-leading digits and underscores");
        for invalid in [String::new(), format!("A{}", "_".repeat(256)), "1_BAD".to_string()] {
            assert!(validate_environment_name(&invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn config_serde_rejects_permissive_policy_and_unknown_fields() {
        let invalid_redaction = r#"
enabled = true
[[bindings]]
role = "planning"
provider = "host"
model = "model"
[bindings.adapter]
kind = "service_managed"
endpoint = "https://models.example/v1"
credential_env = "MODEL_TOKEN"
[bindings.adapter.data_policy]
redaction = "optional"
retention = "none"
timeout_millis = 1000
max_input_bytes = 1024
max_output_bytes = 1024
"#;
        assert!(toml::from_str::<ModelAnalysisConfig>(invalid_redaction).is_err());
        let unknown = r#"enabled = false
fallback_provider = "other"
"#;
        assert!(toml::from_str::<ModelAnalysisConfig>(unknown).is_err());
    }

    #[test]
    fn failed_evaluation_never_marks_binding_eligible() {
        let binding = binding(ModelRole::Verification);
        let mut evaluation = passing_evaluation(&binding);
        evaluation.outcomes[0].answer.verdict = ModelEvaluationVerdict::MissingContext;
        evaluation.outcomes[0].passed = false;
        evaluation.eligible = false;
        evaluation.validate().expect("recomputed failure");
        let config = ModelAnalysisConfig {
            enabled: true,
            bindings: vec![binding],
            evaluations: vec![evaluation],
        };
        config.validate().expect("valid failed evidence");
        assert!(!config.eligible(&config.bindings[0]));
    }
}
