//! Monotonic run-configuration resolution.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ControlErrorCodeV1, ControlErrorV1};

/// Maximum explicit targets in one resolved run.
pub const MAX_CONTROL_TARGETS: usize = 64;
/// Maximum explicit modules in one resolved run.
pub const MAX_CONTROL_MODULES: usize = 256;

/// Provider-neutral target shapes accepted by configuration resolution.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, JsonSchema, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ControlTargetKindV1 {
    /// HTTP or HTTPS application.
    Web,
    /// Canonical local source tree.
    Source,
    /// Local application artifact.
    Artifact,
}

/// One explicit normalized target candidate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlTargetV1 {
    /// Target shape.
    pub kind: ControlTargetKindV1,
    /// Canonical target value.
    pub value: String,
}

/// Capabilities exposed by the v1 control configuration contract.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, JsonSchema, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ControlCapabilityV1 {
    /// Web application scanning.
    DastScan,
    /// Source and artifact analysis.
    CodeScan,
    /// Bounded external tool execution.
    ExternalTool,
    /// Digest-bound isolated third-party extension execution.
    ExtensionExecute,
    /// Explicit credential use.
    CredentialUse,
    /// Explicit exploitation.
    Exploit,
    /// ScorchKit-owned local state access.
    LocalState,
    /// Offline provider snapshot refresh.
    ProviderRefresh,
    /// Policy-owned webhook delivery.
    WebhookDelivery,
}

/// Operational effect classes exposed by v1.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, JsonSchema, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ControlEffectV1 {
    /// Read-only or observation work.
    Passive,
    /// Bounded active probes not intended to alter durable target state.
    ActiveSafe,
    /// Intrusive application behavior.
    Intrusive,
    /// Credential-bearing behavior.
    CredentialTest,
    /// Explicit exploitation.
    Exploit,
}

/// Hard run budgets that may only narrow across layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlBudgetsV1 {
    /// Whole-run wall-time ceiling.
    pub timeout_seconds: u64,
    /// Maximum concurrent modules.
    pub max_concurrent_modules: u16,
    /// Maximum serialized result bytes.
    pub max_result_bytes: u64,
    /// Maximum serialized event bytes.
    pub max_event_bytes: u64,
}

impl ControlBudgetsV1 {
    fn validate(self) -> Result<(), ControlErrorV1> {
        if self.timeout_seconds == 0
            || self.max_concurrent_modules == 0
            || self.max_result_bytes == 0
            || self.max_event_bytes == 0
        {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                "control configuration budgets must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Maximum policy-validated values from which layers may only remove or reduce.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionCeilingV1 {
    /// Exact targets already normalized and authorized by the application service.
    pub targets: Vec<ControlTargetV1>,
    /// Maximum capabilities available to this run.
    pub capabilities: Vec<ControlCapabilityV1>,
    /// Maximum effects available to this run.
    pub effects: Vec<ControlEffectV1>,
    /// Maximum explicit module set.
    pub modules: Vec<String>,
    /// Maximum run budgets.
    pub budgets: ControlBudgetsV1,
}

/// One optional organization, project, or run restriction.
#[derive(Debug, Clone, Default, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigPatchV1 {
    /// Replacement target subset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<ControlTargetV1>>,
    /// Replacement capability subset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<ControlCapabilityV1>>,
    /// Replacement effect subset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effects: Option<Vec<ControlEffectV1>>,
    /// Replacement module subset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modules: Option<Vec<String>>,
    /// Lower whole-run timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    /// Lower module concurrency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_modules: Option<u16>,
    /// Lower result ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_result_bytes: Option<u64>,
    /// Lower event ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_event_bytes: Option<u64>,
}

/// Fixed configuration layers in resolution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigLayerName {
    /// Policy-validated safe defaults and explicit ceiling.
    SafeDefaults,
    /// Organization-wide restrictions.
    Organization,
    /// Project-specific restrictions.
    Project,
    /// One-run restrictions.
    Run,
}

/// Outcome recorded for one field at one layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigDecisionOutcome {
    /// The layer omitted the field, retaining the prior value.
    Retained,
    /// The layer supplied an equal value.
    Confirmed,
    /// The layer reduced the prior value.
    Narrowed,
}

/// One ordered non-secret resolution decision.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigDecision {
    /// Layer that made the decision.
    pub layer: ConfigLayerName,
    /// Stable field name.
    pub field: String,
    /// Whether the value was retained, confirmed, or narrowed.
    pub outcome: ConfigDecisionOutcome,
    /// Cardinality or numeric value before the layer.
    pub before: u64,
    /// Cardinality or numeric value after the layer.
    pub after: u64,
}

/// Complete layered input to one resolution query.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationResolutionRequestV1 {
    /// Policy-authorized maximum inputs.
    pub ceiling: ResolutionCeilingV1,
    /// Organization restrictions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<ConfigPatchV1>,
    /// Project restrictions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<ConfigPatchV1>,
    /// Run restrictions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<ConfigPatchV1>,
}

/// Effective run configuration plus its complete ordered decision log.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedConfigurationV1 {
    /// Effective targets.
    pub targets: Vec<ControlTargetV1>,
    /// Effective capabilities.
    pub capabilities: Vec<ControlCapabilityV1>,
    /// Effective effects.
    pub effects: Vec<ControlEffectV1>,
    /// Effective modules.
    pub modules: Vec<String>,
    /// Effective budgets.
    pub budgets: ControlBudgetsV1,
    /// Ordered decisions beginning with safe defaults.
    pub decisions: Vec<ConfigDecision>,
}

/// Resolve safe defaults plus organization, project, and run restrictions.
///
/// # Errors
///
/// Returns a typed error when the ceiling is malformed or a patch adds a value or raises a budget.
pub fn resolve_configuration(
    ceiling: ResolutionCeilingV1,
    organization: Option<&ConfigPatchV1>,
    project: Option<&ConfigPatchV1>,
    run: Option<&ConfigPatchV1>,
) -> Result<ResolvedConfigurationV1, ControlErrorV1> {
    validate_ceiling(&ceiling)?;
    let mut resolved = ResolvedConfigurationV1 {
        targets: sorted_unique(ceiling.targets, "targets", MAX_CONTROL_TARGETS)?,
        capabilities: sorted_unique(ceiling.capabilities, "capabilities", 32)?,
        effects: sorted_unique(ceiling.effects, "effects", 16)?,
        modules: sorted_unique_strings(ceiling.modules, "modules", MAX_CONTROL_MODULES)?,
        budgets: ceiling.budgets,
        decisions: Vec::new(),
    };
    record_defaults(&mut resolved);
    for (layer, patch) in [
        (ConfigLayerName::Organization, organization),
        (ConfigLayerName::Project, project),
        (ConfigLayerName::Run, run),
    ] {
        apply_patch(&mut resolved, layer, patch)?;
    }
    Ok(resolved)
}

fn validate_ceiling(ceiling: &ResolutionCeilingV1) -> Result<(), ControlErrorV1> {
    ceiling.budgets.validate()?;
    for target in &ceiling.targets {
        validate_identifier(&target.value, "target", 4_096)?;
    }
    for module in &ceiling.modules {
        validate_identifier(module, "module", 256)?;
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str, maximum: usize) -> Result<(), ControlErrorV1> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::InvalidRequest,
            format!("control configuration {label} is empty, oversized, or contains controls"),
        ));
    }
    Ok(())
}

fn sorted_unique<T: Ord>(
    values: Vec<T>,
    field: &str,
    maximum: usize,
) -> Result<Vec<T>, ControlErrorV1> {
    if values.len() > maximum {
        return Err(limit_error(field, maximum));
    }
    let original_len = values.len();
    let unique: BTreeSet<T> = values.into_iter().collect();
    if unique.len() != original_len {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::InvalidRequest,
            format!("control configuration {field} contains duplicates"),
        ));
    }
    Ok(unique.into_iter().collect())
}

fn sorted_unique_strings(
    values: Vec<String>,
    field: &str,
    maximum: usize,
) -> Result<Vec<String>, ControlErrorV1> {
    for value in &values {
        validate_identifier(value, field, 256)?;
    }
    sorted_unique(values, field, maximum)
}

fn limit_error(field: &str, maximum: usize) -> ControlErrorV1 {
    ControlErrorV1::new(
        ControlErrorCodeV1::LimitExceeded,
        format!("control configuration {field} exceeds its {maximum}-item limit"),
    )
}

fn record_defaults(resolved: &mut ResolvedConfigurationV1) {
    for (field, value) in [
        ("targets", resolved.targets.len() as u64),
        ("capabilities", resolved.capabilities.len() as u64),
        ("effects", resolved.effects.len() as u64),
        ("modules", resolved.modules.len() as u64),
        ("timeout_seconds", resolved.budgets.timeout_seconds),
        ("max_concurrent_modules", u64::from(resolved.budgets.max_concurrent_modules)),
        ("max_result_bytes", resolved.budgets.max_result_bytes),
        ("max_event_bytes", resolved.budgets.max_event_bytes),
    ] {
        resolved.decisions.push(ConfigDecision {
            layer: ConfigLayerName::SafeDefaults,
            field: field.to_string(),
            outcome: ConfigDecisionOutcome::Confirmed,
            before: value,
            after: value,
        });
    }
}

fn apply_patch(
    resolved: &mut ResolvedConfigurationV1,
    layer: ConfigLayerName,
    patch: Option<&ConfigPatchV1>,
) -> Result<(), ControlErrorV1> {
    let empty = ConfigPatchV1::default();
    let patch = patch.unwrap_or(&empty);
    apply_subset(
        &mut resolved.targets,
        patch.targets.clone(),
        layer,
        "targets",
        MAX_CONTROL_TARGETS,
        &mut resolved.decisions,
    )?;
    apply_subset(
        &mut resolved.capabilities,
        patch.capabilities.clone(),
        layer,
        "capabilities",
        32,
        &mut resolved.decisions,
    )?;
    apply_subset(
        &mut resolved.effects,
        patch.effects.clone(),
        layer,
        "effects",
        16,
        &mut resolved.decisions,
    )?;
    apply_string_subset(
        &mut resolved.modules,
        patch.modules.clone(),
        layer,
        "modules",
        MAX_CONTROL_MODULES,
        &mut resolved.decisions,
    )?;
    apply_number(
        &mut resolved.budgets.timeout_seconds,
        patch.timeout_seconds,
        layer,
        "timeout_seconds",
        &mut resolved.decisions,
    )?;
    apply_number(
        &mut resolved.budgets.max_concurrent_modules,
        patch.max_concurrent_modules,
        layer,
        "max_concurrent_modules",
        &mut resolved.decisions,
    )?;
    apply_number(
        &mut resolved.budgets.max_result_bytes,
        patch.max_result_bytes,
        layer,
        "max_result_bytes",
        &mut resolved.decisions,
    )?;
    apply_number(
        &mut resolved.budgets.max_event_bytes,
        patch.max_event_bytes,
        layer,
        "max_event_bytes",
        &mut resolved.decisions,
    )?;
    Ok(())
}

fn apply_subset<T: Ord + Clone>(
    current: &mut Vec<T>,
    requested: Option<Vec<T>>,
    layer: ConfigLayerName,
    field: &str,
    maximum: usize,
    decisions: &mut Vec<ConfigDecision>,
) -> Result<(), ControlErrorV1> {
    let before = current.len();
    let Some(requested) = requested else {
        decisions.push(ConfigDecision {
            layer,
            field: field.to_string(),
            outcome: ConfigDecisionOutcome::Retained,
            before: before as u64,
            after: before as u64,
        });
        return Ok(());
    };
    let requested = sorted_unique(requested, field, maximum)?;
    let available: BTreeSet<_> = current.iter().cloned().collect();
    if requested.iter().any(|value| !available.contains(value)) {
        return Err(widening_error(layer, field));
    }
    let after = requested.len();
    *current = requested;
    decisions.push(ConfigDecision {
        layer,
        field: field.to_string(),
        outcome: if after == before {
            ConfigDecisionOutcome::Confirmed
        } else {
            ConfigDecisionOutcome::Narrowed
        },
        before: before as u64,
        after: after as u64,
    });
    Ok(())
}

fn apply_string_subset(
    current: &mut Vec<String>,
    requested: Option<Vec<String>>,
    layer: ConfigLayerName,
    field: &str,
    maximum: usize,
    decisions: &mut Vec<ConfigDecision>,
) -> Result<(), ControlErrorV1> {
    if let Some(values) = &requested {
        for value in values {
            validate_identifier(value, field, 256)?;
        }
    }
    apply_subset(current, requested, layer, field, maximum, decisions)
}

trait NarrowNumber: Copy + PartialOrd + Into<u64> {}
impl NarrowNumber for u16 {}
impl NarrowNumber for u64 {}

fn apply_number<T: NarrowNumber>(
    current: &mut T,
    requested: Option<T>,
    layer: ConfigLayerName,
    field: &str,
    decisions: &mut Vec<ConfigDecision>,
) -> Result<(), ControlErrorV1> {
    let before = (*current).into();
    let (after, outcome) = match requested {
        None => (before, ConfigDecisionOutcome::Retained),
        Some(value) if value.into() == 0 => {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                format!("control configuration {field} must be nonzero"),
            ));
        }
        Some(value) if value > *current => return Err(widening_error(layer, field)),
        Some(value) if value.into() == before => (before, ConfigDecisionOutcome::Confirmed),
        Some(value) => {
            *current = value;
            (value.into(), ConfigDecisionOutcome::Narrowed)
        }
    };
    decisions.push(ConfigDecision { layer, field: field.to_string(), outcome, before, after });
    Ok(())
}

fn widening_error(layer: ConfigLayerName, field: &str) -> ControlErrorV1 {
    ControlErrorV1::new(
        ControlErrorCodeV1::ConfigurationWidening,
        format!("{layer:?} configuration attempted to widen {field}"),
    )
    .with_details(serde_json::json!({ "layer": layer, "field": field }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ceiling() -> ResolutionCeilingV1 {
        ResolutionCeilingV1 {
            targets: vec![
                ControlTargetV1 {
                    kind: ControlTargetKindV1::Web,
                    value: "https://a.example/".to_string(),
                },
                ControlTargetV1 {
                    kind: ControlTargetKindV1::Web,
                    value: "https://b.example/".to_string(),
                },
            ],
            capabilities: vec![ControlCapabilityV1::DastScan, ControlCapabilityV1::ExternalTool],
            effects: vec![ControlEffectV1::Passive, ControlEffectV1::ActiveSafe],
            modules: vec!["headers".to_string(), "tls".to_string()],
            budgets: ControlBudgetsV1 {
                timeout_seconds: 60,
                max_concurrent_modules: 4,
                max_result_bytes: 1_024,
                max_event_bytes: 512,
            },
        }
    }

    #[test]
    fn layers_apply_in_exact_order_and_only_narrow() {
        let organization = ConfigPatchV1 {
            targets: Some(vec![ceiling().targets[0].clone()]),
            max_concurrent_modules: Some(3),
            ..ConfigPatchV1::default()
        };
        let project = ConfigPatchV1 {
            effects: Some(vec![ControlEffectV1::Passive]),
            timeout_seconds: Some(30),
            ..ConfigPatchV1::default()
        };
        let run = ConfigPatchV1 {
            modules: Some(vec!["headers".to_string()]),
            max_result_bytes: Some(128),
            ..ConfigPatchV1::default()
        };
        let resolved =
            resolve_configuration(ceiling(), Some(&organization), Some(&project), Some(&run))
                .expect("narrowing configuration");
        assert_eq!(resolved.targets, organization.targets.expect("targets"));
        assert_eq!(resolved.effects, project.effects.expect("effects"));
        assert_eq!(resolved.modules, run.modules.expect("modules"));
        assert_eq!(resolved.budgets.timeout_seconds, 30);
        assert_eq!(resolved.budgets.max_concurrent_modules, 3);
        assert_eq!(resolved.budgets.max_result_bytes, 128);
        assert_eq!(resolved.decisions.len(), 32);
    }

    #[test]
    fn every_widening_class_is_rejected() {
        let cases = [
            ConfigPatchV1 {
                targets: Some(vec![ControlTargetV1 {
                    kind: ControlTargetKindV1::Web,
                    value: "https://outside.example/".to_string(),
                }]),
                ..ConfigPatchV1::default()
            },
            ConfigPatchV1 {
                capabilities: Some(vec![ControlCapabilityV1::Exploit]),
                ..ConfigPatchV1::default()
            },
            ConfigPatchV1 {
                effects: Some(vec![ControlEffectV1::Exploit]),
                ..ConfigPatchV1::default()
            },
            ConfigPatchV1 {
                modules: Some(vec!["unknown".to_string()]),
                ..ConfigPatchV1::default()
            },
            ConfigPatchV1 { timeout_seconds: Some(61), ..ConfigPatchV1::default() },
            ConfigPatchV1 { max_concurrent_modules: Some(5), ..ConfigPatchV1::default() },
            ConfigPatchV1 { max_result_bytes: Some(1_025), ..ConfigPatchV1::default() },
            ConfigPatchV1 { max_event_bytes: Some(513), ..ConfigPatchV1::default() },
        ];
        for patch in cases {
            let error = resolve_configuration(ceiling(), None, None, Some(&patch))
                .expect_err("widening must fail");
            assert_eq!(error.code, ControlErrorCodeV1::ConfigurationWidening);
        }
    }

    #[test]
    fn malformed_ceiling_and_patches_fail_independently() {
        let mut duplicate = ceiling();
        duplicate.modules.push("headers".to_string());
        assert_eq!(
            resolve_configuration(duplicate, None, None, None).expect_err("duplicate").code,
            ControlErrorCodeV1::InvalidRequest
        );

        let zero = ConfigPatchV1 { timeout_seconds: Some(0), ..ConfigPatchV1::default() };
        assert_eq!(
            resolve_configuration(ceiling(), None, None, Some(&zero)).expect_err("zero").code,
            ControlErrorCodeV1::InvalidRequest
        );
    }
}
