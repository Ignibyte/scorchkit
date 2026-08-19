//! Versioned scanner-adapter metadata and parser outcomes.

use serde::{Deserialize, Serialize};

use crate::error::{Result, ScorchError};
use scorchkit_policy::EffectClass;

/// Wire identity for the first common scanner-adapter contract.
pub const ADAPTER_CONTRACT_V1: &str = "scorchkit.adapter/v1";

/// Product domain served by a scanner adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityDomain {
    /// Static source-code and secret analysis.
    ApplicationSource,
    /// Declared application dependencies and advisories.
    ApplicationDependency,
    /// Built packages, containers, and application deployment definitions.
    ApplicationArtifact,
    /// Running web applications and APIs.
    ApplicationRuntime,
    /// Code-informed runtime validation and attack-path support.
    ApplicationAttackPath,
    /// General host, DNS, port, and network assessment compatibility surface.
    CompatibilityNetwork,
    /// Enterprise identity, credential, SMB, and general exploitation compatibility surface.
    CompatibilityEnterprise,
    /// Cloud-account posture compatibility surface.
    CompatibilityCloud,
}

impl SecurityDomain {
    /// Whether this domain belongs to the default application-security product.
    #[must_use]
    pub const fn is_application_security(self) -> bool {
        matches!(
            self,
            Self::ApplicationSource
                | Self::ApplicationDependency
                | Self::ApplicationArtifact
                | Self::ApplicationRuntime
                | Self::ApplicationAttackPath
        )
    }
}

/// Application lifecycle stage inspected by an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStage {
    /// Source authoring and review.
    Source,
    /// Dependency resolution and application build.
    Build,
    /// Deployed application execution.
    Runtime,
    /// Human-directed validation or attack-path work.
    Manual,
    /// Non-application platform or account posture.
    Platform,
}

/// Target shape accepted by an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterTargetKind {
    /// A local source tree or source file.
    SourceTree,
    /// A dependency manifest or lockfile.
    DependencyManifest,
    /// A built package, container, or deployment artifact.
    ApplicationArtifact,
    /// A running HTTP application.
    WebApplication,
    /// A running API or imported API description.
    Api,
    /// A host, address, DNS name, port, or network range.
    Network,
    /// A cloud account, project, subscription, or general cluster posture target.
    CloudAccount,
}

/// Shape of the scanner output consumed by its adapter parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterOutputContract {
    /// Findings are produced by an in-process scanner.
    NativeFindings,
    /// One JSON document is parsed from standard output or an owned file.
    Json,
    /// One JSON document is parsed per output line.
    JsonLines,
    /// SARIF is the native interchange shape.
    Sarif,
    /// XML is parsed from standard output or an owned file.
    Xml,
    /// Line-oriented or otherwise unstructured text is parsed.
    Text,
    /// The adapter owns one or more generated output files.
    FileArtifacts,
}

/// How scanner and rule identity is established for provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceStrategy {
    /// The implementation and rule identity are versioned with `ScorchKit`.
    BuiltIn,
    /// The external executable version is the primary identity.
    ToolVersion,
    /// A rule-pack version or digest is required in addition to the tool version.
    RuleSet,
    /// A template collection version or digest is required in addition to the tool version.
    TemplateSet,
    /// A configured plugin definition digest is the primary rule identity.
    PluginDefinition,
}

/// Ownership rule for temporary artifacts created by an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporaryArtifactPolicy {
    /// The adapter does not materialize temporary files or directories.
    None,
    /// The adapter owns temporary artifacts through scoped cleanup guards.
    ScopedOwned,
}

/// Common immutable metadata embedded by every scanner-family descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterContractV1<'a> {
    /// Versioned wire identity for this contract.
    pub schema_version: &'static str,
    /// Product domain served by the adapter.
    pub security_domain: SecurityDomain,
    /// Lifecycle stage inspected by the adapter.
    pub lifecycle_stage: LifecycleStage,
    /// Target shapes accepted by the adapter.
    pub target_kinds: &'a [AdapterTargetKind],
    /// Strongest operational effect the adapter can request.
    pub strongest_effect: EffectClass,
    /// Native output shape consumed by the adapter.
    pub output_contract: AdapterOutputContract,
    /// Provenance identity required for reproducibility.
    pub provenance: ProvenanceStrategy,
    /// Temporary artifact ownership rule.
    pub temporary_artifacts: TemporaryArtifactPolicy,
}

impl AdapterContractV1<'_> {
    /// Whether this adapter belongs to the default application-security catalog.
    #[must_use]
    pub const fn is_application_security(&self) -> bool {
        self.security_domain.is_application_security()
    }
}

/// Typed outcome from a v1 scanner-output parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterParseOutcome<T> {
    /// Scanner execution succeeded and reported no findings.
    NoFindings,
    /// Scanner execution succeeded and produced parsed findings.
    Findings(T),
    /// Output could not be interpreted according to the declared contract.
    Malformed {
        /// Stable, secret-safe reason for the parse failure.
        reason: String,
    },
}

impl<T> AdapterParseOutcome<T> {
    /// Construct a malformed-output outcome.
    #[must_use]
    pub fn malformed(reason: impl Into<String>) -> Self {
        Self::Malformed { reason: reason.into() }
    }
}

impl<T: Default> AdapterParseOutcome<T> {
    /// Convert a parser outcome into the module execution result contract.
    ///
    /// # Errors
    ///
    /// Returns [`ScorchError::ToolOutputParse`] for malformed scanner output.
    pub fn into_result(self, tool: &str) -> Result<T> {
        match self {
            Self::NoFindings => Ok(T::default()),
            Self::Findings(findings) => Ok(findings),
            Self::Malformed { reason } => {
                Err(ScorchError::ToolOutputParse { tool: tool.to_string(), reason })
            }
        }
    }

    /// Preserve a legacy parser API that historically returned an empty value on malformed input.
    #[must_use]
    pub fn into_legacy(self) -> T {
        match self {
            Self::Findings(findings) => findings,
            Self::NoFindings | Self::Malformed { .. } => T::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_domains_partition_application_and_compatibility_surfaces() {
        for domain in [
            SecurityDomain::ApplicationSource,
            SecurityDomain::ApplicationDependency,
            SecurityDomain::ApplicationArtifact,
            SecurityDomain::ApplicationRuntime,
            SecurityDomain::ApplicationAttackPath,
        ] {
            assert!(domain.is_application_security());
        }
        for domain in [
            SecurityDomain::CompatibilityNetwork,
            SecurityDomain::CompatibilityEnterprise,
            SecurityDomain::CompatibilityCloud,
        ] {
            assert!(!domain.is_application_security());
        }
    }

    #[test]
    fn parser_outcome_distinguishes_empty_findings_and_malformed_output() {
        assert_eq!(
            AdapterParseOutcome::<Vec<u8>>::NoFindings.into_result("fixture").expect("empty"),
            Vec::<u8>::new()
        );
        assert_eq!(
            AdapterParseOutcome::Findings(vec![7_u8]).into_result("fixture").expect("findings"),
            vec![7]
        );
        let error = AdapterParseOutcome::<Vec<u8>>::malformed("invalid JSON")
            .into_result("fixture")
            .expect_err("malformed output must fail");
        assert!(matches!(
            error,
            ScorchError::ToolOutputParse { tool, reason }
                if tool == "fixture" && reason == "invalid JSON"
        ));
    }

    #[test]
    fn adapter_contract_serializes_stable_camel_case_fields() {
        let contract = AdapterContractV1 {
            schema_version: ADAPTER_CONTRACT_V1,
            security_domain: SecurityDomain::ApplicationRuntime,
            lifecycle_stage: LifecycleStage::Runtime,
            target_kinds: &[AdapterTargetKind::WebApplication],
            strongest_effect: EffectClass::ActiveSafe,
            output_contract: AdapterOutputContract::Json,
            provenance: ProvenanceStrategy::ToolVersion,
            temporary_artifacts: TemporaryArtifactPolicy::None,
        };
        let json = serde_json::to_value(contract).expect("serialize adapter contract");
        assert_eq!(json["schemaVersion"], ADAPTER_CONTRACT_V1);
        assert_eq!(json["securityDomain"], "application_runtime");
        assert_eq!(json["strongestEffect"], "active-safe");
    }
}
