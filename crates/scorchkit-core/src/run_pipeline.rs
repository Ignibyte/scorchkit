//! Provider-neutral contracts for typed scan lifecycle processors.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::observation::redact_text;
use crate::severity::Severity;
use scorchkit_policy::policy::{Capability, EffectClass, PolicyTarget};

pub const PROCESSOR_CONTRACT_SCHEMA_V1: &str = "scorchkit.run-processor/v1";
pub const PROCESSOR_REQUEST_SCHEMA_V1: &str = "scorchkit.run-processor-request/v1";
pub const PROCESSOR_RESPONSE_SCHEMA_V1: &str = "scorchkit.run-processor-response/v1";
pub const PROCESSOR_OUTCOME_SCHEMA_V1: &str = "scorchkit.run-processor-outcome/v1";
pub const PREPROCESS_INPUT_SCHEMA_V1: &str = "scorchkit.run-preprocess-input/v1";
pub const PREPROCESS_PROPOSAL_SCHEMA_V1: &str = "scorchkit.run-preprocess-proposal/v1";
pub const FINDING_INPUT_SCHEMA_V1: &str = "scorchkit.run-finding-input/v1";
pub const FINDING_PROPOSAL_SCHEMA_V1: &str = "scorchkit.run-finding-proposal/v1";
pub const REPORT_INPUT_SCHEMA_V1: &str = "scorchkit.run-report-input/v1";
pub const REPORT_PROPOSAL_SCHEMA_V1: &str = "scorchkit.run-report-proposal/v1";

pub const MAX_RUN_PROCESSORS: usize = 64;
pub const MAX_RUN_OUTCOMES: usize = MAX_RUN_PROCESSORS * (MAX_RUN_MODULES + 2);
pub const MAX_RUN_PROCESSOR_ID_BYTES: usize = 64;
pub const MAX_RUN_MODULES: usize = 512;
pub const MAX_RUN_FINDINGS: usize = 10_000;
pub const MAX_RUN_PROPOSALS: usize = 10_000;
pub const MAX_RUN_ANNOTATIONS: usize = 64;
pub const MAX_RUN_TEXT_BYTES: usize = 4_096;
pub const MAX_RUN_INPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RUN_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RUN_TIMEOUT_MILLIS: u64 = 300_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPipelineValidationError(pub String);

impl fmt::Display for RunPipelineValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RunPipelineValidationError {}

type ValidationResult<T> = Result<T, RunPipelineValidationError>;

/// Canonical order of a complete `ScorchKit` run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunPhase {
    IntakeValidation,
    Preprocessing,
    PlanProposal,
    Authorization,
    Execution,
    Normalization,
    Enrichment,
    Correlation,
    AnalysisAttachment,
    Reporting,
    Notification,
}

impl RunPhase {
    #[must_use]
    pub const fn input_schema(self) -> &'static str {
        match self {
            Self::Preprocessing => PREPROCESS_INPUT_SCHEMA_V1,
            Self::Enrichment => FINDING_INPUT_SCHEMA_V1,
            Self::Reporting => REPORT_INPUT_SCHEMA_V1,
            Self::IntakeValidation
            | Self::PlanProposal
            | Self::Authorization
            | Self::Execution
            | Self::Normalization
            | Self::Correlation
            | Self::AnalysisAttachment
            | Self::Notification => "scorchkit.run-system-phase-input/v1",
        }
    }

    #[must_use]
    pub const fn output_schema(self) -> &'static str {
        match self {
            Self::Preprocessing => PREPROCESS_PROPOSAL_SCHEMA_V1,
            Self::Enrichment => FINDING_PROPOSAL_SCHEMA_V1,
            Self::Reporting => REPORT_PROPOSAL_SCHEMA_V1,
            Self::IntakeValidation
            | Self::PlanProposal
            | Self::Authorization
            | Self::Execution
            | Self::Normalization
            | Self::Correlation
            | Self::AnalysisAttachment
            | Self::Notification => "scorchkit.run-system-phase-output/v1",
        }
    }

    #[must_use]
    pub const fn supports_local_processor(self) -> bool {
        matches!(self, Self::Preprocessing | Self::Enrichment | Self::Reporting)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessorFailureMode {
    Required,
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessorBudget {
    pub timeout_millis: u64,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
}

impl ProcessorBudget {
    /// Validate nonzero upper-bounded time and byte ceilings.
    ///
    /// # Errors
    ///
    /// Returns an error when any ceiling is zero or exceeds its protocol maximum.
    pub fn validate(self) -> ValidationResult<()> {
        if !(1..=MAX_RUN_TIMEOUT_MILLIS).contains(&self.timeout_millis) {
            return invalid(format!("processor timeout_millis must be 1-{MAX_RUN_TIMEOUT_MILLIS}"));
        }
        if !(1..=MAX_RUN_INPUT_BYTES).contains(&self.max_input_bytes) {
            return invalid(format!("processor max_input_bytes must be 1-{MAX_RUN_INPUT_BYTES}"));
        }
        if !(1..=MAX_RUN_OUTPUT_BYTES).contains(&self.max_output_bytes) {
            return invalid(format!("processor max_output_bytes must be 1-{MAX_RUN_OUTPUT_BYTES}"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunProcessorContract {
    pub schema: String,
    pub id: String,
    pub phase: RunPhase,
    pub input_schema: String,
    pub output_schema: String,
    #[serde(default)]
    pub capabilities: BTreeSet<Capability>,
    pub failure_mode: ProcessorFailureMode,
    pub order: u16,
    pub budget: ProcessorBudget,
}

impl RunProcessorContract {
    /// Validate the processor identity, schemas, phase, capabilities, and budgets.
    ///
    /// # Errors
    ///
    /// Returns an error when any contract field violates the v1 protocol.
    pub fn validate(&self) -> ValidationResult<()> {
        if self.schema != PROCESSOR_CONTRACT_SCHEMA_V1 {
            return invalid("unsupported run processor contract schema");
        }
        validate_identifier("processor id", &self.id)?;
        if !self.phase.supports_local_processor() {
            return invalid(format!("phase {:?} does not accept a local processor", self.phase));
        }
        if self.input_schema != self.phase.input_schema()
            || self.output_schema != self.phase.output_schema()
        {
            return invalid("processor phase and input/output schemas do not match");
        }
        if self.capabilities.len() > 16 {
            return invalid("processor capability count exceeds 16");
        }
        self.budget.validate()
    }
}

/// Policy-sealed maxima supplied by the host, never by a processor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunAuthority {
    pub target: PolicyTarget,
    pub modules: BTreeSet<String>,
    pub capabilities: BTreeSet<Capability>,
    pub max_effect: EffectClass,
    pub credential_use: bool,
}

impl RunAuthority {
    /// Validate the host-built authorization ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid module identities, excessive counts, or inconsistent grants.
    pub fn validate(&self) -> ValidationResult<()> {
        validate_policy_target(&self.target)?;
        if self.modules.len() > MAX_RUN_MODULES {
            return invalid(format!("run authority module count exceeds {MAX_RUN_MODULES}"));
        }
        for module in &self.modules {
            validate_identifier("module id", module)?;
        }
        if self.capabilities.len() > 16 {
            return invalid("run authority capability count exceeds 16");
        }
        if self.credential_use && !self.capabilities.contains(&Capability::CredentialUse) {
            return invalid("credential_use requires the credential-use capability");
        }
        Ok(())
    }

    /// Clamp a preprocessing proposal to this host-built ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error when the proposal changes the target or expands any authority dimension.
    pub fn clamp(&self, proposal: &PreprocessProposal) -> ValidationResult<AcceptedPreprocess> {
        self.validate()?;
        if proposal.schema != PREPROCESS_PROPOSAL_SCHEMA_V1 {
            return invalid("unsupported preprocessing proposal schema");
        }
        if proposal.target.as_ref().is_some_and(|target| target != &self.target) {
            return invalid("preprocessing proposal cannot change the authorized target");
        }
        if proposal.modules.len() > MAX_RUN_MODULES {
            return invalid(format!("proposed module count exceeds {MAX_RUN_MODULES}"));
        }
        let modules: BTreeSet<_> = proposal.modules.iter().cloned().collect();
        if modules.len() != proposal.modules.len() {
            return invalid("proposed modules must be unique");
        }
        for module in &modules {
            validate_identifier("module id", module)?;
        }
        if !modules.is_subset(&self.modules) {
            return invalid("preprocessing proposal cannot add an unavailable module");
        }
        if !proposal.capabilities.is_subset(&self.capabilities) {
            return invalid("preprocessing proposal cannot expand capabilities");
        }
        if proposal.effect > self.max_effect {
            return invalid("preprocessing proposal cannot increase the authorized effect");
        }
        if proposal.credential_use && !self.credential_use {
            return invalid("preprocessing proposal cannot enable credential use");
        }
        if proposal.credential_use && !proposal.capabilities.contains(&Capability::CredentialUse) {
            return invalid("credential use requires the proposed credential-use capability");
        }
        Ok(AcceptedPreprocess {
            target: self.target.clone(),
            modules,
            capabilities: proposal.capabilities.clone(),
            effect: proposal.effect,
            credential_use: proposal.credential_use,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreprocessProposal {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PolicyTarget>,
    #[serde(default)]
    pub modules: Vec<String>,
    #[serde(default)]
    pub capabilities: BTreeSet<Capability>,
    pub effect: EffectClass,
    #[serde(default)]
    pub credential_use: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedPreprocess {
    pub target: PolicyTarget,
    pub modules: BTreeSet<String>,
    pub capabilities: BTreeSet<Capability>,
    pub effect: EffectClass,
    pub credential_use: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingSnapshot {
    pub finding_id: String,
    pub module_id: String,
    pub severity: Severity,
    pub title: String,
    pub affected_target: String,
}

impl FindingSnapshot {
    /// Validate the bounded immutable finding projection.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identities or unbounded text.
    pub fn validate(&self) -> ValidationResult<()> {
        validate_identity("finding id", &self.finding_id)?;
        validate_identifier("module id", &self.module_id)?;
        validate_text("finding title", &self.title)?;
        validate_text("finding target", &self.affected_target)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingProposalKind {
    Retain,
    Filter,
    Duplicate,
    Enrich,
    Correlate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingProposal {
    pub source_finding_id: String,
    pub kind: FindingProposalKind,
    #[serde(default)]
    pub related_finding_ids: Vec<String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

impl FindingProposal {
    fn validate(&mut self, source_ids: &BTreeSet<String>) -> ValidationResult<()> {
        validate_identity("source finding id", &self.source_finding_id)?;
        if !source_ids.contains(&self.source_finding_id) {
            return invalid("finding proposal references an unknown source finding");
        }
        if self.related_finding_ids.len() > MAX_RUN_PROPOSALS {
            return invalid("finding proposal has too many related identities");
        }
        let mut related = BTreeSet::new();
        for identity in &self.related_finding_ids {
            validate_identity("related finding id", identity)?;
            if identity == &self.source_finding_id {
                return invalid("related finding identity must differ from its source");
            }
            if !source_ids.contains(identity) {
                return invalid("finding proposal references an unknown related finding");
            }
            if !related.insert(identity.clone()) {
                return invalid("related finding identities must be unique");
            }
        }
        if self.annotations.len() > MAX_RUN_ANNOTATIONS {
            return invalid(format!("finding annotations exceed {MAX_RUN_ANNOTATIONS}"));
        }
        for (name, value) in &mut self.annotations {
            validate_identifier("annotation name", name)?;
            validate_text("annotation value", value)?;
            *value = redact_text(value);
        }
        match self.kind {
            FindingProposalKind::Retain | FindingProposalKind::Filter
                if !self.related_finding_ids.is_empty() || !self.annotations.is_empty() =>
            {
                return invalid("retain/filter proposals cannot carry relations or annotations");
            }
            FindingProposalKind::Duplicate if self.related_finding_ids.is_empty() => {
                return invalid("duplicate proposals require a related finding identity");
            }
            FindingProposalKind::Duplicate if !self.annotations.is_empty() => {
                return invalid("duplicate proposals cannot carry annotations");
            }
            FindingProposalKind::Enrich if self.annotations.is_empty() => {
                return invalid("enrichment proposals require at least one annotation");
            }
            FindingProposalKind::Enrich if !self.related_finding_ids.is_empty() => {
                return invalid("enrichment proposals cannot carry related finding identities");
            }
            FindingProposalKind::Correlate if self.related_finding_ids.is_empty() => {
                return invalid("correlation proposals require a related finding identity");
            }
            FindingProposalKind::Retain
            | FindingProposalKind::Filter
            | FindingProposalKind::Duplicate
            | FindingProposalKind::Enrich
            | FindingProposalKind::Correlate => {}
        }
        self.related_finding_ids.sort();
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum RunProcessorInput {
    Preprocess {
        target: PolicyTarget,
        modules: Vec<String>,
        capabilities: BTreeSet<Capability>,
        max_effect: EffectClass,
        credential_use: bool,
    },
    Findings {
        module_id: String,
        module_name: String,
        findings: Vec<FindingSnapshot>,
    },
    Report {
        scan_id: String,
        target: PolicyTarget,
        total_findings: usize,
        severity_counts: BTreeMap<String, usize>,
    },
}

impl RunProcessorInput {
    #[must_use]
    pub const fn phase(&self) -> RunPhase {
        match self {
            Self::Preprocess { .. } => RunPhase::Preprocessing,
            Self::Findings { .. } => RunPhase::Enrichment,
            Self::Report { .. } => RunPhase::Reporting,
        }
    }

    /// Validate phase-specific input counts, identities, and consistency.
    ///
    /// # Errors
    ///
    /// Returns an error when nested input exceeds a bound or contradicts its enclosing record.
    pub fn validate(&self) -> ValidationResult<()> {
        match self {
            Self::Preprocess { target, modules, capabilities, credential_use, .. } => {
                validate_policy_target(target)?;
                if modules.len() > MAX_RUN_MODULES {
                    return invalid(format!(
                        "processor input module count exceeds {MAX_RUN_MODULES}"
                    ));
                }
                let mut unique = BTreeSet::new();
                for module in modules {
                    validate_identifier("module id", module)?;
                    if !unique.insert(module) {
                        return invalid("processor input modules must be unique");
                    }
                }
                if capabilities.len() > 16 {
                    return invalid("processor input capability count exceeds 16");
                }
                if *credential_use && !capabilities.contains(&Capability::CredentialUse) {
                    return invalid(
                        "processor input credential_use requires the credential-use capability",
                    );
                }
            }
            Self::Findings { module_id, module_name, findings } => {
                validate_identifier("module id", module_id)?;
                validate_text("module name", module_name)?;
                if findings.len() > MAX_RUN_FINDINGS {
                    return invalid(format!(
                        "processor input finding count exceeds {MAX_RUN_FINDINGS}"
                    ));
                }
                let mut identities = BTreeSet::new();
                for finding in findings {
                    finding.validate()?;
                    if finding.module_id != *module_id {
                        return invalid(
                            "processor input finding module does not match the enclosing module",
                        );
                    }
                    if !identities.insert(&finding.finding_id) {
                        return invalid("processor input finding identities must be unique");
                    }
                }
            }
            Self::Report { scan_id, target, total_findings, severity_counts } => {
                validate_identifier("scan id", scan_id)?;
                validate_policy_target(target)?;
                if *total_findings > MAX_RUN_FINDINGS {
                    return invalid(format!("report finding count exceeds {MAX_RUN_FINDINGS}"));
                }
                let expected: BTreeSet<_> =
                    ["critical", "high", "medium", "low", "info"].into_iter().collect();
                if severity_counts.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
                    return invalid("report severity counts must contain the five canonical keys");
                }
                let sum = severity_counts
                    .values()
                    .try_fold(0_usize, |total, count| total.checked_add(*count));
                if sum != Some(*total_findings) {
                    return invalid("report severity counts must sum to total_findings");
                }
            }
        }
        Ok(())
    }

    fn source_finding_ids(&self) -> BTreeSet<String> {
        match self {
            Self::Findings { findings, .. } => {
                findings.iter().map(|finding| finding.finding_id.clone()).collect()
            }
            Self::Preprocess { .. } | Self::Report { .. } => BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunProcessorRequest {
    pub schema: String,
    pub processor_id: String,
    pub phase: RunPhase,
    pub input: RunProcessorInput,
}

impl RunProcessorRequest {
    /// Build a typed request after validating its contract and phase input.
    ///
    /// # Errors
    ///
    /// Returns an error when the contract or input is invalid or their phases do not match.
    pub fn new(
        contract: &RunProcessorContract,
        input: RunProcessorInput,
    ) -> ValidationResult<Self> {
        contract.validate()?;
        input.validate()?;
        if input.phase() != contract.phase {
            return invalid("processor input phase does not match its contract");
        }
        Ok(Self {
            schema: PROCESSOR_REQUEST_SCHEMA_V1.to_string(),
            processor_id: contract.id.clone(),
            phase: contract.phase,
            input,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum RunProposal {
    Passthrough,
    Preprocess(PreprocessProposal),
    Findings(Vec<FindingProposal>),
    Report(BTreeMap<String, String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunProcessorResponse {
    pub schema: String,
    pub processor_id: String,
    pub phase: RunPhase,
    pub proposal: RunProposal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
}

impl RunProcessorResponse {
    /// Validate one response against its registered contract, exact input, and optional authority.
    ///
    /// # Errors
    ///
    /// Returns an error for a schema, identity, phase, proposal, source, or authority mismatch.
    pub fn validate(
        &mut self,
        contract: &RunProcessorContract,
        input: &RunProcessorInput,
        authority: Option<&RunAuthority>,
    ) -> ValidationResult<Option<AcceptedPreprocess>> {
        contract.validate()?;
        input.validate()?;
        if self.schema != PROCESSOR_RESPONSE_SCHEMA_V1 {
            return invalid("unsupported run processor response schema");
        }
        if self.processor_id != contract.id {
            return invalid("processor response identity or phase does not match its contract");
        }
        if self.phase != contract.phase {
            return invalid("processor response identity or phase does not match its contract");
        }
        if input.phase() != contract.phase {
            return invalid("processor response does not match its input phase");
        }
        if let Some(diagnostic) = &mut self.diagnostic {
            validate_text("processor diagnostic", diagnostic)?;
            *diagnostic = redact_text(diagnostic);
        }
        match (&mut self.proposal, contract.phase) {
            (RunProposal::Passthrough, _) => Ok(None),
            (RunProposal::Preprocess(proposal), RunPhase::Preprocessing) => {
                if !proposal.capabilities.is_subset(&contract.capabilities) {
                    return invalid(
                        "preprocessing proposal exceeds the processor's declared capabilities",
                    );
                }
                let accepted = authority
                    .ok_or_else(|| {
                        RunPipelineValidationError("preprocessing authority is missing".into())
                    })
                    .and_then(|authority| authority.clamp(proposal))
                    .map(Some)?;
                proposal.target = None;
                Ok(accepted)
            }
            (RunProposal::Findings(proposals), RunPhase::Enrichment) => {
                if proposals.len() > MAX_RUN_PROPOSALS {
                    return invalid(format!("finding proposal count exceeds {MAX_RUN_PROPOSALS}"));
                }
                let source_ids = input.source_finding_ids();
                validate_finding_proposals(proposals, &source_ids)?;
                Ok(None)
            }
            (RunProposal::Report(annotations), RunPhase::Reporting) => {
                if annotations.len() > MAX_RUN_ANNOTATIONS {
                    return invalid(format!("report annotations exceed {MAX_RUN_ANNOTATIONS}"));
                }
                for (name, value) in annotations {
                    validate_identifier("report annotation name", name)?;
                    validate_text("report annotation value", value)?;
                    *value = redact_text(value);
                }
                Ok(None)
            }
            _ => invalid("processor proposal kind does not match its phase"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessorDisposition {
    Applied,
    NoChange,
    Rejected,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunProcessorOutcome {
    pub schema: String,
    pub processor_id: String,
    pub phase: RunPhase,
    pub disposition: ProcessorDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<RunProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
}

impl RunProcessorOutcome {
    #[must_use]
    pub fn success(response: RunProcessorResponse) -> Self {
        let disposition = if matches!(response.proposal, RunProposal::Passthrough) {
            ProcessorDisposition::NoChange
        } else {
            ProcessorDisposition::Applied
        };
        Self {
            schema: PROCESSOR_OUTCOME_SCHEMA_V1.to_string(),
            processor_id: response.processor_id,
            phase: response.phase,
            disposition,
            proposal: (!matches!(response.proposal, RunProposal::Passthrough))
                .then_some(response.proposal),
            diagnostic: response.diagnostic,
        }
    }

    #[must_use]
    pub fn degraded(contract: &RunProcessorContract, diagnostic: impl AsRef<str>) -> Self {
        Self {
            schema: PROCESSOR_OUTCOME_SCHEMA_V1.to_string(),
            processor_id: contract.id.clone(),
            phase: contract.phase,
            disposition: ProcessorDisposition::Degraded,
            proposal: None,
            diagnostic: Some(redact_text(diagnostic.as_ref())),
        }
    }

    /// Record a validated proposal rejection without retaining processor output bytes.
    #[must_use]
    pub fn rejected(contract: &RunProcessorContract, diagnostic: impl AsRef<str>) -> Self {
        Self {
            schema: PROCESSOR_OUTCOME_SCHEMA_V1.to_string(),
            processor_id: contract.id.clone(),
            phase: contract.phase,
            disposition: ProcessorDisposition::Rejected,
            proposal: None,
            diagnostic: Some(redact_text(diagnostic.as_ref())),
        }
    }

    /// Revalidate and redact an outcome at a public or durable boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when the outcome is malformed, unbounded, or inconsistent.
    pub fn normalized(mut self) -> ValidationResult<Self> {
        if self.schema != PROCESSOR_OUTCOME_SCHEMA_V1 {
            return invalid("unsupported run processor outcome schema");
        }
        validate_identifier("processor id", &self.processor_id)?;
        if let Some(diagnostic) = &mut self.diagnostic {
            validate_text("processor diagnostic", diagnostic)?;
            *diagnostic = redact_text(diagnostic);
        }
        if let Some(proposal) = &mut self.proposal {
            match proposal {
                RunProposal::Passthrough => {
                    return invalid("passthrough outcomes must omit their proposal")
                }
                RunProposal::Preprocess(proposal) => {
                    if self.phase != RunPhase::Preprocessing
                        || proposal.schema != PREPROCESS_PROPOSAL_SCHEMA_V1
                        || proposal.modules.len() > MAX_RUN_MODULES
                        || proposal.capabilities.len() > 16
                        || proposal.target.is_some()
                        || (proposal.credential_use
                            && !proposal.capabilities.contains(&Capability::CredentialUse))
                    {
                        return invalid("invalid preprocessing outcome proposal");
                    }
                    let mut modules = BTreeSet::new();
                    for module in &proposal.modules {
                        validate_identifier("module id", module)?;
                        if !modules.insert(module) {
                            return invalid("preprocessing outcome modules must be unique");
                        }
                    }
                }
                RunProposal::Findings(proposals) => {
                    if self.phase != RunPhase::Enrichment || proposals.len() > MAX_RUN_PROPOSALS {
                        return invalid("invalid finding outcome proposal");
                    }
                    let source_ids: BTreeSet<_> = proposals
                        .iter()
                        .flat_map(|proposal| {
                            std::iter::once(proposal.source_finding_id.clone())
                                .chain(proposal.related_finding_ids.iter().cloned())
                        })
                        .collect();
                    validate_finding_proposals(proposals, &source_ids)?;
                }
                RunProposal::Report(annotations) => {
                    if self.phase != RunPhase::Reporting || annotations.len() > MAX_RUN_ANNOTATIONS
                    {
                        return invalid("invalid report outcome proposal");
                    }
                    for (name, value) in annotations {
                        validate_identifier("report annotation name", name)?;
                        validate_text("report annotation value", value)?;
                        *value = redact_text(value);
                    }
                }
            }
        }
        if self.disposition == ProcessorDisposition::NoChange && self.proposal.is_some() {
            return invalid("no-change outcome must not contain a proposal");
        }
        if self.disposition == ProcessorDisposition::Applied && self.proposal.is_none() {
            return invalid("applied outcome must contain a proposal");
        }
        if matches!(
            self.disposition,
            ProcessorDisposition::Rejected | ProcessorDisposition::Degraded
        ) && self.proposal.is_some()
        {
            return invalid("rejected or degraded outcome must not contain a proposal");
        }
        Ok(self)
    }
}

/// Revalidate a bounded collection of outcomes at a public or durable boundary.
///
/// # Errors
///
/// Returns an error when the collection is too large or any outcome is invalid.
pub fn normalize_run_outcomes(
    outcomes: Vec<RunProcessorOutcome>,
) -> ValidationResult<Vec<RunProcessorOutcome>> {
    if outcomes.len() > MAX_RUN_OUTCOMES {
        return invalid(format!("run processor outcomes exceed {MAX_RUN_OUTCOMES}"));
    }
    outcomes.into_iter().map(RunProcessorOutcome::normalized).collect()
}

fn validate_identifier(label: &str, value: &str) -> ValidationResult<()> {
    if value.is_empty()
        || value.len() > MAX_RUN_PROCESSOR_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return invalid(format!(
            "{label} must be 1-{MAX_RUN_PROCESSOR_ID_BYTES} ASCII letters, digits, '-', '_', or '.'"
        ));
    }
    Ok(())
}

fn validate_finding_proposals(
    proposals: &mut [FindingProposal],
    source_ids: &BTreeSet<String>,
) -> ValidationResult<()> {
    let mut keys = BTreeSet::new();
    let mut terminal_sources = BTreeSet::new();
    for proposal in proposals {
        proposal.validate(source_ids)?;
        let key = (proposal.source_finding_id.clone(), proposal.kind);
        if !keys.insert(key) {
            return invalid("finding proposals must have unique source/kind pairs");
        }
        if matches!(
            proposal.kind,
            FindingProposalKind::Retain
                | FindingProposalKind::Filter
                | FindingProposalKind::Duplicate
        ) && !terminal_sources.insert(proposal.source_finding_id.clone())
        {
            return invalid("finding proposals conflict on a terminal source disposition");
        }
    }
    Ok(())
}

fn validate_policy_target(target: &PolicyTarget) -> ValidationResult<()> {
    match target {
        PolicyTarget::Web(url) => {
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return invalid("web policy target must be a host-bearing HTTP(S) URL");
            }
            if !url.username().is_empty() || url.password().is_some() {
                return invalid("web policy target must not contain embedded credentials");
            }
            validate_text("web policy target", url.as_str())
        }
        PolicyTarget::Network(value) => validate_text("network policy target", value),
        PolicyTarget::Cloud(value) => validate_text("cloud policy target", value),
        PolicyTarget::Code(path) => {
            validate_text("code policy target", &path.as_os_str().to_string_lossy())
        }
    }
}

fn validate_identity(label: &str, value: &str) -> ValidationResult<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return invalid(format!("{label} must be a 64-character hexadecimal digest"));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str) -> ValidationResult<()> {
    if value.is_empty() || value.len() > MAX_RUN_TEXT_BYTES || value.contains('\0') {
        return invalid(format!("{label} must be 1-{MAX_RUN_TEXT_BYTES} bytes without NUL"));
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> ValidationResult<T> {
    Err(RunPipelineValidationError(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_capabilities() -> BTreeSet<Capability> {
        [
            Capability::DastScan,
            Capability::CodeScan,
            Capability::InfraScan,
            Capability::CloudScan,
            Capability::ExternalTool,
            Capability::ExtensionExecute,
            Capability::CredentialUse,
            Capability::Exploit,
            Capability::LocalState,
            Capability::ProviderRefresh,
            Capability::WebhookDelivery,
        ]
        .into()
    }

    fn module_ids(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("module-{index:04}")).collect()
    }

    fn finding_id(index: usize) -> String {
        format!("{index:064x}")
    }

    fn finding_snapshots(count: usize) -> Vec<FindingSnapshot> {
        (0..count)
            .map(|index| FindingSnapshot {
                finding_id: finding_id(index),
                module_id: "headers".into(),
                severity: Severity::Low,
                title: "title".into(),
                affected_target: "https://example.test".into(),
            })
            .collect()
    }

    fn finding_proposals(count: usize) -> Vec<FindingProposal> {
        (0..count)
            .map(|index| FindingProposal {
                source_finding_id: finding_id(index),
                kind: FindingProposalKind::Retain,
                related_finding_ids: Vec::new(),
                annotations: BTreeMap::new(),
            })
            .collect()
    }

    fn annotations(count: usize) -> BTreeMap<String, String> {
        (0..count).map(|index| (format!("key-{index}"), "value".into())).collect()
    }

    fn report_input(total_findings: usize) -> RunProcessorInput {
        RunProcessorInput::Report {
            scan_id: "scan-one".into(),
            target: authority().target,
            total_findings,
            severity_counts: [
                ("critical".into(), 0),
                ("high".into(), 0),
                ("medium".into(), 0),
                ("low".into(), total_findings),
                ("info".into(), 0),
            ]
            .into(),
        }
    }

    fn applied_outcome(phase: RunPhase, proposal: RunProposal) -> RunProcessorOutcome {
        RunProcessorOutcome {
            schema: PROCESSOR_OUTCOME_SCHEMA_V1.into(),
            processor_id: "processor.one".into(),
            phase,
            disposition: ProcessorDisposition::Applied,
            proposal: Some(proposal),
            diagnostic: None,
        }
    }

    fn contract(phase: RunPhase) -> RunProcessorContract {
        RunProcessorContract {
            schema: PROCESSOR_CONTRACT_SCHEMA_V1.into(),
            id: "processor.one".into(),
            phase,
            input_schema: phase.input_schema().into(),
            output_schema: phase.output_schema().into(),
            capabilities: [Capability::DastScan].into(),
            failure_mode: ProcessorFailureMode::Required,
            order: 10,
            budget: ProcessorBudget {
                timeout_millis: 1_000,
                max_input_bytes: 4_096,
                max_output_bytes: 4_096,
            },
        }
    }

    fn authority() -> RunAuthority {
        RunAuthority {
            target: PolicyTarget::web("https://example.test").unwrap(),
            modules: ["headers".to_string(), "tls".to_string()].into(),
            capabilities: [Capability::DastScan].into(),
            max_effect: EffectClass::ActiveSafe,
            credential_use: false,
        }
    }

    fn proposal() -> PreprocessProposal {
        PreprocessProposal {
            schema: PREPROCESS_PROPOSAL_SCHEMA_V1.into(),
            target: None,
            modules: vec!["headers".into()],
            capabilities: [Capability::DastScan].into(),
            effect: EffectClass::Passive,
            credential_use: false,
        }
    }

    #[test]
    fn phase_order_and_wire_names_are_stable() {
        let phases = [
            RunPhase::IntakeValidation,
            RunPhase::Preprocessing,
            RunPhase::PlanProposal,
            RunPhase::Authorization,
            RunPhase::Execution,
            RunPhase::Normalization,
            RunPhase::Enrichment,
            RunPhase::Correlation,
            RunPhase::AnalysisAttachment,
            RunPhase::Reporting,
            RunPhase::Notification,
        ];
        assert!(phases.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            serde_json::to_string(&RunPhase::AnalysisAttachment).unwrap(),
            "\"analysis_attachment\""
        );
    }

    #[test]
    fn processor_contract_pins_schema_phase_and_each_budget_boundary() {
        assert!(contract(RunPhase::Preprocessing).validate().is_ok());
        assert!(contract(RunPhase::Notification).validate().is_err());
        let mut candidate = contract(RunPhase::Enrichment);
        candidate.input_schema = PREPROCESS_INPUT_SCHEMA_V1.into();
        assert!(candidate.validate().is_err());
        for (timeout, input, output, valid) in [
            (0, 1, 1, false),
            (1, 1, 1, true),
            (MAX_RUN_TIMEOUT_MILLIS, MAX_RUN_INPUT_BYTES, MAX_RUN_OUTPUT_BYTES, true),
            (MAX_RUN_TIMEOUT_MILLIS + 1, 1, 1, false),
            (1, 0, 1, false),
            (1, MAX_RUN_INPUT_BYTES + 1, 1, false),
            (1, 1, 0, false),
            (1, 1, MAX_RUN_OUTPUT_BYTES + 1, false),
        ] {
            let budget = ProcessorBudget {
                timeout_millis: timeout,
                max_input_bytes: input,
                max_output_bytes: output,
            };
            assert_eq!(budget.validate().is_ok(), valid);
        }
    }

    #[test]
    fn preprocessing_clamp_accepts_only_equal_or_narrower_authority() {
        let authority = authority();
        let accepted = authority.clamp(&proposal()).unwrap();
        assert_eq!(accepted.modules, ["headers".to_string()].into());
        let mut changed_target = proposal();
        changed_target.target = Some(PolicyTarget::web("https://other.test").unwrap());
        assert!(authority.clamp(&changed_target).is_err());
        let mut added_module = proposal();
        added_module.modules.push("unknown".into());
        assert!(authority.clamp(&added_module).is_err());
        let mut expanded_capability = proposal();
        expanded_capability.capabilities.insert(Capability::ExternalTool);
        assert!(authority.clamp(&expanded_capability).is_err());
        let mut expanded_effect = proposal();
        expanded_effect.effect = EffectClass::Exploit;
        assert!(authority.clamp(&expanded_effect).is_err());
        let mut credentials = proposal();
        credentials.credential_use = true;
        assert!(authority.clamp(&credentials).is_err());

        let mut credentialed_target = authority;
        credentialed_target.target =
            PolicyTarget::Web(url::Url::parse("https://user:secret@example.test").unwrap());
        assert!(credentialed_target.validate().is_err());
    }

    #[test]
    fn finding_proposals_require_known_sources_and_redact_annotations() {
        let digest = "a".repeat(64);
        let input = RunProcessorInput::Findings {
            module_id: "headers".into(),
            module_name: "Headers".into(),
            findings: vec![FindingSnapshot {
                finding_id: digest.clone(),
                module_id: "headers".into(),
                severity: Severity::Low,
                title: "title".into(),
                affected_target: "https://example.test".into(),
            }],
        };
        let contract = contract(RunPhase::Enrichment);
        let mut response = RunProcessorResponse {
            schema: PROCESSOR_RESPONSE_SCHEMA_V1.into(),
            processor_id: contract.id.clone(),
            phase: contract.phase,
            proposal: RunProposal::Findings(vec![FindingProposal {
                source_finding_id: digest,
                kind: FindingProposalKind::Enrich,
                related_finding_ids: Vec::new(),
                annotations: [(
                    "note".into(),
                    "authorization=Bearer secret-value-1234567890".into(),
                )]
                .into(),
            }]),
            diagnostic: None,
        };
        assert!(response.validate(&contract, &input, None).is_ok());
        let serialized = serde_json::to_string(&response).unwrap();
        assert!(serialized.contains("REDACTED"));
        assert!(!serialized.contains("secret-value-1234567890"));
    }

    #[test]
    fn response_identity_phase_and_proposal_kind_must_match() {
        let contract = contract(RunPhase::Preprocessing);
        let input = RunProcessorInput::Preprocess {
            target: authority().target,
            modules: vec!["headers".into()],
            capabilities: [Capability::DastScan].into(),
            max_effect: EffectClass::ActiveSafe,
            credential_use: false,
        };
        let mut response = RunProcessorResponse {
            schema: PROCESSOR_RESPONSE_SCHEMA_V1.into(),
            processor_id: "wrong".into(),
            phase: RunPhase::Preprocessing,
            proposal: RunProposal::Preprocess(proposal()),
            diagnostic: None,
        };
        assert!(response.validate(&contract, &input, Some(&authority())).is_err());
        response.processor_id.clone_from(&contract.id);
        response.proposal = RunProposal::Report(BTreeMap::new());
        assert!(response.validate(&contract, &input, Some(&authority())).is_err());
    }

    #[test]
    fn accepted_preprocess_outcomes_omit_the_redundant_policy_target() {
        let contract = contract(RunPhase::Preprocessing);
        let authority = authority();
        let input = RunProcessorInput::Preprocess {
            target: authority.target.clone(),
            modules: vec!["headers".into(), "tls".into()],
            capabilities: authority.capabilities.clone(),
            max_effect: authority.max_effect,
            credential_use: false,
        };
        let mut proposal = proposal();
        proposal.target = Some(authority.target.clone());
        let mut response = RunProcessorResponse {
            schema: PROCESSOR_RESPONSE_SCHEMA_V1.into(),
            processor_id: contract.id.clone(),
            phase: contract.phase,
            proposal: RunProposal::Preprocess(proposal),
            diagnostic: None,
        };

        assert!(response.validate(&contract, &input, Some(&authority)).is_ok());
        let RunProposal::Preprocess(proposal) = response.proposal else {
            panic!("expected preprocessing proposal");
        };
        assert!(proposal.target.is_none());
    }

    #[test]
    fn public_outcome_normalization_rechecks_schema_shape_and_secrets() {
        let mut outcome =
            RunProcessorOutcome::degraded(&contract(RunPhase::Reporting), "initial diagnostic");
        outcome.diagnostic = Some("authorization=Bearer outcome-secret".into());
        let normalized = outcome.normalized().unwrap();
        let diagnostic = normalized.diagnostic.unwrap();
        assert!(diagnostic.contains("REDACTED"));
        assert!(!diagnostic.contains("outcome-secret"));

        let mut invalid =
            RunProcessorOutcome::degraded(&contract(RunPhase::Reporting), "diagnostic");
        invalid.schema = "wrong".into();
        assert!(invalid.normalized().is_err());
    }

    #[test]
    fn typed_inputs_require_consistent_nested_counts_and_authority_flags() {
        let mut invalid_preprocess = RunProcessorInput::Preprocess {
            target: authority().target,
            modules: vec!["headers".into()],
            capabilities: [Capability::DastScan].into(),
            max_effect: EffectClass::Passive,
            credential_use: true,
        };
        assert!(invalid_preprocess.validate().is_err());
        if let RunProcessorInput::Preprocess { credential_use, .. } = &mut invalid_preprocess {
            *credential_use = false;
        }
        assert!(invalid_preprocess.validate().is_ok());

        let findings = RunProcessorInput::Findings {
            module_id: "headers".into(),
            module_name: "Headers".into(),
            findings: vec![FindingSnapshot {
                finding_id: "a".repeat(64),
                module_id: "tls".into(),
                severity: Severity::Low,
                title: "title".into(),
                affected_target: "https://example.test".into(),
            }],
        };
        assert!(findings.validate().is_err());

        let report = RunProcessorInput::Report {
            scan_id: "scan-one".into(),
            target: authority().target,
            total_findings: 1,
            severity_counts: [
                ("critical".into(), 0),
                ("high".into(), 0),
                ("medium".into(), 0),
                ("low".into(), 0),
                ("info".into(), 0),
            ]
            .into(),
        };
        assert!(report.validate().is_err());

        let overflowing_report = RunProcessorInput::Report {
            scan_id: "scan-one".into(),
            target: authority().target,
            total_findings: 0,
            severity_counts: [
                ("critical".into(), usize::MAX),
                ("high".into(), 1),
                ("medium".into(), 0),
                ("low".into(), 0),
                ("info".into(), 0),
            ]
            .into(),
        };
        assert!(overflowing_report.validate().is_err());
    }

    #[test]
    fn applied_public_outcome_requires_a_proposal() {
        let mut outcome =
            RunProcessorOutcome::degraded(&contract(RunPhase::Reporting), "diagnostic");
        outcome.disposition = ProcessorDisposition::Applied;
        assert!(outcome.normalized().is_err());
    }

    #[test]
    fn finding_proposal_kinds_require_their_semantic_payloads() {
        let source = "a".repeat(64);
        let related = "b".repeat(64);
        let sources = [source.clone(), related.clone()].into();
        let mut duplicate = FindingProposal {
            source_finding_id: source.clone(),
            kind: FindingProposalKind::Duplicate,
            related_finding_ids: Vec::new(),
            annotations: BTreeMap::new(),
        };
        assert!(duplicate.validate(&sources).is_err());
        duplicate.related_finding_ids.push(related);
        assert!(duplicate.validate(&sources).is_ok());

        let mut enrichment = FindingProposal {
            source_finding_id: source,
            kind: FindingProposalKind::Enrich,
            related_finding_ids: Vec::new(),
            annotations: BTreeMap::new(),
        };
        assert!(enrichment.validate(&sources).is_err());
        enrichment.annotations.insert("note".into(), "safe context".into());
        assert!(enrichment.validate(&sources).is_ok());

        let mut conflicting = vec![
            FindingProposal {
                source_finding_id: "a".repeat(64),
                kind: FindingProposalKind::Retain,
                related_finding_ids: Vec::new(),
                annotations: BTreeMap::new(),
            },
            FindingProposal {
                source_finding_id: "a".repeat(64),
                kind: FindingProposalKind::Filter,
                related_finding_ids: Vec::new(),
                annotations: BTreeMap::new(),
            },
        ];
        assert!(validate_finding_proposals(&mut conflicting, &sources).is_err());
    }

    #[test]
    fn protocol_constants_and_private_validators_pin_every_exact_boundary() {
        assert_eq!(MAX_RUN_OUTCOMES, 32_896);
        assert_eq!(MAX_RUN_INPUT_BYTES, 8_388_608);
        assert_eq!(MAX_RUN_OUTPUT_BYTES, 8_388_608);
        assert_eq!(RunPipelineValidationError("exact error".into()).to_string(), "exact error");

        assert!(validate_identifier("id", &"a".repeat(MAX_RUN_PROCESSOR_ID_BYTES)).is_ok());
        assert!(validate_identifier("id", "").is_err());
        assert!(validate_identifier("id", &"a".repeat(MAX_RUN_PROCESSOR_ID_BYTES + 1)).is_err());
        assert!(validate_identifier("id", "invalid/value").is_err());
        assert!(validate_identity("digest", &"a".repeat(64)).is_ok());
        assert!(validate_identity("digest", &"a".repeat(63)).is_err());
        assert!(validate_identity("digest", &"g".repeat(64)).is_err());
        assert!(validate_text("text", &"a".repeat(MAX_RUN_TEXT_BYTES)).is_ok());
        assert!(validate_text("text", "").is_err());
        assert!(validate_text("text", &"a".repeat(MAX_RUN_TEXT_BYTES + 1)).is_err());
        assert!(validate_text("text", "valid\0invalid").is_err());

        let wrong_scheme = PolicyTarget::Web(url::Url::parse("ftp://example.test").unwrap());
        let username = PolicyTarget::Web(url::Url::parse("https://user@example.test").unwrap());
        let password = PolicyTarget::Web(url::Url::parse("https://:secret@example.test").unwrap());
        assert!(validate_policy_target(&wrong_scheme).is_err());
        assert!(validate_policy_target(&username).is_err());
        assert!(validate_policy_target(&password).is_err());
    }

    #[test]
    fn closed_capability_ceiling_uses_the_deliberate_future_proof_bound() {
        assert_eq!(all_capabilities().len(), 11);
        let production = include_str!("run_pipeline.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        let compact: String = production.split_whitespace().collect();
        assert_eq!(compact.matches("capabilities.len()>16").count(), 4);
    }

    #[test]
    fn authority_and_clamp_counts_and_credential_predicates_are_independent() {
        let exact_modules = module_ids(MAX_RUN_MODULES);
        let mut exact_authority = authority();
        exact_authority.modules = exact_modules.iter().cloned().collect();
        assert!(exact_authority.validate().is_ok());
        let mut too_many = exact_authority.clone();
        too_many.modules.insert("module-over-limit".into());
        assert!(too_many.validate().is_err());

        let mut credential_authority = authority();
        credential_authority.capabilities.insert(Capability::CredentialUse);
        credential_authority.credential_use = true;
        assert!(credential_authority.validate().is_ok());
        credential_authority.capabilities.remove(&Capability::CredentialUse);
        assert_eq!(
            credential_authority.validate().unwrap_err().0,
            "credential_use requires the credential-use capability"
        );

        let exact_proposal = PreprocessProposal { modules: exact_modules, ..proposal() };
        assert!(exact_authority.clamp(&exact_proposal).is_ok());
        let mut oversized_proposal = exact_proposal;
        oversized_proposal.modules.push("module-over-limit".into());
        assert_eq!(
            exact_authority.clamp(&oversized_proposal).unwrap_err().0,
            format!("proposed module count exceeds {MAX_RUN_MODULES}")
        );

        let mut credential_cap_without_host_permission = authority();
        credential_cap_without_host_permission.capabilities.insert(Capability::CredentialUse);
        let mut credential_request = proposal();
        credential_request.capabilities.insert(Capability::CredentialUse);
        credential_request.credential_use = true;
        assert!(credential_cap_without_host_permission.clamp(&credential_request).is_err());

        let mut credential_host = credential_cap_without_host_permission;
        credential_host.credential_use = true;
        let mut missing_proposed_capability = credential_request;
        missing_proposed_capability.capabilities.remove(&Capability::CredentialUse);
        assert!(credential_host.clamp(&missing_proposed_capability).is_err());
    }

    #[test]
    fn finding_proposal_bounds_and_kind_shapes_are_exact() {
        let source = finding_id(0);
        let related: Vec<_> = (1..=MAX_RUN_PROPOSALS).map(finding_id).collect();
        let sources: BTreeSet<_> =
            std::iter::once(source.clone()).chain(related.iter().cloned()).collect();
        let mut correlation = FindingProposal {
            source_finding_id: source.clone(),
            kind: FindingProposalKind::Correlate,
            related_finding_ids: related,
            annotations: BTreeMap::new(),
        };
        assert!(correlation.validate(&sources).is_ok());
        correlation.related_finding_ids.push(finding_id(MAX_RUN_PROPOSALS + 1));
        assert_eq!(
            correlation.validate(&sources).unwrap_err().0,
            "finding proposal has too many related identities"
        );

        let mut enrichment = FindingProposal {
            source_finding_id: source.clone(),
            kind: FindingProposalKind::Enrich,
            related_finding_ids: Vec::new(),
            annotations: annotations(MAX_RUN_ANNOTATIONS),
        };
        assert!(enrichment.validate(&[source.clone()].into()).is_ok());
        enrichment.annotations.insert("over-limit".into(), "value".into());
        assert!(enrichment.validate(&[source.clone()].into()).is_err());

        for (kind, related_finding_ids, annotations) in [
            (FindingProposalKind::Retain, vec![finding_id(1)], BTreeMap::new()),
            (FindingProposalKind::Filter, Vec::new(), annotations(1)),
            (FindingProposalKind::Duplicate, vec![finding_id(1)], annotations(1)),
            (FindingProposalKind::Correlate, Vec::new(), BTreeMap::new()),
        ] {
            let mut candidate = FindingProposal {
                source_finding_id: source.clone(),
                kind,
                related_finding_ids,
                annotations,
            };
            assert!(candidate.validate(&[source.clone(), finding_id(1)].into()).is_err());
        }
        let mut valid_correlation = FindingProposal {
            source_finding_id: source.clone(),
            kind: FindingProposalKind::Correlate,
            related_finding_ids: vec![finding_id(1)],
            annotations: BTreeMap::new(),
        };
        assert!(valid_correlation.validate(&[source, finding_id(1)].into()).is_ok());
    }

    #[test]
    fn typed_input_collection_boundaries_accept_exact_and_reject_one_over() {
        let exact_modules = RunProcessorInput::Preprocess {
            target: authority().target,
            modules: module_ids(MAX_RUN_MODULES),
            capabilities: all_capabilities(),
            max_effect: EffectClass::Passive,
            credential_use: false,
        };
        assert!(exact_modules.validate().is_ok());
        let mut too_many_modules = exact_modules;
        let RunProcessorInput::Preprocess { modules, .. } = &mut too_many_modules else {
            unreachable!()
        };
        modules.push("module-over-limit".into());
        assert!(too_many_modules.validate().is_err());

        let exact_findings = RunProcessorInput::Findings {
            module_id: "headers".into(),
            module_name: "Headers".into(),
            findings: finding_snapshots(MAX_RUN_FINDINGS),
        };
        assert!(exact_findings.validate().is_ok());
        let mut too_many_findings = exact_findings;
        let RunProcessorInput::Findings { findings, .. } = &mut too_many_findings else {
            unreachable!()
        };
        findings.push(finding_snapshots(1).remove(0));
        assert!(too_many_findings.validate().is_err());

        assert!(report_input(MAX_RUN_FINDINGS).validate().is_ok());
        assert!(report_input(MAX_RUN_FINDINGS + 1).validate().is_err());
    }

    #[test]
    fn response_passthrough_and_collection_boundaries_are_exact() {
        let preprocess_contract = contract(RunPhase::Preprocessing);
        let preprocess_input = RunProcessorInput::Preprocess {
            target: authority().target,
            modules: vec!["headers".into()],
            capabilities: [Capability::DastScan].into(),
            max_effect: EffectClass::Passive,
            credential_use: false,
        };
        let mut passthrough = RunProcessorResponse {
            schema: PROCESSOR_RESPONSE_SCHEMA_V1.into(),
            processor_id: preprocess_contract.id.clone(),
            phase: RunPhase::Preprocessing,
            proposal: RunProposal::Passthrough,
            diagnostic: None,
        };
        assert_eq!(passthrough.validate(&preprocess_contract, &preprocess_input, None), Ok(None));

        let finding_contract = contract(RunPhase::Enrichment);
        let finding_input = RunProcessorInput::Findings {
            module_id: "headers".into(),
            module_name: "Headers".into(),
            findings: finding_snapshots(MAX_RUN_FINDINGS),
        };
        let mut exact_findings = RunProcessorResponse {
            schema: PROCESSOR_RESPONSE_SCHEMA_V1.into(),
            processor_id: finding_contract.id.clone(),
            phase: RunPhase::Enrichment,
            proposal: RunProposal::Findings(finding_proposals(MAX_RUN_PROPOSALS)),
            diagnostic: None,
        };
        assert_eq!(exact_findings.validate(&finding_contract, &finding_input, None), Ok(None));
        let RunProposal::Findings(proposals) = &mut exact_findings.proposal else { unreachable!() };
        proposals.push(finding_proposals(1).remove(0));
        assert_eq!(
            exact_findings.validate(&finding_contract, &finding_input, None).unwrap_err().0,
            format!("finding proposal count exceeds {MAX_RUN_PROPOSALS}")
        );

        let report_contract = contract(RunPhase::Reporting);
        let report_input = report_input(0);
        let mut exact_report = RunProcessorResponse {
            schema: PROCESSOR_RESPONSE_SCHEMA_V1.into(),
            processor_id: report_contract.id.clone(),
            phase: RunPhase::Reporting,
            proposal: RunProposal::Report(annotations(MAX_RUN_ANNOTATIONS)),
            diagnostic: None,
        };
        assert_eq!(exact_report.validate(&report_contract, &report_input, None), Ok(None));
        let RunProposal::Report(annotations) = &mut exact_report.proposal else { unreachable!() };
        annotations.insert("over-limit".into(), "value".into());
        assert!(exact_report.validate(&report_contract, &report_input, None).is_err());
    }

    #[test]
    fn preprocessing_outcome_rejects_each_invalid_field_independently() {
        let base = applied_outcome(RunPhase::Preprocessing, RunProposal::Preprocess(proposal()));
        assert!(base.clone().normalized().is_ok());

        let mut wrong_phase = base.clone();
        wrong_phase.phase = RunPhase::Reporting;
        assert!(wrong_phase.normalized().is_err());
        let mut wrong_schema = base.clone();
        let Some(RunProposal::Preprocess(proposal)) = &mut wrong_schema.proposal else {
            unreachable!()
        };
        proposal.schema = "wrong".into();
        assert!(wrong_schema.normalized().is_err());
        let mut exact_modules = base.clone();
        let Some(RunProposal::Preprocess(proposal)) = &mut exact_modules.proposal else {
            unreachable!()
        };
        proposal.modules = module_ids(MAX_RUN_MODULES);
        assert!(exact_modules.clone().normalized().is_ok());
        let Some(RunProposal::Preprocess(proposal)) = &mut exact_modules.proposal else {
            unreachable!()
        };
        proposal.modules.push("module-over-limit".into());
        assert!(exact_modules.normalized().is_err());

        let mut exact_capabilities = base.clone();
        let Some(RunProposal::Preprocess(proposal)) = &mut exact_capabilities.proposal else {
            unreachable!()
        };
        proposal.capabilities = all_capabilities();
        assert!(exact_capabilities.normalized().is_ok());
        let mut target = base.clone();
        let Some(RunProposal::Preprocess(proposal)) = &mut target.proposal else { unreachable!() };
        proposal.target = Some(authority().target);
        assert!(target.normalized().is_err());
        let mut credentials = base;
        let Some(RunProposal::Preprocess(proposal)) = &mut credentials.proposal else {
            unreachable!()
        };
        proposal.credential_use = true;
        assert!(credentials.normalized().is_err());
    }

    #[test]
    fn finding_report_and_disposition_outcomes_pin_each_consistency_rule() {
        let exact_findings = applied_outcome(
            RunPhase::Enrichment,
            RunProposal::Findings(finding_proposals(MAX_RUN_PROPOSALS)),
        );
        assert!(exact_findings.clone().normalized().is_ok());
        let mut too_many_findings = exact_findings.clone();
        let Some(RunProposal::Findings(proposals)) = &mut too_many_findings.proposal else {
            unreachable!()
        };
        proposals.push(FindingProposal {
            source_finding_id: finding_id(MAX_RUN_PROPOSALS),
            kind: FindingProposalKind::Retain,
            related_finding_ids: Vec::new(),
            annotations: BTreeMap::new(),
        });
        assert!(too_many_findings.normalized().is_err());
        let mut wrong_finding_phase = exact_findings;
        wrong_finding_phase.phase = RunPhase::Reporting;
        assert!(wrong_finding_phase.normalized().is_err());

        let exact_report = applied_outcome(
            RunPhase::Reporting,
            RunProposal::Report(annotations(MAX_RUN_ANNOTATIONS)),
        );
        assert!(exact_report.clone().normalized().is_ok());
        let mut too_many_annotations = exact_report.clone();
        let Some(RunProposal::Report(annotations)) = &mut too_many_annotations.proposal else {
            unreachable!()
        };
        annotations.insert("over-limit".into(), "value".into());
        assert!(too_many_annotations.normalized().is_err());
        let mut wrong_report_phase = exact_report.clone();
        wrong_report_phase.phase = RunPhase::Enrichment;
        assert!(wrong_report_phase.normalized().is_err());

        let mut no_change = exact_report.clone();
        no_change.disposition = ProcessorDisposition::NoChange;
        assert!(no_change.normalized().is_err());
        for disposition in [ProcessorDisposition::Rejected, ProcessorDisposition::Degraded] {
            let mut failed = exact_report.clone();
            failed.disposition = disposition;
            assert!(failed.normalized().is_err());
        }
        let mut applied_without_proposal = exact_report;
        applied_without_proposal.proposal = None;
        assert!(applied_without_proposal.normalized().is_err());
    }

    #[test]
    fn public_outcome_collection_accepts_exact_maximum_and_rejects_one_over() {
        let outcome = RunProcessorOutcome::success(RunProcessorResponse {
            schema: PROCESSOR_RESPONSE_SCHEMA_V1.into(),
            processor_id: "processor.one".into(),
            phase: RunPhase::Reporting,
            proposal: RunProposal::Passthrough,
            diagnostic: None,
        });
        let exact = vec![outcome.clone(); MAX_RUN_OUTCOMES];
        assert_eq!(normalize_run_outcomes(exact).unwrap().len(), MAX_RUN_OUTCOMES);
        assert!(normalize_run_outcomes(vec![outcome; MAX_RUN_OUTCOMES + 1]).is_err());
    }
}
