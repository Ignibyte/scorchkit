//! Agent-neutral application DAST execution, coverage, and provenance contracts.

use serde::{ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

use crate::observation::redact_text;

/// Current application DAST assessment schema.
pub const APPLICATION_DAST_ASSESSMENT_SCHEMA_V1: &str = "scorchkit.application-dast-assessment/v1";

/// Ordered ZAP phase profile selected by an application DAST request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationDastProfile {
    /// Traditional discovery and passive scanning only.
    Passive,
    /// Add strict browser-backed client discovery.
    Standard,
    /// Add the bounded active scanner.
    Active,
}

impl ApplicationDastProfile {
    /// Parse a public profile name.
    #[must_use]
    pub fn from_name(value: &str) -> Option<Self> {
        match value {
            "passive" => Some(Self::Passive),
            "standard" => Some(Self::Standard),
            "active" => Some(Self::Active),
            _ => None,
        }
    }

    /// Stable public profile name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Standard => "standard",
            Self::Active => "active",
        }
    }

    /// Whether the profile includes browser-backed discovery.
    #[must_use]
    pub const fn uses_client_spider(self) -> bool {
        matches!(self, Self::Standard | Self::Active)
    }

    /// Whether the profile includes ZAP active scanning.
    #[must_use]
    pub const fn uses_active_scan(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Supported local schema input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationDastSchemaKind {
    OpenApi,
    GraphQl,
}

/// Verified identity of one local schema used by ZAP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationDastSchemaIdentity {
    pub kind: ApplicationDastSchemaKind,
    pub sha256: String,
    pub source_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Ordered application DAST execution phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationDastPhase {
    Authentication,
    SchemaImport,
    TraditionalSpider,
    ClientSpider,
    PassiveScan,
    ActiveScan,
    UrlExport,
    AlertReport,
    AuthenticationReport,
}

impl ApplicationDastPhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::SchemaImport => "schema_import",
            Self::TraditionalSpider => "traditional_spider",
            Self::ClientSpider => "client_spider",
            Self::PassiveScan => "passive_scan",
            Self::ActiveScan => "active_scan",
            Self::UrlExport => "url_export",
            Self::AlertReport => "alert_report",
            Self::AuthenticationReport => "authentication_report",
        }
    }
}

/// Terminal state of one selected phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationDastPhaseStatus {
    Complete,
    Incomplete,
    Failed,
}

/// One ordered phase outcome for one persona.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApplicationDastPhaseOutcome {
    pub phase: ApplicationDastPhase,
    pub status: ApplicationDastPhaseStatus,
    #[serde(default, deserialize_with = "deserialize_redacted_optional")]
    pub detail: Option<String>,
}

impl Serialize for ApplicationDastPhaseOutcome {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(
            "ApplicationDastPhaseOutcome",
            if self.detail.is_some() { 3 } else { 2 },
        )?;
        state.serialize_field("phase", &self.phase)?;
        state.serialize_field("status", &self.status)?;
        if let Some(detail) = &self.detail {
            state.serialize_field("detail", &redact_text(detail))?;
        }
        state.end()
    }
}

impl ApplicationDastPhaseOutcome {
    #[must_use]
    pub const fn complete(phase: ApplicationDastPhase) -> Self {
        Self { phase, status: ApplicationDastPhaseStatus::Complete, detail: None }
    }

    #[must_use]
    pub fn incomplete(phase: ApplicationDastPhase, detail: impl AsRef<str>) -> Self {
        Self {
            phase,
            status: ApplicationDastPhaseStatus::Incomplete,
            detail: Some(redact_text(detail.as_ref())),
        }
    }

    #[must_use]
    pub fn failed(phase: ApplicationDastPhase, detail: impl AsRef<str>) -> Self {
        Self {
            phase,
            status: ApplicationDastPhaseStatus::Failed,
            detail: Some(redact_text(detail.as_ref())),
        }
    }
}

/// Authentication state proven for one persona run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationDastAuthenticationState {
    Anonymous,
    Verified,
    Failed,
    Lost,
    Unknown,
}

/// Machine-readable DAST coverage gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationDastGapKind {
    MissingTool,
    MissingSchema,
    SchemaInvalid,
    RouteUnobserved,
    AuthenticationFailed,
    AuthenticationLost,
    PlanWarning,
    ExecutionFailed,
    ArtifactMissing,
    ArtifactInvalid,
    ArtifactLimit,
}

impl ApplicationDastGapKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingTool => "missing_tool",
            Self::MissingSchema => "missing_schema",
            Self::SchemaInvalid => "schema_invalid",
            Self::RouteUnobserved => "route_unobserved",
            Self::AuthenticationFailed => "authentication_failed",
            Self::AuthenticationLost => "authentication_lost",
            Self::PlanWarning => "plan_warning",
            Self::ExecutionFailed => "execution_failed",
            Self::ArtifactMissing => "artifact_missing",
            Self::ArtifactInvalid => "artifact_invalid",
            Self::ArtifactLimit => "artifact_limit",
        }
    }

    #[must_use]
    pub const fn is_degraded(self) -> bool {
        matches!(
            self,
            Self::AuthenticationFailed
                | Self::AuthenticationLost
                | Self::ExecutionFailed
                | Self::ArtifactMissing
                | Self::ArtifactInvalid
                | Self::ArtifactLimit
        )
    }
}

/// One explicit persona/phase coverage gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationDastCoverageGap {
    pub persona: String,
    pub phase: ApplicationDastPhase,
    pub kind: ApplicationDastGapKind,
    #[serde(
        serialize_with = "serialize_redacted_string",
        deserialize_with = "deserialize_redacted_string"
    )]
    pub detail: String,
}

impl ApplicationDastCoverageGap {
    #[must_use]
    pub fn new(
        persona: impl Into<String>,
        phase: ApplicationDastPhase,
        kind: ApplicationDastGapKind,
        detail: impl AsRef<str>,
    ) -> Self {
        Self { persona: persona.into(), phase, kind, detail: redact_text(detail.as_ref()) }
    }
}

/// Expected or observed route identity for one persona.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationDastRouteCoverage {
    pub route: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_sha256: Option<String>,
    pub observed: bool,
}

/// Evidence and coverage for one isolated anonymous or named persona run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationDastPersonaAssessment {
    pub persona: String,
    pub authentication: ApplicationDastAuthenticationState,
    pub plan_sha256: String,
    pub phases: Vec<ApplicationDastPhaseOutcome>,
    pub routes: Vec<ApplicationDastRouteCoverage>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_redacted_strings",
        deserialize_with = "deserialize_redacted_strings"
    )]
    pub warnings: Vec<String>,
}

/// Overall coverage of an application DAST assessment.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationDastCoverageStatus {
    #[default]
    Complete,
    Incomplete,
    Degraded,
}

impl ApplicationDastCoverageStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Degraded => "degraded",
        }
    }
}

/// Canonical application DAST evidence attached to a scan result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationDastAssessment {
    pub schema_version: String,
    pub target: String,
    pub profile: ApplicationDastProfile,
    pub zap_version: String,
    pub schemas: Vec<ApplicationDastSchemaIdentity>,
    pub personas: Vec<ApplicationDastPersonaAssessment>,
    pub coverage_status: ApplicationDastCoverageStatus,
    pub gaps: Vec<ApplicationDastCoverageGap>,
}

impl ApplicationDastAssessment {
    #[must_use]
    pub fn new(target: impl Into<String>, profile: ApplicationDastProfile) -> Self {
        Self {
            schema_version: APPLICATION_DAST_ASSESSMENT_SCHEMA_V1.to_string(),
            target: target.into(),
            profile,
            zap_version: String::new(),
            schemas: Vec::new(),
            personas: Vec::new(),
            coverage_status: ApplicationDastCoverageStatus::Complete,
            gaps: Vec::new(),
        }
    }

    pub fn record_gap(&mut self, gap: ApplicationDastCoverageGap) {
        self.gaps.push(gap);
        self.refresh_coverage_status();
    }

    pub fn refresh_coverage_status(&mut self) {
        self.coverage_status = if self.gaps.iter().any(|gap| gap.kind.is_degraded())
            || self.personas.iter().any(|persona| {
                persona
                    .phases
                    .iter()
                    .any(|phase| phase.status == ApplicationDastPhaseStatus::Failed)
            }) {
            ApplicationDastCoverageStatus::Degraded
        } else if !self.gaps.is_empty()
            || self.personas.iter().any(|persona| {
                persona
                    .phases
                    .iter()
                    .any(|phase| phase.status == ApplicationDastPhaseStatus::Incomplete)
            })
        {
            ApplicationDastCoverageStatus::Incomplete
        } else {
            ApplicationDastCoverageStatus::Complete
        };
    }

    pub fn merge(&mut self, mut other: Self) {
        self.schemas.append(&mut other.schemas);
        self.personas.append(&mut other.personas);
        self.gaps.append(&mut other.gaps);
        self.schemas.sort_by(|left, right| left.sha256.cmp(&right.sha256));
        self.schemas.dedup_by(|left, right| left.sha256 == right.sha256);
        self.personas.sort_by(|left, right| left.persona.cmp(&right.persona));
        self.refresh_coverage_status();
    }
}

fn serialize_redacted_string<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&redact_text(value))
}

fn deserialize_redacted_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(|value| redact_text(&value))
}

fn deserialize_redacted_optional<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(|value| redact_text(&value)))
}

fn serialize_redacted_strings<S>(values: &[String], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    values.iter().map(|value| redact_text(value)).collect::<Vec<_>>().serialize(serializer)
}

fn deserialize_redacted_strings<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer)
        .map(|values| values.into_iter().map(|value| redact_text(&value)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persona_with_phase(
        persona: &str,
        phase: ApplicationDastPhaseOutcome,
    ) -> ApplicationDastPersonaAssessment {
        ApplicationDastPersonaAssessment {
            persona: persona.to_string(),
            authentication: ApplicationDastAuthenticationState::Anonymous,
            plan_sha256: format!("{persona}-plan"),
            phases: vec![phase],
            routes: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn profiles_pin_phase_selection() {
        assert!(!ApplicationDastProfile::Passive.uses_client_spider());
        assert!(!ApplicationDastProfile::Standard.uses_active_scan());
        assert!(ApplicationDastProfile::Active.uses_client_spider());
        assert!(ApplicationDastProfile::Active.uses_active_scan());
        for (name, profile) in [
            ("passive", ApplicationDastProfile::Passive),
            ("standard", ApplicationDastProfile::Standard),
            ("active", ApplicationDastProfile::Active),
        ] {
            assert_eq!(ApplicationDastProfile::from_name(name), Some(profile));
            assert_eq!(profile.as_str(), name);
        }
        assert_eq!(ApplicationDastProfile::from_name("pentest"), None);
    }

    #[test]
    fn public_phase_gap_and_coverage_names_are_exact() {
        let phases = [
            (ApplicationDastPhase::Authentication, "authentication"),
            (ApplicationDastPhase::SchemaImport, "schema_import"),
            (ApplicationDastPhase::TraditionalSpider, "traditional_spider"),
            (ApplicationDastPhase::ClientSpider, "client_spider"),
            (ApplicationDastPhase::PassiveScan, "passive_scan"),
            (ApplicationDastPhase::ActiveScan, "active_scan"),
            (ApplicationDastPhase::UrlExport, "url_export"),
            (ApplicationDastPhase::AlertReport, "alert_report"),
            (ApplicationDastPhase::AuthenticationReport, "authentication_report"),
        ];
        for (phase, name) in phases {
            assert_eq!(phase.as_str(), name);
        }

        let gaps = [
            (ApplicationDastGapKind::MissingTool, "missing_tool"),
            (ApplicationDastGapKind::MissingSchema, "missing_schema"),
            (ApplicationDastGapKind::SchemaInvalid, "schema_invalid"),
            (ApplicationDastGapKind::RouteUnobserved, "route_unobserved"),
            (ApplicationDastGapKind::AuthenticationFailed, "authentication_failed"),
            (ApplicationDastGapKind::AuthenticationLost, "authentication_lost"),
            (ApplicationDastGapKind::PlanWarning, "plan_warning"),
            (ApplicationDastGapKind::ExecutionFailed, "execution_failed"),
            (ApplicationDastGapKind::ArtifactMissing, "artifact_missing"),
            (ApplicationDastGapKind::ArtifactInvalid, "artifact_invalid"),
            (ApplicationDastGapKind::ArtifactLimit, "artifact_limit"),
        ];
        for (gap, name) in gaps {
            assert_eq!(gap.as_str(), name);
        }

        for (status, name) in [
            (ApplicationDastCoverageStatus::Complete, "complete"),
            (ApplicationDastCoverageStatus::Incomplete, "incomplete"),
            (ApplicationDastCoverageStatus::Degraded, "degraded"),
        ] {
            assert_eq!(status.as_str(), name);
        }
    }

    #[test]
    fn coverage_distinguishes_incomplete_and_degraded() {
        let mut assessment =
            ApplicationDastAssessment::new("https://example.com", ApplicationDastProfile::Passive);
        assessment.record_gap(ApplicationDastCoverageGap::new(
            "anonymous",
            ApplicationDastPhase::SchemaImport,
            ApplicationDastGapKind::RouteUnobserved,
            "one route was not observed",
        ));
        assert_eq!(assessment.coverage_status, ApplicationDastCoverageStatus::Incomplete);
        assessment.record_gap(ApplicationDastCoverageGap::new(
            "user",
            ApplicationDastPhase::Authentication,
            ApplicationDastGapKind::AuthenticationFailed,
            "password=fixture-secret",
        ));
        assert_eq!(assessment.coverage_status, ApplicationDastCoverageStatus::Degraded);
        let json = serde_json::to_string(&assessment).expect("serialize assessment");
        assert!(!json.contains("fixture-secret"));
    }

    #[test]
    fn persona_phase_statuses_drive_coverage_without_gaps() {
        let mut assessment =
            ApplicationDastAssessment::new("https://example.com", ApplicationDastProfile::Passive);
        assessment.personas.push(persona_with_phase(
            "incomplete",
            ApplicationDastPhaseOutcome::incomplete(
                ApplicationDastPhase::SchemaImport,
                "route absent",
            ),
        ));
        assessment.refresh_coverage_status();
        assert_eq!(assessment.coverage_status, ApplicationDastCoverageStatus::Incomplete);

        assessment.personas.push(persona_with_phase(
            "failed",
            ApplicationDastPhaseOutcome::failed(
                ApplicationDastPhase::Authentication,
                "session lost",
            ),
        ));
        assessment.refresh_coverage_status();
        assert_eq!(assessment.coverage_status, ApplicationDastCoverageStatus::Degraded);

        assessment.personas.clear();
        assessment.refresh_coverage_status();
        assert_eq!(assessment.coverage_status, ApplicationDastCoverageStatus::Complete);
    }

    #[test]
    fn assessment_merge_deduplicates_schemas_and_orders_personas() {
        let schema = |sha256: &str, name: &str| ApplicationDastSchemaIdentity {
            kind: ApplicationDastSchemaKind::OpenApi,
            sha256: sha256.to_string(),
            source_name: name.to_string(),
            endpoint: None,
        };
        let mut left =
            ApplicationDastAssessment::new("https://example.com", ApplicationDastProfile::Passive);
        left.schemas.push(schema("b", "left.yaml"));
        left.personas.push(persona_with_phase(
            "zeta",
            ApplicationDastPhaseOutcome::complete(ApplicationDastPhase::PassiveScan),
        ));
        let mut right =
            ApplicationDastAssessment::new("https://example.com", ApplicationDastProfile::Passive);
        right.schemas.extend([schema("b", "duplicate.yaml"), schema("a", "right.yaml")]);
        right.personas.push(persona_with_phase(
            "alpha",
            ApplicationDastPhaseOutcome::incomplete(
                ApplicationDastPhase::UrlExport,
                "missing export",
            ),
        ));

        left.merge(right);

        assert_eq!(
            left.schemas.iter().map(|schema| schema.sha256.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(
            left.personas.iter().map(|persona| persona.persona.as_str()).collect::<Vec<_>>(),
            ["alpha", "zeta"]
        );
        assert_eq!(left.coverage_status, ApplicationDastCoverageStatus::Incomplete);
    }

    #[test]
    fn deserialization_redacts_required_optional_and_vector_diagnostics() {
        let expected = redact_text("password=fixture-secret");

        let mut required = serde_json::Deserializer::from_str("\"password=fixture-secret\"");
        assert_eq!(deserialize_redacted_string(&mut required).expect("required detail"), expected);

        let mut optional = serde_json::Deserializer::from_str("\"password=fixture-secret\"");
        assert_eq!(
            deserialize_redacted_optional(&mut optional).expect("optional detail"),
            Some(expected.clone())
        );
        let mut absent = serde_json::Deserializer::from_str("null");
        assert_eq!(deserialize_redacted_optional(&mut absent).expect("absent detail"), None);

        let mut vector =
            serde_json::Deserializer::from_str("[\"password=fixture-secret\",\"safe\"]");
        assert_eq!(
            deserialize_redacted_strings(&mut vector).expect("warning details"),
            vec![expected, "safe".to_string()]
        );
    }

    #[test]
    fn phase_outcome_serialization_redacts_direct_field_values() {
        let outcome = ApplicationDastPhaseOutcome {
            phase: ApplicationDastPhase::Authentication,
            status: ApplicationDastPhaseStatus::Failed,
            detail: Some("authorization: Bearer fixture-secret".to_string()),
        };

        let json = serde_json::to_string(&outcome).expect("serialize phase outcome");
        assert!(!json.contains("fixture-secret"));
        assert!(json.contains("[REDACTED]"));
    }
}
