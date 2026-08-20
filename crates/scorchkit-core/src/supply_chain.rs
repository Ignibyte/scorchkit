//! Agent-neutral application supply-chain evidence and coverage contracts.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::severity::Severity;

/// Versioned schema identifier for supply-chain assessment records.
pub const SUPPLY_CHAIN_ASSESSMENT_SCHEMA_V1: &str = "scorchkit.supply-chain-assessment.v1";

/// Explicit local target kinds accepted by the application supply-chain service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplyChainTargetKind {
    SourceDirectory,
    DirectoryArtifact,
    FileArtifact,
    OciArchive,
    OciLayout,
    CycloneDxSbom,
}

/// Canonical identity of the local target assessed by supply-chain tooling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyChainTarget {
    pub kind: SupplyChainTargetKind,
    pub canonical_path: PathBuf,
    /// Caller-supplied revision when known (for example, a Git commit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// Digest of the target artifact or deterministic inventory input when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// Which application dependency question a tool observation answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyEvidenceKind {
    DeclaredSourceDependency,
    BuiltArtifactComponent,
}

/// Overall integrity of an application supply-chain assessment.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplyChainCoverageStatus {
    #[default]
    Complete,
    /// An applicable prerequisite was absent or unusable before its phase could run.
    Incomplete,
    /// A phase started but its execution or evidence validation failed.
    Degraded,
}

impl SupplyChainCoverageStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Degraded => "degraded",
        }
    }
}

/// Stable pipeline phase names used by coverage gaps and public projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplyChainPhase {
    TargetAuthorization,
    SourceDiscovery,
    SourceDependencyScan,
    SbomProduction,
    SbomValidation,
    ArtifactVulnerabilityScan,
    Correlation,
    ProviderRefresh,
}

impl SupplyChainPhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetAuthorization => "target_authorization",
            Self::SourceDiscovery => "source_discovery",
            Self::SourceDependencyScan => "source_dependency_scan",
            Self::SbomProduction => "sbom_production",
            Self::SbomValidation => "sbom_validation",
            Self::ArtifactVulnerabilityScan => "artifact_vulnerability_scan",
            Self::Correlation => "correlation",
            Self::ProviderRefresh => "provider_refresh",
        }
    }
}

/// Machine-readable reason why applicable supply-chain coverage is not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplyChainGapKind {
    LocalStateUnavailable,
    MissingTool,
    IncompatibleToolVersion,
    MissingProviderSnapshot,
    StaleProviderSnapshot,
    InvalidProviderSnapshot,
    UnsupportedTarget,
    NoSupportedManifest,
    ProducerFailed,
    ConsumerFailed,
    OutputInvalid,
    OutputLimitExceeded,
    UpstreamUnavailable,
    ArtifactUnavailable,
    InvalidPackageIdentity,
}

impl SupplyChainGapKind {
    /// Stable machine identifier shared by module outcomes and public projections.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalStateUnavailable => "local_state_unavailable",
            Self::MissingTool => "missing_tool",
            Self::IncompatibleToolVersion => "incompatible_tool_version",
            Self::MissingProviderSnapshot => "missing_provider_snapshot",
            Self::StaleProviderSnapshot => "stale_provider_snapshot",
            Self::InvalidProviderSnapshot => "invalid_provider_snapshot",
            Self::UnsupportedTarget => "unsupported_target",
            Self::NoSupportedManifest => "no_supported_manifest",
            Self::ProducerFailed => "producer_failed",
            Self::ConsumerFailed => "consumer_failed",
            Self::OutputInvalid => "output_invalid",
            Self::OutputLimitExceeded => "output_limit_exceeded",
            Self::UpstreamUnavailable => "upstream_unavailable",
            Self::ArtifactUnavailable => "artifact_unavailable",
            Self::InvalidPackageIdentity => "invalid_package_identity",
        }
    }

    /// Return whether this gap means a phase attempted execution and failed.
    #[must_use]
    pub const fn is_degraded(self) -> bool {
        matches!(
            self,
            Self::ProducerFailed
                | Self::ConsumerFailed
                | Self::OutputInvalid
                | Self::OutputLimitExceeded
                | Self::ArtifactUnavailable
        )
    }
}

/// One explicit coverage gap. Human detail is redacted at every serde boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyChainCoverageGap {
    pub phase: SupplyChainPhase,
    pub kind: SupplyChainGapKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    #[serde(
        serialize_with = "serialize_redacted_detail",
        deserialize_with = "deserialize_redacted_detail"
    )]
    pub detail: String,
}

impl SupplyChainCoverageGap {
    #[must_use]
    pub fn new(
        phase: SupplyChainPhase,
        kind: SupplyChainGapKind,
        component: Option<String>,
        detail: impl AsRef<str>,
    ) -> Self {
        Self { phase, kind, component, detail: crate::observation::redact_text(detail.as_ref()) }
    }
}

fn serialize_redacted_detail<S>(detail: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&crate::observation::redact_text(detail))
}

fn deserialize_redacted_detail<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(|detail| crate::observation::redact_text(&detail))
}

/// Health of an immutable local provider snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSnapshotState {
    Ready,
    Missing,
    Stale,
    Invalid,
}

/// Provenance and integrity metadata for one provider database snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSnapshot {
    pub provider: String,
    pub snapshot_id: String,
    pub schema_version: String,
    /// Immutable directory supplied to the external scanner as its cache root.
    pub consumer_path: PathBuf,
    /// Immutable snapshot root containing the validated provider manifest and artifacts.
    pub canonical_path: PathBuf,
    pub state: ProviderSnapshotState,
    pub expected_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computed_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_built_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<DateTime<Utc>>,
    pub maximum_age_seconds: u64,
    /// Redacted integrity diagnostic when `state` is `Invalid`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_redacted_detail",
        deserialize_with = "deserialize_optional_redacted_detail"
    )]
    pub validation_error: Option<String>,
}

// JUSTIFICATION: Serde's field serializer contract passes `&Option<String>`; accepting
// `Option<&String>` would make the function incompatible with `serialize_with`.
#[allow(clippy::ref_option)]
fn serialize_optional_redacted_detail<S>(
    detail: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    detail.as_deref().map(crate::observation::redact_text).serialize(serializer)
}

fn deserialize_optional_redacted_detail<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
        .map(|detail| detail.map(|value| crate::observation::redact_text(&value)))
}

/// Provenance for the exact `CycloneDX` document shared with all consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomArtifact {
    pub canonical_path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
    pub format: String,
    pub specification_version: String,
    pub producer: String,
    pub producer_version: String,
    pub produced_at: DateTime<Utc>,
}

/// Typed identity for a source dependency or built-artifact component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIdentity {
    pub evidence_kind: DependencyEvidenceKind,
    pub package_type: String,
    pub name: String,
    pub installed_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
    /// Canonical supplied PURL. `ScorchKit` never fabricates this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// Original invalid PURL retained as an explicit identity/coverage defect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct: Option<bool>,
}

/// Advisory identifier with the provider's primary ID and all known aliases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryIdentity {
    pub primary_id: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub aliases: BTreeSet<String>,
}

impl AdvisoryIdentity {
    /// Return primary ID and aliases in normalized, deterministic form.
    #[must_use]
    pub fn normalized_ids(&self) -> BTreeSet<String> {
        let mut ids = self
            .aliases
            .iter()
            .map(|identifier| identifier.trim().to_ascii_uppercase())
            .collect::<BTreeSet<_>>();
        ids.insert(self.primary_id.trim().to_ascii_uppercase());
        ids.retain(|identifier| !identifier.is_empty());
        ids
    }
}

/// One tool-specific vulnerability observation. Raw evidence remains a separate retained artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyChainObservation {
    pub tool: String,
    pub tool_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_snapshot_id: Option<String>,
    pub target_revision: String,
    pub package: PackageIdentity,
    pub advisory: AdvisoryIdentity,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_source: Option<String>,
    pub raw_evidence_sha256: String,
    pub raw_evidence_path: PathBuf,
}

/// A correlation cluster referencing tool observations without replacing them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyChainCorrelation {
    pub target_revision: String,
    pub purl: String,
    pub advisory_ids: BTreeSet<String>,
    pub observation_indexes: Vec<usize>,
}

/// Canonical supply-chain result shared by every application-facing projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyChainAssessment {
    pub schema: String,
    pub target: SupplyChainTarget,
    pub coverage_status: SupplyChainCoverageStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<SupplyChainCoverageGap>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_snapshots: Vec<ProviderSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbom: Option<SbomArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<SupplyChainObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub correlations: Vec<SupplyChainCorrelation>,
}

impl SupplyChainAssessment {
    #[must_use]
    pub fn new(target: SupplyChainTarget) -> Self {
        Self {
            schema: SUPPLY_CHAIN_ASSESSMENT_SCHEMA_V1.to_string(),
            target,
            coverage_status: SupplyChainCoverageStatus::Complete,
            gaps: Vec::new(),
            provider_snapshots: Vec::new(),
            sbom: None,
            observations: Vec::new(),
            correlations: Vec::new(),
        }
    }

    /// Add a gap and recompute assessment integrity.
    pub fn record_gap(&mut self, gap: SupplyChainCoverageGap) {
        self.gaps.push(gap);
        self.refresh_coverage_status();
    }

    /// Recompute coverage from all gaps, with degraded taking precedence over incomplete.
    pub fn refresh_coverage_status(&mut self) {
        self.coverage_status = if self.gaps.iter().any(|gap| gap.kind.is_degraded()) {
            SupplyChainCoverageStatus::Degraded
        } else if self.gaps.is_empty() {
            SupplyChainCoverageStatus::Complete
        } else {
            SupplyChainCoverageStatus::Incomplete
        };
    }

    /// Rebuild deterministic cross-tool correlations from retained observations.
    pub fn correlate(&mut self) {
        self.correlations = correlate_observations(&self.observations);
    }

    /// Merge compatible evidence while retaining the first target identity as canonical.
    pub fn merge(&mut self, other: Self) {
        if self.target != other.target {
            self.record_gap(SupplyChainCoverageGap::new(
                SupplyChainPhase::Correlation,
                SupplyChainGapKind::UnsupportedTarget,
                Some("assessment_merge".to_string()),
                "refused to merge supply-chain evidence from a different target identity",
            ));
            return;
        }
        if self.sbom.is_none() {
            self.sbom = other.sbom;
        }
        self.gaps.extend(other.gaps);
        self.provider_snapshots.extend(other.provider_snapshots);
        self.observations.extend(other.observations);
        self.refresh_coverage_status();
        self.correlate();
    }
}

/// Correlate observations only when target revision, supplied PURL, and advisory identity overlap.
#[must_use]
pub fn correlate_observations(
    observations: &[SupplyChainObservation],
) -> Vec<SupplyChainCorrelation> {
    let mut clusters: Vec<SupplyChainCorrelation> = Vec::new();

    for (index, observation) in observations.iter().enumerate() {
        let Some(purl) = observation.package.purl.as_ref() else {
            continue;
        };
        let advisory_ids = observation.advisory.normalized_ids();
        if advisory_ids.is_empty() {
            continue;
        }

        let matching = clusters.iter().position(|cluster| {
            cluster.target_revision == observation.target_revision
                && cluster.purl == *purl
                && !cluster.advisory_ids.is_disjoint(&advisory_ids)
        });
        if let Some(cluster_index) = matching {
            let cluster = &mut clusters[cluster_index];
            cluster.advisory_ids.extend(advisory_ids);
            cluster.observation_indexes.push(index);
        } else {
            clusters.push(SupplyChainCorrelation {
                target_revision: observation.target_revision.clone(),
                purl: purl.clone(),
                advisory_ids,
                observation_indexes: vec![index],
            });
        }
    }

    // Fold clusters that became transitively connected after aliases were merged.
    let mut cursor = 0;
    while cursor < clusters.len() {
        let mut candidate = cursor + 1;
        while candidate < clusters.len() {
            let same_identity = clusters[cursor].target_revision
                == clusters[candidate].target_revision
                && clusters[cursor].purl == clusters[candidate].purl
                && !clusters[cursor].advisory_ids.is_disjoint(&clusters[candidate].advisory_ids);
            if same_identity {
                let removed = clusters.remove(candidate);
                clusters[cursor].advisory_ids.extend(removed.advisory_ids);
                clusters[cursor].observation_indexes.extend(removed.observation_indexes);
                clusters[cursor].observation_indexes.sort_unstable();
                clusters[cursor].observation_indexes.dedup();
            } else {
                candidate += 1;
            }
        }
        cursor += 1;
    }

    clusters.sort_by(|left, right| {
        (&left.target_revision, &left.purl, &left.advisory_ids).cmp(&(
            &right.target_revision,
            &right.purl,
            &right.advisory_ids,
        ))
    });
    clusters
}

/// Count retained observations by tool without changing their canonical ordering.
#[must_use]
pub fn observation_counts_by_tool(
    observations: &[SupplyChainObservation],
) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for observation in observations {
        *counts.entry(observation.tool.clone()).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(
        tool: &str,
        revision: &str,
        purl: Option<&str>,
        ids: &[&str],
    ) -> SupplyChainObservation {
        let primary_id = ids.first().copied().unwrap_or("CVE-UNKNOWN").to_string();
        SupplyChainObservation {
            tool: tool.to_string(),
            tool_version: "fixture".to_string(),
            provider_snapshot_id: Some("snapshot".to_string()),
            target_revision: revision.to_string(),
            package: PackageIdentity {
                evidence_kind: DependencyEvidenceKind::BuiltArtifactComponent,
                package_type: "npm".to_string(),
                name: "fixture".to_string(),
                installed_version: "1.0.0".to_string(),
                fixed_version: None,
                purl: purl.map(str::to_string),
                invalid_purl: None,
                source_location: None,
                direct: None,
            },
            advisory: AdvisoryIdentity {
                primary_id,
                aliases: ids.iter().skip(1).map(|id| (*id).to_string()).collect(),
            },
            severity: Severity::High,
            data_source: None,
            raw_evidence_sha256: "00".repeat(32),
            raw_evidence_path: PathBuf::from("fixture.json"),
        }
    }

    #[test]
    fn assessment_merge_refuses_a_different_target_identity() {
        let mut first = SupplyChainAssessment::new(SupplyChainTarget {
            kind: SupplyChainTargetKind::SourceDirectory,
            canonical_path: PathBuf::from("/fixture"),
            revision: Some("revision-a".to_string()),
            sha256: None,
        });
        let mut second = SupplyChainAssessment::new(SupplyChainTarget {
            kind: SupplyChainTargetKind::SourceDirectory,
            canonical_path: PathBuf::from("/fixture"),
            revision: Some("revision-b".to_string()),
            sha256: None,
        });
        second.observations.push(observation(
            "grype",
            "revision-b",
            Some("pkg:cargo/example@1.0.0"),
            &["CVE-2026-1"],
        ));

        first.merge(second);

        assert!(first.observations.is_empty());
        assert_eq!(first.coverage_status, SupplyChainCoverageStatus::Incomplete);
        assert_eq!(first.gaps[0].kind, SupplyChainGapKind::UnsupportedTarget);
    }

    #[test]
    fn coverage_is_incomplete_for_missing_input_and_degraded_for_failed_execution() {
        let target = SupplyChainTarget {
            kind: SupplyChainTargetKind::SourceDirectory,
            canonical_path: PathBuf::from("/fixture"),
            revision: None,
            sha256: None,
        };
        let mut assessment = SupplyChainAssessment::new(target);
        assessment.record_gap(SupplyChainCoverageGap::new(
            SupplyChainPhase::SourceDependencyScan,
            SupplyChainGapKind::MissingProviderSnapshot,
            Some("osv".to_string()),
            "cache absent",
        ));
        assert_eq!(assessment.coverage_status, SupplyChainCoverageStatus::Incomplete);

        assessment.record_gap(SupplyChainCoverageGap::new(
            SupplyChainPhase::SbomProduction,
            SupplyChainGapKind::ProducerFailed,
            Some("syft".to_string()),
            "api_key=fixture-secret",
        ));
        assert_eq!(assessment.coverage_status, SupplyChainCoverageStatus::Degraded);
        let encoded = serde_json::to_string(&assessment).expect("serialize assessment");
        assert!(!encoded.contains("fixture-secret"));
    }

    #[test]
    fn correlation_requires_revision_purl_and_overlapping_advisory_identity() {
        let observations = vec![
            observation(
                "grype",
                "revision-a",
                Some("pkg:npm/lodash@4.17.20"),
                &["GHSA-JF85-CPCP-J695", "CVE-2021-23337"],
            ),
            observation("trivy", "revision-a", Some("pkg:npm/lodash@4.17.20"), &["cve-2021-23337"]),
            observation("trivy", "revision-b", Some("pkg:npm/lodash@4.17.20"), &["CVE-2021-23337"]),
            observation("osv", "revision-a", None, &["CVE-2021-23337"]),
        ];
        let correlated = correlate_observations(&observations);
        assert_eq!(correlated.len(), 2);
        assert_eq!(correlated[0].observation_indexes, [0, 1]);
        assert_eq!(correlated[1].observation_indexes, [2]);
    }

    #[test]
    fn public_supply_chain_vocabulary_is_exhaustive_and_stable() {
        assert_eq!(SupplyChainCoverageStatus::Complete.as_str(), "complete");
        assert_eq!(SupplyChainCoverageStatus::Incomplete.as_str(), "incomplete");
        assert_eq!(SupplyChainCoverageStatus::Degraded.as_str(), "degraded");

        let phases = [
            (SupplyChainPhase::TargetAuthorization, "target_authorization"),
            (SupplyChainPhase::SourceDiscovery, "source_discovery"),
            (SupplyChainPhase::SourceDependencyScan, "source_dependency_scan"),
            (SupplyChainPhase::SbomProduction, "sbom_production"),
            (SupplyChainPhase::SbomValidation, "sbom_validation"),
            (SupplyChainPhase::ArtifactVulnerabilityScan, "artifact_vulnerability_scan"),
            (SupplyChainPhase::Correlation, "correlation"),
            (SupplyChainPhase::ProviderRefresh, "provider_refresh"),
        ];
        for (phase, expected) in phases {
            assert_eq!(phase.as_str(), expected);
        }

        let gaps = [
            (SupplyChainGapKind::LocalStateUnavailable, "local_state_unavailable"),
            (SupplyChainGapKind::MissingTool, "missing_tool"),
            (SupplyChainGapKind::IncompatibleToolVersion, "incompatible_tool_version"),
            (SupplyChainGapKind::MissingProviderSnapshot, "missing_provider_snapshot"),
            (SupplyChainGapKind::StaleProviderSnapshot, "stale_provider_snapshot"),
            (SupplyChainGapKind::InvalidProviderSnapshot, "invalid_provider_snapshot"),
            (SupplyChainGapKind::UnsupportedTarget, "unsupported_target"),
            (SupplyChainGapKind::NoSupportedManifest, "no_supported_manifest"),
            (SupplyChainGapKind::ProducerFailed, "producer_failed"),
            (SupplyChainGapKind::ConsumerFailed, "consumer_failed"),
            (SupplyChainGapKind::OutputInvalid, "output_invalid"),
            (SupplyChainGapKind::OutputLimitExceeded, "output_limit_exceeded"),
            (SupplyChainGapKind::UpstreamUnavailable, "upstream_unavailable"),
            (SupplyChainGapKind::ArtifactUnavailable, "artifact_unavailable"),
            (SupplyChainGapKind::InvalidPackageIdentity, "invalid_package_identity"),
        ];
        for (gap, expected) in gaps {
            assert_eq!(gap.as_str(), expected);
        }
    }

    #[test]
    fn advisory_ids_are_trimmed_uppercased_deduplicated_and_nonempty() {
        let advisory = AdvisoryIdentity {
            primary_id: " cve-2026-1 ".to_string(),
            aliases: ["", "  ", "GHSA-abcd", "cve-2026-1"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        };
        assert_eq!(
            advisory.normalized_ids(),
            ["CVE-2026-1", "GHSA-ABCD"].into_iter().map(str::to_string).collect()
        );
    }

    #[test]
    fn supply_chain_deserialization_redacts_required_and_optional_details() {
        let gap: SupplyChainCoverageGap = serde_json::from_value(serde_json::json!({
            "phase": "provider_refresh",
            "kind": "upstream_unavailable",
            "detail": "prefix api_key=wire-secret suffix"
        }))
        .expect("deserialize coverage gap");
        assert_eq!(
            gap.detail,
            crate::observation::redact_text("prefix api_key=wire-secret suffix")
        );

        let snapshot: ProviderSnapshot = serde_json::from_value(serde_json::json!({
            "provider": "osv",
            "snapshot_id": "fixture",
            "schema_version": "v1",
            "consumer_path": "/cache/consumer",
            "canonical_path": "/cache/snapshot",
            "state": "invalid",
            "expected_sha256": "00",
            "maximum_age_seconds": 60,
            "validation_error": "password=wire-secret"
        }))
        .expect("deserialize provider snapshot");
        assert_eq!(
            snapshot.validation_error,
            Some(crate::observation::redact_text("password=wire-secret"))
        );

        let without_error: ProviderSnapshot = serde_json::from_value(serde_json::json!({
            "provider": "osv",
            "snapshot_id": "fixture",
            "schema_version": "v1",
            "consumer_path": "/cache/consumer",
            "canonical_path": "/cache/snapshot",
            "state": "ready",
            "expected_sha256": "00",
            "maximum_age_seconds": 60
        }))
        .expect("deserialize provider snapshot without error");
        assert_eq!(without_error.validation_error, None);
    }

    #[test]
    fn correlation_folds_transitive_aliases_but_keeps_identity_boundaries() {
        let observations = vec![
            observation("grype", "rev-a", Some("pkg:npm/a@1"), &["CVE-A"]),
            observation("trivy", "rev-a", Some("pkg:npm/a@1"), &["CVE-C"]),
            observation("osv", "rev-a", Some("pkg:npm/a@1"), &["CVE-A", "CVE-C"]),
            observation("osv", "rev-b", Some("pkg:npm/a@1"), &["CVE-A"]),
            observation("osv", "rev-a", Some("pkg:npm/b@1"), &["CVE-A"]),
            observation("osv", "rev-a", Some("pkg:npm/a@1"), &["CVE-Z"]),
        ];
        let correlated = correlate_observations(&observations);
        assert_eq!(correlated.len(), 4);
        assert!(correlated.iter().any(|cluster| {
            cluster.target_revision == "rev-a"
                && cluster.purl == "pkg:npm/a@1"
                && cluster.advisory_ids
                    == ["CVE-A", "CVE-C"].into_iter().map(str::to_string).collect()
                && cluster.observation_indexes == [0, 1, 2]
        }));
        assert!(correlated.iter().any(|cluster| cluster.observation_indexes == [3]));
        assert!(correlated.iter().any(|cluster| cluster.observation_indexes == [4]));
        assert!(correlated.iter().any(|cluster| cluster.observation_indexes == [5]));
    }

    #[test]
    fn observation_counts_preserve_exact_tool_multiplicity() {
        let observations = vec![
            observation("grype", "rev", Some("pkg:npm/a@1"), &["CVE-A"]),
            observation("grype", "rev", Some("pkg:npm/b@1"), &["CVE-B"]),
            observation("trivy", "rev", Some("pkg:npm/a@1"), &["CVE-A"]),
        ];
        assert_eq!(
            observation_counts_by_tool(&observations),
            HashMap::from([("grype".to_string(), 2), ("trivy".to_string(), 1)])
        );
    }

    #[test]
    fn correlation_fold_cursor_uses_a_strict_collection_boundary() {
        let production = include_str!("supply_chain.rs").split("#[cfg(test)]").next().unwrap();
        let compact: String = production.split_whitespace().collect();
        assert!(compact.contains("whilecursor<clusters.len()"));
    }
}
