use std::collections::BTreeSet;
use std::path::{Component, Path};

use scorchkit_core::AdapterTargetKind;
use scorchkit_policy::EffectClass;
use serde::{Deserialize, Serialize};

use crate::{
    ExtensionBudgetsV1, ExtensionCapabilityV1, ExtensionManifestV1, MAX_EXTENSION_ID_BYTES,
    MAX_EXTENSION_TEXT_BYTES,
};

pub const EXTENSION_CATALOG_ENVELOPE_SCHEMA_V1: &str = "scorchkit.extension-catalog-envelope/v1";
pub const EXTENSION_CATALOG_PAYLOAD_SCHEMA_V1: &str = "scorchkit.extension-catalog/v1";
pub const EXTENSION_APPROVAL_SCHEMA_V1: &str = "scorchkit.extension-approval/v1";
pub const EXTENSION_LIFECYCLE_STATE_SCHEMA_V1: &str = "scorchkit.extension-lifecycle-state/v1";
pub const EXTENSION_CATALOG_SIGNATURE_DOMAIN_V1: &[u8] =
    b"scorchkit.extension-catalog-signature/v1\0";
pub const MAX_EXTENSION_CATALOG_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EXTENSION_CATALOG_PAYLOAD_BYTES: usize = 3 * 1024 * 1024;
pub const MAX_EXTENSION_CATALOG_RELEASES: usize = 256;
pub const MAX_EXTENSION_CATALOG_REVOCATIONS: usize = 512;
pub const MAX_EXTENSION_NETWORK_ENDPOINTS: usize = 64;
pub const MAX_EXTENSION_LIFECYCLE_TRANSITIONS: usize = 4096;

/// Raw-payload signed catalog envelope. The payload is decoded but never reserialized for
/// signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedExtensionCatalogV1 {
    pub schema_version: String,
    pub key_id: String,
    pub payload_sha256: String,
    pub payload_base64: String,
    pub signature_base64: String,
}

/// Signed catalog payload issued by exactly one publisher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionCatalogPayloadV1 {
    pub schema_version: String,
    pub catalog_id: String,
    pub publisher_id: String,
    pub sequence: u64,
    pub valid_from: String,
    pub valid_until: String,
    pub releases: Vec<ExtensionCatalogReleaseV1>,
    pub revocations: Vec<ExtensionCatalogRevocationV1>,
}

/// Exact release subject bound by a catalog signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionCatalogReleaseV1 {
    pub release_id: String,
    pub extension_id: String,
    pub version: String,
    /// Catalog-relative regular JSON file. Nested and absolute paths are rejected.
    pub manifest_file: String,
    pub manifest_sha256: String,
    pub module_sha256: String,
    pub permissions: ExtensionPermissionsV1,
    pub permissions_sha256: String,
    pub provenance: ExtensionReleaseProvenanceV1,
    pub conformance: ExtensionConformanceV1,
}

/// Signed, normalized upper bound on one release's requested authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionPermissionsV1 {
    pub target_kinds: Vec<AdapterTargetKind>,
    pub strongest_effect: EffectClass,
    pub capabilities: Vec<ExtensionCapabilityV1>,
    /// Exact HTTP(S) origins (`scheme://host[:port]`) the extension may request.
    pub network_endpoints: Vec<String>,
    pub budgets: ExtensionBudgetsV1,
}

/// Signed build/source attribution kept with every historical result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionReleaseProvenanceV1 {
    pub source: String,
    pub revision: String,
    pub build_sha256: String,
}

/// Signed conformance result for the exact release subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionConformanceV1 {
    pub suite: String,
    pub passed: bool,
    pub report_sha256: String,
}

/// Publisher assertion that an exact release or signing key must no longer execute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionCatalogRevocationV1 {
    pub release_id: Option<String>,
    pub key_id: Option<String>,
    pub reason: String,
}

/// One reviewable normalized change between an active and candidate permission profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionPermissionChangeV1 {
    pub field: String,
    pub before: String,
    pub after: String,
    pub widened: bool,
}

/// Immutable content-addressed approval record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionApprovalV1 {
    pub schema_version: String,
    pub approval_id: String,
    pub approved_at: String,
    pub catalog_path: String,
    pub catalog_id: String,
    pub publisher_id: String,
    pub key_id: String,
    pub catalog_sequence: u64,
    pub payload_sha256: String,
    pub release: ExtensionCatalogReleaseV1,
    pub manifest_path: String,
    pub module_path: String,
    pub permission_changes: Vec<ExtensionPermissionChangeV1>,
    pub permission_diff_sha256: String,
}

/// One append-preserved local lifecycle decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionLifecycleTransitionV1 {
    pub sequence: u64,
    pub occurred_at: String,
    pub action: String,
    pub extension_id: String,
    pub from_approval_id: Option<String>,
    pub to_approval_id: Option<String>,
}

/// Atomic active pointers plus bounded append-preserved history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionLifecycleStateV1 {
    pub schema_version: String,
    /// Highest exact catalog checkpoint accepted into local approval state, keyed by catalog ID.
    #[serde(default)]
    pub catalog_checkpoints: std::collections::BTreeMap<String, ExtensionCatalogCheckpointV1>,
    pub active: std::collections::BTreeMap<String, String>,
    pub transitions: Vec<ExtensionLifecycleTransitionV1>,
}

/// Highest locally accepted sequence and the one payload allowed to own that sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionCatalogCheckpointV1 {
    pub sequence: u64,
    pub payload_sha256: String,
}

impl Default for ExtensionLifecycleStateV1 {
    fn default() -> Self {
        Self {
            schema_version: EXTENSION_LIFECYCLE_STATE_SCHEMA_V1.to_string(),
            catalog_checkpoints: std::collections::BTreeMap::new(),
            active: std::collections::BTreeMap::new(),
            transitions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtensionCatalogContractError {
    #[error("unsupported extension catalog schema")]
    Schema,
    #[error("invalid extension catalog field: {0}")]
    Field(&'static str),
    #[error("extension catalog collection exceeds its boundary: {0}")]
    Boundary(&'static str),
    #[error("extension catalog contains duplicate identities")]
    Duplicate,
}

impl ExtensionCatalogPayloadV1 {
    /// Validate closed shape invariants that do not require trust or a clock.
    ///
    /// # Errors
    ///
    /// Returns the first schema, field, boundary, or duplicate-identity violation.
    pub fn validate_shape(&self) -> Result<(), ExtensionCatalogContractError> {
        if self.schema_version != EXTENSION_CATALOG_PAYLOAD_SCHEMA_V1 {
            return Err(ExtensionCatalogContractError::Schema);
        }
        validate_id(&self.catalog_id, "catalog_id")?;
        validate_id(&self.publisher_id, "publisher_id")?;
        if self.sequence == 0 || self.valid_from.is_empty() || self.valid_until.is_empty() {
            return Err(ExtensionCatalogContractError::Field("validity"));
        }
        if self.releases.len() > MAX_EXTENSION_CATALOG_RELEASES {
            return Err(ExtensionCatalogContractError::Boundary("releases"));
        }
        if self.revocations.len() > MAX_EXTENSION_CATALOG_REVOCATIONS {
            return Err(ExtensionCatalogContractError::Boundary("revocations"));
        }
        let mut releases = BTreeSet::new();
        let mut extension_versions = BTreeSet::new();
        for release in &self.releases {
            release.validate_shape()?;
            if !releases.insert(&release.release_id)
                || !extension_versions.insert((&release.extension_id, &release.version))
            {
                return Err(ExtensionCatalogContractError::Duplicate);
            }
        }
        for revocation in &self.revocations {
            revocation.validate_shape()?;
        }
        Ok(())
    }
}

impl ExtensionCatalogReleaseV1 {
    /// Validate one release's bounded identities and signed evidence shape.
    ///
    /// # Errors
    ///
    /// Returns the first malformed identity, digest, permission, or evidence field.
    pub fn validate_shape(&self) -> Result<(), ExtensionCatalogContractError> {
        validate_id(&self.release_id, "release_id")?;
        validate_id(&self.extension_id, "extension_id")?;
        validate_text(&self.version, "version")?;
        if !valid_single_file(&self.manifest_file, "json") {
            return Err(ExtensionCatalogContractError::Field("manifest_file"));
        }
        for (name, digest) in [
            ("manifest_sha256", &self.manifest_sha256),
            ("module_sha256", &self.module_sha256),
            ("permissions_sha256", &self.permissions_sha256),
            ("build_sha256", &self.provenance.build_sha256),
            ("report_sha256", &self.conformance.report_sha256),
        ] {
            if !is_lower_sha256(digest) {
                return Err(ExtensionCatalogContractError::Field(name));
            }
        }
        self.permissions.validate_shape()?;
        validate_text(&self.provenance.source, "provenance.source")?;
        validate_text(&self.provenance.revision, "provenance.revision")?;
        validate_id(&self.conformance.suite, "conformance.suite")?;
        if !self.conformance.passed {
            return Err(ExtensionCatalogContractError::Field("conformance.passed"));
        }
        Ok(())
    }
}

impl ExtensionPermissionsV1 {
    /// Normalize one manifest and its signed exact HTTP-origin allowances.
    #[must_use]
    pub fn from_manifest(
        manifest: &ExtensionManifestV1,
        mut network_endpoints: Vec<String>,
    ) -> Self {
        let mut target_kinds = manifest.adapter.target_kinds.clone();
        target_kinds.sort_by_key(|value| target_kind_rank(*value));
        network_endpoints.sort();
        network_endpoints.dedup();
        Self {
            target_kinds,
            strongest_effect: manifest.adapter.strongest_effect,
            capabilities: manifest.capabilities.clone(),
            network_endpoints,
            budgets: manifest.budgets.clone(),
        }
    }

    /// Validate canonical ordering and exact endpoint-origin syntax.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate, unordered, oversized, or malformed permission claims.
    pub fn validate_shape(&self) -> Result<(), ExtensionCatalogContractError> {
        if self.target_kinds.is_empty()
            || !canonical_target_kinds(&self.target_kinds)
            || !strictly_sorted(&self.capabilities)
            || self.network_endpoints.len() > MAX_EXTENSION_NETWORK_ENDPOINTS
            || !strictly_sorted(&self.network_endpoints)
        {
            return Err(ExtensionCatalogContractError::Field("permissions"));
        }
        if self.network_endpoints.iter().any(|endpoint| !valid_origin(endpoint)) {
            return Err(ExtensionCatalogContractError::Field("network_endpoints"));
        }
        Ok(())
    }
}

impl ExtensionCatalogRevocationV1 {
    fn validate_shape(&self) -> Result<(), ExtensionCatalogContractError> {
        if self.release_id.is_some() == self.key_id.is_some() {
            return Err(ExtensionCatalogContractError::Field("revocation_subject"));
        }
        if let Some(release_id) = &self.release_id {
            validate_id(release_id, "revocation.release_id")?;
        }
        if let Some(key_id) = &self.key_id {
            validate_id(key_id, "revocation.key_id")?;
        }
        validate_text(&self.reason, "revocation.reason")
    }
}

fn validate_id(value: &str, field: &'static str) -> Result<(), ExtensionCatalogContractError> {
    if value.is_empty()
        || value.len() > MAX_EXTENSION_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b'/')
        })
    {
        return Err(ExtensionCatalogContractError::Field(field));
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ExtensionCatalogContractError> {
    if value.trim().is_empty()
        || value.len() > MAX_EXTENSION_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ExtensionCatalogContractError::Field(field));
    }
    Ok(())
}

fn valid_single_file(value: &str, extension: &str) -> bool {
    let path = Path::new(value);
    path.extension().and_then(|value| value.to_str()) == Some(extension)
        && path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn canonical_target_kinds(values: &[AdapterTargetKind]) -> bool {
    values.windows(2).all(|pair| target_kind_rank(pair[0]) < target_kind_rank(pair[1]))
}

const fn target_kind_rank(value: AdapterTargetKind) -> u8 {
    match value {
        AdapterTargetKind::SourceTree => 0,
        AdapterTargetKind::DependencyManifest => 1,
        AdapterTargetKind::ApplicationArtifact => 2,
        AdapterTargetKind::WebApplication => 3,
        AdapterTargetKind::Api => 4,
        AdapterTargetKind::Network => 5,
        AdapterTargetKind::CloudAccount => 6,
    }
}

fn valid_origin(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.origin().ascii_serialization() == value
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permissions() -> ExtensionPermissionsV1 {
        ExtensionPermissionsV1 {
            target_kinds: vec![AdapterTargetKind::WebApplication],
            strongest_effect: EffectClass::ActiveSafe,
            capabilities: vec![ExtensionCapabilityV1::NetworkHttp],
            network_endpoints: vec!["https://example.com".to_string()],
            budgets: ExtensionBudgetsV1 {
                timeout_ms: 1,
                fuel: 1,
                memory_bytes: 1,
                input_bytes: 1,
                output_bytes: 1,
                effects: 1,
                artifact_bytes: 1,
                artifacts: 1,
            },
        }
    }

    fn release() -> ExtensionCatalogReleaseV1 {
        let permissions = permissions();
        ExtensionCatalogReleaseV1 {
            release_id: "publisher.release-1".to_string(),
            extension_id: "publisher.extension".to_string(),
            version: "1.0.0".to_string(),
            manifest_file: "extension.json".to_string(),
            manifest_sha256: "a".repeat(64),
            module_sha256: "b".repeat(64),
            permissions,
            permissions_sha256: "c".repeat(64),
            provenance: ExtensionReleaseProvenanceV1 {
                source: "local fixture".to_string(),
                revision: "revision-1".to_string(),
                build_sha256: "d".repeat(64),
            },
            conformance: ExtensionConformanceV1 {
                suite: "scorchkit.conformance/v1".to_string(),
                passed: true,
                report_sha256: "e".repeat(64),
            },
        }
    }

    fn payload() -> ExtensionCatalogPayloadV1 {
        ExtensionCatalogPayloadV1 {
            schema_version: EXTENSION_CATALOG_PAYLOAD_SCHEMA_V1.to_string(),
            catalog_id: "publisher.catalog".to_string(),
            publisher_id: "publisher.example".to_string(),
            sequence: 1,
            valid_from: "2020-01-01T00:00:00Z".to_string(),
            valid_until: "2099-01-01T00:00:00Z".to_string(),
            releases: vec![release()],
            revocations: Vec::new(),
        }
    }

    #[test]
    fn signed_endpoint_allowances_are_exact_canonical_origins() {
        assert!(valid_origin("https://example.com"));
        assert!(valid_origin("http://127.0.0.1:8080"));
        for rejected in [
            "https://example.com/",
            "https://example.com/path",
            "https://user@example.com",
            "https://example.com?query=yes",
            "ftp://example.com",
        ] {
            assert!(!valid_origin(rejected), "accepted noncanonical origin: {rejected}");
        }
    }

    #[test]
    fn revocation_names_exactly_one_bounded_subject() {
        let valid = ExtensionCatalogRevocationV1 {
            release_id: Some("publisher.release-1".to_string()),
            key_id: None,
            reason: "withdrawn release".to_string(),
        };
        assert!(valid.validate_shape().is_ok());
        let mut neither = valid.clone();
        neither.release_id = None;
        assert!(neither.validate_shape().is_err());
        let mut both = valid;
        both.key_id = Some("publisher.key".to_string());
        assert!(both.validate_shape().is_err());
    }

    #[test]
    fn catalog_constants_and_payload_boundaries_are_exact() {
        assert_eq!(MAX_EXTENSION_CATALOG_BYTES, 4_194_304);
        assert_eq!(MAX_EXTENSION_CATALOG_PAYLOAD_BYTES, 3_145_728);
        assert_eq!(payload().validate_shape(), Ok(()));

        for invalid in [
            {
                let mut value = payload();
                value.schema_version = "unsupported".to_string();
                value
            },
            {
                let mut value = payload();
                value.catalog_id = "INVALID".to_string();
                value
            },
            {
                let mut value = payload();
                value.publisher_id = "INVALID".to_string();
                value
            },
            {
                let mut value = payload();
                value.sequence = 0;
                value
            },
            {
                let mut value = payload();
                value.valid_from.clear();
                value
            },
            {
                let mut value = payload();
                value.valid_until.clear();
                value
            },
        ] {
            assert!(invalid.validate_shape().is_err());
        }

        let mut at_release_limit = payload();
        at_release_limit.releases = (0..MAX_EXTENSION_CATALOG_RELEASES)
            .map(|index| {
                let mut value = release();
                value.release_id = format!("publisher.release-{index}");
                value.extension_id = format!("publisher.extension-{index}");
                value
            })
            .collect();
        assert_eq!(at_release_limit.validate_shape(), Ok(()));
        let mut over_release_limit = payload();
        over_release_limit.releases = vec![release(); MAX_EXTENSION_CATALOG_RELEASES + 1];
        assert_eq!(
            over_release_limit.validate_shape(),
            Err(ExtensionCatalogContractError::Boundary("releases"))
        );

        let revocation = ExtensionCatalogRevocationV1 {
            release_id: Some("publisher.release-1".to_string()),
            key_id: None,
            reason: "withdrawn".to_string(),
        };
        let mut at_revocation_limit = payload();
        at_revocation_limit.revocations =
            vec![revocation.clone(); MAX_EXTENSION_CATALOG_REVOCATIONS];
        assert_eq!(at_revocation_limit.validate_shape(), Ok(()));
        let mut over_revocation_limit = payload();
        over_revocation_limit.revocations = vec![revocation; MAX_EXTENSION_CATALOG_REVOCATIONS + 1];
        assert_eq!(
            over_revocation_limit.validate_shape(),
            Err(ExtensionCatalogContractError::Boundary("revocations"))
        );

        let mut duplicate_release = payload();
        duplicate_release.releases.push(release());
        assert_eq!(
            duplicate_release.validate_shape(),
            Err(ExtensionCatalogContractError::Duplicate)
        );
        let mut duplicate_extension_version = payload();
        let mut second = release();
        second.release_id = "publisher.release-2".to_string();
        duplicate_extension_version.releases.push(second);
        assert_eq!(
            duplicate_extension_version.validate_shape(),
            Err(ExtensionCatalogContractError::Duplicate)
        );
    }

    #[test]
    fn release_shape_checks_every_signed_subject_field() {
        assert_eq!(release().validate_shape(), Ok(()));
        let mut invalid_values = Vec::new();

        let mut value = release();
        value.release_id = "INVALID".to_string();
        invalid_values.push(value);
        let mut value = release();
        value.extension_id = "INVALID".to_string();
        invalid_values.push(value);
        let mut value = release();
        value.version.clear();
        invalid_values.push(value);
        let mut value = release();
        value.manifest_file = "nested/extension.json".to_string();
        invalid_values.push(value);
        for digest_index in 0..5 {
            let mut value = release();
            match digest_index {
                0 => value.manifest_sha256 = "A".repeat(64),
                1 => value.module_sha256 = "A".repeat(64),
                2 => value.permissions_sha256 = "A".repeat(64),
                3 => value.provenance.build_sha256 = "A".repeat(64),
                4 => value.conformance.report_sha256 = "A".repeat(64),
                _ => unreachable!(),
            }
            invalid_values.push(value);
        }
        let mut value = release();
        value.permissions.target_kinds.clear();
        invalid_values.push(value);
        let mut value = release();
        value.provenance.source.clear();
        invalid_values.push(value);
        let mut value = release();
        value.provenance.revision.clear();
        invalid_values.push(value);
        let mut value = release();
        value.conformance.suite = "INVALID".to_string();
        invalid_values.push(value);
        let mut value = release();
        value.conformance.passed = false;
        invalid_values.push(value);

        for invalid in invalid_values {
            assert!(invalid.validate_shape().is_err());
        }
    }

    #[test]
    fn permission_shape_checks_each_canonical_clause_and_endpoint_limit() {
        assert_eq!(permissions().validate_shape(), Ok(()));
        let mut invalid = permissions();
        invalid.target_kinds.clear();
        assert!(invalid.validate_shape().is_err());
        let mut invalid = permissions();
        invalid.target_kinds =
            vec![AdapterTargetKind::WebApplication, AdapterTargetKind::SourceTree];
        assert!(invalid.validate_shape().is_err());
        let mut invalid = permissions();
        invalid.capabilities =
            vec![ExtensionCapabilityV1::NetworkHttp, ExtensionCapabilityV1::NetworkHttp];
        assert!(invalid.validate_shape().is_err());
        let mut invalid = permissions();
        invalid.network_endpoints =
            vec!["https://z.example".to_string(), "https://a.example".to_string()];
        assert!(invalid.validate_shape().is_err());
        let mut invalid = permissions();
        invalid.network_endpoints = vec!["https://example.com/path".to_string()];
        assert!(invalid.validate_shape().is_err());

        let endpoints = (0..MAX_EXTENSION_NETWORK_ENDPOINTS)
            .map(|index| format!("https://host-{index:02}.example"))
            .collect::<Vec<_>>();
        let mut at_limit = permissions();
        at_limit.network_endpoints.clone_from(&endpoints);
        assert_eq!(at_limit.validate_shape(), Ok(()));
        let mut over_limit = permissions();
        over_limit.network_endpoints = endpoints;
        over_limit.network_endpoints.push("https://overflow.example".to_string());
        over_limit.network_endpoints.sort();
        assert!(over_limit.validate_shape().is_err());
    }

    #[test]
    fn identity_text_path_digest_and_order_helpers_have_closed_truth_tables() {
        assert_eq!(validate_id("a", "id"), Ok(()));
        assert_eq!(validate_id(&"a".repeat(MAX_EXTENSION_ID_BYTES), "id"), Ok(()));
        for invalid in [String::new(), "a".repeat(MAX_EXTENSION_ID_BYTES + 1), "A".to_string()] {
            assert!(validate_id(&invalid, "id").is_err());
        }

        assert_eq!(validate_text("a", "text"), Ok(()));
        assert_eq!(validate_text(&"a".repeat(MAX_EXTENSION_TEXT_BYTES), "text"), Ok(()));
        for invalid in [
            String::new(),
            " ".to_string(),
            "a".repeat(MAX_EXTENSION_TEXT_BYTES + 1),
            "bad\ntext".to_string(),
        ] {
            assert!(validate_text(&invalid, "text").is_err());
        }

        assert!(valid_single_file("extension.json", "json"));
        assert!(!valid_single_file("extension.txt", "json"));
        assert!(!valid_single_file("nested/extension.json", "json"));
        assert!(!valid_single_file("/extension.json", "json"));

        assert!(is_lower_sha256(&"a".repeat(64)));
        assert!(!is_lower_sha256(&"a".repeat(63)));
        assert!(!is_lower_sha256(&"g".repeat(64)));
        assert!(!is_lower_sha256(&"A".repeat(64)));

        assert!(strictly_sorted::<u8>(&[]));
        assert!(strictly_sorted(&[1_u8]));
        assert!(strictly_sorted(&[1_u8, 2]));
        assert!(!strictly_sorted(&[1_u8, 1]));
        assert!(!strictly_sorted(&[2_u8, 1]));

        let canonical = [
            AdapterTargetKind::SourceTree,
            AdapterTargetKind::DependencyManifest,
            AdapterTargetKind::ApplicationArtifact,
            AdapterTargetKind::WebApplication,
            AdapterTargetKind::Api,
            AdapterTargetKind::Network,
            AdapterTargetKind::CloudAccount,
        ];
        assert!(canonical_target_kinds(&canonical));
        assert!(!canonical_target_kinds(&[
            AdapterTargetKind::SourceTree,
            AdapterTargetKind::SourceTree,
        ]));
        assert!(!canonical_target_kinds(&[
            AdapterTargetKind::WebApplication,
            AdapterTargetKind::SourceTree,
        ]));
        assert_eq!(target_kind_rank(AdapterTargetKind::SourceTree), 0);
        assert_eq!(target_kind_rank(AdapterTargetKind::DependencyManifest), 1);
        assert_eq!(target_kind_rank(AdapterTargetKind::Api), 4);
        assert_eq!(target_kind_rank(AdapterTargetKind::CloudAccount), 6);
    }
}
