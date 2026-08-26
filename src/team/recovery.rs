//! Pure, bounded recovery-manifest construction and verification.

use std::collections::BTreeSet;

use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use scorchkit_control::{
    TeamObjectKindV1, TeamRecoveryManifestV1, TeamRecoveryObjectV1, TEAM_OBJECT_SCHEMA_V1,
    TEAM_RECOVERY_SCHEMA_V1,
};
use scorchkit_core::sha256_hex;
use serde::Deserialize;
use uuid::Uuid;

use crate::engine::error::{Result, ScorchError};

const MAX_RECOVERY_OBJECTS: usize = 1_000_000;
const MAX_MIGRATION_VERSIONS: usize = 1_024;
const MAX_RECOVERY_SNAPSHOT_BYTES: u64 = 1_099_511_627_776;
const MAX_RECOVERY_CIPHERTEXT_BYTES: u64 = 134_234_112;
const MAX_RECOVERY_TOTAL_CIPHERTEXT_BYTES: u64 = 1_099_511_627_776;

/// Exact bytes and identities used to create or verify one backup manifest.
#[derive(Debug, Clone)]
pub struct RecoveryInput {
    pub cell_id: String,
    pub organization_id: String,
    pub project_id: Uuid,
    pub engagement_id: Uuid,
    pub database_identity_sha256: String,
    pub migration_versions: Vec<i64>,
    pub database_snapshot: Vec<u8>,
    /// Each pair contains public metadata and exact encrypted-envelope bytes.
    pub objects: Vec<(TeamRecoveryObjectV1, Vec<u8>)>,
    /// Exact operator-selected snapshot creation time bound into the manifest.
    pub created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryEnvelopeHeader {
    schema_version: String,
    cell_id: String,
    object_id: String,
    kind: TeamObjectKindV1,
    plaintext_bytes: u64,
    key_id: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    nonce: String,
    ciphertext: String,
}

/// Build a canonical manifest after validating every supplied snapshot and ciphertext digest.
///
/// # Errors
///
/// Returns an error for malformed identities, unsorted inventories, digest drift, or unbounded
/// inputs.
pub fn create_recovery_manifest(input: &RecoveryInput) -> Result<TeamRecoveryManifestV1> {
    validate_input(input)?;
    let objects = verified_objects(input)?;
    let required_key_ids = objects
        .iter()
        .map(|object| object.key_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(TeamRecoveryManifestV1 {
        schema_version: TEAM_RECOVERY_SCHEMA_V1.to_string(),
        cell_id: input.cell_id.clone(),
        organization_id: input.organization_id.clone(),
        project_id: input.project_id,
        engagement_id: input.engagement_id,
        database_identity_sha256: input.database_identity_sha256.clone(),
        migration_versions: input.migration_versions.clone(),
        database_snapshot_sha256: sha256_hex(&input.database_snapshot),
        database_snapshot_bytes: u64::try_from(input.database_snapshot.len()).map_err(|_| {
            ScorchError::Config("team recovery snapshot size is unsupported".to_string())
        })?,
        objects,
        required_key_ids,
        created_at: input.created_at,
    })
}

/// Reverify one manifest immediately before or after consuming its backup bytes.
///
/// A destination identity is mandatory and must differ from the source database identity.
///
/// # Errors
///
/// Returns an error for a same-database destination or any manifest, snapshot, migration, object,
/// key-identifier, or digest mismatch.
pub fn verify_recovery_manifest(
    manifest: &TeamRecoveryManifestV1,
    input: &RecoveryInput,
    destination_database_identity_sha256: &str,
) -> Result<()> {
    validate_input(input)?;
    validate_digest(destination_database_identity_sha256)?;
    if destination_database_identity_sha256 == input.database_identity_sha256 {
        return Err(ScorchError::Config(
            "team recovery destination must be distinct from its source".to_string(),
        ));
    }
    let objects = verified_objects(input)?;
    let required_key_ids: Vec<_> = objects
        .iter()
        .map(|object| object.key_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let snapshot_bytes = u64::try_from(input.database_snapshot.len()).map_err(|_| {
        ScorchError::Config("team recovery snapshot size is unsupported".to_string())
    })?;
    if manifest.schema_version != TEAM_RECOVERY_SCHEMA_V1
        || manifest.cell_id != input.cell_id
        || manifest.organization_id != input.organization_id
        || manifest.project_id != input.project_id
        || manifest.engagement_id != input.engagement_id
        || manifest.database_identity_sha256 != input.database_identity_sha256
        || manifest.migration_versions != input.migration_versions
        || manifest.database_snapshot_sha256 != sha256_hex(&input.database_snapshot)
        || manifest.database_snapshot_bytes != snapshot_bytes
        || manifest.objects != objects
        || manifest.required_key_ids != required_key_ids
        || manifest.created_at != input.created_at
    {
        return Err(ScorchError::Config("team recovery manifest verification failed".to_string()));
    }
    Ok(())
}

fn validate_input(input: &RecoveryInput) -> Result<()> {
    let snapshot_bytes = u64::try_from(input.database_snapshot.len()).unwrap_or(u64::MAX);
    if !valid_identifier(&input.cell_id)
        || !valid_identifier(&input.organization_id)
        || input.project_id.is_nil()
        || input.engagement_id.is_nil()
        || !valid_migration_count(input.migration_versions.len())
        || input.migration_versions.iter().any(|version| *version <= 0)
        || input.migration_versions.windows(2).any(|pair| pair[0] >= pair[1])
        || !valid_snapshot_size(snapshot_bytes)
        || !valid_object_count(input.objects.len())
        || input.created_at.timestamp() <= 0
        || input.created_at > Utc::now() + Duration::minutes(5)
    {
        return Err(ScorchError::Config(
            "team recovery input is empty, oversized, or non-canonical".to_string(),
        ));
    }
    validate_digest(&input.database_identity_sha256)
}

fn verified_objects(input: &RecoveryInput) -> Result<Vec<TeamRecoveryObjectV1>> {
    let mut objects = Vec::with_capacity(input.objects.len());
    let mut previous = None;
    let mut total_bytes = 0_u64;
    for (object, ciphertext) in &input.objects {
        validate_digest(&object.object_id)?;
        validate_digest(&object.ciphertext_sha256)?;
        let stored_bytes = u64::try_from(ciphertext.len()).map_err(|_| {
            ScorchError::Config("team recovery object size is unsupported".to_string())
        })?;
        total_bytes = total_bytes.checked_add(stored_bytes).ok_or_else(|| {
            ScorchError::Config("team recovery object inventory is oversized".to_string())
        })?;
        if !valid_identifier(&object.key_id)
            || !valid_ciphertext_sizes(stored_bytes, total_bytes)
            || object.stored_bytes != stored_bytes
            || object.ciphertext_sha256 != sha256_hex(ciphertext)
            || previous.as_ref().is_some_and(|value: &String| value >= &object.object_id)
        {
            return Err(ScorchError::Config(
                "team recovery object inventory verification failed".to_string(),
            ));
        }
        verify_envelope_header(input, object, ciphertext)?;
        previous = Some(object.object_id.clone());
        objects.push(object.clone());
    }
    Ok(objects)
}

fn verify_envelope_header(
    input: &RecoveryInput,
    object: &TeamRecoveryObjectV1,
    bytes: &[u8],
) -> Result<()> {
    let envelope: RecoveryEnvelopeHeader =
        serde_json::from_slice(bytes).map_err(|_| recovery_object_error())?;
    let nonce = base64::engine::general_purpose::STANDARD
        .decode(envelope.nonce.as_bytes())
        .map_err(|_| recovery_object_error())?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|_| recovery_object_error())?;
    let expected_ciphertext = envelope.plaintext_bytes.checked_add(16);
    if envelope.schema_version != TEAM_OBJECT_SCHEMA_V1
        || envelope.cell_id != input.cell_id
        || envelope.object_id != object.object_id
        || envelope.plaintext_bytes == 0
        || envelope.key_id != object.key_id
        || envelope.created_at.timestamp() <= 0
        || envelope.expires_at <= envelope.created_at
        || nonce.len() != 12
        || u64::try_from(ciphertext.len()).ok() != expected_ciphertext
    {
        return Err(recovery_object_error());
    }
    let _ = envelope.kind;
    Ok(())
}

fn recovery_object_error() -> ScorchError {
    ScorchError::Config("team recovery object inventory verification failed".to_string())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@' | b'/')
        })
}

const fn valid_migration_count(count: usize) -> bool {
    count >= 1 && count <= MAX_MIGRATION_VERSIONS
}

const fn valid_snapshot_size(bytes: u64) -> bool {
    bytes >= 1 && bytes <= MAX_RECOVERY_SNAPSHOT_BYTES
}

const fn valid_object_count(count: usize) -> bool {
    count <= MAX_RECOVERY_OBJECTS
}

const fn valid_ciphertext_sizes(stored_bytes: u64, total_bytes: u64) -> bool {
    stored_bytes >= 1
        && stored_bytes <= MAX_RECOVERY_CIPHERTEXT_BYTES
        && total_bytes <= MAX_RECOVERY_TOTAL_CIPHERTEXT_BYTES
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || value.bytes().any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(ScorchError::Config(
            "team recovery digest is not lowercase SHA-256".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite_envelope(
        mut input: RecoveryInput,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> RecoveryInput {
        let mut value: serde_json::Value =
            serde_json::from_slice(&input.objects[0].1).expect("fixture envelope");
        mutate(&mut value);
        let bytes = serde_json::to_vec(&value).expect("changed envelope");
        input.objects[0].0.ciphertext_sha256 = sha256_hex(&bytes);
        input.objects[0].0.stored_bytes = u64::try_from(bytes.len()).expect("stored size");
        input.objects[0].1 = bytes;
        input
    }

    fn envelope(cell_id: &str, object_id: &str, key_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": TEAM_OBJECT_SCHEMA_V1,
            "cellId": cell_id,
            "objectId": object_id,
            "kind": "evidence",
            "plaintextBytes": 8,
            "keyId": key_id,
            "createdAt": "2023-11-14T22:13:20Z",
            "expiresAt": "2023-12-14T22:13:20Z",
            "nonce": base64::engine::general_purpose::STANDARD.encode([1_u8; 12]),
            "ciphertext": base64::engine::general_purpose::STANDARD.encode([2_u8; 24]),
        }))
        .expect("envelope")
    }

    fn input() -> RecoveryInput {
        let object_id = "b".repeat(64);
        let ciphertext = envelope("alpha", &object_id, "primary");
        RecoveryInput {
            cell_id: "alpha".into(),
            organization_id: "org-alpha".into(),
            project_id: Uuid::from_u128(1),
            engagement_id: Uuid::from_u128(2),
            database_identity_sha256: "a".repeat(64),
            migration_versions: vec![1, 2, 14],
            database_snapshot: b"pg custom snapshot".to_vec(),
            objects: vec![(
                TeamRecoveryObjectV1 {
                    object_id,
                    ciphertext_sha256: sha256_hex(&ciphertext),
                    stored_bytes: u64::try_from(ciphertext.len()).expect("size"),
                    key_id: "primary".into(),
                },
                ciphertext,
            )],
            created_at: DateTime::<Utc>::UNIX_EPOCH + Duration::seconds(1_700_000_000),
        }
    }

    #[test]
    fn manifest_verifies_only_against_exact_bytes_and_distinct_destination() {
        let input = input();
        let manifest = create_recovery_manifest(&input).expect("manifest");
        verify_recovery_manifest(&manifest, &input, &"c".repeat(64)).expect("verification");
        assert!(verify_recovery_manifest(&manifest, &input, &"a".repeat(64)).is_err());

        let mut changed = input;
        changed.database_snapshot.push(b'!');
        assert!(verify_recovery_manifest(&manifest, &changed, &"c".repeat(64)).is_err());
    }

    #[test]
    fn ciphertext_and_inventory_order_are_verified() {
        let mut changed = input();
        changed.objects[0].1.push(b'!');
        assert!(create_recovery_manifest(&changed).is_err());

        let mut input = input();
        let second_id = "a".repeat(64);
        let second_bytes = envelope("alpha", &second_id, "secondary");
        input.objects.push((
            TeamRecoveryObjectV1 {
                object_id: second_id,
                ciphertext_sha256: sha256_hex(&second_bytes),
                stored_bytes: u64::try_from(second_bytes.len()).expect("size"),
                key_id: "secondary".into(),
            },
            second_bytes,
        ));
        assert!(create_recovery_manifest(&input).is_err());
    }

    #[test]
    fn recovery_input_rejects_every_identity_migration_time_and_size_clause() {
        let cases: &[fn(&mut RecoveryInput)] = &[
            |value| value.cell_id.clear(),
            |value| value.organization_id = "org alpha".into(),
            |value| value.project_id = Uuid::nil(),
            |value| value.engagement_id = Uuid::nil(),
            |value| value.migration_versions.clear(),
            |value| value.migration_versions = vec![1; MAX_MIGRATION_VERSIONS + 1],
            |value| value.migration_versions = vec![0],
            |value| value.migration_versions = vec![2, 1],
            |value| value.database_snapshot.clear(),
            |value| value.database_identity_sha256 = "A".repeat(64),
            |value| value.created_at = DateTime::<Utc>::UNIX_EPOCH,
            |value| value.created_at = Utc::now() + Duration::minutes(6),
        ];
        for mutate in cases {
            let mut value = input();
            mutate(&mut value);
            assert!(create_recovery_manifest(&value).is_err());
        }

        assert!(valid_migration_count(1));
        assert!(valid_migration_count(MAX_MIGRATION_VERSIONS));
        assert!(!valid_migration_count(0));
        assert!(!valid_migration_count(MAX_MIGRATION_VERSIONS + 1));
        assert!(valid_snapshot_size(1));
        assert!(valid_snapshot_size(MAX_RECOVERY_SNAPSHOT_BYTES));
        assert!(!valid_snapshot_size(0));
        assert!(!valid_snapshot_size(MAX_RECOVERY_SNAPSHOT_BYTES + 1));
        assert!(valid_object_count(MAX_RECOVERY_OBJECTS));
        assert!(!valid_object_count(MAX_RECOVERY_OBJECTS + 1));
        assert!(valid_ciphertext_sizes(1, 1));
        assert!(valid_ciphertext_sizes(
            MAX_RECOVERY_CIPHERTEXT_BYTES,
            MAX_RECOVERY_TOTAL_CIPHERTEXT_BYTES,
        ));
        assert!(!valid_ciphertext_sizes(0, 1));
        assert!(!valid_ciphertext_sizes(MAX_RECOVERY_CIPHERTEXT_BYTES + 1, 1));
        assert!(!valid_ciphertext_sizes(1, MAX_RECOVERY_TOTAL_CIPHERTEXT_BYTES + 1));
    }

    #[test]
    fn manifest_verifier_binds_every_projected_field() {
        let input = input();
        let manifest = create_recovery_manifest(&input).expect("manifest");
        let destination = "c".repeat(64);
        let cases: &[fn(&mut TeamRecoveryManifestV1)] = &[
            |value| value.schema_version = "wrong".into(),
            |value| value.cell_id = "beta".into(),
            |value| value.organization_id = "org-beta".into(),
            |value| value.project_id = Uuid::from_u128(7),
            |value| value.engagement_id = Uuid::from_u128(8),
            |value| value.database_identity_sha256 = "d".repeat(64),
            |value| value.migration_versions.push(15),
            |value| value.database_snapshot_sha256 = "d".repeat(64),
            |value| value.database_snapshot_bytes += 1,
            |value| value.objects.clear(),
            |value| value.required_key_ids.clear(),
            |value| value.created_at += Duration::seconds(1),
        ];
        for mutate in cases {
            let mut changed = manifest.clone();
            mutate(&mut changed);
            assert!(verify_recovery_manifest(&changed, &input, &destination).is_err());
        }
        assert!(verify_recovery_manifest(&manifest, &input, "invalid").is_err());
    }

    #[test]
    fn object_inventory_and_every_envelope_header_field_are_authenticated() {
        let outer_cases: &[fn(&mut RecoveryInput)] = &[
            |value| value.objects[0].0.object_id = "A".repeat(64),
            |value| value.objects[0].0.ciphertext_sha256 = "c".repeat(64),
            |value| value.objects[0].0.stored_bytes = 0,
            |value| value.objects[0].0.key_id.clear(),
        ];
        for mutate in outer_cases {
            let mut changed = input();
            mutate(&mut changed);
            assert!(create_recovery_manifest(&changed).is_err());
        }

        let envelope_cases: &[fn(&mut serde_json::Value)] = &[
            |value| value["schemaVersion"] = "wrong".into(),
            |value| value["cellId"] = "beta".into(),
            |value| value["objectId"] = "c".repeat(64).into(),
            |value| value["plaintextBytes"] = 0.into(),
            |value| value["keyId"] = "secondary".into(),
            |value| value["createdAt"] = "1970-01-01T00:00:00Z".into(),
            |value| value["expiresAt"] = value["createdAt"].clone(),
            |value| {
                value["nonce"] =
                    base64::engine::general_purpose::STANDARD.encode([1_u8; 11]).into();
            },
            |value| {
                value["ciphertext"] =
                    base64::engine::general_purpose::STANDARD.encode([2_u8; 23]).into();
            },
        ];
        for mutate in envelope_cases {
            let changed = rewrite_envelope(input(), mutate);
            assert!(create_recovery_manifest(&changed).is_err());
        }

        let mut invalid_but_consistent_key =
            rewrite_envelope(input(), |value| value["keyId"] = "".into());
        invalid_but_consistent_key.objects[0].0.key_id.clear();
        assert!(create_recovery_manifest(&invalid_but_consistent_key).is_err());
    }

    #[test]
    fn recovery_grace_window_keeps_its_strict_upper_bound() {
        let source = include_str!("recovery.rs");
        let start = source.find("fn validate_input").expect("input validator");
        let end = source[start..]
            .find("fn verified_objects")
            .map(|offset| start + offset)
            .expect("object validator");
        assert!(source[start..end].contains("input.created_at > Utc::now() + Duration::minutes(5)"));
    }

    #[test]
    fn identifier_and_digest_grammars_have_exact_edges() {
        assert!(valid_identifier("a-A_1.example:test@path/value"));
        assert!(valid_identifier(&"a".repeat(128)));
        assert!(!valid_identifier(""));
        assert!(!valid_identifier(&"a".repeat(129)));
        assert!(!valid_identifier("contains space"));

        assert!(validate_digest(&"a".repeat(64)).is_ok());
        assert!(validate_digest(&"a".repeat(63)).is_err());
        assert!(validate_digest(&"a".repeat(65)).is_err());
        assert!(validate_digest(&"A".repeat(64)).is_err());
        assert!(validate_digest(&"g".repeat(64)).is_err());
    }
}
