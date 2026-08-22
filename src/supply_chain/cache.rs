//! Typed immutable provider snapshots with atomic current-pointer promotion.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::engine::error::{Result, ScorchError};
#[cfg(windows)]
use crate::windows_support::{ensure_same_filesystem, require_private_directory};
use scorchkit_core::{ProviderSnapshot, ProviderSnapshotState};

const METADATA_LIMIT_BYTES: usize = 64 * 1024;
const MAX_SNAPSHOT_ARTIFACTS: usize = 4_096;

/// Validated descriptor stored inside one immutable provider snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub provider: String,
    pub snapshot_id: String,
    pub schema_version: String,
    pub consumer_relative_path: PathBuf,
    pub artifacts: Vec<SnapshotArtifact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_built_at: Option<DateTime<Utc>>,
    pub checked_at: DateTime<Utc>,
    pub maximum_age_seconds: u64,
}

/// One provider file whose exact digest is revalidated before every scanner use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotArtifact {
    pub relative_path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CurrentPointer {
    snapshot_id: String,
    manifest_sha256: String,
}

/// Security-critical snapshot boundary rooted on one configured filesystem.
#[derive(Debug, Clone)]
pub struct SupplyChainSnapshotStore {
    root: PathBuf,
    artifact_limit_bytes: usize,
}

impl SupplyChainSnapshotStore {
    /// Bind a store to an existing canonical directory.
    pub fn open(root: &Path, artifact_limit_bytes: usize) -> Result<Self> {
        reject_symlink(root)?;
        let root = root.canonicalize().map_err(|error| {
            ScorchError::Config(format!(
                "cannot canonicalize supply-chain cache root '{}': {error}",
                root.display()
            ))
        })?;
        if !root.is_dir() {
            return Err(ScorchError::Config(format!(
                "supply-chain cache root '{}' is not a directory",
                root.display()
            )));
        }
        require_private_directory(&root)?;
        Ok(Self { root, artifact_limit_bytes })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return a typed snapshot state; corruption and staleness are never silent misses.
    #[must_use]
    pub fn status(
        &self,
        provider: &str,
        now: DateTime<Utc>,
        policy_maximum_age_seconds: u64,
    ) -> ProviderSnapshot {
        match self.read_current(provider, now, policy_maximum_age_seconds) {
            Ok(snapshot) => snapshot,
            Err(error) => invalid_snapshot(provider, self.root.join(provider), &error.to_string()),
        }
    }

    /// Return a safe staging directory path without creating or mutating it.
    pub fn staging_path(&self, provider: &str, snapshot_id: &str) -> Result<PathBuf> {
        validate_component(provider, "provider")?;
        validate_component(snapshot_id, "snapshot id")?;
        Ok(self.root.join(provider).join("staging").join(snapshot_id))
    }

    /// Create a new private staging slot while refusing redirected cache ancestors.
    pub fn create_staging(&self, provider: &str, snapshot_id: &str) -> Result<PathBuf> {
        let stage = self.staging_path(provider, snapshot_id)?;
        let provider_root = self.root.join(provider);
        create_private_directory_if_missing(&provider_root)?;
        require_canonical_descendant(&self.root, &provider_root, "provider cache")?;
        let staging_root = provider_root.join("staging");
        create_private_directory_if_missing(&staging_root)?;
        require_canonical_descendant(&provider_root, &staging_root, "provider staging root")?;
        create_private_directory(&stage)?;
        require_canonical_descendant(&staging_root, &stage, "provider staging slot")?;
        Ok(stage)
    }

    /// Verify a staged snapshot, move it into immutable storage, and atomically select it.
    ///
    /// The previous current pointer is replaced only after the complete snapshot directory and
    /// manifest are durable. Existing snapshot directories are never overwritten.
    pub fn promote(
        &self,
        staged_directory: &Path,
        manifest: &SnapshotManifest,
    ) -> Result<ProviderSnapshot> {
        validate_manifest_shape(manifest)?;
        let expected_stage = self.staging_path(&manifest.provider, &manifest.snapshot_id)?;
        let provider_root = self.root.join(&manifest.provider);
        require_canonical_descendant(&self.root, &provider_root, "provider cache")?;
        let staging_root = provider_root.join("staging");
        require_canonical_descendant(&provider_root, &staging_root, "provider staging root")?;
        let canonical_stage = staged_directory.canonicalize()?;
        if canonical_stage != expected_stage.canonicalize()?
            || !canonical_stage.starts_with(&staging_root.canonicalize()?)
            || !canonical_stage.starts_with(&self.root)
        {
            return Err(ScorchError::Config(
                "staged provider snapshot is outside its selected cache slot".to_string(),
            ));
        }
        ensure_same_filesystem(&self.root, &canonical_stage)?;
        validate_staged_artifacts(&canonical_stage, manifest, self.artifact_limit_bytes, false)?;

        let manifest_bytes = serde_json::to_vec_pretty(manifest)?;
        let manifest_path = canonical_stage.join("manifest.json");
        write_new_synced(&manifest_path, &manifest_bytes)?;
        sync_directory(&canonical_stage)?;

        let snapshots = provider_root.join("snapshots");
        create_private_directory_if_missing(&snapshots)?;
        require_canonical_descendant(&provider_root, &snapshots, "provider snapshot root")?;
        ensure_same_filesystem(&self.root, &snapshots)?;
        let final_directory = snapshots.join(&manifest.snapshot_id);
        if final_directory.exists() {
            return Err(ScorchError::Config(format!(
                "provider snapshot '{}' already exists",
                manifest.snapshot_id
            )));
        }
        fs::rename(&canonical_stage, &final_directory)?;
        sync_directory(&snapshots)?;

        let pointer = CurrentPointer {
            snapshot_id: manifest.snapshot_id.clone(),
            manifest_sha256: sha256_bytes(&manifest_bytes),
        };
        let pointer_bytes = serde_json::to_vec_pretty(&pointer)?;
        let pointer_path = provider_root.join("current.json");
        let temporary_pointer = provider_root.join(format!("current.{}.new", manifest.snapshot_id));
        write_new_synced(&temporary_pointer, &pointer_bytes)?;
        fs::rename(&temporary_pointer, &pointer_path)?;
        sync_directory(&provider_root)?;

        self.read_current(&manifest.provider, Utc::now(), manifest.maximum_age_seconds)
    }

    fn read_current(
        &self,
        provider: &str,
        now: DateTime<Utc>,
        policy_maximum_age_seconds: u64,
    ) -> Result<ProviderSnapshot> {
        validate_component(provider, "provider")?;
        let provider_root = self.root.join(provider);
        let pointer_path = provider_root.join("current.json");
        if !provider_root.exists() {
            if fs::symlink_metadata(&provider_root).is_ok() {
                return Err(ScorchError::Config(
                    "provider cache path is an invalid filesystem entry".to_string(),
                ));
            }
            return Ok(missing_snapshot(provider, pointer_path));
        }
        require_canonical_descendant(&self.root, &provider_root, "provider cache")?;
        if !pointer_path.exists() {
            return Ok(missing_snapshot(provider, pointer_path));
        }
        reject_symlink(&pointer_path)?;
        let pointer_bytes = read_bounded(&pointer_path, METADATA_LIMIT_BYTES)?;
        let pointer: CurrentPointer = serde_json::from_slice(&pointer_bytes)?;
        validate_component(&pointer.snapshot_id, "snapshot id")?;

        let snapshots_root = provider_root.join("snapshots");
        let canonical_snapshots = require_canonical_descendant(
            &provider_root,
            &snapshots_root,
            "provider snapshot root",
        )?;
        let snapshot_directory = snapshots_root.join(&pointer.snapshot_id);
        reject_symlink(&snapshot_directory)?;
        let canonical_snapshot = snapshot_directory.canonicalize()?;
        let canonical_provider = provider_root.canonicalize()?;
        if !canonical_provider.starts_with(&self.root)
            || !canonical_snapshot.starts_with(&canonical_snapshots)
            || !canonical_snapshot.starts_with(&canonical_provider)
            || !canonical_snapshot.starts_with(&self.root)
        {
            return Err(ScorchError::Config(
                "current provider snapshot escaped its cache root".to_string(),
            ));
        }
        let manifest_path = canonical_snapshot.join("manifest.json");
        reject_symlink(&manifest_path)?;
        let manifest_bytes = read_bounded(&manifest_path, METADATA_LIMIT_BYTES)?;
        if sha256_bytes(&manifest_bytes) != pointer.manifest_sha256 {
            return Err(ScorchError::Config(
                "provider snapshot manifest digest does not match current pointer".to_string(),
            ));
        }
        let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)?;
        validate_manifest_shape(&manifest)?;
        if manifest.provider != provider || manifest.snapshot_id != pointer.snapshot_id {
            return Err(ScorchError::Config(
                "provider snapshot identity does not match its cache slot".to_string(),
            ));
        }
        let consumer_path = canonical_snapshot.join(&manifest.consumer_relative_path);
        let canonical_consumer = consumer_path.canonicalize()?;
        if !canonical_consumer.starts_with(&canonical_snapshot) || !canonical_consumer.is_dir() {
            return Err(ScorchError::Config(
                "provider scanner cache escaped its immutable directory".to_string(),
            ));
        }
        reject_symlink(&consumer_path)?;
        validate_staged_artifacts(&canonical_snapshot, &manifest, self.artifact_limit_bytes, true)?;

        let freshness_timestamp = manifest.upstream_built_at.unwrap_or(manifest.checked_at);
        let effective_maximum_age_seconds =
            manifest.maximum_age_seconds.min(policy_maximum_age_seconds);
        let age = now.signed_duration_since(freshness_timestamp).num_seconds();
        let state =
            if age < 0 || u64::try_from(age).unwrap_or(u64::MAX) > effective_maximum_age_seconds {
                ProviderSnapshotState::Stale
            } else {
                ProviderSnapshotState::Ready
            };
        Ok(ProviderSnapshot {
            provider: provider.to_string(),
            snapshot_id: manifest.snapshot_id,
            schema_version: manifest.schema_version,
            consumer_path: canonical_consumer,
            canonical_path: canonical_snapshot,
            state,
            expected_sha256: pointer.manifest_sha256.clone(),
            computed_sha256: Some(pointer.manifest_sha256),
            upstream_built_at: manifest.upstream_built_at,
            checked_at: Some(manifest.checked_at),
            maximum_age_seconds: effective_maximum_age_seconds,
            validation_error: None,
        })
    }
}

fn validate_manifest_shape(manifest: &SnapshotManifest) -> Result<()> {
    validate_component(&manifest.provider, "provider")?;
    validate_component(&manifest.snapshot_id, "snapshot id")?;
    if manifest.schema_version.trim().is_empty()
        || manifest.consumer_relative_path.is_absolute()
        || manifest.artifacts.is_empty()
        || manifest.artifacts.len() > MAX_SNAPSHOT_ARTIFACTS
        || manifest
            .consumer_relative_path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        || manifest.artifacts.iter().any(|artifact| {
            artifact.relative_path.is_absolute()
                || artifact
                    .relative_path
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
                || !is_sha256(&artifact.sha256)
        })
    {
        return Err(ScorchError::Config(
            "provider snapshot manifest contains an invalid field".to_string(),
        ));
    }
    if manifest
        .artifacts
        .iter()
        .map(|artifact| &artifact.relative_path)
        .collect::<BTreeSet<_>>()
        .len()
        != manifest.artifacts.len()
    {
        return Err(ScorchError::Config(
            "provider snapshot manifest contains duplicate artifact paths".to_string(),
        ));
    }
    Ok(())
}

fn validate_staged_artifacts(
    staged_directory: &Path,
    manifest: &SnapshotManifest,
    maximum_bytes: usize,
    includes_manifest: bool,
) -> Result<()> {
    let mut expected = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.relative_path.clone())
        .collect::<BTreeSet<_>>();
    if includes_manifest {
        expected.insert(PathBuf::from("manifest.json"));
    }
    let actual = inventory_regular_files(staged_directory)?;
    if actual != expected {
        return Err(ScorchError::Config(format!(
            "staged provider snapshot contains untracked or missing artifacts: expected {expected:?}, found {actual:?}"
        )));
    }
    for descriptor in &manifest.artifacts {
        let artifact = staged_directory.join(&descriptor.relative_path);
        reject_symlink(&artifact)?;
        let canonical_artifact = artifact.canonicalize()?;
        if !canonical_artifact.starts_with(staged_directory) || !canonical_artifact.is_file() {
            return Err(ScorchError::Config(
                "staged provider artifact escaped its snapshot directory".to_string(),
            ));
        }
        let computed = sha256_file(&canonical_artifact, maximum_bytes)?;
        if computed != descriptor.sha256 {
            return Err(ScorchError::Config(
                "staged provider artifact digest validation failed".to_string(),
            ));
        }
    }
    Ok(())
}

fn inventory_regular_files(root: &Path) -> Result<BTreeSet<PathBuf>> {
    let canonical_root = root.canonicalize()?;
    let mut pending = vec![canonical_root.clone()];
    let mut files = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                return Err(ScorchError::Config(
                    "provider snapshots must not contain symlinks".to_string(),
                ));
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                if files.len() >= MAX_SNAPSHOT_ARTIFACTS.saturating_add(1) {
                    return Err(ScorchError::Config(
                        "provider snapshot contains too many artifacts".to_string(),
                    ));
                }
                let canonical = entry.path().canonicalize()?;
                if !canonical.starts_with(&canonical_root) {
                    return Err(ScorchError::Config(
                        "provider snapshot artifact escaped staging".to_string(),
                    ));
                }
                files.insert(
                    canonical
                        .strip_prefix(&canonical_root)
                        .map_err(|error| ScorchError::Config(error.to_string()))?
                        .to_path_buf(),
                );
            } else {
                return Err(ScorchError::Config(
                    "provider snapshot contains an unsupported filesystem entry".to_string(),
                ));
            }
        }
    }
    Ok(files)
}

fn validate_component(value: &str, label: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(ScorchError::Config(format!("invalid supply-chain {label}")))
    }
}

fn reject_symlink(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(ScorchError::Config(format!(
            "supply-chain cache path '{}' must not be a symlink",
            path.display()
        )));
    }
    Ok(())
}

fn require_canonical_descendant(root: &Path, path: &Path, label: &str) -> Result<PathBuf> {
    reject_symlink(path)?;
    let canonical = path.canonicalize()?;
    if !canonical.is_dir() || !canonical.starts_with(root) {
        return Err(ScorchError::Config(format!(
            "{label} '{}' escaped its protected root",
            path.display()
        )));
    }
    Ok(canonical)
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

fn create_private_directory_if_missing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ScorchError::Config(format!(
                    "supply-chain cache path '{}' must be a directory, not a redirect",
                    path.display()
                )));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(path)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
// JUSTIFICATION: The octal mask directly expresses the security invariant that group and other
// permission bits are absent; a trailing-zero count would hide that filesystem meaning.
#[allow(clippy::verbose_bit_mask)]
fn require_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mode = fs::metadata(path)?.mode();
    if mode & 0o077 == 0 {
        Ok(())
    } else {
        Err(ScorchError::Config(format!(
            "supply-chain cache root '{}' must not grant group or other permissions",
            path.display()
        )))
    }
}

fn read_bounded(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let read_limit = u64::try_from(maximum_bytes.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(maximum_bytes.min(64 * 1024));
    Read::by_ref(&mut file).take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(ScorchError::Config(format!(
            "supply-chain cache metadata '{}' exceeds {maximum_bytes} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn sha256_file(path: &Path, maximum_bytes: usize) -> Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut total = 0usize;
    let mut hasher = Sha256::new();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        if total > maximum_bytes {
            return Err(ScorchError::Config(format!(
                "provider artifact '{}' exceeds {maximum_bytes} bytes",
                path.display()
            )));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn ensure_same_filesystem(left: &Path, right: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if fs::metadata(left)?.dev() != fs::metadata(right)?.dev() {
        return Err(ScorchError::Config(
            "provider snapshot staging must use the cache filesystem".to_string(),
        ));
    }
    Ok(())
}

fn missing_snapshot(provider: &str, path: PathBuf) -> ProviderSnapshot {
    ProviderSnapshot {
        provider: provider.to_string(),
        snapshot_id: "missing".to_string(),
        schema_version: "unknown".to_string(),
        consumer_path: path.clone(),
        canonical_path: path,
        state: ProviderSnapshotState::Missing,
        expected_sha256: String::new(),
        computed_sha256: None,
        upstream_built_at: None,
        checked_at: None,
        maximum_age_seconds: 0,
        validation_error: None,
    }
}

fn invalid_snapshot(provider: &str, path: PathBuf, detail: &str) -> ProviderSnapshot {
    let safe_detail = scorchkit_core::observation::redact_text(detail);
    ProviderSnapshot {
        provider: provider.to_string(),
        snapshot_id: "invalid".to_string(),
        schema_version: "unknown".to_string(),
        consumer_path: path.clone(),
        canonical_path: path,
        state: ProviderSnapshotState::Invalid,
        expected_sha256: String::new(),
        computed_sha256: None,
        upstream_built_at: None,
        checked_at: None,
        maximum_age_seconds: 0,
        validation_error: Some(safe_detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged_snapshot(
        root: &Path,
        provider: &str,
        snapshot_id: &str,
        checked_at: DateTime<Utc>,
    ) -> (PathBuf, SnapshotManifest) {
        let stage = root.join(provider).join("staging").join(snapshot_id);
        fs::create_dir_all(stage.join("cache")).expect("staging directory");
        let artifact = b"provider fixture";
        fs::write(stage.join("cache/database.bin"), artifact).expect("provider artifact");
        let digest = sha256_bytes(artifact);
        (
            stage,
            SnapshotManifest {
                provider: provider.to_string(),
                snapshot_id: snapshot_id.to_string(),
                schema_version: "fixture-v1".to_string(),
                consumer_relative_path: PathBuf::from("cache"),
                artifacts: vec![SnapshotArtifact {
                    relative_path: PathBuf::from("cache/database.bin"),
                    sha256: digest,
                }],
                upstream_built_at: None,
                checked_at,
                maximum_age_seconds: 60,
            },
        )
    }

    #[test]
    fn missing_stale_invalid_and_ready_are_distinct() {
        let root = tempfile::tempdir().expect("cache root");
        #[cfg(unix)]
        fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let store = SupplyChainSnapshotStore::open(root.path(), 1024).expect("store");
        assert_eq!(store.status("osv", Utc::now(), 60).state, ProviderSnapshotState::Missing);

        let now = Utc::now();
        let (stage, manifest) = staged_snapshot(root.path(), "osv", "snapshot-1", now);
        let ready = store.promote(&stage, &manifest).expect("promote");
        assert_eq!(ready.state, ProviderSnapshotState::Ready);
        assert_eq!(
            store.status("osv", now + chrono::Duration::seconds(61), 60).state,
            ProviderSnapshotState::Stale
        );

        fs::write(ready.consumer_path.join("database.bin"), b"tampered").expect("tamper fixture");
        assert_eq!(store.status("osv", now, 60).state, ProviderSnapshotState::Invalid);
    }

    #[test]
    fn failed_promotion_retains_prior_current_snapshot() {
        let root = tempfile::tempdir().expect("cache root");
        #[cfg(unix)]
        fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let store = SupplyChainSnapshotStore::open(root.path(), 1024).expect("store");
        let now = Utc::now();
        let (first_stage, first) = staged_snapshot(root.path(), "grype", "snapshot-1", now);
        let current = store.promote(&first_stage, &first).expect("first promotion");

        let (second_stage, mut second) = staged_snapshot(root.path(), "grype", "snapshot-2", now);
        second.artifacts[0].sha256 = "00".repeat(32);
        assert!(store.promote(&second_stage, &second).is_err());
        let retained = store.status("grype", now, 60);
        assert_eq!(retained.snapshot_id, current.snapshot_id);
        assert_eq!(retained.state, ProviderSnapshotState::Ready);
    }

    #[test]
    fn policy_age_cap_and_upstream_timestamp_control_freshness() {
        let root = tempfile::tempdir().expect("cache root");
        #[cfg(unix)]
        fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let store = SupplyChainSnapshotStore::open(root.path(), 1024).expect("store");
        let now = Utc::now();
        let (stage, mut manifest) = staged_snapshot(root.path(), "osv", "snapshot-policy", now);
        manifest.maximum_age_seconds = 86_400;
        let promoted = store.promote(&stage, &manifest).expect("promote");
        assert_eq!(promoted.state, ProviderSnapshotState::Ready);
        let policy_stale = store.status("osv", now + chrono::Duration::seconds(61), 60);
        assert_eq!(policy_stale.state, ProviderSnapshotState::Stale);
        assert_eq!(policy_stale.maximum_age_seconds, 60);

        let root = tempfile::tempdir().expect("upstream cache root");
        #[cfg(unix)]
        fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let store = SupplyChainSnapshotStore::open(root.path(), 1024).expect("store");
        let (stage, mut manifest) = staged_snapshot(root.path(), "grype", "snapshot-upstream", now);
        manifest.maximum_age_seconds = 86_400;
        manifest.upstream_built_at = Some(now - chrono::Duration::seconds(61));
        let upstream_stale = store.promote(&stage, &manifest).expect("promote");
        assert_eq!(upstream_stale.state, ProviderSnapshotState::Ready);
        assert_eq!(store.status("grype", now, 60).state, ProviderSnapshotState::Stale);
    }

    #[cfg(unix)]
    #[test]
    fn provider_symlink_cannot_redirect_status_or_staging() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("cache root");
        fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let outside = tempfile::tempdir().expect("outside root");
        symlink(outside.path(), root.path().join("osv")).expect("provider symlink");
        let store = SupplyChainSnapshotStore::open(root.path(), 1024).expect("store");

        let status = store.status("osv", Utc::now(), 60);
        assert_eq!(status.state, ProviderSnapshotState::Invalid);
        assert!(store.create_staging("osv", "snapshot-escape").is_err());
        assert!(!outside.path().join("staging").exists());
    }

    #[test]
    fn promotion_rejects_a_valid_snapshot_from_the_wrong_staging_slot() {
        let root = tempfile::tempdir().expect("cache root");
        #[cfg(unix)]
        fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let store = SupplyChainSnapshotStore::open(root.path(), 1024).expect("store");
        let now = Utc::now();
        let (actual_stage, mut manifest) = staged_snapshot(root.path(), "osv", "actual", now);
        manifest.snapshot_id = "expected".to_string();
        fs::create_dir_all(root.path().join("osv/staging/expected")).expect("expected slot");

        assert!(store.promote(&actual_stage, &manifest).is_err());
        assert!(actual_stage.exists());
        assert!(!root.path().join("osv/snapshots/expected").exists());
    }

    #[test]
    fn current_manifest_provider_and_snapshot_identity_are_independently_enforced() {
        for (provider, snapshot_id) in [("other", "snapshot-1"), ("osv", "other-snapshot")] {
            let root = tempfile::tempdir().expect("cache root");
            #[cfg(unix)]
            fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .expect("private cache");
            let store = SupplyChainSnapshotStore::open(root.path(), 1024).expect("store");
            let now = Utc::now();
            let (stage, manifest) = staged_snapshot(root.path(), "osv", "snapshot-1", now);
            store.promote(&stage, &manifest).expect("promote");

            let manifest_path = root.path().join("osv/snapshots/snapshot-1/manifest.json");
            let mut altered: SnapshotManifest =
                serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                    .expect("parse manifest");
            altered.provider = provider.to_string();
            altered.snapshot_id = snapshot_id.to_string();
            let bytes = serde_json::to_vec_pretty(&altered).expect("serialize altered manifest");
            fs::write(&manifest_path, &bytes).expect("write altered manifest");
            let pointer_path = root.path().join("osv/current.json");
            let mut pointer: CurrentPointer =
                serde_json::from_slice(&fs::read(&pointer_path).expect("read pointer"))
                    .expect("parse pointer");
            pointer.manifest_sha256 = sha256_bytes(&bytes);
            fs::write(pointer_path, serde_json::to_vec_pretty(&pointer).unwrap())
                .expect("write pointer");

            assert_eq!(store.status("osv", now, 60).state, ProviderSnapshotState::Invalid);
        }
    }

    #[test]
    fn snapshot_freshness_includes_the_exact_maximum_age_boundary() {
        let root = tempfile::tempdir().expect("cache root");
        #[cfg(unix)]
        fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let store = SupplyChainSnapshotStore::open(root.path(), 1024).expect("store");
        let now = Utc::now();
        let (stage, manifest) = staged_snapshot(root.path(), "osv", "boundary", now);
        store.promote(&stage, &manifest).expect("promote");

        assert_eq!(
            store.status("osv", now + chrono::Duration::seconds(60), 60).state,
            ProviderSnapshotState::Ready
        );
        assert_eq!(
            store.status("osv", now + chrono::Duration::seconds(61), 60).state,
            ProviderSnapshotState::Stale
        );
    }

    #[test]
    fn current_snapshot_consumer_must_be_a_directory_not_an_artifact_file() {
        let root = tempfile::tempdir().expect("cache root");
        #[cfg(unix)]
        fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let store = SupplyChainSnapshotStore::open(root.path(), 1024).expect("store");
        let (stage, mut manifest) =
            staged_snapshot(root.path(), "osv", "file-consumer", Utc::now());
        manifest.consumer_relative_path = PathBuf::from("cache/database.bin");

        assert!(store.promote(&stage, &manifest).is_err());
        assert_eq!(store.status("osv", Utc::now(), 60).state, ProviderSnapshotState::Invalid);
    }

    fn manifest_fixture() -> SnapshotManifest {
        SnapshotManifest {
            provider: "osv".to_string(),
            snapshot_id: "snapshot-1".to_string(),
            schema_version: "v1".to_string(),
            consumer_relative_path: PathBuf::from("cache"),
            artifacts: vec![SnapshotArtifact {
                relative_path: PathBuf::from("cache/database.bin"),
                sha256: "ab".repeat(32),
            }],
            upstream_built_at: None,
            checked_at: Utc::now(),
            maximum_age_seconds: 60,
        }
    }

    #[test]
    fn manifest_shape_rejects_each_invalid_field_and_accepts_the_artifact_limit() {
        assert!(validate_manifest_shape(&manifest_fixture()).is_ok());

        let mut cases = Vec::new();
        let mut invalid = manifest_fixture();
        invalid.provider.clear();
        cases.push(invalid);
        let mut invalid = manifest_fixture();
        invalid.snapshot_id = "..".to_string();
        cases.push(invalid);
        let mut invalid = manifest_fixture();
        invalid.schema_version = "  ".to_string();
        cases.push(invalid);
        let mut invalid = manifest_fixture();
        invalid.consumer_relative_path = PathBuf::from("/absolute");
        cases.push(invalid);
        let mut invalid = manifest_fixture();
        invalid.consumer_relative_path = PathBuf::from("cache/../outside");
        cases.push(invalid);
        let mut invalid = manifest_fixture();
        invalid.artifacts.clear();
        cases.push(invalid);
        let mut invalid = manifest_fixture();
        invalid.artifacts[0].relative_path = PathBuf::from("/absolute");
        cases.push(invalid);
        let mut invalid = manifest_fixture();
        invalid.artifacts[0].relative_path = PathBuf::from("cache/../outside");
        cases.push(invalid);
        let mut invalid = manifest_fixture();
        invalid.artifacts[0].sha256 = "not-a-digest".to_string();
        cases.push(invalid);
        let mut invalid = manifest_fixture();
        invalid.artifacts.push(invalid.artifacts[0].clone());
        cases.push(invalid);
        for invalid in cases {
            assert!(validate_manifest_shape(&invalid).is_err(), "accepted {invalid:?}");
        }

        let mut boundary = manifest_fixture();
        boundary.artifacts = (0..MAX_SNAPSHOT_ARTIFACTS)
            .map(|index| SnapshotArtifact {
                relative_path: PathBuf::from(format!("cache/{index}.bin")),
                sha256: "ab".repeat(32),
            })
            .collect();
        assert!(validate_manifest_shape(&boundary).is_ok());
        boundary.artifacts.push(SnapshotArtifact {
            relative_path: PathBuf::from("cache/overflow.bin"),
            sha256: "ab".repeat(32),
        });
        assert!(validate_manifest_shape(&boundary).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn staged_artifacts_and_cache_ancestors_reject_redirects_and_non_directories() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("fixture root");
        let stage = root.path().join("stage");
        fs::create_dir_all(stage.join("cache")).expect("stage");
        let outside = root.path().join("outside.bin");
        fs::write(&outside, b"provider fixture").expect("outside artifact");
        symlink(&outside, stage.join("cache/database.bin")).expect("artifact symlink");
        assert!(validate_staged_artifacts(&stage, &manifest_fixture(), 1024, false).is_err());

        let file = root.path().join("file");
        fs::write(&file, b"not a directory").expect("file fixture");
        assert!(require_canonical_descendant(root.path(), &file, "fixture").is_err());
        assert!(create_private_directory_if_missing(&file).is_err());
        let redirected = root.path().join("redirected");
        symlink(root.path(), &redirected).expect("directory symlink");
        assert!(create_private_directory_if_missing(&redirected).is_err());
    }

    #[test]
    fn component_digest_and_bounded_file_helpers_enforce_exact_boundaries() {
        for valid in ["osv", "snapshot-1", "A_b.c"] {
            assert!(validate_component(valid, "fixture").is_ok());
        }
        for invalid in ["", ".", "..", "has/slash", "has space"] {
            assert!(validate_component(invalid, "fixture").is_err());
        }
        assert!(is_sha256(&"ab".repeat(32)));
        assert!(is_sha256(&"AB".repeat(32)));
        assert!(!is_sha256(&"ab".repeat(31)));
        assert!(!is_sha256(&format!("{}g", "a".repeat(63))));

        let root = tempfile::tempdir().expect("fixture root");
        let file = root.path().join("bounded.bin");
        fs::write(&file, b"1234").expect("file fixture");
        assert_eq!(read_bounded(&file, 4).expect("exact bounded read"), b"1234");
        assert!(read_bounded(&file, 3).is_err());
        assert_eq!(sha256_file(&file, 4).expect("exact bounded hash"), sha256_bytes(b"1234"));
        assert!(sha256_file(&file, 3).is_err());
        assert!(sync_directory(&root.path().join("missing")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_and_filesystem_guards_are_effective() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("fixture root");
        fs::set_permissions(root.path(), PermissionsExt::from_mode(0o700)).expect("private mode");
        assert!(require_private_directory(root.path()).is_ok());
        fs::set_permissions(root.path(), PermissionsExt::from_mode(0o750)).expect("shared mode");
        assert!(require_private_directory(root.path()).is_err());

        if Path::new("/dev/shm").is_dir() {
            assert!(ensure_same_filesystem(root.path(), Path::new("/dev/shm")).is_err());
        }
    }

    #[test]
    fn layered_cache_guards_remain_explicit_even_when_prior_checks_make_them_redundant() {
        let production = include_str!("cache.rs").split("#[cfg(test)]").next().unwrap();
        let compact: String = production.split_whitespace().collect();
        for invariant in [
            "canonical_stage!=expected_stage.canonicalize()?||!canonical_stage.starts_with(&staging_root.canonicalize()?)||!canonical_stage.starts_with(&self.root)",
            "if!canonical_consumer.starts_with(&canonical_snapshot)||!canonical_consumer.is_dir()",
            "if!canonical_artifact.starts_with(staged_directory)||!canonical_artifact.is_file()",
            "Err(error)iferror.kind()==std::io::ErrorKind::NotFound=>",
        ] {
            assert!(compact.contains(invariant), "cache guard changed: {invariant}");
        }
    }
}
