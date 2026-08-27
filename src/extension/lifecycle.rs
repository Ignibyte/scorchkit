use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use scorchkit_core::sha256_hex;
use scorchkit_extension::{
    ExtensionApprovalV1, ExtensionCatalogCheckpointV1, ExtensionLifecycleStateV1,
    ExtensionLifecycleTransitionV1, ExtensionPermissionChangeV1, ExtensionPermissionsV1,
    EXTENSION_APPROVAL_SCHEMA_V1, EXTENSION_LIFECYCLE_STATE_SCHEMA_V1, MAX_EXTENSION_CATALOG_BYTES,
    MAX_EXTENSION_LIFECYCLE_TRANSITIONS,
};
use serde::Serialize;

use crate::config::ExtensionConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::policy::{Capability, EffectClass, Engagement, PolicyTarget};

use super::catalog_host::{
    catalog_error, catalog_is_present, permission_sha256, require_not_revoked,
    validate_module_health, verify_catalog, verify_release, CatalogExecutionIdentity,
    VerifiedRelease,
};
use super::loader::{open_bounded, LoadedExtension};

const STATE_FILE: &str = "state.json";
const APPROVALS_DIRECTORY: &str = "approvals";
const LOCK_FILE: &str = ".lifecycle.lock";

struct LifecycleLock {
    file: File,
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogPreview {
    pub catalog_id: String,
    pub publisher_id: String,
    pub key_id: String,
    pub catalog_sequence: u64,
    pub payload_sha256: String,
    pub release_id: String,
    pub extension_id: String,
    pub version: String,
    pub manifest_sha256: String,
    pub module_sha256: String,
    pub minimum_engine_version: String,
    pub maximum_engine_version_exclusive: String,
    pub permissions_sha256: String,
    pub provenance: scorchkit_extension::ExtensionReleaseProvenanceV1,
    pub conformance: scorchkit_extension::ExtensionConformanceV1,
    pub permission_changes: Vec<ExtensionPermissionChangeV1>,
    pub permission_diff_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogStatus {
    pub active: std::collections::BTreeMap<String, String>,
    pub transitions: Vec<ExtensionLifecycleTransitionV1>,
}

/// Policy-authorized local lifecycle controller for signed extension releases.
pub struct CatalogLifecycle<'a> {
    config: &'a ExtensionConfig,
    engagement: &'a Engagement,
}

impl<'a> CatalogLifecycle<'a> {
    #[must_use]
    pub const fn new(config: &'a ExtensionConfig, engagement: &'a Engagement) -> Self {
        Self { config, engagement }
    }

    /// Verify one signed release and return the exact review surface without writing state.
    ///
    /// # Errors
    ///
    /// Returns a bounded trust, signature, artifact, policy, or permission validation error.
    pub fn inspect(&self, catalog_path: &Path, release_id: &str) -> Result<CatalogPreview> {
        self.prepare(catalog_path, release_id).map(|(_, preview)| preview)
    }

    /// Create an immutable approval bound to the candidate and exact permission difference.
    ///
    /// # Errors
    ///
    /// Returns an error when verification, replay defense, authorization, or durable publication
    /// fails.
    pub fn approve(
        &self,
        catalog_path: &Path,
        release_id: &str,
        expected_payload_sha256: &str,
        expected_permission_diff_sha256: &str,
    ) -> Result<ExtensionApprovalV1> {
        let root = self.ensure_layout()?;
        let _lock = acquire_lifecycle_lock(self.engagement, &root)?;
        let (verified, preview) = self.prepare(catalog_path, release_id)?;
        if preview.payload_sha256 != expected_payload_sha256
            || preview.permission_diff_sha256 != expected_permission_diff_sha256
        {
            return Err(catalog_error(
                "approval does not match the inspected payload and permission difference",
            ));
        }
        let mut approval = ExtensionApprovalV1 {
            schema_version: EXTENSION_APPROVAL_SCHEMA_V1.to_string(),
            approval_id: String::new(),
            approved_at: Utc::now().to_rfc3339(),
            catalog_path: verified.catalog_path.to_string_lossy().into_owned(),
            catalog_id: verified.payload.catalog_id.clone(),
            publisher_id: verified.payload.publisher_id.clone(),
            key_id: verified.key_id,
            catalog_sequence: verified.payload.sequence,
            payload_sha256: verified.payload_sha256,
            release: verified.release,
            manifest_path: verified.loaded.manifest_path.to_string_lossy().into_owned(),
            module_path: verified.loaded.module_path.to_string_lossy().into_owned(),
            permission_changes: preview.permission_changes,
            permission_diff_sha256: preview.permission_diff_sha256,
        };
        approval.approval_id = approval_digest(&approval)?;
        let mut state = self.read_state()?.unwrap_or_default();
        if let Some(checkpoint) = state.catalog_checkpoints.get(&approval.catalog_id) {
            match approval.catalog_sequence.cmp(&checkpoint.sequence) {
                std::cmp::Ordering::Less => {
                    return Err(catalog_error("catalog sequence replay was rejected"));
                }
                std::cmp::Ordering::Equal
                    if approval.payload_sha256 != checkpoint.payload_sha256 =>
                {
                    return Err(catalog_error(
                        "catalog sequence payload equivocation was rejected",
                    ));
                }
                std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {}
            }
        }
        let approval_path = approval_path(&root, &approval.approval_id)?;
        write_immutable_json(self.engagement, &approval_path, &approval)?;
        state.catalog_checkpoints.insert(
            approval.catalog_id.clone(),
            ExtensionCatalogCheckpointV1 {
                sequence: approval.catalog_sequence,
                payload_sha256: approval.payload_sha256.clone(),
            },
        );
        let active = state.active.get(&approval.release.extension_id).cloned();
        append_transition(
            &mut state,
            "approve",
            &approval.release.extension_id,
            active,
            Some(approval.approval_id.clone()),
        )?;
        self.write_state(&state)?;
        Ok(approval)
    }

    /// Atomically activate one exact approval after revalidation and structural startup health.
    ///
    /// # Errors
    ///
    /// Returns an error without changing the active pointer if any revalidation or write fails.
    pub fn activate(&self, approval_id: &str) -> Result<CatalogStatus> {
        self.change_active("activate", None, approval_id)
    }

    /// Explicitly reactivate one prior exact approval for the supplied extension identity.
    ///
    /// # Errors
    ///
    /// Returns an error without changing state if the approval is unavailable, mismatched,
    /// revoked, changed, or unhealthy.
    pub fn rollback(&self, extension_id: &str, approval_id: &str) -> Result<CatalogStatus> {
        self.change_active("rollback", Some(extension_id), approval_id)
    }

    /// Read the current pointers and append-preserved lifecycle transitions.
    ///
    /// # Errors
    ///
    /// Returns an authorization, I/O, schema, or state-integrity error.
    pub fn status(&self) -> Result<CatalogStatus> {
        let state = self.read_state()?.unwrap_or_default();
        Ok(CatalogStatus { active: state.active, transitions: state.transitions })
    }

    /// Load every active exact release without requiring its catalog to be online.
    /// Reopen all active exact artifacts for registration, retaining catalog provenance.
    ///
    /// # Errors
    ///
    /// Returns an error if state, approval, artifact, policy, or current revocation checks fail.
    pub fn load_active(&self) -> Result<Vec<LoadedExtension>> {
        let Some(state) = self.read_state()? else {
            return Ok(Vec::new());
        };
        let mut loaded = Vec::with_capacity(state.active.len());
        for (extension_id, approval_id) in state.active {
            let approval = self.read_approval(&approval_id)?;
            if approval.release.extension_id != extension_id {
                return Err(catalog_error("active extension pointer identity mismatch"));
            }
            let checkpoint =
                state.catalog_checkpoints.get(&approval.catalog_id).cloned().unwrap_or_else(|| {
                    ExtensionCatalogCheckpointV1 {
                        sequence: approval.catalog_sequence,
                        payload_sha256: approval.payload_sha256.clone(),
                    }
                });
            loaded.push(self.load_approved(&approval, &checkpoint)?);
        }
        Ok(loaded)
    }

    fn prepare(
        &self,
        catalog_path: &Path,
        release_id: &str,
    ) -> Result<(VerifiedRelease, CatalogPreview)> {
        let verified =
            verify_release(self.config, self.engagement, catalog_path, release_id, Utc::now())?;
        let prior = self.active_permissions(&verified.release.extension_id)?;
        let changes = permission_changes(prior.as_ref(), &verified.release.permissions)?;
        let diff_bytes = serde_json::to_vec(&changes)
            .map_err(|_| catalog_error("permission difference cannot be encoded"))?;
        let preview = CatalogPreview {
            catalog_id: verified.payload.catalog_id.clone(),
            publisher_id: verified.payload.publisher_id.clone(),
            key_id: verified.key_id.clone(),
            catalog_sequence: verified.payload.sequence,
            payload_sha256: verified.payload_sha256.clone(),
            release_id: verified.release.release_id.clone(),
            extension_id: verified.release.extension_id.clone(),
            version: verified.release.version.clone(),
            manifest_sha256: verified.release.manifest_sha256.clone(),
            module_sha256: verified.release.module_sha256.clone(),
            minimum_engine_version: verified
                .loaded
                .manifest
                .compatibility
                .minimum_engine_version
                .clone(),
            maximum_engine_version_exclusive: verified
                .loaded
                .manifest
                .compatibility
                .maximum_engine_version_exclusive
                .clone(),
            permissions_sha256: verified.release.permissions_sha256.clone(),
            provenance: verified.release.provenance.clone(),
            conformance: verified.release.conformance.clone(),
            permission_changes: changes,
            permission_diff_sha256: sha256_hex(&diff_bytes),
        };
        Ok((verified, preview))
    }

    fn active_permissions(&self, extension_id: &str) -> Result<Option<ExtensionPermissionsV1>> {
        let Some(state) = self.read_state()? else {
            return Ok(None);
        };
        state
            .active
            .get(extension_id)
            .map(|approval_id| {
                self.read_approval(approval_id).map(|value| value.release.permissions)
            })
            .transpose()
    }

    fn change_active(
        &self,
        action: &str,
        required_extension_id: Option<&str>,
        approval_id: &str,
    ) -> Result<CatalogStatus> {
        let root = self.ensure_layout()?;
        let _lock = acquire_lifecycle_lock(self.engagement, &root)?;
        let approval = self.read_approval(approval_id)?;
        if required_extension_id.is_some_and(|value| value != approval.release.extension_id) {
            return Err(catalog_error("rollback extension identity does not match its approval"));
        }
        let mut state = self.read_state()?.unwrap_or_default();
        if !state.transitions.iter().any(|transition| {
            transition.action == "approve"
                && transition.extension_id == approval.release.extension_id
                && transition.to_approval_id.as_deref() == Some(approval_id)
        }) {
            return Err(catalog_error("approval is not committed in lifecycle history"));
        }
        let checkpoint =
            state.catalog_checkpoints.get(&approval.catalog_id).cloned().unwrap_or_else(|| {
                ExtensionCatalogCheckpointV1 {
                    sequence: approval.catalog_sequence,
                    payload_sha256: approval.payload_sha256.clone(),
                }
            });
        let loaded = self.load_approved(&approval, &checkpoint)?;
        validate_module_health(&loaded)?;
        let from = state.active.get(&approval.release.extension_id).cloned();
        append_transition(
            &mut state,
            action,
            &approval.release.extension_id,
            from,
            Some(approval.approval_id.clone()),
        )?;
        state.active.insert(approval.release.extension_id.clone(), approval.approval_id.clone());
        self.write_state(&state)?;
        Ok(CatalogStatus { active: state.active, transitions: state.transitions })
    }

    fn load_approved(
        &self,
        approval: &ExtensionApprovalV1,
        checkpoint: &ExtensionCatalogCheckpointV1,
    ) -> Result<LoadedExtension> {
        validate_approval(approval)?;
        let manifest_path = PathBuf::from(&approval.manifest_path);
        let mut loaded = LoadedExtension::load_authorized(self.config, &manifest_path, &|path| {
            authorize(self.engagement, path, EffectClass::Passive, true)
        })?;
        loaded.require_v1_web_adapter()?;
        if loaded.module_path.as_path() != Path::new(&approval.module_path)
            || sha256_hex(&loaded.manifest_bytes) != approval.release.manifest_sha256
            || loaded.manifest.module.sha256 != approval.release.module_sha256
            || loaded.manifest.id != approval.release.extension_id
            || loaded.manifest.version != approval.release.version
            || ExtensionPermissionsV1::from_manifest(
                &loaded.manifest,
                approval.release.permissions.network_endpoints.clone(),
            ) != approval.release.permissions
            || permission_sha256(&approval.release.permissions)?
                != approval.release.permissions_sha256
        {
            return Err(catalog_error("approved extension artifact changed after approval"));
        }
        let catalog_path = PathBuf::from(&approval.catalog_path);
        if catalog_is_present(&catalog_path)? {
            let catalog = verify_catalog(self.config, self.engagement, &catalog_path, Utc::now())?;
            let sequence_is_valid = match catalog.payload.sequence.cmp(&checkpoint.sequence) {
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => catalog.payload_sha256 == checkpoint.payload_sha256,
                std::cmp::Ordering::Greater => true,
            };
            if catalog.payload.catalog_id != approval.catalog_id
                || catalog.payload.publisher_id != approval.publisher_id
                || !sequence_is_valid
            {
                return Err(catalog_error(
                    "current catalog regressed or changed publisher identity",
                ));
            }
            require_not_revoked(&catalog, &approval.release.release_id, &approval.key_id)?;
        }
        loaded.catalog_identity = Some(CatalogExecutionIdentity {
            approval_id: approval.approval_id.clone(),
            catalog_path,
            catalog_id: approval.catalog_id.clone(),
            publisher_id: approval.publisher_id.clone(),
            key_id: approval.key_id.clone(),
            catalog_sequence: checkpoint.sequence,
            catalog_checkpoint_sha256: checkpoint.payload_sha256.clone(),
            payload_sha256: approval.payload_sha256.clone(),
            release_id: approval.release.release_id.clone(),
            manifest_sha256: approval.release.manifest_sha256.clone(),
            permissions_sha256: approval.release.permissions_sha256.clone(),
            provenance_revision: approval.release.provenance.revision.clone(),
            provenance_build_sha256: approval.release.provenance.build_sha256.clone(),
            conformance_report_sha256: approval.release.conformance.report_sha256.clone(),
            network_endpoints: approval.release.permissions.network_endpoints.clone(),
        });
        Ok(loaded)
    }

    fn read_approval(&self, approval_id: &str) -> Result<ExtensionApprovalV1> {
        let root = self.root()?;
        let path = approval_path(&root, approval_id)?;
        require_private_regular_file(&path)?;
        let (_, bytes) = open_bounded(&path, MAX_EXTENSION_CATALOG_BYTES, &|path| {
            authorize(self.engagement, path, EffectClass::Passive, false)
        })?;
        let approval: ExtensionApprovalV1 = serde_json::from_slice(&bytes)
            .map_err(|_| catalog_error("approval record JSON is invalid"))?;
        validate_approval(&approval)?;
        if approval.approval_id != approval_id {
            return Err(catalog_error("approval filename and identity differ"));
        }
        Ok(approval)
    }

    fn read_state(&self) -> Result<Option<ExtensionLifecycleStateV1>> {
        let root = self.root()?;
        let path = root.join(STATE_FILE);
        if !path.exists() {
            return Ok(None);
        }
        require_private_regular_file(&path)?;
        let (_, bytes) = open_bounded(&path, MAX_EXTENSION_CATALOG_BYTES, &|path| {
            authorize(self.engagement, path, EffectClass::Passive, false)
        })?;
        let state: ExtensionLifecycleStateV1 = serde_json::from_slice(&bytes)
            .map_err(|_| catalog_error("extension lifecycle state JSON is invalid"))?;
        validate_state(&state)?;
        Ok(Some(state))
    }

    fn write_state(&self, state: &ExtensionLifecycleStateV1) -> Result<()> {
        validate_state(state)?;
        let root = self.ensure_layout()?;
        atomic_write_json(self.engagement, &root.join(STATE_FILE), state)
    }

    fn root(&self) -> Result<PathBuf> {
        self.config.validate().map_err(|reason| {
            ScorchError::Config(format!("invalid extension configuration: {reason}"))
        })?;
        let root = self
            .config
            .lifecycle_root
            .as_ref()
            .ok_or_else(|| catalog_error("extension lifecycle root is not configured"))?;
        if root.is_absolute() {
            Ok(root.clone())
        } else {
            std::env::current_dir().map(|current| current.join(root)).map_err(ScorchError::from)
        }
    }

    fn ensure_layout(&self) -> Result<PathBuf> {
        let root = self.root()?;
        ensure_private_directory(self.engagement, &root)?;
        ensure_private_directory(self.engagement, &root.join(APPROVALS_DIRECTORY))?;
        Ok(root)
    }
}

fn validate_approval(approval: &ExtensionApprovalV1) -> Result<()> {
    if approval.schema_version != EXTENSION_APPROVAL_SCHEMA_V1
        || approval.approval_id != approval_digest(approval)?
        || approval.release.permissions_sha256 != permission_sha256(&approval.release.permissions)?
        || approval.release.validate_shape().is_err()
        || !valid_id(&approval.catalog_id)
        || !valid_id(&approval.publisher_id)
        || !valid_id(&approval.key_id)
        || approval.catalog_sequence == 0
        || !Path::new(&approval.catalog_path).is_absolute()
        || !Path::new(&approval.manifest_path).is_absolute()
        || !Path::new(&approval.module_path).is_absolute()
        || chrono::DateTime::parse_from_rfc3339(&approval.approved_at).is_err()
    {
        return Err(catalog_error("approval record integrity check failed"));
    }
    let changes = serde_json::to_vec(&approval.permission_changes)
        .map_err(|_| catalog_error("approval permission difference cannot be encoded"))?;
    if sha256_hex(&changes) != approval.permission_diff_sha256 {
        return Err(catalog_error("approval permission difference digest mismatch"));
    }
    Ok(())
}

fn approval_digest(approval: &ExtensionApprovalV1) -> Result<String> {
    let mut subject = approval.clone();
    subject.approval_id.clear();
    serde_json::to_vec(&subject)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| catalog_error("approval subject cannot be encoded"))
}

fn validate_state(state: &ExtensionLifecycleStateV1) -> Result<()> {
    if state.schema_version != EXTENSION_LIFECYCLE_STATE_SCHEMA_V1
        || state.transitions.len() > MAX_EXTENSION_LIFECYCLE_TRANSITIONS
        || state.catalog_checkpoints.iter().any(|(catalog_id, checkpoint)| {
            !valid_id(catalog_id)
                || checkpoint.sequence == 0
                || !valid_sha256(&checkpoint.payload_sha256)
        })
        || state.active.iter().any(|(extension_id, approval_id)| {
            !valid_id(extension_id) || !valid_sha256(approval_id)
        })
        || !state.transitions.iter().enumerate().all(|(index, value)| {
            value.sequence == u64::try_from(index).unwrap_or(u64::MAX) + 1
                && matches!(value.action.as_str(), "approve" | "activate" | "rollback")
                && valid_id(&value.extension_id)
                && value.from_approval_id.as_deref().is_none_or(valid_sha256)
                && value.to_approval_id.as_deref().is_none_or(valid_sha256)
                && chrono::DateTime::parse_from_rfc3339(&value.occurred_at).is_ok()
        })
    {
        return Err(catalog_error("extension lifecycle state integrity check failed"));
    }
    let mut approved = std::collections::BTreeMap::<&str, std::collections::BTreeSet<&str>>::new();
    let mut approval_identities = std::collections::BTreeSet::<&str>::new();
    let mut reconstructed = std::collections::BTreeMap::<&str, &str>::new();
    for transition in &state.transitions {
        let current = reconstructed.get(transition.extension_id.as_str()).copied();
        if transition.from_approval_id.as_deref() != current {
            return Err(catalog_error("extension lifecycle state history is inconsistent"));
        }
        let Some(next) = transition.to_approval_id.as_deref() else {
            return Err(catalog_error("extension lifecycle transition has no approval subject"));
        };
        if transition.action == "approve" {
            if !approval_identities.insert(next)
                || !approved.entry(&transition.extension_id).or_default().insert(next)
            {
                return Err(catalog_error("extension lifecycle approval history is duplicated"));
            }
        } else {
            if !approved
                .get(transition.extension_id.as_str())
                .is_some_and(|values| values.contains(next))
            {
                return Err(catalog_error("active lifecycle pointer was never approved"));
            }
            reconstructed.insert(&transition.extension_id, next);
        }
    }
    if reconstructed.len() != state.active.len()
        || state.active.iter().any(|(extension_id, approval_id)| {
            reconstructed.get(extension_id.as_str()).copied() != Some(approval_id.as_str())
        })
    {
        return Err(catalog_error("active lifecycle pointers do not match their history"));
    }
    Ok(())
}

fn append_transition(
    state: &mut ExtensionLifecycleStateV1,
    action: &str,
    extension_id: &str,
    from_approval_id: Option<String>,
    to_approval_id: Option<String>,
) -> Result<()> {
    if state.transitions.len() >= MAX_EXTENSION_LIFECYCLE_TRANSITIONS {
        return Err(catalog_error("extension lifecycle transition boundary is exhausted"));
    }
    let sequence = u64::try_from(state.transitions.len())
        .map_err(|_| catalog_error("extension lifecycle sequence overflowed"))?
        + 1;
    state.transitions.push(ExtensionLifecycleTransitionV1 {
        sequence,
        occurred_at: Utc::now().to_rfc3339(),
        action: action.to_string(),
        extension_id: extension_id.to_string(),
        from_approval_id,
        to_approval_id,
    });
    Ok(())
}

fn permission_changes(
    prior: Option<&ExtensionPermissionsV1>,
    candidate: &ExtensionPermissionsV1,
) -> Result<Vec<ExtensionPermissionChangeV1>> {
    let mut changes = Vec::new();
    let empty_targets = Vec::new();
    let empty_capabilities = Vec::new();
    let empty_endpoints = Vec::new();
    let before_targets =
        prior.map_or(empty_targets.as_slice(), |value| value.target_kinds.as_slice());
    let before_capabilities =
        prior.map_or(empty_capabilities.as_slice(), |value| value.capabilities.as_slice());
    let before_endpoints =
        prior.map_or(empty_endpoints.as_slice(), |value| value.network_endpoints.as_slice());
    push_set_change(&mut changes, "target_kinds", before_targets, &candidate.target_kinds)?;
    push_change(
        &mut changes,
        "strongest_effect",
        prior.map(|value| &value.strongest_effect),
        &candidate.strongest_effect,
        prior.is_none_or(|value| candidate.strongest_effect > value.strongest_effect),
    )?;
    push_set_change(&mut changes, "capabilities", before_capabilities, &candidate.capabilities)?;
    push_set_change(
        &mut changes,
        "network_endpoints",
        before_endpoints,
        &candidate.network_endpoints,
    )?;
    macro_rules! budget {
        ($field:ident) => {
            push_change(
                &mut changes,
                concat!("budgets.", stringify!($field)),
                prior.map(|value| &value.budgets.$field),
                &candidate.budgets.$field,
                prior.is_none_or(|value| candidate.budgets.$field > value.budgets.$field),
            )?;
        };
    }
    budget!(timeout_ms);
    budget!(fuel);
    budget!(memory_bytes);
    budget!(input_bytes);
    budget!(output_bytes);
    budget!(effects);
    budget!(artifact_bytes);
    budget!(artifacts);
    Ok(changes)
}

fn push_set_change<T: Serialize + PartialEq>(
    output: &mut Vec<ExtensionPermissionChangeV1>,
    field: &str,
    before: &[T],
    after: &[T],
) -> Result<()> {
    if before == after {
        return Ok(());
    }
    let widened = after.iter().any(|item| !before.contains(item));
    output.push(ExtensionPermissionChangeV1 {
        field: field.to_string(),
        before: json_string(before)?,
        after: json_string(after)?,
        widened,
    });
    Ok(())
}

fn push_change<T: Serialize + PartialEq>(
    output: &mut Vec<ExtensionPermissionChangeV1>,
    field: &str,
    before: Option<&T>,
    after: &T,
    widened: bool,
) -> Result<()> {
    if before == Some(after) {
        return Ok(());
    }
    output.push(ExtensionPermissionChangeV1 {
        field: field.to_string(),
        before: before.map_or_else(|| Ok("null".to_string()), json_string)?,
        after: json_string(after)?,
        widened,
    });
    Ok(())
}

fn json_string<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    serde_json::to_string(value)
        .map_err(|_| catalog_error("permission difference value cannot be encoded"))
}

fn approval_path(root: &Path, approval_id: &str) -> Result<PathBuf> {
    if !valid_sha256(approval_id) {
        return Err(catalog_error("approval identity is invalid"));
    }
    Ok(root.join(APPROVALS_DIRECTORY).join(format!("{approval_id}.json")))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= scorchkit_extension::MAX_EXTENSION_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b'/')
        })
}

fn ensure_private_directory(engagement: &Engagement, path: &Path) -> Result<()> {
    authorize(engagement, path, EffectClass::ActiveSafe, false)?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => return require_private_directory_metadata(&metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        if let Err(error) = builder.create(path) {
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error.into());
            }
        }
    }
    #[cfg(any(not(unix), test))]
    if let Err(error) = std::fs::create_dir(path) {
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
    }
    let metadata = std::fs::symlink_metadata(path)?;
    require_private_directory_metadata(&metadata)
}

fn require_private_directory_metadata(metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(catalog_error("lifecycle path is not a regular directory"));
    }
    require_private_mode(metadata)
}

fn acquire_lifecycle_lock(engagement: &Engagement, root: &Path) -> Result<LifecycleLock> {
    let path = root.join(LOCK_FILE);
    authorize(engagement, &path, EffectClass::ActiveSafe, false)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&path)?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Err(catalog_error("extension lifecycle lock is not a regular file"));
    }
    require_private_mode(&opened)?;
    fs2::FileExt::lock_exclusive(&file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current = std::fs::metadata(&path)?;
        if opened.dev() != current.dev() || opened.ino() != current.ino() {
            return Err(catalog_error("extension lifecycle lock changed during acquisition"));
        }
    }
    Ok(LifecycleLock { file })
}

fn write_immutable_json<T: Serialize>(
    engagement: &Engagement,
    path: &Path,
    value: &T,
) -> Result<()> {
    authorize(engagement, path, EffectClass::ActiveSafe, false)?;
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| catalog_error("lifecycle record cannot be encoded"))?;
    match private_create_new(path) {
        Ok(mut file) => {
            file.write_all(&bytes)?;
            file.sync_all()?;
            sync_parent(path)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            require_private_regular_file(path)?;
            let (_, existing) = open_bounded(path, MAX_EXTENSION_CATALOG_BYTES, &|path| {
                authorize(engagement, path, EffectClass::Passive, false)
            })?;
            if existing == bytes {
                Ok(())
            } else {
                Err(catalog_error("immutable approval already exists with different bytes"))
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn atomic_write_json<T: Serialize>(engagement: &Engagement, path: &Path, value: &T) -> Result<()> {
    authorize(engagement, path, EffectClass::ActiveSafe, false)?;
    if path.exists() && std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(catalog_error("lifecycle state destination is a symlink"));
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| catalog_error("lifecycle state cannot be encoded"))?;
    let parent = path.parent().ok_or_else(|| catalog_error("lifecycle state has no parent"))?;
    let temporary = parent.join(format!(".state-{}.tmp", uuid::Uuid::new_v4()));
    authorize(engagement, &temporary, EffectClass::ActiveSafe, false)?;
    let mut file = private_create_new(&temporary)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    drop(file);
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    sync_parent(path)
}

fn private_create_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(0o400_000);
    }
    options.open(path)
}

fn require_private_regular_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(catalog_error("lifecycle record is not a regular file"));
    }
    require_private_mode(&metadata)
}

fn require_private_mode(metadata: &std::fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(catalog_error("lifecycle state permissions or owner are not private"));
        }
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| catalog_error("lifecycle path has no parent"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn authorize(
    engagement: &Engagement,
    path: &Path,
    effect: EffectClass,
    extension: bool,
) -> Result<()> {
    let policy_path = if path.exists() {
        path
    } else {
        path.parent().ok_or_else(|| catalog_error("new lifecycle path has no parent"))?
    };
    let target = PolicyTarget::Code(policy_path.to_path_buf());
    engagement.authorize(target.clone(), Capability::LocalState, effect).require()?;
    if extension {
        engagement.authorize(target, Capability::ExtensionExecute, effect).require()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_difference_covers_every_widening_and_narrowing_axis() {
        let manifest = crate::extension::test_support::manifest(b"module");
        let prior =
            ExtensionPermissionsV1::from_manifest(&manifest, vec!["http://127.0.0.1".to_string()]);
        assert!(permission_changes(Some(&prior), &prior).expect("unchanged difference").is_empty());

        let mut candidate = prior.clone();
        candidate.target_kinds.push(scorchkit_core::AdapterTargetKind::Api);
        candidate.strongest_effect = EffectClass::Intrusive;
        candidate.capabilities.push(scorchkit_extension::ExtensionCapabilityV1::Filesystem);
        candidate.network_endpoints.push("https://example.com".to_string());
        candidate.budgets.timeout_ms += 1;
        candidate.budgets.fuel += 1;
        candidate.budgets.memory_bytes += 1;
        candidate.budgets.input_bytes += 1;
        candidate.budgets.output_bytes += 1;
        candidate.budgets.effects += 1;
        candidate.budgets.artifact_bytes += 1;
        candidate.budgets.artifacts += 1;

        let widened = permission_changes(Some(&prior), &candidate).expect("widening difference");
        assert_eq!(widened.len(), 12);
        assert!(widened.iter().all(|change| change.widened));
        assert_eq!(
            widened.iter().map(|change| change.field.as_str()).collect::<Vec<_>>(),
            vec![
                "target_kinds",
                "strongest_effect",
                "capabilities",
                "network_endpoints",
                "budgets.timeout_ms",
                "budgets.fuel",
                "budgets.memory_bytes",
                "budgets.input_bytes",
                "budgets.output_bytes",
                "budgets.effects",
                "budgets.artifact_bytes",
                "budgets.artifacts",
            ]
        );

        let narrowed = permission_changes(Some(&candidate), &prior).expect("narrowing difference");
        assert_eq!(narrowed.len(), 12);
        assert!(narrowed.iter().all(|change| !change.widened));
    }

    fn engagement_for(root: &Path) -> std::result::Result<Engagement, Box<dyn std::error::Error>> {
        let policy = crate::engine::policy::EngagementPolicy::default()
            .allow_scope(crate::engine::scope::ScopeRule::path_prefix(root)?)
            .allow_capability(Capability::LocalState)
            .allow_capability(Capability::ExtensionExecute)
            .allow_effect(EffectClass::Passive)
            .allow_effect(EffectClass::ActiveSafe);
        Ok(Engagement::new("lifecycle-unit", policy))
    }

    fn approval_for(
        root: &Path,
    ) -> std::result::Result<ExtensionApprovalV1, Box<dyn std::error::Error>> {
        let module = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "scorchkit_abi_version") (result i32) i32.const 1)
                (func (export "scorchkit_reserve_input") (param i32) (result i32) i32.const 1024)
                (func (export "scorchkit_run") (param i32) (result i64) i64.const 1)
            )"#,
        )?;
        let manifest = crate::extension::test_support::manifest(&module);
        let manifest_path = root.join("fixture.json");
        let module_path = root.join("fixture.wasm");
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        std::fs::write(&manifest_path, &manifest_bytes)?;
        std::fs::write(&module_path, &module)?;
        let permissions = ExtensionPermissionsV1::from_manifest(
            &manifest,
            vec!["https://example.com".to_string()],
        );
        let permission_changes = Vec::new();
        let mut approval = ExtensionApprovalV1 {
            schema_version: EXTENSION_APPROVAL_SCHEMA_V1.to_string(),
            approval_id: String::new(),
            approved_at: "2026-08-26T12:00:00Z".to_string(),
            catalog_path: root.join("offline-catalog.json").to_string_lossy().into_owned(),
            catalog_id: "fixture.catalog".to_string(),
            publisher_id: "fixture.publisher".to_string(),
            key_id: "fixture.key".to_string(),
            catalog_sequence: 1,
            payload_sha256: "a".repeat(64),
            release: scorchkit_extension::ExtensionCatalogReleaseV1 {
                release_id: "fixture.release".to_string(),
                extension_id: manifest.id.clone(),
                version: manifest.version.clone(),
                manifest_file: "fixture.json".to_string(),
                manifest_sha256: sha256_hex(&manifest_bytes),
                module_sha256: manifest.module.sha256,
                permissions_sha256: permission_sha256(&permissions)?,
                permissions,
                provenance: scorchkit_extension::ExtensionReleaseProvenanceV1 {
                    source: "unit fixture".to_string(),
                    revision: "revision-1".to_string(),
                    build_sha256: "b".repeat(64),
                },
                conformance: scorchkit_extension::ExtensionConformanceV1 {
                    suite: "scorchkit.conformance/v1".to_string(),
                    passed: true,
                    report_sha256: "c".repeat(64),
                },
            },
            manifest_path: manifest_path.canonicalize()?.to_string_lossy().into_owned(),
            module_path: module_path.canonicalize()?.to_string_lossy().into_owned(),
            permission_diff_sha256: sha256_hex(&serde_json::to_vec(&permission_changes)?),
            permission_changes,
        };
        approval.approval_id = approval_digest(&approval)?;
        Ok(approval)
    }

    fn rehash(approval: &mut ExtensionApprovalV1) {
        approval.approval_id = approval_digest(approval).expect("approval digest");
    }

    fn valid_state() -> ExtensionLifecycleStateV1 {
        let approval_id = "a".repeat(64);
        let extension_id = "fixture.extension".to_string();
        ExtensionLifecycleStateV1 {
            schema_version: EXTENSION_LIFECYCLE_STATE_SCHEMA_V1.to_string(),
            catalog_checkpoints: std::collections::BTreeMap::from([(
                "fixture.catalog".to_string(),
                ExtensionCatalogCheckpointV1 { sequence: 1, payload_sha256: "b".repeat(64) },
            )]),
            active: std::collections::BTreeMap::from([(extension_id.clone(), approval_id.clone())]),
            transitions: vec![
                ExtensionLifecycleTransitionV1 {
                    sequence: 1,
                    occurred_at: "2026-08-26T12:00:00Z".to_string(),
                    action: "approve".to_string(),
                    extension_id: extension_id.clone(),
                    from_approval_id: None,
                    to_approval_id: Some(approval_id.clone()),
                },
                ExtensionLifecycleTransitionV1 {
                    sequence: 2,
                    occurred_at: "2026-08-26T12:00:01Z".to_string(),
                    action: "activate".to_string(),
                    extension_id,
                    from_approval_id: None,
                    to_approval_id: Some(approval_id),
                },
            ],
        }
    }

    #[test]
    fn approval_integrity_checks_each_independent_identity_clause(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let valid = approval_for(directory.path())?;
        assert!(validate_approval(&valid).is_ok());

        let mut invalid = valid.clone();
        invalid.approval_id = "f".repeat(64);
        assert!(validate_approval(&invalid).is_err());

        let mut invalid_values = Vec::new();
        let mut value = valid.clone();
        value.schema_version = "unsupported".to_string();
        invalid_values.push(value);
        let mut value = valid.clone();
        value.release.permissions_sha256 = "f".repeat(64);
        invalid_values.push(value);
        let mut value = valid.clone();
        value.release.conformance.passed = false;
        invalid_values.push(value);
        let mut value = valid.clone();
        value.catalog_id = "INVALID".to_string();
        invalid_values.push(value);
        let mut value = valid.clone();
        value.publisher_id = "INVALID".to_string();
        invalid_values.push(value);
        let mut value = valid.clone();
        value.key_id = "INVALID".to_string();
        invalid_values.push(value);
        let mut value = valid.clone();
        value.catalog_sequence = 0;
        invalid_values.push(value);
        let mut value = valid.clone();
        value.catalog_path = "relative-catalog.json".to_string();
        invalid_values.push(value);
        let mut value = valid.clone();
        value.manifest_path = "relative-manifest.json".to_string();
        invalid_values.push(value);
        let mut value = valid.clone();
        value.module_path = "relative-module.wasm".to_string();
        invalid_values.push(value);
        let mut value = valid.clone();
        value.approved_at = "not-a-time".to_string();
        invalid_values.push(value);
        let mut value = valid;
        value.permission_diff_sha256 = "f".repeat(64);
        invalid_values.push(value);

        for mut invalid in invalid_values {
            rehash(&mut invalid);
            assert!(validate_approval(&invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn lifecycle_state_shape_checks_every_closed_clause_and_exact_limit(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert!(validate_state(&valid_state()).is_ok());
        let mut invalid_values = Vec::new();
        let mut value = valid_state();
        value.schema_version = "unsupported".to_string();
        invalid_values.push(value);
        let mut value = valid_state();
        value.catalog_checkpoints.get_mut("fixture.catalog").expect("checkpoint").sequence = 0;
        invalid_values.push(value);
        let mut value = valid_state();
        value.catalog_checkpoints.get_mut("fixture.catalog").expect("checkpoint").payload_sha256 =
            "invalid".to_string();
        invalid_values.push(value);
        let mut value = valid_state();
        let checkpoint = value.catalog_checkpoints.remove("fixture.catalog").expect("checkpoint");
        value.catalog_checkpoints.insert("INVALID".to_string(), checkpoint);
        invalid_values.push(value);
        let mut value = valid_state();
        let approval = value.active.remove("fixture.extension").expect("active");
        value.active.insert("INVALID".to_string(), approval);
        invalid_values.push(value);
        let mut value = valid_state();
        value.active.insert("fixture.extension".to_string(), "invalid".to_string());
        invalid_values.push(value);
        for field in 0..6 {
            let mut value = valid_state();
            let transition = &mut value.transitions[0];
            match field {
                0 => transition.sequence = 2,
                1 => transition.action = "invalid".to_string(),
                2 => transition.extension_id = "INVALID".to_string(),
                3 => transition.from_approval_id = Some("invalid".to_string()),
                4 => transition.to_approval_id = Some("invalid".to_string()),
                5 => transition.occurred_at = "not-a-time".to_string(),
                _ => unreachable!(),
            }
            invalid_values.push(value);
        }
        for invalid in invalid_values {
            assert!(validate_state(&invalid).is_err());
        }

        let transitions = (0..MAX_EXTENSION_LIFECYCLE_TRANSITIONS)
            .map(|index| ExtensionLifecycleTransitionV1 {
                sequence: u64::try_from(index).expect("bounded index") + 1,
                occurred_at: "2026-08-26T12:00:00Z".to_string(),
                action: "approve".to_string(),
                extension_id: format!("fixture.extension-{index}"),
                from_approval_id: None,
                to_approval_id: Some(sha256_hex(index.to_string().as_bytes())),
            })
            .collect::<Vec<_>>();
        let at_limit =
            ExtensionLifecycleStateV1 { transitions, ..ExtensionLifecycleStateV1::default() };
        assert!(validate_state(&at_limit).is_ok());
        let mut over_limit = at_limit;
        over_limit.transitions.push(ExtensionLifecycleTransitionV1 {
            sequence: u64::try_from(MAX_EXTENSION_LIFECYCLE_TRANSITIONS)? + 1,
            occurred_at: "2026-08-26T12:00:00Z".to_string(),
            action: "approve".to_string(),
            extension_id: "fixture.extension-overflow".to_string(),
            from_approval_id: None,
            to_approval_id: Some("f".repeat(64)),
        });
        assert!(validate_state(&over_limit).is_err());
        Ok(())
    }

    #[test]
    fn lifecycle_state_reconstruction_rejects_each_invalid_history_link(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut inconsistent = valid_state();
        inconsistent.transitions[1].from_approval_id = Some("b".repeat(64));
        assert!(validate_state(&inconsistent).is_err());
        let mut no_subject = valid_state();
        no_subject.transitions[0].to_approval_id = None;
        assert!(validate_state(&no_subject).is_err());
        let mut duplicated = valid_state();
        duplicated.transitions.insert(1, duplicated.transitions[0].clone());
        for (index, transition) in duplicated.transitions.iter_mut().enumerate() {
            transition.sequence = u64::try_from(index)? + 1;
        }
        assert!(validate_state(&duplicated).is_err());
        let mut unapproved = valid_state();
        unapproved.transitions.remove(0);
        unapproved.transitions[0].sequence = 1;
        assert!(validate_state(&unapproved).is_err());
        Ok(())
    }

    #[test]
    fn scalar_identity_and_json_helpers_are_exact() {
        assert_eq!(json_string(&vec![1_u8, 2]).expect("JSON"), "[1,2]");
        assert!(valid_sha256(&"a".repeat(64)));
        assert!(!valid_sha256(&"a".repeat(63)));
        assert!(!valid_sha256(&"g".repeat(64)));
        assert!(!valid_sha256(&"A".repeat(64)));
        assert!(valid_id("a"));
        assert!(valid_id(&"a".repeat(scorchkit_extension::MAX_EXTENSION_ID_BYTES)));
        assert!(!valid_id(""));
        assert!(!valid_id(&"a".repeat(scorchkit_extension::MAX_EXTENSION_ID_BYTES + 1)));
        assert!(!valid_id("INVALID"));
    }

    #[test]
    fn approved_loading_checks_each_retained_artifact_identity(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let engagement = engagement_for(directory.path())?;
        let config = ExtensionConfig {
            lifecycle_root: Some(directory.path().join("lifecycle")),
            ..ExtensionConfig::default()
        };
        let lifecycle = CatalogLifecycle::new(&config, &engagement);
        let valid = approval_for(directory.path())?;
        let checkpoint = ExtensionCatalogCheckpointV1 {
            sequence: 1,
            payload_sha256: valid.payload_sha256.clone(),
        };
        assert!(lifecycle.load_approved(&valid, &checkpoint).is_ok());

        let mut invalid_values = Vec::new();
        let mut value = valid.clone();
        value.module_path = directory.path().join("other.wasm").to_string_lossy().into_owned();
        invalid_values.push(value);
        let mut value = valid.clone();
        value.release.manifest_sha256 = "f".repeat(64);
        invalid_values.push(value);
        let mut value = valid.clone();
        value.release.module_sha256 = "f".repeat(64);
        invalid_values.push(value);
        let mut value = valid.clone();
        value.release.extension_id = "other.extension".to_string();
        invalid_values.push(value);
        let mut value = valid.clone();
        value.release.version = "9.9.9".to_string();
        invalid_values.push(value);
        let mut value = valid;
        value.release.permissions.budgets.timeout_ms += 1;
        value.release.permissions_sha256 = permission_sha256(&value.release.permissions)?;
        invalid_values.push(value);

        for mut invalid in invalid_values {
            rehash(&mut invalid);
            let error = lifecycle
                .load_approved(&invalid, &checkpoint)
                .expect_err("changed approved identity must fail closed");
            assert!(error.to_string().contains("artifact changed"));
        }
        Ok(())
    }

    #[test]
    fn private_layout_lock_immutable_write_sync_and_authorization_are_observable(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use fs2::FileExt as _;

        let directory = tempfile::tempdir()?;
        let engagement = engagement_for(directory.path())?;
        let root = directory.path().join("lifecycle");
        ensure_private_directory(&engagement, &root)?;
        assert!(ensure_private_directory(&engagement, &root).is_ok());
        let regular = directory.path().join("regular");
        std::fs::write(&regular, b"not a directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&regular, std::fs::Permissions::from_mode(0o600))?;
        }
        assert!(ensure_private_directory(&engagement, &regular).is_err());
        assert!(require_private_directory_metadata(&std::fs::metadata(&regular)?).is_err());

        let immutable = root.join("immutable.json");
        write_immutable_json(&engagement, &immutable, &vec![1_u8, 2])?;
        assert!(write_immutable_json(&engagement, &immutable, &vec![1_u8, 2]).is_ok());
        assert!(write_immutable_json(&engagement, &immutable, &vec![2_u8, 1]).is_err());
        assert!(sync_parent(Path::new("/")).is_err());

        let lock = acquire_lifecycle_lock(&engagement, &root)?;
        let retained = lock.file.try_clone()?;
        drop(lock);
        let contender = OpenOptions::new().read(true).write(true).open(root.join(LOCK_FILE))?;
        contender.try_lock_exclusive()?;
        fs2::FileExt::unlock(&contender)?;
        drop(retained);

        let denied = Engagement::new(
            "denied",
            crate::engine::policy::EngagementPolicy::default()
                .allow_scope(crate::engine::scope::ScopeRule::path_prefix(directory.path())?)
                .allow_effect(EffectClass::Passive),
        );
        assert!(authorize(&denied, &immutable, EffectClass::Passive, false).is_err());
        assert!(authorize(&engagement, &immutable, EffectClass::Passive, true).is_ok());
        Ok(())
    }

    #[test]
    fn concurrent_private_directory_creation_accepts_the_single_winner(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let engagement = engagement_for(directory.path())?;
        let path = directory.path().join("concurrent");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let engagement = engagement.clone();
            let path = path.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                ensure_private_directory(&engagement, &path)
            }));
        }
        for worker in workers {
            assert!(worker.join().map_err(|_| "directory worker panicked")?.is_ok());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_metadata_rejects_symlinks() -> std::io::Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let target = directory.path().join("target");
        std::fs::create_dir(&target)?;
        let link = directory.path().join("link");
        symlink(&target, &link)?;
        let metadata = std::fs::symlink_metadata(&link)?;
        assert!(require_private_directory_metadata(&metadata).is_err());
        Ok(())
    }
}
