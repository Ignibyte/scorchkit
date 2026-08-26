//! Cell-local encrypted content-addressed object storage.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use scorchkit_config::{TeamQuotaConfig, TeamRetentionConfig};
use scorchkit_control::{TeamObjectKindV1, TeamObjectViewV1, TEAM_OBJECT_SCHEMA_V1};
use scorchkit_core::sha256_hex;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::auth::PreparedCell;
use crate::engine::error::{Result, ScorchError};
use crate::engine::policy::{Capability, EffectClass, Engagement, PolicyTarget};
use crate::engine::scope::ScopeRule;

const MAX_RECOVERED_TEMPORARY_FILES: usize = 10_000;

#[derive(Clone)]
pub struct TeamObjectStore {
    inner: Arc<TeamObjectStoreInner>,
}

struct TeamObjectStoreInner {
    cell_id: String,
    root: PathBuf,
    engagement: Engagement,
    pool: PgPool,
    write_key_id: String,
    keys: BTreeMap<String, Zeroizing<[u8; 32]>>,
    quotas: TeamQuotaConfig,
    retention: TeamRetentionConfig,
}

impl std::fmt::Debug for TeamObjectStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TeamObjectStore")
            .field("cell_id", &self.inner.cell_id)
            .field("root", &self.inner.root)
            .field("write_key_id", &self.inner.write_key_id)
            .field("key_ids", &self.inner.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredEnvelope {
    schema_version: String,
    cell_id: String,
    object_id: String,
    kind: TeamObjectKindV1,
    plaintext_bytes: u64,
    key_id: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    nonce: String,
    #[serde(with = "zeroizing_string")]
    ciphertext: Zeroizing<String>,
}

mod zeroizing_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Zeroizing::new)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectAad<'a> {
    schema_version: &'a str,
    cell_id: &'a str,
    object_id: &'a str,
    kind: TeamObjectKindV1,
    plaintext_bytes: u64,
    key_id: &'a str,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug)]
struct ObjectMetadata {
    view: TeamObjectViewV1,
    ciphertext_sha256: String,
    stored_bytes: u64,
}

impl TeamObjectStore {
    pub(super) fn new(cell: &PreparedCell, pool: PgPool) -> Result<Self> {
        authorize_root(&cell.config.engagement, &cell.config.object_root)?;
        let metadata = std::fs::symlink_metadata(&cell.config.object_root).map_err(|error| {
            ScorchError::Config(format!("team object root is unavailable: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ScorchError::Config(
                "team object root must be a non-symlink directory".to_string(),
            ));
        }
        require_private_root(&metadata)?;
        let root = cell.config.object_root.canonicalize().map_err(|error| {
            ScorchError::Config(format!("team object root cannot be canonicalized: {error}"))
        })?;
        if root != cell.config.object_root {
            return Err(ScorchError::Config(
                "team object root must already be canonical".to_string(),
            ));
        }
        let keys = cell.keys.iter().cloned().collect();
        Ok(Self {
            inner: Arc::new(TeamObjectStoreInner {
                cell_id: cell.config.cell_id.clone(),
                root,
                engagement: cell.config.engagement.clone(),
                pool,
                write_key_id: cell.config.write_key_id.clone(),
                keys,
                quotas: cell.config.quotas.clone(),
                retention: cell.config.retention.clone(),
            }),
        })
    }

    /// Store authenticated ciphertext under its plaintext SHA-256 identity.
    ///
    /// # Errors
    ///
    /// Returns a policy, quota, filesystem, encryption, integrity, or database error.
    pub async fn put(&self, kind: TeamObjectKindV1, plaintext: &[u8]) -> Result<TeamObjectViewV1> {
        self.authorize()?;
        self.cleanup_deletions().await?;
        let plaintext_bytes = u64::try_from(plaintext.len())
            .map_err(|_| ScorchError::Config("team object size is unsupported".to_string()))?;
        if plaintext_bytes == 0 || plaintext_bytes > self.inner.quotas.max_object_bytes {
            return Err(ScorchError::Config(
                "team object exceeds the configured nonzero object budget".to_string(),
            ));
        }
        let object_id = sha256_hex(plaintext);
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|error| database_error("begin object write", &error))?;
        sqlx::query("LOCK TABLE team_objects IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_error("lock object inventory", &error))?;
        if let Some(existing) = load_metadata_from(&mut *transaction, &object_id).await? {
            if existing.view.kind != kind || existing.view.plaintext_bytes != plaintext_bytes {
                return Err(ScorchError::Config(
                    "team object identity conflicts with immutable metadata".to_string(),
                ));
            }
            transaction
                .commit()
                .await
                .map_err(|error| database_error("commit object lookup", &error))?;
            self.read_authenticated(&object_id, &existing)?;
            return Ok(existing.view);
        }
        let (count, bytes): (i64, i64) = sqlx::query_as(
            "SELECT count(*)::bigint, coalesce(sum(plaintext_bytes), 0)::bigint FROM team_objects",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| database_error("measure object inventory", &error))?;
        let next_count = u64::try_from(count).unwrap_or(u64::MAX).saturating_add(1);
        let next_bytes = u64::try_from(bytes).unwrap_or(u64::MAX).saturating_add(plaintext_bytes);
        if next_count > self.inner.quotas.max_objects
            || next_bytes > self.inner.quotas.max_storage_bytes
        {
            return Err(ScorchError::Config(
                "team object inventory capacity is exhausted".to_string(),
            ));
        }

        let created_at = database_timestamp(Utc::now())?;
        let expires_at = created_at + Duration::days(i64::from(self.inner.retention.object_days));
        let envelope = self.encrypt(
            &object_id,
            kind,
            plaintext,
            &self.inner.write_key_id,
            created_at,
            expires_at,
        )?;
        let stored = serde_json::to_vec(&envelope)?;
        let ciphertext_sha256 = sha256_hex(&stored);
        let stored_bytes = u64::try_from(stored.len())
            .map_err(|_| ScorchError::Config("team stored object size is unsupported".into()))?;
        self.remove_untracked_versions(&object_id)?;
        self.write_new(&object_id, &ciphertext_sha256, &stored)?;
        let inserted = sqlx::query(
            "INSERT INTO team_objects (object_id, kind, plaintext_bytes, ciphertext_sha256, \
             stored_bytes, key_id, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&object_id)
        .bind(kind_name(kind))
        .bind(i64::try_from(plaintext_bytes).unwrap_or(i64::MAX))
        .bind(&ciphertext_sha256)
        .bind(i64::try_from(stored_bytes).unwrap_or(i64::MAX))
        .bind(&self.inner.write_key_id)
        .bind(created_at)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = inserted {
            let _ = self.remove_version(&object_id, &ciphertext_sha256);
            return Err(database_error("record object metadata", &error));
        }
        if let Err(error) = transaction.commit().await {
            // A commit error has an ambiguous server-side outcome. Preserve the immutable
            // version so either outcome stays recoverable; a retry reconciles untracked versions.
            return Err(database_error("commit object metadata", &error));
        }
        Ok(TeamObjectViewV1 {
            object_id,
            kind,
            plaintext_bytes,
            key_id: self.inner.write_key_id.clone(),
            created_at,
            expires_at,
        })
    }

    /// Authenticate and decrypt one non-expired exact object.
    ///
    /// # Errors
    ///
    /// Returns an error when authorization, metadata, ciphertext, key, expiry, or digest checks
    /// fail.
    pub async fn read(&self, object_id: &str) -> Result<(TeamObjectViewV1, Zeroizing<Vec<u8>>)> {
        self.authorize()?;
        validate_object_id(object_id)?;
        let metadata = load_metadata(&self.inner.pool, object_id)
            .await?
            .ok_or_else(|| ScorchError::Config("team object was not found".to_string()))?;
        let plaintext = self.read_authenticated(object_id, &metadata)?;
        Ok((metadata.view, plaintext))
    }

    fn read_authenticated(
        &self,
        object_id: &str,
        metadata: &ObjectMetadata,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if metadata.view.expires_at <= Utc::now() {
            return Err(ScorchError::Config("team object is expired".to_string()));
        }
        let stored =
            self.read_stored(object_id, &metadata.ciphertext_sha256, metadata.stored_bytes)?;
        if sha256_hex(&stored) != metadata.ciphertext_sha256 {
            return Err(integrity_error());
        }
        let envelope: StoredEnvelope =
            serde_json::from_slice(&stored).map_err(|_| integrity_error())?;
        verify_envelope(&self.inner.cell_id, &metadata.view, &envelope)?;
        let plaintext = self.decrypt(&envelope)?;
        if sha256_hex(&plaintext) != object_id
            || u64::try_from(plaintext.len()).ok() != Some(metadata.view.plaintext_bytes)
        {
            return Err(integrity_error());
        }
        Ok(plaintext)
    }

    /// Re-encrypt one object with the configured write key without changing its identity.
    ///
    /// # Errors
    ///
    /// Returns an authorization, integrity, encryption, filesystem, or database error.
    pub async fn rotate(&self, object_id: &str) -> Result<TeamObjectViewV1> {
        self.authorize()?;
        validate_object_id(object_id)?;
        self.cleanup_deletions().await?;
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|error| database_error("begin object rotation", &error))?;
        sqlx::query("LOCK TABLE team_objects IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_error("lock object inventory", &error))?;
        let metadata = load_metadata_from(&mut *transaction, object_id)
            .await?
            .ok_or_else(|| ScorchError::Config("team object was not found".to_string()))?;
        let plaintext = self.read_authenticated(object_id, &metadata)?;
        let mut view = metadata.view.clone();
        if view.key_id == self.inner.write_key_id {
            transaction
                .commit()
                .await
                .map_err(|error| database_error("commit object rotation lookup", &error))?;
            return Ok(view);
        }
        let envelope = self.encrypt(
            object_id,
            view.kind,
            &plaintext,
            &self.inner.write_key_id,
            view.created_at,
            view.expires_at,
        )?;
        let stored = serde_json::to_vec(&envelope)?;
        let ciphertext_sha256 = sha256_hex(&stored);
        let stored_bytes = u64::try_from(stored.len())
            .map_err(|_| ScorchError::Config("team stored object size is unsupported".into()))?;
        self.write_new(object_id, &ciphertext_sha256, &stored)?;
        let queued = sqlx::query(
            "INSERT INTO team_object_deletions (object_id, ciphertext_sha256) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(object_id)
        .bind(&metadata.ciphertext_sha256)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = queued {
            let _ = self.remove_version(object_id, &ciphertext_sha256);
            return Err(database_error("queue retired object version", &error));
        }
        let updated = sqlx::query(
            "UPDATE team_objects SET key_id = $2, ciphertext_sha256 = $3, stored_bytes = $4 \
             WHERE object_id = $1 AND ciphertext_sha256 = $5",
        )
        .bind(object_id)
        .bind(&self.inner.write_key_id)
        .bind(&ciphertext_sha256)
        .bind(i64::try_from(stored_bytes).unwrap_or(i64::MAX))
        .bind(&metadata.ciphertext_sha256)
        .execute(&mut *transaction)
        .await;
        match updated {
            Ok(result) if result.rows_affected() == 1 => {}
            Ok(_) => {
                let _ = self.remove_version(object_id, &ciphertext_sha256);
                return Err(integrity_error());
            }
            Err(error) => {
                let _ = self.remove_version(object_id, &ciphertext_sha256);
                return Err(database_error("record object rotation", &error));
            }
        }
        if let Err(error) = transaction.commit().await {
            // Both immutable versions remain valid across an ambiguous commit outcome.
            return Err(database_error("commit object rotation", &error));
        }
        self.cleanup_deletions().await?;
        view.key_id.clone_from(&self.inner.write_key_id);
        Ok(view)
    }

    /// Delete expired ciphertext and metadata under the configured mandatory retention policy.
    ///
    /// # Errors
    ///
    /// Returns an authorization, filesystem, integrity, or database error.
    pub async fn apply_retention(&self, now: DateTime<Utc>) -> Result<u64> {
        self.authorize()?;
        self.cleanup_deletions().await?;
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|error| database_error("begin object retention", &error))?;
        sqlx::query("LOCK TABLE team_objects IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_error("lock object inventory", &error))?;
        let rows = sqlx::query("SELECT object_id, ciphertext_sha256 FROM team_objects WHERE expires_at <= $1 ORDER BY object_id LIMIT 1000")
            .bind(now)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|error| database_error("load expired objects", &error))?;
        let mut removed = 0_u64;
        for row in rows {
            let object_id: String = row.get("object_id");
            let ciphertext_sha256: String = row.get("ciphertext_sha256");
            sqlx::query(
                "INSERT INTO team_object_deletions (object_id, ciphertext_sha256) \
                 VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(&object_id)
            .bind(&ciphertext_sha256)
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_error("queue expired object deletion", &error))?;
            let result =
                sqlx::query("DELETE FROM team_objects WHERE object_id = $1 AND expires_at <= $2")
                    .bind(&object_id)
                    .bind(now)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|error| database_error("remove expired object metadata", &error))?;
            removed = removed.saturating_add(result.rows_affected());
        }
        transaction
            .commit()
            .await
            .map_err(|error| database_error("commit object retention", &error))?;
        self.cleanup_deletions().await?;
        Ok(removed)
    }

    pub(super) async fn recover_pending_deletions(&self) -> Result<()> {
        self.authorize()?;
        self.recover_temporary_files()?;
        let maximum = self
            .inner
            .quotas
            .max_objects
            .saturating_mul(u64::try_from(self.inner.keys.len()).unwrap_or(u64::MAX));
        let pending: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM team_object_deletions")
            .fetch_one(&self.inner.pool)
            .await
            .map_err(|error| database_error("measure pending object deletions", &error))?;
        if recovery_inventory_exceeds(u64::try_from(pending).unwrap_or(u64::MAX), maximum) {
            return Err(ScorchError::Config(
                "team pending object deletion inventory exceeds its recovery bound".into(),
            ));
        }
        let mut processed = 0_u64;
        loop {
            let batch = u64::try_from(self.cleanup_deletions().await?).unwrap_or(u64::MAX);
            processed = processed.saturating_add(batch);
            if deletion_batch_complete(batch) {
                return Ok(());
            }
            if recovery_inventory_exceeds(processed, maximum) {
                return Err(ScorchError::Config(
                    "team pending object deletion inventory exceeds its recovery bound".into(),
                ));
            }
        }
    }

    async fn cleanup_deletions(&self) -> Result<usize> {
        let rows = sqlx::query(
            "SELECT object_id, ciphertext_sha256 FROM team_object_deletions \
             ORDER BY queued_at, object_id, ciphertext_sha256 LIMIT 1000",
        )
        .fetch_all(&self.inner.pool)
        .await
        .map_err(|error| database_error("load pending object deletions", &error))?;
        let count = rows.len();
        for row in rows {
            let object_id: String = row.get("object_id");
            let ciphertext_sha256: String = row.get("ciphertext_sha256");
            let still_active: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM team_objects \
                 WHERE object_id = $1 AND ciphertext_sha256 = $2)",
            )
            .bind(&object_id)
            .bind(&ciphertext_sha256)
            .fetch_one(&self.inner.pool)
            .await
            .map_err(|error| database_error("verify pending object deletion", &error))?;
            if still_active {
                return Err(integrity_error());
            }
            self.remove_version(&object_id, &ciphertext_sha256)?;
            sqlx::query(
                "DELETE FROM team_object_deletions \
                 WHERE object_id = $1 AND ciphertext_sha256 = $2",
            )
            .bind(&object_id)
            .bind(&ciphertext_sha256)
            .execute(&self.inner.pool)
            .await
            .map_err(|error| database_error("complete pending object deletion", &error))?;
        }
        Ok(count)
    }

    fn recover_temporary_files(&self) -> Result<()> {
        let mut temporary_files = Vec::new();
        for entry in std::fs::read_dir(&self.inner.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(identity) =
                name.strip_prefix('.').and_then(|value| value.strip_suffix(".tmp"))
            else {
                continue;
            };
            let Some((object_id, nonce)) = identity.split_once('.') else {
                continue;
            };
            if validate_object_id(object_id).is_err() || Uuid::parse_str(nonce).is_err() {
                continue;
            }
            temporary_files.push(entry.path());
            if temporary_inventory_exceeds(temporary_files.len()) {
                return Err(ScorchError::Config(
                    "team temporary object inventory exceeds its recovery bound".into(),
                ));
            }
        }
        for path in temporary_files {
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || path.canonicalize()? != path
                || !path.starts_with(&self.inner.root)
            {
                return Err(integrity_error());
            }
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    fn authorize(&self) -> Result<()> {
        let metadata = std::fs::symlink_metadata(&self.inner.root)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ScorchError::Config("team object root identity changed".to_string()));
        }
        require_private_root(&metadata)?;
        if self.inner.root.canonicalize()? != self.inner.root {
            return Err(ScorchError::Config("team object root identity changed".to_string()));
        }
        authorize_root(&self.inner.engagement, &self.inner.root)
    }

    fn encrypt(
        &self,
        object_id: &str,
        kind: TeamObjectKindV1,
        plaintext: &[u8],
        key_id: &str,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<StoredEnvelope> {
        let key = self.inner.keys.get(key_id).ok_or_else(|| {
            ScorchError::Config("team object write key is unavailable".to_string())
        })?;
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| ScorchError::Config("team object nonce generation failed".into()))?;
        let aad = ObjectAad {
            schema_version: TEAM_OBJECT_SCHEMA_V1,
            cell_id: &self.inner.cell_id,
            object_id,
            kind,
            plaintext_bytes: u64::try_from(plaintext.len()).unwrap_or(u64::MAX),
            key_id,
            created_at,
            expires_at,
        };
        let aad = serde_json::to_vec(&aad)?;
        let mut ciphertext = Zeroizing::new(plaintext.to_vec());
        less_safe_key(key)?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad),
                &mut *ciphertext,
            )
            .map_err(|_| ScorchError::Config("team object encryption failed".into()))?;
        Ok(StoredEnvelope {
            schema_version: TEAM_OBJECT_SCHEMA_V1.into(),
            cell_id: self.inner.cell_id.clone(),
            object_id: object_id.into(),
            kind,
            plaintext_bytes: u64::try_from(plaintext.len()).unwrap_or(u64::MAX),
            key_id: key_id.into(),
            created_at,
            expires_at,
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
            ciphertext: Zeroizing::new(
                base64::engine::general_purpose::STANDARD.encode(ciphertext.as_slice()),
            ),
        })
    }

    fn decrypt(&self, envelope: &StoredEnvelope) -> Result<Zeroizing<Vec<u8>>> {
        let key = self.inner.keys.get(&envelope.key_id).ok_or_else(integrity_error)?;
        let nonce: [u8; NONCE_LEN] = base64::engine::general_purpose::STANDARD
            .decode(&envelope.nonce)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(integrity_error)?;
        let mut ciphertext = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(&envelope.ciphertext)
                .map_err(|_| integrity_error())?,
        );
        let aad = serde_json::to_vec(&ObjectAad {
            schema_version: &envelope.schema_version,
            cell_id: &envelope.cell_id,
            object_id: &envelope.object_id,
            kind: envelope.kind,
            plaintext_bytes: envelope.plaintext_bytes,
            key_id: &envelope.key_id,
            created_at: envelope.created_at,
            expires_at: envelope.expires_at,
        })?;
        let plaintext = less_safe_key(key)?
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                ciphertext.as_mut_slice(),
            )
            .map_err(|_| integrity_error())?;
        let length = plaintext.len();
        ciphertext.truncate(length);
        Ok(ciphertext)
    }

    fn write_new(&self, object_id: &str, ciphertext_sha256: &str, bytes: &[u8]) -> Result<()> {
        let destination = self.object_path(object_id, ciphertext_sha256, true)?;
        let temporary = self.inner.root.join(format!(".{object_id}.{}.tmp", Uuid::new_v4()));
        write_private_new(&temporary, bytes)?;
        match std::fs::hard_link(&temporary, &destination) {
            Ok(()) => {
                std::fs::remove_file(temporary)?;
                Ok(())
            }
            Err(error) => {
                let _ = std::fs::remove_file(temporary);
                Err(ScorchError::Io(error))
            }
        }
    }

    fn read_stored(
        &self,
        object_id: &str,
        ciphertext_sha256: &str,
        stored_bytes: u64,
    ) -> Result<Vec<u8>> {
        let maximum_stored =
            self.inner.quotas.max_object_bytes.saturating_mul(2).saturating_add(16_384);
        if stored_bytes == 0 || stored_bytes > maximum_stored {
            return Err(integrity_error());
        }
        let path = self.object_path(object_id, ciphertext_sha256, false)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != stored_bytes
        {
            return Err(integrity_error());
        }
        let canonical = path.canonicalize()?;
        if canonical != path || !canonical.starts_with(&self.inner.root) {
            return Err(integrity_error());
        }
        let limit = usize::try_from(stored_bytes).map_err(|_| integrity_error())?;
        let mut file = open_no_follow(&canonical)?;
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
        Read::by_ref(&mut file)
            .take(u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)?;
        if bytes.len() != limit {
            return Err(integrity_error());
        }
        Ok(bytes)
    }

    fn object_path(
        &self,
        object_id: &str,
        ciphertext_sha256: &str,
        create_shard: bool,
    ) -> Result<PathBuf> {
        validate_object_id(object_id)?;
        validate_object_id(ciphertext_sha256)?;
        let shard = self.inner.root.join(&object_id[..2]);
        if create_shard && !shard.exists() {
            create_private_directory(&shard)?;
        }
        let metadata = std::fs::symlink_metadata(&shard).map_err(|_| integrity_error())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || shard.canonicalize()? != shard
            || !shard.starts_with(&self.inner.root)
        {
            return Err(integrity_error());
        }
        Ok(shard.join(format!("{object_id}.{ciphertext_sha256}.object")))
    }

    fn remove_version(&self, object_id: &str, ciphertext_sha256: &str) -> Result<()> {
        validate_object_id(object_id)?;
        validate_object_id(ciphertext_sha256)?;
        let shard = self.inner.root.join(&object_id[..2]);
        let shard_metadata = match std::fs::symlink_metadata(&shard) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(ScorchError::Io(error)),
        };
        if shard_metadata.file_type().is_symlink()
            || !shard_metadata.is_dir()
            || shard.canonicalize()? != shard
            || !shard.starts_with(&self.inner.root)
        {
            return Err(integrity_error());
        }
        let path = shard.join(format!("{object_id}.{ciphertext_sha256}.object"));
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(ScorchError::Io(error)),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || path.canonicalize()? != path
            || !path.starts_with(&self.inner.root)
        {
            return Err(integrity_error());
        }
        std::fs::remove_file(path).map_err(ScorchError::Io)
    }

    fn remove_untracked_versions(&self, object_id: &str) -> Result<()> {
        validate_object_id(object_id)?;
        let shard = self.inner.root.join(&object_id[..2]);
        let entries = match std::fs::read_dir(&shard) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(ScorchError::Io(error)),
        };
        let prefix = format!("{object_id}.");
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(digest) =
                name.strip_prefix(&prefix).and_then(|value| value.strip_suffix(".object"))
            else {
                continue;
            };
            validate_object_id(digest)?;
            self.remove_version(object_id, digest)?;
        }
        Ok(())
    }
}

const fn recovery_inventory_exceeds(observed: u64, maximum: u64) -> bool {
    observed > maximum
}

const fn deletion_batch_complete(batch: u64) -> bool {
    batch < 1_000
}

const fn temporary_inventory_exceeds(observed: usize) -> bool {
    observed > MAX_RECOVERED_TEMPORARY_FILES
}

fn authorize_root(engagement: &Engagement, root: &Path) -> Result<()> {
    let target = PolicyTarget::Code(root.to_path_buf());
    engagement
        .authorize(target, Capability::LocalState, EffectClass::Passive)
        .require()
        .map_err(ScorchError::from)?;
    let exact = ScopeRule::path_prefix(root)?;
    if !engagement.policy.allowed_scope.contains(&exact) {
        return Err(ScorchError::Config(
            "team object root requires an exact local-state scope grant".to_string(),
        ));
    }
    Ok(())
}

fn less_safe_key(key: &[u8; 32]) -> Result<LessSafeKey> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| ScorchError::Config("team object encryption key is invalid".to_string()))
}

async fn load_metadata(pool: &PgPool, object_id: &str) -> Result<Option<ObjectMetadata>> {
    let mut connection = pool
        .acquire()
        .await
        .map_err(|error| database_error("acquire object metadata connection", &error))?;
    load_metadata_from(&mut *connection, object_id).await
}

async fn load_metadata_from<'e, E>(executor: E, object_id: &str) -> Result<Option<ObjectMetadata>>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query(
        "SELECT object_id, kind, plaintext_bytes, ciphertext_sha256, stored_bytes, key_id, \
         created_at, expires_at FROM team_objects WHERE object_id = $1",
    )
    .bind(object_id)
    .fetch_optional(executor)
    .await
    .map_err(|error| database_error("load object metadata", &error))?;
    row.map(|row| {
        let kind: String = row.get("kind");
        let plaintext_bytes: i64 = row.get("plaintext_bytes");
        let stored_bytes: i64 = row.get("stored_bytes");
        Ok(ObjectMetadata {
            view: TeamObjectViewV1 {
                object_id: row.get("object_id"),
                kind: parse_kind(&kind)?,
                plaintext_bytes: u64::try_from(plaintext_bytes).map_err(|_| integrity_error())?,
                key_id: row.get("key_id"),
                created_at: row.get("created_at"),
                expires_at: row.get("expires_at"),
            },
            ciphertext_sha256: row.get("ciphertext_sha256"),
            stored_bytes: u64::try_from(stored_bytes).map_err(|_| integrity_error())?,
        })
    })
    .transpose()
}

fn verify_envelope(
    cell_id: &str,
    view: &TeamObjectViewV1,
    envelope: &StoredEnvelope,
) -> Result<()> {
    if envelope.schema_version != TEAM_OBJECT_SCHEMA_V1
        || envelope.cell_id != cell_id
        || envelope.object_id != view.object_id
        || envelope.kind != view.kind
        || envelope.plaintext_bytes != view.plaintext_bytes
        || envelope.key_id != view.key_id
        || envelope.created_at != view.created_at
        || envelope.expires_at != view.expires_at
    {
        return Err(integrity_error());
    }
    Ok(())
}

const fn kind_name(kind: TeamObjectKindV1) -> &'static str {
    match kind {
        TeamObjectKindV1::Evidence => "evidence",
        TeamObjectKindV1::Report => "report",
        TeamObjectKindV1::ExtensionArtifact => "extension_artifact",
    }
}

fn parse_kind(value: &str) -> Result<TeamObjectKindV1> {
    match value {
        "evidence" => Ok(TeamObjectKindV1::Evidence),
        "report" => Ok(TeamObjectKindV1::Report),
        "extension_artifact" => Ok(TeamObjectKindV1::ExtensionArtifact),
        _ => Err(integrity_error()),
    }
}

fn validate_object_id(object_id: &str) -> Result<()> {
    if object_id.len() != 64
        || object_id.bytes().any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(ScorchError::Config("team object identity is invalid".to_string()));
    }
    Ok(())
}

fn database_timestamp(value: DateTime<Utc>) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp_micros(value.timestamp_micros()).ok_or_else(integrity_error)
}

#[cfg(unix)]
// JUSTIFICATION: The octal mask directly expresses the security invariant that group and other
// permission bits are absent; a trailing-zero count would hide that filesystem meaning.
#[allow(clippy::verbose_bit_mask)]
fn require_private_root(metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if metadata.mode() & 0o077 == 0 {
        Ok(())
    } else {
        Err(ScorchError::Config(
            "team object root must not grant group or other permissions".to_string(),
        ))
    }
}

#[cfg(windows)]
fn require_private_root(_metadata: &std::fs::Metadata) -> Result<()> {
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(ScorchError::Io)
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn open_no_follow(path: &Path) -> Result<File> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{Mode, OFlags, ResolveFlags};
        let descriptor = rustix::fs::openat2(
            rustix::fs::ABS,
            path,
            OFlags::RDONLY.union(OFlags::CLOEXEC).union(OFlags::NOFOLLOW),
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS.union(ResolveFlags::NO_MAGICLINKS),
        )
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
        Ok(File::from(descriptor))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        Ok(options.open(path)?)
    }
}

fn database_error(label: &str, error: &sqlx::Error) -> ScorchError {
    ScorchError::Database(format!("team {label}: {error}"))
}

fn integrity_error() -> ScorchError {
    ScorchError::Config("team object integrity validation failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use scorchkit_policy::EngagementPolicy;

    fn fixture_store() -> (tempfile::TempDir, TeamObjectStore) {
        let directory = tempfile::tempdir().expect("object root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private root");
        }
        let root = directory.path().canonicalize().expect("canonical root");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(&root).expect("root scope"))
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::Passive);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/scorchkit_object_store_unit")
            .expect("lazy pool");
        let mut keys = BTreeMap::new();
        keys.insert("primary".into(), Zeroizing::new([7_u8; 32]));
        let store = TeamObjectStore {
            inner: Arc::new(TeamObjectStoreInner {
                cell_id: "alpha".into(),
                root,
                engagement: Engagement::new("alpha", policy),
                pool,
                write_key_id: "primary".into(),
                keys,
                quotas: TeamQuotaConfig::default(),
                retention: TeamRetentionConfig::default(),
            }),
        };
        (directory, store)
    }

    fn view() -> TeamObjectViewV1 {
        TeamObjectViewV1 {
            object_id: "a".repeat(64),
            kind: TeamObjectKindV1::Evidence,
            plaintext_bytes: 8,
            key_id: "primary".into(),
            created_at: DateTime::<Utc>::UNIX_EPOCH + Duration::seconds(1_700_000_000),
            expires_at: DateTime::<Utc>::UNIX_EPOCH + Duration::seconds(1_700_000_100),
        }
    }

    fn envelope() -> StoredEnvelope {
        let view = view();
        StoredEnvelope {
            schema_version: TEAM_OBJECT_SCHEMA_V1.into(),
            cell_id: "alpha".into(),
            object_id: view.object_id,
            kind: view.kind,
            plaintext_bytes: view.plaintext_bytes,
            key_id: view.key_id,
            created_at: view.created_at,
            expires_at: view.expires_at,
            nonce: base64::engine::general_purpose::STANDARD.encode([1_u8; NONCE_LEN]),
            ciphertext: Zeroizing::new(
                base64::engine::general_purpose::STANDARD.encode([2_u8; 24]),
            ),
        }
    }

    #[tokio::test]
    async fn object_debug_and_zeroizing_envelope_serde_are_complete_and_secret_safe() {
        let (_directory, store) = fixture_store();
        let debug = format!("{store:?}");
        assert!(debug.contains("TeamObjectStore"));
        assert!(debug.contains("cell_id: \"alpha\""));
        assert!(debug.contains("write_key_id: \"primary\""));
        assert!(!debug.contains(&base64::engine::general_purpose::STANDARD.encode([7_u8; 32])));

        let envelope = envelope();
        let encoded = serde_json::to_vec(&envelope).expect("serialize envelope");
        let decoded: StoredEnvelope = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(decoded.ciphertext.as_str(), envelope.ciphertext.as_str());
        assert_eq!(decoded.object_id, envelope.object_id);
    }

    #[test]
    fn envelope_projection_and_kind_parser_check_every_field() {
        let expected = view();
        let cases: &[fn(&mut StoredEnvelope)] = &[
            |value| value.schema_version = "wrong".into(),
            |value| value.cell_id = "beta".into(),
            |value| value.object_id = "b".repeat(64),
            |value| value.kind = TeamObjectKindV1::Report,
            |value| value.plaintext_bytes += 1,
            |value| value.key_id = "secondary".into(),
            |value| value.created_at += Duration::seconds(1),
            |value| value.expires_at += Duration::seconds(1),
        ];
        verify_envelope("alpha", &expected, &envelope()).expect("exact envelope");
        for mutate in cases {
            let mut changed = envelope();
            mutate(&mut changed);
            assert!(verify_envelope("alpha", &expected, &changed).is_err());
        }
        assert!(verify_envelope("beta", &expected, &envelope()).is_err());

        assert_eq!(parse_kind("evidence").expect("evidence"), TeamObjectKindV1::Evidence);
        assert_eq!(parse_kind("report").expect("report"), TeamObjectKindV1::Report);
        assert_eq!(
            parse_kind("extension_artifact").expect("extension artifact"),
            TeamObjectKindV1::ExtensionArtifact
        );
        assert!(parse_kind("unknown").is_err());
    }

    #[tokio::test]
    async fn object_identity_and_root_authorization_grammars_are_exact() {
        assert!(validate_object_id(&"a".repeat(64)).is_ok());
        assert!(validate_object_id(&"a".repeat(63)).is_err());
        assert!(validate_object_id(&"a".repeat(65)).is_err());
        assert!(validate_object_id(&"A".repeat(64)).is_err());
        assert!(validate_object_id(&"g".repeat(64)).is_err());

        let (directory, store) = fixture_store();
        authorize_root(&store.inner.engagement, directory.path()).expect("exact authorization");
        let parent = directory.path().parent().expect("root parent");
        let broader = Engagement::new(
            "broader",
            EngagementPolicy::default()
                .allow_scope(ScopeRule::path_prefix(parent).expect("parent scope"))
                .allow_capability(Capability::LocalState)
                .allow_effect(EffectClass::Passive),
        );
        assert!(authorize_root(&broader, directory.path()).is_err());
    }

    #[tokio::test]
    async fn filesystem_helpers_reject_malformed_paths_and_preserve_exact_versions() {
        let (_directory, store) = fixture_store();
        let object_id = "a".repeat(64);
        let first_digest = "b".repeat(64);
        let second_digest = "c".repeat(64);

        assert!(store.object_path("short", &first_digest, true).is_err());
        assert!(store.object_path(&object_id, "short", true).is_err());
        let first = store.object_path(&object_id, &first_digest, true).expect("first path");
        std::fs::write(&first, b"first").expect("write first");
        assert_eq!(store.read_stored(&object_id, &first_digest, 5).expect("read"), b"first");
        assert!(store.read_stored(&object_id, &first_digest, 0).is_err());
        assert!(store.read_stored(&object_id, &first_digest, 4).is_err());
        assert!(store
            .read_stored(
                &object_id,
                &first_digest,
                store.inner.quotas.max_object_bytes.saturating_mul(2).saturating_add(16_385),
            )
            .is_err());

        let second = store.object_path(&object_id, &second_digest, true).expect("second path");
        std::fs::write(&second, b"second").expect("write second");
        store.remove_version(&object_id, &first_digest).expect("remove first");
        assert!(!first.exists());
        assert!(second.exists());
        store.remove_version(&object_id, &first_digest).expect("missing version is idempotent");
        store.remove_untracked_versions(&object_id).expect("remove remaining versions");
        assert!(!second.exists());
        assert!(store.remove_untracked_versions(&"d".repeat(64)).is_ok());
    }

    #[tokio::test]
    async fn temporary_recovery_removes_only_strict_owned_regular_files() {
        let (_directory, store) = fixture_store();
        let object_id = "a".repeat(64);
        let temporary = store.inner.root.join(format!(".{object_id}.{}.tmp", Uuid::new_v4()));
        let unrelated = store.inner.root.join(".not-an-object.tmp");
        std::fs::write(&temporary, b"temporary").expect("write temporary");
        std::fs::write(&unrelated, b"unrelated").expect("write unrelated");
        store.recover_temporary_files().expect("temporary recovery");
        assert!(!temporary.exists());
        assert!(unrelated.exists());

        #[cfg(unix)]
        {
            let linked = store.inner.root.join(format!(".{object_id}.{}.tmp", Uuid::new_v4()));
            std::os::unix::fs::symlink(&unrelated, &linked).expect("temporary symlink");
            assert!(store.recover_temporary_files().is_err());
        }
    }

    #[test]
    fn recovery_inventory_helpers_have_inclusive_exact_edges() {
        assert!(!recovery_inventory_exceeds(16, 16));
        assert!(recovery_inventory_exceeds(17, 16));
        assert!(deletion_batch_complete(999));
        assert!(!deletion_batch_complete(1_000));
        assert!(!temporary_inventory_exceeds(MAX_RECOVERED_TEMPORARY_FILES));
        assert!(temporary_inventory_exceeds(MAX_RECOVERED_TEMPORARY_FILES + 1));
    }

    #[test]
    fn filesystem_and_inventory_guards_remain_explicit_and_fail_closed() {
        let source = include_str!("object_store.rs");
        let production = source.split("#[cfg(test)]").next().expect("production source");
        let section = |start: &str, end: &str| {
            let start = production.find(start).unwrap_or_else(|| panic!("missing {start}"));
            let end = production[start..]
                .find(end)
                .map_or_else(|| panic!("missing {end}"), |offset| start + offset);
            production[start..end].split_whitespace().collect::<Vec<_>>().join(" ")
        };

        let put = section("pub async fn put(", "pub async fn read(");
        assert!(put.contains(
            "existing.view.kind != kind || existing.view.plaintext_bytes != plaintext_bytes"
        ));
        assert!(put.contains(
            "next_count > self.inner.quotas.max_objects || next_bytes > self.inner.quotas.max_storage_bytes"
        ));

        let read = section("fn read_authenticated(", "pub async fn rotate(");
        assert!(read.contains(
            "sha256_hex(&plaintext) != object_id || u64::try_from(plaintext.len()).ok() != Some(metadata.view.plaintext_bytes)"
        ));

        let rotate = section("pub async fn rotate(", "pub async fn apply_retention(");
        assert!(rotate.contains("Ok(result) if result.rows_affected() == 1 => {}"));

        let recovery = section("fn recover_temporary_files(", "fn authorize(");
        assert!(recovery
            .contains("validate_object_id(object_id).is_err() || Uuid::parse_str(nonce).is_err()"));
        assert!(recovery.contains(
            "metadata.file_type().is_symlink() || !metadata.is_file() || path.canonicalize()? != path || !path.starts_with(&self.inner.root)"
        ));

        let authorize = section("fn authorize(", "fn encrypt(");
        assert!(authorize.contains("metadata.file_type().is_symlink() || !metadata.is_dir()"));

        let stored = section("fn read_stored(", "fn object_path(");
        assert!(stored.contains("stored_bytes == 0 || stored_bytes > maximum_stored"));
        assert!(stored.contains(
            "metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != stored_bytes"
        ));
        assert!(stored.contains("canonical != path || !canonical.starts_with(&self.inner.root)"));

        let object_path = section("fn object_path(", "fn remove_version(");
        assert!(object_path.contains(
            "metadata.file_type().is_symlink() || !metadata.is_dir() || shard.canonicalize()? != shard || !shard.starts_with(&self.inner.root)"
        ));

        let remove = section("fn remove_version(", "fn remove_untracked_versions(");
        assert_eq!(remove.matches("error.kind() == std::io::ErrorKind::NotFound").count(), 2);
        assert!(remove.contains(
            "shard_metadata.file_type().is_symlink() || !shard_metadata.is_dir() || shard.canonicalize()? != shard || !shard.starts_with(&self.inner.root)"
        ));
        assert!(remove.contains(
            "metadata.file_type().is_symlink() || !metadata.is_file() || path.canonicalize()? != path || !path.starts_with(&self.inner.root)"
        ));

        let untracked =
            section("fn remove_untracked_versions(", "const fn temporary_inventory_exceeds");
        assert!(untracked.contains("error.kind() == std::io::ErrorKind::NotFound"));
    }
}
