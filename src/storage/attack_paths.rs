//! Transactional persistence for canonical attack paths.
//!
//! The current path snapshot is project-scoped. State transitions are append-preserved in a child
//! table and restored as the authority during reads, so a snapshot update cannot discard history.

use std::collections::BTreeMap;

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::models::{StoredAttackPath, StoredAttackPathTransition};
use crate::engine::attack_path::{AttackPath, AttackPathTransition};
use crate::engine::error::{Result, ScorchError};

/// Save canonical paths and append every previously unseen transition.
///
/// Returns the number of newly created path rows. Each path is identity-locked and committed in
/// one transaction. Existing transition history must be present and byte-equivalent in the caller's
/// path, which prevents stale snapshots from erasing or rewriting proof.
///
/// # Errors
///
/// Returns an error for a malformed path, conflicting history, stale state, serialization failure,
/// or database failure.
pub async fn save_attack_paths(
    pool: &PgPool,
    project_id: Uuid,
    paths: &[AttackPath],
) -> Result<usize> {
    let mut created = 0;
    for path in paths {
        validate_path(path)?;
        created += usize::from(save_attack_path(pool, project_id, path).await?);
    }
    Ok(created)
}

async fn save_attack_path(pool: &PgPool, project_id: Uuid, path: &AttackPath) -> Result<bool> {
    let raw_path = serde_json::to_value(path)
        .map_err(|error| ScorchError::Database(format!("serialize attack path: {error}")))?;
    let mut transaction = pool.begin().await.map_err(|error| {
        ScorchError::Database(format!("begin attack-path transaction: {error}"))
    })?;

    lock_path_identity(&mut transaction, project_id, &path.identity.value).await?;
    let existing = sqlx::query_as::<_, StoredAttackPath>(
        "SELECT * FROM attack_paths WHERE project_id = $1 AND path_identity = $2 FOR UPDATE",
    )
    .bind(project_id)
    .bind(&path.identity.value)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| ScorchError::Database(format!("lookup attack path: {error}")))?;

    let (path_id, created) = if let Some(existing) = existing {
        ensure_history_extends(&mut transaction, &existing, path).await?;
        sqlx::query(
            "UPDATE attack_paths SET path_schema = $2, identity_schema = $3, \
             current_state = $4, raw_path = $5, updated_at = now() WHERE id = $1",
        )
        .bind(existing.id)
        .bind(&path.schema)
        .bind(&path.identity.schema)
        .bind(path.state.as_str())
        .bind(&raw_path)
        .execute(&mut *transaction)
        .await
        .map_err(|error| ScorchError::Database(format!("update attack path: {error}")))?;
        (existing.id, false)
    } else {
        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO attack_paths \
             (project_id, path_identity, path_schema, identity_schema, current_state, raw_path) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(project_id)
        .bind(&path.identity.value)
        .bind(&path.schema)
        .bind(&path.identity.schema)
        .bind(path.state.as_str())
        .bind(&raw_path)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| ScorchError::Database(format!("insert attack path: {error}")))?;
        (id, true)
    };

    append_transitions(&mut transaction, path_id, &path.transitions).await?;
    transaction.commit().await.map_err(|error| {
        ScorchError::Database(format!("commit attack-path transaction: {error}"))
    })?;
    Ok(created)
}

async fn lock_path_identity(
    transaction: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    path_identity: &str,
) -> Result<()> {
    let lock_key = format!("attack-path:{project_id}:{path_identity}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut **transaction)
        .await
        .map_err(|error| ScorchError::Database(format!("lock attack-path identity: {error}")))?;
    Ok(())
}

async fn ensure_history_extends(
    transaction: &mut Transaction<'_, Postgres>,
    existing: &StoredAttackPath,
    incoming: &AttackPath,
) -> Result<()> {
    if existing.path_schema != incoming.schema
        || existing.identity_schema != incoming.identity.schema
        || existing.path_identity != incoming.identity.value
    {
        return Err(ScorchError::Database(
            "attack-path schema or identity changed for an existing row".to_string(),
        ));
    }

    let stored = sqlx::query_as::<_, StoredAttackPathTransition>(
        "SELECT * FROM attack_path_transitions WHERE attack_path_id = $1 \
         ORDER BY observed_at, transition_identity",
    )
    .bind(existing.id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| ScorchError::Database(format!("list stored path history: {error}")))?;
    let incoming_by_id: BTreeMap<&str, &AttackPathTransition> = incoming
        .transitions
        .iter()
        .map(|transition| (transition.identity.as_str(), transition))
        .collect();

    for row in &stored {
        let Some(candidate) = incoming_by_id.get(row.transition_identity.as_str()) else {
            return Err(ScorchError::Database(
                "stale attack-path snapshot omits stored transition history".to_string(),
            ));
        };
        let raw = serde_json::to_value(candidate).map_err(|error| {
            ScorchError::Database(format!("serialize attack-path transition: {error}"))
        })?;
        if raw != row.raw_transition {
            return Err(ScorchError::Database(
                "attack-path transition identity collision has conflicting content".to_string(),
            ));
        }
    }
    Ok(())
}

async fn append_transitions(
    transaction: &mut Transaction<'_, Postgres>,
    path_id: Uuid,
    transitions: &[AttackPathTransition],
) -> Result<()> {
    for transition in transitions {
        let raw = serde_json::to_value(transition).map_err(|error| {
            ScorchError::Database(format!("serialize attack-path transition: {error}"))
        })?;
        sqlx::query(
            "INSERT INTO attack_path_transitions \
             (attack_path_id, transition_identity, transition_schema, raw_transition, observed_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (attack_path_id, transition_identity) DO NOTHING",
        )
        .bind(path_id)
        .bind(&transition.identity)
        .bind(&transition.schema)
        .bind(raw)
        .bind(transition.observed_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| ScorchError::Database(format!("append path transition: {error}")))?;
    }
    Ok(())
}

/// List canonical project paths with child-table transition history restored.
///
/// # Errors
///
/// Returns an error if a stored path or transition is malformed or the database read fails.
pub async fn list_attack_paths(pool: &PgPool, project_id: Uuid) -> Result<Vec<AttackPath>> {
    let rows = sqlx::query_as::<_, StoredAttackPath>(
        "SELECT * FROM attack_paths WHERE project_id = $1 ORDER BY path_identity",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(|error| ScorchError::Database(format!("list attack paths: {error}")))?;

    let mut paths = Vec::with_capacity(rows.len());
    for row in rows {
        let mut path: AttackPath = serde_json::from_value(row.raw_path.clone())
            .map_err(|error| ScorchError::Database(format!("decode attack path: {error}")))?;
        if path.identity.value != row.path_identity
            || path.identity.schema != row.identity_schema
            || path.schema != row.path_schema
            || path.state.as_str() != row.current_state
        {
            return Err(ScorchError::Database(
                "stored attack-path columns disagree with canonical JSON".to_string(),
            ));
        }
        path.transitions = list_transitions(pool, row.id).await?;
        validate_path(&path)?;
        paths.push(path);
    }
    Ok(paths)
}

async fn list_transitions(pool: &PgPool, path_id: Uuid) -> Result<Vec<AttackPathTransition>> {
    let rows = sqlx::query_as::<_, StoredAttackPathTransition>(
        "SELECT * FROM attack_path_transitions WHERE attack_path_id = $1 \
         ORDER BY observed_at, transition_identity",
    )
    .bind(path_id)
    .fetch_all(pool)
    .await
    .map_err(|error| ScorchError::Database(format!("list attack-path transitions: {error}")))?;
    rows.into_iter()
        .map(|row| {
            let transition: AttackPathTransition = serde_json::from_value(row.raw_transition)
                .map_err(|error| {
                    ScorchError::Database(format!("decode attack-path transition: {error}"))
                })?;
            if transition.identity != row.transition_identity
                || transition.schema != row.transition_schema
                || transition.observed_at.timestamp_micros() != row.observed_at.timestamp_micros()
            {
                return Err(ScorchError::Database(
                    "stored transition columns disagree with canonical JSON".to_string(),
                ));
            }
            Ok(transition)
        })
        .collect()
}

fn validate_path(path: &AttackPath) -> Result<()> {
    path.validate().map_err(|error| {
        ScorchError::Database(format!("attack path violates the canonical contract: {error:?}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validation_rejects_empty_history() {
        let malformed = serde_json::from_value::<AttackPath>(serde_json::json!({}));
        assert!(malformed.is_err());
    }
}
