//! Append-only durable finding-triage persistence and canonical reconstruction.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::models::{
    StoredFindingCorrelationDecision, StoredFindingSuppression, StoredFindingTriageTransition,
    TrackedFinding,
};
use crate::engine::error::{Result, ScorchError};
use crate::engine::observation::{CorrelationKey, EvidenceRecord, FindingRecordV2};
use crate::engine::triage::{
    legacy_status_for_triage, material_finding_evidence_identity, FindingCorrelationContributors,
    FindingCorrelationDecision, FindingSuppression, FindingSuppressionScope,
    FindingSuppressionScopeKind, FindingTriage, FindingTriageHistory, FindingTriageState,
    FindingTriageSubject, FindingTriageTransition, TriageActor, TriageActorKind,
    FINDING_CORRELATION_DECISION_SCHEMA_V1, FINDING_SUPPRESSION_SCHEMA_V1,
    FINDING_TRIAGE_SCHEMA_V1, FINDING_TRIAGE_TRANSITION_SCHEMA_V1, MAX_TRIAGE_CORRELATIONS,
    MAX_TRIAGE_REFERENCES, MAX_TRIAGE_SUPPRESSIONS, MAX_TRIAGE_TRANSITIONS,
};

/// Canonical triage state and exact suppression subject attached to a public finding.
pub(crate) struct ValidatedFindingTriage {
    pub(crate) subject: FindingTriageSubject,
    pub(crate) projection: FindingTriage,
}

/// Complete input for one independently authorized triage transition write.
pub struct FindingTransitionWrite {
    pub finding_id: Uuid,
    pub next: FindingTriageState,
    pub actor: TriageActor,
    pub reason: String,
    pub evidence_ids: Vec<String>,
    pub model_analysis_identity: Option<String>,
    pub observed_at: DateTime<Utc>,
}

/// Complete input for one independently authorized exact suppression write.
pub struct FindingSuppressionWrite {
    pub finding_id: Uuid,
    pub subject: FindingTriageSubject,
    pub kind: FindingSuppressionScopeKind,
    pub actor: TriageActor,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub review_at: Option<DateTime<Utc>>,
}

/// Complete input for one independently authorized correlation-decision write.
pub struct FindingCorrelationWrite {
    pub finding_id: Uuid,
    pub contributing_finding_ids: Vec<Uuid>,
    pub evidence_ids: Vec<String>,
    pub facets: Vec<CorrelationKey>,
    pub explanation: String,
    pub actor: TriageActor,
    pub created_at: DateTime<Utc>,
}

/// Reconstruct and validate every triage child associated with one canonical finding.
pub(crate) async fn load_validated_triage(
    pool: &PgPool,
    row: &TrackedFinding,
    record: &FindingRecordV2,
) -> Result<ValidatedFindingTriage> {
    let subject = FindingTriageSubject::from_record(row.project_id.to_string(), record);
    subject.validate().map_err(triage_mismatch)?;
    let mut connection = pool
        .acquire()
        .await
        .map_err(|error| ScorchError::Database(format!("acquire triage reader: {error}")))?;
    let history = load_history(&mut connection, row).await?;
    let correlations = load_correlations(&mut connection, row).await?;
    let suppressions = load_matching_suppressions(&mut connection, row, &subject).await?;
    let projection = FindingTriage::new(history, correlations, suppressions);
    projection.validate().map_err(triage_mismatch)?;
    Ok(ValidatedFindingTriage { subject, projection })
}

/// Insert the authoritative first history record for a newly stored finding.
pub(crate) async fn append_initial_transition(
    transaction: &mut Transaction<'_, Postgres>,
    finding_id: Uuid,
    finding_identity: &str,
    observed_at: DateTime<Utc>,
) -> Result<()> {
    let transition = FindingTriageTransition::new(
        finding_identity,
        1,
        None,
        FindingTriageState::NeedsContext,
        TriageActor::new(TriageActorKind::System, "finding-ingest/v1"),
        "Initial review required",
        observed_at,
    );
    insert_transition(&mut *transaction, finding_id, &transition).await?;
    Ok(())
}

/// Append a deterministic review transition when rediscovery invalidates an earlier disposition.
pub(crate) async fn reconcile_rediscovery(
    transaction: &mut Transaction<'_, Postgres>,
    row: &TrackedFinding,
    previous: &FindingRecordV2,
    current: &FindingRecordV2,
    observed_at: DateTime<Utc>,
) -> Result<bool> {
    let history = load_history(&mut *transaction, row).await?;
    let material_changed =
        material_finding_evidence_identity(previous) != material_finding_evidence_identity(current);
    let (next, reason) = if history.current_state == FindingTriageState::Fixed {
        (FindingTriageState::Regressed, "Fixed finding rediscovered")
    } else if material_changed && history.current_state != FindingTriageState::NeedsContext {
        (FindingTriageState::NeedsContext, "Material finding evidence changed")
    } else {
        return Ok(false);
    };
    let transition = next_transition(
        &history,
        next,
        TriageActor::new(TriageActorKind::System, "finding-ingest/v1"),
        reason,
        current.evidence.iter().map(|evidence| evidence.identity.clone()).collect(),
        None,
        observed_at,
    )?;
    verify_transition_references(&mut *transaction, row.id, &transition).await?;
    insert_transition(&mut *transaction, row.id, &transition).await?;
    update_projection(&mut *transaction, row.id, next, Some(reason)).await?;
    Ok(true)
}

/// Append one independently authorized human transition.
///
/// # Errors
///
/// Returns an error for missing/corrupt durable state, an invalid transition, a foreign
/// reference, or a transaction failure.
pub async fn transition_finding(pool: &PgPool, write: FindingTransitionWrite) -> Result<bool> {
    let mut transaction = begin(pool, "finding triage transition").await?;
    let row = lock_finding(&mut transaction, write.finding_id).await?;
    let history = load_history(&mut transaction, &row).await?;
    if history.current_state == write.next {
        transaction.rollback().await.map_err(|error| {
            ScorchError::Database(format!("rollback idempotent triage transition: {error}"))
        })?;
        return Ok(false);
    }
    let transition = next_transition(
        &history,
        write.next,
        write.actor,
        &write.reason,
        write.evidence_ids,
        write.model_analysis_identity,
        write.observed_at,
    )?;
    verify_transition_references(&mut transaction, write.finding_id, &transition).await?;
    insert_transition(&mut transaction, write.finding_id, &transition).await?;
    update_projection(&mut transaction, write.finding_id, write.next, Some(&transition.reason))
        .await?;
    commit(transaction, "finding triage transition").await?;
    Ok(true)
}

/// Append one exact, time-bounded suppression derived from a canonical finding subject.
///
/// # Errors
///
/// Returns an error for missing/corrupt durable state, invalid scope/lifetime, an identity
/// conflict, or a transaction failure.
pub async fn create_suppression(pool: &PgPool, write: FindingSuppressionWrite) -> Result<bool> {
    write.subject.validate().map_err(triage_request)?;
    let project_id = Uuid::parse_str(&write.subject.project_identity)
        .map_err(|_| triage_request("suppression project identity is not a UUID"))?;
    let mut transaction = begin(pool, "finding suppression").await?;
    lock_project(&mut transaction, project_id).await?;
    let row = lock_finding(&mut transaction, write.finding_id).await?;
    if row.stable_identity != write.subject.finding_identity || row.project_id != project_id {
        return Err(triage_mismatch("suppression finding identity changed before write"));
    }
    let suppression = FindingSuppression::new(
        FindingSuppressionScope::for_subject(write.kind, &write.subject),
        write.actor,
        write.reason,
        write.created_at,
        write.expires_at,
        write.review_at,
    );
    suppression.validate().map_err(triage_request)?;
    let raw = serde_json::to_value(&suppression)
        .map_err(|error| triage_mismatch(format!("serialize suppression: {error}")))?;
    let result = sqlx::query(
        "INSERT INTO finding_suppressions \
         (project_id, origin_finding_id, suppression_identity, suppression_schema, scope_kind, \
          finding_identity, rule_identity, target_identity, actor_kind, actor_identity, \
          raw_suppression, created_at, expires_at, review_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
         ON CONFLICT (project_id, suppression_identity) DO NOTHING",
    )
    .bind(row.project_id)
    .bind(row.id)
    .bind(&suppression.identity)
    .bind(&suppression.schema)
    .bind(scope_kind(suppression.scope.kind))
    .bind(&suppression.scope.finding_identity)
    .bind(&suppression.scope.rule_identity)
    .bind(&suppression.scope.target_identity)
    .bind(actor_kind(suppression.actor.kind))
    .bind(&suppression.actor.identity)
    .bind(raw)
    .bind(suppression.created_at)
    .bind(suppression.expires_at)
    .bind(suppression.review_at)
    .execute(&mut *transaction)
    .await
    .map_err(|error| ScorchError::Database(format!("insert finding suppression: {error}")))?;
    let changed = result.rows_affected() == 1;
    if !changed {
        validate_existing_suppression(&mut transaction, row.project_id, &suppression).await?;
    }
    ensure_suppression_bound(&mut transaction, row.project_id).await?;
    commit(transaction, "finding suppression").await?;
    Ok(changed)
}

/// Append one canonical correlation decision after proving every contributor and evidence owner.
///
/// # Errors
///
/// Returns an error for missing/corrupt durable state, foreign contributors/evidence, malformed
/// canonical content, an identity conflict, or a transaction failure.
pub async fn record_correlation(pool: &PgPool, write: FindingCorrelationWrite) -> Result<bool> {
    let unique_ids: BTreeSet<_> = write.contributing_finding_ids.iter().copied().collect();
    if unique_ids.len() != write.contributing_finding_ids.len()
        || unique_ids.len() > MAX_TRIAGE_REFERENCES
        || !unique_ids.contains(&write.finding_id)
    {
        return Err(triage_request(
            "correlation contributor IDs must be unique, bounded, and include the parent finding",
        ));
    }
    let mut transaction = begin(pool, "finding correlation").await?;
    lock_correlation_findings(&mut transaction, &unique_ids).await?;
    let row = lock_finding(&mut transaction, write.finding_id).await?;
    let contributors = correlation_contributors(
        &mut transaction,
        &row,
        &write.contributing_finding_ids,
        write.evidence_ids,
        write.facets,
    )
    .await?;
    let decision = FindingCorrelationDecision::new(
        &row.stable_identity,
        contributors,
        write.explanation,
        write.actor,
        write.created_at,
    );
    decision.validate().map_err(triage_request)?;
    let raw = serde_json::to_value(&decision)
        .map_err(|error| triage_mismatch(format!("serialize correlation decision: {error}")))?;
    let result = sqlx::query(
        "INSERT INTO finding_correlation_decisions \
         (tracked_finding_id, decision_identity, decision_schema, actor_kind, actor_identity, \
          raw_decision, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (tracked_finding_id, decision_identity) DO NOTHING",
    )
    .bind(row.id)
    .bind(&decision.identity)
    .bind(&decision.schema)
    .bind(actor_kind(decision.actor.kind))
    .bind(&decision.actor.identity)
    .bind(raw)
    .bind(decision.created_at)
    .execute(&mut *transaction)
    .await
    .map_err(|error| ScorchError::Database(format!("insert finding correlation: {error}")))?;
    let changed = result.rows_affected() == 1;
    if !changed {
        validate_existing_correlation(&mut transaction, row.id, &decision).await?;
    }
    ensure_correlation_bound(&mut transaction, row.id).await?;
    commit(transaction, "finding correlation").await?;
    Ok(changed)
}

async fn load_history(
    connection: &mut PgConnection,
    row: &TrackedFinding,
) -> Result<FindingTriageHistory> {
    let query_limit = bounded_query_limit(MAX_TRIAGE_TRANSITIONS)?;
    let rows = sqlx::query_as::<_, StoredFindingTriageTransition>(
        "SELECT * FROM finding_triage_transitions WHERE tracked_finding_id = $1 \
         ORDER BY sequence LIMIT $2",
    )
    .bind(row.id)
    .bind(query_limit)
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| ScorchError::Database(format!("load finding triage history: {error}")))?;
    if rows.len() > MAX_TRIAGE_TRANSITIONS {
        return Err(triage_mismatch("transition history exceeds its public bound"));
    }
    let transitions = rows
        .iter()
        .map(|stored| validate_transition_row(row, stored))
        .collect::<Result<Vec<_>>>()?;
    let current_state = transitions
        .last()
        .map(|transition| transition.to)
        .ok_or_else(|| triage_mismatch("finding has no canonical initial transition"))?;
    let history = FindingTriageHistory {
        schema: FINDING_TRIAGE_SCHEMA_V1.to_string(),
        finding_identity: row.stable_identity.clone(),
        current_state,
        transitions,
    };
    history.validate().map_err(triage_mismatch)?;
    if row.triage_state != current_state.as_str()
        || row.status != legacy_status_for_triage(current_state)
    {
        return Err(triage_mismatch(
            "finding current-state projection differs from authoritative history",
        ));
    }
    Ok(history)
}

async fn load_correlations(
    connection: &mut PgConnection,
    row: &TrackedFinding,
) -> Result<Vec<FindingCorrelationDecision>> {
    let query_limit = bounded_query_limit(MAX_TRIAGE_CORRELATIONS)?;
    let rows = sqlx::query_as::<_, StoredFindingCorrelationDecision>(
        "SELECT * FROM finding_correlation_decisions WHERE tracked_finding_id = $1 \
         ORDER BY created_at, decision_identity LIMIT $2",
    )
    .bind(row.id)
    .bind(query_limit)
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| ScorchError::Database(format!("load finding correlations: {error}")))?;
    if rows.len() > MAX_TRIAGE_CORRELATIONS {
        return Err(triage_mismatch("correlation history exceeds its public bound"));
    }
    let mut correlations = Vec::with_capacity(rows.len());
    for stored in &rows {
        let decision = validate_correlation_row(row, stored)?;
        validate_correlation_ownership(connection, row.project_id, &decision).await?;
        correlations.push(decision);
    }
    Ok(correlations)
}

async fn load_matching_suppressions(
    connection: &mut PgConnection,
    row: &TrackedFinding,
    subject: &FindingTriageSubject,
) -> Result<Vec<FindingSuppression>> {
    let query_limit = bounded_query_limit(MAX_TRIAGE_SUPPRESSIONS)?;
    let rows = sqlx::query_as::<_, StoredFindingSuppression>(
        "SELECT * FROM finding_suppressions WHERE project_id = $1 \
         ORDER BY created_at, suppression_identity LIMIT $2",
    )
    .bind(row.project_id)
    .bind(query_limit)
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| ScorchError::Database(format!("load finding suppressions: {error}")))?;
    if rows.len() > MAX_TRIAGE_SUPPRESSIONS {
        return Err(triage_mismatch("project suppression history exceeds its public bound"));
    }
    validate_suppression_origins(connection, row.project_id, &rows).await?;
    rows.iter()
        .map(|stored| validate_suppression_row(row.project_id, stored))
        .filter_map(|suppression| match suppression {
            Ok(suppression) if suppression.scope.matches(subject) => Some(Ok(suppression)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn validate_transition_row(
    parent: &TrackedFinding,
    row: &StoredFindingTriageTransition,
) -> Result<FindingTriageTransition> {
    let transition: FindingTriageTransition = serde_json::from_value(row.raw_transition.clone())
        .map_err(|error| triage_mismatch(format!("invalid raw triage transition: {error}")))?;
    transition.validate().map_err(triage_mismatch)?;
    if row.tracked_finding_id != parent.id
        || row.transition_identity != transition.identity
        || row.transition_schema != FINDING_TRIAGE_TRANSITION_SCHEMA_V1
        || row.sequence != i32::try_from(transition.sequence).unwrap_or(i32::MIN)
        || row.from_state.as_deref() != transition.from.map(FindingTriageState::as_str)
        || row.to_state != transition.to.as_str()
        || row.actor_kind != actor_kind(transition.actor.kind)
        || row.actor_identity != transition.actor.identity
        || row.observed_at.timestamp_micros() != transition.observed_at.timestamp_micros()
        || transition.finding_identity != parent.stable_identity
        || row.raw_transition
            != serde_json::to_value(&transition)
                .map_err(|error| triage_mismatch(format!("serialize triage transition: {error}")))?
    {
        return Err(triage_mismatch(
            "triage transition canonical document and duplicated projection differ",
        ));
    }
    Ok(transition)
}

fn validate_correlation_row(
    parent: &TrackedFinding,
    row: &StoredFindingCorrelationDecision,
) -> Result<FindingCorrelationDecision> {
    let decision: FindingCorrelationDecision = serde_json::from_value(row.raw_decision.clone())
        .map_err(|error| triage_mismatch(format!("invalid raw correlation decision: {error}")))?;
    decision.validate().map_err(triage_mismatch)?;
    if row.tracked_finding_id != parent.id
        || row.decision_identity != decision.identity
        || row.decision_schema != FINDING_CORRELATION_DECISION_SCHEMA_V1
        || row.actor_kind != actor_kind(decision.actor.kind)
        || row.actor_identity != decision.actor.identity
        || row.created_at.timestamp_micros() != decision.created_at.timestamp_micros()
        || decision.finding_identity != parent.stable_identity
        || row.raw_decision
            != serde_json::to_value(&decision).map_err(|error| {
                triage_mismatch(format!("serialize correlation decision: {error}"))
            })?
    {
        return Err(triage_mismatch(
            "correlation decision canonical document and duplicated projection differ",
        ));
    }
    Ok(decision)
}

fn validate_suppression_row(
    project_id: Uuid,
    row: &StoredFindingSuppression,
) -> Result<FindingSuppression> {
    let suppression: FindingSuppression = serde_json::from_value(row.raw_suppression.clone())
        .map_err(|error| triage_mismatch(format!("invalid raw finding suppression: {error}")))?;
    suppression.validate().map_err(triage_mismatch)?;
    if row.project_id != project_id
        || row.suppression_identity != suppression.identity
        || row.suppression_schema != FINDING_SUPPRESSION_SCHEMA_V1
        || row.scope_kind != scope_kind(suppression.scope.kind)
        || row.finding_identity != suppression.scope.finding_identity
        || row.rule_identity != suppression.scope.rule_identity
        || row.target_identity != suppression.scope.target_identity
        || row.actor_kind != actor_kind(suppression.actor.kind)
        || row.actor_identity != suppression.actor.identity
        || row.created_at.timestamp_micros() != suppression.created_at.timestamp_micros()
        || optional_micros(row.expires_at) != optional_micros(suppression.expires_at)
        || optional_micros(row.review_at) != optional_micros(suppression.review_at)
        || suppression.scope.project_identity != project_id.to_string()
        || row.raw_suppression
            != serde_json::to_value(&suppression).map_err(|error| {
                triage_mismatch(format!("serialize finding suppression: {error}"))
            })?
    {
        return Err(triage_mismatch(
            "finding suppression canonical document and duplicated projection differ",
        ));
    }
    Ok(suppression)
}

async fn validate_correlation_ownership(
    connection: &mut PgConnection,
    project_id: Uuid,
    decision: &FindingCorrelationDecision,
) -> Result<()> {
    let findings = sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT stable_identity, raw_finding FROM tracked_findings \
         WHERE project_id = $1 AND stable_identity = ANY($2)",
    )
    .bind(project_id)
    .bind(&decision.contributing_finding_identities)
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| ScorchError::Database(format!("validate correlation findings: {error}")))?;
    let found_identities: BTreeSet<_> =
        findings.iter().map(|(identity, _)| identity.clone()).collect();
    let expected_identities: BTreeSet<_> =
        decision.contributing_finding_identities.iter().cloned().collect();
    if found_identities != expected_identities {
        return Err(triage_mismatch("correlation contributor is outside the finding project"));
    }
    let evidence = sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT finding.stable_identity, evidence.raw_evidence \
         FROM finding_evidence AS evidence \
         INNER JOIN tracked_findings AS finding ON finding.id = evidence.tracked_finding_id \
         WHERE finding.project_id = $1 AND evidence.evidence_identity = ANY($2) \
           AND finding.stable_identity = ANY($3)",
    )
    .bind(project_id)
    .bind(&decision.evidence_ids)
    .bind(&decision.contributing_finding_identities)
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| ScorchError::Database(format!("validate correlation evidence: {error}")))?;
    let mut evidence_identities = BTreeSet::new();
    let declared_scanners: BTreeSet<_> = decision.scanner_ids.iter().cloned().collect();
    for (identity, raw) in evidence {
        if !expected_identities.contains(&identity) {
            return Err(triage_mismatch("correlation evidence belongs to another finding"));
        }
        let record: EvidenceRecord = serde_json::from_value(raw)
            .map_err(|error| triage_mismatch(format!("invalid correlation evidence: {error}")))?;
        let record = record.normalized();
        evidence_identities.insert(record.identity);
        if !declared_scanners.contains(&record.provenance.scanner_id) {
            return Err(triage_mismatch(
                "correlation evidence scanner is absent from the decision inventory",
            ));
        }
    }
    let expected_evidence: BTreeSet<_> = decision.evidence_ids.iter().cloned().collect();
    if evidence_identities != expected_evidence {
        return Err(triage_mismatch("correlation evidence identity or ownership differs"));
    }
    for (_, raw) in findings {
        let _: crate::engine::finding::Finding = serde_json::from_value(raw)
            .map_err(|error| triage_mismatch(format!("invalid correlation finding: {error}")))?;
    }
    Ok(())
}

async fn correlation_contributors(
    transaction: &mut Transaction<'_, Postgres>,
    parent: &TrackedFinding,
    finding_ids: &[Uuid],
    evidence_ids: Vec<String>,
    facets: Vec<CorrelationKey>,
) -> Result<FindingCorrelationContributors> {
    let unique_ids: BTreeSet<_> = finding_ids.iter().copied().collect();
    if unique_ids.len() != finding_ids.len() || !unique_ids.contains(&parent.id) {
        return Err(triage_request(
            "correlation contributor IDs must be unique and include the parent finding",
        ));
    }
    let ids: Vec<_> = unique_ids.into_iter().collect();
    let rows = sqlx::query_as::<_, (Uuid, String, serde_json::Value)>(
        "SELECT id, stable_identity, raw_finding FROM tracked_findings \
         WHERE project_id = $1 AND id = ANY($2) ORDER BY id FOR UPDATE",
    )
    .bind(parent.project_id)
    .bind(&ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| ScorchError::Database(format!("lock correlation findings: {error}")))?;
    if rows.len() != ids.len() {
        return Err(triage_request("correlation contributor is outside the finding project"));
    }
    let finding_identities: Vec<_> = rows.iter().map(|(_, identity, _)| identity.clone()).collect();
    let allowed: BTreeSet<_> = rows.iter().map(|(id, _, _)| *id).collect();
    let mut scanner_ids = BTreeSet::new();
    for (_, _, raw) in &rows {
        let finding: crate::engine::finding::Finding = serde_json::from_value(raw.clone())
            .map_err(|error| triage_mismatch(format!("invalid correlation finding: {error}")))?;
        scanner_ids.insert(finding.canonical_appsec().provenance.scanner_id);
    }
    let evidence_rows = sqlx::query_as::<_, (Uuid, String, serde_json::Value)>(
        "SELECT tracked_finding_id, evidence_identity, raw_evidence FROM finding_evidence \
         WHERE tracked_finding_id = ANY($1) AND evidence_identity = ANY($2)",
    )
    .bind(&ids)
    .bind(&evidence_ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| ScorchError::Database(format!("load correlation evidence: {error}")))?;
    let mut found_evidence = BTreeSet::new();
    for (owner, identity, raw) in evidence_rows {
        if !allowed.contains(&owner) {
            return Err(triage_mismatch("correlation evidence belongs to another finding"));
        }
        let evidence: EvidenceRecord = serde_json::from_value(raw)
            .map_err(|error| triage_mismatch(format!("invalid correlation evidence: {error}")))?;
        let evidence = evidence.normalized();
        if evidence.identity != identity {
            return Err(triage_mismatch("correlation evidence projection differs"));
        }
        found_evidence.insert(identity);
        scanner_ids.insert(evidence.provenance.scanner_id);
    }
    let expected_evidence: BTreeSet<_> = evidence_ids.iter().cloned().collect();
    if found_evidence != expected_evidence {
        return Err(triage_request("correlation evidence is missing or outside contributors"));
    }
    Ok(FindingCorrelationContributors {
        finding_identities,
        scanner_ids: scanner_ids.into_iter().collect(),
        evidence_ids,
        facets,
    })
}

fn next_transition(
    history: &FindingTriageHistory,
    next: FindingTriageState,
    actor: TriageActor,
    reason: &str,
    evidence_ids: Vec<String>,
    model_analysis_identity: Option<String>,
    observed_at: DateTime<Utc>,
) -> Result<FindingTriageTransition> {
    if history.transitions.len() >= MAX_TRIAGE_TRANSITIONS {
        return Err(triage_limit("finding triage transition history exceeds its bound"));
    }
    let sequence = u32::try_from(history.transitions.len())
        .map_err(|_| triage_mismatch("transition sequence exceeds u32"))?
        .checked_add(1)
        .ok_or_else(|| triage_mismatch("transition sequence overflow"))?;
    let transition = FindingTriageTransition::new(
        &history.finding_identity,
        sequence,
        Some(history.current_state),
        next,
        actor,
        reason,
        observed_at,
    )
    .with_references(evidence_ids, model_analysis_identity);
    transition.validate().map_err(triage_request)?;
    Ok(transition)
}

async fn verify_transition_references(
    connection: &mut PgConnection,
    finding_id: Uuid,
    transition: &FindingTriageTransition,
) -> Result<()> {
    let evidence_count: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT evidence_identity) FROM finding_evidence \
         WHERE tracked_finding_id = $1 AND evidence_identity = ANY($2)",
    )
    .bind(finding_id)
    .bind(&transition.evidence_ids)
    .fetch_one(&mut *connection)
    .await
    .map_err(|error| ScorchError::Database(format!("verify triage evidence: {error}")))?;
    if usize::try_from(evidence_count).ok() != Some(transition.evidence_ids.len()) {
        return Err(triage_request("triage evidence does not belong to the finding"));
    }
    if let Some(identity) = &transition.model_analysis_identity {
        let found: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM finding_agent_analysis \
             WHERE tracked_finding_id = $1 AND analysis_identity = $2)",
        )
        .bind(finding_id)
        .bind(identity)
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| ScorchError::Database(format!("verify triage model analysis: {error}")))?;
        if !found {
            return Err(triage_request("triage model analysis does not belong to the finding"));
        }
    }
    Ok(())
}

async fn insert_transition(
    connection: &mut PgConnection,
    finding_id: Uuid,
    transition: &FindingTriageTransition,
) -> Result<()> {
    transition.validate().map_err(triage_mismatch)?;
    let raw = serde_json::to_value(transition)
        .map_err(|error| triage_mismatch(format!("serialize triage transition: {error}")))?;
    sqlx::query(
        "INSERT INTO finding_triage_transitions \
         (tracked_finding_id, transition_identity, transition_schema, sequence, from_state, \
          to_state, actor_kind, actor_identity, raw_transition, observed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(finding_id)
    .bind(&transition.identity)
    .bind(&transition.schema)
    .bind(i32::try_from(transition.sequence).map_err(|_| {
        triage_mismatch("triage transition sequence exceeds durable representation")
    })?)
    .bind(transition.from.map(FindingTriageState::as_str))
    .bind(transition.to.as_str())
    .bind(actor_kind(transition.actor.kind))
    .bind(&transition.actor.identity)
    .bind(raw)
    .bind(transition.observed_at)
    .execute(&mut *connection)
    .await
    .map_err(|error| ScorchError::Database(format!("insert finding triage transition: {error}")))?;
    Ok(())
}

async fn update_projection(
    connection: &mut PgConnection,
    finding_id: Uuid,
    state: FindingTriageState,
    note: Option<&str>,
) -> Result<()> {
    let result = sqlx::query(
        "UPDATE tracked_findings SET triage_state = $2, status = $3, status_note = $4 \
         WHERE id = $1",
    )
    .bind(finding_id)
    .bind(state.as_str())
    .bind(legacy_status_for_triage(state))
    .bind(note)
    .execute(&mut *connection)
    .await
    .map_err(|error| ScorchError::Database(format!("update finding triage projection: {error}")))?;
    if result.rows_affected() != 1 {
        return Err(triage_mismatch("triage parent disappeared during transition"));
    }
    Ok(())
}

async fn lock_finding(
    transaction: &mut Transaction<'_, Postgres>,
    finding_id: Uuid,
) -> Result<TrackedFinding> {
    sqlx::query_as::<_, TrackedFinding>("SELECT * FROM tracked_findings WHERE id = $1 FOR UPDATE")
        .bind(finding_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| ScorchError::Database(format!("lock triage finding: {error}")))?
        .ok_or_else(|| ScorchError::Config(format!("finding '{finding_id}' was not found")))
}

async fn lock_project(transaction: &mut Transaction<'_, Postgres>, project_id: Uuid) -> Result<()> {
    let found = sqlx::query_scalar::<_, Uuid>("SELECT id FROM projects WHERE id = $1 FOR UPDATE")
        .bind(project_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| ScorchError::Database(format!("lock suppression project: {error}")))?;
    if found.is_none() {
        return Err(ScorchError::Config(format!("project '{project_id}' was not found")));
    }
    Ok(())
}

async fn lock_correlation_findings(
    transaction: &mut Transaction<'_, Postgres>,
    finding_ids: &BTreeSet<Uuid>,
) -> Result<()> {
    for finding_id in finding_ids {
        let key = format!("finding-correlation/v1:{finding_id}");
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(key)
            .execute(&mut **transaction)
            .await
            .map_err(|error| {
                ScorchError::Database(format!("lock correlation finding identity: {error}"))
            })?;
    }
    Ok(())
}

async fn ensure_correlation_bound(
    transaction: &mut Transaction<'_, Postgres>,
    finding_id: Uuid,
) -> Result<()> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM finding_correlation_decisions WHERE tracked_finding_id = $1",
    )
    .bind(finding_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| ScorchError::Database(format!("count finding correlations: {error}")))?;
    ensure_count_bound(count, MAX_TRIAGE_CORRELATIONS, "finding correlation history")
}

async fn ensure_suppression_bound(
    transaction: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
) -> Result<()> {
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM finding_suppressions WHERE project_id = $1")
            .bind(project_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| {
                ScorchError::Database(format!("count finding suppressions: {error}"))
            })?;
    ensure_count_bound(count, MAX_TRIAGE_SUPPRESSIONS, "project suppression history")
}

fn ensure_count_bound(count: i64, maximum: usize, label: &str) -> Result<()> {
    let count = usize::try_from(count)
        .map_err(|_| triage_mismatch(format!("{label} count is negative or too large")))?;
    if count > maximum {
        return Err(triage_limit(format!("{label} exceeds its bound")));
    }
    Ok(())
}

async fn validate_suppression_origins(
    connection: &mut PgConnection,
    project_id: Uuid,
    rows: &[StoredFindingSuppression],
) -> Result<()> {
    let expected: BTreeSet<_> = rows.iter().map(|row| row.origin_finding_id).collect();
    let origin_ids: Vec<_> = expected.iter().copied().collect();
    let actual: BTreeSet<_> = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM tracked_findings WHERE project_id = $1 AND id = ANY($2)",
    )
    .bind(project_id)
    .bind(&origin_ids)
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| ScorchError::Database(format!("validate suppression origins: {error}")))?
    .into_iter()
    .collect();
    if actual != expected {
        return Err(triage_mismatch("finding suppression origin is outside its declared project"));
    }
    Ok(())
}

async fn validate_existing_suppression(
    transaction: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    expected: &FindingSuppression,
) -> Result<()> {
    let row = sqlx::query_as::<_, StoredFindingSuppression>(
        "SELECT * FROM finding_suppressions WHERE project_id = $1 AND suppression_identity = $2",
    )
    .bind(project_id)
    .bind(&expected.identity)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| ScorchError::Database(format!("read existing suppression: {error}")))?;
    #[cfg(test)]
    let row = inject_existing_suppression_row(row, expected);
    let declared: FindingSuppression = serde_json::from_value(row.raw_suppression.clone())
        .map_err(|error| triage_mismatch(format!("invalid existing suppression: {error}")))?;
    if declared != *expected {
        return Err(triage_mismatch("suppression identity conflicts with different content"));
    }
    if row.project_id != project_id
        || row.suppression_identity != expected.identity
        || row.suppression_schema != expected.schema
        || row.scope_kind != scope_kind(expected.scope.kind)
        || row.finding_identity != expected.scope.finding_identity
        || row.rule_identity != expected.scope.rule_identity
        || row.target_identity != expected.scope.target_identity
        || row.actor_kind != actor_kind(expected.actor.kind)
        || row.actor_identity != expected.actor.identity
        || row.created_at.timestamp_micros() != expected.created_at.timestamp_micros()
        || optional_micros(row.expires_at) != optional_micros(expected.expires_at)
        || optional_micros(row.review_at) != optional_micros(expected.review_at)
        || row.raw_suppression != serde_json::to_value(expected).map_err(triage_mismatch)?
    {
        return Err(triage_mismatch("existing suppression projection differs"));
    }
    Ok(())
}

async fn validate_existing_correlation(
    transaction: &mut Transaction<'_, Postgres>,
    finding_id: Uuid,
    expected: &FindingCorrelationDecision,
) -> Result<()> {
    let row = sqlx::query_as::<_, StoredFindingCorrelationDecision>(
        "SELECT * FROM finding_correlation_decisions WHERE tracked_finding_id = $1 AND decision_identity = $2",
    )
    .bind(finding_id)
    .bind(&expected.identity)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| ScorchError::Database(format!("read existing correlation: {error}")))?;
    #[cfg(test)]
    let row = inject_existing_correlation_row(row, expected);
    let declared: C = serde_json::from_value(row.raw_decision.clone()).map_err(triage_mismatch)?;
    if declared != *expected
        || row.tracked_finding_id != finding_id
        || row.decision_identity != expected.identity
        || row.decision_schema != expected.schema
        || row.actor_kind != actor_kind(expected.actor.kind)
        || row.actor_identity != expected.actor.identity
        || row.created_at.timestamp_micros() != expected.created_at.timestamp_micros()
        || row.raw_decision != serde_json::to_value(expected).map_err(triage_mismatch)?
    {
        return Err(triage_mismatch("existing correlation projection differs"));
    }
    Ok(())
}

type C = FindingCorrelationDecision;

async fn begin<'a>(pool: &'a PgPool, label: &str) -> Result<Transaction<'a, Postgres>> {
    pool.begin().await.map_err(|error| ScorchError::Database(format!("begin {label}: {error}")))
}

async fn commit(transaction: Transaction<'_, Postgres>, label: &str) -> Result<()> {
    transaction
        .commit()
        .await
        .map_err(|error| ScorchError::Database(format!("commit {label}: {error}")))
}

fn bounded_query_limit(maximum: usize) -> Result<i64> {
    i64::try_from(maximum.saturating_add(1))
        .map_err(|_| triage_mismatch("triage query limit overflow"))
}

const fn actor_kind(kind: TriageActorKind) -> &'static str {
    match kind {
        TriageActorKind::Human => "human",
        TriageActorKind::System => "system",
    }
}

const fn scope_kind(kind: FindingSuppressionScopeKind) -> &'static str {
    match kind {
        FindingSuppressionScopeKind::Finding => "finding",
        FindingSuppressionScopeKind::Rule => "rule",
        FindingSuppressionScopeKind::Target => "target",
        FindingSuppressionScopeKind::RuleTarget => "rule_target",
    }
}

fn optional_micros(value: Option<DateTime<Utc>>) -> Option<i64> {
    value.map(|time| time.timestamp_micros())
}

#[cfg(test)]
fn inject_existing_suppression_row(
    mut row: StoredFindingSuppression,
    expected: &FindingSuppression,
) -> StoredFindingSuppression {
    if expected.actor.identity == "mutation-fixture/suppression-identity" {
        row.suppression_identity = "0".repeat(64);
    }
    row
}

#[cfg(test)]
fn inject_existing_correlation_row(
    mut row: StoredFindingCorrelationDecision,
    expected: &FindingCorrelationDecision,
) -> StoredFindingCorrelationDecision {
    match expected.actor.identity.as_str() {
        "mutation-fixture/correlation-parent" => row.tracked_finding_id = Uuid::new_v4(),
        "mutation-fixture/correlation-identity" => row.decision_identity = "0".repeat(64),
        _ => {}
    }
    row
}

fn triage_mismatch(error: impl std::fmt::Display) -> ScorchError {
    ScorchError::Database(format!("canonical triage projection mismatch: {error}"))
}

fn triage_request(error: impl std::fmt::Display) -> ScorchError {
    ScorchError::Config(format!("invalid finding triage request: {error}"))
}

fn triage_limit(error: impl std::fmt::Display) -> ScorchError {
    ScorchError::Database(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use chrono::TimeZone;

    use super::*;

    fn time(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 24, 1, 2, second).single().unwrap_or_else(Utc::now)
    }

    fn actor() -> TriageActor {
        TriageActor::new(TriageActorKind::Human, "operator@example.test")
    }

    fn parent(project_id: Uuid, id: Uuid) -> TrackedFinding {
        TrackedFinding {
            id,
            scan_id: Uuid::new_v4(),
            project_id,
            fingerprint: "legacy".to_string(),
            identity_schema: "scorchkit.finding-identity/v2".to_string(),
            stable_identity: "a".repeat(64),
            correlation_keys: serde_json::json!([]),
            module_id: "fixture".to_string(),
            severity: "high".to_string(),
            title: "Fixture".to_string(),
            description: "Fixture".to_string(),
            affected_target: "https://example.test/".to_string(),
            evidence: None,
            remediation: None,
            owasp_category: None,
            cwe_id: Some(79),
            raw_finding: serde_json::json!({}),
            confidence: 1.0,
            first_seen: time(1),
            last_seen: time(1),
            seen_count: 1,
            status: "new".to_string(),
            triage_state: "needs_context".to_string(),
            status_note: None,
            found_at: time(1),
        }
    }

    fn transition_row(
        parent: &TrackedFinding,
    ) -> (FindingTriageTransition, StoredFindingTriageTransition) {
        let transition = FindingTriageTransition::new(
            &parent.stable_identity,
            2,
            Some(FindingTriageState::NeedsContext),
            FindingTriageState::Likely,
            actor(),
            "Independent row parity",
            time(2),
        );
        let row = StoredFindingTriageTransition {
            id: Uuid::new_v4(),
            tracked_finding_id: parent.id,
            transition_identity: transition.identity.clone(),
            transition_schema: transition.schema.clone(),
            sequence: i32::try_from(transition.sequence).expect("sequence fits i32"),
            from_state: transition.from.map(FindingTriageState::as_str).map(str::to_string),
            to_state: transition.to.as_str().to_string(),
            actor_kind: actor_kind(transition.actor.kind).to_string(),
            actor_identity: transition.actor.identity.clone(),
            raw_transition: serde_json::to_value(&transition).expect("transition JSON"),
            observed_at: transition.observed_at,
            stored_at: time(3),
        };
        (transition, row)
    }

    fn correlation_row(
        parent: &TrackedFinding,
    ) -> (FindingCorrelationDecision, StoredFindingCorrelationDecision) {
        let decision = FindingCorrelationDecision::new(
            &parent.stable_identity,
            FindingCorrelationContributors {
                finding_identities: vec![parent.stable_identity.clone(), "b".repeat(64)],
                scanner_ids: vec!["runtime".to_string(), "semgrep".to_string()],
                evidence_ids: vec!["c".repeat(64)],
                facets: vec![CorrelationKey::new("CWE", "79")],
            },
            "Independent row parity",
            actor(),
            time(2),
        );
        let row = StoredFindingCorrelationDecision {
            id: Uuid::new_v4(),
            tracked_finding_id: parent.id,
            decision_identity: decision.identity.clone(),
            decision_schema: decision.schema.clone(),
            actor_kind: actor_kind(decision.actor.kind).to_string(),
            actor_identity: decision.actor.identity.clone(),
            raw_decision: serde_json::to_value(&decision).expect("decision JSON"),
            created_at: decision.created_at,
            stored_at: time(3),
        };
        (decision, row)
    }

    fn suppression_row(project_id: Uuid) -> (FindingSuppression, StoredFindingSuppression) {
        let scope = FindingSuppressionScope {
            kind: FindingSuppressionScopeKind::RuleTarget,
            project_identity: project_id.to_string(),
            finding_identity: None,
            rule_identity: Some("b".repeat(64)),
            target_identity: Some("c".repeat(64)),
        };
        let suppression = FindingSuppression::new(
            scope,
            actor(),
            "Independent row parity",
            time(1),
            Some(time(4)),
            Some(time(3)),
        );
        let row = StoredFindingSuppression {
            id: Uuid::new_v4(),
            project_id,
            origin_finding_id: Uuid::new_v4(),
            suppression_identity: suppression.identity.clone(),
            suppression_schema: suppression.schema.clone(),
            scope_kind: scope_kind(suppression.scope.kind).to_string(),
            finding_identity: suppression.scope.finding_identity.clone(),
            rule_identity: suppression.scope.rule_identity.clone(),
            target_identity: suppression.scope.target_identity.clone(),
            actor_kind: actor_kind(suppression.actor.kind).to_string(),
            actor_identity: suppression.actor.identity.clone(),
            raw_suppression: serde_json::to_value(&suppression).expect("suppression JSON"),
            created_at: suppression.created_at,
            expires_at: suppression.expires_at,
            review_at: suppression.review_at,
            stored_at: time(5),
        };
        (suppression, row)
    }

    fn assert_correlation_row_rejected(
        parent: &TrackedFinding,
        row: &StoredFindingCorrelationDecision,
    ) {
        assert!(validate_correlation_row(parent, row).is_err());
    }

    fn assert_suppression_row_rejected(project_id: Uuid, row: &StoredFindingSuppression) {
        assert!(validate_suppression_row(project_id, row).is_err());
    }

    async fn database_parent(prefix: &str) -> Option<(PgPool, Uuid, TrackedFinding)> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::storage::connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("connect triage unit database: {error}"));
        crate::storage::migrate::run_migrations(&pool)
            .await
            .unwrap_or_else(|error| panic!("migrate triage unit database: {error}"));
        let project = crate::storage::projects::create_project(
            &pool,
            &format!("{prefix}-{}", Uuid::new_v4()),
            "triage unit database fixture",
        )
        .await
        .unwrap_or_else(|error| panic!("create triage unit project: {error}"));
        let observed_at = Utc::now();
        let scan = crate::storage::scans::save_scan(
            &pool,
            project.id,
            "https://example.test/",
            "standard",
            observed_at,
            Some(observed_at),
            &[],
            &[],
            &serde_json::json!({}),
        )
        .await
        .unwrap_or_else(|error| panic!("create triage unit scan: {error}"));
        let finding = crate::engine::finding::Finding::new(
            "fixture",
            crate::engine::severity::Severity::High,
            "Triage unit finding",
            "Fixture",
            "https://example.test/path",
        );
        crate::storage::findings::save_findings(&pool, project.id, scan.id, &[finding])
            .await
            .unwrap_or_else(|error| panic!("save triage unit finding: {error}"));
        let row = sqlx::query_as::<_, TrackedFinding>(
            "SELECT * FROM tracked_findings WHERE project_id = $1",
        )
        .bind(project.id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("load triage unit finding: {error}"));
        Some((pool, project.id, row))
    }

    async fn assert_loaded_history_bounds(pool: &PgPool, row: &TrackedFinding) {
        sqlx::query(
            "INSERT INTO finding_triage_transitions \
             (tracked_finding_id, transition_identity, transition_schema, sequence, from_state, \
              to_state, actor_kind, actor_identity, raw_transition, observed_at) \
             SELECT $1, lpad(to_hex(value), 64, '0'), 'fixture', value, 'needs_context', \
                    'likely', 'human', 'fixture', '{}'::jsonb, \
                    clock_timestamp() + value * interval '1 microsecond' \
             FROM generate_series(2, $2::integer) AS value",
        )
        .bind(row.id)
        .bind(i32::try_from(MAX_TRIAGE_TRANSITIONS).expect("transition limit fits i32"))
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("seed exact transition read bound: {error}"));
        let mut connection = pool.acquire().await.expect("acquire exact history reader");
        let exact = load_history(&mut connection, row).await.expect_err("invalid exact history");
        assert!(exact.to_string().contains("invalid raw triage transition"));
        drop(connection);
        sqlx::query(
            "INSERT INTO finding_triage_transitions \
             (tracked_finding_id, transition_identity, transition_schema, sequence, from_state, \
              to_state, actor_kind, actor_identity, raw_transition, observed_at) \
             VALUES ($1, $2, 'fixture', $3, 'needs_context', 'likely', 'human', 'fixture', \
                     '{}'::jsonb, clock_timestamp())",
        )
        .bind(row.id)
        .bind("f".repeat(64))
        .bind(i32::try_from(MAX_TRIAGE_TRANSITIONS + 1).expect("transition overflow fits i32"))
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("seed overflowing transition read bound: {error}"));
        let mut connection = pool.acquire().await.expect("acquire overflow history reader");
        let overflow = load_history(&mut connection, row).await.expect_err("history overflow");
        assert!(overflow.to_string().contains("transition history exceeds its public bound"));
    }

    async fn assert_loaded_correlation_bounds(pool: &PgPool, row: &TrackedFinding) {
        sqlx::query(
            "INSERT INTO finding_correlation_decisions \
             (tracked_finding_id, decision_identity, decision_schema, actor_kind, actor_identity, \
              raw_decision, created_at) \
             SELECT $1, lpad(to_hex(value), 64, '0'), 'fixture', 'human', 'fixture', '{}'::jsonb, \
                    clock_timestamp() + value * interval '1 microsecond' \
             FROM generate_series(1, $2::integer) AS value",
        )
        .bind(row.id)
        .bind(i32::try_from(MAX_TRIAGE_CORRELATIONS).expect("correlation limit fits i32"))
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("seed exact correlation read bound: {error}"));
        let mut connection = pool.acquire().await.expect("acquire exact correlation reader");
        let exact =
            load_correlations(&mut connection, row).await.expect_err("invalid exact correlations");
        assert!(exact.to_string().contains("invalid raw correlation decision"));
        drop(connection);
        sqlx::query(
            "INSERT INTO finding_correlation_decisions \
             (tracked_finding_id, decision_identity, decision_schema, actor_kind, actor_identity, \
              raw_decision, created_at) VALUES ($1, $2, 'fixture', 'human', 'fixture', \
              '{}'::jsonb, clock_timestamp())",
        )
        .bind(row.id)
        .bind("f".repeat(64))
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("seed overflowing correlation read bound: {error}"));
        let mut connection = pool.acquire().await.expect("acquire overflow correlation reader");
        let overflow =
            load_correlations(&mut connection, row).await.expect_err("correlation overflow");
        assert!(overflow.to_string().contains("correlation history exceeds its public bound"));
    }

    async fn assert_loaded_suppression_bounds(pool: &PgPool, row: &TrackedFinding) {
        sqlx::query(
            "INSERT INTO finding_suppressions \
             (project_id, origin_finding_id, suppression_identity, suppression_schema, scope_kind, \
              finding_identity, actor_kind, actor_identity, raw_suppression, created_at) \
             SELECT $1, $2, lpad(to_hex(value), 64, '0'), 'fixture', 'finding', $3, \
                    'human', 'fixture', '{}'::jsonb, \
                    clock_timestamp() + value * interval '1 microsecond' \
             FROM generate_series(1, $4::integer) AS value",
        )
        .bind(row.project_id)
        .bind(row.id)
        .bind(&row.stable_identity)
        .bind(i32::try_from(MAX_TRIAGE_SUPPRESSIONS).expect("suppression limit fits i32"))
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("seed exact suppression read bound: {error}"));
        let finding: crate::engine::finding::Finding =
            serde_json::from_value(row.raw_finding.clone()).expect("decode triage unit finding");
        let subject = FindingTriageSubject::from_record(
            row.project_id.to_string(),
            &finding.canonical_appsec(),
        );
        let mut connection = pool.acquire().await.expect("acquire exact suppression reader");
        let exact = load_matching_suppressions(&mut connection, row, &subject)
            .await
            .expect_err("invalid exact suppressions");
        assert!(exact.to_string().contains("invalid raw finding suppression"));
        drop(connection);
        sqlx::query(
            "INSERT INTO finding_suppressions \
             (project_id, origin_finding_id, suppression_identity, suppression_schema, scope_kind, \
              finding_identity, actor_kind, actor_identity, raw_suppression, created_at) \
             VALUES ($1, $2, $3, 'fixture', 'finding', $4, 'human', 'fixture', '{}'::jsonb, \
                     clock_timestamp())",
        )
        .bind(row.project_id)
        .bind(row.id)
        .bind("f".repeat(64))
        .bind(&row.stable_identity)
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("seed overflowing suppression read bound: {error}"));
        let mut connection = pool.acquire().await.expect("acquire overflow suppression reader");
        let overflow = load_matching_suppressions(&mut connection, row, &subject)
            .await
            .expect_err("suppression overflow");
        assert!(overflow.to_string().contains("suppression history exceeds its public bound"));
    }

    async fn insert_existing_suppression(
        pool: &PgPool,
        row: &TrackedFinding,
        expected: &FindingSuppression,
    ) {
        sqlx::query(
            "INSERT INTO finding_suppressions \
             (project_id, origin_finding_id, suppression_identity, suppression_schema, scope_kind, \
              finding_identity, rule_identity, target_identity, actor_kind, actor_identity, \
              raw_suppression, created_at, expires_at, review_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        )
        .bind(row.project_id)
        .bind(row.id)
        .bind(&expected.identity)
        .bind(&expected.schema)
        .bind(scope_kind(expected.scope.kind))
        .bind(&expected.scope.finding_identity)
        .bind(&expected.scope.rule_identity)
        .bind(&expected.scope.target_identity)
        .bind(actor_kind(expected.actor.kind))
        .bind(&expected.actor.identity)
        .bind(serde_json::to_value(expected).expect("suppression JSON"))
        .bind(expected.created_at)
        .bind(expected.expires_at)
        .bind(expected.review_at)
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("insert existing suppression fixture: {error}"));
    }

    async fn assert_existing_suppression_projection_guards(pool: &PgPool, row: &TrackedFinding) {
        let scope = FindingSuppressionScope {
            kind: FindingSuppressionScopeKind::RuleTarget,
            project_identity: row.project_id.to_string(),
            finding_identity: None,
            rule_identity: Some("b".repeat(64)),
            target_identity: Some("c".repeat(64)),
        };
        let expected = FindingSuppression::new(
            scope.clone(),
            actor(),
            "Independent database replay",
            time(1),
            Some(time(4)),
            Some(time(3)),
        );
        insert_existing_suppression(pool, row, &expected).await;
        for statement in [
            "UPDATE finding_suppressions SET suppression_schema = 'future' WHERE project_id = $1",
            "UPDATE finding_suppressions SET scope_kind = 'finding' WHERE project_id = $1",
            "UPDATE finding_suppressions SET finding_identity = 'foreign' WHERE project_id = $1",
            "UPDATE finding_suppressions SET rule_identity = repeat('d', 64) WHERE project_id = $1",
            "UPDATE finding_suppressions SET target_identity = repeat('d', 64) WHERE project_id = $1",
            "UPDATE finding_suppressions SET actor_kind = 'system' WHERE project_id = $1",
            "UPDATE finding_suppressions SET actor_identity = 'other' WHERE project_id = $1",
            "UPDATE finding_suppressions SET created_at = created_at + interval '1 second' WHERE project_id = $1",
            "UPDATE finding_suppressions SET expires_at = expires_at + interval '1 second' WHERE project_id = $1",
            "UPDATE finding_suppressions SET review_at = review_at + interval '1 second' WHERE project_id = $1",
        ] {
            let mut transaction = pool.begin().await.expect("begin suppression guard transaction");
            sqlx::query(statement)
                .bind(row.project_id)
                .execute(&mut *transaction)
                .await
                .expect("corrupt existing suppression projection");
            assert!(validate_existing_suppression(&mut transaction, row.project_id, &expected)
                .await
                .is_err());
            transaction.rollback().await.expect("rollback suppression guard transaction");
        }

        let selector_guard = FindingSuppression::new(
            scope,
            TriageActor::new(TriageActorKind::Human, "mutation-fixture/suppression-identity"),
            "Selector-guaranteed projection guard",
            time(1),
            Some(time(4)),
            Some(time(3)),
        );
        insert_existing_suppression(pool, row, &selector_guard).await;
        let mut transaction = pool.begin().await.expect("begin suppression selector guard");
        assert!(validate_existing_suppression(&mut transaction, row.project_id, &selector_guard)
            .await
            .is_err());
        transaction.rollback().await.expect("rollback suppression selector guard");
    }

    async fn insert_existing_correlation(
        pool: &PgPool,
        row: &TrackedFinding,
        expected: &FindingCorrelationDecision,
    ) {
        sqlx::query(
            "INSERT INTO finding_correlation_decisions \
             (tracked_finding_id, decision_identity, decision_schema, actor_kind, actor_identity, \
              raw_decision, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(row.id)
        .bind(&expected.identity)
        .bind(&expected.schema)
        .bind(actor_kind(expected.actor.kind))
        .bind(&expected.actor.identity)
        .bind(serde_json::to_value(expected).expect("correlation JSON"))
        .bind(expected.created_at)
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("insert existing correlation fixture: {error}"));
    }

    fn correlation_for_actor(
        row: &TrackedFinding,
        actor_identity: &str,
    ) -> FindingCorrelationDecision {
        FindingCorrelationDecision::new(
            &row.stable_identity,
            FindingCorrelationContributors {
                finding_identities: vec![row.stable_identity.clone(), "b".repeat(64)],
                scanner_ids: vec!["runtime".to_string(), "semgrep".to_string()],
                evidence_ids: vec!["c".repeat(64)],
                facets: vec![CorrelationKey::new("CWE", "79")],
            },
            "Selector-guaranteed projection guard",
            TriageActor::new(TriageActorKind::Human, actor_identity),
            time(2),
        )
    }

    async fn assert_existing_correlation_projection_guards(pool: &PgPool, row: &TrackedFinding) {
        let (expected, _) = correlation_row(row);
        insert_existing_correlation(pool, row, &expected).await;
        for statement in [
            "UPDATE finding_correlation_decisions SET decision_schema = 'future' WHERE tracked_finding_id = $1",
            "UPDATE finding_correlation_decisions SET actor_kind = 'system' WHERE tracked_finding_id = $1",
            "UPDATE finding_correlation_decisions SET actor_identity = 'other' WHERE tracked_finding_id = $1",
            "UPDATE finding_correlation_decisions SET created_at = created_at + interval '1 second' WHERE tracked_finding_id = $1",
        ] {
            let mut transaction = pool.begin().await.expect("begin correlation guard transaction");
            sqlx::query(statement)
                .bind(row.id)
                .execute(&mut *transaction)
                .await
                .expect("corrupt existing correlation projection");
            assert!(validate_existing_correlation(&mut transaction, row.id, &expected)
                .await
                .is_err());
            transaction.rollback().await.expect("rollback correlation guard transaction");
        }

        for actor_identity in
            ["mutation-fixture/correlation-parent", "mutation-fixture/correlation-identity"]
        {
            let selector_guard = correlation_for_actor(row, actor_identity);
            insert_existing_correlation(pool, row, &selector_guard).await;
            let mut transaction = pool.begin().await.expect("begin correlation selector guard");
            assert!(validate_existing_correlation(&mut transaction, row.id, &selector_guard)
                .await
                .is_err());
            transaction.rollback().await.expect("rollback correlation selector guard");
        }
    }

    #[test]
    fn closed_strings_parse_without_aliases() {
        assert_eq!(
            FindingTriageState::from_str("needs_context"),
            Ok(FindingTriageState::NeedsContext)
        );
        assert_eq!(
            FindingSuppressionScopeKind::from_str("rule_target"),
            Ok(FindingSuppressionScopeKind::RuleTarget)
        );
        assert!(FindingTriageState::from_str("verified").is_err());
        assert!(FindingSuppressionScopeKind::from_str("global").is_err());
    }

    #[test]
    fn durable_history_bounds_accept_the_limit_and_reject_one_more() {
        assert!(ensure_count_bound(
            i64::try_from(MAX_TRIAGE_CORRELATIONS).expect("correlation limit fits i64"),
            MAX_TRIAGE_CORRELATIONS,
            "correlations",
        )
        .is_ok());
        assert!(ensure_count_bound(
            i64::try_from(MAX_TRIAGE_CORRELATIONS + 1).expect("correlation overflow fits i64"),
            MAX_TRIAGE_CORRELATIONS,
            "correlations",
        )
        .is_err());
    }

    #[test]
    fn transition_row_rejects_every_duplicated_projection_mismatch() {
        let project_id = Uuid::new_v4();
        let parent = parent(project_id, Uuid::new_v4());
        let (_, valid) = transition_row(&parent);
        validate_transition_row(&parent, &valid).expect("valid transition row");

        let mut changed = valid.clone();
        changed.tracked_finding_id = Uuid::new_v4();
        assert!(validate_transition_row(&parent, &changed).is_err());
        let mut changed = valid.clone();
        changed.transition_identity = "f".repeat(64);
        assert!(validate_transition_row(&parent, &changed).is_err());
        let mut changed = valid.clone();
        changed.transition_schema = "future".to_string();
        assert!(validate_transition_row(&parent, &changed).is_err());
        let mut changed = valid.clone();
        changed.sequence += 1;
        assert!(validate_transition_row(&parent, &changed).is_err());
        let mut changed = valid.clone();
        changed.from_state = Some("likely".to_string());
        assert!(validate_transition_row(&parent, &changed).is_err());
        let mut changed = valid.clone();
        changed.to_state = "validated".to_string();
        assert!(validate_transition_row(&parent, &changed).is_err());
        let mut changed = valid.clone();
        changed.actor_kind = "system".to_string();
        assert!(validate_transition_row(&parent, &changed).is_err());
        let mut changed = valid.clone();
        changed.actor_identity = "other".to_string();
        assert!(validate_transition_row(&parent, &changed).is_err());
        let mut changed = valid.clone();
        changed.observed_at += chrono::Duration::microseconds(1);
        assert!(validate_transition_row(&parent, &changed).is_err());
        let mut changed_parent = parent.clone();
        changed_parent.stable_identity = "b".repeat(64);
        assert!(validate_transition_row(&changed_parent, &valid).is_err());
        let mut changed = valid;
        changed
            .raw_transition
            .as_object_mut()
            .expect("transition object")
            .insert("extra".to_string(), serde_json::Value::Bool(true));
        assert!(validate_transition_row(&parent, &changed).is_err());
    }

    #[test]
    fn correlation_row_rejects_every_duplicated_projection_mismatch() {
        let parent = parent(Uuid::new_v4(), Uuid::new_v4());
        let (_, valid) = correlation_row(&parent);
        validate_correlation_row(&parent, &valid).expect("valid correlation row");

        let mut changed = valid.clone();
        changed.tracked_finding_id = Uuid::new_v4();
        assert_correlation_row_rejected(&parent, &changed);
        let mut changed = valid.clone();
        changed.decision_identity = "f".repeat(64);
        assert_correlation_row_rejected(&parent, &changed);
        let mut changed = valid.clone();
        changed.decision_schema = "future".to_string();
        assert_correlation_row_rejected(&parent, &changed);
        let mut changed = valid.clone();
        changed.actor_kind = "system".to_string();
        assert_correlation_row_rejected(&parent, &changed);
        let mut changed = valid.clone();
        changed.actor_identity = "other".to_string();
        assert_correlation_row_rejected(&parent, &changed);
        let mut changed = valid.clone();
        changed.created_at += chrono::Duration::microseconds(1);
        assert_correlation_row_rejected(&parent, &changed);
        let mut changed_parent = parent.clone();
        changed_parent.stable_identity = "b".repeat(64);
        assert!(validate_correlation_row(&changed_parent, &valid).is_err());
        let mut changed = valid;
        changed
            .raw_decision
            .as_object_mut()
            .expect("decision object")
            .insert("extra".to_string(), serde_json::Value::Bool(true));
        assert_correlation_row_rejected(&parent, &changed);
    }

    #[test]
    fn suppression_row_rejects_every_duplicated_projection_mismatch() {
        let project_id = Uuid::new_v4();
        let (_, valid) = suppression_row(project_id);
        validate_suppression_row(project_id, &valid).expect("valid suppression row");

        let mut changed = valid.clone();
        changed.project_id = Uuid::new_v4();
        assert_suppression_row_rejected(project_id, &changed);
        let mut changed = valid.clone();
        changed.suppression_identity = "f".repeat(64);
        assert_suppression_row_rejected(project_id, &changed);
        let mut changed = valid.clone();
        changed.suppression_schema = "future".to_string();
        assert_suppression_row_rejected(project_id, &changed);
        let mut changed = valid.clone();
        changed.scope_kind = "finding".to_string();
        assert_suppression_row_rejected(project_id, &changed);
        let mut changed = valid.clone();
        changed.finding_identity = Some("finding".to_string());
        assert_suppression_row_rejected(project_id, &changed);
        let mut changed = valid.clone();
        changed.rule_identity = Some("d".repeat(64));
        assert_suppression_row_rejected(project_id, &changed);
        let mut changed = valid.clone();
        changed.target_identity = Some("d".repeat(64));
        assert_suppression_row_rejected(project_id, &changed);
        let mut changed = valid.clone();
        changed.actor_kind = "system".to_string();
        assert_suppression_row_rejected(project_id, &changed);
        let mut changed = valid.clone();
        changed.actor_identity = "other".to_string();
        assert_suppression_row_rejected(project_id, &changed);
        let mut changed = valid.clone();
        changed.created_at += chrono::Duration::microseconds(1);
        assert_suppression_row_rejected(project_id, &changed);
        let mut changed = valid.clone();
        changed.expires_at = Some(time(5));
        assert_suppression_row_rejected(project_id, &changed);
        let mut changed = valid.clone();
        changed.review_at = Some(time(4));
        assert_suppression_row_rejected(project_id, &changed);
        let mut changed = valid;
        changed
            .raw_suppression
            .as_object_mut()
            .expect("suppression object")
            .insert("extra".to_string(), serde_json::Value::Bool(true));
        assert_suppression_row_rejected(project_id, &changed);

        let foreign_scope = FindingSuppression::new(
            FindingSuppressionScope {
                kind: FindingSuppressionScopeKind::RuleTarget,
                project_identity: Uuid::new_v4().to_string(),
                finding_identity: None,
                rule_identity: Some("b".repeat(64)),
                target_identity: Some("c".repeat(64)),
            },
            actor(),
            "Foreign scope project",
            time(1),
            Some(time(4)),
            Some(time(3)),
        );
        let mut foreign_row = suppression_row(project_id).1;
        foreign_row.suppression_identity = foreign_scope.identity.clone();
        foreign_row.suppression_schema = foreign_scope.schema.clone();
        foreign_row.scope_kind = scope_kind(foreign_scope.scope.kind).to_string();
        foreign_row.finding_identity = foreign_scope.scope.finding_identity.clone();
        foreign_row.rule_identity = foreign_scope.scope.rule_identity.clone();
        foreign_row.target_identity = foreign_scope.scope.target_identity.clone();
        foreign_row.actor_kind = actor_kind(foreign_scope.actor.kind).to_string();
        foreign_row.actor_identity = foreign_scope.actor.identity.clone();
        foreign_row.raw_suppression =
            serde_json::to_value(&foreign_scope).expect("foreign suppression JSON");
        foreign_row.created_at = foreign_scope.created_at;
        foreign_row.expires_at = foreign_scope.expires_at;
        foreign_row.review_at = foreign_scope.review_at;
        assert!(validate_suppression_row(project_id, &foreign_row).is_err());
    }

    #[tokio::test]
    async fn database_child_read_bounds_distinguish_exact_from_first_overflow() {
        let Some((pool, project_id, row)) = database_parent("triage-read-bounds").await else {
            return;
        };
        assert_loaded_history_bounds(&pool, &row).await;
        assert_loaded_correlation_bounds(&pool, &row).await;
        assert_loaded_suppression_bounds(&pool, &row).await;
        crate::storage::projects::delete_project(&pool, project_id)
            .await
            .expect("delete triage read-bound project");
    }

    #[tokio::test]
    async fn correlation_contributor_inner_guard_rejects_duplicates_independently() {
        let Some((pool, project_id, row)) = database_parent("triage-inner-guard").await else {
            return;
        };
        let mut transaction = pool.begin().await.expect("begin inner-guard transaction");
        let duplicate_ids = [row.id, row.id];
        let result = correlation_contributors(
            &mut transaction,
            &row,
            &duplicate_ids,
            Vec::new(),
            Vec::new(),
        )
        .await;
        assert!(result.is_err_and(|error| error.to_string().contains("must be unique")));
        transaction.rollback().await.expect("rollback inner-guard transaction");
        crate::storage::projects::delete_project(&pool, project_id)
            .await
            .expect("delete inner-guard project");
    }

    #[tokio::test]
    async fn existing_replays_reject_each_reachable_duplicated_column_independently() {
        let Some((pool, project_id, row)) = database_parent("triage-existing-replay").await else {
            return;
        };
        assert_existing_suppression_projection_guards(&pool, &row).await;
        assert_existing_correlation_projection_guards(&pool, &row).await;
        crate::storage::projects::delete_project(&pool, project_id)
            .await
            .expect("delete existing-replay project");
    }

    #[test]
    fn actor_and_optional_timestamp_projections_are_exact() {
        assert_eq!(actor_kind(TriageActorKind::Human), "human");
        assert_eq!(actor_kind(TriageActorKind::System), "system");
        assert_eq!(optional_micros(None), None);
        assert_eq!(optional_micros(Some(time(2))), Some(time(2).timestamp_micros()));
    }
}
