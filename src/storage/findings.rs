//! Finding persistence with versioned identity and append-preserved evidence.
//!
//! A canonical v2 finding identity deduplicates equivalent observations for a project. Scanner
//! evidence and labeled agent analysis are stored as independently identified child records so an
//! update cannot discard prior proof.

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::models::{FindingEvidence, StoredAgentAnalysis, TrackedFinding, VulnStatus};
use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::observation::{redact_text, redact_url, FindingRecordV2};

struct FindingWrite<'a> {
    finding: &'a Finding,
    appsec: FindingRecordV2,
    legacy_fingerprint: String,
    raw_json: serde_json::Value,
    correlation_keys: serde_json::Value,
    evidence: Option<String>,
    title: String,
    description: String,
    affected_target: String,
    remediation: Option<String>,
}

impl<'a> FindingWrite<'a> {
    fn prepare(finding: &'a Finding) -> Result<Self> {
        let appsec = finding.canonical_appsec();
        let raw_json = serde_json::to_value(finding)
            .map_err(|e| ScorchError::Database(format!("serialize finding: {e}")))?;
        let correlation_keys = serde_json::to_value(&appsec.correlation_keys)
            .map_err(|e| ScorchError::Database(format!("serialize correlation keys: {e}")))?;
        let evidence = finding.evidence.as_deref().map(redact_text);
        let title = redact_text(&finding.title);
        let description = redact_text(&finding.description);
        let affected_target = redact_url(&finding.affected_target).0;
        let remediation = finding.remediation.as_deref().map(redact_text);
        let legacy_fingerprint =
            legacy_fingerprint_parts(&finding.module_id, &title, &affected_target);

        Ok(Self {
            finding,
            appsec,
            legacy_fingerprint,
            raw_json,
            correlation_keys,
            evidence,
            title,
            description,
            affected_target,
            remediation,
        })
    }
}

/// Compute the canonical stable finding identity.
///
/// The core contract deliberately excludes evidence, descriptions, confidence, and timestamps.
#[must_use]
pub fn fingerprint(finding: &Finding) -> String {
    finding.canonical_appsec().identity.value
}

fn legacy_fingerprint_parts(module_id: &str, title: &str, affected_target: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(module_id.as_bytes());
    hasher.update(b"|");
    hasher.update(title.as_bytes());
    hasher.update(b"|");
    hasher.update(affected_target.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Save a batch of findings from a scan, deduplicating against existing
/// findings in the same project.
///
/// For each finding:
/// - If the fingerprint already exists for this project, update
///   `last_seen`, `seen_count`, and `scan_id` on the existing row.
/// - Otherwise, insert a new tracked finding.
///
/// Returns the number of new findings created (not counting updates).
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn save_findings(
    pool: &PgPool,
    project_id: Uuid,
    scan_id: Uuid,
    findings: &[Finding],
) -> Result<usize> {
    let mut new_count = 0;

    for finding in findings {
        new_count += usize::from(save_finding(pool, project_id, scan_id, finding).await?);
    }

    Ok(new_count)
}

async fn save_finding(
    pool: &PgPool,
    project_id: Uuid,
    scan_id: Uuid,
    finding: &Finding,
) -> Result<bool> {
    let write = FindingWrite::prepare(finding)?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|e| ScorchError::Database(format!("begin finding transaction: {e}")))?;

    lock_finding_identity(&mut transaction, project_id, &write).await?;
    let existing_id = find_existing_id(&mut transaction, project_id, &write).await?;
    let (tracked_finding_id, created) =
        upsert_tracked_finding(&mut transaction, project_id, scan_id, &write, existing_id).await?;
    append_observations(&mut transaction, tracked_finding_id, scan_id, &write.appsec).await?;

    transaction
        .commit()
        .await
        .map_err(|e| ScorchError::Database(format!("commit finding transaction: {e}")))?;
    Ok(created)
}

async fn lock_finding_identity(
    transaction: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    write: &FindingWrite<'_>,
) -> Result<()> {
    let lock_key = format!("{project_id}:{}", write.appsec.identity.value);
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut **transaction)
        .await
        .map_err(|e| ScorchError::Database(format!("lock finding identity: {e}")))?;
    Ok(())
}

async fn find_existing_id(
    transaction: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    write: &FindingWrite<'_>,
) -> Result<Option<Uuid>> {
    let current_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM tracked_findings \
         WHERE project_id = $1 AND stable_identity = $2",
    )
    .bind(project_id)
    .bind(&write.appsec.identity.value)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|e| ScorchError::Database(format!("lookup finding identity: {e}")))?;

    if current_id.is_some() {
        return Ok(current_id);
    }

    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM tracked_findings \
         WHERE project_id = $1 AND fingerprint = $2 \
           AND identity_schema <> $3 \
         ORDER BY first_seen, id LIMIT 1 FOR UPDATE",
    )
    .bind(project_id)
    .bind(&write.legacy_fingerprint)
    .bind(&write.appsec.identity.schema)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|e| ScorchError::Database(format!("lookup legacy finding: {e}")))
}

async fn upsert_tracked_finding(
    transaction: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    scan_id: Uuid,
    write: &FindingWrite<'_>,
    existing_id: Option<Uuid>,
) -> Result<(Uuid, bool)> {
    if let Some(id) = existing_id {
        update_tracked_finding(transaction, id, scan_id, write).await?;
        return Ok((id, false));
    }

    let finding = write.finding;
    let id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO tracked_findings \
         (scan_id, project_id, fingerprint, identity_schema, stable_identity, \
          correlation_keys, module_id, severity, title, description, affected_target, \
          evidence, remediation, owasp_category, cwe_id, raw_finding, confidence) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) \
         RETURNING id",
    )
    .bind(scan_id)
    .bind(project_id)
    .bind(&write.legacy_fingerprint)
    .bind(&write.appsec.identity.schema)
    .bind(&write.appsec.identity.value)
    .bind(&write.correlation_keys)
    .bind(&finding.module_id)
    .bind(finding.severity.to_string())
    .bind(&write.title)
    .bind(&write.description)
    .bind(&write.affected_target)
    .bind(&write.evidence)
    .bind(&write.remediation)
    .bind(&finding.owasp_category)
    .bind(finding.cwe_id.map(u32::cast_signed))
    .bind(&write.raw_json)
    .bind(finding.confidence)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|e| ScorchError::Database(format!("insert finding: {e}")))?;
    Ok((id, true))
}

async fn update_tracked_finding(
    transaction: &mut Transaction<'_, Postgres>,
    id: Uuid,
    scan_id: Uuid,
    write: &FindingWrite<'_>,
) -> Result<()> {
    let finding = write.finding;
    sqlx::query(
        "UPDATE tracked_findings \
         SET last_seen = now(), seen_count = seen_count + 1, scan_id = $2, \
             fingerprint = $3, identity_schema = $4, stable_identity = $5, \
             correlation_keys = $6, module_id = $7, severity = $8, title = $9, \
             description = $10, affected_target = $11, \
             evidence = COALESCE($12, evidence), remediation = $13, \
             owasp_category = $14, cwe_id = $15, raw_finding = $16, confidence = $17 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(scan_id)
    .bind(&write.legacy_fingerprint)
    .bind(&write.appsec.identity.schema)
    .bind(&write.appsec.identity.value)
    .bind(&write.correlation_keys)
    .bind(&finding.module_id)
    .bind(finding.severity.to_string())
    .bind(&write.title)
    .bind(&write.description)
    .bind(&write.affected_target)
    .bind(&write.evidence)
    .bind(&write.remediation)
    .bind(&finding.owasp_category)
    .bind(finding.cwe_id.map(u32::cast_signed))
    .bind(&write.raw_json)
    .bind(finding.confidence)
    .execute(&mut **transaction)
    .await
    .map_err(|e| ScorchError::Database(format!("update finding: {e}")))?;
    Ok(())
}

async fn append_observations(
    transaction: &mut Transaction<'_, Postgres>,
    tracked_finding_id: Uuid,
    scan_id: Uuid,
    appsec: &FindingRecordV2,
) -> Result<()> {
    for record in &appsec.evidence {
        let raw_evidence = serde_json::to_value(record)
            .map_err(|e| ScorchError::Database(format!("serialize evidence: {e}")))?;
        sqlx::query(
            "INSERT INTO finding_evidence \
             (tracked_finding_id, scan_id, evidence_identity, evidence_schema, raw_evidence, collected_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (tracked_finding_id, scan_id, evidence_identity) DO NOTHING",
        )
        .bind(tracked_finding_id)
        .bind(scan_id)
        .bind(&record.identity)
        .bind(&record.schema)
        .bind(raw_evidence)
        .bind(record.provenance.collected_at)
        .execute(&mut **transaction)
        .await
        .map_err(|e| ScorchError::Database(format!("insert finding evidence: {e}")))?;
    }

    for analysis in &appsec.agent_analysis {
        let raw_analysis = serde_json::to_value(analysis)
            .map_err(|e| ScorchError::Database(format!("serialize agent analysis: {e}")))?;
        sqlx::query(
            "INSERT INTO finding_agent_analysis \
             (tracked_finding_id, analysis_identity, analysis_schema, raw_analysis, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (tracked_finding_id, analysis_identity) DO NOTHING",
        )
        .bind(tracked_finding_id)
        .bind(&analysis.identity)
        .bind(&analysis.schema)
        .bind(raw_analysis)
        .bind(analysis.created_at)
        .execute(&mut **transaction)
        .await
        .map_err(|e| ScorchError::Database(format!("insert agent analysis: {e}")))?;
    }
    Ok(())
}

/// List append-preserved scanner evidence for a tracked finding.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn list_evidence(pool: &PgPool, finding_id: Uuid) -> Result<Vec<FindingEvidence>> {
    sqlx::query_as::<_, FindingEvidence>(
        "SELECT * FROM finding_evidence WHERE tracked_finding_id = $1 \
         ORDER BY collected_at, evidence_identity",
    )
    .bind(finding_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("list finding evidence: {e}")))
}

/// List append-preserved scanner evidence for every finding in one project.
///
/// This batch form lets correlation reconstruct durable proof history without one query per
/// finding.
///
/// # Errors
///
/// Returns an error if the database read fails.
pub async fn list_project_evidence(
    pool: &PgPool,
    project_id: Uuid,
    limit: usize,
) -> Result<Vec<FindingEvidence>> {
    let limit = i64::try_from(limit)
        .map_err(|_| ScorchError::Database("project evidence limit exceeds i64".to_string()))?;
    sqlx::query_as::<_, FindingEvidence>(
        "SELECT evidence.* FROM finding_evidence AS evidence \
         INNER JOIN tracked_findings AS finding ON finding.id = evidence.tracked_finding_id \
         WHERE finding.project_id = $1 \
         ORDER BY evidence.tracked_finding_id, evidence.collected_at, evidence.evidence_identity \
         LIMIT $2",
    )
    .bind(project_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("list project finding evidence: {e}")))
}

/// Count tracked findings without loading their JSON documents.
///
/// # Errors
///
/// Returns an error if the database read fails or the count cannot fit in `usize`.
pub async fn count_findings(pool: &PgPool, project_id: Uuid) -> Result<usize> {
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM tracked_findings WHERE project_id = $1")
            .bind(project_id)
            .fetch_one(pool)
            .await
            .map_err(|e| ScorchError::Database(format!("count project findings: {e}")))?;
    usize::try_from(count)
        .map_err(|_| ScorchError::Database("negative or oversized finding count".to_string()))
}

/// List append-preserved labeled agent analysis for a tracked finding.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn list_agent_analysis(
    pool: &PgPool,
    finding_id: Uuid,
) -> Result<Vec<StoredAgentAnalysis>> {
    sqlx::query_as::<_, StoredAgentAnalysis>(
        "SELECT * FROM finding_agent_analysis WHERE tracked_finding_id = $1 \
         ORDER BY created_at, analysis_identity",
    )
    .bind(finding_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("list agent analysis: {e}")))
}

/// Update the lifecycle status of a tracked finding with an optional note.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn update_finding_status(
    pool: &PgPool,
    finding_id: Uuid,
    status: VulnStatus,
    note: Option<&str>,
) -> Result<bool> {
    let result =
        sqlx::query("UPDATE tracked_findings SET status = $2, status_note = $3 WHERE id = $1")
            .bind(finding_id)
            .bind(status.as_db_str())
            .bind(note)
            .execute(pool)
            .await
            .map_err(|e| ScorchError::Database(format!("update finding status: {e}")))?;

    Ok(result.rows_affected() > 0)
}

/// Query findings for a project filtered by severity.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn find_by_severity(
    pool: &PgPool,
    project_id: Uuid,
    severity: &str,
) -> Result<Vec<TrackedFinding>> {
    sqlx::query_as::<_, TrackedFinding>(
        "SELECT * FROM tracked_findings \
         WHERE project_id = $1 AND severity = $2 \
         ORDER BY last_seen DESC",
    )
    .bind(project_id)
    .bind(severity)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("find by severity: {e}")))
}

/// Query findings for a project filtered by lifecycle status.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn find_by_status(
    pool: &PgPool,
    project_id: Uuid,
    status: VulnStatus,
) -> Result<Vec<TrackedFinding>> {
    sqlx::query_as::<_, TrackedFinding>(
        "SELECT * FROM tracked_findings \
         WHERE project_id = $1 AND status = $2 \
         ORDER BY last_seen DESC",
    )
    .bind(project_id)
    .bind(status.as_db_str())
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("find by status: {e}")))
}

/// Get all findings for a specific scan.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn find_by_scan(pool: &PgPool, scan_id: Uuid) -> Result<Vec<TrackedFinding>> {
    sqlx::query_as::<_, TrackedFinding>(
        "SELECT * FROM tracked_findings WHERE scan_id = $1 \
         ORDER BY severity DESC, title",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("find by scan: {e}")))
}

/// List all findings for a project, newest first.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn list_findings(pool: &PgPool, project_id: Uuid) -> Result<Vec<TrackedFinding>> {
    sqlx::query_as::<_, TrackedFinding>(
        "SELECT * FROM tracked_findings \
         WHERE project_id = $1 \
         ORDER BY last_seen DESC",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("list findings: {e}")))
}

/// Get a single tracked finding by ID.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn get_finding(pool: &PgPool, id: Uuid) -> Result<Option<TrackedFinding>> {
    sqlx::query_as::<_, TrackedFinding>("SELECT * FROM tracked_findings WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("get finding: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::severity::Severity;

    #[tokio::test]
    async fn finding_identity_lock_is_visible_to_other_transactions() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect mutation validation database");
        let finding = Finding::new("scanner", Severity::High, "Rule", "Desc", "src/lib.rs:7");
        let write = FindingWrite::prepare(&finding).expect("prepare finding");
        let project_id = Uuid::new_v4();
        let mut transaction = pool.begin().await.expect("begin lock holder");

        lock_finding_identity(&mut transaction, project_id, &write)
            .await
            .expect("lock finding identity");
        let lock_key = format!("{project_id}:{}", write.appsec.identity.value);
        let acquired_elsewhere: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(lock_key)
                .fetch_one(&pool)
                .await
                .expect("probe lock from a second connection");

        assert!(!acquired_elsewhere, "identity lock must serialize competing upserts");
        transaction.rollback().await.expect("release identity lock");
    }

    /// Verify that the same finding inputs always produce the same
    /// fingerprint hash, ensuring deterministic deduplication.
    #[test]
    fn test_finding_fingerprint_deterministic() {
        let f1 = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "desc",
            "https://example.com/login",
        );
        let f2 = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "desc",
            "https://example.com/login",
        );

        assert_eq!(fingerprint(&f1), fingerprint(&f2));
    }

    /// Verify that different affected targets produce different
    /// fingerprints, so the same vuln type on different pages
    /// tracks separately.
    #[test]
    fn test_fingerprint_differs_by_target() {
        let f1 = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "desc",
            "https://example.com/login",
        );
        let f2 = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "desc",
            "https://example.com/register",
        );

        assert_ne!(fingerprint(&f1), fingerprint(&f2));
    }

    /// Verify that evidence and timestamp do NOT affect the
    /// fingerprint — same vuln found at different times with
    /// different evidence should still dedup.
    #[test]
    fn test_fingerprint_ignores_evidence_and_timestamp() {
        let f1 = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "desc",
            "https://example.com/login",
        )
        .with_evidence("evidence 1");
        let f2 = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "desc",
            "https://example.com/login",
        )
        .with_evidence("evidence 2");

        assert_eq!(fingerprint(&f1), fingerprint(&f2));
    }

    #[test]
    fn legacy_fingerprint_hash_is_exact_and_stable() {
        assert_eq!(
            legacy_fingerprint_parts("scanner", "Rule", "src/lib.rs:7"),
            "c4826eac151b1a297d89b40dd98157d6a328d4018a487a82545934290115813f"
        );
    }
}
