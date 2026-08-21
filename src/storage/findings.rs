//! Finding persistence with versioned identity and append-preserved evidence.
//!
//! A canonical v2 finding identity deduplicates equivalent observations for a project. Scanner
//! evidence and labeled agent analysis are stored as independently identified child records so an
//! update cannot discard prior proof.

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use url::Url;
use uuid::Uuid;

use super::models::{FindingEvidence, ScanRecord, StoredAgentAnalysis, TrackedFinding, VulnStatus};
use crate::application_pentest::PreparedApplicationEvidenceImport;
use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::observation::{
    redact_text, redact_url, EvidencePayload, EvidenceRecord, FindingRecordV2,
};

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

/// Durable result of one atomic application-pentest scan and finding write.
pub struct StoredApplicationPentestScan {
    pub scan: ScanRecord,
    pub findings_new: usize,
}

/// Store an application-pentest execution record and every finding in one transaction.
///
/// # Errors
///
/// Returns a database or canonical finding error. No scan or finding change is committed unless
/// the complete batch succeeds.
pub async fn save_application_pentest_scan(
    pool: &PgPool,
    project_id: Uuid,
    result: &crate::engine::scan_result::ScanResult,
) -> Result<StoredApplicationPentestScan> {
    let writes = result.findings.iter().map(FindingWrite::prepare).collect::<Result<Vec<_>>>()?;
    let modules_skipped: Vec<String> =
        result.modules_skipped.iter().map(|(id, reason)| format!("{id}: {reason}")).collect();
    let summary = serde_json::to_value(&result.summary)
        .map_err(|error| ScorchError::Database(format!("serialize scan summary: {error}")))?;
    let execution_evidence = super::scans::execution_evidence(result);
    let mut transaction = pool.begin().await.map_err(|error| {
        ScorchError::Database(format!("begin application-pentest scan: {error}"))
    })?;
    let scan = sqlx::query_as::<_, ScanRecord>(
        "INSERT INTO scan_records \
         (project_id, target_url, profile, started_at, completed_at, modules_run, \
          modules_skipped, summary, execution_evidence) \
         VALUES ($1, $2, 'application-pentest', $3, $4, $5, $6, $7, $8) RETURNING *",
    )
    .bind(project_id)
    .bind(result.target.url.as_str())
    .bind(result.started_at)
    .bind(result.completed_at)
    .bind(&result.modules_run)
    .bind(&modules_skipped)
    .bind(&summary)
    .bind(&execution_evidence)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| ScorchError::Database(format!("insert application-pentest scan: {error}")))?;
    let mut findings_new = 0;
    for write in &writes {
        let (_, created) =
            save_finding_in_transaction(&mut transaction, project_id, scan.id, write).await?;
        findings_new += usize::from(created);
    }
    transaction.commit().await.map_err(|error| {
        ScorchError::Database(format!("commit application-pentest scan: {error}"))
    })?;
    Ok(StoredApplicationPentestScan { scan, findings_new })
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

    let (_, created) =
        save_finding_in_transaction(&mut transaction, project_id, scan_id, &write).await?;

    transaction
        .commit()
        .await
        .map_err(|e| ScorchError::Database(format!("commit finding transaction: {e}")))?;
    Ok(created)
}

async fn save_finding_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    scan_id: Uuid,
    write: &FindingWrite<'_>,
) -> Result<(Uuid, bool)> {
    lock_finding_identity(transaction, project_id, write).await?;
    let existing_id = find_existing_id(transaction, project_id, write).await?;
    let (tracked_finding_id, created) =
        upsert_tracked_finding(transaction, project_id, scan_id, write, existing_id).await?;
    append_observations(transaction, tracked_finding_id, scan_id, &write.appsec).await?;
    Ok((tracked_finding_id, created))
}

/// Durable result of one atomic manual/proxy application-evidence import.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredApplicationEvidenceImport {
    pub scan_id: Uuid,
    pub finding_id: Uuid,
    pub finding_identity: String,
    pub finding_created: bool,
    pub evidence_appended: usize,
    pub assessment: scorchkit_core::ApplicationEvidenceImportAssessment,
}

/// Atomically store one verified import execution and its existing/new finding evidence linkage.
///
/// # Errors
///
/// Returns a database or canonical evidence error. Existing finding IDs must belong to the same
/// project. The transaction rolls back the scan row, finding change, and evidence together.
pub async fn save_application_evidence_import(
    pool: &PgPool,
    project_id: Uuid,
    prepared: &PreparedApplicationEvidenceImport,
) -> Result<StoredApplicationEvidenceImport> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| ScorchError::Database(format!("begin evidence import: {error}")))?;

    let (existing_finding_id, existing_identity) = if let Some(finding_id) =
        prepared.existing_finding_id
    {
        let row = sqlx::query_as::<_, (Uuid, String, String)>(
                "SELECT id, stable_identity, affected_target FROM tracked_findings \
                 WHERE id = $1 AND project_id = $2 FOR UPDATE",
            )
            .bind(finding_id)
            .bind(project_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| {
                ScorchError::Database(format!("lock imported-evidence finding: {error}"))
            })?
            .ok_or_else(|| {
                ScorchError::Config(format!(
                    "application evidence finding '{finding_id}' does not belong to project {project_id}"
                ))
            })?;
        validate_existing_finding_evidence_target(&row.2, prepared)?;
        (Some(row.0), Some(row.1))
    } else {
        (None, None)
    };

    let new_identity =
        prepared.new_finding.as_ref().map(|finding| finding.canonical_appsec().identity.value);
    let finding_identity = existing_identity.or(new_identity).ok_or_else(|| {
        ScorchError::Config(
            "application evidence import has no existing or new finding identity".to_string(),
        )
    })?;
    let mut assessment = prepared.assessment.clone();
    assessment.finding_identity = Some(finding_identity.clone());
    assessment = assessment
        .canonicalize()
        .map_err(|error| ScorchError::Database(format!("canonicalize evidence import: {error}")))?;

    let scan_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let execution_evidence = serde_json::json!({
        "schema": "scorchkit.scan-execution-evidence.v1",
        "application_evidence_import": assessment,
    });
    let modules_run = vec!["manual-application-evidence".to_string()];
    let modules_skipped: Vec<String> = Vec::new();
    let summary = serde_json::json!({
        "total_findings": usize::from(prepared.new_finding.is_some()),
        "evidence_entries": prepared.evidence.len(),
    });
    sqlx::query(
        "INSERT INTO scan_records \
         (id, project_id, target_url, profile, started_at, completed_at, modules_run, \
          modules_skipped, summary, execution_evidence) \
         VALUES ($1, $2, $3, 'manual-application-evidence', $4, $4, $5, $6, $7, $8)",
    )
    .bind(scan_id)
    .bind(project_id)
    .bind(&assessment.target)
    .bind(now)
    .bind(&modules_run)
    .bind(&modules_skipped)
    .bind(&summary)
    .bind(&execution_evidence)
    .execute(&mut *transaction)
    .await
    .map_err(|error| ScorchError::Database(format!("insert evidence import scan: {error}")))?;

    let (finding_id, finding_created) = if let Some(finding_id) = existing_finding_id {
        (finding_id, false)
    } else {
        let mut finding = prepared.new_finding.clone().ok_or_else(|| {
            ScorchError::Config("application evidence new finding is missing".to_string())
        })?;
        finding.evidence = None;
        finding.http_evidence = None;
        finding.appsec.evidence.clear();
        let write = FindingWrite::prepare(&finding)?;
        save_finding_in_transaction(&mut transaction, project_id, scan_id, &write).await?
    };
    let evidence_appended =
        append_manual_evidence(&mut transaction, finding_id, scan_id, &prepared.evidence).await?;

    transaction
        .commit()
        .await
        .map_err(|error| ScorchError::Database(format!("commit evidence import: {error}")))?;
    Ok(StoredApplicationEvidenceImport {
        scan_id,
        finding_id,
        finding_identity,
        finding_created,
        evidence_appended,
        assessment,
    })
}

fn validate_existing_finding_evidence_target(
    affected_target: &str,
    prepared: &PreparedApplicationEvidenceImport,
) -> Result<()> {
    let finding_url = Url::parse(affected_target).map_err(|_| {
        ScorchError::Config(
            "manual application evidence requires an existing runtime HTTP(S) finding".to_string(),
        )
    })?;
    let assessment_url = Url::parse(&prepared.assessment.target).map_err(|_| {
        ScorchError::Config("application evidence assessment target is invalid".to_string())
    })?;
    if !same_origin(&finding_url, &assessment_url) {
        return Err(ScorchError::Config(
            "application evidence target does not match the existing finding origin".to_string(),
        ));
    }
    let finding_parameters: Vec<String> =
        finding_url.query_pairs().map(|(name, _)| name.into_owned()).collect();
    let compatible = prepared.evidence.iter().all(|record| {
        let EvidencePayload::Http { exchange } = &record.payload else {
            return false;
        };
        let Ok(evidence_url) = Url::parse(&exchange.url) else {
            return false;
        };
        same_origin(&finding_url, &evidence_url)
            && path_is_under(finding_url.path(), evidence_url.path())
            && finding_parameters.iter().all(|required| {
                evidence_url.query_pairs().any(|(name, _)| name.as_ref() == required)
            })
    });
    if !compatible {
        return Err(ScorchError::Config(
            "application evidence route or parameter does not match the existing finding"
                .to_string(),
        ));
    }
    Ok(())
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn path_is_under(base: &str, candidate: &str) -> bool {
    let base = base.trim_end_matches('/');
    base.is_empty()
        || candidate == base
        || candidate.strip_prefix(base).is_some_and(|rest| rest.starts_with('/'))
}

async fn append_manual_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    tracked_finding_id: Uuid,
    scan_id: Uuid,
    records: &[EvidenceRecord],
) -> Result<usize> {
    let mut appended = 0;
    for record in records {
        let normalized = record.clone().normalized();
        let raw_evidence = serde_json::to_value(&normalized)
            .map_err(|error| ScorchError::Database(format!("serialize evidence: {error}")))?;
        if normalized.identity != record.identity
            || normalized.schema != record.schema
            || serde_json::to_value(record).ok().as_ref() != Some(&raw_evidence)
        {
            return Err(ScorchError::Database(
                "manual evidence is not canonical at the persistence boundary".to_string(),
            ));
        }
        let result = sqlx::query(
            "INSERT INTO finding_evidence \
             (tracked_finding_id, scan_id, evidence_identity, evidence_schema, raw_evidence, collected_at) \
             SELECT $1, $2, $3, $4, $5, $6 \
             WHERE NOT EXISTS (SELECT 1 FROM finding_evidence \
                               WHERE tracked_finding_id = $1 AND evidence_identity = $3) \
             ON CONFLICT (tracked_finding_id, scan_id, evidence_identity) DO NOTHING",
        )
        .bind(tracked_finding_id)
        .bind(scan_id)
        .bind(&normalized.identity)
        .bind(&normalized.schema)
        .bind(raw_evidence)
        .bind(normalized.provenance.collected_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("insert manual finding evidence: {error}"))
        })?;
        appended += usize::try_from(result.rows_affected()).map_err(|_| {
            ScorchError::Database("manual evidence row count exceeds usize".to_string())
        })?;
    }
    Ok(appended)
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
    use crate::engine::evidence::HttpEvidence;
    use crate::engine::observation::ScannerProvenance;
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

    fn prepared_evidence(url: &str) -> PreparedApplicationEvidenceImport {
        let record = EvidenceRecord::http(
            HttpEvidence::new("GET", url, 200),
            ScannerProvenance::new("fixture", chrono::Utc::now()),
        );
        PreparedApplicationEvidenceImport {
            assessment: scorchkit_core::ApplicationEvidenceImportAssessment {
                schema: scorchkit_core::APPLICATION_EVIDENCE_IMPORT_SCHEMA_V1.to_string(),
                identity: "a".repeat(64),
                target: "https://example.com/api/items?id=".to_string(),
                source_kind: scorchkit_core::ApplicationEvidenceSourceKind::Human,
                source_label: "fixture".to_string(),
                format: scorchkit_core::ApplicationEvidenceFormat::HttpExchange,
                input_sha256: "b".repeat(64),
                entries_imported: 1,
                evidence_identities: vec![record.identity.clone()],
                finding_identity: None,
            },
            evidence: vec![record],
            new_finding: None,
            existing_finding_id: None,
        }
    }

    #[test]
    fn existing_finding_evidence_requires_exact_route_and_parameter_compatibility() {
        let finding = "https://example.com/api/items?id=fixture";
        validate_existing_finding_evidence_target(
            finding,
            &prepared_evidence("https://example.com/api/items?id=proof"),
        )
        .expect("matching runtime evidence");
        assert!(validate_existing_finding_evidence_target(
            finding,
            &prepared_evidence("https://example.com/other?id=proof")
        )
        .is_err());
        assert!(validate_existing_finding_evidence_target(
            finding,
            &prepared_evidence("https://example.com/api/items")
        )
        .is_err());
        assert!(validate_existing_finding_evidence_target(
            finding,
            &prepared_evidence("https://example.com/api/items?other=proof")
        )
        .is_err());
    }

    #[test]
    fn route_prefix_matching_respects_segment_boundaries() {
        assert!(path_is_under("", "/anything"));
        assert!(path_is_under("/api/items/", "/api/items"));
        assert!(path_is_under("/api/items", "/api/items/1"));
        assert!(!path_is_under("/api/items", "/api/itemsets"));
        assert!(!path_is_under("/api/items", "/other"));
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
