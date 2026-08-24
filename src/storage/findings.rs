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
    redact_text, redact_url, AgentAnalysisRecord, EvidencePayload, EvidenceRecord, FindingRecordV2,
};

const MAX_VALIDATED_ANALYSES_PER_FINDING: usize = 1_000;

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

/// Canonical finding plus its verified durable metadata.
pub(crate) struct ValidatedFinding {
    pub(crate) row: TrackedFinding,
    pub(crate) canonical: serde_json::Value,
}

/// Canonical evidence plus its verified durable metadata.
pub(crate) struct ValidatedEvidence {
    pub(crate) row: FindingEvidence,
    pub(crate) canonical: serde_json::Value,
}

impl<'a> FindingWrite<'a> {
    fn prepare(finding: &'a Finding) -> Result<Self> {
        let appsec = finding.canonical_appsec();
        for analysis in &appsec.agent_analysis {
            analysis.validate().map_err(|error| {
                ScorchError::Database(format!("invalid canonical agent analysis: {error}"))
            })?;
        }
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
             evidence = $12, remediation = $13, \
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

/// Get and validate one canonical finding at the public durable boundary.
///
/// # Errors
///
/// Returns an error when storage fails or any canonical/duplicated projection differs.
pub(crate) async fn get_validated_finding(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<ValidatedFinding>> {
    let Some(row) = get_finding(pool, id).await? else {
        return Ok(None);
    };
    validate_finding_row(pool, row).await.map(Some)
}

/// List one bounded stable page of validated project findings.
///
/// # Errors
///
/// Returns an error for an invalid cursor/limit, database failure, or any corrupt row.
pub(crate) async fn list_validated_findings_page(
    pool: &PgPool,
    project_id: Uuid,
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<ValidatedFinding>> {
    let limit = validated_page_limit(limit)?;
    let cursor = if let Some(id) = after {
        let cursor = get_validated_finding(pool, id)
            .await?
            .filter(|finding| finding.row.project_id == project_id)
            .ok_or_else(|| ScorchError::Database("finding cursor was not found".to_string()))?;
        Some((cursor.row.first_seen, cursor.row.id))
    } else {
        None
    };
    let rows = sqlx::query_as::<_, TrackedFinding>(
        "SELECT * FROM tracked_findings \
         WHERE project_id = $1 \
           AND ($2::timestamptz IS NULL OR (first_seen, id) < ($2, $3)) \
         ORDER BY first_seen DESC, id DESC LIMIT $4",
    )
    .bind(project_id)
    .bind(cursor.map(|value| value.0))
    .bind(cursor.map(|value| value.1))
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|error| ScorchError::Database(format!("list validated finding page: {error}")))?;
    let mut validated = Vec::with_capacity(rows.len());
    for row in rows {
        validated.push(validate_finding_row(pool, row).await?);
    }
    Ok(validated)
}

/// List all validated findings up to one explicit aggregate ceiling.
///
/// # Errors
///
/// Returns an error instead of producing an incomplete aggregate when the ceiling is exceeded.
pub(crate) async fn list_validated_findings_bounded(
    pool: &PgPool,
    project_id: Uuid,
    maximum: usize,
) -> Result<Vec<ValidatedFinding>> {
    if !(1..=10_000).contains(&maximum) {
        return Err(ScorchError::Database(
            "validated finding aggregate limit must be 1-10000".to_string(),
        ));
    }
    let query_limit = i64::try_from(maximum.saturating_add(1)).map_err(|_| {
        ScorchError::Database("validated finding aggregate limit overflow".to_string())
    })?;
    let rows = sqlx::query_as::<_, TrackedFinding>(
        "SELECT * FROM tracked_findings WHERE project_id = $1 \
         ORDER BY last_seen DESC, id DESC LIMIT $2",
    )
    .bind(project_id)
    .bind(query_limit)
    .fetch_all(pool)
    .await
    .map_err(|error| ScorchError::Database(format!("list validated findings: {error}")))?;
    if rows.len() > maximum {
        return Err(ScorchError::Database(format!(
            "project findings exceed the bounded {maximum}-record report limit"
        )));
    }
    let mut validated = Vec::with_capacity(rows.len());
    for row in rows {
        validated.push(validate_finding_row(pool, row).await?);
    }
    Ok(validated)
}

/// List one bounded stable page of validated evidence.
///
/// # Errors
///
/// Returns an error for an invalid cursor/limit, missing parent, database failure, or corruption.
pub(crate) async fn list_validated_evidence_page(
    pool: &PgPool,
    finding_id: Uuid,
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<ValidatedEvidence>> {
    let limit = validated_page_limit(limit)?;
    let parent = get_validated_finding(pool, finding_id).await?.ok_or_else(|| {
        ScorchError::Database("evidence parent finding was not found".to_string())
    })?;
    let cursor = if let Some(id) = after {
        let cursor = sqlx::query_as::<_, FindingEvidence>(
            "SELECT * FROM finding_evidence WHERE tracked_finding_id = $1 AND id = $2",
        )
        .bind(finding_id)
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|error| ScorchError::Database(format!("load evidence cursor: {error}")))?
        .ok_or_else(|| ScorchError::Database("evidence cursor was not found".to_string()))?;
        let cursor = validate_evidence_row(pool, &parent, cursor).await?;
        Some((cursor.row.collected_at, cursor.row.id))
    } else {
        None
    };
    let rows = sqlx::query_as::<_, FindingEvidence>(
        "SELECT * FROM finding_evidence \
         WHERE tracked_finding_id = $1 \
           AND ($2::timestamptz IS NULL OR (collected_at, id) > ($2, $3)) \
         ORDER BY collected_at, id LIMIT $4",
    )
    .bind(finding_id)
    .bind(cursor.map(|value| value.0))
    .bind(cursor.map(|value| value.1))
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|error| ScorchError::Database(format!("list validated evidence page: {error}")))?;
    let mut validated = Vec::with_capacity(rows.len());
    for row in rows {
        validated.push(validate_evidence_row(pool, &parent, row).await?);
    }
    Ok(validated)
}

async fn validate_finding_row(pool: &PgPool, row: TrackedFinding) -> Result<ValidatedFinding> {
    let declared_appsec = row
        .raw_finding
        .get("appsec")
        .cloned()
        .map(serde_json::from_value::<FindingRecordV2>)
        .transpose()
        .map_err(|error| canonical_mismatch(format!("invalid raw finding appsec: {error}")))?;
    let finding: Finding = serde_json::from_value(row.raw_finding.clone())
        .map_err(|error| canonical_mismatch(format!("invalid raw finding: {error}")))?;
    let write = FindingWrite::prepare(&finding)?;
    if let Some(declared) = declared_appsec {
        let declared = serde_json::to_value(declared)
            .map_err(|error| canonical_mismatch(format!("serialize declared finding: {error}")))?;
        let normalized = serde_json::to_value(&write.appsec)
            .map_err(|error| canonical_mismatch(format!("serialize canonical finding: {error}")))?;
        if declared != normalized {
            return Err(canonical_mismatch(
                "raw finding is not canonical at the durable read boundary",
            ));
        }
    }
    let expected_cwe = finding.cwe_id.map(u32::cast_signed);
    let projections_match = row.fingerprint == write.legacy_fingerprint
        && row.identity_schema == write.appsec.identity.schema
        && row.stable_identity == write.appsec.identity.value
        && row.correlation_keys == write.correlation_keys
        && row.module_id == finding.module_id
        && row.severity == finding.severity.to_string()
        && row.title == write.title
        && row.description == write.description
        && row.affected_target == write.affected_target
        && row.evidence == write.evidence
        && row.remediation == write.remediation
        && row.owasp_category == finding.owasp_category
        && row.cwe_id == expected_cwe
        && row.confidence.to_bits() == finding.confidence.to_bits()
        && row.seen_count > 0
        && row.first_seen <= row.last_seen
        && row.found_at.timestamp_micros() == row.first_seen.timestamp_micros()
        && VulnStatus::from_db(&row.status).is_some();
    if !projections_match {
        return Err(canonical_mismatch(
            "finding canonical document and duplicated projection differ",
        ));
    }
    validate_scan_project(pool, row.scan_id, row.project_id).await?;
    for declared in &write.appsec.agent_analysis {
        declared.validate().map_err(|error| {
            canonical_mismatch(format!("invalid declared agent analysis: {error}"))
        })?;
    }
    let canonical = serde_json::to_value(&finding)
        .map_err(|error| canonical_mismatch(format!("serialize validated finding: {error}")))?;
    let mut validated = ValidatedFinding { row, canonical };
    for declared in &write.appsec.evidence {
        let evidence = sqlx::query_as::<_, FindingEvidence>(
            "SELECT * FROM finding_evidence \
             WHERE tracked_finding_id = $1 AND scan_id = $2 AND evidence_identity = $3",
        )
        .bind(validated.row.id)
        .bind(validated.row.scan_id)
        .bind(&declared.identity)
        .fetch_optional(pool)
        .await
        .map_err(|error| ScorchError::Database(format!("load declared finding evidence: {error}")))?
        .ok_or_else(|| canonical_mismatch("canonical finding evidence row is missing"))?;
        let evidence = validate_evidence_row(pool, &validated, evidence).await?;
        let declared = serde_json::to_value(declared.clone().normalized()).map_err(|error| {
            canonical_mismatch(format!("serialize declared finding evidence: {error}"))
        })?;
        if evidence.canonical != declared {
            return Err(canonical_mismatch(
                "canonical finding and declared evidence document differ",
            ));
        }
    }

    let analyses =
        load_validated_analyses(pool, validated.row.id, &write.appsec.agent_analysis).await?;
    let mut projected = finding;
    projected.appsec.agent_analysis = analyses;
    validated.canonical = serde_json::to_value(projected)
        .map_err(|error| canonical_mismatch(format!("serialize projected finding: {error}")))?;
    Ok(validated)
}

async fn load_validated_analyses(
    pool: &PgPool,
    parent_finding_id: Uuid,
    declared_analyses: &[AgentAnalysisRecord],
) -> Result<Vec<AgentAnalysisRecord>> {
    let query_limit = i64::try_from(MAX_VALIDATED_ANALYSES_PER_FINDING + 1)
        .map_err(|_| canonical_mismatch("agent analysis limit overflow"))?;
    let rows = sqlx::query_as::<_, StoredAgentAnalysis>(
        "SELECT * FROM finding_agent_analysis WHERE tracked_finding_id = $1 \
         ORDER BY analysis_identity LIMIT $2",
    )
    .bind(parent_finding_id)
    .bind(query_limit)
    .fetch_all(pool)
    .await
    .map_err(|error| ScorchError::Database(format!("load validated agent analysis: {error}")))?;
    if rows.len() > MAX_VALIDATED_ANALYSES_PER_FINDING {
        return Err(canonical_mismatch(
            "agent analysis exceeds the bounded public projection limit",
        ));
    }
    let analyses = rows
        .iter()
        .map(|row| validate_analysis_row(parent_finding_id, row))
        .collect::<Result<Vec<_>>>()?;
    if declared_analyses
        .iter()
        .any(|declared| !analyses.iter().any(|analysis| analysis == declared))
    {
        return Err(canonical_mismatch(
            "canonical finding and declared agent analysis document differ",
        ));
    }
    Ok(analyses)
}

fn validate_analysis_row(
    parent_finding_id: Uuid,
    row: &StoredAgentAnalysis,
) -> Result<AgentAnalysisRecord> {
    if row.tracked_finding_id != parent_finding_id {
        return Err(canonical_mismatch("agent analysis parent finding projection differs"));
    }
    let declared: AgentAnalysisRecord = serde_json::from_value(row.raw_analysis.clone())
        .map_err(|error| canonical_mismatch(format!("invalid raw agent analysis: {error}")))?;
    declared
        .validate()
        .map_err(|error| canonical_mismatch(format!("invalid agent analysis: {error}")))?;
    let normalized = declared.normalized();
    let canonical = serde_json::to_value(&normalized)
        .map_err(|error| canonical_mismatch(format!("serialize agent analysis: {error}")))?;
    if row.raw_analysis != canonical
        || row.analysis_schema != normalized.schema
        || row.analysis_identity != normalized.identity
        || row.created_at.timestamp_micros() != normalized.created_at.timestamp_micros()
    {
        return Err(canonical_mismatch(
            "agent analysis canonical document and duplicated projection differ",
        ));
    }
    Ok(normalized)
}

async fn validate_evidence_row(
    pool: &PgPool,
    parent: &ValidatedFinding,
    row: FindingEvidence,
) -> Result<ValidatedEvidence> {
    if row.tracked_finding_id != parent.row.id {
        return Err(canonical_mismatch("evidence parent finding projection differs"));
    }
    let declared: EvidenceRecord = serde_json::from_value(row.raw_evidence.clone())
        .map_err(|error| canonical_mismatch(format!("invalid raw evidence: {error}")))?;
    let normalized = declared.clone().normalized();
    let canonical = serde_json::to_value(&normalized)
        .map_err(|error| canonical_mismatch(format!("serialize canonical evidence: {error}")))?;
    if row.raw_evidence != canonical
        || row.evidence_schema != normalized.schema
        || row.evidence_identity != normalized.identity
        || row.collected_at.timestamp_micros()
            != normalized.provenance.collected_at.timestamp_micros()
    {
        return Err(canonical_mismatch(
            "evidence canonical document and duplicated projection differ",
        ));
    }
    validate_scan_project(pool, row.scan_id, parent.row.project_id).await?;
    Ok(ValidatedEvidence { row, canonical })
}

async fn validate_scan_project(pool: &PgPool, scan_id: Uuid, project_id: Uuid) -> Result<()> {
    let stored_project =
        sqlx::query_scalar::<_, Uuid>("SELECT project_id FROM scan_records WHERE id = $1")
            .bind(scan_id)
            .fetch_optional(pool)
            .await
            .map_err(|error| {
                ScorchError::Database(format!("validate finding scan project: {error}"))
            })?;
    if stored_project != Some(project_id) {
        return Err(canonical_mismatch("finding or evidence scan/project projection differs"));
    }
    Ok(())
}

fn validated_page_limit(limit: usize) -> Result<i64> {
    if !(1..=201).contains(&limit) {
        return Err(ScorchError::Database(
            "validated control page limit must be 1-201".to_string(),
        ));
    }
    i64::try_from(limit)
        .map_err(|_| ScorchError::Database("validated control page limit overflow".to_string()))
}

fn canonical_mismatch(message: impl Into<String>) -> ScorchError {
    ScorchError::Database(format!("canonical projection mismatch: {}", message.into()))
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

    #[test]
    fn canonical_write_rejects_invalid_model_analysis_provenance() {
        let now = chrono::Utc::now();
        let mut analysis = model_analysis_record(now);
        analysis.model_provenance.as_mut().expect("provenance").schema = "future".to_string();
        let finding = Finding::new(
            "fixture",
            Severity::High,
            "Canonical fixture",
            "Canonical description",
            "src/lib.rs:7",
        )
        .with_agent_analysis(analysis);
        let Err(error) = FindingWrite::prepare(&finding) else {
            panic!("invalid model analysis was accepted");
        };
        assert!(error.to_string().contains("invalid canonical agent analysis"));
    }

    struct CanonicalFixture {
        project: Uuid,
        scan: Uuid,
        finding: Uuid,
        evidence: Uuid,
        analysis: Uuid,
    }

    fn model_analysis_record(now: chrono::DateTime<chrono::Utc>) -> AgentAnalysisRecord {
        let request = scorchkit_core::ModelAnalysisRequest::analysis(
            "fixture-host",
            "exact-model",
            scorchkit_core::ModelRole::FindingValidation,
            "workflow/v1",
            vec![scorchkit_core::ModelAnalysisInput::new("1".repeat(64), "canonical evidence")
                .expect("model input")],
            "validate",
        )
        .expect("model request");
        let response = scorchkit_core::ModelAnalysisResponse {
            schema: scorchkit_core::MODEL_ANALYSIS_CONTRACT_V1.to_string(),
            provider: "fixture-host".to_string(),
            model: "exact-model".to_string(),
            role: scorchkit_core::ModelRole::FindingValidation,
            payload: scorchkit_core::ModelResponsePayload::Analysis {
                summary: "Canonical model analysis".to_string(),
                confidence_bps: 8_000,
                evidence_digests: vec!["1".repeat(64)],
            },
        };
        let provenance = scorchkit_core::ModelAnalysisProvenance::from_validated_response(
            &request,
            &response,
            scorchkit_core::ModelExecutionLocation::HostManaged,
            now,
        )
        .expect("model provenance");
        AgentAnalysisRecord::from_model(provenance, "Canonical model analysis")
            .expect("model analysis")
    }

    async fn canonical_fixture(pool: &PgPool) -> CanonicalFixture {
        let project = crate::storage::projects::create_project(
            pool,
            &format!("control-canonical-{}", Uuid::new_v4()),
            "canonical validation fixture",
        )
        .await
        .expect("create canonical project");
        let now = chrono::Utc::now();
        let scan = crate::storage::scans::save_scan(
            pool,
            project.id,
            "https://example.com/items?id=1",
            "quick",
            now,
            Some(now),
            &["fixture".to_string()],
            &[],
            &serde_json::json!({}),
        )
        .await
        .expect("create canonical scan");
        let finding = Finding::new(
            "fixture",
            Severity::High,
            "Canonical fixture",
            "Canonical description",
            "https://example.com/items?id=1",
        )
        .with_evidence("canonical evidence")
        .with_remediation("canonical remediation")
        .with_owasp("A03:2021")
        .with_cwe(89)
        .with_confidence(0.75)
        .with_agent_analysis(model_analysis_record(now));
        save_findings(pool, project.id, scan.id, &[finding]).await.expect("save canonical finding");
        let finding = list_findings(pool, project.id)
            .await
            .expect("list fixture findings")
            .into_iter()
            .next()
            .expect("fixture finding");
        let evidence = list_evidence(pool, finding.id)
            .await
            .expect("list fixture evidence")
            .into_iter()
            .next()
            .expect("fixture evidence");
        let analysis = list_agent_analysis(pool, finding.id)
            .await
            .expect("list fixture analysis")
            .into_iter()
            .next()
            .expect("fixture analysis");
        CanonicalFixture {
            project: project.id,
            scan: scan.id,
            finding: finding.id,
            evidence: evidence.id,
            analysis: analysis.id,
        }
    }

    async fn insert_bounded_analysis_fixtures(
        pool: &PgPool,
        finding_id: Uuid,
        start: usize,
        count: usize,
    ) {
        let now = chrono::Utc::now();
        let rows = (start..start + count)
            .map(|index| {
                let analysis = AgentAnalysisRecord::new(
                    "bounded-fixture",
                    None,
                    format!("bounded analysis {index}"),
                    Vec::new(),
                    now,
                );
                (
                    analysis.identity.clone(),
                    analysis.schema.clone(),
                    serde_json::to_value(&analysis).expect("serialize bounded analysis"),
                    analysis.created_at,
                )
            })
            .collect::<Vec<_>>();
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO finding_agent_analysis \
             (tracked_finding_id, analysis_identity, analysis_schema, raw_analysis, created_at) ",
        );
        query.push_values(&rows, |mut row, (identity, schema, raw, created_at)| {
            row.push_bind(finding_id)
                .push_bind(identity)
                .push_bind(schema)
                .push_bind(raw)
                .push_bind(created_at);
        });
        query.build().execute(pool).await.expect("insert bounded analyses");
    }

    fn assert_canonical_mismatch<T>(result: Result<T>) {
        let Err(error) = result else {
            panic!("corrupt canonical projection was accepted");
        };
        assert!(error.to_string().contains("canonical projection mismatch"));
    }

    async fn assert_finding_corruptions(pool: &PgPool) {
        let corruptions = [
            "UPDATE tracked_findings SET raw_finding = '{}'::jsonb WHERE id = $1",
            "UPDATE tracked_findings SET fingerprint = fingerprint || '-corrupt' WHERE id = $1",
            "UPDATE tracked_findings SET identity_schema = identity_schema || '-corrupt' WHERE id = $1",
            "UPDATE tracked_findings SET stable_identity = stable_identity || '-corrupt' WHERE id = $1",
            "UPDATE tracked_findings SET correlation_keys = '{\"corrupt\":true}'::jsonb WHERE id = $1",
            "UPDATE tracked_findings SET module_id = module_id || '-corrupt' WHERE id = $1",
            "UPDATE tracked_findings SET severity = 'critical' WHERE id = $1",
            "UPDATE tracked_findings SET title = title || '-corrupt' WHERE id = $1",
            "UPDATE tracked_findings SET description = description || '-corrupt' WHERE id = $1",
            "UPDATE tracked_findings SET affected_target = affected_target || '/corrupt' WHERE id = $1",
            "UPDATE tracked_findings SET evidence = evidence || '-corrupt' WHERE id = $1",
            "UPDATE tracked_findings SET remediation = remediation || '-corrupt' WHERE id = $1",
            "UPDATE tracked_findings SET owasp_category = 'A01:2021' WHERE id = $1",
            "UPDATE tracked_findings SET cwe_id = 79 WHERE id = $1",
            "UPDATE tracked_findings SET confidence = 0.125 WHERE id = $1",
            "UPDATE tracked_findings SET found_at = found_at + interval '1 second' WHERE id = $1",
            "UPDATE tracked_findings SET seen_count = 0 WHERE id = $1",
            "UPDATE tracked_findings SET status = 'corrupt' WHERE id = $1",
            "UPDATE tracked_findings SET first_seen = last_seen + interval '1 second' WHERE id = $1",
        ];
        for corruption in corruptions {
            let fixture = canonical_fixture(pool).await;
            sqlx::query(corruption)
                .bind(fixture.finding)
                .execute(pool)
                .await
                .expect("corrupt finding projection");
            assert_canonical_mismatch(get_validated_finding(pool, fixture.finding).await);
            crate::storage::projects::delete_project(pool, fixture.project)
                .await
                .expect("delete corrupt finding project");
        }
    }

    async fn assert_evidence_corruptions(pool: &PgPool) {
        let corruptions = [
            "UPDATE finding_evidence SET raw_evidence = '{}'::jsonb WHERE id = $1",
            "UPDATE finding_evidence SET evidence_identity = evidence_identity || '-corrupt' WHERE id = $1",
            "UPDATE finding_evidence SET evidence_schema = evidence_schema || '-corrupt' WHERE id = $1",
            "UPDATE finding_evidence SET collected_at = collected_at + interval '1 second' WHERE id = $1",
        ];
        for corruption in corruptions {
            let fixture = canonical_fixture(pool).await;
            sqlx::query(corruption)
                .bind(fixture.evidence)
                .execute(pool)
                .await
                .expect("corrupt evidence projection");
            assert_canonical_mismatch(
                list_validated_evidence_page(pool, fixture.finding, None, 2).await,
            );
            crate::storage::projects::delete_project(pool, fixture.project)
                .await
                .expect("delete corrupt evidence project");
        }
    }

    async fn assert_analysis_corruptions(pool: &PgPool) {
        let corruptions = [
            "UPDATE finding_agent_analysis SET raw_analysis = '{}'::jsonb WHERE id = $1",
            "UPDATE finding_agent_analysis SET analysis_identity = analysis_identity || '-corrupt' WHERE id = $1",
            "UPDATE finding_agent_analysis SET analysis_schema = analysis_schema || '-corrupt' WHERE id = $1",
            "UPDATE finding_agent_analysis SET created_at = created_at + interval '1 second' WHERE id = $1",
        ];
        for corruption in corruptions {
            let fixture = canonical_fixture(pool).await;
            sqlx::query(corruption)
                .bind(fixture.analysis)
                .execute(pool)
                .await
                .expect("corrupt analysis projection");
            assert_canonical_mismatch(get_validated_finding(pool, fixture.finding).await);
            crate::storage::projects::delete_project(pool, fixture.project)
                .await
                .expect("delete corrupt analysis project");
        }
    }

    async fn assert_relationship_corruptions(pool: &PgPool) {
        let finding = canonical_fixture(pool).await;
        let other_project = crate::storage::projects::create_project(
            pool,
            &format!("control-canonical-other-{}", Uuid::new_v4()),
            "relationship fixture",
        )
        .await
        .expect("create other project");
        sqlx::query("UPDATE tracked_findings SET project_id = $2 WHERE id = $1")
            .bind(finding.finding)
            .bind(other_project.id)
            .execute(pool)
            .await
            .expect("corrupt scan/project relationship");
        assert_canonical_mismatch(get_validated_finding(pool, finding.finding).await);
        crate::storage::projects::delete_project(pool, other_project.id)
            .await
            .expect("delete other project");
        crate::storage::projects::delete_project(pool, finding.project)
            .await
            .expect("delete relationship project");

        let evidence = canonical_fixture(pool).await;
        let other = canonical_fixture(pool).await;
        sqlx::query("UPDATE finding_evidence SET scan_id = $2 WHERE id = $1")
            .bind(evidence.evidence)
            .bind(other.scan)
            .execute(pool)
            .await
            .expect("corrupt evidence scan/project relationship");
        assert_canonical_mismatch(
            list_validated_evidence_page(pool, evidence.finding, None, 2).await,
        );
        crate::storage::projects::delete_project(pool, evidence.project)
            .await
            .expect("delete evidence relationship project");
        crate::storage::projects::delete_project(pool, other.project)
            .await
            .expect("delete other evidence project");
    }

    #[tokio::test]
    async fn canonical_control_reads_fail_closed_for_independent_projection_corruption() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = crate::storage::connect(&database_url)
            .await
            .expect("connect canonical validation database");
        crate::storage::migrate::run_migrations(&pool)
            .await
            .expect("migrate canonical validation database");

        let round_trip = canonical_fixture(&pool).await;
        assert!(get_validated_finding(&pool, round_trip.finding)
            .await
            .expect("validate canonical finding")
            .is_some());
        assert_eq!(
            list_validated_evidence_page(&pool, round_trip.finding, None, 2)
                .await
                .expect("validate canonical evidence")
                .len(),
            1
        );
        let projected = get_validated_finding(&pool, round_trip.finding)
            .await
            .expect("validated model finding")
            .expect("model finding");
        assert_eq!(
            projected.canonical["appsec"]["agent_analysis"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(
            projected.canonical["appsec"]["agent_analysis"][0]["schema"],
            scorchkit_core::MODEL_ANALYSIS_CONTRACT_V1
        );
        crate::storage::projects::delete_project(&pool, round_trip.project)
            .await
            .expect("delete round-trip project");
        assert_finding_corruptions(&pool).await;
        assert_evidence_corruptions(&pool).await;
        assert_analysis_corruptions(&pool).await;
        assert_relationship_corruptions(&pool).await;
    }

    #[tokio::test]
    async fn validated_analysis_projection_enforces_the_exact_child_limit() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = crate::storage::connect(&database_url)
            .await
            .expect("connect bounded-analysis database");
        crate::storage::migrate::run_migrations(&pool)
            .await
            .expect("migrate bounded-analysis database");
        let fixture = canonical_fixture(&pool).await;

        insert_bounded_analysis_fixtures(
            &pool,
            fixture.finding,
            0,
            MAX_VALIDATED_ANALYSES_PER_FINDING - 1,
        )
        .await;
        assert_eq!(
            load_validated_analyses(&pool, fixture.finding, &[])
                .await
                .expect("exact child limit")
                .len(),
            MAX_VALIDATED_ANALYSES_PER_FINDING
        );

        insert_bounded_analysis_fixtures(
            &pool,
            fixture.finding,
            MAX_VALIDATED_ANALYSES_PER_FINDING - 1,
            1,
        )
        .await;
        let error = load_validated_analyses(&pool, fixture.finding, &[])
            .await
            .expect_err("one child over the limit");
        assert!(error
            .to_string()
            .contains("agent analysis exceeds the bounded public projection limit"));
        crate::storage::projects::delete_project(&pool, fixture.project)
            .await
            .expect("delete bounded-analysis project");
    }

    #[tokio::test]
    async fn control_finding_cursor_is_stable_when_unseen_findings_are_rediscovered() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = crate::storage::connect(&database_url)
            .await
            .expect("connect stable-pagination database");
        crate::storage::migrate::run_migrations(&pool)
            .await
            .expect("migrate stable-pagination database");

        let project = crate::storage::projects::create_project(
            &pool,
            &format!("control-page-{}", Uuid::new_v4()),
            "stable finding page fixture",
        )
        .await
        .expect("create stable-pagination project");
        let now = chrono::Utc::now();
        let scan = crate::storage::scans::save_scan(
            &pool,
            project.id,
            "https://example.com/",
            "quick",
            now,
            Some(now),
            &["fixture".to_string()],
            &[],
            &serde_json::json!({}),
        )
        .await
        .expect("create stable-pagination scan");
        let findings = [
            Finding::new(
                "fixture",
                Severity::High,
                "Stable page A",
                "first page fixture",
                "https://example.com/a",
            ),
            Finding::new(
                "fixture",
                Severity::Medium,
                "Stable page B",
                "second page fixture",
                "https://example.com/b",
            ),
        ];
        save_findings(&pool, project.id, scan.id, &findings)
            .await
            .expect("save stable-pagination findings");

        let first = list_validated_findings_page(&pool, project.id, None, 1)
            .await
            .expect("first finding page");
        assert_eq!(first.len(), 1);
        let first_id = first[0].row.id;
        let all = list_findings(&pool, project.id).await.expect("list finding fixtures");
        let unseen_id =
            all.iter().find(|finding| finding.id != first_id).expect("unseen finding").id;
        sqlx::query(
            "UPDATE tracked_findings SET last_seen = now() + interval '1 hour' WHERE id = $1",
        )
        .bind(unseen_id)
        .execute(&pool)
        .await
        .expect("rediscover unseen finding");

        let second = list_validated_findings_page(&pool, project.id, Some(first_id), 1)
            .await
            .expect("second finding page");
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].row.id, unseen_id);
        sqlx::query("UPDATE tracked_findings SET first_seen = first_seen + interval '1 second' WHERE id = $1")
            .bind(first_id)
            .execute(&pool)
            .await
            .expect("corrupt finding cursor projection");
        assert_canonical_mismatch(
            list_validated_findings_page(&pool, project.id, Some(first_id), 1).await,
        );
        crate::storage::projects::delete_project(&pool, project.id)
            .await
            .expect("delete stable-pagination project");
    }
}
