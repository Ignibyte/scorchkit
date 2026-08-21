//! Scan record persistence.
//!
//! Stores and retrieves scan execution records linked to projects.
//! Each scan record captures what was scanned, which modules ran,
//! and summary statistics.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::models::ScanRecord;
use crate::engine::error::{Result, ScorchError};

/// Save a new scan record for a project.
///
/// # Errors
///
/// Returns an error if the database query fails.
// JUSTIFICATION: save_scan maps directly to the scan_records table columns;
// bundling into a struct would add unnecessary indirection for an internal API.
#[allow(clippy::too_many_arguments)]
pub async fn save_scan(
    pool: &PgPool,
    project_id: Uuid,
    target_url: &str,
    profile: &str,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    modules_run: &[String],
    modules_skipped: &[String],
    summary: &serde_json::Value,
) -> Result<ScanRecord> {
    save_scan_with_evidence(
        pool,
        project_id,
        target_url,
        profile,
        started_at,
        completed_at,
        modules_run,
        modules_skipped,
        summary,
        &serde_json::json!({}),
    )
    .await
}

/// Save a scan together with the versioned execution and coverage evidence projection.
///
/// # Errors
///
/// Returns a database error when the immutable scan record cannot be inserted.
// JUSTIFICATION: The parameters map one-for-one to the immutable scan record and its versioned
// evidence projection; grouping them would duplicate the storage schema as a transport type.
#[allow(clippy::too_many_arguments)]
pub async fn save_scan_with_evidence(
    pool: &PgPool,
    project_id: Uuid,
    target_url: &str,
    profile: &str,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    modules_run: &[String],
    modules_skipped: &[String],
    summary: &serde_json::Value,
    execution_evidence: &serde_json::Value,
) -> Result<ScanRecord> {
    sqlx::query_as::<_, ScanRecord>(
        "INSERT INTO scan_records \
         (project_id, target_url, profile, started_at, completed_at, \
          modules_run, modules_skipped, summary, execution_evidence) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *",
    )
    .bind(project_id)
    .bind(target_url)
    .bind(profile)
    .bind(started_at)
    .bind(completed_at)
    .bind(modules_run)
    .bind(modules_skipped)
    .bind(summary)
    .bind(execution_evidence)
    .fetch_one(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("save scan: {e}")))
}

/// Build the stable storage projection for typed scan execution and supply-chain evidence.
#[must_use]
pub fn execution_evidence(result: &crate::engine::scan_result::ScanResult) -> serde_json::Value {
    serde_json::json!({
        "schema": "scorchkit.scan-execution-evidence.v1",
        "execution_status": result.execution_status,
        "module_outcomes": result.module_outcomes,
        "supply_chain": result.supply_chain,
        "application_dast": result.application_dast,
    })
}

/// Get a scan record by ID.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn get_scan(pool: &PgPool, id: Uuid) -> Result<Option<ScanRecord>> {
    sqlx::query_as::<_, ScanRecord>("SELECT * FROM scan_records WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("get scan: {e}")))
}

/// List all scans for a project, newest first.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn list_scans(pool: &PgPool, project_id: Uuid) -> Result<Vec<ScanRecord>> {
    sqlx::query_as::<_, ScanRecord>(
        "SELECT * FROM scan_records WHERE project_id = $1 \
         ORDER BY started_at DESC",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("list scans: {e}")))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::engine::scan_result::ScanResult;
    use crate::engine::target::Target;
    use crate::{
        ApplicationDastAssessment, ApplicationDastCoverageGap, ApplicationDastGapKind,
        ApplicationDastPhase, ApplicationDastProfile, SupplyChainAssessment,
        SupplyChainCoverageGap, SupplyChainGapKind, SupplyChainPhase, SupplyChainTarget,
        SupplyChainTargetKind,
    };

    #[test]
    fn execution_evidence_preserves_incomplete_supply_chain_state_and_schema() {
        let mut assessment = SupplyChainAssessment::new(SupplyChainTarget {
            kind: SupplyChainTargetKind::SourceDirectory,
            canonical_path: PathBuf::from("/owned/source"),
            revision: Some("revision-1".to_string()),
            sha256: None,
        });
        assessment.record_gap(SupplyChainCoverageGap::new(
            SupplyChainPhase::ArtifactVulnerabilityScan,
            SupplyChainGapKind::MissingProviderSnapshot,
            Some("grype".to_string()),
            "Grype snapshot is unavailable",
        ));
        let result = ScanResult::new(
            "storage-evidence".to_string(),
            Target::parse("https://example.com").expect("target"),
            Utc::now(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .with_supply_chain(assessment);

        let evidence = execution_evidence(&result);
        assert_eq!(evidence["schema"], "scorchkit.scan-execution-evidence.v1");
        assert_eq!(evidence["execution_status"], "incomplete");
        assert_eq!(evidence["supply_chain"]["coverage_status"], "incomplete");
        assert_eq!(evidence["supply_chain"]["gaps"][0]["kind"], "missing_provider_snapshot");
    }

    #[test]
    fn execution_evidence_preserves_redacted_application_dast_state() {
        let mut assessment =
            ApplicationDastAssessment::new("https://example.com", ApplicationDastProfile::Passive);
        assessment.zap_version = "2.17.0".to_string();
        assessment.record_gap(ApplicationDastCoverageGap::new(
            "user",
            ApplicationDastPhase::Authentication,
            ApplicationDastGapKind::AuthenticationLost,
            "token=storage-dast-secret",
        ));
        let result = ScanResult::new(
            "storage-dast-evidence".to_string(),
            Target::parse("https://example.com").expect("target"),
            Utc::now(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .with_application_dast(assessment);

        let evidence = execution_evidence(&result);
        assert_eq!(evidence["execution_status"], "degraded");
        assert_eq!(evidence["application_dast"]["gaps"][0]["kind"], "authentication_lost");
        assert!(!evidence.to_string().contains("storage-dast-secret"));
    }
}
