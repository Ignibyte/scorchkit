//! Durable finding-triage lifecycle contracts across storage and the control API.

#![cfg(feature = "storage")]

use std::sync::Arc;

use chrono::{Duration, Utc};
use scorchkit::config::AppConfig;
use scorchkit::control::ControlService;
use scorchkit::engine::finding::Finding;
use scorchkit::engine::observation::{AgentAnalysisRecord, CorrelationKey};
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::scope::ScopeRule;
use scorchkit::engine::severity::Severity;
use scorchkit::engine::triage::{
    FindingSuppressionScopeKind, FindingTriageSubject, TriageActor, TriageActorKind,
    MAX_TRIAGE_CORRELATIONS, MAX_TRIAGE_REFERENCES, MAX_TRIAGE_SUPPRESSIONS,
};
use scorchkit::storage;
use scorchkit::storage::triage::{FindingCorrelationWrite, FindingSuppressionWrite};
use scorchkit_control::{
    ControlCommandV1, ControlErrorCodeV1, ControlQueryV1, ControlRequestV1,
    ControlResponseOutcomeV1, ControlResultV1, FindingCorrelationFacetV1, FindingViewV1,
    ProjectReportViewV1,
};
use uuid::Uuid;

async fn fixture() -> Option<(sqlx::PgPool, ControlService, Uuid, Uuid, Uuid)> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let pool = storage::connect(&database_url)
        .await
        .unwrap_or_else(|error| panic!("connect triage database: {error}"));
    storage::migrate::run_migrations(&pool)
        .await
        .unwrap_or_else(|error| panic!("migrate triage database: {error}"));
    let project = storage::projects::create_project(
        &pool,
        &format!("finding-triage-{}", Uuid::new_v4()),
        "triage fixture",
    )
    .await
    .unwrap_or_else(|error| panic!("create triage project: {error}"));
    let scan = storage::scans::save_scan(
        &pool,
        project.id,
        "https://example.test/",
        "standard",
        Utc::now(),
        Some(Utc::now()),
        &[],
        &[],
        &serde_json::json!({}),
    )
    .await
    .unwrap_or_else(|error| panic!("create triage scan: {error}"));
    let first_finding = Finding::new(
        "scanner-a",
        Severity::High,
        "Runtime issue",
        "runtime proof",
        "https://example.test/a",
    )
    .with_cwe(79)
    .with_evidence("runtime evidence");
    let mut second_finding = Finding::new(
        "scanner-b",
        Severity::Medium,
        "Source issue",
        "source proof",
        "https://example.test/b",
    )
    .with_evidence("source evidence");
    let analysis = AgentAnalysisRecord::new(
        "fixture-provider",
        Some("fixture-model".to_string()),
        "Foreign finding recommendation",
        vec![second_finding.appsec.evidence[0].identity.clone()],
        Utc::now(),
    );
    second_finding = second_finding.with_agent_analysis(analysis);
    let findings = [first_finding, second_finding];
    storage::findings::save_findings(&pool, project.id, scan.id, &findings)
        .await
        .unwrap_or_else(|error| panic!("store triage findings: {error}"));
    let rows = storage::findings::list_findings(&pool, project.id)
        .await
        .unwrap_or_else(|error| panic!("list triage findings: {error}"));
    let first = rows
        .iter()
        .find(|row| row.module_id == "scanner-a")
        .unwrap_or_else(|| panic!("first finding was not stored"))
        .id;
    let second = rows
        .iter()
        .find(|row| row.module_id == "scanner-b")
        .unwrap_or_else(|| panic!("second finding was not stored"))
        .id;

    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::parse("example.test").unwrap_or_else(|| panic!("invalid scope")))
        .allow_capability(Capability::LocalState)
        .allow_effect(EffectClass::ActiveSafe);
    let config = AppConfig {
        engagement: Some(Engagement::new("finding triage fixture", policy)),
        ..AppConfig::default()
    };
    let engagement_id =
        config.engagement.as_ref().unwrap_or_else(|| panic!("triage engagement is absent")).id;
    let service = ControlService::persistent(Arc::new(config), pool.clone(), None);
    Some((pool, service, engagement_id, first, second))
}

async fn finding(service: &ControlService, engagement_id: Uuid, finding_id: Uuid) -> FindingViewV1 {
    let response = service
        .execute_local(ControlRequestV1::query(
            ControlQueryV1::GetFinding { id: finding_id },
            Some(engagement_id),
        ))
        .await;
    let ControlResponseOutcomeV1::Success(result) = response.result else {
        panic!("finding query failed: {:?}", response.result);
    };
    let ControlResultV1::Finding(finding) = *result else {
        panic!("unexpected finding result");
    };
    finding
}

async fn triage_subject(pool: &sqlx::PgPool, finding_id: Uuid) -> FindingTriageSubject {
    let row = storage::findings::get_finding(pool, finding_id)
        .await
        .unwrap_or_else(|error| panic!("load triage subject row: {error}"))
        .unwrap_or_else(|| panic!("triage subject row is absent"));
    let finding: Finding = serde_json::from_value(row.raw_finding)
        .unwrap_or_else(|error| panic!("decode triage subject finding: {error}"));
    FindingTriageSubject::from_record(row.project_id.to_string(), &finding.canonical_appsec())
}

fn triage_actor() -> TriageActor {
    TriageActor::new(TriageActorKind::Human, "integration@example.test")
}

async fn command(
    service: &ControlService,
    engagement_id: Uuid,
    command: ControlCommandV1,
) -> FindingViewV1 {
    let response = service.execute_local(ControlRequestV1::command(command, engagement_id)).await;
    let ControlResponseOutcomeV1::Success(result) = response.result else {
        panic!("triage command failed: {:?}", response.result);
    };
    let ControlResultV1::Finding(finding) = *result else {
        panic!("unexpected triage command result");
    };
    finding
}

async fn report(
    service: &ControlService,
    engagement_id: Uuid,
    project_id: Uuid,
) -> ProjectReportViewV1 {
    let response = service
        .execute_local(ControlRequestV1::query(
            ControlQueryV1::GetProjectReport { project_id },
            Some(engagement_id),
        ))
        .await;
    let ControlResponseOutcomeV1::Success(result) = response.result else {
        panic!("project report failed");
    };
    let ControlResultV1::Report(report) = *result else {
        panic!("unexpected report result");
    };
    report
}

async fn assert_report_counts(service: &ControlService, engagement_id: Uuid, project_id: Uuid) {
    let report = report(service, engagement_id, project_id).await;
    assert_eq!(report.triage_state_counts.get("validated"), Some(&1));
    assert_eq!(report.triage_state_counts.get("needs_context"), Some(&1));
    assert_eq!(report.active_suppressed_count, 1);
}

async fn assert_suppression_does_not_cross_findings(
    service: &ControlService,
    engagement_id: Uuid,
    finding_id: Uuid,
) {
    let unsuppressed = finding(service, engagement_id, finding_id).await;
    assert!(unsuppressed.triage.suppressions.is_empty());
    assert!(unsuppressed.triage.active_suppression_ids.is_empty());
}

async fn assert_correlation_and_report_views(
    pool: &sqlx::PgPool,
    service: &ControlService,
    engagement_id: Uuid,
    first: Uuid,
    second: Uuid,
    correlated: &FindingViewV1,
    original_evidence: &serde_json::Value,
) {
    assert_eq!(correlated.triage.correlations.len(), 1);
    assert_eq!(
        &storage::findings::list_evidence(pool, first)
            .await
            .unwrap_or_else(|error| panic!("retained evidence: {error}"))[0]
            .raw_evidence,
        original_evidence
    );
    assert_report_counts(service, engagement_id, correlated.project_id).await;
    command(
        service,
        engagement_id,
        ControlCommandV1::CreateFindingSuppression {
            finding_id: second,
            scope: "finding".to_string(),
            reason: "Second time-bounded fixture suppression".to_string(),
            expires_at: Some(Utc::now() + Duration::hours(1)),
            review_at: None,
        },
    )
    .await;
    assert_eq!(
        report(service, engagement_id, correlated.project_id).await.active_suppressed_count,
        2
    );
}

async fn assert_same_scan_retry_is_idempotent(
    pool: &sqlx::PgPool,
    service: &ControlService,
    engagement_id: Uuid,
    project_id: Uuid,
    scan_id: Uuid,
    finding_id: Uuid,
    record: &Finding,
) {
    storage::findings::save_findings(pool, project_id, scan_id, std::slice::from_ref(record))
        .await
        .unwrap_or_else(|error| panic!("retry original finding scan: {error}"));
    let retried = finding(service, engagement_id, finding_id).await;
    assert_eq!(retried.triage.current_state, "fixed");
    assert_eq!(retried.triage.transitions.len(), 3);
    assert_eq!(retried.seen_count, 1);
}

async fn create_rediscovery_scan(pool: &sqlx::PgPool, project_id: Uuid) -> Uuid {
    storage::scans::save_scan(
        pool,
        project_id,
        "https://example.test/",
        "standard",
        Utc::now(),
        Some(Utc::now()),
        &[],
        &[],
        &serde_json::json!({}),
    )
    .await
    .unwrap_or_else(|error| panic!("create rediscovery scan: {error}"))
    .id
}

async fn assert_cross_scanner_rediscovery_preserves_correlation(
    pool: &sqlx::PgPool,
    service: &ControlService,
    engagement_id: Uuid,
    project_id: Uuid,
    finding_id: Uuid,
) {
    let scan_id = create_rediscovery_scan(pool, project_id).await;
    let cross_scanner = Finding::new(
        "scanner-c",
        Severity::High,
        "Cross-scanner runtime issue",
        "new scanner proof",
        "https://example.test/a",
    )
    .with_cwe(79)
    .with_evidence("cross-scanner evidence");
    storage::findings::save_findings(pool, project_id, scan_id, &[cross_scanner])
        .await
        .unwrap_or_else(|error| panic!("store cross-scanner rediscovery: {error}"));
    let evolved = finding(service, engagement_id, finding_id).await;
    assert_eq!(evolved.triage.current_state, "needs_context");
    assert_eq!(evolved.triage.correlations.len(), 1);
}

async fn add_suppression_and_correlation(
    pool: &sqlx::PgPool,
    service: &ControlService,
    engagement_id: Uuid,
    first: Uuid,
    second: Uuid,
) {
    command(
        service,
        engagement_id,
        ControlCommandV1::CreateFindingSuppression {
            finding_id: first,
            scope: "finding".to_string(),
            reason: "Corruption fixture suppression".to_string(),
            expires_at: Some(Utc::now() + Duration::hours(1)),
            review_at: None,
        },
    )
    .await;
    let first_evidence = storage::findings::list_evidence(pool, first)
        .await
        .unwrap_or_else(|error| panic!("first evidence: {error}"));
    let second_evidence = storage::findings::list_evidence(pool, second)
        .await
        .unwrap_or_else(|error| panic!("second evidence: {error}"));
    command(
        service,
        engagement_id,
        ControlCommandV1::RecordFindingCorrelation {
            finding_id: first,
            contributing_finding_ids: vec![first, second],
            evidence_ids: vec![
                first_evidence[0].evidence_identity.clone(),
                second_evidence[0].evidence_identity.clone(),
            ],
            facets: Vec::new(),
            explanation: "Corruption fixture correlation".to_string(),
        },
    )
    .await;
}

async fn execute_corruption_sql(
    pool: &sqlx::PgPool,
    sql: &'static str,
    first: Uuid,
    second: Option<Uuid>,
) {
    let query = sqlx::query(sql).bind(first);
    match second {
        Some(second) => query.bind(second).execute(pool).await,
        None => query.execute(pool).await,
    }
    .unwrap_or_else(|error| panic!("execute corruption fixture SQL: {error}"));
}

#[derive(Clone, Copy)]
struct CorruptionCase {
    read_finding_id: Uuid,
    mutation_finding_id: Uuid,
    other_id: Option<Uuid>,
    corrupt_sql: &'static str,
    restore_sql: &'static str,
}

async fn assert_corruption_rejected(
    pool: &sqlx::PgPool,
    service: &ControlService,
    engagement_id: Uuid,
    case: CorruptionCase,
) {
    execute_corruption_sql(pool, case.corrupt_sql, case.mutation_finding_id, case.other_id).await;
    let response = service
        .execute_local(ControlRequestV1::query(
            ControlQueryV1::GetFinding { id: case.read_finding_id },
            Some(engagement_id),
        ))
        .await;
    execute_corruption_sql(pool, case.restore_sql, case.mutation_finding_id, case.other_id).await;
    assert!(
        matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ref error)
                if error.code == ControlErrorCodeV1::CanonicalProjectionMismatch
        ),
        "corruption was not rejected as a projection mismatch: {}: {:?}",
        case.corrupt_sql,
        response.result
    );
}

#[tokio::test]
async fn cloud_finding_transition_uses_the_exact_cloud_scope() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = storage::connect(&database_url)
        .await
        .unwrap_or_else(|error| panic!("connect cloud triage database: {error}"));
    storage::migrate::run_migrations(&pool)
        .await
        .unwrap_or_else(|error| panic!("migrate cloud triage database: {error}"));
    let project = storage::projects::create_project(
        &pool,
        &format!("cloud-finding-triage-{}", Uuid::new_v4()),
        "cloud triage fixture",
    )
    .await
    .unwrap_or_else(|error| panic!("create cloud triage project: {error}"));
    let scan = storage::scans::save_scan(
        &pool,
        project.id,
        "cloud://aws:123456789012",
        "standard",
        Utc::now(),
        Some(Utc::now()),
        &[],
        &[],
        &serde_json::json!({}),
    )
    .await
    .unwrap_or_else(|error| panic!("create cloud triage scan: {error}"));
    storage::findings::save_findings(
        &pool,
        project.id,
        scan.id,
        &[Finding::new(
            "cloud-scanner",
            Severity::High,
            "Cloud posture issue",
            "cloud proof",
            "cloud://aws:123456789012",
        )],
    )
    .await
    .unwrap_or_else(|error| panic!("store cloud triage finding: {error}"));
    let finding_id = storage::findings::list_findings(&pool, project.id)
        .await
        .unwrap_or_else(|error| panic!("list cloud triage finding: {error}"))[0]
        .id;
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::cloud("aws:123456789012"))
        .allow_capability(Capability::LocalState)
        .allow_effect(EffectClass::ActiveSafe);
    let config = AppConfig {
        engagement: Some(Engagement::new("cloud finding triage fixture", policy)),
        ..AppConfig::default()
    };
    let engagement_id = config
        .engagement
        .as_ref()
        .unwrap_or_else(|| panic!("cloud triage engagement is absent"))
        .id;
    let service = ControlService::persistent(Arc::new(config), pool.clone(), None);
    let transitioned = command(
        &service,
        engagement_id,
        ControlCommandV1::TransitionFinding {
            finding_id,
            state: "validated".to_string(),
            reason: "Cloud evidence was validated".to_string(),
            evidence_ids: Vec::new(),
            model_analysis_identity: None,
        },
    )
    .await;
    assert_eq!(transitioned.triage.current_state, "validated");
    storage::projects::delete_project(&pool, project.id)
        .await
        .unwrap_or_else(|error| panic!("delete cloud triage fixture: {error}"));
}

#[tokio::test]
async fn transition_correlation_suppression_and_report_share_one_projection() {
    let Some((pool, service, engagement_id, first, second)) = fixture().await else {
        return;
    };
    let before = finding(&service, engagement_id, first).await;
    assert_eq!(before.triage.current_state, "needs_context");
    assert_eq!(before.triage.transitions.len(), 1);
    let original_scanner_document = before.canonical.clone();
    let original_evidence = storage::findings::list_evidence(&pool, first)
        .await
        .unwrap_or_else(|error| panic!("first evidence: {error}"));
    let second_evidence = storage::findings::list_evidence(&pool, second)
        .await
        .unwrap_or_else(|error| panic!("second evidence: {error}"));
    let foreign_analysis = storage::findings::list_agent_analysis(&pool, second)
        .await
        .unwrap_or_else(|error| panic!("foreign analysis: {error}"));

    let rejected = service
        .execute_local(ControlRequestV1::command(
            ControlCommandV1::TransitionFinding {
                finding_id: first,
                state: "validated".to_string(),
                reason: "Must reject borrowed analysis".to_string(),
                evidence_ids: vec![original_evidence[0].evidence_identity.clone()],
                model_analysis_identity: Some(foreign_analysis[0].analysis_identity.clone()),
            },
            engagement_id,
        ))
        .await;
    assert!(matches!(rejected.result, ControlResponseOutcomeV1::Error(_)));
    assert_eq!(finding(&service, engagement_id, first).await.triage.transitions.len(), 1);

    let transitioned = command(
        &service,
        engagement_id,
        ControlCommandV1::TransitionFinding {
            finding_id: first,
            state: "validated".to_string(),
            reason: "Reproduced against retained evidence".to_string(),
            evidence_ids: vec![original_evidence[0].evidence_identity.clone()],
            model_analysis_identity: None,
        },
    )
    .await;
    assert_eq!(transitioned.triage.current_state, "validated");
    assert_eq!(transitioned.triage.transitions.len(), 2);
    assert_eq!(transitioned.canonical, original_scanner_document);

    let suppressed = command(
        &service,
        engagement_id,
        ControlCommandV1::CreateFindingSuppression {
            finding_id: first,
            scope: "finding".to_string(),
            reason: "Time-bounded fixture suppression".to_string(),
            expires_at: Some(Utc::now() + Duration::hours(1)),
            review_at: None,
        },
    )
    .await;
    assert_eq!(suppressed.triage.suppressions.len(), 1);
    assert_eq!(suppressed.triage.active_suppression_ids.len(), 1);
    assert_suppression_does_not_cross_findings(&service, engagement_id, second).await;

    let correlated = command(
        &service,
        engagement_id,
        ControlCommandV1::RecordFindingCorrelation {
            finding_id: first,
            contributing_finding_ids: vec![first, second],
            evidence_ids: vec![
                original_evidence[0].evidence_identity.clone(),
                second_evidence[0].evidence_identity.clone(),
            ],
            facets: vec![FindingCorrelationFacetV1 {
                namespace: "route-family".to_string(),
                value: "example-fixture".to_string(),
            }],
            explanation: "Source and runtime findings share one application boundary".to_string(),
        },
    )
    .await;
    assert_eq!(correlated.canonical, original_scanner_document);
    assert_correlation_and_report_views(
        &pool,
        &service,
        engagement_id,
        first,
        second,
        &correlated,
        &original_evidence[0].raw_evidence,
    )
    .await;

    assert_cross_scanner_rediscovery_preserves_correlation(
        &pool,
        &service,
        engagement_id,
        correlated.project_id,
        first,
    )
    .await;

    storage::projects::delete_project(&pool, correlated.project_id)
        .await
        .unwrap_or_else(|error| panic!("delete triage fixture: {error}"));
}

#[tokio::test]
async fn unauthorized_and_corrupt_triage_state_fail_before_or_during_public_read() {
    let Some((pool, service, engagement_id, first, _)) = fixture().await else {
        return;
    };
    let initial = finding(&service, engagement_id, first).await;
    let transition_count = initial.triage.transitions.len();

    let denied = ControlService::persistent(Arc::new(AppConfig::default()), pool.clone(), None)
        .execute_local(ControlRequestV1::command(
            ControlCommandV1::TransitionFinding {
                finding_id: first,
                state: "likely".to_string(),
                reason: "must not write".to_string(),
                evidence_ids: Vec::new(),
                model_analysis_identity: None,
            },
            engagement_id,
        ))
        .await;
    assert!(matches!(
        denied.result,
        ControlResponseOutcomeV1::Error(ref error)
            if matches!(
                error.code,
                ControlErrorCodeV1::PrincipalBindingMismatch
                    | ControlErrorCodeV1::EngagementUnavailable
                    | ControlErrorCodeV1::PolicyDenied
            )
    ));
    assert_eq!(
        finding(&service, engagement_id, first).await.triage.transitions.len(),
        transition_count
    );

    let denied_policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::parse("denied.test").unwrap_or_else(|| panic!("invalid scope")))
        .allow_capability(Capability::LocalState)
        .allow_effect(EffectClass::ActiveSafe);
    let denied_config = AppConfig {
        engagement: Some(Engagement::new("denied finding target", denied_policy)),
        ..AppConfig::default()
    };
    let denied_engagement_id = denied_config
        .engagement
        .as_ref()
        .unwrap_or_else(|| panic!("denied engagement is absent"))
        .id;
    let denied = ControlService::persistent(Arc::new(denied_config), pool.clone(), None)
        .execute_local(ControlRequestV1::command(
            ControlCommandV1::TransitionFinding {
                finding_id: first,
                state: "likely".to_string(),
                reason: "must remain outside scope".to_string(),
                evidence_ids: Vec::new(),
                model_analysis_identity: None,
            },
            denied_engagement_id,
        ))
        .await;
    assert!(matches!(
        denied.result,
        ControlResponseOutcomeV1::Error(ref error)
            if error.code == ControlErrorCodeV1::PolicyDenied
    ));
    assert_eq!(
        finding(&service, engagement_id, first).await.triage.transitions.len(),
        transition_count
    );

    sqlx::query(
        "UPDATE finding_triage_transitions SET actor_identity = 'corrupt' \
         WHERE tracked_finding_id = $1 AND sequence = 1",
    )
    .bind(first)
    .execute(&pool)
    .await
    .unwrap_or_else(|error| panic!("corrupt transition projection: {error}"));
    let corrupt = service
        .execute_local(ControlRequestV1::query(
            ControlQueryV1::GetFinding { id: first },
            Some(engagement_id),
        ))
        .await;
    assert!(matches!(
        corrupt.result,
        ControlResponseOutcomeV1::Error(ref error)
            if error.code == ControlErrorCodeV1::CanonicalProjectionMismatch
    ));
    storage::projects::delete_project(&pool, initial.project_id)
        .await
        .unwrap_or_else(|error| panic!("delete corruption fixture: {error}"));
}

#[tokio::test]
async fn every_durable_child_projection_corruption_fails_the_complete_read() {
    let Some((pool, service, engagement_id, first, second)) = fixture().await else {
        return;
    };
    let project_id = finding(&service, engagement_id, first).await.project_id;
    add_suppression_and_correlation(&pool, &service, engagement_id, first, second).await;
    for (corrupt, restore) in [
        (
            "UPDATE tracked_findings SET triage_state = 'fixed' WHERE id = $1",
            "UPDATE tracked_findings SET triage_state = 'needs_context' WHERE id = $1",
        ),
        (
            "UPDATE finding_correlation_decisions SET created_at = created_at + interval '1 second' WHERE tracked_finding_id = $1",
            "UPDATE finding_correlation_decisions SET created_at = created_at - interval '1 second' WHERE tracked_finding_id = $1",
        ),
        (
            "UPDATE finding_suppressions SET scope_kind = 'target' WHERE origin_finding_id = $1",
            "UPDATE finding_suppressions SET scope_kind = 'finding' WHERE origin_finding_id = $1",
        ),
        (
            "UPDATE finding_suppressions SET raw_suppression = jsonb_set(raw_suppression, '{reason}', to_jsonb('corrupt'::text)) WHERE origin_finding_id = $1",
            "UPDATE finding_suppressions SET raw_suppression = jsonb_set(raw_suppression, '{reason}', to_jsonb('Corruption fixture suppression'::text)) WHERE origin_finding_id = $1",
        ),
    ] {
        let case = CorruptionCase {
            read_finding_id: first,
            mutation_finding_id: first,
            other_id: None,
            corrupt_sql: corrupt,
            restore_sql: restore,
        };
        assert_corruption_rejected(&pool, &service, engagement_id, case).await;
    }
    let parent_case = CorruptionCase {
        read_finding_id: second,
        mutation_finding_id: first,
        other_id: Some(second),
        corrupt_sql: "UPDATE finding_correlation_decisions SET tracked_finding_id = $2 WHERE tracked_finding_id = $1",
        restore_sql: "UPDATE finding_correlation_decisions SET tracked_finding_id = $1 WHERE tracked_finding_id = $2",
    };
    assert_corruption_rejected(&pool, &service, engagement_id, parent_case).await;
    sqlx::query("DELETE FROM finding_evidence WHERE tracked_finding_id = $1")
        .bind(second)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("delete cited correlation evidence: {error}"));
    let missing_evidence = service
        .execute_local(ControlRequestV1::query(
            ControlQueryV1::GetFinding { id: first },
            Some(engagement_id),
        ))
        .await;
    assert!(matches!(
        missing_evidence.result,
        ControlResponseOutcomeV1::Error(ref error)
            if error.code == ControlErrorCodeV1::CanonicalProjectionMismatch
    ));
    storage::projects::delete_project(&pool, project_id)
        .await
        .unwrap_or_else(|error| panic!("delete durable corruption fixture: {error}"));
}

#[tokio::test]
async fn exact_replays_validate_every_existing_projection_before_reporting_idempotency() {
    let Some((pool, _, _, first, second)) = fixture().await else {
        return;
    };
    let subject = triage_subject(&pool, first).await;
    let project_id = Uuid::parse_str(&subject.project_identity)
        .unwrap_or_else(|error| panic!("parse subject project: {error}"));
    let created_at = Utc::now();
    let suppression = || FindingSuppressionWrite {
        finding_id: first,
        subject: subject.clone(),
        kind: FindingSuppressionScopeKind::Finding,
        actor: triage_actor(),
        reason: "Exact replay suppression".to_string(),
        created_at,
        expires_at: Some(created_at + Duration::hours(1)),
        review_at: None,
    };
    assert!(storage::triage::create_suppression(&pool, suppression())
        .await
        .unwrap_or_else(|error| panic!("create suppression: {error}")));
    assert!(!storage::triage::create_suppression(&pool, suppression())
        .await
        .unwrap_or_else(|error| panic!("replay suppression: {error}")));
    sqlx::query(
        "UPDATE finding_suppressions SET actor_identity = 'corrupt' WHERE origin_finding_id = $1",
    )
    .bind(first)
    .execute(&pool)
    .await
    .unwrap_or_else(|error| panic!("corrupt replay suppression: {error}"));
    assert!(storage::triage::create_suppression(&pool, suppression()).await.is_err());

    let first_evidence = storage::findings::list_evidence(&pool, first)
        .await
        .unwrap_or_else(|error| panic!("first replay evidence: {error}"));
    let second_evidence = storage::findings::list_evidence(&pool, second)
        .await
        .unwrap_or_else(|error| panic!("second replay evidence: {error}"));
    let correlation = || FindingCorrelationWrite {
        finding_id: first,
        contributing_finding_ids: vec![first, second],
        evidence_ids: vec![
            first_evidence[0].evidence_identity.clone(),
            second_evidence[0].evidence_identity.clone(),
        ],
        facets: vec![CorrelationKey::new("fixture", "exact-replay")],
        explanation: "Exact replay correlation".to_string(),
        actor: triage_actor(),
        created_at,
    };
    assert!(storage::triage::record_correlation(&pool, correlation())
        .await
        .unwrap_or_else(|error| panic!("create correlation: {error}")));
    assert!(!storage::triage::record_correlation(&pool, correlation())
        .await
        .unwrap_or_else(|error| panic!("replay correlation: {error}")));
    sqlx::query(
        "UPDATE finding_correlation_decisions SET actor_identity = 'corrupt' \
         WHERE tracked_finding_id = $1",
    )
    .bind(first)
    .execute(&pool)
    .await
    .unwrap_or_else(|error| panic!("corrupt replay correlation: {error}"));
    assert!(storage::triage::record_correlation(&pool, correlation()).await.is_err());

    storage::projects::delete_project(&pool, project_id)
        .await
        .unwrap_or_else(|error| panic!("delete replay fixture: {error}"));
}

#[tokio::test]
async fn suppression_write_locks_project_and_checks_each_parent_identity() {
    let Some((pool, _, _, first, _)) = fixture().await else {
        return;
    };
    let subject = triage_subject(&pool, first).await;
    let project_id = Uuid::parse_str(&subject.project_identity)
        .unwrap_or_else(|error| panic!("parse subject project: {error}"));
    let foreign = storage::projects::create_project(
        &pool,
        &format!("foreign-suppression-{}", Uuid::new_v4()),
        "foreign suppression fixture",
    )
    .await
    .unwrap_or_else(|error| panic!("create foreign project: {error}"));
    let created_at = Utc::now();
    let write = |subject: FindingTriageSubject| FindingSuppressionWrite {
        finding_id: first,
        subject,
        kind: FindingSuppressionScopeKind::Finding,
        actor: triage_actor(),
        reason: "Must preserve parent identity".to_string(),
        created_at,
        expires_at: Some(created_at + Duration::hours(1)),
        review_at: None,
    };

    let mut wrong_finding = subject.clone();
    wrong_finding.finding_identity = "0".repeat(64);
    assert!(storage::triage::create_suppression(&pool, write(wrong_finding))
        .await
        .is_err_and(|error| error.to_string().contains("finding identity changed")));

    let mut wrong_project = subject.clone();
    wrong_project.project_identity = foreign.id.to_string();
    assert!(storage::triage::create_suppression(&pool, write(wrong_project))
        .await
        .is_err_and(|error| error.to_string().contains("finding identity changed")));

    let missing_project = Uuid::new_v4();
    let mut missing = subject;
    missing.project_identity = missing_project.to_string();
    assert!(storage::triage::create_suppression(&pool, write(missing)).await.is_err_and(|error| {
        error.to_string().contains(&format!("project '{missing_project}' was not found"))
    }));

    storage::projects::delete_project(&pool, project_id)
        .await
        .unwrap_or_else(|error| panic!("delete suppression identity fixture: {error}"));
    storage::projects::delete_project(&pool, foreign.id)
        .await
        .unwrap_or_else(|error| panic!("delete foreign project: {error}"));
}

#[tokio::test]
async fn sorted_correlation_advisory_lock_blocks_then_releases_the_write() {
    let Some((pool, _, _, first, second)) = fixture().await else {
        return;
    };
    let project_id = triage_subject(&pool, first)
        .await
        .project_identity
        .parse::<Uuid>()
        .unwrap_or_else(|error| panic!("parse lock project: {error}"));
    let first_evidence = storage::findings::list_evidence(&pool, first)
        .await
        .unwrap_or_else(|error| panic!("first lock evidence: {error}"));
    let second_evidence = storage::findings::list_evidence(&pool, second)
        .await
        .unwrap_or_else(|error| panic!("second lock evidence: {error}"));
    let locked_id = [first, second]
        .into_iter()
        .min()
        .unwrap_or_else(|| panic!("correlation lock set is empty"));
    let mut blocker =
        pool.begin().await.unwrap_or_else(|error| panic!("begin advisory lock blocker: {error}"));
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("finding-correlation/v1:{locked_id}"))
        .execute(&mut *blocker)
        .await
        .unwrap_or_else(|error| panic!("acquire advisory lock blocker: {error}"));

    let task_pool = pool.clone();
    let mut task = tokio::spawn(async move {
        storage::triage::record_correlation(
            &task_pool,
            FindingCorrelationWrite {
                finding_id: first,
                contributing_finding_ids: vec![first, second],
                evidence_ids: vec![
                    first_evidence[0].evidence_identity.clone(),
                    second_evidence[0].evidence_identity.clone(),
                ],
                facets: vec![CorrelationKey::new("fixture", "advisory-lock")],
                explanation: "Advisory lock fixture".to_string(),
                actor: triage_actor(),
                created_at: Utc::now(),
            },
        )
        .await
    });
    assert!(tokio::time::timeout(std::time::Duration::from_millis(500), &mut task).await.is_err());
    blocker
        .rollback()
        .await
        .unwrap_or_else(|error| panic!("release advisory lock blocker: {error}"));
    assert!(tokio::time::timeout(std::time::Duration::from_secs(10), task)
        .await
        .unwrap_or_else(|_| panic!("correlation write did not resume"))
        .unwrap_or_else(|error| panic!("correlation lock task failed: {error}"))
        .unwrap_or_else(|error| panic!("correlation write failed after release: {error}")));

    storage::projects::delete_project(&pool, project_id)
        .await
        .unwrap_or_else(|error| panic!("delete advisory lock fixture: {error}"));
}

#[tokio::test]
async fn correlation_input_guard_distinguishes_each_independent_failure_and_exact_bound() {
    let Some((pool, _, _, first, second)) = fixture().await else {
        return;
    };
    let project_id = triage_subject(&pool, first)
        .await
        .project_identity
        .parse::<Uuid>()
        .unwrap_or_else(|error| panic!("parse correlation guard project: {error}"));
    let write = |contributing_finding_ids| FindingCorrelationWrite {
        finding_id: first,
        contributing_finding_ids,
        evidence_ids: Vec::new(),
        facets: Vec::new(),
        explanation: "Independent correlation input guard".to_string(),
        actor: triage_actor(),
        created_at: Utc::now(),
    };

    for ids in [vec![first, first], vec![second]] {
        let error = storage::triage::record_correlation(&pool, write(ids))
            .await
            .expect_err("independent correlation input rejection");
        assert!(error.to_string().contains("unique, bounded, and include"));
    }

    let mut exact = vec![first];
    exact.extend((1..MAX_TRIAGE_REFERENCES).map(|_| Uuid::new_v4()));
    let error = storage::triage::record_correlation(&pool, write(exact.clone()))
        .await
        .expect_err("unknown contributors at exact reference bound");
    assert!(error.to_string().contains("outside the finding project"));

    exact.push(Uuid::new_v4());
    let error = storage::triage::record_correlation(&pool, write(exact))
        .await
        .expect_err("correlation reference overflow");
    assert!(error.to_string().contains("unique, bounded, and include"));

    storage::projects::delete_project(&pool, project_id)
        .await
        .unwrap_or_else(|error| panic!("delete correlation guard fixture: {error}"));
}

#[tokio::test]
async fn durable_append_ceiling_helpers_reject_the_first_overflowing_write() {
    let Some((pool, _, _, first, _second)) = fixture().await else {
        return;
    };
    let subject = triage_subject(&pool, first).await;
    let project_id = subject
        .project_identity
        .parse::<Uuid>()
        .unwrap_or_else(|error| panic!("parse suppression ceiling project: {error}"));
    sqlx::query(
        "INSERT INTO finding_suppressions \
         (project_id, origin_finding_id, suppression_identity, suppression_schema, scope_kind, \
          finding_identity, actor_kind, actor_identity, raw_suppression, created_at, expires_at) \
         SELECT $1, $2, lpad(to_hex(value), 64, '0'), 'fixture', 'finding', $3, \
                'human', 'fixture', '{}'::jsonb, \
                clock_timestamp() + value * interval '1 microsecond', \
                clock_timestamp() + interval '1 hour' \
         FROM generate_series(1, $4::integer) AS value",
    )
    .bind(project_id)
    .bind(first)
    .bind(&subject.finding_identity)
    .bind(i32::try_from(MAX_TRIAGE_SUPPRESSIONS).expect("suppression limit fits i32"))
    .execute(&pool)
    .await
    .unwrap_or_else(|error| panic!("seed suppression ceiling: {error}"));
    let created_at = Utc::now();
    assert!(storage::triage::create_suppression(
        &pool,
        FindingSuppressionWrite {
            finding_id: first,
            subject,
            kind: FindingSuppressionScopeKind::Finding,
            actor: triage_actor(),
            reason: "Suppression overflow".to_string(),
            created_at,
            expires_at: Some(created_at + Duration::hours(1)),
            review_at: None,
        },
    )
    .await
    .is_err_and(|error| error.to_string().contains("suppression history exceeds its bound")));
    storage::projects::delete_project(&pool, project_id)
        .await
        .unwrap_or_else(|error| panic!("delete suppression ceiling fixture: {error}"));

    let Some((pool, _, _, first, second)) = fixture().await else {
        return;
    };
    let project_id = triage_subject(&pool, first)
        .await
        .project_identity
        .parse::<Uuid>()
        .unwrap_or_else(|error| panic!("parse correlation ceiling project: {error}"));
    sqlx::query(
        "INSERT INTO finding_correlation_decisions \
         (tracked_finding_id, decision_identity, decision_schema, actor_kind, actor_identity, \
          raw_decision, created_at) \
         SELECT $1, lpad(to_hex(value), 64, '0'), 'fixture', 'human', 'fixture', '{}'::jsonb, \
                clock_timestamp() + value * interval '1 microsecond' \
         FROM generate_series(1, $2::integer) AS value",
    )
    .bind(first)
    .bind(i32::try_from(MAX_TRIAGE_CORRELATIONS).expect("correlation limit fits i32"))
    .execute(&pool)
    .await
    .unwrap_or_else(|error| panic!("seed correlation ceiling: {error}"));
    let first_evidence = storage::findings::list_evidence(&pool, first)
        .await
        .unwrap_or_else(|error| panic!("first ceiling evidence: {error}"));
    let second_evidence = storage::findings::list_evidence(&pool, second)
        .await
        .unwrap_or_else(|error| panic!("second ceiling evidence: {error}"));
    assert!(storage::triage::record_correlation(
        &pool,
        FindingCorrelationWrite {
            finding_id: first,
            contributing_finding_ids: vec![first, second],
            evidence_ids: vec![
                first_evidence[0].evidence_identity.clone(),
                second_evidence[0].evidence_identity.clone(),
            ],
            facets: vec![CorrelationKey::new("fixture", "correlation-overflow")],
            explanation: "Correlation overflow".to_string(),
            actor: triage_actor(),
            created_at: Utc::now(),
        },
    )
    .await
    .is_err_and(|error| error.to_string().contains("correlation history exceeds its bound")));
    storage::projects::delete_project(&pool, project_id)
        .await
        .unwrap_or_else(|error| panic!("delete correlation ceiling fixture: {error}"));
}

#[tokio::test]
async fn suppression_origin_must_remain_in_the_declared_project() {
    let Some((pool, service, engagement_id, first, second)) = fixture().await else {
        return;
    };
    let project_id = finding(&service, engagement_id, first).await.project_id;
    command(
        &service,
        engagement_id,
        ControlCommandV1::CreateFindingSuppression {
            finding_id: first,
            scope: "finding".to_string(),
            reason: "Origin ownership fixture".to_string(),
            expires_at: Some(Utc::now() + Duration::hours(1)),
            review_at: None,
        },
    )
    .await;
    let foreign = storage::projects::create_project(
        &pool,
        &format!("foreign-origin-{}", Uuid::new_v4()),
        "foreign origin fixture",
    )
    .await
    .unwrap_or_else(|error| panic!("create foreign origin project: {error}"));
    sqlx::query("UPDATE tracked_findings SET project_id = $2 WHERE id = $1")
        .bind(second)
        .bind(foreign.id)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("move suppression origin: {error}"));
    sqlx::query("UPDATE finding_suppressions SET origin_finding_id = $2 WHERE project_id = $1")
        .bind(project_id)
        .bind(second)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("replace suppression origin: {error}"));
    let response = service
        .execute_local(ControlRequestV1::query(
            ControlQueryV1::GetFinding { id: first },
            Some(engagement_id),
        ))
        .await;
    assert!(matches!(
        response.result,
        ControlResponseOutcomeV1::Error(ref error)
            if error.code == ControlErrorCodeV1::CanonicalProjectionMismatch
    ));
    sqlx::query("UPDATE finding_suppressions SET origin_finding_id = $2 WHERE project_id = $1")
        .bind(project_id)
        .bind(first)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("restore suppression origin: {error}"));
    sqlx::query("UPDATE tracked_findings SET project_id = $2 WHERE id = $1")
        .bind(second)
        .bind(project_id)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("restore origin project: {error}"));
    storage::projects::delete_project(&pool, project_id)
        .await
        .unwrap_or_else(|error| panic!("delete suppression origin fixture: {error}"));
    storage::projects::delete_project(&pool, foreign.id)
        .await
        .unwrap_or_else(|error| panic!("delete foreign origin fixture: {error}"));
}

#[tokio::test]
async fn rediscovery_appends_regressed_or_needs_context_without_rewriting_history() {
    let Some((pool, service, engagement_id, fixed_id, changed_id)) = fixture().await else {
        return;
    };
    for state in ["validated", "fixed"] {
        command(
            &service,
            engagement_id,
            ControlCommandV1::TransitionFinding {
                finding_id: fixed_id,
                state: state.to_string(),
                reason: format!("Fixture transition to {state}"),
                evidence_ids: Vec::new(),
                model_analysis_identity: None,
            },
        )
        .await;
    }
    command(
        &service,
        engagement_id,
        ControlCommandV1::TransitionFinding {
            finding_id: changed_id,
            state: "validated".to_string(),
            reason: "Fixture validated evidence".to_string(),
            evidence_ids: Vec::new(),
            model_analysis_identity: None,
        },
    )
    .await;
    let fixed_row = storage::findings::get_finding(&pool, fixed_id)
        .await
        .unwrap_or_else(|error| panic!("get fixed finding: {error}"))
        .unwrap_or_else(|| panic!("fixed finding is absent"));
    let changed_row = storage::findings::get_finding(&pool, changed_id)
        .await
        .unwrap_or_else(|error| panic!("get changed finding: {error}"))
        .unwrap_or_else(|| panic!("changed finding is absent"));
    let fixed_finding: Finding = serde_json::from_value(fixed_row.raw_finding)
        .unwrap_or_else(|error| panic!("decode fixed finding: {error}"));
    let changed_finding = serde_json::from_value::<Finding>(changed_row.raw_finding)
        .unwrap_or_else(|error| panic!("decode changed finding: {error}"))
        .with_evidence("materially different proof");

    assert_same_scan_retry_is_idempotent(
        &pool,
        &service,
        engagement_id,
        fixed_row.project_id,
        fixed_row.scan_id,
        fixed_id,
        &fixed_finding,
    )
    .await;

    let scan_id = create_rediscovery_scan(&pool, fixed_row.project_id).await;
    let concurrent_scan_id = create_rediscovery_scan(&pool, fixed_row.project_id).await;
    let first_findings = [fixed_finding.clone(), changed_finding.clone()];
    let second_findings = [fixed_finding, changed_finding];
    let (first_save, second_save) = tokio::join!(
        storage::findings::save_findings(&pool, fixed_row.project_id, scan_id, &first_findings,),
        storage::findings::save_findings(
            &pool,
            fixed_row.project_id,
            concurrent_scan_id,
            &second_findings,
        )
    );
    first_save.unwrap_or_else(|error| panic!("store first rediscovered findings: {error}"));
    second_save.unwrap_or_else(|error| panic!("store concurrent rediscovered findings: {error}"));

    let regressed = finding(&service, engagement_id, fixed_id).await;
    assert_eq!(regressed.triage.current_state, "regressed");
    assert_eq!(regressed.triage.transitions.len(), 4);
    assert_eq!(
        regressed
            .triage
            .transitions
            .last()
            .unwrap_or_else(|| panic!("regression transition is absent"))["actor"]["kind"],
        "system"
    );
    let needs_context = finding(&service, engagement_id, changed_id).await;
    assert_eq!(needs_context.triage.current_state, "needs_context");
    assert_eq!(needs_context.triage.transitions.len(), 3);
    assert_eq!(regressed.seen_count, 3);
    assert_eq!(needs_context.seen_count, 3);

    storage::projects::delete_project(&pool, fixed_row.project_id)
        .await
        .unwrap_or_else(|error| panic!("delete rediscovery fixture: {error}"));
}
