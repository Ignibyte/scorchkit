//! Integration tests for the project model storage layer.
//!
//! These tests require a running `PostgreSQL` instance and `DATABASE_URL`
//! environment variable. If `DATABASE_URL` is not set, tests skip
//! gracefully with a message (not a failure).

#![cfg(feature = "storage")]

use scorchkit::config::DatabaseConfig;
use scorchkit::engine::attack_path::{
    correlate_attack_paths, AttackPath, VerificationAttempt, VerificationConditions,
    VerificationCoverage, VerificationOutcome,
};
use scorchkit::engine::evidence::HttpEvidence;
use scorchkit::engine::finding::Finding;
use scorchkit::engine::observation::{
    CodeFlow, CodeFlowStep, CorrelationKey, ObservationLocation, ScannerProvenance, SourceRegion,
    ThreadFlow,
};
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::scope::ScopeRule;
use scorchkit::engine::severity::Severity;
use scorchkit::runner::job::{DastJobRequest, JobStore, ScanJob};
use scorchkit::storage;
use scorchkit::storage::jobs::PostgresJobStore;
use scorchkit::storage::models::VulnStatus;
use scorchkit::storage::webhooks::PostgresWebhookStore;
use scorchkit_executor::webhook::{WebhookDelivery, WebhookDeliveryState, WebhookStore};

/// Helper to get a database pool or skip the test.
///
/// Uses the `let-else` early-return pattern: if `DATABASE_URL` is not
/// set, prints a message and returns `Ok(())` (counted as passed, not
/// skipped/ignored). This follows the established `ScorchKit` convention.
async fn get_pool_or_skip() -> Option<sqlx::PgPool> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set — skipping integration test");
        return None;
    };
    let pool = storage::connect(&url)
        .await
        .unwrap_or_else(|error| panic!("failed to connect to test database: {error}"));
    storage::migrate::run_migrations(&pool)
        .await
        .unwrap_or_else(|error| panic!("test database migration failed: {error}"));
    Some(pool)
}

fn stored_job_request() -> DastJobRequest {
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::Exact("example.com".to_string()))
        .allow_capability(Capability::DastScan)
        .allow_effect(EffectClass::ActiveSafe);
    DastJobRequest::new(
        "https://example.com",
        "quick",
        Engagement::new("postgres-job-store", policy),
    )
}

#[tokio::test]
async fn postgres_job_store_matches_compare_and_swap_contract() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let store = PostgresJobStore::new(pool.clone());
    let job = ScanJob::new(stored_job_request(), uuid::Uuid::new_v4());
    store.create(&job).await.expect("create scan job");

    let loaded = store.get(job.id).await.expect("load scan job").expect("stored job");
    assert_eq!(loaded.id, job.id);
    assert_eq!(loaded.revision, 0);

    let mut updated = loaded.clone();
    updated.revision = 1;
    updated.state = scorchkit::runner::job::ScanJobState::Running;
    updated.lease_expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
    updated.started_at = Some(chrono::Utc::now());
    updated.updated_at = chrono::Utc::now();
    updated.error = Some("conformance update".to_string());
    assert!(store.compare_and_swap(0, &updated).await.expect("current revision update"));
    assert!(!store.compare_and_swap(0, &loaded).await.expect("stale revision rejection"));
    assert!(store.list().await.expect("list scan jobs").iter().any(|item| item.id == job.id));
    assert!(store
        .list_recoverable(chrono::Utc::now())
        .await
        .expect("list recoverable scan jobs")
        .iter()
        .any(|item| item.id == job.id));
    let mut illegal = updated.clone();
    illegal.revision = 2;
    illegal.request.target = "https://changed.example".to_string();
    illegal.updated_at = chrono::Utc::now();
    assert!(
        store.compare_and_swap(1, &illegal).await.is_err(),
        "immutable requests must be enforced by the store"
    );
    let audit = store.audit_events(job.id).await.expect("list scan job audit events");
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0].revision, 0);
    assert_eq!(audit[1].revision, 1);

    let mut interrupted = updated.clone();
    interrupted.revision = 2;
    interrupted.state = scorchkit::runner::job::ScanJobState::Interrupted;
    interrupted.owner_id = None;
    interrupted.lease_expires_at = None;
    interrupted.updated_at = chrono::Utc::now();
    interrupted.finished_at = Some(chrono::Utc::now());
    assert!(store.compare_and_swap(1, &interrupted).await.expect("interrupt root job"));
    let successor = ScanJob::successor(&interrupted, uuid::Uuid::new_v4());
    store.create(&successor).await.expect("create unique successor");
    let continuation = store.list_page(Some(job.id), 1_000).await.expect("list job continuation");
    assert!(continuation.iter().any(|candidate| candidate.id == successor.id));
    assert!(store.list_page(Some(uuid::Uuid::new_v4()), 10).await.is_err());
    let competing_successor = ScanJob::successor(&interrupted, uuid::Uuid::new_v4());
    assert!(
        store.create(&competing_successor).await.is_err(),
        "a parent attempt must not fork concurrent successors"
    );
    let mut forged_successor = ScanJob::successor(&interrupted, uuid::Uuid::new_v4());
    forged_successor.attempt = 99;
    assert!(
        store.create(&forged_successor).await.is_err(),
        "successor lineage must be validated before insertion"
    );

    sqlx::query("DELETE FROM scan_jobs WHERE id = $1")
        .bind(successor.id)
        .execute(&pool)
        .await
        .expect("delete successor fixture");
    sqlx::query("DELETE FROM scan_jobs WHERE id = $1")
        .bind(job.id)
        .execute(&pool)
        .await
        .expect("delete scan job fixture");
}

#[tokio::test]
async fn postgres_webhook_store_enforces_capacity_cas_and_atomic_audits() {
    let Some(pool) = get_pool_or_skip().await else { return };
    sqlx::query("DELETE FROM webhook_deliveries WHERE destination_id LIKE 'fixture-%'")
        .execute(&pool)
        .await
        .expect("delete stale webhook fixtures");
    let store = PostgresWebhookStore::new(pool.clone());
    let engagement = Engagement::new("postgres-webhook-store", EngagementPolicy::default());
    let delivery = WebhookDelivery::new(
        format!("fixture-{}", uuid::Uuid::new_v4()),
        "scan_completed".to_string(),
        serde_json::json!({"schema":"scorchkit.webhook-event/v1","event":"redacted"}),
        engagement,
        2,
    );
    store.create(&delivery, 1).await.expect("create delivery");
    assert_eq!(store.get(delivery.id).await.expect("get delivery").unwrap().id, delivery.id);
    assert!(store.list().await.expect("list deliveries").iter().any(|item| item.id == delivery.id));
    assert!(store
        .list_due(chrono::Utc::now(), 1_000)
        .await
        .expect("list due deliveries")
        .iter()
        .any(|item| item.id == delivery.id));
    let competing = WebhookDelivery::new(
        delivery.destination_id.clone(),
        delivery.event_kind.clone(),
        delivery.payload.clone(),
        delivery.engagement.clone(),
        2,
    );
    assert!(store.create(&competing, 1).await.is_err(), "capacity must be atomic");

    let mut claimed = delivery.clone();
    let now = chrono::Utc::now();
    scorchkit_executor::webhook_integration::transition_delivery(
        &mut claimed,
        WebhookDeliveryState::Delivering,
        now,
    )
    .expect("legal claim transition");
    claimed.revision = 1;
    claimed.attempts = 1;
    claimed.owner_id = Some(uuid::Uuid::new_v4());
    claimed.lease_expires_at = Some(now + chrono::Duration::seconds(15));
    claimed.next_attempt_at = None;
    claimed.updated_at = now;
    assert!(store.compare_and_swap(0, &claimed).await.expect("claim current revision"));
    assert!(!store.compare_and_swap(0, &claimed).await.expect("reject stale claim"));
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT attempts FROM webhook_deliveries WHERE id = $1")
            .bind(delivery.id)
            .fetch_one(&pool)
            .await
            .expect("read indexed attempts"),
        1
    );
    assert!(!store
        .list_due(now + chrono::Duration::seconds(30), 10)
        .await
        .expect("claimed delivery is not due")
        .iter()
        .any(|item| item.id == delivery.id));
    assert_eq!(store.audit_events(delivery.id).await.expect("delivery audits").len(), 2);
    assert!(store
        .list_recoverable(now + chrono::Duration::seconds(30), 10)
        .await
        .expect("recoverable deliveries")
        .iter()
        .any(|item| item.id == delivery.id));

    sqlx::query("DELETE FROM webhook_deliveries WHERE id = $1")
        .bind(delivery.id)
        .execute(&pool)
        .await
        .expect("delete webhook fixture");
}

/// Generate a unique project name to avoid collisions in parallel test runs.
fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

/// Verify `connect_from_config` resolves URL from config, falls back to env var.
#[tokio::test]
async fn test_connect_from_config() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set — skipping integration test");
        return;
    };

    // Config with explicit URL
    let config =
        DatabaseConfig { url: Some(url.clone()), max_connections: 2, migrate_on_startup: false };
    let pool = storage::connect_from_config(&config, None).await;
    assert!(pool.is_ok(), "connect_from_config with explicit URL should succeed");

    // Override via parameter takes precedence
    let config_no_url = DatabaseConfig { url: None, max_connections: 2, migrate_on_startup: false };
    let pool = storage::connect_from_config(&config_no_url, Some(&url)).await;
    assert!(pool.is_ok(), "connect_from_config with url_override should succeed");
}

/// Full project CRUD lifecycle: create → get by name → update → list → delete.
#[tokio::test]
async fn test_project_crud_lifecycle() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let name = unique_name("test-proj");

    // Create
    let project = storage::projects::create_project(&pool, &name, "test description").await;
    assert!(project.is_ok(), "create_project should succeed");
    let project = project.unwrap();
    assert_eq!(project.name, name);

    // Get by name
    let found = storage::projects::get_project_by_name(&pool, &name).await;
    assert!(found.is_ok());
    let found = found.unwrap();
    assert!(found.is_some(), "get_project_by_name should find the project");
    assert_eq!(found.unwrap().id, project.id);

    // Update
    let updated = storage::projects::update_project(&pool, project.id, &name, "updated desc").await;
    assert!(updated.is_ok());
    let updated = updated.unwrap();
    assert!(updated.is_some());
    assert_eq!(updated.unwrap().description, "updated desc");

    // List
    let all = storage::projects::list_projects(&pool).await;
    assert!(all.is_ok());
    assert!(all.unwrap().iter().any(|p| p.id == project.id));

    // Delete
    let deleted = storage::projects::delete_project(&pool, project.id).await;
    assert!(deleted.is_ok());
    assert!(deleted.unwrap());

    // Verify gone
    let gone = storage::projects::get_project(&pool, project.id).await;
    assert!(gone.is_ok());
    assert!(gone.unwrap().is_none());
}

/// Target CRUD lifecycle: add → list → remove.
#[tokio::test]
async fn test_target_crud_lifecycle() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let name = unique_name("test-target");

    let project = storage::projects::create_project(&pool, &name, "").await.unwrap();

    // Add target
    let target =
        storage::projects::add_target(&pool, project.id, "https://example.com", "main").await;
    assert!(target.is_ok());
    let target = target.unwrap();
    assert_eq!(target.url, "https://example.com");
    assert_eq!(target.label, "main");

    // List targets
    let targets = storage::projects::list_targets(&pool, project.id).await;
    assert!(targets.is_ok());
    assert_eq!(targets.unwrap().len(), 1);

    // Remove target
    let removed = storage::projects::remove_target(&pool, project.id, target.id).await;
    assert!(removed.is_ok());
    assert!(removed.unwrap());

    // Verify gone
    let targets = storage::projects::list_targets(&pool, project.id).await;
    assert!(targets.is_ok());
    assert!(targets.unwrap().is_empty());

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Save a scan record and findings, then query them back.
#[tokio::test]
async fn test_scan_persist_and_query() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let name = unique_name("test-scan");

    let project = storage::projects::create_project(&pool, &name, "").await.unwrap();
    let now = chrono::Utc::now();

    let scan = storage::scans::save_scan(
        &pool,
        project.id,
        "https://example.com",
        "standard",
        now,
        Some(now),
        &["headers".to_string(), "ssl".to_string()],
        &[],
        &serde_json::json!({"total_findings": 1}),
    )
    .await;
    assert!(scan.is_ok());
    let scan = scan.unwrap();

    let findings = vec![Finding::new(
        "xss",
        Severity::High,
        "Reflected XSS",
        "XSS in search param",
        "https://example.com/search?q=test",
    )
    .with_evidence("<script>alert(1)</script>")
    .with_remediation("Encode output")];

    let new_count = storage::findings::save_findings(&pool, project.id, scan.id, &findings).await;
    assert!(new_count.is_ok());
    assert_eq!(new_count.unwrap(), 1);

    // Query by scan
    let scan_findings = storage::findings::find_by_scan(&pool, scan.id).await;
    assert!(scan_findings.is_ok());
    assert_eq!(scan_findings.unwrap().len(), 1);

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

#[tokio::test]
async fn isolated_extension_provenance_round_trips_through_postgres() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let project =
        storage::projects::create_project(&pool, &unique_name("test-extension-provenance"), "")
            .await
            .expect("create extension persistence project");
    let now = chrono::Utc::now();
    let scan = storage::scans::save_scan(
        &pool,
        project.id,
        "https://example.com/extension",
        "standard",
        now,
        Some(now),
        &["fixture.extension".to_string()],
        &[],
        &serde_json::json!({"total_findings": 1}),
    )
    .await
    .expect("save extension scan");
    let digest = "a".repeat(64);
    let finding = Finding::new(
        "fixture.extension",
        Severity::Medium,
        "Extension persistence fixture",
        "Engine-normalized extension proposal",
        "https://example.com/extension",
    )
    .with_confidence(0.75)
    .with_provenance(
        ScannerProvenance::new("fixture.extension", now)
            .with_version("1.2.3")
            .with_rule("extension-module", Some(digest.clone()))
            .with_config("extension-invocation:fixture-1;parser:validated"),
    );

    let created = storage::findings::save_findings(&pool, project.id, scan.id, &[finding])
        .await
        .expect("save extension finding");
    assert_eq!(created, 1);
    let stored =
        storage::findings::find_by_scan(&pool, scan.id).await.expect("read extension finding");
    assert_eq!(stored.len(), 1);
    let restored: Finding =
        serde_json::from_value(stored[0].raw_finding.clone()).expect("decode stored finding");
    assert_eq!(restored.module_id, "fixture.extension");
    assert_eq!(restored.appsec.provenance.scanner_version.as_deref(), Some("1.2.3"));
    assert_eq!(restored.appsec.provenance.rule_digest.as_deref(), Some(digest.as_str()));
    assert_eq!(
        restored.appsec.provenance.config_identity.as_deref(),
        Some("extension-invocation:fixture-1;parser:validated")
    );

    storage::projects::delete_project(&pool, project.id)
        .await
        .expect("delete extension persistence project");
}

#[tokio::test]
async fn test_scan_execution_evidence_round_trips() {
    let Some(pool) = get_pool_or_skip().await else {
        return;
    };
    let project = storage::projects::create_project(&pool, &unique_name("test-scan-evidence"), "")
        .await
        .expect("create project");
    let now = chrono::Utc::now();
    let evidence = serde_json::json!({
        "schema": "scorchkit.scan-execution-evidence.v1",
        "execution_status": "incomplete",
        "module_outcomes": [],
        "supply_chain": {
            "coverage_status": "incomplete",
            "gaps": [{"kind": "missing_provider_snapshot"}]
        }
    });

    let scan = storage::scans::save_scan_with_evidence(
        &pool,
        project.id,
        "file:///owned/source",
        "standard",
        now,
        Some(now),
        &[],
        &[],
        &serde_json::json!({"total_findings": 0}),
        &evidence,
    )
    .await
    .expect("save scan evidence");
    assert_eq!(scan.execution_evidence, evidence);

    let restored =
        storage::scans::get_scan(&pool, scan.id).await.expect("read scan").expect("stored scan");
    assert_eq!(restored.execution_evidence, evidence);

    storage::projects::delete_project(&pool, project.id).await.expect("delete project");
}

fn reproduced_storage_path(observed_at: chrono::DateTime<chrono::Utc>) -> AttackPath {
    let source = Finding::new(
        "semgrep",
        Severity::High,
        "SQL input reaches query",
        "typed source proof",
        "src/users.rs:18",
    )
    .with_location(ObservationLocation::Source {
        path: "src/users.rs".to_string(),
        region: Some(SourceRegion::new(18)),
    })
    .with_cwe(89)
    .with_correlation_key(CorrelationKey::new("route", "/users"))
    .with_provenance(
        ScannerProvenance::new("semgrep", observed_at).with_target_revision("revision-1"),
    )
    .with_code_flows(vec![CodeFlow {
        message: None,
        thread_flows: vec![ThreadFlow {
            message: None,
            steps: vec![
                CodeFlowStep::new(ObservationLocation::Source {
                    path: "src/users.rs".to_string(),
                    region: Some(SourceRegion::new(8)),
                }),
                CodeFlowStep::new(ObservationLocation::Source {
                    path: "src/users.rs".to_string(),
                    region: Some(SourceRegion::new(18)),
                }),
            ],
        }],
    }]);
    let runtime = Finding::new(
        "nuclei",
        Severity::Critical,
        "Runtime SQL behavior",
        "typed runtime proof",
        "https://example.test/users?id=7",
    )
    .with_location(ObservationLocation::Runtime {
        uri: "https://example.test/users?id=7".to_string(),
        route: Some("/users".to_string()),
        parameter: None,
    })
    .with_cwe(89)
    .with_provenance(
        ScannerProvenance::new("nuclei", observed_at).with_target_revision("revision-1"),
    )
    .with_http_evidence(HttpEvidence::new("GET", "https://example.test/users?id=7", 500));
    let mut paths = correlate_attack_paths(&[source, runtime]).paths;
    assert_eq!(paths.len(), 1);
    paths.remove(0)
}

#[tokio::test]
async fn attack_paths_round_trip_and_append_transition_history() {
    let Some(pool) = get_pool_or_skip().await else {
        return;
    };
    let project = storage::projects::create_project(&pool, &unique_name("test-attack-path"), "")
        .await
        .expect("create attack-path project");
    let observed_at = chrono::Utc::now();
    let mut path = reproduced_storage_path(observed_at);
    let stale = path.clone();
    assert_eq!(
        storage::attack_paths::save_attack_paths(&pool, project.id, &[path.clone()])
            .await
            .expect("insert attack path"),
        1
    );

    sqlx::query("UPDATE attack_paths SET path_schema = 'wrong-schema' WHERE project_id = $1")
        .bind(project.id)
        .execute(&pool)
        .await
        .expect("tamper stored path schema");
    assert!(
        storage::attack_paths::save_attack_paths(&pool, project.id, &[path.clone()]).await.is_err(),
        "a stored path schema mismatch must fail closed"
    );
    sqlx::query("UPDATE attack_paths SET path_schema = $1 WHERE project_id = $2")
        .bind(&path.schema)
        .bind(project.id)
        .execute(&pool)
        .await
        .expect("restore stored path schema");

    sqlx::query("UPDATE attack_paths SET identity_schema = 'wrong-schema' WHERE project_id = $1")
        .bind(project.id)
        .execute(&pool)
        .await
        .expect("tamper stored identity schema");
    assert!(
        storage::attack_paths::save_attack_paths(&pool, project.id, &[path.clone()]).await.is_err(),
        "a stored identity schema mismatch must fail closed"
    );
    sqlx::query("UPDATE attack_paths SET identity_schema = $1 WHERE project_id = $2")
        .bind(&path.identity.schema)
        .bind(project.id)
        .execute(&pool)
        .await
        .expect("restore stored identity schema");

    let attempt = VerificationAttempt::new(
        path.identity.value.clone(),
        path.focused_verification.identity.clone(),
        VerificationCoverage::CompleteComparable,
        VerificationOutcome::NotReproduced,
        VerificationConditions {
            deployment_identity: Some("revision-1".to_string()),
            config_identities: Vec::new(),
        },
        vec!["negative-proof-1".to_string()],
        observed_at + chrono::Duration::seconds(1),
    );
    assert!(path.apply_verification(attempt).expect("apply complete negative"));
    assert_eq!(
        storage::attack_paths::save_attack_paths(&pool, project.id, &[path.clone()])
            .await
            .expect("append verification transition"),
        0
    );

    let restored = storage::attack_paths::list_attack_paths(&pool, project.id)
        .await
        .expect("list attack paths");
    assert_eq!(restored, vec![path]);
    assert!(
        storage::attack_paths::save_attack_paths(&pool, project.id, &[stale]).await.is_err(),
        "a stale snapshot must not erase stored transition history"
    );

    storage::projects::delete_project(&pool, project.id).await.expect("delete attack-path project");
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM attack_paths WHERE project_id = $1")
            .bind(project.id)
            .fetch_one(&pool)
            .await
            .expect("verify attack-path cascade");
    assert_eq!(remaining, 0);
}

/// Verify that saving the same finding twice increments `seen_count` via dedup.
#[tokio::test]
async fn test_finding_dedup_increments() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let name = unique_name("test-dedup");

    let project = storage::projects::create_project(&pool, &name, "").await.unwrap();
    let now = chrono::Utc::now();

    let scan1 = storage::scans::save_scan(
        &pool,
        project.id,
        "https://example.com",
        "standard",
        now,
        Some(now),
        &["xss".to_string()],
        &[],
        &serde_json::json!({}),
    )
    .await
    .unwrap();

    let scan2 = storage::scans::save_scan(
        &pool,
        project.id,
        "https://example.com",
        "standard",
        now,
        Some(now),
        &["xss".to_string()],
        &[],
        &serde_json::json!({}),
    )
    .await
    .unwrap();

    let finding = vec![Finding::new(
        "xss",
        Severity::High,
        "Reflected XSS",
        "desc",
        "https://example.com/search",
    )];

    // First save — should be new
    let count1 =
        storage::findings::save_findings(&pool, project.id, scan1.id, &finding).await.unwrap();
    assert_eq!(count1, 1, "first save should create 1 new finding");

    // Second save — same fingerprint, should update
    let count2 =
        storage::findings::save_findings(&pool, project.id, scan2.id, &finding).await.unwrap();
    assert_eq!(count2, 0, "second save should create 0 new (dedup)");

    // Verify seen_count incremented
    let all = storage::findings::list_findings(&pool, project.id).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].seen_count, 2, "seen_count should be 2 after dedup");

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify finding status lifecycle transitions.
#[tokio::test]
async fn test_finding_status_lifecycle() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let name = unique_name("test-status");

    let project = storage::projects::create_project(&pool, &name, "").await.unwrap();
    let now = chrono::Utc::now();

    let scan = storage::scans::save_scan(
        &pool,
        project.id,
        "https://example.com",
        "standard",
        now,
        Some(now),
        &[],
        &[],
        &serde_json::json!({}),
    )
    .await
    .unwrap();

    let finding =
        vec![Finding::new("ssl", Severity::Medium, "Weak cipher", "desc", "https://example.com")];
    storage::findings::save_findings(&pool, project.id, scan.id, &finding).await.unwrap();

    let all = storage::findings::list_findings(&pool, project.id).await.unwrap();
    assert_eq!(all.len(), 1);
    let finding_id = all[0].id;
    assert_eq!(all[0].status, "new");

    // Transition through lifecycle
    for (status, expected_str) in [
        (VulnStatus::Acknowledged, "acknowledged"),
        (VulnStatus::Remediated, "remediated"),
        (VulnStatus::Verified, "verified"),
    ] {
        let ok = storage::findings::update_finding_status(&pool, finding_id, status, None)
            .await
            .unwrap();
        assert!(ok);
        let updated = storage::findings::get_finding(&pool, finding_id).await.unwrap().unwrap();
        assert_eq!(updated.status, expected_str);
    }

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify `list_findings` returns all findings for a project (unfiltered).
#[tokio::test]
async fn test_list_findings_unfiltered() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let name = unique_name("test-listall");

    let project = storage::projects::create_project(&pool, &name, "").await.unwrap();
    let now = chrono::Utc::now();

    let scan = storage::scans::save_scan(
        &pool,
        project.id,
        "https://example.com",
        "standard",
        now,
        Some(now),
        &[],
        &[],
        &serde_json::json!({}),
    )
    .await
    .unwrap();

    let findings_data = vec![
        Finding::new("xss", Severity::High, "XSS", "desc", "https://example.com/a"),
        Finding::new("ssl", Severity::Low, "Weak TLS", "desc", "https://example.com/b"),
        Finding::new("csrf", Severity::Medium, "CSRF", "desc", "https://example.com/c"),
    ];
    let new_count =
        storage::findings::save_findings(&pool, project.id, scan.id, &findings_data).await.unwrap();
    assert_eq!(new_count, 3);

    let all = storage::findings::list_findings(&pool, project.id).await.unwrap();
    assert_eq!(all.len(), 3, "list_findings should return all 3 findings");

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}
