//! Integration tests for the project model storage layer.
//!
//! These tests require a running PostgreSQL instance and `DATABASE_URL`
//! environment variable. If `DATABASE_URL` is not set, tests skip
//! gracefully with a message (not a failure).

#![cfg(feature = "storage")]

use scorchkit::config::DatabaseConfig;
use scorchkit::engine::finding::Finding;
use scorchkit::engine::severity::Severity;
use scorchkit::storage;
use scorchkit::storage::models::VulnStatus;

/// Helper to get a database pool or skip the test.
///
/// Uses the `let-else` early-return pattern: if `DATABASE_URL` is not
/// set, prints a message and returns `Ok(())` (counted as passed, not
/// skipped/ignored). This follows the established ScorchKit convention.
async fn get_pool_or_skip() -> Option<sqlx::PgPool> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set — skipping integration test");
        return None;
    };
    let pool = storage::connect(&url).await.expect("failed to connect to test database");
    storage::migrate::run_migrations(&pool).await.expect("migrations failed");
    Some(pool)
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
    let removed = storage::projects::remove_target(&pool, target.id).await;
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
        let ok = storage::findings::update_finding_status(&pool, finding_id, status).await.unwrap();
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
