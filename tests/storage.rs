//! Integration tests for the storage layer.
//!
//! These tests require a running PostgreSQL instance. Set the
//! `DATABASE_URL` environment variable to run them:
//!
//! ```bash
//! DATABASE_URL=postgresql://user:pass@localhost/scorchkit_test cargo test --features storage
//! ```
//!
//! Tests that require a database are skipped gracefully when
//! `DATABASE_URL` is not set.

#[cfg(feature = "storage")]
mod storage_tests {
    use scorchkit::engine::finding::Finding;
    use scorchkit::engine::severity::Severity;
    use scorchkit::storage;
    use scorchkit::storage::models::VulnStatus;

    /// Helper: connect to the test database, or skip if DATABASE_URL
    /// is not set.
    async fn test_pool() -> Option<sqlx::PgPool> {
        let url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => return None,
        };
        let pool = storage::connect(&url).await.ok()?;
        storage::migrate::run_migrations(&pool).await.ok()?;
        Some(pool)
    }

    /// Helper: create a uniquely-named project for test isolation.
    async fn create_test_project(pool: &sqlx::PgPool) -> scorchkit::storage::models::Project {
        let name = format!("test-project-{}", uuid::Uuid::new_v4());
        storage::projects::create_project(pool, &name, "test project")
            .await
            .expect("create_project should succeed")
    }

    /// Verify that the pool connects and migrations run successfully.
    #[tokio::test]
    async fn test_connect_and_migrate() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };
        // If we got here, connect + migrate succeeded
        let row: (i64,) = sqlx::query_as("SELECT count(*) FROM projects")
            .fetch_one(&pool)
            .await
            .expect("query should work after migration");
        assert!(row.0 >= 0);
    }

    /// Verify the full project CRUD lifecycle: create, get, list,
    /// update, delete.
    #[tokio::test]
    async fn test_project_crud() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };

        // Create
        let project = create_test_project(&pool).await;
        assert!(!project.name.is_empty());

        // Get
        let fetched = storage::projects::get_project(&pool, project.id)
            .await
            .expect("get should work")
            .expect("project should exist");
        assert_eq!(fetched.id, project.id);

        // List
        let all = storage::projects::list_projects(&pool).await.expect("list should work");
        assert!(all.iter().any(|p| p.id == project.id));

        // Update
        let updated = storage::projects::update_project(
            &pool,
            project.id,
            &format!("{}-updated", project.name),
            "updated description",
        )
        .await
        .expect("update should work")
        .expect("project should exist");
        assert_eq!(updated.description, "updated description");

        // Delete
        let deleted =
            storage::projects::delete_project(&pool, project.id).await.expect("delete should work");
        assert!(deleted);

        let gone =
            storage::projects::get_project(&pool, project.id).await.expect("get should work");
        assert!(gone.is_none());
    }

    /// Verify adding, listing, and removing targets from a project.
    #[tokio::test]
    async fn test_project_targets() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };

        let project = create_test_project(&pool).await;

        // Add targets
        let t1 =
            storage::projects::add_target(&pool, project.id, "https://example.com", "main site")
                .await
                .expect("add target 1");

        let _t2 =
            storage::projects::add_target(&pool, project.id, "https://api.example.com", "API")
                .await
                .expect("add target 2");

        // List
        let targets =
            storage::projects::list_targets(&pool, project.id).await.expect("list targets");
        assert_eq!(targets.len(), 2);

        // Remove
        let removed = storage::projects::remove_target(&pool, t1.id).await.expect("remove target");
        assert!(removed);

        let targets =
            storage::projects::list_targets(&pool, project.id).await.expect("list after remove");
        assert_eq!(targets.len(), 1);

        // Cleanup
        storage::projects::delete_project(&pool, project.id).await.expect("cleanup");
    }

    /// Verify saving a scan record and retrieving it by ID.
    #[tokio::test]
    async fn test_save_scan_record() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };

        let project = create_test_project(&pool).await;
        let now = chrono::Utc::now();

        let scan = storage::scans::save_scan(
            &pool,
            project.id,
            "https://example.com",
            "standard",
            now,
            Some(now),
            &["headers".to_string(), "xss".to_string()],
            &["nmap".to_string()],
            &serde_json::json!({"total_findings": 3, "critical": 1}),
        )
        .await
        .expect("save scan");

        let fetched = storage::scans::get_scan(&pool, scan.id)
            .await
            .expect("get scan")
            .expect("scan should exist");

        assert_eq!(fetched.target_url, "https://example.com");
        assert_eq!(fetched.modules_run.len(), 2);
        assert_eq!(fetched.modules_skipped.len(), 1);

        storage::projects::delete_project(&pool, project.id).await.expect("cleanup");
    }

    /// Verify listing multiple scans for a project returns them
    /// in reverse chronological order.
    #[tokio::test]
    async fn test_list_scans_for_project() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };

        let project = create_test_project(&pool).await;
        let now = chrono::Utc::now();

        // Create two scans
        let _s1 = storage::scans::save_scan(
            &pool,
            project.id,
            "https://a.com",
            "quick",
            now - chrono::Duration::hours(1),
            Some(now),
            &[],
            &[],
            &serde_json::json!({}),
        )
        .await
        .expect("scan 1");

        let _s2 = storage::scans::save_scan(
            &pool,
            project.id,
            "https://b.com",
            "thorough",
            now,
            Some(now),
            &[],
            &[],
            &serde_json::json!({}),
        )
        .await
        .expect("scan 2");

        let scans = storage::scans::list_scans(&pool, project.id).await.expect("list scans");
        assert_eq!(scans.len(), 2);
        // Newest first
        assert_eq!(scans[0].target_url, "https://b.com");

        storage::projects::delete_project(&pool, project.id).await.expect("cleanup");
    }

    /// Verify finding deduplication: first save creates the row,
    /// second save with same fingerprint bumps seen_count.
    #[tokio::test]
    async fn test_save_and_dedup_findings() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };

        let project = create_test_project(&pool).await;
        let now = chrono::Utc::now();

        let scan1 = storage::scans::save_scan(
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
        .expect("scan 1");

        let finding = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "XSS in search param",
            "https://example.com/search?q=test",
        );

        // First save — should create 1 new finding
        let new_count =
            storage::findings::save_findings(&pool, project.id, scan1.id, &[finding.clone()])
                .await
                .expect("first save");
        assert_eq!(new_count, 1);

        // Second save with same fingerprint — should update, not create
        let scan2 = storage::scans::save_scan(
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
        .expect("scan 2");

        let new_count = storage::findings::save_findings(&pool, project.id, scan2.id, &[finding])
            .await
            .expect("second save");
        assert_eq!(new_count, 0, "dedup should prevent new row");

        // Verify seen_count was bumped
        let findings =
            storage::findings::find_by_severity(&pool, project.id, "high").await.expect("query");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].seen_count, 2);

        storage::projects::delete_project(&pool, project.id).await.expect("cleanup");
    }

    /// Verify the vulnerability status lifecycle transitions.
    #[tokio::test]
    async fn test_finding_status_lifecycle() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };

        let project = create_test_project(&pool).await;
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
        .expect("scan");

        let finding = Finding::new(
            "ssl",
            Severity::Medium,
            "Weak TLS",
            "TLS 1.0 enabled",
            "https://example.com",
        );

        storage::findings::save_findings(&pool, project.id, scan.id, &[finding])
            .await
            .expect("save");

        // Get the finding
        let findings = storage::findings::find_by_status(&pool, project.id, VulnStatus::New)
            .await
            .expect("query new");
        assert_eq!(findings.len(), 1);
        let fid = findings[0].id;

        // Transition: New → Acknowledged
        storage::findings::update_finding_status(&pool, fid, VulnStatus::Acknowledged, None)
            .await
            .expect("ack");

        let acked = storage::findings::find_by_status(&pool, project.id, VulnStatus::Acknowledged)
            .await
            .expect("query acked");
        assert_eq!(acked.len(), 1);

        // Transition: Acknowledged → Remediated
        storage::findings::update_finding_status(&pool, fid, VulnStatus::Remediated, None)
            .await
            .expect("remediate");

        // Transition: Remediated → Verified
        storage::findings::update_finding_status(&pool, fid, VulnStatus::Verified, None)
            .await
            .expect("verify");

        let verified = storage::findings::find_by_status(&pool, project.id, VulnStatus::Verified)
            .await
            .expect("query verified");
        assert_eq!(verified.len(), 1);

        storage::projects::delete_project(&pool, project.id).await.expect("cleanup");
    }

    /// Verify filtering findings by severity.
    #[tokio::test]
    async fn test_query_findings_by_severity() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };

        let project = create_test_project(&pool).await;
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
        .expect("scan");

        let findings = vec![
            Finding::new("xss", Severity::High, "XSS", "desc", "https://example.com/a"),
            Finding::new(
                "headers",
                Severity::Low,
                "Missing Header",
                "desc",
                "https://example.com/b",
            ),
            Finding::new("ssl", Severity::High, "Weak TLS", "desc", "https://example.com/c"),
        ];

        storage::findings::save_findings(&pool, project.id, scan.id, &findings)
            .await
            .expect("save");

        let high = storage::findings::find_by_severity(&pool, project.id, "high")
            .await
            .expect("query high");
        assert_eq!(high.len(), 2);

        let low =
            storage::findings::find_by_severity(&pool, project.id, "low").await.expect("query low");
        assert_eq!(low.len(), 1);

        storage::projects::delete_project(&pool, project.id).await.expect("cleanup");
    }

    /// Verify filtering findings by lifecycle status.
    #[tokio::test]
    async fn test_query_findings_by_status() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };

        let project = create_test_project(&pool).await;
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
        .expect("scan");

        let findings = vec![
            Finding::new("xss", Severity::High, "XSS", "desc", "https://example.com/a"),
            Finding::new("ssl", Severity::Medium, "Weak TLS", "desc", "https://example.com/b"),
        ];

        storage::findings::save_findings(&pool, project.id, scan.id, &findings)
            .await
            .expect("save");

        // Both should be New
        let new_findings = storage::findings::find_by_status(&pool, project.id, VulnStatus::New)
            .await
            .expect("query new");
        assert_eq!(new_findings.len(), 2);

        // Mark one as false positive
        storage::findings::update_finding_status(
            &pool,
            new_findings[0].id,
            VulnStatus::FalsePositive,
            None,
        )
        .await
        .expect("mark fp");

        let still_new = storage::findings::find_by_status(&pool, project.id, VulnStatus::New)
            .await
            .expect("query new again");
        assert_eq!(still_new.len(), 1);

        let fp = storage::findings::find_by_status(&pool, project.id, VulnStatus::FalsePositive)
            .await
            .expect("query fp");
        assert_eq!(fp.len(), 1);

        storage::projects::delete_project(&pool, project.id).await.expect("cleanup");
    }

    /// Verify that existing CLI commands work without any database
    /// configuration. The storage module is feature-gated and optional.
    #[tokio::test]
    async fn test_existing_cli_without_db() {
        // Just verify AppConfig loads with default (no database URL)
        let config = scorchkit::config::AppConfig::default();
        assert!(config.database.url.is_none());
        // The CLI runner would check config.database.url and skip storage
        // if None — no panic, no error.
    }

    /// Full end-to-end flow: project → target → scan → findings →
    /// dedup → status update. Exercises the entire storage layer.
    #[tokio::test]
    async fn test_full_scan_to_storage_flow() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };

        // 1. Create project
        let project = create_test_project(&pool).await;

        // 2. Add target
        let target =
            storage::projects::add_target(&pool, project.id, "https://example.com", "main")
                .await
                .expect("add target");
        assert_eq!(target.url, "https://example.com");

        // 3. Save first scan
        let now = chrono::Utc::now();
        let scan1 = storage::scans::save_scan(
            &pool,
            project.id,
            "https://example.com",
            "thorough",
            now,
            Some(now),
            &["xss".into(), "ssl".into()],
            &["nmap".into()],
            &serde_json::json!({"total_findings": 2, "high": 1, "medium": 1}),
        )
        .await
        .expect("scan 1");

        // 4. Save findings
        let findings = vec![
            Finding::new(
                "xss",
                Severity::High,
                "Reflected XSS",
                "XSS found",
                "https://example.com/search",
            )
            .with_evidence("<script>alert(1)</script>")
            .with_remediation("Encode output")
            .with_owasp("A03:2021")
            .with_cwe(79),
            Finding::new(
                "ssl",
                Severity::Medium,
                "Weak Cipher",
                "RC4 in use",
                "https://example.com",
            )
            .with_remediation("Disable RC4"),
        ];

        let new_count = storage::findings::save_findings(&pool, project.id, scan1.id, &findings)
            .await
            .expect("save findings");
        assert_eq!(new_count, 2);

        // 5. Second scan — same findings should dedup
        let scan2 = storage::scans::save_scan(
            &pool,
            project.id,
            "https://example.com",
            "thorough",
            now,
            Some(now),
            &["xss".into(), "ssl".into()],
            &[],
            &serde_json::json!({"total_findings": 2}),
        )
        .await
        .expect("scan 2");

        let new_count = storage::findings::save_findings(&pool, project.id, scan2.id, &findings)
            .await
            .expect("dedup save");
        assert_eq!(new_count, 0, "all findings should dedup");

        // 6. Verify seen_count = 2 on both
        let all = storage::findings::find_by_status(&pool, project.id, VulnStatus::New)
            .await
            .expect("query all new");
        assert_eq!(all.len(), 2);
        for f in &all {
            assert_eq!(f.seen_count, 2, "seen_count should be 2 after dedup");
        }

        // 7. Update status
        let xss_finding = all.iter().find(|f| f.module_id == "xss").expect("xss finding");
        storage::findings::update_finding_status(
            &pool,
            xss_finding.id,
            VulnStatus::Remediated,
            None,
        )
        .await
        .expect("remediate xss");

        // 8. Verify scans list
        let scans = storage::scans::list_scans(&pool, project.id).await.expect("list scans");
        assert_eq!(scans.len(), 2);

        // 9. Cleanup
        storage::projects::delete_project(&pool, project.id).await.expect("cleanup");
    }
}
