pub mod args;
#[cfg(feature = "storage")]
pub(crate) mod control_adapter;
#[cfg(feature = "control-api")]
pub mod control_api;
#[cfg(feature = "storage")]
pub mod db;
pub mod doctor;
#[cfg(feature = "storage")]
pub mod finding;
pub mod init;
#[cfg(feature = "storage")]
pub mod job;
#[cfg(feature = "storage")]
pub mod project;
pub mod runner;
#[cfg(feature = "storage")]
pub mod schedule;
#[cfg(feature = "mcp")]
pub mod serve;
#[cfg(feature = "storage")]
pub mod webhook;

#[cfg(all(test, feature = "storage"))]
mod control_adapter_tests {
    use super::control_adapter::{append_bounded_for_test, LocalControlClient};
    use crate::config::AppConfig;
    use crate::control::ControlService;
    use crate::engine::finding::Finding;
    use crate::engine::policy::{Capability, Engagement, EngagementPolicy};
    use crate::engine::scope::ScopeRule;
    use crate::engine::severity::Severity;
    use chrono::Utc;
    use std::sync::Arc;
    use uuid::Uuid;

    async fn test_pool() -> Option<sqlx::PgPool> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::storage::connect(&database_url).await.ok()?;
        crate::storage::migrate::run_migrations(&pool).await.ok()?;
        Some(pool)
    }

    #[tokio::test]
    async fn compatibility_queries_return_the_selected_project_targets_and_findings() {
        let Some(pool) = test_pool().await else {
            eprintln!("DATABASE_URL not set - skipping control adapter database test");
            return;
        };
        let project_name = format!("control-adapter-{}", Uuid::new_v4());
        let project =
            crate::storage::projects::create_project(&pool, &project_name, "adapter fixture")
                .await
                .expect("create adapter project");
        crate::storage::projects::add_target(
            &pool,
            project.id,
            "https://example.test/",
            "adapter target",
        )
        .await
        .expect("create adapter target");
        let now = Utc::now();
        let scan = crate::storage::scans::save_scan(
            &pool,
            project.id,
            "https://example.test/",
            "quick",
            now,
            Some(now),
            &[],
            &[],
            &serde_json::json!({}),
        )
        .await
        .expect("create adapter scan");
        crate::storage::findings::save_findings(
            &pool,
            project.id,
            scan.id,
            &[Finding::new(
                "control-adapter",
                Severity::Low,
                "Adapter fixture",
                "Adapter fixture finding",
                "https://example.test/",
            )],
        )
        .await
        .expect("create adapter finding");

        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.test").expect("fixture scope"))
            .allow_capability(Capability::LocalState);
        let config = Arc::new(AppConfig {
            engagement: Some(Engagement::new("control-adapter", policy)),
            ..AppConfig::default()
        });
        let service = ControlService::persistent(Arc::clone(&config), pool.clone(), None);
        let client = LocalControlClient::new(&config, service);

        assert_eq!(client.project(&project_name).await.expect("select project").id, project.id);
        let targets = client.targets(project.id).await.expect("list targets");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].project_id, project.id);
        let findings = client.findings(project.id).await.expect("list findings");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].project_id, project.id);

        crate::storage::projects::delete_project(&pool, project.id)
            .await
            .expect("delete adapter fixture");
    }

    #[test]
    fn compatibility_result_bound_accepts_the_limit_and_rejects_one_more() {
        const COMPATIBILITY_LIMIT: usize = 10_000;
        let mut values = Vec::new();
        append_bounded_for_test(&mut values, vec![(); COMPATIBILITY_LIMIT], "fixture")
            .expect("exact compatibility limit");
        assert_eq!(values.len(), COMPATIBILITY_LIMIT);
        let error = append_bounded_for_test(&mut values, vec![()], "fixture")
            .expect_err("one item beyond the compatibility limit");
        assert!(error.to_string().contains("exceeds the CLI compatibility limit"));
        assert_eq!(values.len(), COMPATIBILITY_LIMIT);
    }
}
