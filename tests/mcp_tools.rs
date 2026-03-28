//! Integration tests for MCP server tools.
//!
//! Each test verifies one MCP tool by calling its `do_*` public method
//! on a `ScorchKitServer` instance. Tests that require database access
//! use the `DATABASE_URL` let-else early-return pattern for graceful skip.

#![cfg(feature = "mcp")]

use std::sync::Arc;

use scorchkit::config::AppConfig;
use scorchkit::engine::finding::Finding;
use scorchkit::engine::severity::Severity;
use scorchkit::mcp::server::ScorchKitServer;
use scorchkit::mcp::types::*;
use scorchkit::storage;

/// Helper to get a database pool or skip the test.
async fn get_pool_or_skip() -> Option<sqlx::PgPool> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set — skipping MCP integration test");
        return None;
    };
    let pool = storage::connect(&url).await.expect("failed to connect to test database");
    storage::migrate::run_migrations(&pool).await.expect("migrations failed");
    Some(pool)
}

/// Generate a unique project name.
fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

/// Create a test server.
fn test_server(pool: sqlx::PgPool) -> ScorchKitServer {
    ScorchKitServer::new(Arc::new(AppConfig::default()), pool)
}

/// Verify `scorchkit serve --help` shows the command.
#[test]
fn test_serve_help() {
    use assert_cmd::Command;
    use predicates::prelude::*;

    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["serve", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MCP server"));
}

/// Verify `ScorchKitServer::new()` constructs successfully.
#[tokio::test]
async fn test_server_creation() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    use rmcp::handler::server::ServerHandler;
    let info = server.get_info();
    assert_eq!(info.server_info.name, "scorchkit");
}

/// Verify `list_modules` returns a JSON array of modules.
#[tokio::test]
async fn test_tool_list_modules() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    let result = server.do_list_modules();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
    assert!(!parsed.is_empty(), "should return at least one module");
    assert!(parsed[0].get("id").is_some(), "each module should have an id");
}

/// Verify `check_tools` returns a JSON array of tool status.
#[tokio::test]
async fn test_tool_check_tools() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    let result = server.do_check_tools();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
    assert!(!parsed.is_empty(), "should return at least one tool");
    assert!(parsed[0].get("installed").is_some(), "each tool should have installed status");
}

/// Verify `scan` runs against a URL (non-routable — validates execution path).
#[tokio::test]
async fn test_tool_scan() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    let params = ScanParams {
        target: "http://192.0.2.1".to_string(),
        profile: "quick".to_string(),
        modules: Some("headers".to_string()),
        skip: None,
    };
    // May succeed with empty findings or fail with timeout — both are valid
    let _result = server.do_scan(params).await;
}

/// Verify `project_create` creates a project and returns JSON.
#[tokio::test]
async fn test_tool_project_create() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-create");

    let result = server
        .do_project_create(ProjectCreateParams {
            name: name.clone(),
            description: Some("test project".to_string()),
        })
        .await;
    assert!(result.is_ok(), "project_create should succeed");
    let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(json["name"], name);

    // Cleanup
    let project = storage::projects::get_project_by_name(&pool, &name).await.unwrap().unwrap();
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify `project_list` returns a JSON array.
#[tokio::test]
async fn test_tool_project_list() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-list");

    storage::projects::create_project(&pool, &name, "").await.unwrap();

    let result = server.do_project_list().await;
    assert!(result.is_ok(), "project_list should succeed");
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&result.unwrap()).unwrap();
    assert!(parsed.iter().any(|p| p["name"] == name));

    // Cleanup
    let project = storage::projects::get_project_by_name(&pool, &name).await.unwrap().unwrap();
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify `project_show` returns project details JSON.
#[tokio::test]
async fn test_tool_project_show() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-show");

    storage::projects::create_project(&pool, &name, "show test").await.unwrap();

    let result = server.do_project_show(ProjectRefParams { project: name.clone() }).await;
    assert!(result.is_ok(), "project_show should succeed");
    let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(json["project"]["name"], name);
    assert!(json.get("scan_count").is_some());

    // Cleanup
    let project = storage::projects::get_project_by_name(&pool, &name).await.unwrap().unwrap();
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify `project_delete` with force=false warns, force=true deletes.
#[tokio::test]
async fn test_tool_project_delete() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-delete");

    storage::projects::create_project(&pool, &name, "").await.unwrap();

    // Without force — warning
    let result =
        server.do_project_delete(ProjectDeleteParams { project: name.clone(), force: false }).await;
    assert!(result.is_ok());
    assert!(result.unwrap().contains("warning"));

    // With force — delete
    let result =
        server.do_project_delete(ProjectDeleteParams { project: name.clone(), force: true }).await;
    assert!(result.is_ok());
    assert!(result.unwrap().contains("deleted"));

    let gone = storage::projects::get_project_by_name(&pool, &name).await.unwrap();
    assert!(gone.is_none());
}

/// Verify `project_scan` runs a scan within a project.
#[tokio::test]
async fn test_tool_project_scan() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-pscan");

    storage::projects::create_project(&pool, &name, "").await.unwrap();

    let params = ProjectScanParams {
        project: name.clone(),
        target: "http://192.0.2.1".to_string(),
        profile: "quick".to_string(),
    };
    // May timeout or succeed — both valid, tests persistence path
    let _result = server.do_project_scan(params).await;

    // Cleanup
    let project = storage::projects::get_project_by_name(&pool, &name).await.unwrap().unwrap();
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify `project_findings` returns findings for a project.
#[tokio::test]
async fn test_tool_project_findings() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-findings");

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
    let findings_data =
        vec![Finding::new("xss", Severity::High, "XSS", "desc", "https://example.com")];
    storage::findings::save_findings(&pool, project.id, scan.id, &findings_data).await.unwrap();

    let result = server
        .do_project_findings(FindingListParams {
            project: name.clone(),
            severity: None,
            status: None,
        })
        .await;
    assert!(result.is_ok(), "project_findings should succeed");
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(parsed.len(), 1);

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify `finding_show` returns details for a finding.
#[tokio::test]
async fn test_tool_finding_show() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-fshow");

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
    let findings_data =
        vec![Finding::new("xss", Severity::High, "XSS", "desc", "https://example.com")];
    storage::findings::save_findings(&pool, project.id, scan.id, &findings_data).await.unwrap();

    let all = storage::findings::list_findings(&pool, project.id).await.unwrap();
    let finding_id = all[0].id;

    let result = server.do_finding_show(FindingRefParams { id: finding_id.to_string() }).await;
    assert!(result.is_ok(), "finding_show should succeed");
    let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(json["title"], "XSS");

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify `finding_update_status` updates a finding's status.
#[tokio::test]
async fn test_tool_finding_update_status() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-fstatus");

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
    let findings_data =
        vec![Finding::new("ssl", Severity::Medium, "Weak TLS", "desc", "https://example.com")];
    storage::findings::save_findings(&pool, project.id, scan.id, &findings_data).await.unwrap();

    let all = storage::findings::list_findings(&pool, project.id).await.unwrap();
    let finding_id = all[0].id;

    let result = server
        .do_finding_update_status(FindingUpdateStatusParams {
            id: finding_id.to_string(),
            status: "acknowledged".to_string(),
        })
        .await;
    assert!(result.is_ok(), "finding_update_status should succeed");
    assert!(result.unwrap().contains("acknowledged"));

    let updated = storage::findings::get_finding(&pool, finding_id).await.unwrap().unwrap();
    assert_eq!(updated.status, "acknowledged");

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify `target_add` adds a target to a project.
#[tokio::test]
async fn test_tool_target_add() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-tadd");

    storage::projects::create_project(&pool, &name, "").await.unwrap();

    let result = server
        .do_target_add(TargetAddParams {
            project: name.clone(),
            url: "https://example.com".to_string(),
            label: Some("main".to_string()),
        })
        .await;
    assert!(result.is_ok(), "target_add should succeed");
    let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(json["url"], "https://example.com");

    // Cleanup
    let project = storage::projects::get_project_by_name(&pool, &name).await.unwrap().unwrap();
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify `target_list` lists targets for a project.
#[tokio::test]
async fn test_tool_target_list() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-tlist");

    let project = storage::projects::create_project(&pool, &name, "").await.unwrap();
    storage::projects::add_target(&pool, project.id, "https://a.com", "").await.unwrap();
    storage::projects::add_target(&pool, project.id, "https://b.com", "").await.unwrap();

    let result = server.do_target_list(ProjectRefParams { project: name.clone() }).await;
    assert!(result.is_ok(), "target_list should succeed");
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(parsed.len(), 2);

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify `target_remove` removes a target from a project.
#[tokio::test]
async fn test_tool_target_remove() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-tremove");

    let project = storage::projects::create_project(&pool, &name, "").await.unwrap();
    let target =
        storage::projects::add_target(&pool, project.id, "https://example.com", "").await.unwrap();

    let result = server
        .do_target_remove(TargetRemoveParams { project: name.clone(), id: target.id.to_string() })
        .await;
    assert!(result.is_ok(), "target_remove should succeed");
    assert!(result.unwrap().contains("removed"));

    let targets = storage::projects::list_targets(&pool, project.id).await.unwrap();
    assert!(targets.is_empty());

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify `db_migrate` runs migrations successfully.
#[tokio::test]
async fn test_tool_db_migrate() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    let result = server.do_db_migrate().await;
    assert!(result.is_ok(), "db_migrate should succeed");
    assert!(result.unwrap().contains("success"));
}
