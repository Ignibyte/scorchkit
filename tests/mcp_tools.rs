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

// ═══════════════════════════════════════════════════════════════════════
// MCP Resource Tests
// ═══════════════════════════════════════════════════════════════════════

/// Verify `do_list_resources` returns at least the static projects
/// collection resource.
#[tokio::test]
async fn test_resource_list_resources() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    let result = server.do_list_resources().await;
    assert!(result.is_ok(), "do_list_resources should succeed");
    let list = result.unwrap();
    // At minimum, the static "All Projects" resource must be present
    assert!(
        list.resources.iter().any(|r| r.raw.uri == "scorchkit://projects"),
        "should contain the projects collection resource"
    );
}

/// Verify `do_list_resource_templates` returns exactly 5 templates.
#[tokio::test]
async fn test_resource_list_templates() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    let result = server.do_list_resource_templates();
    assert_eq!(result.resource_templates.len(), 5, "should return 5 resource templates");
}

/// Verify reading `scorchkit://projects` returns a JSON array of projects.
#[tokio::test]
async fn test_resource_read_projects() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("res-projects");

    storage::projects::create_project(&pool, &name, "").await.unwrap();

    let result = server.do_read_resource("scorchkit://projects").await;
    assert!(result.is_ok(), "reading projects should succeed");
    let read = result.unwrap();
    assert_eq!(read.contents.len(), 1, "should return one content block");

    // Cleanup
    let project = storage::projects::get_project_by_name(&pool, &name).await.unwrap().unwrap();
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify reading `scorchkit://projects/{id}` returns project details
/// with targets, scan_count, and finding_count fields.
#[tokio::test]
async fn test_resource_read_project() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("res-project");

    let project = storage::projects::create_project(&pool, &name, "resource test").await.unwrap();
    let uri = format!("scorchkit://projects/{}", project.id);

    let result = server.do_read_resource(&uri).await;
    assert!(result.is_ok(), "reading single project should succeed");
    let read = result.unwrap();
    let text = match &read.contents[0] {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("expected text resource content"),
    };
    let json: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(json["project"]["name"], name);
    assert!(json.get("scan_count").is_some());
    assert!(json.get("finding_count").is_some());

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify reading `scorchkit://projects/{id}/scans` returns scan history.
#[tokio::test]
async fn test_resource_read_scans() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("res-scans");

    let project = storage::projects::create_project(&pool, &name, "").await.unwrap();
    let now = chrono::Utc::now();
    storage::scans::save_scan(
        &pool,
        project.id,
        "https://example.com",
        "quick",
        now,
        Some(now),
        &[],
        &[],
        &serde_json::json!({}),
    )
    .await
    .unwrap();

    let uri = format!("scorchkit://projects/{}/scans", project.id);
    let result = server.do_read_resource(&uri).await;
    assert!(result.is_ok(), "reading project scans should succeed");
    let read = result.unwrap();
    let text = match &read.contents[0] {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("expected text resource content"),
    };
    let parsed: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
    assert_eq!(parsed.len(), 1, "should return one scan");

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify reading `scorchkit://projects/{id}/scans/{scan_id}` returns
/// a single scan record.
#[tokio::test]
async fn test_resource_read_scan() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("res-scan");

    let project = storage::projects::create_project(&pool, &name, "").await.unwrap();
    let now = chrono::Utc::now();
    let scan = storage::scans::save_scan(
        &pool,
        project.id,
        "https://example.com",
        "standard",
        now,
        Some(now),
        &["headers".to_string()],
        &[],
        &serde_json::json!({}),
    )
    .await
    .unwrap();

    let uri = format!("scorchkit://projects/{}/scans/{}", project.id, scan.id);
    let result = server.do_read_resource(&uri).await;
    assert!(result.is_ok(), "reading single scan should succeed");
    let read = result.unwrap();
    let text = match &read.contents[0] {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("expected text resource content"),
    };
    let json: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(json["profile"], "standard");

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify reading `scorchkit://projects/{id}/findings` returns tracked
/// findings for a project.
#[tokio::test]
async fn test_resource_read_findings() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("res-findings");

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
        vec![Finding::new("xss", Severity::High, "XSS Found", "desc", "https://example.com")];
    storage::findings::save_findings(&pool, project.id, scan.id, &findings_data).await.unwrap();

    let uri = format!("scorchkit://projects/{}/findings", project.id);
    let result = server.do_read_resource(&uri).await;
    assert!(result.is_ok(), "reading project findings should succeed");
    let read = result.unwrap();
    let text = match &read.contents[0] {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("expected text resource content"),
    };
    let parsed: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
    assert_eq!(parsed.len(), 1, "should return one finding");

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify reading `scorchkit://projects/{id}/findings/{finding_id}`
/// returns a single finding's details.
#[tokio::test]
async fn test_resource_read_finding() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("res-finding");

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

    let uri = format!("scorchkit://projects/{}/findings/{}", project.id, finding_id);
    let result = server.do_read_resource(&uri).await;
    assert!(result.is_ok(), "reading single finding should succeed");
    let read = result.unwrap();
    let text = match &read.contents[0] {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("expected text resource content"),
    };
    let json: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(json["title"], "Weak TLS");

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify reading an invalid URI returns an error.
#[tokio::test]
async fn test_resource_read_invalid_uri() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    let result = server.do_read_resource("http://example.com").await;
    assert!(result.is_err(), "invalid URI should return an error");
}

/// Verify reading a non-existent project returns a not-found error.
#[tokio::test]
async fn test_resource_read_not_found() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    let fake_id = uuid::Uuid::new_v4();
    let uri = format!("scorchkit://projects/{fake_id}");
    let result = server.do_read_resource(&uri).await;
    assert!(result.is_err(), "non-existent project should return an error");
}

/// Verify `get_info()` capabilities include resources.
#[tokio::test]
async fn test_server_capabilities_include_resources() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    use rmcp::handler::server::ServerHandler;
    let info = server.get_info();
    assert!(info.capabilities.resources.is_some(), "server capabilities should include resources");
}

/// Verify `get_info()` instructions contain the rich methodology guide,
/// not the old minimal placeholder string.
#[tokio::test]
async fn test_server_uses_rich_instructions() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    use rmcp::handler::server::ServerHandler;
    let info = server.get_info();
    let instructions = info.instructions.as_deref().unwrap_or("");
    assert!(
        instructions.contains("Engagement Workflow"),
        "instructions should contain the engagement workflow"
    );
    assert!(
        instructions.contains("project_create"),
        "instructions should reference project_create tool"
    );
    assert!(instructions.len() > 1000, "instructions should be substantial");
}

/// Verify `auto_scan` params deserialize with defaults.
#[test]
fn test_tool_auto_scan() {
    let json = r#"{"target": "https://example.com"}"#;
    let params: AutoScanParams = serde_json::from_str(json).expect("deserialize");
    assert_eq!(params.target, "https://example.com");
    assert_eq!(params.profile, "standard"); // default
    assert!(params.project.is_none());

    let json_with_project =
        r#"{"target": "example.com", "profile": "quick", "project": "test-proj"}"#;
    let params: AutoScanParams = serde_json::from_str(json_with_project).expect("deserialize");
    assert_eq!(params.profile, "quick");
    assert_eq!(params.project.as_deref(), Some("test-proj"));
}

/// Verify `target_intelligence` params deserialize.
#[test]
fn test_tool_target_intelligence() {
    let json = r#"{"target": "https://example.com"}"#;
    let params: TargetIntelligenceParams = serde_json::from_str(json).expect("deserialize");
    assert_eq!(params.target, "https://example.com");
}

/// Verify `scan_progress` params deserialize.
#[test]
fn test_tool_scan_progress() {
    let json = r#"{"project": "my-project"}"#;
    let params: ScanProgressParams = serde_json::from_str(json).expect("deserialize");
    assert_eq!(params.project, "my-project");
}

/// Verify `correlate_findings` params deserialize.
#[test]
fn test_tool_correlate_findings() {
    let json = r#"{"project": "my-project"}"#;
    let params: CorrelateFindingsParams = serde_json::from_str(json).expect("deserialize");
    assert_eq!(params.project, "my-project");
}

/// Verify MCP prompt list returns 5 templates.
#[test]
fn test_prompt_list() {
    let prompts = ScorchKitServer::do_list_prompts();
    assert_eq!(prompts.len(), 5);

    let names: Vec<&str> = prompts.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"full-web-assessment"));
    assert!(names.contains(&"investigate-finding"));
    assert!(names.contains(&"remediation-plan"));
    assert!(names.contains(&"compare-scans"));
    assert!(names.contains(&"executive-summary"));
}

/// Verify MCP prompt retrieval with arguments.
#[test]
fn test_prompt_get() {
    let mut args = std::collections::HashMap::new();
    args.insert("target".to_string(), "https://example.com".to_string());

    let result = ScorchKitServer::do_get_prompt("full-web-assessment", &args);
    assert!(result.is_ok());
    let prompt = result.unwrap();
    assert_eq!(prompt.messages.len(), 2);
}

// ═══════════════════════════════════════════════════════════════════════
// Schedule Scan Tests
// ═══════════════════════════════════════════════════════════════════════

/// Verify `do_schedule_scan` creates a recurring schedule and returns JSON
/// with `target_url`, `cron_expression`, and `enabled=true`.
#[tokio::test]
async fn test_tool_schedule_scan() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-sched");
    storage::projects::create_project(&pool, &name, "schedule test").await?;

    // Act
    let result = server
        .do_schedule_scan(ScheduleScanParams {
            project: name.clone(),
            target: "https://example.com".to_string(),
            cron: "0 0 * * *".to_string(),
            profile: "quick".to_string(),
        })
        .await;

    // Assert
    assert!(result.is_ok(), "schedule_scan should succeed: {result:?}");
    let body = result.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["target_url"], "https://example.com");
    assert_eq!(json["cron_expression"], "0 0 * * *");
    assert_eq!(json["enabled"], true);

    // Cleanup
    let project = storage::projects::get_project_by_name(&pool, &name)
        .await?
        .ok_or("project should exist for cleanup")?;
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

/// Verify `do_schedule_scan` returns an error when the project does not exist.
#[tokio::test]
async fn test_tool_schedule_scan_invalid_project() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let server = test_server(pool);
    let fake_name = unique_name("mcp-sched-noexist");

    // Act
    let result = server
        .do_schedule_scan(ScheduleScanParams {
            project: fake_name,
            target: "https://example.com".to_string(),
            cron: "0 0 * * *".to_string(),
            profile: "standard".to_string(),
        })
        .await;

    // Assert
    assert!(result.is_err(), "scheduling against a non-existent project should fail");
    Ok(())
}

/// Verify `do_schedule_scan` returns an error when given an invalid cron expression.
#[tokio::test]
async fn test_tool_schedule_scan_invalid_cron() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-sched-badcron");
    storage::projects::create_project(&pool, &name, "").await?;

    // Act
    let result = server
        .do_schedule_scan(ScheduleScanParams {
            project: name.clone(),
            target: "https://example.com".to_string(),
            cron: "not-a-cron".to_string(),
            profile: "standard".to_string(),
        })
        .await;

    // Assert
    assert!(result.is_err(), "invalid cron expression should produce an error");

    // Cleanup
    let project = storage::projects::get_project_by_name(&pool, &name)
        .await?
        .ok_or("project should exist for cleanup")?;
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

/// Verify `do_schedule_scan` defaults to the "standard" profile when none is
/// explicitly provided in the JSON input.
#[tokio::test]
async fn test_tool_schedule_scan_default_profile() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-sched-defprof");
    storage::projects::create_project(&pool, &name, "").await?;

    // Act — deserialize without explicit profile to trigger the serde default
    let params: ScheduleScanParams = serde_json::from_value(serde_json::json!({
        "project": name,
        "target": "https://example.com",
        "cron": "0 0 * * *"
    }))?;
    let result = server.do_schedule_scan(params).await;

    // Assert
    assert!(result.is_ok(), "schedule_scan with default profile should succeed: {result:?}");
    let body = result.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["profile"], "standard", "default profile should be 'standard'");

    // Cleanup
    let project = storage::projects::get_project_by_name(&pool, &name)
        .await?
        .ok_or("project should exist for cleanup")?;
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Run Due Scans Tests
// ═══════════════════════════════════════════════════════════════════════

/// Verify `do_run_due_scans` returns executed=0 when no schedules exist.
#[tokio::test]
async fn test_tool_run_due_scans_none_due() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange — no schedules created
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let server = test_server(pool);

    // Act
    let result = server.do_run_due_scans().await;

    // Assert
    assert!(result.is_ok(), "run_due_scans should succeed even with nothing due: {result:?}");
    let body = result.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["executed"], 0);
    Ok(())
}

/// Verify `do_run_due_scans` picks up a schedule whose `next_run` is in the
/// past and reports a non-zero executed count.
#[tokio::test]
async fn test_tool_run_due_scans_with_schedule() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-due-run");
    let project = storage::projects::create_project(&pool, &name, "").await?;

    // Create a schedule, then backdate next_run so it appears due
    let schedule = storage::schedules::create_schedule(
        &pool,
        project.id,
        "http://192.0.2.1",
        "quick",
        "0 0 * * *",
    )
    .await?;
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    sqlx::query("UPDATE scan_schedules SET next_run = $1 WHERE id = $2")
        .bind(past)
        .bind(schedule.id)
        .execute(&pool)
        .await?;

    // Act
    let result = server.do_run_due_scans().await;

    // Assert
    assert!(result.is_ok(), "run_due_scans should succeed: {result:?}");
    let body = result.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    let executed = json["executed"].as_u64().ok_or("executed field should be a number")?;
    assert!(executed > 0, "should have executed at least one schedule");

    // Cleanup
    storage::schedules::delete_schedule(&pool, schedule.id).await?;
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

/// Verify `do_run_due_scans` skips disabled schedules even if their `next_run`
/// is in the past.
#[tokio::test]
async fn test_tool_run_due_scans_disabled_skipped() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-due-disabled");
    let project = storage::projects::create_project(&pool, &name, "").await?;

    let schedule = storage::schedules::create_schedule(
        &pool,
        project.id,
        "http://192.0.2.1",
        "quick",
        "0 0 * * *",
    )
    .await?;

    // Disable the schedule and backdate it
    storage::schedules::update_schedule_enabled(&pool, schedule.id, false).await?;
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    sqlx::query("UPDATE scan_schedules SET next_run = $1 WHERE id = $2")
        .bind(past)
        .bind(schedule.id)
        .execute(&pool)
        .await?;

    // Act
    let result = server.do_run_due_scans().await;

    // Assert
    assert!(result.is_ok(), "run_due_scans should succeed: {result:?}");
    let body = result.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["executed"], 0, "disabled schedule should not be executed");

    // Cleanup
    storage::schedules::delete_schedule(&pool, schedule.id).await?;
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

/// Verify that after `do_run_due_scans` executes a due schedule, the
/// schedule's `next_run` is recalculated to a future timestamp.
#[tokio::test]
async fn test_tool_run_due_scans_next_run_updated() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-due-nextrun");
    let project = storage::projects::create_project(&pool, &name, "").await?;

    let schedule = storage::schedules::create_schedule(
        &pool,
        project.id,
        "http://192.0.2.1",
        "quick",
        "0 0 * * *",
    )
    .await?;

    // Backdate next_run so the schedule is due
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    sqlx::query("UPDATE scan_schedules SET next_run = $1 WHERE id = $2")
        .bind(past)
        .bind(schedule.id)
        .execute(&pool)
        .await?;

    // Act
    let result = server.do_run_due_scans().await;
    assert!(result.is_ok(), "run_due_scans should succeed: {result:?}");

    // Assert — next_run should now be in the future
    let updated = storage::schedules::get_schedule(&pool, schedule.id)
        .await?
        .ok_or("schedule should still exist after execution")?;
    assert!(
        updated.next_run > chrono::Utc::now(),
        "next_run ({}) should be recalculated to a future time",
        updated.next_run
    );

    // Cleanup
    storage::schedules::delete_schedule(&pool, schedule.id).await?;
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Project Status Tests
// ═══════════════════════════════════════════════════════════════════════

/// Verify `do_project_status` returns JSON with posture metrics for a
/// project that has scan history and tracked findings.
#[tokio::test]
async fn test_tool_project_status() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-status");
    let project = storage::projects::create_project(&pool, &name, "status test").await?;
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
    .await?;
    let findings_data =
        vec![Finding::new("xss", Severity::High, "XSS Found", "desc", "https://example.com")];
    storage::findings::save_findings(&pool, project.id, scan.id, &findings_data).await?;

    // Act
    let result = server.do_project_status(ProjectStatusParams { project: name.clone() }).await;

    // Assert
    assert!(result.is_ok(), "project_status should succeed: {result:?}");
    let body = result.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["project_name"], name);
    assert!(json.get("scan_summary").is_some(), "should contain scan_summary");
    assert!(json.get("finding_summary").is_some(), "should contain finding_summary");
    assert!(json.get("severity_breakdown").is_some(), "should contain severity_breakdown");
    assert!(json.get("trend").is_some(), "should contain trend direction");
    let total = json["finding_summary"]["total_findings"]
        .as_u64()
        .ok_or("total_findings should be a number")?;
    assert!(total > 0, "should have at least one finding");

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

/// Verify `do_project_status` returns valid but empty metrics for a
/// project that has no scans or findings.
#[tokio::test]
async fn test_tool_project_status_empty() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-status-empty");
    let project = storage::projects::create_project(&pool, &name, "empty project").await?;

    // Act
    let result = server.do_project_status(ProjectStatusParams { project: name.clone() }).await;

    // Assert
    assert!(result.is_ok(), "project_status on empty project should succeed: {result:?}");
    let body = result.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["project_name"], name);
    assert_eq!(json["scan_summary"]["total_scans"], 0);
    assert_eq!(json["finding_summary"]["total_findings"], 0);
    assert_eq!(json["finding_summary"]["active_findings"], 0);
    assert_eq!(json["trend"], "stable", "empty project should have stable trend");

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Plan Scan Tests
// ═══════════════════════════════════════════════════════════════════════

/// Verify `PlanScanParams` serialization round-trips correctly with
/// the expected target field.
#[test]
fn test_tool_plan_scan_params() {
    // Arrange
    let json = r#"{"target": "https://example.com"}"#;

    // Act
    let params: PlanScanParams = serde_json::from_str(json).expect("deserialize PlanScanParams");

    // Assert
    assert_eq!(params.target, "https://example.com");
}

/// Verify `do_plan_scan` returns an error when AI is disabled in config,
/// rather than panicking or producing an empty plan.
#[tokio::test]
async fn test_tool_plan_scan_no_ai() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange — create server with AI explicitly disabled
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let mut config = AppConfig::default();
    config.ai.enabled = false;
    let server = ScorchKitServer::new(Arc::new(config), pool);

    // Act
    let result =
        server.do_plan_scan(PlanScanParams { target: "https://example.com".to_string() }).await;

    // Assert — should fail gracefully, not panic
    assert!(result.is_err(), "plan_scan with AI disabled should return an error");
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("AI is disabled") || err_msg.contains("claude"),
        "error should mention AI is disabled: {err_msg}"
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Analyze Findings Tests
// ═══════════════════════════════════════════════════════════════════════

/// Verify `AnalyzeFindingsParams` serialization with all fields including
/// the optional `scan_id` and default `focus`.
#[test]
fn test_tool_analyze_findings_params() {
    // Arrange
    let json_minimal = r#"{"project": "my-project"}"#;
    let json_full = r#"{"project": "my-project", "focus": "prioritize", "scan_id": "abc-123"}"#;

    // Act
    let params_min: AnalyzeFindingsParams =
        serde_json::from_str(json_minimal).expect("deserialize minimal AnalyzeFindingsParams");
    let params_full: AnalyzeFindingsParams =
        serde_json::from_str(json_full).expect("deserialize full AnalyzeFindingsParams");

    // Assert
    assert_eq!(params_min.project, "my-project");
    assert_eq!(params_min.focus, "summary", "default focus should be 'summary'");
    assert!(params_min.scan_id.is_none());
    assert_eq!(params_full.focus, "prioritize");
    assert_eq!(params_full.scan_id.as_deref(), Some("abc-123"));
}

/// Verify `do_analyze_findings` returns an appropriate response when the
/// project has no findings to analyze, rather than invoking AI needlessly.
#[tokio::test]
async fn test_tool_analyze_findings_no_findings() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-analyze-empty");
    let project = storage::projects::create_project(&pool, &name, "empty for analysis").await?;

    // Act
    let result = server
        .do_analyze_findings(AnalyzeFindingsParams {
            project: name.clone(),
            focus: "summary".to_string(),
            scan_id: None,
        })
        .await;

    // Assert — should return a valid response indicating no findings
    assert!(result.is_ok(), "analyze_findings with no findings should succeed: {result:?}");
    let body = result.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    let content = json["analysis"]["content"].as_str().unwrap_or("");
    assert!(content.contains("No findings"), "should indicate no findings to analyze: {body}");

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}
