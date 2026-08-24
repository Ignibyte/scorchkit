//! Integration tests for MCP server tools.
//!
//! Each test verifies one MCP tool by calling its `do_*` public method
//! on a `ScorchKitServer` instance. Tests that require database access
//! use the `DATABASE_URL` let-else early-return pattern for graceful skip.

#![cfg(feature = "mcp")]

use std::path::Path;
use std::sync::Arc;

use httpmock::MockServer;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{CallToolRequestParams, Implementation, ResourceContents};
use rmcp::ServiceExt;
use scorchkit::config::AppConfig;
use scorchkit::engine::evidence::HttpEvidence;
use scorchkit::engine::finding::Finding;
use scorchkit::engine::observation::{
    CodeFlow, CodeFlowStep, CorrelationKey, ObservationLocation, ScannerProvenance, SourceRegion,
    ThreadFlow,
};
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::scan_result::ScanResult;
use scorchkit::engine::scope::ScopeRule;
use scorchkit::engine::severity::Severity;
use scorchkit::engine::target::Target;
use scorchkit::mcp::contract::{tool_contract, MCP_OUTPUT_SCHEMA_VERSION};
use scorchkit::mcp::server::ScorchKitServer;
use scorchkit::mcp::types::*;
use scorchkit::storage;
use uuid::Uuid;

/// Helper to get a database pool or skip the test.
async fn get_pool_or_skip() -> Option<sqlx::PgPool> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set — skipping MCP integration test");
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

/// Generate a unique project name.
fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

fn application_persona_scenario() -> ApplicationPentestScenarioParams {
    ApplicationPentestScenarioParams {
        name: "anonymous access invariant".to_string(),
        proposal_kind: "agent".to_string(),
        proposal_label: "codex".to_string(),
        scenario_class: "authorization_invariant".to_string(),
        payload_class: "persona_comparison".to_string(),
        method: "GET".to_string(),
        route: "/".to_string(),
        parameter_name: None,
        parameter_location: None,
        personas: vec![ApplicationPentestPersonaParams {
            persona: "anonymous".to_string(),
            expected: "allow".to_string(),
        }],
        max_seconds: 5,
        max_concurrency: 1,
        cleanup: "not_required".to_string(),
        preconditions: vec!["loopback fixture is reachable".to_string()],
        evidence_requirements: vec!["status_code".to_string()],
        source_finding_identities: vec!["a".repeat(64)],
        source_path_identities: Vec::new(),
    }
}

fn test_engagement() -> Engagement {
    let code_root = match std::env::current_dir() {
        Ok(path) => path,
        Err(error) => panic!("failed to resolve test working directory: {error}"),
    };
    let code_scope = match ScopeRule::path_prefix(&code_root) {
        Ok(scope) => scope,
        Err(error) => panic!("failed to build code scope: {error}"),
    };
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::Cidr {
            network: u32::from(std::net::Ipv4Addr::new(127, 0, 0, 0)),
            mask: u32::MAX << 24,
        })
        .allow_scope(ScopeRule::CidrV6 { network: 1, mask: u128::MAX })
        .allow_scope(ScopeRule::Exact("localhost".to_string()))
        .allow_scope(ScopeRule::Exact("example.com".to_string()))
        .allow_scope(code_scope)
        .allow_capability(Capability::DastScan)
        .allow_capability(Capability::CodeScan)
        .allow_capability(Capability::ExternalTool)
        .allow_capability(Capability::LocalState)
        .allow_effect(EffectClass::Passive)
        .allow_effect(EffectClass::ActiveSafe)
        .allow_effect(EffectClass::Intrusive);
    let mut engagement = Engagement::new("mcp-loopback-tests", policy);
    engagement.id = uuid::Uuid::from_u128(0x5343_4f52_4348_4b49_5454_4553_5453);
    engagement
}

/// Create a test server.
fn test_server(pool: sqlx::PgPool) -> ScorchKitServer {
    let mut config = AppConfig::default();
    config.scan.timeout_seconds = 5;
    config.engagement = Some(test_engagement());
    ScorchKitServer::new(Arc::new(config), pool)
}

/// Build a server for methods that do not touch storage.
fn test_server_without_database() -> ScorchKitServer {
    let mut config = AppConfig::default();
    config.scan.timeout_seconds = 5;
    config.engagement = Some(test_engagement());
    ScorchKitServer::new_stateless(Arc::new(config))
}

fn supply_chain_test_server(
    cache_root: &std::path::Path,
) -> scorchkit::engine::error::Result<ScorchKitServer> {
    let code_root = std::env::current_dir()?;
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::path_prefix(&code_root)?)
        .allow_scope(ScopeRule::path_prefix(cache_root)?)
        .allow_capability(Capability::CodeScan)
        .allow_capability(Capability::LocalState)
        .allow_effect(EffectClass::Passive);
    let config = AppConfig {
        engagement: Some(Engagement::new("mcp-supply-chain-tests", policy)),
        supply_chain: scorchkit::config::SupplyChainConfig {
            cache_root: cache_root.to_path_buf(),
            ..Default::default()
        },
        ..Default::default()
    };
    Ok(ScorchKitServer::new_stateless(Arc::new(config)))
}

/// Build a server with no engagement to prove effectful tools fail closed.
fn unconfigured_test_server() -> ScorchKitServer {
    ScorchKitServer::new_stateless(Arc::new(AppConfig::default()))
}

fn workflow_context_params() -> ApplicationContextParams {
    let code_root = std::env::current_dir()
        .unwrap_or_else(|error| panic!("failed to resolve workflow test root: {error}"));
    ApplicationContextParams {
        path: code_root.to_string_lossy().into_owned(),
        project: None,
        change_set: Some(ApplicationChangeSetParams {
            base_revision: "a".repeat(40),
            head_revision: "b".repeat(40),
            changed_paths: vec!["src/lib.rs".to_string(), "Cargo.toml".to_string()],
        }),
        routes: vec!["/api/items".to_string()],
        artifacts: vec!["Cargo.toml".to_string()],
    }
}

fn workflow_test_server() -> ScorchKitServer {
    let mut config = AppConfig { engagement: Some(test_engagement()), ..AppConfig::default() };
    config.dast.personas.insert(
        "member".to_string(),
        scorchkit::config::DastPersonaConfig::Header {
            header_name: "Authorization".to_string(),
            value_env: "WORKFLOW_FIXTURE_SECRET_ENV".to_string(),
            verification: scorchkit::config::DastVerificationConfig::default(),
        },
    );
    ScorchKitServer::new_stateless(Arc::new(config))
}

#[tokio::test]
async fn application_context_and_workflow_are_read_only_stable_and_scope_honest() {
    let server = workflow_test_server();
    let expected_code_root = std::env::current_dir()
        .and_then(|path| path.canonicalize())
        .unwrap_or_else(|error| panic!("failed to canonicalize workflow test root: {error}"));
    let context_json = server
        .do_application_context(workflow_context_params())
        .await
        .expect("application context");
    let context: scorchkit::ApplicationSecurityContext =
        serde_json::from_str(&context_json).expect("decode application context");
    assert_eq!(Path::new(&context.code_root), expected_code_root);
    assert!(context.languages.contains(&"rust".to_string()));
    assert!(context.manifests.contains(&"Cargo.toml".to_string()));
    assert_eq!(context.change_set.as_ref().expect("change set").changed_paths.len(), 2);
    assert!(context.registered_targets.is_empty());
    assert_eq!(context.persona_labels, ["member"]);
    assert!(context.configured_capabilities.contains(&Capability::CodeScan));
    assert!(!context_json.contains("password"));
    assert!(!context_json.contains("WORKFLOW_FIXTURE_SECRET_ENV"));

    let commit_json = server
        .do_plan_appsec_workflow(ApplicationSecurityWorkflowParams {
            profile: "commit".to_string(),
            context: workflow_context_params(),
            focused_selection: None,
        })
        .await
        .expect("commit workflow");
    let commit: scorchkit::ApplicationSecurityWorkflowPlan =
        serde_json::from_str(&commit_json).expect("decode commit workflow");
    assert_eq!(commit.steps.len(), 1);
    assert_eq!(commit.steps[0].operation, "security_change_review");
    assert!(!commit.steps[0].broad);
    assert!(!commit.steps[0].requires_execution_authorization);

    let staging_json = server
        .do_plan_appsec_workflow(ApplicationSecurityWorkflowParams {
            profile: "staging".to_string(),
            context: workflow_context_params(),
            focused_selection: None,
        })
        .await
        .expect("staging workflow");
    let staging: scorchkit::ApplicationSecurityWorkflowPlan =
        serde_json::from_str(&staging_json).expect("decode staging workflow");
    assert!(staging.steps[1].broad);
    assert_eq!(staging.steps[2].status, scorchkit::ApplicationSecurityWorkflowStepStatus::Blocked);
    assert!(staging.gaps.iter().any(|gap| {
        gap.kind == scorchkit::ApplicationSecurityWorkflowGapKind::MissingRegisteredTarget
    }));
    assert_eq!(
        tool_contract("application_context").expect("context contract").tool_class,
        scorchkit::mcp::contract::McpToolClass::Read
    );
    assert_eq!(
        tool_contract("plan_appsec_workflow").expect("workflow contract").tool_class,
        scorchkit::mcp::contract::McpToolClass::Read
    );
}

#[tokio::test]
async fn application_context_redacts_registered_target_query_values_and_labels() {
    let Some(pool) = get_pool_or_skip().await else {
        return;
    };
    let server = test_server(pool.clone());
    let project = unique_name("mcp-appsec-context");
    let stored =
        storage::projects::create_project(&pool, &project, "application workflow context fixture")
            .await
            .expect("create context project");
    storage::projects::add_target(
        &pool,
        stored.id,
        "https://example.com/app?token=registered-target-fixture-secret",
        "api_key=registered-label-fixture-secret",
    )
    .await
    .expect("seed legacy context target");
    let mut params = workflow_context_params();
    params.project = Some(project);
    let context_json = server.do_application_context(params).await.expect("project context");
    let context: scorchkit::ApplicationSecurityContext =
        serde_json::from_str(&context_json).expect("decode project context");
    assert_eq!(context.registered_targets.len(), 1);
    assert_eq!(context.registered_targets[0].url, "https://example.com/app?token=");
    assert!(context.registered_targets[0].label.is_some());
    assert!(!context_json.contains("registered-target-fixture-secret"));
    assert!(!context_json.contains("registered-label-fixture-secret"));
    storage::projects::delete_project(&pool, stored.id).await.expect("delete context project");
}

#[tokio::test]
async fn application_context_denies_discovery_without_an_engagement() {
    let error = unconfigured_test_server()
        .do_application_context(workflow_context_params())
        .await
        .expect_err("missing engagement must deny context discovery");
    assert!(error.contains("no engagement authorization is configured"));
}

#[tokio::test]
async fn supply_chain_mcp_status_and_target_kind_contracts_are_typed(
) -> Result<(), Box<dyn std::error::Error>> {
    let cache = tempfile::tempdir().expect("private cache root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(cache.path(), std::fs::Permissions::from_mode(0o700))
            .expect("owner-only cache root");
    }
    let server = supply_chain_test_server(cache.path())?;

    let status_json = server.do_supply_chain_cache_status().expect("cache status");
    let statuses: Vec<scorchkit::ProviderSnapshot> =
        serde_json::from_str(&status_json).expect("decode cache status");
    assert_eq!(statuses.len(), 3);
    assert!(statuses
        .iter()
        .all(|snapshot| snapshot.state == scorchkit::ProviderSnapshotState::Missing));

    let error = server
        .do_supply_chain_scan(SupplyChainScanParams {
            path: cache.path().display().to_string(),
            kind: "registry_image".to_string(),
            profile: "standard".to_string(),
            revision: None,
        })
        .await
        .expect_err("remote-like target kind must be rejected");
    assert!(error.contains("unknown supply-chain target kind"));
    Ok(())
}

/// Start a loopback server that accepts every bounded scan request.
async fn local_scan_target() -> MockServer {
    let server = MockServer::start_async().await;
    {
        let _mock = server
            .mock_async(|when, then| {
                when.any_request();
                then.status(200)
                    .header("content-type", "text/html; charset=utf-8")
                    .body("<html><head><title>ScorchKit test</title></head><body>ok</body></html>");
            })
            .await;
    }
    server
}

/// Serialize tests whose contract is defined over the database-wide due set.
async fn due_scan_test_guard(
    pool: &sqlx::PgPool,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, sqlx::Error> {
    const TEST_LOCK: i64 = 0x5343_4F52_5445_5354;
    let mut guard = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(TEST_LOCK).execute(&mut *guard).await?;
    sqlx::query("DELETE FROM projects WHERE name LIKE 'mcp-due-%'").execute(pool).await?;
    Ok(guard)
}

/// Return text from a resource result or fail with its actual content kind.
fn resource_text(result: &rmcp::model::ReadResourceResult) -> &str {
    let Some(content) = result.contents.first() else {
        panic!("resource result was empty");
    };
    match content {
        ResourceContents::TextResourceContents { text, .. } => text,
        ResourceContents::BlobResourceContents { .. } => {
            panic!("expected text resource content, received a blob")
        }
    }
}

fn tool_text(result: &rmcp::model::CallToolResult) -> &str {
    result.content.first().and_then(|content| content.raw.as_text()).map_or_else(
        || panic!("expected MCP text tool content: {result:?}"),
        |text| text.text.as_str(),
    )
}

fn tool_structured(result: &rmcp::model::CallToolResult) -> &serde_json::Value {
    result
        .structured_content
        .as_ref()
        .unwrap_or_else(|| panic!("expected MCP structured tool content: {result:?}"))
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

#[test]
fn serve_fails_closed_when_explicit_database_url_is_invalid() {
    use assert_cmd::Command;
    use predicates::prelude::*;

    let directory = tempfile::tempdir().expect("create serve config directory");
    let config_path = directory.path().join("scorchkit.toml");
    let mut config = AppConfig::default();
    config.database.url = Some("not-a-postgresql-url".to_string());
    std::fs::write(
        &config_path,
        toml::to_string_pretty(&config).expect("serialize invalid database config"),
    )
    .expect("write serve config");

    Command::cargo_bin("scorchkit")
        .expect("resolve scorchkit binary")
        .args(["--config", config_path.to_str().expect("UTF-8 config path"), "serve"])
        .env_remove("DATABASE_URL")
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .failure()
        .stderr(predicate::str::contains("connection failed"));
}

/// Verify `ScorchKitServer::new()` constructs successfully.
#[tokio::test]
async fn test_server_creation() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    let info = server.get_info();
    assert_eq!(info.server_info.name, "scorchkit");
}

/// Verify `list_modules` returns a JSON array of modules.
#[tokio::test]
async fn test_tool_list_modules() {
    let server = test_server_without_database();
    let result = server.do_list_modules().await.expect("list modules");
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.len(), 67);
    assert!(parsed
        .iter()
        .all(|module| module["adapter"]["schemaVersion"] == scorchkit_core::ADAPTER_CONTRACT_V1));
    assert!(!parsed.iter().any(|module| module["id"] == "nmap"));
    assert!(!parsed.iter().any(|module| module["id"] == "metasploit"));
}

#[tokio::test]
async fn test_tool_list_code_modules_uses_application_catalog() {
    let server = test_server_without_database();
    let result = server.do_list_code_modules();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.len(), 21);
    assert!(parsed
        .iter()
        .all(|module| module["adapter"]["schemaVersion"] == scorchkit_core::ADAPTER_CONTRACT_V1));
    assert!(!parsed.iter().any(|module| module["id"] == "scoutsuite"));
    assert_eq!(
        parsed.iter().find(|module| module["id"] == "semgrep").map(|module| &module["depth"]),
        Some(&serde_json::json!("fast"))
    );
    assert_eq!(
        parsed.iter().find(|module| module["id"] == "codeql").map(|module| &module["depth"]),
        Some(&serde_json::json!("deep"))
    );
    assert_eq!(
        parsed.iter().find(|module| module["id"] == "psalm").map(|module| &module["depth"]),
        Some(&serde_json::json!("deep"))
    );
}

/// Verify `check_tools` returns a JSON array of tool status.
#[tokio::test]
async fn test_tool_check_tools() {
    let server = test_server_without_database();
    let result = server.do_check_tools();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.len(), 21, "tool inventory is an MCP contract");
    assert!(parsed.iter().all(|tool| tool["tool"].is_string()));
    assert!(parsed.iter().all(|tool| tool["installed"].is_boolean()));
    assert_eq!(parsed.first().and_then(|tool| tool["tool"].as_str()), Some("nmap"));
    assert_eq!(parsed.last().and_then(|tool| tool["tool"].as_str()), Some("msfconsole"));
}

/// Verify `scan` completes against a deterministic loopback target.
#[tokio::test]
async fn test_tool_scan() {
    let target = local_scan_target().await;
    let server = test_server_without_database();
    let params = ScanParams {
        target: target.url("/"),
        profile: "quick".to_string(),
        modules: Some("headers".to_string()),
        skip: None,
    };
    let result = server.do_scan(params).await;
    assert!(result.is_ok(), "loopback scan should succeed: {result:?}");
    let scan: scorchkit::engine::scan_result::ScanResult =
        serde_json::from_str(&result.expect("scan result JSON")).expect("decode complete scan");
    assert_eq!(scan.target.url.as_str(), target.url("/"));
    assert_eq!(scan.modules_run, ["headers"]);
}

#[tokio::test]
async fn stateless_scan_job_start_status_and_cancel_need_no_database() {
    let target = MockServer::start_async().await;
    let _mock = target
        .mock_async(|when, then| {
            when.any_request();
            then.delay(std::time::Duration::from_secs(5)).status(200).body("slow");
        })
        .await;
    let server = test_server_without_database();
    let started_json = server
        .do_scan_job_start(ScanParams {
            target: target.url("/"),
            profile: "quick".to_string(),
            modules: Some("headers".to_string()),
            skip: None,
        })
        .await
        .expect("start stateless scan job");
    let started: scorchkit::runner::job::ScanJob =
        serde_json::from_str(&started_json).expect("decode started job");

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let status_json = server
                .do_scan_job_status(ScanJobRefParams { job_id: started.id.to_string() })
                .await
                .expect("read stateless job");
            let status: scorchkit::runner::job::ScanJob =
                serde_json::from_str(&status_json).expect("decode status job");
            if status.state == scorchkit::runner::job::ScanJobState::Running {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("job reached running state");

    let cancelled_json = server
        .do_scan_job_cancel(ScanJobRefParams { job_id: started.id.to_string() })
        .await
        .expect("cancel stateless job");
    let cancelling: scorchkit::runner::job::ScanJob =
        serde_json::from_str(&cancelled_json).expect("decode cancelling job");
    assert_eq!(cancelling.state, scorchkit::runner::job::ScanJobState::Cancelling);

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let status_json = server
                .do_scan_job_status(ScanJobRefParams { job_id: started.id.to_string() })
                .await
                .expect("read cancelled stateless job");
            let status: scorchkit::runner::job::ScanJob =
                serde_json::from_str(&status_json).expect("decode cancelled job");
            if status.state == scorchkit::runner::job::ScanJobState::Cancelled {
                assert!(status.result.is_none());
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("job reached cancelled state");

    let database_error = server.do_project_list().await.expect_err("database tool must fail");
    assert!(database_error.contains("database unavailable"));
}

#[tokio::test]
async fn stateless_job_runs_through_mcp_transport_without_database() {
    let target = local_scan_target().await;
    let server = test_server_without_database();
    let (server_transport, client_transport) = tokio::io::duplex(1_048_576);
    let server_task = tokio::spawn(async move {
        let running =
            Box::pin(server.serve(server_transport)).await.map_err(|error| error.to_string())?;
        running.waiting().await.map_err(|error| error.to_string())
    });
    let client = ().serve(client_transport).await.expect("initialize MCP client");
    let tools = client.list_all_tools().await.expect("list MCP tools");
    assert_eq!(tools.len(), 39, "every routed MCP tool has a canonical contract");
    let expected_output_schema: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mcp/tool-output-schema-v1.json"))
            .expect("decode output schema fixture");
    for tool in &tools {
        let contract = tool_contract(&tool.name).expect("advertised tool contract");
        let annotations = tool.annotations.as_ref().expect("complete tool annotations");
        assert_eq!(
            annotations.read_only_hint,
            Some(contract.tool_class == scorchkit::mcp::contract::McpToolClass::Read)
        );
        assert_eq!(annotations.destructive_hint, Some(contract.destructive));
        assert_eq!(annotations.idempotent_hint, Some(contract.idempotent));
        assert_eq!(annotations.open_world_hint, Some(contract.open_world));
        assert_eq!(
            serde_json::to_value(tool.output_schema.as_ref().expect("tool output schema"))
                .expect("serialize advertised output schema"),
            expected_output_schema
        );
        assert_eq!(
            tool.meta
                .as_ref()
                .and_then(|meta| meta.0.get("scorchkit"))
                .and_then(|value| value.get("outputSchemaVersion")),
            Some(&serde_json::json!(MCP_OUTPUT_SCHEMA_VERSION))
        );
    }
    assert!(tools.iter().any(|tool| tool.name == "scan_job_start"));
    assert!(tools.iter().any(|tool| tool.name == "scan_job_status"));
    let project_scan = tools
        .iter()
        .find(|tool| tool.name == "project_scan")
        .expect("project_scan tool is advertised");
    let properties = project_scan
        .input_schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .expect("project_scan input properties");
    assert!(properties.contains_key("modules"));
    assert!(properties.contains_key("skip"));

    let arguments = serde_json::json!({
        "target": target.url("/"),
        "profile": "quick",
        "modules": "headers"
    })
    .as_object()
    .expect("tool arguments object")
    .clone();
    let started_result = client
        .call_tool(CallToolRequestParams::new("scan_job_start").with_arguments(arguments))
        .await
        .expect("start job through MCP transport");
    assert_ne!(started_result.is_error, Some(true));
    let started_structured = tool_structured(&started_result);
    assert_eq!(started_structured["schemaVersion"], MCP_OUTPUT_SCHEMA_VERSION);
    assert_eq!(started_structured["tool"], "scan_job_start");
    assert_eq!(started_structured["toolClass"], "external_effect");
    assert_eq!(started_structured["outcome"], "success");
    assert_eq!(started_structured["principal"]["kind"], "local_process");
    assert_eq!(started_structured["principal"]["clientAttribution"]["trusted"], false);
    let started: scorchkit::runner::job::ScanJob =
        serde_json::from_str(tool_text(&started_result)).expect("decode transport job");
    assert_eq!(started_structured["result"]["id"], started.id.to_string());

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let arguments = serde_json::json!({"job_id": started.id.to_string()})
                .as_object()
                .expect("status arguments object")
                .clone();
            let status_result = client
                .call_tool(CallToolRequestParams::new("scan_job_status").with_arguments(arguments))
                .await
                .expect("read job through MCP transport");
            let status: scorchkit::runner::job::ScanJob =
                serde_json::from_str(tool_text(&status_result)).expect("decode transport status");
            if status.state == scorchkit::runner::job::ScanJobState::Succeeded {
                assert!(status.result.is_some());
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("transport job completed");

    client.cancel().await.expect("close MCP client");
    server_task.await.expect("server task joined").expect("server transport closed cleanly");
}

#[tokio::test]
async fn spoofed_client_attribution_cannot_authorize_an_effect() {
    let server = unconfigured_test_server();
    let (server_transport, client_transport) = tokio::io::duplex(1_048_576);
    let server_task = tokio::spawn(async move {
        let running =
            Box::pin(server.serve(server_transport)).await.map_err(|error| error.to_string())?;
        running.waiting().await.map_err(|error| error.to_string())
    });
    let client_info = rmcp::model::ClientInfo::new(
        rmcp::model::ClientCapabilities::default(),
        Implementation::new("local-administrator", "999.0"),
    );
    let client = client_info.serve(client_transport).await.expect("initialize spoofed MCP client");
    let arguments = serde_json::json!({
        "target": "http://127.0.0.1:9",
        "profile": "quick",
        "modules": "headers"
    })
    .as_object()
    .expect("scan arguments object")
    .clone();
    let result = client
        .call_tool(CallToolRequestParams::new("scan").with_arguments(arguments))
        .await
        .expect("routed authorization denial");
    assert_eq!(result.is_error, Some(true));
    assert!(tool_text(&result).contains("no engagement authorization"));
    let structured = tool_structured(&result);
    assert_eq!(structured["schemaVersion"], MCP_OUTPUT_SCHEMA_VERSION);
    assert_eq!(structured["tool"], "scan");
    assert_eq!(structured["toolClass"], "external_effect");
    assert_eq!(structured["outcome"], "error");
    assert_eq!(structured["result"], serde_json::Value::Null);
    assert_eq!(structured["error"]["code"], "tool_execution_failed");
    assert!(structured["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("no engagement authorization")));
    assert_eq!(structured["principal"]["kind"], "local_process");
    assert_eq!(structured["principal"]["subject"], "local-mcp-process");
    assert_eq!(
        structured["principal"]["clientAttribution"],
        serde_json::json!({"name": "local-administrator", "version": "999.0", "trusted": false})
    );

    client.cancel().await.expect("close spoofed MCP client");
    server_task.await.expect("server task joined").expect("server transport closed cleanly");
}

#[tokio::test]
async fn test_tool_scan_denies_without_engagement() {
    let server = unconfigured_test_server();
    let result = server
        .do_scan(ScanParams {
            target: "http://127.0.0.1:9".to_string(),
            profile: "quick".to_string(),
            modules: Some("headers".to_string()),
            skip: None,
        })
        .await;
    assert!(
        result.is_err_and(|error| error.contains("no engagement authorization")),
        "MCP scan must fail closed before attempting loopback I/O"
    );
}

#[tokio::test]
async fn composite_effect_tools_deny_without_engagement() {
    let server = unconfigured_test_server();

    let auto_scan = server
        .do_auto_scan(AutoScanParams {
            target: "http://127.0.0.1:9".to_string(),
            profile: "quick".to_string(),
            project: None,
        })
        .await;
    assert!(
        auto_scan.is_err_and(|error| error.contains("no engagement authorization")),
        "MCP auto-scan must fail closed before attempting loopback I/O"
    );

    let intelligence = server
        .do_target_intelligence(TargetIntelligenceParams {
            target: "http://127.0.0.1:9".to_string(),
        })
        .await;
    assert!(
        intelligence.is_err_and(|error| error.contains("no engagement authorization")),
        "MCP target intelligence must fail closed before attempting loopback I/O"
    );

    let code_path = std::env::current_dir()
        .unwrap_or_else(|error| panic!("failed to resolve test working directory: {error}"));
    let code_scan = server
        .do_scan_code(CodeScanParams {
            path: code_path.display().to_string(),
            language: Some("rust".to_string()),
            profile: "standard".to_string(),
            modules: None,
            skip: None,
        })
        .await;
    assert!(
        code_scan.is_err_and(|error| error.contains("no engagement authorization")),
        "MCP code scan must fail closed before traversing the source tree"
    );
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
    let name = format!("{}-quoted-\"name", unique_name("mcp-delete"));

    storage::projects::create_project(&pool, &name, "").await.unwrap();

    // Without force — warning
    let result =
        server.do_project_delete(ProjectDeleteParams { project: name.clone(), force: false }).await;
    let warning: serde_json::Value =
        serde_json::from_str(&result.expect("warning JSON")).expect("valid warning JSON");
    assert!(warning["warning"].as_str().is_some_and(|value| value.contains(&name)));

    // With force — delete
    let result =
        server.do_project_delete(ProjectDeleteParams { project: name.clone(), force: true }).await;
    let deleted: serde_json::Value =
        serde_json::from_str(&result.expect("deleted JSON")).expect("valid deletion JSON");
    assert_eq!(deleted["deleted"], true);
    assert_eq!(deleted["project"], name);

    let gone = storage::projects::get_project_by_name(&pool, &name).await.unwrap();
    assert!(gone.is_none());
}

/// Verify `project_scan` runs a scan within a project.
#[tokio::test]
async fn test_tool_project_scan() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let target = local_scan_target().await;
    let server = test_server(pool.clone());
    let name = unique_name("mcp-pscan");

    let project = storage::projects::create_project(&pool, &name, "").await.unwrap();
    storage::projects::add_target(&pool, project.id, &target.url("/"), "loopback").await.unwrap();

    let params = ProjectScanParams {
        project: name.clone(),
        target: target.url("/"),
        profile: "quick".to_string(),
        modules: Some("headers,tech,cors".to_string()),
        skip: Some("tech".to_string()),
    };
    let result = server.do_project_scan(params).await;
    assert!(result.is_ok(), "loopback project scan should succeed: {result:?}");
    let response: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(response["modules_run"], serde_json::json!(["headers"]));
    assert_eq!(response["modules_skipped"], serde_json::json!([]));
    let persisted = storage::scans::list_scans(&pool, project.id).await.unwrap();
    assert_eq!(persisted.len(), 1, "project scan should persist exactly one scan record");
    assert_eq!(persisted[0].modules_run, vec!["headers"], "project scan must apply plan selectors");

    // Cleanup
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

#[tokio::test]
async fn test_tool_project_scan_denies_without_engagement() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let name = unique_name("mcp-pscan-no-engagement");
    let project = storage::projects::create_project(&pool, &name, "").await.unwrap();
    let target = "http://127.0.0.1:9";
    storage::projects::add_target(&pool, project.id, target, "must-not-connect").await.unwrap();
    let server = ScorchKitServer::new(Arc::new(AppConfig::default()), pool.clone());

    let result = server
        .do_project_scan(ProjectScanParams {
            project: name,
            target: target.to_string(),
            profile: "quick".to_string(),
            modules: Some("headers".to_string()),
            skip: None,
        })
        .await;
    assert!(
        result.is_err_and(|error| error.contains("no engagement authorization")),
        "persisted MCP scans must fail closed before loopback I/O without an engagement"
    );

    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

#[tokio::test]
async fn test_tool_project_scan_rejects_unregistered_target() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-pscan-unregistered");
    let project = storage::projects::create_project(&pool, &name, "").await.unwrap();

    let result = server
        .do_project_scan(ProjectScanParams {
            project: name,
            target: "http://127.0.0.1:9".to_string(),
            profile: "quick".to_string(),
            modules: Some("headers".to_string()),
            skip: None,
        })
        .await;
    assert!(
        result.is_err_and(|error| error.contains("not registered")),
        "project membership must be checked before scan authorization or I/O"
    );

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
    let findings_data = vec![
        Finding::new("xss", Severity::High, "XSS", "desc", "https://example.com"),
        Finding::new(
            "headers",
            Severity::Critical,
            "Missing headers",
            "desc",
            "https://example.com/headers",
        ),
    ];
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
    assert_eq!(parsed.len(), 2);

    let critical = server
        .do_project_findings(FindingListParams {
            project: name.clone(),
            severity: Some("critical".to_string()),
            status: None,
        })
        .await
        .expect("filter findings by severity");
    let critical: Vec<serde_json::Value> = serde_json::from_str(&critical).unwrap();
    assert_eq!(critical.len(), 1);
    assert_eq!(critical[0]["severity"], "critical");

    let tracked = storage::findings::list_findings(&pool, project.id).await.unwrap();
    let high = tracked.iter().find(|finding| finding.severity == "high").expect("high finding");
    storage::findings::update_finding_status(
        &pool,
        high.id,
        scorchkit::storage::models::VulnStatus::Acknowledged,
        Some("reviewed"),
    )
    .await
    .unwrap();
    let acknowledged = server
        .do_project_findings(FindingListParams {
            project: name.clone(),
            severity: None,
            status: Some("acknowledged".to_string()),
        })
        .await
        .expect("filter findings by status");
    let acknowledged: Vec<serde_json::Value> = serde_json::from_str(&acknowledged).unwrap();
    assert_eq!(acknowledged.len(), 1);
    assert_eq!(acknowledged[0]["status"], "acknowledged");

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
    assert_eq!(json["url"], "https://example.com/");

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

#[tokio::test]
async fn test_tool_target_remove_cannot_cross_project_boundary() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool.clone());
    let first_name = unique_name("mcp-tremove-owner");
    let second_name = unique_name("mcp-tremove-other");
    let first = storage::projects::create_project(&pool, &first_name, "").await.unwrap();
    let second = storage::projects::create_project(&pool, &second_name, "").await.unwrap();
    let target =
        storage::projects::add_target(&pool, first.id, "https://example.com", "").await.unwrap();

    let result = server
        .do_target_remove(TargetRemoveParams { project: second_name, id: target.id.to_string() })
        .await;
    assert!(result.is_err(), "a target ID must be constrained by its owning project");
    assert_eq!(storage::projects::list_targets(&pool, first.id).await.unwrap().len(), 1);

    storage::projects::delete_project(&pool, first.id).await.unwrap();
    storage::projects::delete_project(&pool, second.id).await.unwrap();
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
/// with targets, `scan_count`, and `finding_count` fields.
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
    let text = resource_text(&read);
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
    let text = resource_text(&read);
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
    let text = resource_text(&read);
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
    let text = resource_text(&read);
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
    let text = resource_text(&read);
    let json: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(json["canonical"]["title"], "Weak TLS");
    assert_eq!(json["triage"]["currentState"], "needs_context");

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
    let server = test_server(pool.clone());
    let fake_id = uuid::Uuid::new_v4();
    let uri = format!("scorchkit://projects/{fake_id}");
    let result = server.do_read_resource(&uri).await;
    assert!(result.is_err(), "non-existent project should return an error");

    let project = storage::projects::create_project(&pool, &unique_name("missing-finding"), "")
        .await
        .unwrap();
    let uri = format!("scorchkit://projects/{}/findings/{fake_id}", project.id);
    assert!(
        server.do_read_resource(&uri).await.is_err(),
        "non-existent finding in an existing project should return an error"
    );
    storage::projects::delete_project(&pool, project.id).await.unwrap();
}

/// Verify `get_info()` capabilities include resources.
#[tokio::test]
async fn test_server_capabilities_include_resources() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
    let info = server.get_info();
    assert!(info.capabilities.resources.is_some(), "server capabilities should include resources");
}

/// Verify `get_info()` instructions contain the rich methodology guide,
/// not the old minimal placeholder string.
#[tokio::test]
async fn test_server_uses_rich_instructions() {
    let Some(pool) = get_pool_or_skip().await else { return };
    let server = test_server(pool);
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

#[test]
fn code_scan_params_default_to_fast_and_accept_deep_profiles() {
    let defaulted: CodeScanParams =
        serde_json::from_str(r#"{"path":"."}"#).expect("default code profile");
    assert_eq!(defaulted.profile, "standard");

    let deep: CodeScanParams =
        serde_json::from_str(r#"{"path":".","profile":"thorough"}"#).expect("deep code profile");
    assert_eq!(deep.profile, "thorough");
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

#[tokio::test]
async fn scan_progress_and_correlation_return_structured_project_results(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-progress-correlation");
    let project = storage::projects::create_project(&pool, &name, "").await?;

    let empty_progress: serde_json::Value = serde_json::from_str(
        &server
            .do_scan_progress(ScanProgressParams { project: name.clone() })
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;
    assert_eq!(empty_progress["project"], name);
    assert_eq!(empty_progress["status"], "no_scans");

    let now = chrono::Utc::now();
    let scan = storage::scans::save_scan(
        &pool,
        project.id,
        "https://example.com",
        "quick",
        now,
        Some(now),
        &["gitleaks".to_string()],
        &[],
        &serde_json::json!({}),
    )
    .await?;
    let seeded = vec![Finding::new(
        "gitleaks",
        Severity::Critical,
        "Exposed API key",
        "fixture",
        "https://example.com",
    )];
    storage::findings::save_findings(&pool, project.id, scan.id, &seeded).await?;

    let progress: serde_json::Value = serde_json::from_str(
        &server
            .do_scan_progress(ScanProgressParams { project: name.clone() })
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;
    assert_eq!(progress["project"], name);
    assert_eq!(progress["status"], "complete");
    assert_eq!(progress["total_scans"], 1);
    assert_eq!(progress["total_tracked_findings"], 1);

    let correlation: serde_json::Value = serde_json::from_str(
        &server
            .do_correlate_findings(CorrelateFindingsParams { project: name.clone() })
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;
    assert_eq!(correlation["project"], name);
    assert_eq!(correlation["total_findings_available"], 1);
    assert_eq!(correlation["total_findings_analyzed"], 1);
    assert_eq!(correlation["schema"], "scorchkit.attack-path-correlation/v1");
    assert_eq!(correlation["status"], "complete");
    assert_eq!(correlation["attack_paths_found"], 0);
    assert_eq!(correlation["gaps"], serde_json::json!([]));
    assert_eq!(correlation["legacy_unverified_attack_chains"]["status"], "unverified_heuristic");
    assert!(correlation["legacy_unverified_attack_chains"]["chains"]
        .as_array()
        .is_some_and(|chains| !chains.is_empty()));

    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

/// Verify `correlate_findings` params deserialize.
#[test]
fn test_tool_correlate_findings() {
    let json = r#"{"project": "my-project"}"#;
    let params: CorrelateFindingsParams = serde_json::from_str(json).expect("deserialize");
    assert_eq!(params.project, "my-project");
}

fn mcp_correlation_findings(revision: &str, include_http: bool) -> Vec<Finding> {
    let observed_at = chrono::Utc::now();
    let source =
        Finding::new("semgrep", Severity::High, "source rule", "source proof", "src/users.rs:8")
            .with_location(ObservationLocation::Source {
                path: "src/users.rs".to_string(),
                region: Some(SourceRegion::new(8)),
            })
            .with_cwe(89)
            .with_correlation_key(CorrelationKey::new("route", "/users"))
            .with_provenance(
                ScannerProvenance::new("semgrep", observed_at).with_target_revision(revision),
            )
            .with_code_flows(vec![CodeFlow {
                message: None,
                thread_flows: vec![ThreadFlow {
                    message: None,
                    steps: vec![
                        CodeFlowStep::new(ObservationLocation::Source {
                            path: "src/users.rs".to_string(),
                            region: Some(SourceRegion::new(4)),
                        }),
                        CodeFlowStep::new(ObservationLocation::Source {
                            path: "src/users.rs".to_string(),
                            region: Some(SourceRegion::new(8)),
                        }),
                    ],
                }],
            }]);
    let mut runtime = Finding::new(
        "nuclei",
        Severity::High,
        "runtime probe",
        "runtime proof",
        "https://example.test/users",
    )
    .with_location(ObservationLocation::Runtime {
        uri: "https://example.test/users".to_string(),
        route: Some("/users".to_string()),
        parameter: None,
    })
    .with_cwe(89)
    .with_correlation_key(CorrelationKey::new("route", "/users"))
    .with_provenance(ScannerProvenance::new("nuclei", observed_at).with_target_revision(revision));
    if include_http {
        runtime = runtime.with_http_evidence(
            HttpEvidence::new("GET", "https://example.test/users", 500).with_route("/users"),
        );
    }
    vec![source, runtime]
}

#[tokio::test]
async fn correlate_findings_preserves_typed_paths_and_reports_malformed_durable_records(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = get_pool_or_skip().await else {
        return Ok(());
    };
    let server = test_server(pool.clone());
    let name = unique_name("mcp-typed-correlation");
    let project = storage::projects::create_project(&pool, &name, "").await?;
    let now = chrono::Utc::now();
    let scan = storage::scans::save_scan(
        &pool,
        project.id,
        "https://example.test/users",
        "standard",
        now,
        Some(now),
        &["semgrep".to_string(), "nuclei".to_string()],
        &[],
        &serde_json::json!({}),
    )
    .await?;
    let initial_findings = mcp_correlation_findings("revision-1", true);
    storage::findings::save_findings(&pool, project.id, scan.id, &initial_findings).await?;

    let response: serde_json::Value = serde_json::from_str(
        &server
            .do_correlate_findings(CorrelateFindingsParams { project: project.id.to_string() })
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;
    let expected = scorchkit::engine::attack_path::correlate_attack_paths(&initial_findings);
    assert_eq!(response["status"], "complete");
    assert_eq!(response["attack_paths_found"], 1);
    assert_eq!(response["attack_paths"][0], serde_json::to_value(&expected.paths[0])?);
    assert_eq!(response["legacy_unverified_attack_chains"]["status"], "unverified_heuristic");

    let scan_two = storage::scans::save_scan(
        &pool,
        project.id,
        "https://example.test/users",
        "standard",
        now,
        Some(now),
        &["semgrep".to_string(), "nuclei".to_string()],
        &[],
        &serde_json::json!({}),
    )
    .await?;
    let current_findings = mcp_correlation_findings("revision-2", false);
    assert_eq!(
        storage::findings::save_findings(&pool, project.id, scan_two.id, &current_findings).await?,
        0
    );
    let current: serde_json::Value = serde_json::from_str(
        &server
            .do_correlate_findings(CorrelateFindingsParams { project: project.id.to_string() })
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;
    assert_eq!(current["attack_paths"][0]["state"], "reachable");
    assert!(current["attack_paths"][0]["gaps"].as_array().is_some_and(|gaps| gaps
        .iter()
        .any(|gap| gap["kind"] == "runtime_proof_revision_unbound")));

    sqlx::query(
        "UPDATE tracked_findings SET raw_finding = '{\"malformed\":true}'::jsonb \
         WHERE project_id = $1 AND module_id = 'semgrep'",
    )
    .bind(project.id)
    .execute(&pool)
    .await?;
    let malformed: serde_json::Value = serde_json::from_str(
        &server
            .do_correlate_findings(CorrelateFindingsParams { project: project.id.to_string() })
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;
    assert_eq!(malformed["status"], "incomplete");
    assert_eq!(malformed["total_findings_available"], 2);
    assert_eq!(malformed["total_findings_analyzed"], 1);
    assert_eq!(malformed["attack_paths_found"], 0);
    assert!(malformed["gaps"].as_array().is_some_and(|gaps| gaps.iter().any(|gap| {
        gap["kind"] == "malformed_finding_record"
            && gap["finding_identity"].as_str().is_some_and(|identity| !identity.is_empty())
    })));

    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

#[tokio::test]
async fn correlate_findings_enforces_exact_finding_read_ceiling(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = get_pool_or_skip().await else {
        return Ok(());
    };
    let server = test_server(pool.clone());
    let now = chrono::Utc::now();

    let finding_project =
        storage::projects::create_project(&pool, &unique_name("mcp-finding-ceiling"), "").await?;
    let finding_scan = storage::scans::save_scan(
        &pool,
        finding_project.id,
        "https://example.test",
        "standard",
        now,
        Some(now),
        &[],
        &[],
        &serde_json::json!({}),
    )
    .await?;
    storage::findings::save_findings(
        &pool,
        finding_project.id,
        finding_scan.id,
        &[Finding::new("fixture", Severity::Low, "fixture", "fixture", "src/lib.rs:1")],
    )
    .await?;
    let seed = storage::findings::list_findings(&pool, finding_project.id).await?.remove(0);
    sqlx::query(
        "INSERT INTO tracked_findings \
         (scan_id, project_id, fingerprint, identity_schema, stable_identity, correlation_keys, \
          module_id, severity, title, description, affected_target, evidence, remediation, \
          owasp_category, cwe_id, raw_finding, confidence, status_note) \
         SELECT scan_id, project_id, fingerprint || series::text, identity_schema, \
          stable_identity || '-' || series::text, correlation_keys, module_id, severity, title, \
          description, affected_target, evidence, remediation, owasp_category, cwe_id, \
          raw_finding, confidence, status_note \
         FROM tracked_findings CROSS JOIN generate_series(1, $2) AS series WHERE id = $1",
    )
    .bind(seed.id)
    .bind(i32::try_from(scorchkit::engine::attack_path::MAX_CORRELATION_FINDINGS - 1)?)
    .execute(&pool)
    .await?;
    let exact: serde_json::Value = serde_json::from_str(
        &server
            .do_correlate_findings(CorrelateFindingsParams {
                project: finding_project.id.to_string(),
            })
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;
    assert_eq!(
        exact["total_findings_available"],
        scorchkit::engine::attack_path::MAX_CORRELATION_FINDINGS
    );
    assert_eq!(exact["legacy_unverified_attack_chains"]["status"], "unverified_heuristic");

    sqlx::query(
        "INSERT INTO tracked_findings \
         (scan_id, project_id, fingerprint, identity_schema, stable_identity, correlation_keys, \
          module_id, severity, title, description, affected_target, evidence, remediation, \
          owasp_category, cwe_id, raw_finding, confidence, status_note) \
         SELECT scan_id, project_id, fingerprint || '-overflow', identity_schema, \
          stable_identity || '-overflow', correlation_keys, module_id, severity, title, \
          description, affected_target, evidence, remediation, owasp_category, cwe_id, \
          raw_finding, confidence, status_note FROM tracked_findings WHERE id = $1",
    )
    .bind(seed.id)
    .execute(&pool)
    .await?;
    let overflow: serde_json::Value = serde_json::from_str(
        &server
            .do_correlate_findings(CorrelateFindingsParams {
                project: finding_project.id.to_string(),
            })
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;
    assert_eq!(overflow["total_findings_analyzed"], 0);
    assert_eq!(
        overflow["legacy_unverified_attack_chains"]["status"],
        "not_evaluated_resource_limit"
    );
    storage::projects::delete_project(&pool, finding_project.id).await?;

    Ok(())
}

#[tokio::test]
async fn correlate_findings_enforces_exact_evidence_read_ceiling(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = get_pool_or_skip().await else {
        return Ok(());
    };
    let server = test_server(pool.clone());
    let now = chrono::Utc::now();
    let evidence_project =
        storage::projects::create_project(&pool, &unique_name("mcp-evidence-ceiling"), "").await?;
    let evidence_scan = storage::scans::save_scan(
        &pool,
        evidence_project.id,
        "https://example.test",
        "standard",
        now,
        Some(now),
        &[],
        &[],
        &serde_json::json!({}),
    )
    .await?;
    storage::findings::save_findings(
        &pool,
        evidence_project.id,
        evidence_scan.id,
        &[Finding::new("fixture", Severity::Low, "fixture", "fixture", "src/lib.rs:1")
            .with_evidence("fixture evidence")],
    )
    .await?;
    let tracked = storage::findings::list_findings(&pool, evidence_project.id).await?.remove(0);
    let evidence = storage::findings::list_evidence(&pool, tracked.id).await?.remove(0);
    sqlx::query(
        "INSERT INTO finding_evidence \
         (tracked_finding_id, scan_id, evidence_identity, evidence_schema, raw_evidence, collected_at) \
         SELECT tracked_finding_id, scan_id, evidence_identity || '-' || series::text, \
          evidence_schema, raw_evidence, collected_at \
         FROM finding_evidence CROSS JOIN generate_series(1, $2) AS series WHERE id = $1",
    )
    .bind(evidence.id)
    .bind(i32::try_from(
        scorchkit::engine::attack_path::MAX_CORRELATION_PROJECT_EVIDENCE - 1,
    )?)
    .execute(&pool)
    .await?;
    let exact: serde_json::Value = serde_json::from_str(
        &server
            .do_correlate_findings(CorrelateFindingsParams {
                project: evidence_project.id.to_string(),
            })
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;
    assert!(exact["gaps"].as_array().is_some_and(|gaps| gaps
        .iter()
        .all(|gap| { gap["kind"] != "project_evidence_limit_exceeded" })));

    sqlx::query(
        "INSERT INTO finding_evidence \
         (tracked_finding_id, scan_id, evidence_identity, evidence_schema, raw_evidence, collected_at) \
         SELECT tracked_finding_id, scan_id, evidence_identity || '-overflow', \
          evidence_schema, raw_evidence, collected_at FROM finding_evidence WHERE id = $1",
    )
    .bind(evidence.id)
    .execute(&pool)
    .await?;
    let overflow: serde_json::Value = serde_json::from_str(
        &server
            .do_correlate_findings(CorrelateFindingsParams {
                project: evidence_project.id.to_string(),
            })
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;
    assert!(overflow["gaps"].as_array().is_some_and(|gaps| gaps
        .iter()
        .any(|gap| { gap["kind"] == "project_evidence_limit_exceeded" })));
    storage::projects::delete_project(&pool, evidence_project.id).await?;
    Ok(())
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
    let project = storage::projects::create_project(&pool, &name, "schedule test").await?;
    storage::projects::add_target(&pool, project.id, "https://example.com", "fixture").await?;

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
    assert_eq!(json["target_url"], "https://example.com/");
    assert_eq!(json["cron_expression"], "0 0 * * *");
    assert_eq!(json["enabled"], true);
    assert_eq!(
        json["engagement_snapshot"]["id"],
        test_engagement().id.to_string(),
        "the schedule must retain the engagement that authorized it"
    );

    // Cleanup
    let project = storage::projects::get_project_by_name(&pool, &name)
        .await?
        .ok_or("project should exist for cleanup")?;
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

#[tokio::test]
async fn test_tool_schedule_scan_denies_without_engagement(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let name = unique_name("mcp-sched-denied");
    let project = storage::projects::create_project(&pool, &name, "").await?;
    storage::projects::add_target(&pool, project.id, "https://example.com", "fixture").await?;
    let server = ScorchKitServer::new(Arc::new(AppConfig::default()), pool.clone());

    let result = server
        .do_schedule_scan(ScheduleScanParams {
            project: name,
            target: "https://example.com".to_string(),
            cron: "0 0 * * *".to_string(),
            profile: "quick".to_string(),
        })
        .await;

    assert!(
        result.is_err_and(|error| error.contains("no engagement authorization")),
        "schedule creation must fail before persistence without an engagement"
    );
    assert!(storage::schedules::list_schedules(&pool, project.id).await?.is_empty());
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
    let project = storage::projects::create_project(&pool, &name, "").await?;
    storage::projects::add_target(&pool, project.id, "https://example.com", "fixture").await?;

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
    let project = storage::projects::create_project(&pool, &name, "").await?;
    storage::projects::add_target(&pool, project.id, "https://example.com", "fixture").await?;

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
    let _due_scan_guard = due_scan_test_guard(&pool).await?;
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
    let _due_scan_guard = due_scan_test_guard(&pool).await?;
    let target = local_scan_target().await;
    let database_url = std::env::var("DATABASE_URL")?;
    let single_connection_pool = storage::connect_with_max(&database_url, 1).await?;
    let first_server = test_server(single_connection_pool.clone());
    let second_server = test_server(single_connection_pool);
    let name = unique_name("mcp-due-run");
    let project = storage::projects::create_project(&pool, &name, "").await?;

    storage::projects::add_target(&pool, project.id, &target.url("/first"), "first").await?;
    storage::projects::add_target(&pool, project.id, &target.url("/second"), "second").await?;

    // Two due schedules prove that the MCP endpoint executes the batch once,
    // rather than invoking an all-due loop once per schedule.
    let first = storage::schedules::create_schedule(
        &pool,
        project.id,
        &target.url("/first"),
        "quick",
        "0 0 * * *",
        &test_engagement(),
    )
    .await?;
    let second = storage::schedules::create_schedule(
        &pool,
        project.id,
        &target.url("/second"),
        "quick",
        "0 0 * * *",
        &test_engagement(),
    )
    .await?;
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    sqlx::query("UPDATE scan_schedules SET next_run = $1 WHERE id IN ($2, $3)")
        .bind(past)
        .bind(first.id)
        .bind(second.id)
        .execute(&pool)
        .await?;

    // Act: two callers contend for claims through a one-connection pool.
    let (first_result, second_result) =
        tokio::join!(first_server.do_run_due_scans(), second_server.do_run_due_scans());

    // Assert
    let first_body = first_result.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let second_body = second_result.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let first_json: serde_json::Value = serde_json::from_str(&first_body)?;
    let second_json: serde_json::Value = serde_json::from_str(&second_body)?;
    let executed = first_json["executed"].as_u64().unwrap_or_default()
        + second_json["executed"].as_u64().unwrap_or_default();
    assert_eq!(executed, 2, "concurrent callers must execute each due schedule exactly once");
    for output in [&first_json, &second_json] {
        if let Some(results) = output["results"].as_array() {
            assert!(results.iter().all(|outcome| outcome["status"] == "success"));
        }
    }
    let persisted = storage::scans::list_scans(&pool, project.id).await?;
    assert_eq!(persisted.len(), 2, "N due schedules must create N scan records, not N²");

    // Cleanup
    storage::schedules::delete_schedule(&pool, first.id).await?;
    storage::schedules::delete_schedule(&pool, second.id).await?;
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

/// Verify `do_run_due_scans` skips disabled schedules even if their `next_run`
/// is in the past.
#[tokio::test]
async fn test_tool_run_due_scans_disabled_skipped() -> Result<(), Box<dyn std::error::Error>> {
    // Arrange
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let _due_scan_guard = due_scan_test_guard(&pool).await?;
    let server = test_server(pool.clone());
    let name = unique_name("mcp-due-disabled");
    let project = storage::projects::create_project(&pool, &name, "").await?;

    let schedule = storage::schedules::create_schedule(
        &pool,
        project.id,
        "http://127.0.0.1:9",
        "quick",
        "0 0 * * *",
        &test_engagement(),
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
    let _due_scan_guard = due_scan_test_guard(&pool).await?;
    let target = local_scan_target().await;
    let server = test_server(pool.clone());
    let name = unique_name("mcp-due-nextrun");
    let project = storage::projects::create_project(&pool, &name, "").await?;
    storage::projects::add_target(&pool, project.id, &target.url("/scheduled"), "scheduled")
        .await?;

    let schedule = storage::schedules::create_schedule(
        &pool,
        project.id,
        &target.url("/scheduled"),
        "quick",
        "0 0 * * *",
        &test_engagement(),
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

#[tokio::test]
async fn test_tool_failed_due_scan_is_claimed_at_most_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let _due_scan_guard = due_scan_test_guard(&pool).await?;
    let name = unique_name("mcp-due-denied");
    let project = storage::projects::create_project(&pool, &name, "").await?;
    let target = "http://127.0.0.1:9";
    storage::projects::add_target(&pool, project.id, target, "denied fixture").await?;
    let schedule = storage::schedules::create_schedule(
        &pool,
        project.id,
        target,
        "quick",
        "0 0 * * *",
        &test_engagement(),
    )
    .await?;
    sqlx::query("UPDATE scan_schedules SET next_run = $1 WHERE id = $2")
        .bind(chrono::Utc::now() - chrono::Duration::hours(1))
        .bind(schedule.id)
        .execute(&pool)
        .await?;
    let server = ScorchKitServer::new(Arc::new(AppConfig::default()), pool.clone());

    let first: serde_json::Value = serde_json::from_str(
        &server
            .do_run_due_scans()
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;
    let second: serde_json::Value = serde_json::from_str(
        &server
            .do_run_due_scans()
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;

    assert_eq!(first["executed"], 1);
    assert_eq!(first["results"][0]["status"], "error");
    assert!(first["results"][0]["error"]
        .as_str()
        .is_some_and(|error| error.contains("no engagement authorization")));
    assert_eq!(second["executed"], 0, "a claimed failed occurrence must not be retried");
    let updated = storage::schedules::get_schedule(&pool, schedule.id)
        .await?
        .ok_or("claimed schedule should remain")?;
    assert!(updated.last_run.is_some());
    assert!(updated.next_run > chrono::Utc::now());

    storage::schedules::delete_schedule(&pool, schedule.id).await?;
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

#[tokio::test]
async fn test_due_scan_rejects_changed_engagement_snapshot(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let _due_scan_guard = due_scan_test_guard(&pool).await?;
    let target = local_scan_target().await;
    let name = unique_name("mcp-due-policy-change");
    let project = storage::projects::create_project(&pool, &name, "").await?;
    let target_url = target.url("/policy-change");
    storage::projects::add_target(&pool, project.id, &target_url, "fixture").await?;
    let schedule = storage::schedules::create_schedule(
        &pool,
        project.id,
        &target_url,
        "quick",
        "0 0 * * *",
        &test_engagement(),
    )
    .await?;
    sqlx::query("UPDATE scan_schedules SET next_run = $1 WHERE id = $2")
        .bind(chrono::Utc::now() - chrono::Duration::hours(1))
        .bind(schedule.id)
        .execute(&pool)
        .await?;

    let mut changed = test_engagement();
    changed.policy.allowed_scope.push(ScopeRule::Exact("newly-broadened.test".to_string()));
    let mut config = AppConfig::default();
    config.scan.timeout_seconds = 5;
    config.engagement = Some(changed);
    let server = ScorchKitServer::new(Arc::new(config), pool.clone());
    let body: serde_json::Value = serde_json::from_str(
        &server
            .do_run_due_scans()
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    )?;

    assert_eq!(body["executed"], 1);
    assert_eq!(body["results"][0]["status"], "error");
    assert!(body["results"][0]["error"]
        .as_str()
        .is_some_and(|error| error.contains("does not match its authorization snapshot")));
    assert!(storage::scans::list_scans(&pool, project.id).await?.is_empty());

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

#[test]
fn application_pentest_planning_is_effect_free_and_returns_a_canonical_plan() {
    let server = test_server_without_database();
    let plan_json = server
        .do_plan_application_pentest(ApplicationPentestPlanParams {
            target: "https://example.com/?credential=fixture-secret".to_string(),
            scenarios: vec![application_persona_scenario()],
        })
        .expect("compile application-pentest plan");
    let plan: scorchkit_core::ApplicationPentestPlan =
        serde_json::from_str(&plan_json).expect("decode canonical plan");

    plan.validate().expect("validate plan identity");
    assert!(!plan.target.contains("fixture-secret"));
    assert_eq!(url::Url::parse(&plan.target).expect("target").query(), Some("credential="));
    assert_eq!(plan.scenarios.len(), 1);
    assert_eq!(
        plan.scenarios[0].executor_kind,
        scorchkit_core::ApplicationPentestExecutorKind::PersonaComparator
    );
    assert_eq!(
        plan.scenarios[0].authorization_requirements,
        [scorchkit_core::ApplicationPentestAuthorizationRequirement {
            capability: Capability::DastScan,
            effect: EffectClass::Intrusive,
        }]
    );
}

#[tokio::test]
async fn application_pentest_requires_the_exact_plan_and_persists_complete_coverage(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = get_pool_or_skip().await else {
        return Ok(());
    };
    let target = MockServer::start_async().await;
    let response = target
        .mock_async(|when, then| {
            when.method("GET").path("/");
            then.status(200).body("allowed");
        })
        .await;
    let server = test_server(pool.clone());
    let name = unique_name("mcp-application-pentest");
    let project = storage::projects::create_project(&pool, &name, "application pentest").await?;
    let target_url = target.url("/");
    storage::projects::add_target(&pool, project.id, &target_url, "loopback").await?;
    let plan_json = server.do_plan_application_pentest(ApplicationPentestPlanParams {
        target: target_url.clone(),
        scenarios: vec![application_persona_scenario()],
    })?;
    let plan: scorchkit_core::ApplicationPentestPlan = serde_json::from_str(&plan_json)?;

    let mismatch = server
        .do_application_pentest(ApplicationPentestExecuteParams {
            project: name.clone(),
            target: target_url.clone(),
            approved_plan_identity: "0".repeat(64),
            scenarios: vec![application_persona_scenario()],
        })
        .await;
    assert!(mismatch.is_err_and(|error| error.contains("identity")));
    assert_eq!(response.calls_async().await, 0, "identity mismatch must precede target I/O");

    let output = server
        .do_application_pentest(ApplicationPentestExecuteParams {
            project: name.clone(),
            target: target_url,
            approved_plan_identity: plan.identity.clone(),
            scenarios: vec![application_persona_scenario()],
        })
        .await?;
    let output: serde_json::Value = serde_json::from_str(&output)?;
    assert_eq!(output["plan"]["identity"], plan.identity);
    assert_eq!(output["assessment"]["coverage_status"], "complete");
    assert_eq!(
        output["assessment"]["plan"]["scenarios"][0]["scenario"]["proposal_source"]["label"],
        "codex"
    );
    assert_eq!(response.calls_async().await, 1);
    let scans = storage::scans::list_scans(&pool, project.id).await?;
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].profile, "application-pentest");
    assert_eq!(
        scans[0].execution_evidence["application_pentest"]["plan"]["identity"],
        plan.identity
    );

    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

#[tokio::test]
async fn application_pentest_storage_rolls_back_scan_and_findings_as_one_unit(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = get_pool_or_skip().await else {
        return Ok(());
    };
    let suffix = Uuid::new_v4().simple().to_string();
    assert_eq!(suffix.len(), 32);
    assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let trigger = format!("scorchkit_t16_{suffix}");
    let function = format!("scorchkit_t16_fail_{suffix}");
    let failing_module = format!("transaction-failure-{suffix}");
    let create_function = format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.module_id = '{failing_module}' THEN \
         RAISE EXCEPTION 'fixture transaction failure'; END IF; RETURN NEW; END $$"
    );
    // SQL identifiers cannot be bind parameters. Every interpolated byte is a locally generated,
    // length-pinned hexadecimal UUID suffix, so this fixture DDL has no operator-controlled input.
    sqlx::query(sqlx::AssertSqlSafe(create_function)).execute(&pool).await?;
    let create_trigger = format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT OR UPDATE ON tracked_findings \
         FOR EACH ROW EXECUTE FUNCTION {function}()"
    );
    sqlx::query(sqlx::AssertSqlSafe(create_trigger)).execute(&pool).await?;

    let project =
        storage::projects::create_project(&pool, &unique_name("mcp-atomic-pentest"), "").await?;
    let now = chrono::Utc::now();
    let mut result = ScanResult::new(
        Uuid::new_v4().to_string(),
        Target::parse("https://example.com/")?,
        now,
        vec![
            Finding::new(
                "transaction-success",
                Severity::Low,
                "First transaction fixture",
                "must roll back",
                "https://example.com/first",
            ),
            Finding::new(
                &failing_module,
                Severity::High,
                "Second transaction fixture",
                "forces rollback",
                "https://example.com/second",
            ),
        ],
        vec!["persona-comparator-v1".to_string()],
        Vec::new(),
    );
    result.completed_at = now;
    result.summary = scorchkit_core::ScanSummary::from_findings(&result.findings);
    let stored = storage::findings::save_application_pentest_scan(&pool, project.id, &result).await;
    assert!(stored.is_err_and(|error| error.to_string().contains("fixture transaction failure")));
    assert!(storage::scans::list_scans(&pool, project.id).await?.is_empty());
    assert!(storage::findings::list_findings(&pool, project.id).await?.is_empty());

    sqlx::query(sqlx::AssertSqlSafe(format!("DROP TRIGGER {trigger} ON tracked_findings")))
        .execute(&pool)
        .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP FUNCTION {function}()"))).execute(&pool).await?;
    let stored =
        storage::findings::save_application_pentest_scan(&pool, project.id, &result).await?;
    assert_eq!(stored.findings_new, 2);
    assert_eq!(storage::scans::list_scans(&pool, project.id).await?.len(), 1);
    assert_eq!(storage::findings::list_findings(&pool, project.id).await?.len(), 2);
    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

#[tokio::test]
async fn application_evidence_import_is_atomic_attributed_and_evidence_idempotent(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = get_pool_or_skip().await else {
        return Ok(());
    };
    let target = MockServer::start_async().await;
    let target_url = target.url("/");
    let server = test_server(pool.clone());
    let name = unique_name("mcp-application-evidence");
    let project = storage::projects::create_project(&pool, &name, "manual evidence").await?;
    storage::projects::add_target(&pool, project.id, &target_url, "loopback").await?;
    let root = tempfile::Builder::new()
        .prefix("ticket-016-evidence-")
        .tempdir_in(std::env::current_dir()?)?;
    let bytes = format!(
        "{{\"log\":{{\"entries\":[{{\"request\":{{\"method\":\"GET\",\"url\":{url},\"headers\":[]}},\"response\":{{\"status\":403,\"headers\":[],\"content\":{{\"text\":\"token=fixture-secret\"}}}}}}]}}}}",
        url = serde_json::to_string(&target_url)?
    );
    let path = root.path().join("evidence.har");
    std::fs::write(&path, &bytes)?;
    let digest = scorchkit_core::sha256_hex(bytes.as_bytes());
    let request = || ApplicationEvidenceImportParams {
        project: name.clone(),
        target: target_url.clone(),
        path: path.display().to_string(),
        sha256: digest.clone(),
        format: "har".to_string(),
        source_kind: "proxy".to_string(),
        source_label: "reviewed-proxy".to_string(),
        finding_id: None,
        new_finding: Some(ManualApplicationFindingParams {
            severity: "high".to_string(),
            title: "Manual authorization finding".to_string(),
            description: "Observed denied response".to_string(),
            remediation: Some("Review authorization policy".to_string()),
            cwe_id: Some(862),
        }),
    };

    let first: serde_json::Value =
        serde_json::from_str(&server.do_import_application_evidence(request()).await?)?;
    assert_eq!(first["finding_created"], true);
    assert_eq!(first["evidence_appended"], 1);
    assert_eq!(first["assessment"]["source_kind"], "proxy");
    assert!(!first.to_string().contains("fixture-secret"));
    let finding_id = Uuid::parse_str(first["finding_id"].as_str().ok_or("finding ID")?)?;
    assert_eq!(storage::findings::list_evidence(&pool, finding_id).await?.len(), 1);
    assert!(storage::attack_paths::list_attack_paths(&pool, project.id).await?.is_empty());

    let second: serde_json::Value =
        serde_json::from_str(&server.do_import_application_evidence(request()).await?)?;
    assert_eq!(second["finding_id"], first["finding_id"]);
    assert_eq!(second["finding_created"], false);
    assert_eq!(second["evidence_appended"], 0);
    assert_eq!(storage::findings::list_evidence(&pool, finding_id).await?.len(), 1);
    assert_eq!(storage::scans::list_scans(&pool, project.id).await?.len(), 2);

    let distinct_digest = append_distinct_application_evidence(
        &server,
        &pool,
        project.id,
        &name,
        &target_url,
        &path,
        finding_id,
    )
    .await?;
    assert_cross_project_application_evidence_rolls_back(
        &server,
        &pool,
        &name,
        &target_url,
        &path,
        &distinct_digest,
    )
    .await?;
    assert_cross_target_application_evidence_rolls_back(
        &server, &pool, project.id, &name, &path, finding_id,
    )
    .await?;
    assert_eq!(storage::scans::list_scans(&pool, project.id).await?.len(), 3);

    storage::projects::delete_project(&pool, project.id).await?;
    Ok(())
}

async fn assert_cross_target_application_evidence_rolls_back(
    server: &ScorchKitServer,
    pool: &sqlx::PgPool,
    project_id: Uuid,
    project_name: &str,
    path: &Path,
    finding_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let other = MockServer::start_async().await;
    let other_target = other.url("/other");
    storage::projects::add_target(pool, project_id, &other_target, "other loopback").await?;
    let bytes = format!(
        "{{\"log\":{{\"entries\":[{{\"request\":{{\"method\":\"GET\",\"url\":{url},\"headers\":[]}},\"response\":{{\"status\":200,\"headers\":[],\"content\":{{\"text\":\"unrelated proof\"}}}}}}]}}}}",
        url = serde_json::to_string(&other_target)?
    );
    std::fs::write(path, &bytes)?;
    let before = storage::scans::list_scans(pool, project_id).await?.len();
    let mismatch = server
        .do_import_application_evidence(ApplicationEvidenceImportParams {
            project: project_name.to_string(),
            target: other_target,
            path: path.display().to_string(),
            sha256: scorchkit_core::sha256_hex(bytes.as_bytes()),
            format: "har".to_string(),
            source_kind: "proxy".to_string(),
            source_label: "unrelated-proxy".to_string(),
            finding_id: Some(finding_id.to_string()),
            new_finding: None,
        })
        .await;
    assert!(mismatch.is_err_and(|error| error.contains("does not match")));
    assert_eq!(storage::scans::list_scans(pool, project_id).await?.len(), before);
    assert_eq!(storage::findings::list_evidence(pool, finding_id).await?.len(), 2);
    Ok(())
}

async fn append_distinct_application_evidence(
    server: &ScorchKitServer,
    pool: &sqlx::PgPool,
    project_id: Uuid,
    project_name: &str,
    target_url: &str,
    path: &Path,
    finding_id: Uuid,
) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = format!(
        "{{\"log\":{{\"entries\":[{{\"request\":{{\"method\":\"GET\",\"url\":{url},\"headers\":[]}},\"response\":{{\"status\":200,\"headers\":[],\"content\":{{\"text\":\"reviewed distinct proof\"}}}}}}]}}}}",
        url = serde_json::to_string(target_url)?
    );
    std::fs::write(path, &bytes)?;
    let digest = scorchkit_core::sha256_hex(bytes.as_bytes());
    let existing: serde_json::Value = serde_json::from_str(
        &server
            .do_import_application_evidence(ApplicationEvidenceImportParams {
                project: project_name.to_string(),
                target: target_url.to_string(),
                path: path.display().to_string(),
                sha256: digest.clone(),
                format: "har".to_string(),
                source_kind: "human".to_string(),
                source_label: "reviewed-human".to_string(),
                finding_id: Some(finding_id.to_string()),
                new_finding: None,
            })
            .await?,
    )?;
    assert_eq!(existing["finding_id"], finding_id.to_string());
    assert_eq!(existing["finding_created"], false);
    assert_eq!(existing["evidence_appended"], 1);
    assert_eq!(storage::findings::list_evidence(pool, finding_id).await?.len(), 2);
    assert_eq!(storage::scans::list_scans(pool, project_id).await?.len(), 3);
    assert!(storage::attack_paths::list_attack_paths(pool, project_id).await?.is_empty());
    Ok(digest)
}

async fn assert_cross_project_application_evidence_rolls_back(
    server: &ScorchKitServer,
    pool: &sqlx::PgPool,
    project_name: &str,
    target_url: &str,
    path: &Path,
    digest: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let foreign = storage::projects::create_project(
        pool,
        &unique_name("mcp-foreign-evidence"),
        "foreign finding",
    )
    .await?;
    let now = chrono::Utc::now();
    let foreign_scan = storage::scans::save_scan(
        pool,
        foreign.id,
        target_url,
        "fixture",
        now,
        Some(now),
        &[],
        &[],
        &serde_json::json!({}),
    )
    .await?;
    storage::findings::save_findings(
        pool,
        foreign.id,
        foreign_scan.id,
        &[Finding::new(
            "fixture",
            Severity::High,
            "Foreign finding",
            "Must not receive evidence",
            target_url,
        )],
    )
    .await?;
    let foreign_finding = storage::findings::list_findings(pool, foreign.id).await?[0].id;
    let mismatch = server
        .do_import_application_evidence(ApplicationEvidenceImportParams {
            project: project_name.to_string(),
            target: target_url.to_string(),
            path: path.display().to_string(),
            sha256: digest.to_string(),
            format: "har".to_string(),
            source_kind: "proxy".to_string(),
            source_label: "reviewed-proxy".to_string(),
            finding_id: Some(foreign_finding.to_string()),
            new_finding: None,
        })
        .await;
    assert!(mismatch.is_err_and(|error| error.contains("does not belong")));
    storage::projects::delete_project(pool, foreign.id).await?;
    Ok(())
}

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

    // Assert — the disabled state must not be confused with host availability.
    assert_eq!(
        result.as_ref().err().map(String::as_str),
        Some("AI is disabled in config — scan planning requires AI")
    );
    Ok(())
}

#[tokio::test]
async fn test_tool_plan_scan_reports_unavailable_provider() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/scorchkit_unconnected_test")
        .unwrap_or_else(|error| panic!("lazy test database URL should parse: {error}"));
    let mut config = AppConfig::default();
    config.ai.binary = Some("scorchkit-test-ai-provider-does-not-exist".to_string());
    let server = ScorchKitServer::new(Arc::new(config), pool);

    let result =
        server.do_plan_scan(PlanScanParams { target: "https://example.com".to_string() }).await;

    assert_eq!(
        result.as_ref().err().map(String::as_str),
        Some("Codex CLI not found. Install or configure the selected AI provider.")
    );
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

#[tokio::test]
async fn test_tool_analyze_findings_distinguishes_disabled_and_unavailable(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pool) = get_pool_or_skip().await else { return Ok(()) };
    let name = unique_name("mcp-analyze-provider-state");
    let project = storage::projects::create_project(&pool, &name, "AI provider state").await?;
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
    let seeded = vec![Finding::new(
        "fixture",
        Severity::High,
        "Seeded finding",
        "fixture",
        "https://example.com",
    )];
    storage::findings::save_findings(&pool, project.id, scan.id, &seeded).await?;
    let params = || AnalyzeFindingsParams {
        project: name.clone(),
        focus: "summary".to_string(),
        scan_id: None,
    };

    let mut disabled_config = AppConfig::default();
    disabled_config.ai.enabled = false;
    disabled_config.engagement = Some(test_engagement());
    let disabled = ScorchKitServer::new(Arc::new(disabled_config), pool.clone())
        .do_analyze_findings(params())
        .await;

    let mut unavailable_config = AppConfig::default();
    unavailable_config.ai.binary = Some("scorchkit-test-ai-provider-does-not-exist".to_string());
    unavailable_config.engagement = Some(test_engagement());
    let unavailable = ScorchKitServer::new(Arc::new(unavailable_config), pool.clone())
        .do_analyze_findings(params())
        .await;

    storage::projects::delete_project(&pool, project.id).await?;

    assert_eq!(
        disabled.as_ref().err().map(String::as_str),
        Some("AI analysis is disabled in config")
    );
    assert_eq!(
        unavailable.as_ref().err().map(String::as_str),
        Some("Codex CLI not found. Install or configure the selected AI provider.")
    );
    Ok(())
}
