//! Real Rustal dispatch tests against a typed loopback control stub.

use std::process::Command;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use rustal::testing::{TestClient, TestResponse};
use scorchkit_console::client::ControlClient;
use scorchkit_console::config::{ConsoleConfig, MAX_CONTROL_RESPONSE_BYTES, MAX_FORM_BYTES};
use scorchkit_console::render::{self, PageChrome};
use scorchkit_console::{ConsoleState, build_app};
use scorchkit_control::{
    CONTROL_API_SCHEMA_V1, ControlCommandV1, ControlOperationV1, ControlQueryV1, ControlRequestV1,
    ControlResultV1, PageRequestV1,
};
use serde_json::{Value, json};
use tokio::task::JoinHandle;

const ENGAGEMENT: &str = "b1382ed4-0ad0-45a2-afd6-550c0d947566";
const PROJECT: &str = "7f7202f4-9620-43f0-9e14-075099545d6f";
const TARGET: &str = "4338d3d4-e6e4-4ab5-8cb8-73d28ec835ae";
const JOB: &str = "482f8eaf-b10e-4eb2-9c88-f3ec6b55e38f";
const FINDING: &str = "f47fd4fb-a099-4b83-91bb-59967e4b7c08";
const SCAN: &str = "aff167d3-c693-46af-b8e4-e37512566390";
const EVIDENCE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONSOLE_HOST: &str = "127.0.0.1:7445";
const CONSOLE_ORIGIN: &str = "http://127.0.0.1:7445";
const MALICIOUS: &str = "<img src=x onerror=alert(1)>";

fn test_bearer() -> String {
    ["console", "test", "bearer", "value", "not", "secret"].join("-")
}

#[derive(Debug, Clone, Copy)]
enum Fault {
    None,
    WrongPrincipal,
    Redirect,
    WrongContentType,
    Oversized,
}

#[derive(Debug, Clone)]
struct MockState {
    requests: Arc<Mutex<Vec<ControlRequestV1>>>,
    fault: Fault,
}

#[derive(Debug)]
struct MockControl {
    origin: String,
    requests: Arc<Mutex<Vec<ControlRequestV1>>>,
    task: JoinHandle<std::io::Result<()>>,
}

impl MockControl {
    async fn start(fault: Fault) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = MockState { requests: Arc::clone(&requests), fault };
        let app = Router::new().route("/v1/control", post(control)).with_state(state);
        let task = tokio::spawn(axum::serve(listener, app).into_future());
        Ok(Self { origin: format!("http://{address}"), requests, task })
    }

    fn captured(&self) -> Result<Vec<ControlRequestV1>> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|_| anyhow!("mock request ledger was poisoned"))
    }
}

impl Drop for MockControl {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn control(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(request): Json<ControlRequestV1>,
) -> Response {
    let authenticated = headers.get("authorization").and_then(|value| value.to_str().ok())
        == Some(&format!("Bearer {}", test_bearer()));
    let accepts_json = headers
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("application/json"));
    if !authenticated || !accepts_json {
        return (
            StatusCode::UNAUTHORIZED,
            Json(error_envelope(&request, "unauthenticated", "control authentication failed")),
        )
            .into_response();
    }
    match state.fault {
        Fault::Redirect => {
            return (
                StatusCode::TEMPORARY_REDIRECT,
                [("location", "http://127.0.0.1:9/v1/control")],
            )
                .into_response();
        }
        Fault::WrongContentType => {
            return (StatusCode::OK, [("content-type", "text/plain")], "not JSON").into_response();
        }
        Fault::Oversized => {
            return Json(json!({"padding": "x".repeat(MAX_CONTROL_RESPONSE_BYTES + 1)}))
                .into_response();
        }
        Fault::None | Fault::WrongPrincipal => {}
    }
    if let Ok(mut requests) = state.requests.lock() {
        requests.push(request.clone());
    }
    let subject_engagement = match state.fault {
        Fault::WrongPrincipal => "74ec13af-6847-4229-9ba8-894a6ce99a39",
        Fault::None | Fault::Redirect | Fault::WrongContentType | Fault::Oversized => ENGAGEMENT,
    };
    let (status, outcome) = outcome(&request);
    (
        status,
        Json(json!({
            "schemaVersion": CONTROL_API_SCHEMA_V1,
            "requestId": request.request_id,
            "principal": {
                "kind": "authenticated_bearer",
                "subject": "console-test",
                "engagementId": subject_engagement
            },
            "result": outcome
        })),
    )
        .into_response()
}

fn outcome(request: &ControlRequestV1) -> (StatusCode, Value) {
    match &request.operation {
        ControlOperationV1::Query(query) => {
            let (kind, value) = match query.as_ref() {
                ControlQueryV1::GetEngagement => ("engagement", engagement()),
                ControlQueryV1::ListProjects { .. } => {
                    ("projects", json!({"items": [project()], "nextCursor": "next-project-page"}))
                }
                ControlQueryV1::GetProject { .. } => ("project", project()),
                ControlQueryV1::ListTargets { .. } => {
                    ("targets", json!({"items": [target()], "nextCursor": "next-target-page"}))
                }
                ControlQueryV1::ListJobs { .. } => {
                    ("jobs", json!({"items": [job()], "nextCursor": null}))
                }
                ControlQueryV1::GetJob { .. } => ("job", job()),
                ControlQueryV1::ListFindings { .. } => {
                    ("findings", json!({"items": [finding()], "nextCursor": "next-finding-page"}))
                }
                ControlQueryV1::GetFinding { .. } => ("finding", finding()),
                ControlQueryV1::ListEvidence { .. } => {
                    ("evidence", json!({"items": [evidence()], "nextCursor": null}))
                }
                ControlQueryV1::GetProjectReport { .. } => ("report", report()),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        error_value("invalid_request", "query not mocked"),
                    );
                }
            };
            (StatusCode::OK, success_value(kind, &value))
        }
        ControlOperationV1::Command(ControlCommandV1::StartJob { .. }) => {
            (StatusCode::OK, success_value("job", &job()))
        }
        ControlOperationV1::Command(ControlCommandV1::AddTarget { url, .. })
            if url.contains("outside.example") =>
        {
            (
                StatusCode::FORBIDDEN,
                error_value("policy_denied", "Target is outside the active engagement."),
            )
        }
        ControlOperationV1::Command(_) => (
            StatusCode::OK,
            success_value("acknowledged", &json!({"changed": true, "affected": 1})),
        ),
    }
}

fn success_value(kind: &str, value: &Value) -> Value {
    json!({"outcome": "success", "value": {"kind": kind, "value": value}})
}

fn error_value(code: &str, message: &str) -> Value {
    json!({
        "outcome": "error",
        "value": {"code": code, "message": message, "retryable": false}
    })
}

fn error_envelope(request: &ControlRequestV1, code: &str, message: &str) -> Value {
    json!({
        "schemaVersion": CONTROL_API_SCHEMA_V1,
        "requestId": request.request_id,
        "principal": {
            "kind": "authenticated_bearer",
            "subject": "console-test",
            "engagementId": ENGAGEMENT
        },
        "result": error_value(code, message)
    })
}

fn engagement() -> Value {
    json!({
        "id": ENGAGEMENT,
        "name": "Dogfood engagement",
        "enabled": true,
        "expiresAt": "2026-09-30T12:00:00Z",
        "capabilities": ["scan", "triage"],
        "effects": ["active_safe"]
    })
}

fn project() -> Value {
    json!({
        "id": PROJECT,
        "name": "Dogfood API",
        "description": MALICIOUS,
        "createdAt": "2026-08-24T12:00:00Z",
        "updatedAt": "2026-08-24T12:30:00Z"
    })
}

fn target() -> Value {
    json!({
        "id": TARGET,
        "projectId": PROJECT,
        "url": "https://app.example.test/",
        "label": "Primary application",
        "createdAt": "2026-08-24T12:00:00Z"
    })
}

fn job() -> Value {
    json!({
        "id": JOB,
        "rootJobId": JOB,
        "attempt": 1,
        "state": "queued",
        "revision": 2,
        "target": "https://app.example.test/",
        "profile": "standard",
        "progress": {
            "totalModules": 3,
            "activeModules": ["nuclei"],
            "completedModules": ["headers"],
            "skippedModules": ["zap"],
            "failedModules": [],
            "findingCount": 1
        },
        "createdAt": "2026-08-24T12:00:00Z",
        "updatedAt": "2026-08-24T12:30:00Z"
    })
}

fn finding() -> Value {
    json!({
        "id": FINDING,
        "projectId": PROJECT,
        "scanId": SCAN,
        "fingerprint": "legacy-fingerprint",
        "identitySchema": "scorchkit.finding-identity/v1",
        "stableIdentity": "finding:dogfood:authorization",
        "correlationKeys": {"rule": "authz-001"},
        "status": "new",
        "statusNote": "Needs ownership confirmation",
        "seenCount": 2,
        "firstSeen": "2026-08-24T12:00:00Z",
        "lastSeen": "2026-08-24T12:30:00Z",
        "foundAt": "2026-08-24T12:00:00Z",
        "canonical": {
            "title": MALICIOUS,
            "severity": "high quiet",
            "appsec": {
                "scanner": "nuclei",
                "evidence": [{"kind": "text", "text": "cross-tenant response"}],
                "agent_analysis": [{"schema": "scorchkit.agent-analysis/v1", "conclusion": "plausible"}]
            }
        },
        "triage": {
            "schema": "scorchkit.finding-triage/v1",
            "currentState": "needs_context",
            "subject": {
                "projectIdentity": "project:dogfood",
                "findingIdentity": "finding:dogfood:authorization",
                "ruleIdentity": "authz-001",
                "targetIdentity": "https://app.example.test/accounts/{id}"
            },
            "transitions": [{"state": "needs_context", "reason": "verify ownership"}],
            "correlations": [{"decision": "related", "evidenceIds": [EVIDENCE_ID]}],
            "suppressions": [{"scope": "exact", "active": true}],
            "activeSuppressionIds": ["suppression:1"]
        }
    })
}

fn evidence() -> Value {
    json!({
        "id": "a30cc483-b33e-4ef4-a53a-501918472187",
        "findingId": FINDING,
        "scanId": SCAN,
        "evidenceSchema": "scorchkit.evidence/v1",
        "evidenceIdentity": EVIDENCE_ID,
        "canonical": {"kind": "http", "status": 200, "body": MALICIOUS}
    })
}

fn report() -> Value {
    json!({
        "schemaVersion": "scorchkit.project-report/v1",
        "project": project(),
        "targetCount": 1,
        "scanCount": 4,
        "findingCount": 1,
        "severityCounts": {"high": 1},
        "triageStateCounts": {"needs_context": 1},
        "activeSuppressedCount": 1,
        "generatedAt": "2026-08-24T13:00:00Z"
    })
}

fn config(mock: &MockControl) -> Result<ConsoleConfig> {
    ConsoleConfig::new(CONSOLE_HOST, &mock.origin, ENGAGEMENT, &test_bearer())
}

fn console(mock: &MockControl) -> Result<TestClient> {
    let app = build_app(ConsoleState::new(config(mock)?)?)?;
    Ok(TestClient::new(&app))
}

async fn get(client: &TestClient, path: &str) -> TestResponse {
    client.get(path).header("host", CONSOLE_HOST).send().await
}

async fn post_form(client: &TestClient, path: &str, origin: &str, body: String) -> TestResponse {
    client
        .post(path)
        .header("host", CONSOLE_HOST)
        .header("origin", origin)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
}

fn csrf(body: &str) -> Result<&str> {
    let marker = "name=\"csrf\" value=\"";
    let (_, tail) = body.split_once(marker).context("rendered page omitted CSRF field")?;
    tail.split_once('"').map(|(value, _)| value).context("rendered CSRF field was malformed")
}

#[tokio::test]
async fn real_routes_render_bounded_escaped_control_views() -> Result<()> {
    let mock = MockControl::start(Fault::None).await?;
    let direct = ControlClient::new(config(&mock)?)?;
    let ControlResultV1::Engagement(engagement) =
        direct.query(ControlQueryV1::GetEngagement).await?
    else {
        return Err(anyhow!("mock returned the wrong engagement shape"));
    };
    let ControlResultV1::Projects(projects) = direct
        .query(ControlQueryV1::ListProjects { page: PageRequestV1 { cursor: None, limit: 100 } })
        .await?
    else {
        return Err(anyhow!("mock returned the wrong project shape"));
    };
    let ControlResultV1::Jobs(jobs) = direct
        .query(ControlQueryV1::ListJobs { page: PageRequestV1 { cursor: None, limit: 100 } })
        .await?
    else {
        return Err(anyhow!("mock returned the wrong job shape"));
    };
    let rendered = render::dashboard(
        PageChrome { csrf: "fixture".to_owned(), event_after: 0, message: String::new() },
        engagement,
        projects,
        jobs,
    )?;
    assert!(rendered.contains("Dogfood engagement"));
    let client = console(&mock)?;

    let dashboard = get(&client, "/").await;
    assert_eq!(dashboard.status(), StatusCode::OK, "{}", dashboard.text());
    assert!(dashboard.header("content-security-policy").is_some());
    assert_eq!(dashboard.header("x-frame-options"), Some("DENY"));
    let dashboard_body = dashboard.text();
    assert!(dashboard_body.contains("Dogfood engagement"));
    assert!(dashboard_body.contains("Read-only authority"));
    assert!(dashboard_body.contains("more available"));
    assert!(!dashboard_body.contains(&test_bearer()));

    let project_page = get(&client, &format!("/projects/{PROJECT}")).await;
    assert_eq!(project_page.status(), StatusCode::OK);
    let project_body = project_page.text();
    assert!(project_body.contains("Registered targets"));
    assert!(project_body.contains("needs_context: 1"));
    assert!(project_body.contains("onerror"));
    assert!(!project_body.contains("<img src=x"));

    let finding_page = get(&client, &format!("/findings/{FINDING}")).await;
    assert_eq!(finding_page.status(), StatusCode::OK);
    let finding_body = finding_page.text();
    for required in [
        "Scanner record",
        "Model analysis",
        "Correlation decisions",
        "Suppression history",
        "Transition history",
        EVIDENCE_ID,
    ] {
        assert!(finding_body.contains(required), "finding page omitted {required}");
    }
    assert!(finding_body.contains("onerror"));
    assert!(!finding_body.contains("<img src=x"));
    assert!(finding_body.contains("severity unknown"));
    assert!(!finding_body.contains("severity high quiet"));

    let job_page = get(&client, &format!("/jobs/{JOB}")).await;
    assert_eq!(job_page.status(), StatusCode::OK);
    assert!(job_page.text().contains("Degraded: 0 failed, 1 skipped"));

    let events = get(&client, "/events?after=0").await;
    assert_eq!(events.status(), StatusCode::OK);
    assert_eq!(events.header("content-type"), Some("text/event-stream; charset=utf-8"));
    assert!(events.text().contains("event: heartbeat"));
    Ok(())
}

async fn assert_request_rejections(
    mock: &MockControl,
    client: &TestClient,
    token: &str,
) -> Result<()> {
    let before = mock.captured()?.len();

    let rejected = post_form(
        client,
        &format!("/projects/{PROJECT}/targets"),
        "http://evil.test",
        format!("csrf={token}&url=https%3A%2F%2Fapp.example.test%2F&label=primary"),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    assert_eq!(mock.captured()?.len(), before);

    let invalid_path = get(client, "/jobs/not-a-uuid").await;
    assert_eq!(invalid_path.status(), StatusCode::BAD_REQUEST);
    assert!(invalid_path.text().contains("Request parameters were invalid"));
    let malformed = post_form(
        client,
        &format!("/projects/{PROJECT}/targets"),
        CONSOLE_ORIGIN,
        "csrf=only".to_owned(),
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    let oversized = post_form(
        client,
        &format!("/projects/{PROJECT}/targets"),
        CONSOLE_ORIGIN,
        "x".repeat(MAX_FORM_BYTES + 1),
    )
    .await;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let invalid_command = post_form(
        client,
        "/jobs/start",
        CONSOLE_ORIGIN,
        format!("csrf={token}&target=https%3A%2F%2Fapp.example.test%2F&profile=&modules=&skip="),
    )
    .await;
    assert_eq!(invalid_command.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mock.captured()?.len(), before);
    Ok(())
}

#[tokio::test]
async fn real_mutation_routes_guard_then_dispatch_exact_commands() -> Result<()> {
    let mock = MockControl::start(Fault::None).await?;
    let client = console(&mock)?;
    let dashboard = get(&client, "/").await.text();
    let token = csrf(&dashboard)?.to_owned();
    assert_request_rejections(&mock, &client, &token).await?;

    let cases = [
        (
            format!("/projects/{PROJECT}/targets"),
            format!("csrf={token}&url=https%3A%2F%2Fapp.example.test%2F&label=primary"),
        ),
        (format!("/projects/{PROJECT}/targets/{TARGET}/remove"), format!("csrf={token}")),
        (
            "/jobs/start".to_owned(),
            format!(
                "csrf={token}&target=https%3A%2F%2Fapp.example.test%2F&profile=standard&modules=nuclei%2Cheaders&skip=zap"
            ),
        ),
        (format!("/jobs/{JOB}/cancel"), format!("csrf={token}")),
        (
            format!("/findings/{FINDING}/triage"),
            format!(
                "csrf={token}&state=validated&reason=manual+proof&evidence_ids_json=%5B%22{EVIDENCE_ID}%22%5D"
            ),
        ),
    ];
    for (path, body) in cases {
        let response = post_form(&client, &path, CONSOLE_ORIGIN, body).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "mutation failed at {path}");
        assert_eq!(response.header("cache-control"), Some("no-store"));
    }

    let commands: Vec<_> = mock
        .captured()?
        .into_iter()
        .filter_map(|request| match request.operation {
            ControlOperationV1::Command(command) => Some(command),
            ControlOperationV1::Query(_) => None,
        })
        .collect();
    assert_eq!(commands.len(), 5);
    assert!(matches!(
        &commands[0],
        ControlCommandV1::AddTarget { project_id, url, label }
            if project_id.to_string() == PROJECT
                && url == "https://app.example.test/"
                && label == "primary"
    ));
    assert!(matches!(
        &commands[2],
        ControlCommandV1::StartJob { target, profile, modules: Some(modules), skip }
            if target == "https://app.example.test/"
                && profile == "standard"
                && modules == &["nuclei", "headers"]
                && skip == &["zap"]
    ));
    assert!(matches!(
        &commands[4],
        ControlCommandV1::TransitionFinding { state, reason, evidence_ids, model_analysis_identity, .. }
            if state == "validated"
                && reason == "manual proof"
                && evidence_ids == &[EVIDENCE_ID]
                && model_analysis_identity.is_none()
    ));

    let denied = post_form(
        &client,
        &format!("/projects/{PROJECT}/targets"),
        CONSOLE_ORIGIN,
        format!("csrf={token}&url=https%3A%2F%2Foutside.example%2F&label=outside"),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::BAD_GATEWAY);
    assert!(denied.text().contains("Target is outside the active engagement."));
    Ok(())
}

#[tokio::test]
async fn client_rejects_authenticated_response_identity_drift_without_secret_output() -> Result<()>
{
    let mock = MockControl::start(Fault::WrongPrincipal).await?;
    let client = ControlClient::new(config(&mock)?)?;
    let error = client.query(ControlQueryV1::GetEngagement).await.expect_err("identity mismatch");
    let message = error.to_string();
    assert!(message.contains("response identity did not match"));
    assert!(!message.contains(&test_bearer()));
    Ok(())
}

#[tokio::test]
async fn client_rejects_redirect_media_type_and_response_limit_drift() -> Result<()> {
    for (fault, expected) in [
        (Fault::Redirect, "redirects are not allowed"),
        (Fault::WrongContentType, "did not use JSON"),
        (Fault::Oversized, "exceeded the console limit"),
    ] {
        let mock = MockControl::start(fault).await?;
        let client = ControlClient::new(config(&mock)?)?;
        let error = client.query(ControlQueryV1::GetEngagement).await.expect_err(expected);
        let message = error.to_string();
        assert!(message.contains(expected), "unexpected error for {fault:?}: {message}");
        assert!(!message.contains(&test_bearer()));
    }
    Ok(())
}

#[test]
fn process_refuses_an_absent_bearer_before_listening() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_scorchkit-console"))
        .env_clear()
        .env("SCORCHKIT_CONSOLE_CONTROL_URL", "http://127.0.0.1:7444")
        .env("SCORCHKIT_CONSOLE_ENGAGEMENT_ID", ENGAGEMENT)
        .env("SCORCHKIT_CONSOLE_TOKEN_ENV", "MISSING_TEST_BEARER")
        .output()
        .context("console process must execute")?;
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("configured console token is absent"));
    assert!(!error.contains("MISSING_TEST_BEARER"));
    Ok(())
}
