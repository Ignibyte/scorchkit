//! Rustal routes, request guards, and exact control-command adaptation.

use std::fmt::Write as _;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header;
use hyper::{Method, Response, StatusCode};
use rand::RngExt;
use rustal::app::{App, get, post};
use rustal::config::AppConfig;
use rustal::extractors::{
    ExtractorError, Form, FormConfig, FromRequestParts, IntoHandler, Path, State,
};
use rustal::middleware::{BodyLimitLayer, TimeoutLayer, TracingLayer};
use rustal::middleware::{BoxCloneService, BoxFuture};
use rustal::router::RouterError;
use rustal::security::SecurityHeadersLayer;
use scorchkit_control::{
    CONTROL_MAX_TRIAGE_REFERENCES, ControlCommandV1, ControlQueryV1, ControlResultV1, PageRequestV1,
};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tower::{Layer, Service};
use uuid::Uuid;

use crate::client::{ControlClient, control_error, local_request_error};
use crate::config::{ConsoleConfig, MAX_BROWSER_EVENTS, MAX_FORM_BYTES, MAX_RENDERED_PAGE_BYTES};
use crate::event_mirror::{EventMirror, ReplayError};
use crate::render::{self, PageChrome};

const PAGE_SIZE: u16 = 100;

/// Shared server state. Its `Debug` implementation never exposes the bearer or CSRF value.
#[derive(Clone)]
pub struct ConsoleState {
    config: ConsoleConfig,
    client: ControlClient,
    mirror: EventMirror,
    csrf: String,
}

impl std::fmt::Debug for ConsoleState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsoleState")
            .field("config", &self.config)
            .field("client", &self.client)
            .field("mirror", &self.mirror)
            .field("csrf", &"<redacted>")
            .finish()
    }
}

impl ConsoleState {
    /// Construct server state and a fresh process-scoped CSRF value.
    ///
    /// # Errors
    ///
    /// Returns a safe error if the authenticated control client cannot be built.
    pub fn new(config: ConsoleConfig) -> Result<Self> {
        let client = ControlClient::new(config.clone())?;
        let mut bytes = [0_u8; 32];
        rand::rng().fill(&mut bytes);
        Ok(Self { config, client, mirror: EventMirror::default(), csrf: hex::encode(bytes) })
    }

    /// Clone the authenticated client for the background event worker.
    #[must_use]
    pub fn client(&self) -> ControlClient {
        self.client.clone()
    }

    /// Clone the bounded event mirror for the background event worker.
    #[must_use]
    pub fn mirror(&self) -> EventMirror {
        self.mirror.clone()
    }
}

/// Build the loopback-only Rustal app with all console routes and middleware.
///
/// # Errors
///
/// Returns a build error before listening when routes, middleware, or configuration are invalid.
pub fn build_app(state: ConsoleState) -> Result<App> {
    let mut config = AppConfig::default();
    config.server.host = state.config.bind.ip().to_string();
    config.server.port = state.config.bind.port();
    config.security.csp_enabled = true;
    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        .clone_into(&mut config.security.csp_directives);
    config.security.hsts_enabled = false;
    "DENY".clone_into(&mut config.security.x_frame_options);
    "same-origin".clone_into(&mut config.security.referrer_policy);

    let security = SecurityHeadersLayer::new(config.security.clone());
    let mut app = App::builder();
    let _ = app
        .config(config)
        .state(state)
        .state(FormConfig::default().max_body_size(MAX_FORM_BYTES as u64))
        .route("/", get(dashboard.into_handler()))
        .route("/projects/:id", get(project.into_handler()))
        .route("/findings/:id", get(finding.into_handler()))
        .route("/jobs/:id", get(job.into_handler()))
        .route("/events", get(events.into_handler()))
        .route("/assets/console.css", get(css.into_handler()))
        .route("/assets/console.js", get(javascript.into_handler()))
        .route("/projects/:id/targets", post(add_target.into_handler()))
        .route(
            "/projects/:project_id/targets/:target_id/remove",
            post(remove_target.into_handler()),
        )
        .route("/jobs/start", post(start_job.into_handler()))
        .route("/jobs/:id/cancel", post(cancel_job.into_handler()))
        .route("/findings/:id/triage", post(triage_finding.into_handler()))
        .middleware(TimeoutLayer::new(Duration::from_secs(15)))
        .middleware(BodyLimitLayer::new(MAX_FORM_BYTES))
        .middleware(security)
        .middleware(TracingLayer::new())
        .middleware(ConsoleErrorLayer);
    app.build().map_err(Into::into)
}

#[derive(Debug, Clone)]
struct RequestMeta {
    method: Method,
    host: Option<String>,
    origin: Option<String>,
    fetch_site: Option<String>,
    last_event_id: Option<String>,
    query: Option<String>,
}

impl FromRequestParts for RequestMeta {
    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
    ) -> Pin<Box<dyn Future<Output = Result<Self, ExtractorError>> + Send + '_>> {
        Box::pin(async move {
            Ok(Self {
                method: parts.method.clone(),
                host: header_text(&parts.headers, header::HOST),
                origin: header_text(&parts.headers, header::ORIGIN),
                fetch_site: header_text(&parts.headers, HeaderValueName::SEC_FETCH_SITE),
                last_event_id: header_text(&parts.headers, HeaderValueName::LAST_EVENT_ID),
                query: parts.uri.query().map(str::to_owned),
            })
        })
    }
}

struct HeaderValueName;

impl HeaderValueName {
    const SEC_FETCH_SITE: header::HeaderName = header::HeaderName::from_static("sec-fetch-site");
    const LAST_EVENT_ID: header::HeaderName = header::HeaderName::from_static("last-event-id");
}

fn header_text(headers: &header::HeaderMap, name: header::HeaderName) -> Option<String> {
    headers.get(name).and_then(|value| value.to_str().ok()).map(str::to_owned)
}

#[derive(Debug, Deserialize)]
struct AddTargetForm {
    csrf: String,
    url: String,
    #[serde(default)]
    label: String,
}

#[derive(Debug, Deserialize)]
struct CsrfForm {
    csrf: String,
}

#[derive(Debug, Deserialize)]
struct StartJobForm {
    csrf: String,
    target: String,
    profile: String,
    #[serde(default)]
    modules: String,
    #[serde(default)]
    skip: String,
}

#[derive(Debug, Deserialize)]
struct TriageForm {
    csrf: String,
    state: String,
    reason: String,
    evidence_ids_json: String,
}

#[derive(Debug, Deserialize)]
struct TargetPath {
    project_id: Uuid,
    target_id: Uuid,
}

async fn dashboard(
    State(state): State<ConsoleState>,
    meta: RequestMeta,
) -> Result<Response<Full<Bytes>>, RouterError> {
    guard_get(&state, &meta)?;
    let page = page();
    let (engagement, projects, jobs) = tokio::try_join!(
        state.client.query(ControlQueryV1::GetEngagement),
        state.client.query(ControlQueryV1::ListProjects { page: page.clone() }),
        state.client.query(ControlQueryV1::ListJobs { page }),
    )
    .map_err(|error| handler_failure("Control API unavailable", &error))?;
    let engagement = expect_engagement(engagement)?;
    let projects = expect_projects(projects)?;
    let jobs = expect_jobs(jobs)?;
    let chrome = chrome(&state, parse_status(meta.query.as_deref())).await;
    html(
        StatusCode::OK,
        render::dashboard(chrome, engagement, projects, jobs).map_err(anyhow_handler)?,
    )
}

async fn project(
    State(state): State<ConsoleState>,
    meta: RequestMeta,
    Path(id): Path<Uuid>,
) -> Result<Response<Full<Bytes>>, RouterError> {
    guard_get(&state, &meta)?;
    let page = page();
    let (project, targets, findings, report) = tokio::try_join!(
        state.client.query(ControlQueryV1::GetProject { id }),
        state.client.query(ControlQueryV1::ListTargets { project_id: id, page: page.clone() }),
        state.client.query(ControlQueryV1::ListFindings { project_id: id, page }),
        state.client.query(ControlQueryV1::GetProjectReport { project_id: id }),
    )
    .map_err(|error| handler_failure("Project unavailable", &error))?;
    html(
        StatusCode::OK,
        render::project(
            chrome(&state, parse_status(meta.query.as_deref())).await,
            expect_project(project)?,
            expect_targets(targets)?,
            &expect_findings(findings)?,
            &expect_report(report)?,
        )
        .map_err(anyhow_handler)?,
    )
}

async fn finding(
    State(state): State<ConsoleState>,
    meta: RequestMeta,
    Path(id): Path<Uuid>,
) -> Result<Response<Full<Bytes>>, RouterError> {
    guard_get(&state, &meta)?;
    let finding = expect_finding(
        state
            .client
            .query(ControlQueryV1::GetFinding { id })
            .await
            .map_err(|error| handler_failure("Finding unavailable", &error))?,
    )?;
    let evidence = expect_evidence(
        state
            .client
            .query(ControlQueryV1::ListEvidence { finding_id: id, page: page() })
            .await
            .map_err(|error| handler_failure("Evidence unavailable", &error))?,
    )?;
    html(
        StatusCode::OK,
        render::finding(
            chrome(&state, parse_status(meta.query.as_deref())).await,
            finding,
            evidence,
        )
        .map_err(anyhow_handler)?,
    )
}

async fn job(
    State(state): State<ConsoleState>,
    meta: RequestMeta,
    Path(id): Path<Uuid>,
) -> Result<Response<Full<Bytes>>, RouterError> {
    guard_get(&state, &meta)?;
    let job = expect_job(
        state
            .client
            .query(ControlQueryV1::GetJob { id })
            .await
            .map_err(|error| handler_failure("Job unavailable", &error))?,
    )?;
    html(
        StatusCode::OK,
        render::job(chrome(&state, parse_status(meta.query.as_deref())).await, job)
            .map_err(anyhow_handler)?,
    )
}

async fn events(
    State(state): State<ConsoleState>,
    meta: RequestMeta,
) -> Result<Response<Full<Bytes>>, RouterError> {
    guard_get(&state, &meta)?;
    let query_after = parse_after(meta.query.as_deref())?;
    let header_after = meta
        .last_event_id
        .as_deref()
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|_| response_error(StatusCode::BAD_REQUEST, "Invalid event cursor"))?;
    if header_after.is_some_and(|value| value < query_after) {
        return Err(response_error(StatusCode::BAD_REQUEST, "Invalid event cursor"));
    }
    let after = header_after.unwrap_or(query_after);
    let body = match state.mirror.replay(after, MAX_BROWSER_EVENTS).await {
        Ok(batch) => {
            browser_sse(&batch.events, batch.newest, batch.connected).map_err(anyhow_handler)?
        }
        Err(ReplayError::Expired { oldest }) => format!(
            "retry: 5000\n\nevent: reset\ndata: {{\"reason\":\"cursor_expired\",\"oldest\":{oldest}}}\n\n"
        ),
        Err(ReplayError::Future { newest }) => format!(
            "retry: 5000\n\nevent: reset\ndata: {{\"reason\":\"cursor_future\",\"newest\":{newest}}}\n\n"
        ),
    };
    response(
        StatusCode::OK,
        "text/event-stream; charset=utf-8",
        body,
        &[("cache-control", "no-store"), ("x-accel-buffering", "no")],
    )
}

async fn css(
    State(state): State<ConsoleState>,
    meta: RequestMeta,
) -> Result<Response<Full<Bytes>>, RouterError> {
    guard_get(&state, &meta)?;
    response(
        StatusCode::OK,
        "text/css; charset=utf-8",
        include_str!("../assets/console.css").to_owned(),
        &[("cache-control", "no-store")],
    )
}

async fn javascript(
    State(state): State<ConsoleState>,
    meta: RequestMeta,
) -> Result<Response<Full<Bytes>>, RouterError> {
    guard_get(&state, &meta)?;
    response(
        StatusCode::OK,
        "text/javascript; charset=utf-8",
        include_str!("../assets/console.js").to_owned(),
        &[("cache-control", "no-store")],
    )
}

async fn add_target(
    State(state): State<ConsoleState>,
    meta: RequestMeta,
    Path(project_id): Path<Uuid>,
    Form(form): Form<AddTargetForm>,
) -> Result<Response<Full<Bytes>>, RouterError> {
    guard_mutation(&state, &meta, &form.csrf)?;
    let _ = state
        .client
        .command(ControlCommandV1::AddTarget { project_id, url: form.url, label: form.label })
        .await
        .map_err(|error| handler_failure("Target registration denied", &error))?;
    redirect(&format!("/projects/{project_id}?status=target-added"))
}

async fn remove_target(
    State(state): State<ConsoleState>,
    meta: RequestMeta,
    Path(path): Path<TargetPath>,
    Form(form): Form<CsrfForm>,
) -> Result<Response<Full<Bytes>>, RouterError> {
    guard_mutation(&state, &meta, &form.csrf)?;
    let _ = state
        .client
        .command(ControlCommandV1::RemoveTarget {
            project_id: path.project_id,
            target_id: path.target_id,
        })
        .await
        .map_err(|error| handler_failure("Target removal denied", &error))?;
    redirect(&format!("/projects/{}?status=target-removed", path.project_id))
}

async fn start_job(
    State(state): State<ConsoleState>,
    meta: RequestMeta,
    Form(form): Form<StartJobForm>,
) -> Result<Response<Full<Bytes>>, RouterError> {
    guard_mutation(&state, &meta, &form.csrf)?;
    let modules = parse_selectors(&form.modules)
        .map_err(|_| response_error(StatusCode::BAD_REQUEST, "Invalid module selection"))?;
    let skip = parse_selectors(&form.skip)
        .map_err(|_| response_error(StatusCode::BAD_REQUEST, "Invalid module selection"))?
        .unwrap_or_default();
    let job = expect_job(
        state
            .client
            .command(ControlCommandV1::StartJob {
                target: form.target,
                profile: form.profile,
                modules,
                skip,
            })
            .await
            .map_err(|error| handler_failure("Job start denied", &error))?,
    )?;
    redirect(&format!("/jobs/{}?status=job-started", job.id))
}

async fn cancel_job(
    State(state): State<ConsoleState>,
    meta: RequestMeta,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Result<Response<Full<Bytes>>, RouterError> {
    guard_mutation(&state, &meta, &form.csrf)?;
    let _ = state
        .client
        .command(ControlCommandV1::CancelJob { id })
        .await
        .map_err(|error| handler_failure("Cancellation denied", &error))?;
    redirect(&format!("/jobs/{id}?status=job-cancelled"))
}

async fn triage_finding(
    State(state): State<ConsoleState>,
    meta: RequestMeta,
    Path(id): Path<Uuid>,
    Form(form): Form<TriageForm>,
) -> Result<Response<Full<Bytes>>, RouterError> {
    guard_mutation(&state, &meta, &form.csrf)?;
    let evidence_ids = parse_evidence_ids(&form.evidence_ids_json)?;
    let _ = state
        .client
        .command(ControlCommandV1::TransitionFinding {
            finding_id: id,
            state: form.state,
            reason: form.reason,
            evidence_ids,
            model_analysis_identity: None,
        })
        .await
        .map_err(|error| handler_failure("Triage decision denied", &error))?;
    redirect(&format!("/findings/{id}?status=triage-updated"))
}

fn guard_get(state: &ConsoleState, meta: &RequestMeta) -> Result<(), RouterError> {
    if meta.method != Method::GET
        || meta.host.as_deref() != Some(state.config.browser_host.as_str())
    {
        tracing::warn!(
            event = "console.request.rejected",
            method_allowed = meta.method == Method::GET,
            host_allowed = meta.host.as_deref() == Some(state.config.browser_host.as_str()),
            "console request boundary rejected a read"
        );
        return Err(response_error(StatusCode::MISDIRECTED_REQUEST, "Request host was rejected"));
    }
    Ok(())
}

fn guard_mutation(
    state: &ConsoleState,
    meta: &RequestMeta,
    supplied_csrf: &str,
) -> Result<(), RouterError> {
    let method_allowed = meta.method == Method::POST;
    let host_allowed = meta.host.as_deref() == Some(state.config.browser_host.as_str());
    let origin_allowed = meta.origin.as_deref() == Some(state.config.browser_origin.as_str());
    let fetch_site_allowed = meta.fetch_site.as_deref().is_none_or(|value| value == "same-origin");
    let csrf_length_allowed = supplied_csrf.len() == state.csrf.len();
    let csrf_allowed =
        csrf_length_allowed && bool::from(supplied_csrf.as_bytes().ct_eq(state.csrf.as_bytes()));
    if !method_allowed || !host_allowed || !origin_allowed || !fetch_site_allowed || !csrf_allowed {
        tracing::warn!(
            event = "console.request.rejected",
            method_allowed,
            host_allowed,
            origin_present = meta.origin.is_some(),
            origin_allowed,
            fetch_site_allowed,
            csrf_length_allowed,
            csrf_allowed,
            "console request boundary rejected a mutation"
        );
        return Err(response_error(StatusCode::FORBIDDEN, "Mutation request was rejected"));
    }
    Ok(())
}

async fn chrome(state: &ConsoleState, status: Option<&str>) -> PageChrome {
    PageChrome {
        csrf: state.csrf.clone(),
        event_after: state.mirror.newest().await,
        message: status_message(status).to_owned(),
    }
}

fn status_message(status: Option<&str>) -> &'static str {
    match status {
        Some("target-added") => "Target registered after control-policy authorization.",
        Some("target-removed") => "Target registration removed through the control API.",
        Some("job-started") => "Job accepted by the control API.",
        Some("job-cancelled") => "Cancellation request accepted by the control API.",
        Some("triage-updated") => "Triage decision appended through the control API.",
        _ => "",
    }
}

fn parse_status(query: Option<&str>) -> Option<&str> {
    query.and_then(|query| query.strip_prefix("status=")).filter(|value| !value.contains('&'))
}

fn parse_after(query: Option<&str>) -> Result<u64, RouterError> {
    match query {
        None | Some("") => Ok(0),
        Some(query) => query
            .strip_prefix("after=")
            .filter(|value| !value.is_empty() && !value.contains('&'))
            .ok_or_else(|| response_error(StatusCode::BAD_REQUEST, "Invalid event cursor"))?
            .parse::<u64>()
            .map_err(|_| response_error(StatusCode::BAD_REQUEST, "Invalid event cursor")),
    }
}

const fn page() -> PageRequestV1 {
    PageRequestV1 { cursor: None, limit: PAGE_SIZE }
}

fn parse_selectors(value: &str) -> Result<Option<Vec<String>>> {
    if value.is_empty() {
        return Ok(None);
    }
    let values: Vec<String> = value.split(',').map(str::trim).map(str::to_owned).collect();
    if values.is_empty()
        || values.len() > 256
        || values.iter().any(|value| {
            value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
        })
        || values.iter().collect::<std::collections::BTreeSet<_>>().len() != values.len()
    {
        bail!("invalid selector list");
    }
    Ok(Some(values))
}

fn parse_evidence_ids(value: &str) -> Result<Vec<String>, RouterError> {
    let values: Vec<String> = serde_json::from_str(value)
        .map_err(|_| response_error(StatusCode::BAD_REQUEST, "Invalid evidence selection"))?;
    if values.len() > CONTROL_MAX_TRIAGE_REFERENCES
        || values.iter().any(|value| {
            value.len() != 64
                || value.bytes().any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        })
        || values.iter().collect::<std::collections::BTreeSet<_>>().len() != values.len()
    {
        return Err(response_error(StatusCode::BAD_REQUEST, "Invalid evidence selection"));
    }
    Ok(values)
}

fn browser_sse(
    events: &[scorchkit_control::ControlEventV1],
    newest: u64,
    connected: bool,
) -> Result<String> {
    let mut body = "retry: 1500\n\n".to_owned();
    for event in events {
        let data = serde_json::to_string(event)?;
        write!(body, "event: control\nid: {}\ndata: {data}\n\n", event.sequence)
            .map_err(|_| anyhow!("failed to encode browser event"))?;
    }
    if events.is_empty() {
        write!(
            body,
            "event: heartbeat\ndata: {{\"newest\":{newest},\"connected\":{connected}}}\n\n"
        )
        .map_err(|_| anyhow!("failed to encode browser heartbeat"))?;
    }
    Ok(body)
}

fn html(status: StatusCode, body: String) -> Result<Response<Full<Bytes>>, RouterError> {
    if body.len() > MAX_RENDERED_PAGE_BYTES {
        return Err(anyhow_handler(anyhow!("rendered console page exceeded its output limit")));
    }
    response(status, "text/html; charset=utf-8", body, &[("cache-control", "no-store")])
}

fn response(
    status: StatusCode,
    content_type: &'static str,
    body: String,
    headers: &[(&'static str, &'static str)],
) -> Result<Response<Full<Bytes>>, RouterError> {
    let mut builder = Response::builder().status(status).header(header::CONTENT_TYPE, content_type);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Full::new(Bytes::from(body))).map_err(handler_err)
}

fn redirect(location: &str) -> Result<Response<Full<Bytes>>, RouterError> {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::new()))
        .map_err(handler_err)
}

fn handler_failure(title: &str, error: &anyhow::Error) -> RouterError {
    if local_request_error(error) {
        return response_error_with_title(
            StatusCode::BAD_REQUEST,
            title,
            "Request parameters were invalid.",
        );
    }
    let message = control_error(error)
        .map_or("The authenticated control API request could not be completed.", |error| {
            error.message.as_str()
        });
    response_error_with_title(StatusCode::BAD_GATEWAY, title, message)
}

fn response_error(status: StatusCode, message: &str) -> RouterError {
    response_error_with_title(status, "Request rejected", message)
}

fn response_error_with_title(status: StatusCode, title: &str, message: &str) -> RouterError {
    let response = html(status, render::error(title, message)).unwrap_or_else(|_| {
        Response::builder()
            .status(status)
            .body(Full::new(Bytes::from_static(b"ScorchKit Console request failed")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
    });
    RouterError::HandlerError(Box::new(ConsoleHttpError { response }))
}

#[derive(Debug)]
struct ConsoleHttpError {
    response: Response<Full<Bytes>>,
}

impl std::fmt::Display for ConsoleHttpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("console request rejected")
    }
}

impl std::error::Error for ConsoleHttpError {}

#[derive(Debug, Clone, Copy)]
struct ConsoleErrorLayer;

impl Layer<BoxCloneService> for ConsoleErrorLayer {
    type Service = ConsoleErrorService;

    fn layer(&self, inner: BoxCloneService) -> Self::Service {
        ConsoleErrorService { inner }
    }
}

#[derive(Debug, Clone)]
struct ConsoleErrorService {
    inner: BoxCloneService,
}

impl Service<hyper::Request<hyper::body::Incoming>> for ConsoleErrorService {
    type Response = Response<Full<Bytes>>;
    type Error = RouterError;
    type Future = BoxFuture;

    fn poll_ready(
        &mut self,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        let future = self.inner.call(request);
        Box::pin(async move {
            match future.await {
                Err(RouterError::HandlerError(error)) => match error.downcast::<ConsoleHttpError>()
                {
                    Ok(error) => Ok(error.response),
                    Err(error) => match error.downcast::<ExtractorError>() {
                        Ok(error) => Ok(extractor_error_response(&error)),
                        Err(error) => Err(RouterError::HandlerError(error)),
                    },
                },
                outcome => outcome,
            }
        })
    }
}

fn extractor_error_response(error: &ExtractorError) -> Response<Full<Bytes>> {
    let status = match error {
        ExtractorError::FormBodyTooLarge { .. } | ExtractorError::JsonBodyTooLarge { .. } => {
            StatusCode::PAYLOAD_TOO_LARGE
        }
        ExtractorError::MissingState { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    let message = if status == StatusCode::PAYLOAD_TOO_LARGE {
        "Request body exceeded the console limit"
    } else if status == StatusCode::INTERNAL_SERVER_ERROR {
        "ScorchKit Console could not process this request"
    } else {
        "Request parameters were invalid"
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(render::error("Request rejected", message))))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"Request rejected"))))
}

fn handler_err(error: impl std::error::Error + Send + Sync + 'static) -> RouterError {
    RouterError::HandlerError(Box::new(error))
}

fn anyhow_handler(error: anyhow::Error) -> RouterError {
    RouterError::HandlerError(error.into_boxed_dyn_error())
}

fn wrong_result() -> RouterError {
    response_error(StatusCode::BAD_GATEWAY, "Control API result shape did not match the request")
}

fn expect_engagement(
    value: ControlResultV1,
) -> Result<scorchkit_control::EngagementViewV1, RouterError> {
    if let ControlResultV1::Engagement(value) = value { Ok(value) } else { Err(wrong_result()) }
}
fn expect_projects(
    value: ControlResultV1,
) -> Result<scorchkit_control::PageV1<scorchkit_control::ProjectViewV1>, RouterError> {
    if let ControlResultV1::Projects(value) = value { Ok(value) } else { Err(wrong_result()) }
}
fn expect_project(value: ControlResultV1) -> Result<scorchkit_control::ProjectViewV1, RouterError> {
    if let ControlResultV1::Project(value) = value { Ok(value) } else { Err(wrong_result()) }
}
fn expect_targets(
    value: ControlResultV1,
) -> Result<scorchkit_control::PageV1<scorchkit_control::TargetViewV1>, RouterError> {
    if let ControlResultV1::Targets(value) = value { Ok(value) } else { Err(wrong_result()) }
}
fn expect_jobs(
    value: ControlResultV1,
) -> Result<scorchkit_control::PageV1<scorchkit_control::JobViewV1>, RouterError> {
    if let ControlResultV1::Jobs(value) = value { Ok(value) } else { Err(wrong_result()) }
}
fn expect_job(value: ControlResultV1) -> Result<scorchkit_control::JobViewV1, RouterError> {
    if let ControlResultV1::Job(value) = value { Ok(value) } else { Err(wrong_result()) }
}
fn expect_findings(
    value: ControlResultV1,
) -> Result<scorchkit_control::PageV1<scorchkit_control::FindingViewV1>, RouterError> {
    if let ControlResultV1::Findings(value) = value { Ok(value) } else { Err(wrong_result()) }
}
fn expect_finding(value: ControlResultV1) -> Result<scorchkit_control::FindingViewV1, RouterError> {
    if let ControlResultV1::Finding(value) = value { Ok(value) } else { Err(wrong_result()) }
}
fn expect_evidence(
    value: ControlResultV1,
) -> Result<Vec<scorchkit_control::EvidenceViewV1>, RouterError> {
    if let ControlResultV1::Evidence(value) = value { Ok(value.items) } else { Err(wrong_result()) }
}
fn expect_report(
    value: ControlResultV1,
) -> Result<scorchkit_control::ProjectReportViewV1, RouterError> {
    if let ControlResultV1::Report(value) = value { Ok(value) } else { Err(wrong_result()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENGAGEMENT: &str = "b1382ed4-0ad0-45a2-afd6-550c0d947566";

    fn test_bearer() -> String {
        ["console", "test", "bearer", "value", "not", "secret"].join("-")
    }

    fn state() -> Result<ConsoleState> {
        ConsoleState::new(ConsoleConfig::new(
            "127.0.0.1:7445",
            "http://127.0.0.1:7444",
            ENGAGEMENT,
            &test_bearer(),
        )?)
    }

    #[test]
    fn host_origin_fetch_site_and_csrf_are_independent_guards() -> Result<()> {
        let state = state()?;
        let valid = RequestMeta {
            method: Method::POST,
            host: Some(state.config.browser_host.clone()),
            origin: Some(state.config.browser_origin.clone()),
            fetch_site: Some("same-origin".to_owned()),
            last_event_id: None,
            query: None,
        };
        assert!(guard_mutation(&state, &valid, &state.csrf).is_ok());
        let mut cases = Vec::new();
        let mut wrong_method = valid.clone();
        wrong_method.method = Method::GET;
        cases.push((wrong_method, state.csrf.clone()));
        let mut wrong_host = valid.clone();
        wrong_host.host = Some("localhost:7445".to_owned());
        cases.push((wrong_host, state.csrf.clone()));
        let mut wrong_origin = valid.clone();
        wrong_origin.origin = Some("http://evil.test".to_owned());
        cases.push((wrong_origin, state.csrf.clone()));
        let mut cross_site = valid;
        cross_site.fetch_site = Some("cross-site".to_owned());
        cases.push((cross_site, state.csrf.clone()));
        cases.push((cases[0].0.clone(), "wrong".to_owned()));
        for (meta, csrf) in cases {
            assert!(guard_mutation(&state, &meta, &csrf).is_err());
        }
        Ok(())
    }

    #[test]
    fn selector_lists_are_trimmed_unique_and_bounded() -> Result<()> {
        assert_eq!(parse_selectors("")?, None);
        assert_eq!(
            parse_selectors("nuclei, semgrep")?,
            Some(vec!["nuclei".to_owned(), "semgrep".to_owned()])
        );
        for invalid in ["nuclei,nuclei", "nuclei,,semgrep", "bad\nname"] {
            assert!(parse_selectors(invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn closed_status_vocabulary_cannot_echo_query_input() {
        assert_eq!(status_message(Some("job-started")), "Job accepted by the control API.");
        assert_eq!(status_message(Some("<script>alert(1)</script>")), "");
        assert_eq!(parse_status(Some("status=job-started")), Some("job-started"));
        assert_eq!(parse_status(Some("status=job-started&extra=1")), None);
        assert!(parse_after(None).is_ok_and(|value| value == 0));
        assert!(parse_after(Some("after=42")).is_ok_and(|value| value == 42));
        for invalid in ["after=", "after=-1", "after=1&after=2", "status=job-started"] {
            assert!(parse_after(Some(invalid)).is_err());
        }
    }

    #[test]
    fn evidence_selection_is_json_unique_and_bounded() {
        let digest = "a".repeat(64);
        assert!(parse_evidence_ids("[]").is_ok_and(|values| values.is_empty()));
        let encoded = serde_json::to_string(&[&digest]);
        assert!(encoded.is_ok_and(|value| {
            parse_evidence_ids(&value).is_ok_and(|values| values == [digest.clone()])
        }));
        for invalid in ["not-json", "[\"\"]", "[\"evidence:1\"]", "[\"bad\\nidentity\"]"] {
            assert!(parse_evidence_ids(invalid).is_err());
        }
        let duplicate = serde_json::to_string(&[&digest, &digest]);
        assert!(duplicate.is_ok_and(|value| parse_evidence_ids(&value).is_err()));
        let too_many = serde_json::to_string(
            &(0..=CONTROL_MAX_TRIAGE_REFERENCES)
                .map(|index| format!("{index:064x}"))
                .collect::<Vec<_>>(),
        );
        assert!(too_many.is_ok_and(|value| parse_evidence_ids(&value).is_err()));
    }
}
