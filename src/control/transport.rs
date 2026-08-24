//! Bearer-authenticated loopback HTTP transport for the control service.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Router;
use chrono::Utc;
use futures_util::stream;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::service::ControlService;
use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::policy::Engagement;
use crate::storage::webhooks::PostgresWebhookStore;
use crate::webhooks::WebhookService;
use scorchkit_control::{
    ControlErrorCodeV1, ControlErrorV1, ControlEventV1, ControlQueryV1, ControlRequestV1,
    ControlResponseOutcomeV1, ControlResponseV1, EventCursorV1,
};

const DESCRIPTION_PATH: &str = "/v1/description";
const CONTROL_PATH: &str = "/v1/control";
const EVENTS_PATH: &str = "/v1/events";
const CLAIMED_SUBJECT_HEADER: &str = "x-scorchkit-subject";
const CLAIMED_ENGAGEMENT_HEADER: &str = "x-scorchkit-engagement-id";
const LAST_EVENT_ID_HEADER: &str = "last-event-id";
const MIN_BEARER_TOKEN_BYTES: usize = 32;
const MAX_BEARER_TOKEN_BYTES: usize = 4_096;
const MAX_EVENT_QUERY_BYTES: usize = 1_024;
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Credential-resolved listener configuration that never retains the bearer token itself.
struct PreparedControlApi {
    bind: SocketAddr,
    subject: String,
    engagement_id: Uuid,
    token_digest: [u8; 32],
    max_body_bytes: usize,
    max_response_bytes: usize,
    max_concurrent_requests: usize,
    max_subscribers: usize,
    replay_page_size: u16,
}

impl std::fmt::Debug for PreparedControlApi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedControlApi")
            .field("bind", &self.bind)
            .field("subject", &self.subject)
            .field("engagement_id", &self.engagement_id)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .field("max_subscribers", &self.max_subscribers)
            .field("replay_page_size", &self.replay_page_size)
            .finish_non_exhaustive()
    }
}

impl PreparedControlApi {
    fn from_app_config(config: &AppConfig) -> Result<Self> {
        Self::from_app_config_with(config, |name| std::env::var(name).ok())
    }

    fn from_app_config_with(
        config: &AppConfig,
        mut resolve_environment: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self> {
        config.control_api.validate().map_err(ScorchError::Config)?;
        let engagement = config.engagement.as_ref().ok_or_else(|| {
            ScorchError::Config(
                "control API requires an explicit engagement authorization".to_string(),
            )
        })?;
        if !engagement.enabled {
            return Err(ScorchError::Config(
                "control API configured engagement is disabled".to_string(),
            ));
        }
        if engagement.expires_at.is_some_and(|expiry| expiry <= Utc::now()) {
            return Err(ScorchError::Config(
                "control API configured engagement is expired".to_string(),
            ));
        }
        let configured_engagement = config.control_api.engagement_id.ok_or_else(|| {
            ScorchError::Config("control API requires an exact engagement binding".to_string())
        })?;
        if configured_engagement != engagement.id {
            return Err(ScorchError::Config(
                "control API principal is not bound to the configured engagement".to_string(),
            ));
        }
        let token_environment = config.control_api.token_env.as_deref().ok_or_else(|| {
            ScorchError::Config("control API requires a token environment".to_string())
        })?;
        let token = Zeroizing::new(resolve_environment(token_environment).ok_or_else(|| {
            ScorchError::Config(format!(
                "control API token environment '{token_environment}' is unavailable"
            ))
        })?);
        validate_token(&token).map_err(|message| {
            ScorchError::Config(format!(
                "control API token environment '{token_environment}' {message}"
            ))
        })?;
        Ok(Self {
            bind: config.control_api.bind.ok_or_else(|| {
                ScorchError::Config("control API requires an explicit loopback bind".to_string())
            })?,
            subject: config.control_api.subject.clone().ok_or_else(|| {
                ScorchError::Config("control API requires a principal subject".to_string())
            })?,
            engagement_id: configured_engagement,
            token_digest: token_digest(&token),
            max_body_bytes: config.control_api.max_body_bytes,
            max_response_bytes: config.control_api.max_response_bytes,
            max_concurrent_requests: config.control_api.max_concurrent_requests,
            max_subscribers: config.control_api.max_subscribers,
            replay_page_size: config.control_api.default_page_size,
        })
    }
}

fn validate_token(token: &str) -> std::result::Result<(), &'static str> {
    if !(MIN_BEARER_TOKEN_BYTES..=MAX_BEARER_TOKEN_BYTES).contains(&token.len()) {
        return Err("must contain 32-4096 bytes");
    }
    if !token.is_ascii()
        || token.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err("must contain only non-whitespace printable ASCII");
    }
    Ok(())
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Cloneable HTTP adapter over one composed control service.
#[derive(Clone)]
struct ControlApiHost {
    inner: Arc<ControlApiHostInner>,
}

struct ControlApiHostInner {
    bind: SocketAddr,
    subject: String,
    engagement_id: Uuid,
    engagement: Arc<Engagement>,
    token_digest: [u8; 32],
    max_body_bytes: usize,
    max_response_bytes: usize,
    replay_page_size: u16,
    concurrency: Arc<Semaphore>,
    subscribers: Arc<Semaphore>,
    service: ControlService,
}

impl ControlApiHost {
    fn new(
        prepared: PreparedControlApi,
        service: ControlService,
        engagement: Arc<Engagement>,
    ) -> Result<Self> {
        if engagement.id != prepared.engagement_id
            || service.configured_engagement_id() != Some(prepared.engagement_id)
        {
            return Err(ScorchError::Config(
                "control API runtime composition does not match its principal binding".to_string(),
            ));
        }
        if !engagement.enabled || engagement.expires_at.is_some_and(|expiry| expiry <= Utc::now()) {
            return Err(ScorchError::Config(
                "control API runtime composition requires an enabled, unexpired engagement"
                    .to_string(),
            ));
        }
        Ok(Self {
            inner: Arc::new(ControlApiHostInner {
                bind: prepared.bind,
                subject: prepared.subject,
                engagement_id: prepared.engagement_id,
                engagement,
                token_digest: prepared.token_digest,
                max_body_bytes: prepared.max_body_bytes,
                max_response_bytes: prepared.max_response_bytes,
                replay_page_size: prepared.replay_page_size,
                concurrency: Arc::new(Semaphore::new(prepared.max_concurrent_requests)),
                subscribers: Arc::new(Semaphore::new(prepared.max_subscribers)),
                service,
            }),
        })
    }

    fn router(self) -> Router {
        Router::new().fallback(control_request).with_state(self)
    }

    async fn handle(&self, mut request: Request) -> Response {
        if !loopback_host(request.headers(), self.inner.bind.port()) {
            tracing::warn!(
                event = "control.api.request_rejected",
                reason = "host",
                method = %request.method(),
                path = request.uri().path(),
                "control API request rejected"
            );
            return self.error_response(
                StatusCode::FORBIDDEN,
                &ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "control API host is not loopback",
                ),
            );
        }
        if !self.authenticate(request.headers()) {
            tracing::warn!(
                event = "control.api.request_rejected",
                reason = "authentication",
                method = %request.method(),
                path = request.uri().path(),
                "control API request rejected"
            );
            return self.authentication_rejection();
        }
        request.headers_mut().remove(header::AUTHORIZATION);
        request.headers_mut().remove(CLAIMED_SUBJECT_HEADER);
        request.headers_mut().remove(CLAIMED_ENGAGEMENT_HEADER);
        if !self.inner.engagement.enabled
            || self.inner.engagement.id != self.inner.engagement_id
            || self.inner.engagement.expires_at.is_some_and(|expiry| expiry <= Utc::now())
        {
            tracing::warn!(
                event = "control.api.request_rejected",
                reason = "engagement",
                method = %request.method(),
                path = request.uri().path(),
                subject = %self.inner.subject,
                engagement_id = %self.inner.engagement_id,
                "control API request rejected"
            );
            return self.error_response(
                StatusCode::FORBIDDEN,
                &ControlErrorV1::new(
                    ControlErrorCodeV1::EngagementUnavailable,
                    "control API engagement binding is unavailable",
                ),
            );
        }
        tracing::info!(
            event = "control.api.authenticated_request",
            method = %request.method(),
            path = request.uri().path(),
            subject = %self.inner.subject,
            engagement_id = %self.inner.engagement_id,
            "authenticated control API request"
        );
        let Ok(_request_permit) = Arc::clone(&self.inner.concurrency).try_acquire_owned() else {
            return self.error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &ControlErrorV1::new(
                    ControlErrorCodeV1::Busy,
                    "control API request capacity is exhausted",
                )
                .retryable(),
            );
        };

        match (request.method().clone(), request.uri().path()) {
            (Method::GET, DESCRIPTION_PATH) if request.uri().query().is_none() => {
                self.description_response().await
            }
            (Method::POST, CONTROL_PATH) if request.uri().query().is_none() => {
                self.control_response(request).await
            }
            (Method::GET, EVENTS_PATH) => self.events_response(&request),
            (_, DESCRIPTION_PATH | CONTROL_PATH | EVENTS_PATH) => self.error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                &ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "control API method or query is not allowed for this route",
                ),
            ),
            _ => self.error_response(
                StatusCode::NOT_FOUND,
                &ControlErrorV1::new(
                    ControlErrorCodeV1::NotFound,
                    "control API route was not found",
                ),
            ),
        }
    }

    fn authenticate(&self, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let Some(authorization) = values.next().and_then(|value| value.to_str().ok()) else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }
        let Some(token) = authorization.strip_prefix("Bearer ") else {
            return false;
        };
        if validate_token(token).is_err() {
            return false;
        }
        bool::from(token_digest(token).ct_eq(&self.inner.token_digest))
    }

    async fn description_response(&self) -> Response {
        let request =
            ControlRequestV1::query(ControlQueryV1::Describe, Some(self.inner.engagement_id));
        let response = self
            .inner
            .service
            .execute_authenticated(self.inner.subject.clone(), self.inner.engagement_id, request)
            .await;
        self.service_response(&response)
    }

    async fn control_response(&self, request: Request) -> Response {
        if !json_content_type(request.headers()) {
            return self.error_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "control API requests require application/json",
                ),
            );
        }
        if content_length_exceeds(request.headers(), self.inner.max_body_bytes) {
            return self.body_limit_response();
        }
        let bytes = match read_bounded_body(request.into_body(), self.inner.max_body_bytes).await {
            Ok(bytes) => bytes,
            Err(BodyReadFailure::Limit) => return self.body_limit_response(),
            Err(BodyReadFailure::Timeout) => {
                return self.error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    &ControlErrorV1::new(
                        ControlErrorCodeV1::Busy,
                        "control API request body timed out",
                    )
                    .retryable(),
                );
            }
        };
        let Ok(request) = serde_json::from_slice::<ControlRequestV1>(&bytes) else {
            return self.error_response(
                StatusCode::BAD_REQUEST,
                &ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "control API request JSON is invalid",
                ),
            );
        };
        let response = self
            .inner
            .service
            .execute_authenticated(self.inner.subject.clone(), self.inner.engagement_id, request)
            .await;
        self.service_response(&response)
    }

    fn events_response(&self, request: &Request) -> Response {
        let cursor = match event_cursor(
            request.headers(),
            request.uri().query(),
            self.inner.replay_page_size,
        ) {
            Ok(cursor) => cursor,
            Err(error) => return self.error_response(error_status(error.code), &error),
        };
        let Ok(subscriber_permit) = Arc::clone(&self.inner.subscribers).try_acquire_owned() else {
            return self.error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &ControlErrorV1::new(
                    ControlErrorCodeV1::Busy,
                    "control API event subscriber capacity is exhausted",
                )
                .retryable(),
            );
        };
        let receiver = self.inner.service.journal().subscribe();
        let replay = match self.inner.service.journal().replay(cursor) {
            Ok(replay) => replay,
            Err(error) => return self.error_response(error_status(error.code), &error),
        };
        let stream = stream::unfold(
            EventStreamState {
                pending: replay.events.into(),
                replay_has_more: replay.has_more,
                replay_limit: cursor.limit,
                last_sequence: cursor.after_sequence,
                receiver,
                journal: Arc::clone(self.inner.service.journal()),
                engagement: Arc::clone(&self.inner.engagement),
                engagement_id: self.inner.engagement_id,
                finished: false,
                _permit: subscriber_permit,
            },
            next_stream_event,
        );
        let mut response = Sse::new(stream)
            .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("keep-alive"))
            .into_response();
        secure_response_headers(response.headers_mut());
        response
    }

    fn service_response(&self, response: &ControlResponseV1) -> Response {
        let status = match &response.result {
            ControlResponseOutcomeV1::Success(_) => StatusCode::OK,
            ControlResponseOutcomeV1::Error(error) => error_status(error.code),
        };
        self.json_response(status, response)
    }

    fn body_limit_response(&self) -> Response {
        self.error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            &ControlErrorV1::new(
                ControlErrorCodeV1::LimitExceeded,
                "control API request body exceeds the configured limit",
            ),
        )
    }

    fn authentication_rejection(&self) -> Response {
        let mut response = self.error_response(
            StatusCode::UNAUTHORIZED,
            &ControlErrorV1::new(
                ControlErrorCodeV1::Unauthenticated,
                "control API authentication is required",
            ),
        );
        response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        response
    }

    fn error_response(&self, status: StatusCode, error: &ControlErrorV1) -> Response {
        self.json_response(status, error)
    }

    fn json_response(&self, status: StatusCode, value: &impl serde::Serialize) -> Response {
        match serde_json::to_vec(value) {
            Ok(bytes) if bytes.len() <= self.inner.max_response_bytes => {
                bounded_json_response(status, bytes)
            }
            _ => bounded_json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                br#"{"code":"internal","message":"control API response serialization failed","retryable":false}"#.to_vec(),
            ),
        }
    }
}

async fn control_request(State(host): State<ControlApiHost>, request: Request) -> Response {
    host.handle(request).await
}

struct EventStreamState {
    pending: VecDeque<ControlEventV1>,
    replay_has_more: bool,
    replay_limit: u16,
    last_sequence: u64,
    receiver: broadcast::Receiver<ControlEventV1>,
    journal: Arc<super::journal::ControlEventJournal>,
    engagement: Arc<Engagement>,
    engagement_id: Uuid,
    finished: bool,
    _permit: OwnedSemaphorePermit,
}

async fn next_stream_event(
    mut state: EventStreamState,
) -> Option<(std::result::Result<Event, Infallible>, EventStreamState)> {
    loop {
        if state.finished {
            return None;
        }
        if !state.engagement.enabled
            || state.engagement.id != state.engagement_id
            || state.engagement.expires_at.is_some_and(|expiry| expiry <= Utc::now())
        {
            state.finished = true;
            return Some((
                Ok(sse_error(&ControlErrorV1::new(
                    ControlErrorCodeV1::EngagementUnavailable,
                    "control API engagement expired during event delivery",
                ))),
                state,
            ));
        }
        if let Some(event) = state.pending.pop_front() {
            if event.sequence <= state.last_sequence {
                continue;
            }
            if event.sequence != state.last_sequence.saturating_add(1) {
                state.finished = true;
                return Some((Ok(sse_error(&reset_required())), state));
            }
            state.last_sequence = event.sequence;
            return Some((Ok(sse_event(&event)), state));
        }
        if state.replay_has_more {
            if let Err(error) = refill_replay(&mut state) {
                state.finished = true;
                return Some((Ok(sse_error(&error)), state));
            }
            continue;
        }
        match state.receiver.recv().await {
            Ok(event) if event.sequence <= state.last_sequence => {}
            Ok(event) if event.sequence == state.last_sequence.saturating_add(1) => {
                state.last_sequence = event.sequence;
                return Some((Ok(sse_event(&event)), state));
            }
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                state.replay_has_more = true;
                if let Err(error) = refill_replay(&mut state) {
                    state.finished = true;
                    return Some((Ok(sse_error(&error)), state));
                }
            }
            Err(broadcast::error::RecvError::Closed) => return None,
        }
    }
}

fn refill_replay(state: &mut EventStreamState) -> std::result::Result<(), ControlErrorV1> {
    let replay = state
        .journal
        .replay(EventCursorV1 { after_sequence: state.last_sequence, limit: state.replay_limit })?;
    state.pending = replay.events.into();
    state.replay_has_more = replay.has_more;
    Ok(())
}

fn reset_required() -> ControlErrorV1 {
    ControlErrorV1::new(
        ControlErrorCodeV1::EventCursorExpired,
        "control API event continuity was lost; replay from a retained cursor",
    )
}

fn sse_event(event: &ControlEventV1) -> Event {
    serde_json::to_string(event).map_or_else(
        |_| {
            sse_error(&ControlErrorV1::new(
                ControlErrorCodeV1::Internal,
                "control API event serialization failed",
            ))
        },
        |data| Event::default().event("control").id(event.sequence.to_string()).data(data),
    )
}

fn sse_error(error: &ControlErrorV1) -> Event {
    let data = serde_json::to_string(error).unwrap_or_else(|_| {
        "{\"code\":\"internal\",\"message\":\"control API stream failed\",\"retryable\":false}"
            .to_string()
    });
    Event::default().event("error").data(data)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyReadFailure {
    Limit,
    Timeout,
}

async fn read_bounded_body(
    body: Body,
    maximum: usize,
) -> std::result::Result<Bytes, BodyReadFailure> {
    match tokio::time::timeout(BODY_READ_TIMEOUT, to_bytes(body, maximum)).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(_)) => Err(BodyReadFailure::Limit),
        Err(_) => Err(BodyReadFailure::Timeout),
    }
}

fn content_length_exceeds(headers: &HeaderMap, maximum: usize) -> bool {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    let valid = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length <= maximum);
    !valid || values.next().is_some()
}

fn json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let valid = values
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    valid && values.next().is_none()
}

fn loopback_host(headers: &HeaderMap, configured_port: u16) -> bool {
    let mut values = headers.get_all(header::HOST).iter();
    let Some(authority) = values
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<axum::http::uri::Authority>().ok())
    else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let host = authority.host();
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    is_loopback
        && (configured_port == 0
            || authority.port_u16().is_some_and(|port| port == configured_port))
}

fn event_cursor(
    headers: &HeaderMap,
    query: Option<&str>,
    default_limit: u16,
) -> std::result::Result<EventCursorV1, ControlErrorV1> {
    let query = query.unwrap_or_default();
    if query.len() > MAX_EVENT_QUERY_BYTES {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::LimitExceeded,
            "control API event query exceeds its configured limit",
        ));
    }
    let mut event_ids = headers.get_all(LAST_EVENT_ID_HEADER).iter();
    let mut after_sequence = event_ids
        .next()
        .map(|value| {
            value.to_str().ok().and_then(|value| value.parse::<u64>().ok()).ok_or_else(|| {
                ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "control API Last-Event-ID is invalid",
                )
            })
        })
        .transpose()?;
    if event_ids.next().is_some() {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::InvalidRequest,
            "control API Last-Event-ID must appear at most once",
        ));
    }
    let mut limit = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "after" if after_sequence.is_none() => {
                after_sequence = Some(value.parse::<u64>().map_err(|_| {
                    ControlErrorV1::new(
                        ControlErrorCodeV1::InvalidRequest,
                        "control API event after cursor is invalid",
                    )
                })?);
            }
            "limit" if limit.is_none() => {
                limit = Some(value.parse::<u16>().map_err(|_| {
                    ControlErrorV1::new(
                        ControlErrorCodeV1::InvalidRequest,
                        "control API event limit is invalid",
                    )
                })?);
            }
            "after" => {
                return Err(ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "control API event cursor must use either Last-Event-ID or after, not both",
                ));
            }
            _ => {
                return Err(ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "control API event query contains an unknown or duplicate field",
                ));
            }
        }
    }
    let cursor = EventCursorV1 {
        after_sequence: after_sequence.unwrap_or(0),
        limit: limit.unwrap_or(default_limit),
    };
    cursor.validate()?;
    Ok(cursor)
}

const fn error_status(code: ControlErrorCodeV1) -> StatusCode {
    match code {
        ControlErrorCodeV1::UnsupportedSchema | ControlErrorCodeV1::InvalidRequest => {
            StatusCode::BAD_REQUEST
        }
        ControlErrorCodeV1::LimitExceeded => StatusCode::PAYLOAD_TOO_LARGE,
        ControlErrorCodeV1::Unauthenticated => StatusCode::UNAUTHORIZED,
        ControlErrorCodeV1::ConfigurationWidening
        | ControlErrorCodeV1::PrincipalBindingMismatch
        | ControlErrorCodeV1::EngagementUnavailable
        | ControlErrorCodeV1::PolicyDenied => StatusCode::FORBIDDEN,
        ControlErrorCodeV1::NotFound => StatusCode::NOT_FOUND,
        ControlErrorCodeV1::EventCursorExpired
        | ControlErrorCodeV1::EventCursorFuture
        | ControlErrorCodeV1::Conflict
        | ControlErrorCodeV1::CanonicalProjectionMismatch => StatusCode::CONFLICT,
        ControlErrorCodeV1::Busy => StatusCode::SERVICE_UNAVAILABLE,
        ControlErrorCodeV1::StorageUnavailable | ControlErrorCodeV1::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn bounded_json_response(status: StatusCode, bytes: Vec<u8>) -> Response {
    let mut response = (status, bytes).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    secure_response_headers(response.headers_mut());
    response
}

fn secure_response_headers(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
}

/// Validate, compose, and start the control API. Nothing listens unless this explicit path runs.
pub async fn serve(config: Arc<AppConfig>, database_url: Option<&str>) -> Result<()> {
    let prepared = PreparedControlApi::from_app_config(&config)?;
    let engagement = Arc::new(config.engagement.clone().ok_or_else(|| {
        ScorchError::Config("control API requires an explicit engagement".to_string())
    })?);
    let pool = crate::storage::connect_from_config(&config.database, database_url).await?;
    let webhooks = if config.webhooks.is_empty() {
        None
    } else {
        Some(Arc::new(WebhookService::new(
            &config.webhooks,
            Arc::new(PostgresWebhookStore::new(pool.clone())),
        )?))
    };
    let service = ControlService::persistent(config, pool, webhooks);
    let bind = prepared.bind;
    let host = ControlApiHost::new(prepared, service, engagement)?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| ScorchError::Config(format!("control API listener failed: {error}")))?;
    tracing::info!(
        address = %listener.local_addr().unwrap_or(bind),
        "authenticated loopback control API ready"
    );
    axum::serve(listener, host.router())
        .with_graceful_shutdown(async {
            if tokio::signal::ctrl_c().await.is_err() {
                tracing::warn!("control API shutdown signal handler failed");
            }
        })
        .await
        .map_err(|error| ScorchError::Config(format!("control API server failed: {error}")))
}

#[cfg(test)]
mod tests {
    use axum::http::Request as HttpRequest;
    use chrono::Duration as ChronoDuration;
    use futures_util::StreamExt;

    use super::*;
    use crate::engine::policy::{Capability, EffectClass, EngagementPolicy};
    use crate::engine::scope::ScopeRule;

    fn token() -> String {
        "t".repeat(MIN_BEARER_TOKEN_BYTES)
    }

    fn config() -> AppConfig {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.test").expect("scope"))
            .allow_capability(Capability::DastScan)
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::Passive)
            .allow_effect(EffectClass::ActiveSafe);
        let engagement = Engagement::new("control transport", policy);
        let mut config = AppConfig { engagement: Some(engagement.clone()), ..AppConfig::default() };
        config.control_api.bind = Some("127.0.0.1:7444".parse().expect("bind"));
        config.control_api.subject = Some("local-control-test".to_string());
        config.control_api.engagement_id = Some(engagement.id);
        config.control_api.token_env = Some("SCORCHKIT_CONTROL_TEST".to_string());
        config.control_api.max_body_bytes = 2_048;
        config.control_api.max_response_bytes = 1_048_576;
        config
    }

    fn prepared(config: &AppConfig) -> Result<PreparedControlApi> {
        PreparedControlApi::from_app_config_with(config, |name| {
            (name == "SCORCHKIT_CONTROL_TEST").then(token)
        })
    }

    fn host(config: &AppConfig) -> ControlApiHost {
        let service = ControlService::in_memory(Arc::new(config.clone()));
        let engagement = Arc::new(config.engagement.clone().expect("engagement"));
        ControlApiHost::new(prepared(config).expect("prepared"), service, engagement).expect("host")
    }

    fn request(method: Method, path: &str, body: Body, token: Option<&str>) -> Request {
        let mut builder =
            HttpRequest::builder().method(method).uri(path).header(header::HOST, "127.0.0.1:7444");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(body).expect("request")
    }

    #[test]
    fn startup_rejects_exposure_binding_and_credential_failures() {
        let mut exposed = config();
        exposed.control_api.bind = Some("0.0.0.0:7444".parse().expect("bind"));
        assert!(prepared(&exposed).unwrap_err().to_string().contains("loopback"));

        let mut mismatch = config();
        mismatch.control_api.engagement_id = Some(Uuid::new_v4());
        assert!(prepared(&mismatch).unwrap_err().to_string().contains("not bound"));

        let unavailable =
            PreparedControlApi::from_app_config_with(&config(), |_| None).unwrap_err().to_string();
        assert!(unavailable.contains("SCORCHKIT_CONTROL_TEST"));
        assert!(!unavailable.contains(&token()));

        let mut expired = config();
        expired.engagement.as_mut().expect("engagement").expires_at =
            Some(Utc::now() - ChronoDuration::seconds(1));
        assert!(prepared(&expired).unwrap_err().to_string().contains("expired"));

        let debug = format!("{:?}", prepared(&config()).expect("prepared"));
        assert!(!debug.contains(&token()));
        assert!(!debug.contains(&format!("{:?}", token_digest(&token()))));

        let active = config();
        let service = ControlService::in_memory(Arc::new(active.clone()));
        let mut expired_engagement = active.engagement.clone().expect("engagement");
        expired_engagement.expires_at = Some(Utc::now() - ChronoDuration::seconds(1));
        assert!(ControlApiHost::new(
            prepared(&active).expect("prepared active host"),
            service,
            Arc::new(expired_engagement),
        )
        .err()
        .expect("expired composition")
        .to_string()
        .contains("enabled, unexpired"));
    }

    #[tokio::test]
    async fn every_route_requires_exact_auth_and_loopback_host() {
        let host = host(&config());
        let unauthenticated =
            host.handle(request(Method::GET, DESCRIPTION_PATH, Body::empty(), None)).await;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let mut duplicate = request(Method::GET, DESCRIPTION_PATH, Body::empty(), Some(&token()));
        duplicate.headers_mut().append(
            header::AUTHORIZATION,
            format!("Bearer {}", token()).parse().expect("authorization"),
        );
        assert_eq!(host.handle(duplicate).await.status(), StatusCode::UNAUTHORIZED);

        let mut external_host =
            request(Method::GET, DESCRIPTION_PATH, Body::empty(), Some(&token()));
        external_host
            .headers_mut()
            .insert(header::HOST, HeaderValue::from_static("evil.example:7444"));
        assert_eq!(host.handle(external_host).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn description_and_control_post_share_the_application_service() {
        let host = host(&config());
        let mut description_request =
            request(Method::GET, DESCRIPTION_PATH, Body::empty(), Some(&token()));
        description_request
            .headers_mut()
            .insert(CLAIMED_SUBJECT_HEADER, HeaderValue::from_static("spoofed-subject"));
        description_request.headers_mut().insert(
            CLAIMED_ENGAGEMENT_HEADER,
            HeaderValue::from_static("00000000-0000-0000-0000-000000000000"),
        );
        let description = host.handle(description_request).await;
        assert_eq!(description.status(), StatusCode::OK);
        let body = to_bytes(description.into_body(), 1_048_576).await.expect("body");
        let response: ControlResponseV1 = serde_json::from_slice(&body).expect("response");
        assert_eq!(response.principal.subject, "local-control-test");
        assert_eq!(response.principal.engagement_id, Some(host.inner.engagement_id));

        let engagement_id = host.inner.engagement_id;
        let control = ControlRequestV1::query(ControlQueryV1::GetEngagement, Some(engagement_id));
        let bytes = serde_json::to_vec(&control).expect("request JSON");
        let mut request = request(Method::POST, CONTROL_PATH, Body::from(bytes), Some(&token()));
        request
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let response = host.handle(request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_048_576).await.expect("body");
        let response: ControlResponseV1 = serde_json::from_slice(&body).expect("response");
        assert!(matches!(response.result, ControlResponseOutcomeV1::Success(_)));
    }

    #[tokio::test]
    async fn malformed_oversized_and_future_event_requests_are_typed_rejections() {
        let host = host(&config());
        let mut wrong_type = request(Method::POST, CONTROL_PATH, Body::from("{}"), Some(&token()));
        wrong_type
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert_eq!(host.handle(wrong_type).await.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let mut oversized =
            request(Method::POST, CONTROL_PATH, Body::from(vec![b'x'; 2_049]), Some(&token()));
        oversized
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert_eq!(host.handle(oversized).await.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let future = host
            .handle(request(
                Method::GET,
                "/v1/events?after=1&limit=1",
                Body::empty(),
                Some(&token()),
            ))
            .await;
        assert_eq!(future.status(), StatusCode::CONFLICT);

        let mut last_event = request(Method::GET, EVENTS_PATH, Body::empty(), Some(&token()));
        last_event.headers_mut().insert(LAST_EVENT_ID_HEADER, HeaderValue::from_static("1"));
        assert_eq!(host.handle(last_event).await.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn concurrency_response_and_subscriber_limits_are_enforced() {
        let mut limited = config();
        limited.control_api.max_subscribers = 1;
        limited.control_api.max_concurrent_requests = 1;
        let primary_host = host(&limited);
        let first = primary_host
            .handle(request(Method::GET, EVENTS_PATH, Body::empty(), Some(&token())))
            .await;
        assert_eq!(first.status(), StatusCode::OK);
        let second = primary_host
            .handle(request(Method::GET, EVENTS_PATH, Body::empty(), Some(&token())))
            .await;
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
        drop(first);
        let third = primary_host
            .handle(request(Method::GET, EVENTS_PATH, Body::empty(), Some(&token())))
            .await;
        assert_eq!(third.status(), StatusCode::OK);
        drop(third);

        let permit = Arc::clone(&primary_host.inner.concurrency)
            .try_acquire_owned()
            .expect("reserve request capacity");
        let busy = primary_host
            .handle(request(Method::GET, DESCRIPTION_PATH, Body::empty(), Some(&token())))
            .await;
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        drop(permit);

        let mut response_limited = config();
        response_limited.control_api.max_response_bytes = 1_024;
        response_limited.control_api.max_event_bytes = 512;
        let limited_host = host(&response_limited);
        let response = limited_host
            .handle(request(Method::GET, DESCRIPTION_PATH, Body::empty(), Some(&token())))
            .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn real_loopback_http_serves_control_and_replay_sse() {
        let mut config = config();
        config.control_api.bind = Some("127.0.0.1:0".parse().expect("ephemeral bind"));
        let host = host(&config);
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind live control test");
        let address = listener.local_addr().expect("live address");
        let task = tokio::spawn(async move {
            axum::serve(listener, host.router()).await.expect("serve live control test");
        });
        let client = reqwest::Client::new();
        let description = client
            .get(format!("http://{address}{DESCRIPTION_PATH}"))
            .bearer_auth(token())
            .send()
            .await
            .expect("live description");
        assert_eq!(description.status(), reqwest::StatusCode::OK);

        let request = ControlRequestV1::command(
            scorchkit_control::ControlCommandV1::StartJob {
                target: "https://example.test/".to_string(),
                profile: "quick".to_string(),
                modules: Some(Vec::new()),
                skip: Vec::new(),
            },
            config.engagement.as_ref().expect("engagement").id,
        );
        let started = client
            .post(format!("http://{address}{CONTROL_PATH}"))
            .bearer_auth(token())
            .json(&request)
            .send()
            .await
            .expect("live control command");
        assert_eq!(started.status(), reqwest::StatusCode::OK);

        let events = client
            .get(format!("http://{address}{EVENTS_PATH}?after=0&limit=10"))
            .bearer_auth(token())
            .send()
            .await
            .expect("live events");
        assert_eq!(events.status(), reqwest::StatusCode::OK);
        let mut stream = events.bytes_stream();
        let bytes = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("SSE replay deadline")
            .expect("SSE replay chunk")
            .expect("SSE replay bytes");
        let text = String::from_utf8(bytes.to_vec()).expect("UTF-8 SSE");
        assert!(text.contains("event: control"));
        assert!(text.contains("scorchkit.control.event/v1"));
        task.abort();
    }
}
