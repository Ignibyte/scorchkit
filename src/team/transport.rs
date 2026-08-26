//! Trusted-proxy loopback HTTP adapter for the authenticated team service.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use scorchkit_control::{
    ControlErrorCodeV1, ControlErrorV1, ControlQueryV1, ControlRequestV1, ControlResponseOutcomeV1,
    TeamObjectKindV1,
};
use tokio::sync::Semaphore;
use uuid::Uuid;

use super::service::{TeamService, TeamSession};
use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};

const DESCRIPTION_PATH: &str = "/v1/team/description";
const CONTROL_PATH: &str = "/v1/team/control";
const AUDIT_PATH: &str = "/v1/team/audit";
const RETENTION_PATH: &str = "/v1/team/retention";
const OBJECT_PREFIX: &str = "/v1/team/objects/";
const REQUEST_ID_HEADER: &str = "x-scorchkit-request-id";
const CLAIM_HEADERS: &[&str] = &[
    "x-scorchkit-subject",
    "x-scorchkit-organization-id",
    "x-scorchkit-project-id",
    "x-scorchkit-cell-id",
    "x-scorchkit-role",
    "x-scorchkit-engagement-id",
];
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct TeamHttpHost {
    inner: Arc<TeamHttpHostInner>,
}

struct TeamHttpHostInner {
    service: TeamService,
    concurrency: Arc<Semaphore>,
}

impl TeamHttpHost {
    fn new(service: TeamService) -> Self {
        let concurrency = Arc::new(Semaphore::new(service.config().max_concurrent_requests));
        Self { inner: Arc::new(TeamHttpHostInner { service, concurrency }) }
    }

    fn router(self) -> Router {
        Router::new().fallback(team_request).with_state(self)
    }

    async fn handle(&self, mut request: Request) -> Response {
        if !accepted_authority(
            request.headers(),
            &self.inner.service.config().allowed_hosts,
            &self.inner.service.config().allowed_origins,
        ) {
            return error_response(
                StatusCode::FORBIDDEN,
                &ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "team request authority is not allowed",
                ),
                self.inner.service.config().max_response_bytes,
            );
        }
        let Some(session) = authenticate(&self.inner.service, request.headers()) else {
            tracing::warn!(event = "team.request_rejected", reason = "authentication");
            let mut response = error_response(
                StatusCode::UNAUTHORIZED,
                &ControlErrorV1::new(
                    ControlErrorCodeV1::Unauthenticated,
                    "team authentication is required",
                ),
                self.inner.service.config().max_response_bytes,
            );
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            return response;
        };
        request.headers_mut().remove(header::AUTHORIZATION);
        for name in CLAIM_HEADERS {
            request.headers_mut().remove(*name);
        }
        let Ok(_permit) = Arc::clone(&self.inner.concurrency).try_acquire_owned() else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &ControlErrorV1::new(
                    ControlErrorCodeV1::Busy,
                    "team request capacity is exhausted",
                )
                .retryable(),
                self.inner.service.config().max_response_bytes,
            );
        };
        tracing::info!(
            event = "team.authenticated_request",
            subject = %session.principal().subject,
            cell_id = %session.principal().cell_id,
            method = %request.method(),
            "authenticated team request"
        );
        Box::pin(self.route(session, request)).await
    }

    async fn route(&self, session: TeamSession, request: Request) -> Response {
        let maximum = self.inner.service.config().max_response_bytes;
        let method = request.method().clone();
        let path = request.uri().path().to_string();
        if method == Method::GET && path == DESCRIPTION_PATH && request.uri().query().is_none() {
            if let Err(response) = empty_body(request, maximum).await {
                return response;
            }
            let control = ControlRequestV1::query(
                ControlQueryV1::Describe,
                Some(session.principal().engagement_id),
            );
            return team_control_response(&session.execute_control(control).await, maximum);
        }
        if method == Method::POST && path == CONTROL_PATH && request.uri().query().is_none() {
            return self.control(session, request).await;
        }
        if method == Method::GET && path == AUDIT_PATH {
            return self.audit(session, request).await;
        }
        if method == Method::POST && path == RETENTION_PATH && request.uri().query().is_none() {
            let request_id = match request_id(request.headers()) {
                Ok(value) => value,
                Err(error) => return error_response(StatusCode::BAD_REQUEST, &error, maximum),
            };
            if let Err(response) = empty_body(request, maximum).await {
                return response;
            }
            return match session.apply_retention(request_id).await {
                Ok(removed) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({ "requestId": request_id, "removed": removed }),
                    maximum,
                ),
                Err(error) => error_response(error_status(error.code), &error, maximum),
            };
        }
        if let Some(suffix) = path.strip_prefix(OBJECT_PREFIX) {
            return self.object(session, request, &method, suffix).await;
        }
        error_response(
            StatusCode::NOT_FOUND,
            &ControlErrorV1::new(ControlErrorCodeV1::NotFound, "team route was not found"),
            maximum,
        )
    }

    async fn control(&self, session: TeamSession, request: Request) -> Response {
        let maximum = self.inner.service.config().max_response_bytes;
        if !json_content_type(request.headers()) {
            return error_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "team control requests require application/json",
                ),
                maximum,
            );
        }
        let bytes = match bounded_body(request, self.inner.service.config().max_body_bytes).await {
            Ok(bytes) => bytes,
            Err(response) => return response,
        };
        let control: ControlRequestV1 = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &ControlErrorV1::new(
                        ControlErrorCodeV1::InvalidRequest,
                        "team control request JSON is invalid",
                    ),
                    maximum,
                );
            }
        };
        team_control_response(&session.execute_control(control).await, maximum)
    }

    async fn audit(&self, session: TeamSession, request: Request) -> Response {
        let maximum = self.inner.service.config().max_response_bytes;
        let request_id = match request_id(request.headers()) {
            Ok(value) => value,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, &error, maximum),
        };
        let (after, limit) = match audit_cursor(request.uri().query()) {
            Ok(value) => value,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, &error, maximum),
        };
        if let Err(response) = empty_body(request, maximum).await {
            return response;
        }
        match session.read_audit(request_id, after, limit).await {
            Ok(events) => json_response(
                StatusCode::OK,
                &serde_json::json!({ "requestId": request_id, "events": events }),
                maximum,
            ),
            Err(error) => error_response(error_status(error.code), &error, maximum),
        }
    }

    async fn object(
        &self,
        session: TeamSession,
        request: Request,
        method: &Method,
        suffix: &str,
    ) -> Response {
        let maximum = self.inner.service.config().max_response_bytes;
        let request_id = match request_id(request.headers()) {
            Ok(value) => value,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, &error, maximum),
        };
        if *method == Method::PUT && !suffix.contains('/') && request.uri().query().is_none() {
            if !octet_stream_content_type(request.headers()) {
                return error_response(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    &ControlErrorV1::new(
                        ControlErrorCodeV1::InvalidRequest,
                        "team object writes require application/octet-stream",
                    ),
                    maximum,
                );
            }
            let Some(kind) = parse_kind(suffix) else {
                return error_response(
                    StatusCode::NOT_FOUND,
                    &ControlErrorV1::new(ControlErrorCodeV1::NotFound, "team route was not found"),
                    maximum,
                );
            };
            let bytes =
                match bounded_body(request, self.inner.service.config().max_body_bytes).await {
                    Ok(bytes) => bytes,
                    Err(response) => return response,
                };
            return match session.put_object(request_id, kind, &bytes).await {
                Ok(view) => json_response(StatusCode::CREATED, &view, maximum),
                Err(error) => error_response(error_status(error.code), &error, maximum),
            };
        }
        if *method == Method::POST && suffix.ends_with("/rotate") && request.uri().query().is_none()
        {
            let object_id = suffix.trim_end_matches("/rotate");
            if let Err(response) = empty_body(request, maximum).await {
                return response;
            }
            return match session.rotate_object(request_id, object_id).await {
                Ok(view) => json_response(StatusCode::OK, &view, maximum),
                Err(error) => error_response(error_status(error.code), &error, maximum),
            };
        }
        if *method == Method::GET && !suffix.contains('/') && request.uri().query().is_none() {
            if let Err(response) = empty_body(request, maximum).await {
                return response;
            }
            return match session.read_object(request_id, suffix).await {
                Ok((view, bytes)) => {
                    if bytes.len() > maximum {
                        return error_response(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            &ControlErrorV1::new(
                                ControlErrorCodeV1::LimitExceeded,
                                "team object response exceeds the configured limit",
                            ),
                            maximum,
                        );
                    }
                    let mut response = bounded_response(StatusCode::OK, bytes.to_vec());
                    response.headers_mut().insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/octet-stream"),
                    );
                    if let Ok(value) = HeaderValue::from_str(&view.object_id) {
                        response.headers_mut().insert("x-scorchkit-object-id", value);
                    }
                    response
                }
                Err(error) => error_response(error_status(error.code), &error, maximum),
            };
        }
        error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            &ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                "team method or object route is not allowed",
            ),
            maximum,
        )
    }
}

async fn team_request(State(host): State<TeamHttpHost>, request: Request) -> Response {
    Box::pin(host.handle(request)).await
}

fn authenticate(service: &TeamService, headers: &HeaderMap) -> Option<TeamSession> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    service.authenticate(value.strip_prefix("Bearer ")?)
}

fn accepted_authority(headers: &HeaderMap, hosts: &[String], origins: &[String]) -> bool {
    let mut host_values = headers.get_all(header::HOST).iter();
    let Some(host) = host_values.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    if host_values.next().is_some()
        || !hosts.iter().any(|allowed| allowed.eq_ignore_ascii_case(host))
    {
        return false;
    }
    let mut origin_values = headers.get_all(header::ORIGIN).iter();
    let Some(origin) = origin_values.next() else {
        return true;
    };
    let Some(origin) = origin.to_str().ok() else {
        return false;
    };
    origin_values.next().is_none() && origins.iter().any(|allowed| allowed == origin)
}

async fn bounded_body(request: Request, maximum: usize) -> std::result::Result<Bytes, Response> {
    if content_length_exceeds(request.headers(), maximum) {
        return Err(body_limit_response(maximum));
    }
    match tokio::time::timeout(BODY_READ_TIMEOUT, to_bytes(request.into_body(), maximum)).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(_)) => Err(body_limit_response(maximum)),
        Err(_) => Err(error_response(
            StatusCode::REQUEST_TIMEOUT,
            &ControlErrorV1::new(ControlErrorCodeV1::Busy, "team request body timed out")
                .retryable(),
            maximum,
        )),
    }
}

async fn empty_body(
    request: Request,
    maximum_response: usize,
) -> std::result::Result<(), Response> {
    if content_length_exceeds(request.headers(), 0) {
        return Err(empty_body_rejection(maximum_response));
    }
    match tokio::time::timeout(BODY_READ_TIMEOUT, to_bytes(request.into_body(), 0)).await {
        Ok(Ok(bytes)) if bytes.is_empty() => Ok(()),
        Ok(_) => Err(empty_body_rejection(maximum_response)),
        Err(_) => Err(error_response(
            StatusCode::REQUEST_TIMEOUT,
            &ControlErrorV1::new(ControlErrorCodeV1::Busy, "team request body timed out")
                .retryable(),
            maximum_response,
        )),
    }
}

fn empty_body_rejection(maximum: usize) -> Response {
    error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        &ControlErrorV1::new(
            ControlErrorCodeV1::LimitExceeded,
            "team route requires an empty request body",
        ),
        maximum,
    )
}

fn body_limit_response(maximum: usize) -> Response {
    error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        &ControlErrorV1::new(
            ControlErrorCodeV1::LimitExceeded,
            "team request body exceeds the configured limit",
        ),
        maximum,
    )
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
    exact_content_type(headers, "application/json")
}

fn octet_stream_content_type(headers: &HeaderMap) -> bool {
    exact_content_type(headers, "application/octet-stream")
}

fn exact_content_type(headers: &HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let valid = values
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(expected));
    valid && values.next().is_none()
}

fn request_id(headers: &HeaderMap) -> std::result::Result<Uuid, ControlErrorV1> {
    let mut values = headers.get_all(REQUEST_ID_HEADER).iter();
    let request_id = values
        .next()
        .map_or_else(
            || Some(Uuid::new_v4()),
            |value| value.to_str().ok().and_then(|value| value.parse().ok()),
        )
        .ok_or_else(|| {
            ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                "team request identity is invalid",
            )
        })?;
    if values.next().is_some() || request_id.is_nil() {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::InvalidRequest,
            "team request identity is invalid",
        ));
    }
    Ok(request_id)
}

fn audit_cursor(query: Option<&str>) -> std::result::Result<(u64, u16), ControlErrorV1> {
    let mut after = None;
    let mut limit = None;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "after" if after.is_none() => {
                after = Some(value.parse().map_err(|_| invalid_cursor())?);
            }
            "limit" if limit.is_none() => {
                limit = Some(value.parse().map_err(|_| invalid_cursor())?);
            }
            _ => return Err(invalid_cursor()),
        }
    }
    let limit = limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(invalid_cursor());
    }
    Ok((after.unwrap_or(0), limit))
}

fn invalid_cursor() -> ControlErrorV1 {
    ControlErrorV1::new(ControlErrorCodeV1::InvalidRequest, "team audit cursor is invalid")
}

fn parse_kind(value: &str) -> Option<TeamObjectKindV1> {
    match value {
        "evidence" => Some(TeamObjectKindV1::Evidence),
        "report" => Some(TeamObjectKindV1::Report),
        "extension_artifact" => Some(TeamObjectKindV1::ExtensionArtifact),
        _ => None,
    }
}

fn team_control_response(
    response: &scorchkit_control::TeamControlResponseV1,
    maximum: usize,
) -> Response {
    let status = match &response.result {
        ControlResponseOutcomeV1::Success(_) => StatusCode::OK,
        ControlResponseOutcomeV1::Error(error) => error_status(error.code),
    };
    json_response(status, response, maximum)
}

fn error_response(status: StatusCode, error: &ControlErrorV1, maximum: usize) -> Response {
    json_response(status, error, maximum)
}

fn json_response(status: StatusCode, value: &impl serde::Serialize, maximum: usize) -> Response {
    match serde_json::to_vec(value) {
        Ok(bytes) if bytes.len() <= maximum => bounded_response(status, bytes),
        _ => bounded_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"code":"internal","message":"team response serialization failed","retryable":false}"#.to_vec(),
        ),
    }
}

fn bounded_response(status: StatusCode, bytes: Vec<u8>) -> Response {
    let mut response = (status, bytes).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    response
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

/// Complete startup preflight, then bind only the configured loopback backend.
///
/// # Errors
///
/// Returns before listening when service preflight or loopback listener startup fails, or returns
/// a server error after startup.
pub async fn serve(config: Arc<AppConfig>) -> Result<()> {
    let service = TeamService::from_app_config(config).await?;
    let bind = service.config().bind.ok_or_else(|| {
        ScorchError::Config("team service requires an explicit loopback bind".to_string())
    })?;
    let host = TeamHttpHost::new(service);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| ScorchError::Config(format!("team listener failed: {error}")))?;
    tracing::info!(
        address = %listener.local_addr().unwrap_or(bind),
        "authenticated team service ready behind trusted TLS proxy"
    );
    axum::serve(listener, host.router())
        .with_graceful_shutdown(async {
            if tokio::signal::ctrl_c().await.is_err() {
                tracing::warn!("team service shutdown signal handler failed");
            }
        })
        .await
        .map_err(|error| ScorchError::Config(format!("team server failed: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use scorchkit_control::{
        ControlResponseOutcomeV1, TeamControlResponseV1, TeamPrincipalV1, TeamRoleV1,
        TEAM_API_SCHEMA_V1,
    };

    #[test]
    fn authority_requires_exact_host_and_exact_optional_origin() {
        let hosts = vec!["security.example.test".to_string()];
        let origins = vec!["https://security.example.test".to_string()];
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("security.example.test"));
        assert!(accepted_authority(&headers, &hosts, &origins));
        headers.insert(header::ORIGIN, HeaderValue::from_static("https://evil.example.test"));
        assert!(!accepted_authority(&headers, &hosts, &origins));
        headers.insert(header::ORIGIN, HeaderValue::from_static("https://security.example.test"));
        assert!(accepted_authority(&headers, &hosts, &origins));

        let missing = HeaderMap::new();
        assert!(!accepted_authority(&missing, &hosts, &origins));

        let mut case_insensitive_host = HeaderMap::new();
        case_insensitive_host
            .insert(header::HOST, HeaderValue::from_static("SECURITY.EXAMPLE.TEST"));
        assert!(accepted_authority(&case_insensitive_host, &hosts, &origins));

        let mut duplicate_host = HeaderMap::new();
        duplicate_host.append(header::HOST, HeaderValue::from_static("security.example.test"));
        duplicate_host.append(header::HOST, HeaderValue::from_static("security.example.test"));
        assert!(!accepted_authority(&duplicate_host, &hosts, &origins));

        let mut invalid_host = HeaderMap::new();
        invalid_host.insert(header::HOST, HeaderValue::from_bytes(&[0xff]).expect("opaque host"));
        assert!(!accepted_authority(&invalid_host, &hosts, &origins));

        let mut duplicate_origin = HeaderMap::new();
        duplicate_origin.insert(header::HOST, HeaderValue::from_static("security.example.test"));
        duplicate_origin
            .append(header::ORIGIN, HeaderValue::from_static("https://security.example.test"));
        duplicate_origin
            .append(header::ORIGIN, HeaderValue::from_static("https://security.example.test"));
        assert!(!accepted_authority(&duplicate_origin, &hosts, &origins));

        let mut invalid_origin = HeaderMap::new();
        invalid_origin.insert(header::HOST, HeaderValue::from_static("security.example.test"));
        invalid_origin
            .insert(header::ORIGIN, HeaderValue::from_bytes(&[0xff]).expect("opaque origin"));
        assert!(!accepted_authority(&invalid_origin, &hosts, &origins));
    }

    #[test]
    fn audit_cursor_and_request_identity_are_bounded() {
        assert_eq!(audit_cursor(Some("after=4&limit=10")).expect("cursor"), (4, 10));
        assert_eq!(audit_cursor(None).expect("default cursor"), (0, 50));
        assert_eq!(audit_cursor(Some("after=4")).expect("after cursor"), (4, 50));
        assert_eq!(audit_cursor(Some("limit=1")).expect("minimum limit"), (0, 1));
        assert_eq!(audit_cursor(Some("limit=200")).expect("maximum limit"), (0, 200));
        assert!(audit_cursor(Some("limit=0")).is_err());
        assert!(audit_cursor(Some("limit=201")).is_err());
        assert!(audit_cursor(Some("after=bad")).is_err());
        assert!(audit_cursor(Some("limit=bad")).is_err());
        assert!(audit_cursor(Some("after=1&after=2")).is_err());
        assert!(audit_cursor(Some("limit=1&limit=2")).is_err());
        assert!(audit_cursor(Some("unknown=1")).is_err());

        let cursor_error = invalid_cursor();
        assert_eq!(cursor_error.code, ControlErrorCodeV1::InvalidRequest);
        assert_eq!(cursor_error.message, "team audit cursor is invalid");

        let headers = HeaderMap::new();
        assert!(!request_id(&headers).expect("generated").is_nil());
        let expected = Uuid::from_u128(7);
        let mut exact = HeaderMap::new();
        exact.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_str(&expected.to_string()).expect("request ID"),
        );
        assert_eq!(request_id(&exact).expect("exact request ID"), expected);
        let mut invalid = HeaderMap::new();
        invalid.insert(REQUEST_ID_HEADER, HeaderValue::from_static("invalid"));
        assert!(request_id(&invalid).is_err());
        let mut nil = HeaderMap::new();
        nil.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_static("00000000-0000-0000-0000-000000000000"),
        );
        assert!(request_id(&nil).is_err());
        let mut duplicate = HeaderMap::new();
        duplicate.append(
            REQUEST_ID_HEADER,
            HeaderValue::from_str(&Uuid::from_u128(8).to_string()).expect("first request ID"),
        );
        duplicate.append(
            REQUEST_ID_HEADER,
            HeaderValue::from_str(&Uuid::from_u128(9).to_string()).expect("second request ID"),
        );
        assert!(request_id(&duplicate).is_err());
    }

    #[test]
    fn content_length_and_content_type_parsers_have_exact_edges() {
        let mut headers = HeaderMap::new();
        assert!(!content_length_exceeds(&headers, 0));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        assert!(!content_length_exceeds(&headers, 0));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("8"));
        assert!(!content_length_exceeds(&headers, 8));
        assert!(content_length_exceeds(&headers, 7));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("invalid"));
        assert!(content_length_exceeds(&headers, usize::MAX));
        headers.clear();
        headers.append(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
        headers.append(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert!(content_length_exceeds(&headers, 1));

        let mut content_type = HeaderMap::new();
        assert!(!json_content_type(&content_type));
        assert!(!octet_stream_content_type(&content_type));
        content_type.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/JSON; charset=utf-8"),
        );
        assert!(json_content_type(&content_type));
        assert!(!octet_stream_content_type(&content_type));
        content_type
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
        assert!(octet_stream_content_type(&content_type));
        assert!(!json_content_type(&content_type));
        content_type
            .append(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
        assert!(!octet_stream_content_type(&content_type));
    }

    #[test]
    fn object_kind_and_error_status_mappings_are_complete() {
        assert_eq!(parse_kind("evidence"), Some(TeamObjectKindV1::Evidence));
        assert_eq!(parse_kind("report"), Some(TeamObjectKindV1::Report));
        assert_eq!(parse_kind("extension_artifact"), Some(TeamObjectKindV1::ExtensionArtifact));
        assert_eq!(parse_kind("unknown"), None);

        for (code, status) in [
            (ControlErrorCodeV1::UnsupportedSchema, StatusCode::BAD_REQUEST),
            (ControlErrorCodeV1::InvalidRequest, StatusCode::BAD_REQUEST),
            (ControlErrorCodeV1::LimitExceeded, StatusCode::PAYLOAD_TOO_LARGE),
            (ControlErrorCodeV1::Unauthenticated, StatusCode::UNAUTHORIZED),
            (ControlErrorCodeV1::ConfigurationWidening, StatusCode::FORBIDDEN),
            (ControlErrorCodeV1::PrincipalBindingMismatch, StatusCode::FORBIDDEN),
            (ControlErrorCodeV1::EngagementUnavailable, StatusCode::FORBIDDEN),
            (ControlErrorCodeV1::PolicyDenied, StatusCode::FORBIDDEN),
            (ControlErrorCodeV1::NotFound, StatusCode::NOT_FOUND),
            (ControlErrorCodeV1::EventCursorExpired, StatusCode::CONFLICT),
            (ControlErrorCodeV1::EventCursorFuture, StatusCode::CONFLICT),
            (ControlErrorCodeV1::Conflict, StatusCode::CONFLICT),
            (ControlErrorCodeV1::CanonicalProjectionMismatch, StatusCode::CONFLICT),
            (ControlErrorCodeV1::Busy, StatusCode::SERVICE_UNAVAILABLE),
            (ControlErrorCodeV1::StorageUnavailable, StatusCode::INTERNAL_SERVER_ERROR),
            (ControlErrorCodeV1::Internal, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            assert_eq!(error_status(code), status);
        }
    }

    #[tokio::test]
    async fn body_and_response_helpers_enforce_exact_bounds_and_headers() {
        let empty = Request::builder().body(Body::empty()).expect("empty request");
        empty_body(empty, 1_024).await.expect("empty body");
        let nonempty = Request::builder().body(Body::from("x")).expect("nonempty request");
        assert!(empty_body(nonempty, 1_024).await.is_err());

        let exact = Request::builder()
            .header(header::CONTENT_LENGTH, "4")
            .body(Body::from("body"))
            .expect("exact request");
        assert_eq!(bounded_body(exact, 4).await.expect("exact body"), "body");
        let oversized = Request::builder()
            .header(header::CONTENT_LENGTH, "5")
            .body(Body::from("body!"))
            .expect("oversized request");
        assert!(bounded_body(oversized, 4).await.is_err());
        let streaming_oversized =
            Request::builder().body(Body::from("body!")).expect("streaming oversized request");
        assert!(bounded_body(streaming_oversized, 4).await.is_err());

        let value = serde_json::json!({"ok": true});
        let encoded = serde_json::to_vec(&value).expect("JSON");
        let response = json_response(StatusCode::CREATED, &value, encoded.len());
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        let response = json_response(StatusCode::CREATED, &value, encoded.len() - 1);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let limit = body_limit_response(1_024);
        assert_eq!(limit.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let empty_rejection = empty_body_rejection(1_024);
        assert_eq!(empty_rejection.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let error = ControlErrorV1::new(ControlErrorCodeV1::NotFound, "missing");
        assert_eq!(
            error_response(StatusCode::NOT_FOUND, &error, 1_024).status(),
            StatusCode::NOT_FOUND
        );

        let principal = TeamPrincipalV1 {
            subject: "reader".into(),
            organization_id: "org-alpha".into(),
            project_id: Uuid::from_u128(1),
            cell_id: "alpha".into(),
            role: TeamRoleV1::Reader,
            engagement_id: Uuid::from_u128(2),
        };
        let control = TeamControlResponseV1 {
            schema_version: TEAM_API_SCHEMA_V1.into(),
            request_id: Uuid::from_u128(3),
            principal,
            result: ControlResponseOutcomeV1::Error(error),
        };
        assert_eq!(team_control_response(&control, 4_096).status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn route_method_path_and_body_guards_remain_conjunctive_and_exact() {
        let source = include_str!("transport.rs");
        let production = source.split("#[cfg(test)]").next().expect("production source");
        let normalized = production.split_whitespace().collect::<Vec<_>>().join(" ");
        for required in [
            "method == Method::GET && path == AUDIT_PATH",
            "method == Method::POST && path == RETENTION_PATH && request.uri().query().is_none()",
            "*method == Method::POST && suffix.ends_with(\"/rotate\") && request.uri().query().is_none()",
            "*method == Method::GET && !suffix.contains('/') && request.uri().query().is_none()",
            "if bytes.len() > maximum",
            "Ok(Ok(bytes)) if bytes.is_empty() => Ok(())",
        ] {
            assert!(normalized.contains(required), "missing exact route guard: {required}");
        }
    }
}
