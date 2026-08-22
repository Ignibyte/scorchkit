//! Authenticated Streamable HTTP MCP transport.
//!
//! The first remote profile is intentionally narrow: a same-host reverse proxy
//! terminates TLS and forwards to a loopback-only listener. Bearer credentials
//! select isolated principal/session services before rmcp receives a request.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use chrono::Utc;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{
    SessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Semaphore};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};
use crate::mcp::server::ScorchKitServer;

const MCP_PATH: &str = "/mcp";
const FORWARDED_PROTOCOL_HEADER: &str = "x-forwarded-proto";
const SESSION_HEADER: &str = "mcp-session-id";
const MIN_BEARER_TOKEN_BYTES: usize = 32;
const MAX_BEARER_TOKEN_BYTES: usize = 4_096;
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

type HttpMcpService = StreamableHttpService<ScorchKitServer, LocalSessionManager>;

#[derive(Clone)]
struct PreparedBinding {
    subject: String,
    engagement_id: uuid::Uuid,
    token_digest: [u8; 32],
}

/// Validated, credential-resolved remote host configuration.
pub(crate) struct PreparedRemoteMcp {
    bind: SocketAddr,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    max_body_bytes: usize,
    max_concurrent_requests: usize,
    max_sessions_per_principal: usize,
    bindings: Vec<PreparedBinding>,
}

impl std::fmt::Debug for PreparedRemoteMcp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedRemoteMcp")
            .field("bind", &self.bind)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_origins", &self.allowed_origins)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .field("max_sessions_per_principal", &self.max_sessions_per_principal)
            .field("binding_count", &self.bindings.len())
            .finish_non_exhaustive()
    }
}

impl PreparedRemoteMcp {
    /// Validate remote configuration, engagement eligibility, and runtime credentials.
    pub(crate) fn from_app_config(config: &AppConfig) -> Result<Self> {
        Self::from_app_config_with(config, |name| std::env::var(name).ok())
    }

    fn from_app_config_with(
        config: &AppConfig,
        mut resolve_environment: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self> {
        let remote = config.mcp.remote.as_ref().ok_or_else(|| {
            ScorchError::Config(
                "remote MCP requires an explicit [mcp.remote] configuration".to_string(),
            )
        })?;
        remote.validate().map_err(ScorchError::Config)?;
        let engagement = config.engagement.as_ref().ok_or_else(|| {
            ScorchError::Config(
                "remote MCP requires an explicit engagement authorization".to_string(),
            )
        })?;
        if !engagement.enabled {
            return Err(ScorchError::Config(
                "remote MCP configured engagement is disabled".to_string(),
            ));
        }
        if engagement.expires_at.is_some_and(|expiry| expiry <= Utc::now()) {
            return Err(ScorchError::Config(
                "remote MCP configured engagement is expired".to_string(),
            ));
        }

        let mut bindings = Vec::with_capacity(remote.bindings.len());
        for binding in &remote.bindings {
            if binding.engagement_id != engagement.id {
                return Err(ScorchError::Config(format!(
                    "remote MCP principal '{}' is not bound to the configured engagement",
                    binding.subject
                )));
            }
            let token =
                Zeroizing::new(resolve_environment(&binding.token_env).ok_or_else(|| {
                    ScorchError::Config(format!(
                        "remote MCP token environment '{}' is unavailable",
                        binding.token_env
                    ))
                })?);
            validate_token(&token).map_err(|message| {
                ScorchError::Config(format!(
                    "remote MCP token environment '{}' {message}",
                    binding.token_env
                ))
            })?;
            let token_digest = token_digest(&token);
            if bindings
                .iter()
                .any(|existing: &PreparedBinding| existing.token_digest == token_digest)
            {
                return Err(ScorchError::Config(
                    "remote MCP principal bindings contain duplicate credentials".to_string(),
                ));
            }
            bindings.push(PreparedBinding {
                subject: binding.subject.clone(),
                engagement_id: binding.engagement_id,
                token_digest,
            });
        }

        let bind = remote.bind.ok_or_else(|| {
            ScorchError::Config("remote MCP requires an explicit backend bind address".to_string())
        })?;
        Ok(Self {
            bind,
            allowed_hosts: remote.allowed_hosts.clone(),
            allowed_origins: remote.allowed_origins.clone(),
            max_body_bytes: remote.max_body_bytes,
            max_concurrent_requests: remote.max_concurrent_requests,
            max_sessions_per_principal: remote.max_sessions_per_principal,
            bindings,
        })
    }

    pub(crate) const fn bind(&self) -> SocketAddr {
        self.bind
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

struct RemoteEndpoint {
    subject: String,
    engagement_id: uuid::Uuid,
    token_digest: [u8; 32],
    manager: Arc<LocalSessionManager>,
    service: HttpMcpService,
    initialize_lock: Mutex<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyReadFailure {
    Limit,
    Timeout,
}

/// Cloneable authenticated remote request host.
#[derive(Clone)]
pub(crate) struct RemoteMcpHost {
    inner: Arc<RemoteMcpHostInner>,
}

struct RemoteMcpHostInner {
    endpoints: Vec<RemoteEndpoint>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    max_body_bytes: usize,
    max_sessions_per_principal: usize,
    concurrency: Arc<Semaphore>,
    shutdown: CancellationToken,
    engagement: Arc<crate::engine::policy::Engagement>,
}

impl RemoteMcpHost {
    pub(crate) fn new(prepared: PreparedRemoteMcp, server: &ScorchKitServer) -> Result<Self> {
        let engagement = Arc::new(server.config.engagement.clone().ok_or_else(|| {
            ScorchError::Config(
                "remote MCP requires an explicit engagement authorization".to_string(),
            )
        })?);
        if !engagement.enabled || engagement.expires_at.is_some_and(|expiry| expiry <= Utc::now()) {
            return Err(ScorchError::Config(
                "remote MCP composed engagement is disabled or expired".to_string(),
            ));
        }
        if prepared.bindings.iter().any(|binding| binding.engagement_id != engagement.id) {
            return Err(ScorchError::Config(
                "remote MCP runtime bindings do not match the composed engagement".to_string(),
            ));
        }
        let shutdown = CancellationToken::new();
        let endpoints = prepared
            .bindings
            .into_iter()
            .map(|binding| {
                let manager = Arc::new(LocalSessionManager::default());
                let service_server = server.clone().with_remote_principal(binding.subject.clone());
                let transport_config = StreamableHttpServerConfig::default()
                    .with_stateful_mode(true)
                    .with_allowed_hosts(prepared.allowed_hosts.clone())
                    .with_allowed_origins(prepared.allowed_origins.clone())
                    .with_cancellation_token(shutdown.child_token());
                let service = StreamableHttpService::new(
                    move || Ok(service_server.clone()),
                    Arc::clone(&manager),
                    transport_config,
                );
                RemoteEndpoint {
                    subject: binding.subject,
                    engagement_id: binding.engagement_id,
                    token_digest: binding.token_digest,
                    manager,
                    service,
                    initialize_lock: Mutex::new(()),
                }
            })
            .collect();
        Ok(Self {
            inner: Arc::new(RemoteMcpHostInner {
                endpoints,
                allowed_hosts: prepared.allowed_hosts,
                allowed_origins: prepared.allowed_origins,
                max_body_bytes: prepared.max_body_bytes,
                max_sessions_per_principal: prepared.max_sessions_per_principal,
                concurrency: Arc::new(Semaphore::new(prepared.max_concurrent_requests)),
                shutdown,
                engagement,
            }),
        })
    }

    pub(crate) fn router(self) -> Router {
        Router::new().fallback(remote_request).with_state(self)
    }

    fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }

    async fn handle(&self, mut request: Request) -> Response {
        if request.uri().path() != MCP_PATH || request.uri().query().is_some() {
            return rejection(StatusCode::NOT_FOUND, "mcp_path_rejected");
        }
        if !one_exact_header(request.headers(), FORWARDED_PROTOCOL_HEADER, "https") {
            return rejection(StatusCode::BAD_REQUEST, "mcp_tls_assertion_rejected");
        }
        if !allowed_host(request.headers(), &self.inner.allowed_hosts) {
            return rejection(StatusCode::FORBIDDEN, "mcp_host_rejected");
        }
        if !allowed_origin(request.headers(), &self.inner.allowed_origins) {
            return rejection(StatusCode::FORBIDDEN, "mcp_origin_rejected");
        }
        let Some(endpoint) = self.authenticate(request.headers()) else {
            return authentication_rejection();
        };
        request.headers_mut().remove(header::AUTHORIZATION);
        if !self.inner.engagement.enabled
            || endpoint.engagement_id != self.inner.engagement.id
            || self.inner.engagement.expires_at.is_some_and(|expiry| expiry <= Utc::now())
        {
            return rejection(StatusCode::FORBIDDEN, "mcp_engagement_binding_rejected");
        }
        let Ok(_request_permit) = Arc::clone(&self.inner.concurrency).try_acquire_owned() else {
            return rejection(StatusCode::SERVICE_UNAVAILABLE, "mcp_concurrency_exhausted");
        };
        if content_length_exceeds(request.headers(), self.inner.max_body_bytes) {
            return rejection(StatusCode::PAYLOAD_TOO_LARGE, "mcp_body_limit_exceeded");
        }

        let (parts, body) = request.into_parts();
        let bytes =
            match read_bounded_body(body, self.inner.max_body_bytes, BODY_READ_TIMEOUT).await {
                Ok(bytes) => bytes,
                Err(BodyReadFailure::Limit) => {
                    return rejection(StatusCode::PAYLOAD_TOO_LARGE, "mcp_body_limit_exceeded");
                }
                Err(BodyReadFailure::Timeout) => {
                    return rejection(StatusCode::REQUEST_TIMEOUT, "mcp_body_timeout");
                }
            };
        let request = Request::from_parts(parts, Body::from(bytes));
        tracing::info!(
            event = "mcp.remote.authenticated",
            subject = endpoint.subject,
            engagement_id = %endpoint.engagement_id,
            "authenticated remote MCP request"
        );

        if request.method() == Method::POST && request.headers().get(SESSION_HEADER).is_none() {
            let _initialize_guard = endpoint.initialize_lock.lock().await;
            if endpoint.manager.sessions.read().await.len() >= self.inner.max_sessions_per_principal
            {
                return rejection(StatusCode::TOO_MANY_REQUESTS, "mcp_session_limit_exceeded");
            }
            let sessions_before =
                endpoint.manager.sessions.read().await.keys().cloned().collect::<Vec<_>>();
            let response = endpoint.service.handle(request).await;
            if response.headers().get(SESSION_HEADER).is_none() {
                let leaked_sessions = endpoint
                    .manager
                    .sessions
                    .read()
                    .await
                    .keys()
                    .filter(|id| !sessions_before.contains(id))
                    .cloned()
                    .collect::<Vec<_>>();
                for session_id in leaked_sessions {
                    if endpoint.manager.close_session(&session_id).await.is_err() {
                        tracing::warn!(
                            event = "mcp.remote.failed_initialization_cleanup",
                            "failed to close rejected remote MCP session"
                        );
                    }
                }
            }
            response.map(Body::new)
        } else {
            endpoint.service.handle(request).await.map(Body::new)
        }
    }

    fn authenticate(&self, headers: &HeaderMap) -> Option<&RemoteEndpoint> {
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let authorization = values.next()?.to_str().ok()?;
        if values.next().is_some() {
            return None;
        }
        let token = authorization.strip_prefix("Bearer ")?;
        if validate_token(token).is_err() {
            return None;
        }
        let candidate = token_digest(token);
        let mut matched = None;
        for (index, endpoint) in self.inner.endpoints.iter().enumerate() {
            if bool::from(candidate.ct_eq(&endpoint.token_digest)) {
                matched = Some(index);
            }
        }
        matched.map(|index| &self.inner.endpoints[index])
    }
}

async fn remote_request(State(host): State<RemoteMcpHost>, request: Request) -> Response {
    host.handle(request).await
}

fn one_exact_header(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    let mut values = headers.get_all(name).iter();
    let matches =
        values.next().and_then(|value| value.to_str().ok()).is_some_and(|value| value == expected);
    matches && values.next().is_none()
}

fn allowed_host(headers: &HeaderMap, allowed: &[String]) -> bool {
    let mut values = headers.get_all(header::HOST).iter();
    let matches = values
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| allowed.iter().any(|item| item.eq_ignore_ascii_case(value)));
    matches && values.next().is_none()
}

fn allowed_origin(headers: &HeaderMap, allowed: &[String]) -> bool {
    let mut values = headers.get_all(header::ORIGIN).iter();
    let Some(value) = values.next() else {
        return true;
    };
    let Some(origin) = value.to_str().ok().and_then(|value| Url::parse(value).ok()) else {
        return false;
    };
    values.next().is_none()
        && allowed.iter().filter_map(|item| Url::parse(item).ok()).any(|item| item == origin)
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

async fn read_bounded_body(
    body: Body,
    maximum: usize,
    deadline: Duration,
) -> std::result::Result<Bytes, BodyReadFailure> {
    match tokio::time::timeout(deadline, to_bytes(body, maximum)).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(_)) => Err(BodyReadFailure::Limit),
        Err(_) => Err(BodyReadFailure::Timeout),
    }
}

fn authentication_rejection() -> Response {
    tracing::warn!(event = "mcp.remote.authentication_rejected");
    (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Bearer")], "Unauthorized")
        .into_response()
}

fn rejection(status: StatusCode, event: &'static str) -> Response {
    tracing::warn!(event = event, "remote MCP request rejected");
    (status, status.canonical_reason().unwrap_or("Request rejected")).into_response()
}

/// Start the authenticated remote listener after all validation and composition succeeds.
pub(crate) async fn listen(prepared: PreparedRemoteMcp, server: &ScorchKitServer) -> Result<()> {
    let bind = prepared.bind();
    let host = RemoteMcpHost::new(prepared, server)?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| ScorchError::Config(format!("remote MCP listener failed: {error}")))?;
    tracing::info!(address = %listener.local_addr().unwrap_or(bind), "remote MCP listener ready");
    let shutdown_host = host.clone();
    let shutdown_after_serve = host.clone();
    let result = axum::serve(listener, host.router())
        .with_graceful_shutdown(async move {
            if tokio::signal::ctrl_c().await.is_err() {
                tracing::warn!("remote MCP shutdown signal handler failed");
            }
            shutdown_host.shutdown();
        })
        .await;
    shutdown_after_serve.shutdown();
    result.map_err(|error| ScorchError::Config(format!("remote MCP server failed: {error}")))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::http::Request as HttpRequest;
    use chrono::Duration as ChronoDuration;
    use scorchkit_policy::policy::{Engagement, EngagementPolicy};
    use uuid::Uuid;

    use super::*;
    use crate::config::{
        McpConfig, RemoteMcpConfig, RemoteMcpPrincipalBinding, RemoteMcpTlsTermination,
    };

    const PRIMARY_TOKEN: &str = "primary-remote-mcp-token-value-0001";
    const SECONDARY_TOKEN: &str = "secondary-remote-mcp-token-value-02";

    fn app_config() -> AppConfig {
        let engagement = Engagement::new("remote fixture", EngagementPolicy::default());
        AppConfig {
            engagement: Some(engagement.clone()),
            mcp: McpConfig {
                remote: Some(RemoteMcpConfig {
                    bind: Some("127.0.0.1:0".parse().expect("socket")),
                    tls_termination: Some(RemoteMcpTlsTermination::TrustedReverseProxy),
                    allowed_hosts: vec!["security.example.test".to_string()],
                    allowed_origins: vec!["https://console.example.test".to_string()],
                    max_body_bytes: 1_024,
                    max_concurrent_requests: 2,
                    max_sessions_per_principal: 1,
                    bindings: vec![RemoteMcpPrincipalBinding {
                        subject: "primary@example.test".to_string(),
                        engagement_id: engagement.id,
                        token_env: "SCORCHKIT_MCP_PRIMARY".to_string(),
                    }],
                }),
            },
            ..AppConfig::default()
        }
    }

    fn prepare(config: &AppConfig) -> Result<PreparedRemoteMcp> {
        PreparedRemoteMcp::from_app_config_with(config, |name| match name {
            "SCORCHKIT_MCP_PRIMARY" => Some(PRIMARY_TOKEN.to_string()),
            "SCORCHKIT_MCP_SECONDARY" => Some(SECONDARY_TOKEN.to_string()),
            _ => None,
        })
    }

    fn request(body: impl Into<Body>, token: Option<&str>) -> Request {
        let mut builder = HttpRequest::builder()
            .method(Method::POST)
            .uri(MCP_PATH)
            .header(header::HOST, "security.example.test")
            .header(header::ORIGIN, "https://console.example.test")
            .header(FORWARDED_PROTOCOL_HEADER, "https")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(body.into()).expect("request")
    }

    fn initialize_body(id: u64) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "local-administrator", "version": "999.0"}
            }
        })
        .to_string()
    }

    fn host(config: &AppConfig) -> RemoteMcpHost {
        let prepared = prepare(config).expect("prepared remote config");
        let server = ScorchKitServer::new_stateless(Arc::new(config.clone()));
        RemoteMcpHost::new(prepared, &server).expect("remote host")
    }

    fn app_config_with_secondary_principal() -> AppConfig {
        let mut config = app_config();
        let engagement_id = config.engagement.as_ref().expect("engagement").id;
        config.mcp.remote.as_mut().expect("remote").bindings.push(RemoteMcpPrincipalBinding {
            subject: "secondary@example.test".to_string(),
            engagement_id,
            token_env: "SCORCHKIT_MCP_SECONDARY".to_string(),
        });
        config
    }

    async fn initialize_session(
        host: &RemoteMcpHost,
        token: &str,
        id: u64,
    ) -> axum::http::HeaderValue {
        let response = host.handle(request(initialize_body(id), Some(token))).await;
        assert_eq!(response.status(), StatusCode::OK);
        response.headers().get(SESSION_HEADER).expect("session header").clone()
    }

    fn session_request(
        body: impl Into<Body>,
        token: &str,
        session: &axum::http::HeaderValue,
    ) -> Request {
        let mut request = request(body, Some(token));
        request.headers_mut().insert(SESSION_HEADER, session.clone());
        request
            .headers_mut()
            .insert("mcp-protocol-version", "2025-06-18".parse().expect("version"));
        request
    }

    async fn rpc_response(response: Response) -> serde_json::Value {
        assert_eq!(response.status(), StatusCode::OK);
        let bytes =
            tokio::time::timeout(Duration::from_secs(1), to_bytes(response.into_body(), 1_048_576))
                .await
                .expect("tool response completed")
                .expect("tool response body");
        let text = String::from_utf8(bytes.to_vec()).expect("UTF-8 SSE");
        let data = text
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim)
            .find(|line| !line.is_empty())
            .expect("SSE data line");
        serde_json::from_str(data).expect("JSON-RPC response")
    }

    #[test]
    fn startup_rejects_engagement_and_token_failures_without_disclosure() {
        let mut missing_remote = app_config();
        missing_remote.mcp.remote = None;
        assert!(PreparedRemoteMcp::from_app_config_with(&missing_remote, |_| None).is_err());

        let mut missing_engagement = app_config();
        missing_engagement.engagement = None;
        assert!(prepare(&missing_engagement).is_err());

        let mut disabled = app_config();
        disabled.engagement.as_mut().expect("engagement").enabled = false;
        assert!(prepare(&disabled).unwrap_err().to_string().contains("disabled"));

        let mut expired = app_config();
        expired.engagement.as_mut().expect("engagement").expires_at =
            Some(Utc::now() - ChronoDuration::seconds(1));
        assert!(prepare(&expired).unwrap_err().to_string().contains("expired"));

        let mut mismatch = app_config();
        mismatch.mcp.remote.as_mut().expect("remote").bindings[0].engagement_id = Uuid::new_v4();
        assert!(prepare(&mismatch).unwrap_err().to_string().contains("not bound"));

        let unavailable = PreparedRemoteMcp::from_app_config_with(&app_config(), |_| None)
            .unwrap_err()
            .to_string();
        assert!(unavailable.contains("SCORCHKIT_MCP_PRIMARY"));
        assert!(!unavailable.contains(PRIMARY_TOKEN));

        let prepared_debug = format!("{:?}", prepare(&app_config()).expect("prepared config"));
        let digest_text = format!("{:?}", token_digest(PRIMARY_TOKEN));
        assert!(prepared_debug.contains("PreparedRemoteMcp"));
        assert!(prepared_debug.contains("binding_count: 1"));
        assert!(prepared_debug.contains("max_body_bytes: 1024"));
        assert!(!prepared_debug.contains(PRIMARY_TOKEN));
        assert!(!prepared_debug.contains(&digest_text));
    }

    #[test]
    fn host_composition_rejects_a_different_runtime_engagement() {
        let config = app_config();
        let prepared = prepare(&config).expect("prepared remote config");
        let mut mismatched = app_config();
        mismatched.engagement.as_mut().expect("engagement").id = Uuid::new_v4();
        let server = ScorchKitServer::new_stateless(Arc::new(mismatched));

        let error = match RemoteMcpHost::new(prepared, &server) {
            Ok(_) => panic!("mismatched engagement was accepted"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("runtime bindings do not match"));
        assert!(!error.contains(PRIMARY_TOKEN));
    }

    #[test]
    fn host_composition_rechecks_engagement_eligibility_before_bind() {
        let config = app_config();
        let prepared = prepare(&config).expect("prepared remote config");
        let mut expired = config;
        expired.engagement.as_mut().expect("engagement").expires_at =
            Some(Utc::now() - ChronoDuration::seconds(1));
        let server = ScorchKitServer::new_stateless(Arc::new(expired));

        let error = match RemoteMcpHost::new(prepared, &server) {
            Ok(_) => panic!("expired composed engagement was accepted"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("disabled or expired"));
        assert!(!error.contains(PRIMARY_TOKEN));
    }

    #[tokio::test]
    async fn request_guard_rechecks_each_engagement_dimension_after_startup() {
        let config = app_config();
        let mut disabled = host(&config);
        Arc::get_mut(&mut disabled.inner).expect("unshared host state").engagement = Arc::new({
            let mut engagement = config.engagement.clone().expect("engagement");
            engagement.enabled = false;
            engagement
        });
        assert_eq!(
            disabled.handle(request("{}", Some(PRIMARY_TOKEN))).await.status(),
            StatusCode::FORBIDDEN
        );

        let mut mismatched = host(&config);
        Arc::get_mut(&mut mismatched.inner).expect("unshared host state").endpoints[0]
            .engagement_id = Uuid::new_v4();
        assert_eq!(
            mismatched.handle(request("{}", Some(PRIMARY_TOKEN))).await.status(),
            StatusCode::FORBIDDEN
        );

        let mut expired = host(&config);
        Arc::get_mut(&mut expired.inner).expect("unshared host state").engagement = Arc::new({
            let mut expired = config.engagement.expect("engagement");
            expired.expires_at = Some(Utc::now() - ChronoDuration::seconds(1));
            expired
        });
        assert_eq!(
            expired.handle(request("{}", Some(PRIMARY_TOKEN))).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn shutdown_cancels_the_shared_session_token() {
        let host = host(&app_config());
        assert!(!host.inner.shutdown.is_cancelled());

        host.shutdown();

        assert!(host.inner.shutdown.is_cancelled());
    }

    #[test]
    fn token_bounds_and_duplicate_digests_fail_closed() {
        for token in [
            "short",
            &"x".repeat(MAX_BEARER_TOKEN_BYTES + 1),
            &format!("{} ", "x".repeat(31)),
            "éééééééééééééééé",
        ] {
            assert!(validate_token(token).is_err());
        }
        assert!(validate_token(&"x".repeat(MIN_BEARER_TOKEN_BYTES)).is_ok());
        assert!(validate_token(&"x".repeat(MAX_BEARER_TOKEN_BYTES)).is_ok());

        let mut duplicate = app_config();
        let engagement_id = duplicate.engagement.as_ref().expect("engagement").id;
        duplicate.mcp.remote.as_mut().expect("remote").bindings.push(RemoteMcpPrincipalBinding {
            subject: "secondary@example.test".to_string(),
            engagement_id,
            token_env: "SCORCHKIT_MCP_SECONDARY".to_string(),
        });
        let error = PreparedRemoteMcp::from_app_config_with(&duplicate, |_| {
            Some(PRIMARY_TOKEN.to_string())
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("duplicate credentials"));
        assert!(!error.contains(PRIMARY_TOKEN));
    }

    #[tokio::test]
    async fn request_guard_rejects_each_untrusted_dimension_before_protocol_routing() {
        let config = app_config();
        let host = host(&config);

        let mut wrong_path = request("{}", Some(PRIMARY_TOKEN));
        *wrong_path.uri_mut() = "/other".parse().expect("URI");
        assert_eq!(host.handle(wrong_path).await.status(), StatusCode::NOT_FOUND);

        let mut query = request("{}", Some(PRIMARY_TOKEN));
        *query.uri_mut() = "/mcp?subject=admin".parse().expect("URI");
        assert_eq!(host.handle(query).await.status(), StatusCode::NOT_FOUND);

        for (header_name, value, status) in [
            (FORWARDED_PROTOCOL_HEADER, "http", StatusCode::BAD_REQUEST),
            (header::HOST.as_str(), "evil.example.test", StatusCode::FORBIDDEN),
            (header::ORIGIN.as_str(), "https://evil.example.test", StatusCode::FORBIDDEN),
        ] {
            let mut denied = request("{}", Some(PRIMARY_TOKEN));
            denied.headers_mut().insert(header_name, value.parse().expect("header value"));
            assert_eq!(host.handle(denied).await.status(), status);
        }

        let mut missing_tls = request("{}", Some(PRIMARY_TOKEN));
        missing_tls.headers_mut().remove(FORWARDED_PROTOCOL_HEADER);
        assert_eq!(host.handle(missing_tls).await.status(), StatusCode::BAD_REQUEST);

        let mut duplicate_tls = request("{}", Some(PRIMARY_TOKEN));
        duplicate_tls
            .headers_mut()
            .append(FORWARDED_PROTOCOL_HEADER, "https".parse().expect("header"));
        assert_eq!(host.handle(duplicate_tls).await.status(), StatusCode::BAD_REQUEST);

        let mut missing_host = request("{}", Some(PRIMARY_TOKEN));
        missing_host.headers_mut().remove(header::HOST);
        assert_eq!(host.handle(missing_host).await.status(), StatusCode::FORBIDDEN);

        let mut duplicate_host = request("{}", Some(PRIMARY_TOKEN));
        duplicate_host
            .headers_mut()
            .append(header::HOST, "security.example.test".parse().expect("host"));
        assert_eq!(host.handle(duplicate_host).await.status(), StatusCode::FORBIDDEN);

        let mut absent_origin = request("{}", Some(PRIMARY_TOKEN));
        absent_origin.headers_mut().remove(header::ORIGIN);
        assert_ne!(host.handle(absent_origin).await.status(), StatusCode::FORBIDDEN);

        let mut duplicate_origin = request("{}", Some(PRIMARY_TOKEN));
        duplicate_origin
            .headers_mut()
            .append(header::ORIGIN, "https://console.example.test".parse().expect("origin"));
        assert_eq!(host.handle(duplicate_origin).await.status(), StatusCode::FORBIDDEN);

        assert_eq!(host.handle(request("{}", None)).await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            host.handle(request("{}", Some(SECONDARY_TOKEN))).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            host.handle(request("{}", Some("short"))).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let mut wrong_scheme = request("{}", None);
        wrong_scheme.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Basic {PRIMARY_TOKEN}").parse().expect("authorization"),
        );
        assert_eq!(host.handle(wrong_scheme).await.status(), StatusCode::UNAUTHORIZED);
        let mut duplicate_authorization = request("{}", Some(PRIMARY_TOKEN));
        duplicate_authorization.headers_mut().append(
            header::AUTHORIZATION,
            format!("Bearer {PRIMARY_TOKEN}").parse().expect("authorization"),
        );
        assert_eq!(host.handle(duplicate_authorization).await.status(), StatusCode::UNAUTHORIZED);

        let oversized = "x".repeat(1_025);
        assert_eq!(
            host.handle(request(oversized, Some(PRIMARY_TOKEN))).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );

        let _permit = Arc::clone(&host.inner.concurrency)
            .try_acquire_owned()
            .expect("reserve first request slot");
        let _second_permit = Arc::clone(&host.inner.concurrency)
            .try_acquire_owned()
            .expect("reserve second request slot");
        assert_eq!(
            host.handle(request("{}", Some(PRIMARY_TOKEN))).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn header_content_length_and_body_guards_pin_exact_boundaries() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_PROTOCOL_HEADER, "https".parse().expect("header"));
        assert!(one_exact_header(&headers, FORWARDED_PROTOCOL_HEADER, "https"));
        headers.append(FORWARDED_PROTOCOL_HEADER, "https".parse().expect("header"));
        assert!(!one_exact_header(&headers, FORWARDED_PROTOCOL_HEADER, "https"));

        let mut lengths = HeaderMap::new();
        assert!(!content_length_exceeds(&lengths, 1_024));
        lengths.insert(header::CONTENT_LENGTH, "1024".parse().expect("length"));
        assert!(!content_length_exceeds(&lengths, 1_024));
        lengths.insert(header::CONTENT_LENGTH, "1025".parse().expect("length"));
        assert!(content_length_exceeds(&lengths, 1_024));
        lengths.insert(header::CONTENT_LENGTH, "invalid".parse().expect("length"));
        assert!(content_length_exceeds(&lengths, 1_024));
        lengths.append(header::CONTENT_LENGTH, "1".parse().expect("length"));
        assert!(content_length_exceeds(&lengths, 1_024));

        assert_eq!(
            read_bounded_body(Body::from("x"), 1, Duration::from_secs(1))
                .await
                .expect("exact body"),
            Bytes::from_static(b"x")
        );
        assert_eq!(
            read_bounded_body(Body::from("xx"), 1, Duration::from_secs(1)).await,
            Err(BodyReadFailure::Limit)
        );
        let pending = Body::from_stream(futures_util::stream::pending::<
            std::result::Result<Bytes, std::io::Error>,
        >());
        assert_eq!(
            read_bounded_body(pending, 1, Duration::from_millis(1)).await,
            Err(BodyReadFailure::Timeout)
        );
    }

    #[tokio::test]
    async fn rejected_initialization_does_not_consume_bounded_session_capacity() {
        let host = host(&app_config());
        let rejected_first_message = host
            .handle(request(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "tools/call",
                    "params": {"name": "list_modules", "arguments": {}}
                })
                .to_string(),
                Some(PRIMARY_TOKEN),
            ))
            .await;
        assert_eq!(rejected_first_message.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(host.inner.endpoints[0].manager.sessions.read().await.is_empty());

        let _session = initialize_session(&host, PRIMARY_TOKEN, 1).await;
        let capacity = host.handle(request(initialize_body(2), Some(PRIMARY_TOKEN))).await;
        assert_eq!(capacity.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn remote_principal_projection_and_policy_denial_share_the_local_engine() {
        let host = host(&app_config());
        let session = initialize_session(&host, PRIMARY_TOKEN, 1).await;

        let tool_call = session_request(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "list_modules", "arguments": {}}
            })
            .to_string(),
            PRIMARY_TOKEN,
            &session,
        );
        let rpc = rpc_response(host.handle(tool_call).await).await;
        let principal = &rpc["result"]["structuredContent"]["principal"];
        assert_eq!(principal["kind"], "authenticated_bearer");
        assert_eq!(principal["subject"], "primary@example.test");
        assert_eq!(principal["clientAttribution"]["name"], "local-administrator");
        assert_eq!(principal["clientAttribution"]["version"], "999.0");
        assert_eq!(principal["clientAttribution"]["trusted"], false);

        let denied_scan = session_request(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "scan",
                    "arguments": {
                        "target": "http://127.0.0.1:9",
                        "profile": "quick",
                        "modules": "headers"
                    }
                }
            })
            .to_string(),
            PRIMARY_TOKEN,
            &session,
        );
        let denied_rpc = rpc_response(host.handle(denied_scan).await).await;
        assert_eq!(denied_rpc["result"]["structuredContent"]["outcome"], "error");
        assert_eq!(
            denied_rpc["result"]["structuredContent"]["principal"]["subject"],
            "primary@example.test"
        );
        assert!(denied_rpc["result"]["structuredContent"]["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("capability is not granted")));
    }

    #[tokio::test]
    async fn sessions_are_isolated_by_authenticated_principal_and_recover_capacity() {
        let host = host(&app_config_with_secondary_principal());
        let session = initialize_session(&host, PRIMARY_TOKEN, 1).await;

        let cross_principal = session_request(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "list_modules", "arguments": {}}
            })
            .to_string(),
            SECONDARY_TOKEN,
            &session,
        );
        assert_eq!(host.handle(cross_principal).await.status(), StatusCode::NOT_FOUND);

        let mut delete = session_request(Body::empty(), PRIMARY_TOKEN, &session);
        *delete.method_mut() = Method::DELETE;
        assert_eq!(host.handle(delete).await.status(), StatusCode::ACCEPTED);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if host.inner.endpoints[0].manager.sessions.read().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("session removed");
        assert_eq!(
            host.handle(request(initialize_body(4), Some(PRIMARY_TOKEN))).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn authenticated_transport_runs_over_an_actual_loopback_listener() {
        let config = app_config();
        let prepared = prepare(&config).expect("prepared remote config");
        let server = ScorchKitServer::new_stateless(Arc::new(config));
        let host = RemoteMcpHost::new(prepared, &server).expect("remote host");
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown_host = host.clone();
        let server_task = tokio::spawn(async move {
            axum::serve(listener, host.router())
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                    shutdown_host.shutdown();
                })
                .await
        });
        let client = reqwest::Client::builder().no_proxy().build().expect("HTTP client");
        let endpoint = format!("http://{address}{MCP_PATH}");
        let response = client
            .post(&endpoint)
            .header(header::HOST.as_str(), "security.example.test")
            .header(header::ORIGIN.as_str(), "https://console.example.test")
            .header(FORWARDED_PROTOCOL_HEADER, "https")
            .header(header::AUTHORIZATION.as_str(), format!("Bearer {PRIMARY_TOKEN}"))
            .header(header::CONTENT_TYPE.as_str(), "application/json")
            .header(header::ACCEPT.as_str(), "application/json, text/event-stream")
            .body(initialize_body(1))
            .send()
            .await
            .expect("initialize over loopback");
        assert_eq!(response.status(), StatusCode::OK);
        let session = response
            .headers()
            .get(SESSION_HEADER)
            .expect("session header")
            .to_str()
            .expect("session text")
            .to_string();

        let tool_response = client
            .post(&endpoint)
            .header(header::HOST.as_str(), "security.example.test")
            .header(header::ORIGIN.as_str(), "https://console.example.test")
            .header(FORWARDED_PROTOCOL_HEADER, "https")
            .header(header::AUTHORIZATION.as_str(), format!("Bearer {PRIMARY_TOKEN}"))
            .header(header::CONTENT_TYPE.as_str(), "application/json")
            .header(header::ACCEPT.as_str(), "application/json, text/event-stream")
            .header(SESSION_HEADER, &session)
            .header("mcp-protocol-version", "2025-06-18")
            .body(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "list_modules", "arguments": {}}
                })
                .to_string(),
            )
            .send()
            .await
            .expect("tool call over loopback");
        assert_eq!(tool_response.status(), StatusCode::OK);
        let body = tool_response.text().await.expect("tool SSE response");
        assert!(body.contains("authenticated_bearer"));
        assert!(body.contains("primary@example.test"));
        assert!(body.contains("\"trusted\":false"));

        let closed = client
            .delete(&endpoint)
            .header(header::HOST.as_str(), "security.example.test")
            .header(header::ORIGIN.as_str(), "https://console.example.test")
            .header(FORWARDED_PROTOCOL_HEADER, "https")
            .header(header::AUTHORIZATION.as_str(), format!("Bearer {PRIMARY_TOKEN}"))
            .header(SESSION_HEADER, session)
            .header("mcp-protocol-version", "2025-06-18")
            .send()
            .await
            .expect("delete loopback session");
        assert_eq!(closed.status(), StatusCode::ACCEPTED);

        let _ = shutdown_tx.send(());
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("loopback server stopped")
            .expect("loopback task joined")
            .expect("loopback server result");
    }

    #[tokio::test]
    async fn production_listener_reports_loopback_bind_conflicts() {
        let held =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("reserve loopback address");
        let address = held.local_addr().expect("reserved address");
        let mut config = app_config();
        config.mcp.remote.as_mut().expect("remote config").bind = Some(address);
        let prepared = prepare(&config).expect("prepared remote config");
        let server = ScorchKitServer::new_stateless(Arc::new(config));

        let error = listen(prepared, &server).await.unwrap_err().to_string();

        assert!(error.contains("listener failed"));
    }

    #[tokio::test]
    async fn remote_server_selector_fails_instead_of_becoming_a_noop() {
        let mut config = app_config();
        config.mcp.remote = None;

        let error =
            crate::mcp::server::serve_remote(Arc::new(config)).await.unwrap_err().to_string();

        assert!(error.contains("explicit [mcp.remote]"));
    }
}
