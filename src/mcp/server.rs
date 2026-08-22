//! MCP server core — struct definition, `ServerHandler` implementation,
//! and `serve()` entry point for stdio transport.

use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    GetPromptRequestParams, GetPromptResult, Implementation, ListPromptsResult,
    ListResourceTemplatesResult, ListResourcesResult, PaginatedRequestParams,
    ReadResourceRequestParams, ReadResourceResult, ServerCapabilities, ServerInfo,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::tool_handler;
use rmcp::transport::io::stdio;
use rmcp::ServiceExt;
use sqlx::PgPool;

use crate::config::AppConfig;
use crate::engine::error::ScorchError;
use crate::runner::job::{JobStore, ScanJobService};
use crate::runner::job_executor::CancellationToken;
use crate::storage::jobs::PostgresJobStore;
use crate::storage::webhooks::PostgresWebhookStore;
use crate::webhooks::WebhookService;

const RECOVERY_INTERVAL_SECONDS: u64 = 5;

/// The `ScorchKit` MCP server.
///
/// Holds shared application state (configuration and database pool)
/// that all MCP tool methods can access.
#[derive(Clone)]
pub struct ScorchKitServer {
    /// Shared application configuration.
    pub(crate) config: Arc<AppConfig>,
    /// Optional `PostgreSQL` connection pool for stateful project operations.
    pub(crate) pool: Option<PgPool>,
    /// Provider-neutral job control plane used by stateless and stateful sessions.
    pub(crate) jobs: ScanJobService,
    /// Optional durable webhook service for lifecycle enqueue and background delivery.
    pub(crate) webhooks: Option<Arc<WebhookService>>,
    webhook_configuration_error: Option<String>,
    pub(crate) transport_principal: McpTransportPrincipal,
}

/// Host-owned identity source for MCP result attribution.
#[derive(Clone)]
pub(crate) enum McpTransportPrincipal {
    LocalProcess,
    AuthenticatedBearer { subject: String },
}

impl ScorchKitServer {
    /// Create a new server instance with the given config and database pool.
    #[must_use]
    pub fn new(config: Arc<AppConfig>, pool: PgPool) -> Self {
        let store: Arc<dyn JobStore> = Arc::new(PostgresJobStore::new(pool.clone()));
        let jobs = ScanJobService::new(Arc::clone(&config), store);
        let (jobs, webhooks, webhook_configuration_error) = match WebhookService::new(
            &config.webhooks,
            Arc::new(PostgresWebhookStore::new(pool.clone())),
        ) {
            Ok(webhooks) if webhooks.is_enabled() => {
                let webhooks = Arc::new(webhooks);
                (jobs.with_webhooks(Arc::clone(&webhooks)), Some(webhooks), None)
            }
            Ok(_) => (jobs, None, None),
            Err(error) => (jobs, None, Some(error.to_string())),
        };
        Self {
            config,
            pool: Some(pool),
            jobs,
            webhooks,
            webhook_configuration_error,
            transport_principal: McpTransportPrincipal::LocalProcess,
        }
    }

    /// Create a stateless server backed by process-local jobs and no database.
    #[must_use]
    pub fn new_stateless(config: Arc<AppConfig>) -> Self {
        let jobs = ScanJobService::in_memory(Arc::clone(&config));
        let webhook_configuration_error = (!config.webhooks.is_empty()).then(|| {
            "webhook delivery requires an explicitly configured durable database".to_string()
        });
        Self {
            config,
            pool: None,
            jobs,
            webhooks: None,
            webhook_configuration_error,
            transport_principal: McpTransportPrincipal::LocalProcess,
        }
    }

    pub(crate) fn with_remote_principal(mut self, subject: String) -> Self {
        self.transport_principal = McpTransportPrincipal::AuthenticatedBearer { subject };
        self
    }

    pub(crate) fn require_pool(&self) -> Result<&PgPool, String> {
        self.pool.as_ref().ok_or_else(|| {
            "database unavailable: start MCP with an explicit database URL".to_string()
        })
    }

    fn require_valid_webhook_host(&self) -> crate::engine::error::Result<()> {
        if let Some(error) = &self.webhook_configuration_error {
            return Err(ScorchError::Config(error.clone()));
        }
        Ok(())
    }
}

#[tool_handler(router = Self::contract_tool_router())]
impl ServerHandler for ScorchKitServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info(Implementation::new("scorchkit", env!("CARGO_PKG_VERSION")))
        .with_instructions(super::instructions::INSTRUCTIONS.to_string())
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, rmcp::ErrorData> {
        self.do_list_resources().await
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, rmcp::ErrorData> {
        Ok(self.do_list_resource_templates())
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, rmcp::ErrorData> {
        self.do_read_resource(&request.uri).await
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, rmcp::ErrorData> {
        Ok(ListPromptsResult { prompts: Self::do_list_prompts(), meta: None, next_cursor: None })
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, rmcp::ErrorData> {
        let arguments = request
            .arguments
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| {
                let s = v.as_str().map_or_else(|| v.to_string(), str::to_string);
                (k, s)
            })
            .collect();

        Self::do_get_prompt(&request.name, &arguments)
            .map_err(|e| rmcp::ErrorData::invalid_params(e, None::<serde_json::Value>))
    }
}

/// Start the MCP server on stdio transport.
///
/// Uses process-local jobs when no database URL is configured. When a URL is explicitly configured,
/// startup connects and fails closed if that database is unavailable.
///
/// # Errors
///
/// Returns an error if an explicitly configured database connection fails or the MCP transport
/// encounters an I/O error.
pub async fn serve(config: Arc<AppConfig>) -> crate::engine::error::Result<()> {
    let server = compose_server(config).await?;
    server.require_valid_webhook_host()?;
    server.jobs.recover_interrupted().await?;

    let service = server
        .clone()
        .serve(stdio())
        .await
        .map_err(|e| ScorchError::Config(format!("MCP server failed to start: {e}")))?;
    let (recovery_stop, recovery_task) = spawn_recovery(&server);

    let service_result =
        service.waiting().await.map_err(|e| ScorchError::Config(format!("MCP server error: {e}")));
    stop_recovery(recovery_stop, recovery_task).await?;
    service_result.map(|_| ())
}

/// Start authenticated Streamable HTTP MCP behind the configured trusted TLS proxy.
///
/// # Errors
///
/// Returns an error before listening when remote authentication, engagement binding, TLS policy,
/// database composition, or the listener cannot be established.
pub async fn serve_remote(config: Arc<AppConfig>) -> crate::engine::error::Result<()> {
    let prepared = super::remote::PreparedRemoteMcp::from_app_config(&config)?;
    let server = compose_server(config).await?;
    server.require_valid_webhook_host()?;
    server.jobs.recover_interrupted().await?;
    let (recovery_stop, recovery_task) = spawn_recovery(&server);
    let service_result = super::remote::listen(prepared, &server).await;
    stop_recovery(recovery_stop, recovery_task).await?;
    service_result
}

async fn compose_server(config: Arc<AppConfig>) -> crate::engine::error::Result<ScorchKitServer> {
    let database_configured =
        config.database.url.is_some() || std::env::var_os("DATABASE_URL").is_some();
    if database_configured {
        let pool = crate::storage::connect_from_config(&config.database, None).await?;
        Ok(ScorchKitServer::new(config, pool))
    } else {
        Ok(ScorchKitServer::new_stateless(config))
    }
}

fn spawn_recovery(server: &ScorchKitServer) -> (CancellationToken, tokio::task::JoinHandle<()>) {
    let recovery_jobs = server.jobs.clone();
    let recovery_webhooks = server.webhooks.clone();
    let recovery_stop = CancellationToken::new();
    let recovery_stop_task = recovery_stop.clone();
    let recovery_task = tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(RECOVERY_INTERVAL_SECONDS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            tokio::select! {
                () = recovery_stop_task.cancelled() => break,
                _ = interval.tick() => {
                    if let Err(error) = recovery_jobs.recover_interrupted().await {
                        tracing::warn!(%error, "scan job recovery pass failed");
                    }
                    if let Some(webhooks) = &recovery_webhooks {
                        if let Err(error) = webhooks.run_due().await {
                            tracing::warn!(%error, "webhook delivery pass failed");
                        }
                    }
                }
            }
        }
    });
    (recovery_stop, recovery_task)
}

async fn stop_recovery(
    recovery_stop: CancellationToken,
    recovery_task: tokio::task::JoinHandle<()>,
) -> crate::engine::error::Result<()> {
    recovery_stop.cancel();
    recovery_task
        .await
        .map_err(|error| ScorchError::Job(format!("scan job recovery task failed: {error}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[test]
    fn stateless_host_rejects_webhook_enabled_configuration() {
        let mut config = AppConfig::default();
        config.webhooks.push(
            serde_json::from_value(serde_json::json!({
                "id": "primary",
                "url": "https://hooks.example.test/delivery"
            }))
            .unwrap(),
        );
        let server = ScorchKitServer::new_stateless(Arc::new(config));
        assert!(server.require_valid_webhook_host().is_err());
        assert!(server.webhooks.is_none());
    }

    #[tokio::test]
    async fn recovery_shutdown_cancels_and_awaits_the_background_task() {
        let stop = CancellationToken::new();
        let waiter = stop.clone();
        let observed = Arc::new(AtomicBool::new(false));
        let observed_by_task = Arc::clone(&observed);
        let task = tokio::spawn(async move {
            waiter.cancelled().await;
            observed_by_task.store(true, Ordering::SeqCst);
        });

        stop_recovery(stop, task).await.expect("stop recovery task");

        assert!(observed.load(Ordering::SeqCst));
    }
}
