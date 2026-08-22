//! CLI adapter for durable webhook delivery state.

use std::sync::Arc;

use uuid::Uuid;

use super::args::WebhookCommands;
use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};
use crate::storage::webhooks::PostgresWebhookStore;
use crate::webhooks::WebhookService;

fn parse_id(value: &str) -> Result<Uuid> {
    Uuid::parse_str(value).map_err(|error| {
        ScorchError::Webhook(format!("invalid webhook delivery UUID '{value}': {error}"))
    })
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

async fn service(config: &Arc<AppConfig>, database_url: Option<&str>) -> Result<WebhookService> {
    let pool = crate::storage::connect_from_config(&config.database, database_url).await?;
    WebhookService::new(&config.webhooks, Arc::new(PostgresWebhookStore::new(pool)))
}

/// Run one durable-webhook CLI command.
///
/// # Errors
///
/// Returns a configuration, connection, identifier, storage, or worker error.
pub async fn run_webhook_command(config: &Arc<AppConfig>, command: WebhookCommands) -> Result<()> {
    match command {
        WebhookCommands::List { database_url } => {
            let webhooks = service(config, database_url.as_deref()).await?;
            print_json(&webhooks.list().await?)
        }
        WebhookCommands::Status { id, database_url } => {
            let webhooks = service(config, database_url.as_deref()).await?;
            print_json(&webhooks.get(parse_id(&id)?).await?)
        }
        WebhookCommands::Audit { id, database_url } => {
            let webhooks = service(config, database_url.as_deref()).await?;
            print_json(&webhooks.audit_events(parse_id(&id)?).await?)
        }
        WebhookCommands::RunDue { database_url } => {
            let webhooks = service(config, database_url.as_deref()).await?;
            print_json(&webhooks.run_due().await?)
        }
    }
}
