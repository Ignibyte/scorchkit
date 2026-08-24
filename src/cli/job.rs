//! CLI adapter for durable scan jobs.

use std::sync::Arc;

use uuid::Uuid;

use super::args::JobCommands;
use crate::config::AppConfig;
use crate::control::ControlService;
use crate::engine::error::{Result, ScorchError};
use crate::runner::job::{ScanJob, ScanJobState};
use crate::storage::webhooks::PostgresWebhookStore;
use crate::webhooks::WebhookService;
use scorchkit_control::{
    ControlCommandV1, ControlQueryV1, ControlRequestV1, ControlResponseOutcomeV1, ControlResultV1,
    PageRequestV1,
};

fn comma_separated(value: &str) -> Vec<String> {
    value.split(',').map(str::trim).filter(|item| !item.is_empty()).map(str::to_string).collect()
}

fn parse_job_id(value: &str) -> Result<Uuid> {
    Uuid::parse_str(value)
        .map_err(|error| ScorchError::Job(format!("invalid scan job UUID '{value}': {error}")))
}

async fn service(config: &Arc<AppConfig>, database_url: Option<&str>) -> Result<ControlService> {
    let pool = crate::storage::connect_from_config(&config.database, database_url).await?;
    let webhooks = if config.webhooks.is_empty() {
        None
    } else {
        Some(Arc::new(WebhookService::new(
            &config.webhooks,
            Arc::new(PostgresWebhookStore::new(pool.clone())),
        )?))
    };
    Ok(ControlService::persistent(Arc::clone(config), pool, webhooks))
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}

fn expected_job(result: ControlResultV1) -> Result<Uuid> {
    let ControlResultV1::Job(job) = result else {
        return Err(ScorchError::Job(
            "control service returned an unexpected job result".to_string(),
        ));
    };
    Ok(job.id)
}

async fn list_legacy_jobs(service: &ControlService, config: &AppConfig) -> Result<Vec<ScanJob>> {
    let mut jobs = Vec::new();
    let mut cursor = None;
    loop {
        let result = query(
            service,
            config,
            ControlQueryV1::ListJobs {
                page: PageRequestV1 { cursor, limit: config.control_api.default_page_size },
            },
        )
        .await?;
        let ControlResultV1::Jobs(page) = result else {
            return Err(ScorchError::Job(
                "control service returned an unexpected job list".to_string(),
            ));
        };
        for job in page.items {
            jobs.push(service.job_service().get(job.id).await?);
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(jobs);
        }
    }
}

async fn execute(
    service: &ControlService,
    config: &AppConfig,
    operation: ControlCommandV1,
) -> Result<ControlResultV1> {
    let engagement_id =
        config.engagement.as_ref().map(|engagement| engagement.id).ok_or_else(|| {
            ScorchError::Job("no engagement authorization configured".to_string())
        })?;
    let response = service.execute_local(ControlRequestV1::command(operation, engagement_id)).await;
    match response.result {
        ControlResponseOutcomeV1::Success(result) => Ok(*result),
        ControlResponseOutcomeV1::Error(error) => Err(ScorchError::Job(error.to_string())),
    }
}

async fn query(
    service: &ControlService,
    config: &AppConfig,
    operation: ControlQueryV1,
) -> Result<ControlResultV1> {
    let engagement_id = config.engagement.as_ref().map(|engagement| engagement.id);
    let response = service.execute_local(ControlRequestV1::query(operation, engagement_id)).await;
    match response.result {
        ControlResponseOutcomeV1::Success(result) => Ok(*result),
        ControlResponseOutcomeV1::Error(error) => Err(ScorchError::Job(error.to_string())),
    }
}

async fn run_foreground(service: &ControlService, config: &AppConfig, id: Uuid) -> Result<ScanJob> {
    let mut cancellation_requested = false;
    loop {
        let current = service.job_service().get(id).await?;
        if current.state.is_terminal() {
            return Ok(current);
        }
        tokio::select! {
            () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
            signal = tokio::signal::ctrl_c(), if !cancellation_requested => {
                signal.map_err(ScorchError::Io)?;
                execute(service, config, ControlCommandV1::CancelJob { id }).await?;
                cancellation_requested = true;
            }
        }
    }
}

/// Run one durable-job CLI command.
///
/// # Errors
///
/// Returns an error for invalid IDs, unavailable storage, denied requests, or lifecycle failures.
pub async fn run_job_command(config: &Arc<AppConfig>, command: JobCommands) -> Result<()> {
    match command {
        JobCommands::Run { target, profile, modules, skip, database_url } => {
            let service = service(config, database_url.as_deref()).await?;
            let result = execute(
                &service,
                config,
                ControlCommandV1::StartJob {
                    target,
                    profile,
                    modules: modules.as_deref().map(comma_separated),
                    skip: skip.as_deref().map_or_else(Vec::new, comma_separated),
                },
            )
            .await?;
            print_json(&run_foreground(&service, config, expected_job(result)?).await?)
        }
        JobCommands::List { database_url } => {
            let service = service(config, database_url.as_deref()).await?;
            print_json(&list_legacy_jobs(&service, config).await?)
        }
        JobCommands::Status { id, database_url } => {
            let service = service(config, database_url.as_deref()).await?;
            let result =
                query(&service, config, ControlQueryV1::GetJob { id: parse_job_id(&id)? }).await?;
            print_json(&service.job_service().get(expected_job(result)?).await?)
        }
        JobCommands::Cancel { id, database_url } => {
            let service = service(config, database_url.as_deref()).await?;
            let result =
                execute(&service, config, ControlCommandV1::CancelJob { id: parse_job_id(&id)? })
                    .await?;
            print_json(&service.job_service().get(expected_job(result)?).await?)
        }
        JobCommands::Recover { database_url } => {
            let service = service(config, database_url.as_deref()).await?;
            let candidates =
                service.job_service().store().list_recoverable(chrono::Utc::now()).await?;
            let result = execute(&service, config, ControlCommandV1::RecoverJobs).await?;
            if !matches!(result, ControlResultV1::Acknowledged { .. }) {
                return Err(ScorchError::Job(
                    "control service returned an unexpected recovery result".to_string(),
                ));
            }
            let mut recovered = Vec::new();
            for candidate in candidates {
                let current = service.job_service().get(candidate.id).await?;
                if current.state == ScanJobState::Interrupted
                    && current.revision > candidate.revision
                {
                    recovered.push(current);
                }
            }
            print_json(&recovered)
        }
        JobCommands::Resume { id, database_url } => {
            let service = service(config, database_url.as_deref()).await?;
            let result =
                execute(&service, config, ControlCommandV1::ResumeJob { id: parse_job_id(&id)? })
                    .await?;
            print_json(&run_foreground(&service, config, expected_job(result)?).await?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::comma_separated;

    #[test]
    fn comma_separated_trims_and_drops_empty_items() {
        assert_eq!(comma_separated(" headers,ssl ,, nuclei "), ["headers", "ssl", "nuclei"]);
        assert!(comma_separated(" , , ").is_empty());
    }
}
