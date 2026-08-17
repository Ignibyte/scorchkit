//! CLI adapter for durable scan jobs.

use std::sync::Arc;

use uuid::Uuid;

use super::args::JobCommands;
use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};
use crate::runner::job::{DastJobRequest, JobStore, ScanJob, ScanJobService};
use crate::storage::jobs::PostgresJobStore;

fn comma_separated(value: &str) -> Vec<String> {
    value.split(',').map(str::trim).filter(|item| !item.is_empty()).map(str::to_string).collect()
}

fn parse_job_id(value: &str) -> Result<Uuid> {
    Uuid::parse_str(value)
        .map_err(|error| ScorchError::Job(format!("invalid scan job UUID '{value}': {error}")))
}

async fn service(config: &Arc<AppConfig>, database_url: Option<&str>) -> Result<ScanJobService> {
    let pool = crate::storage::connect_from_config(&config.database, database_url).await?;
    let store: Arc<dyn JobStore> = Arc::new(PostgresJobStore::new(pool));
    Ok(ScanJobService::new(Arc::clone(config), store))
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}

async fn run_foreground(service: &ScanJobService, job: ScanJob) -> Result<ScanJob> {
    let run = service.run(job.id);
    tokio::pin!(run);
    tokio::select! {
        result = &mut run => result,
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(ScorchError::Io)?;
            let _cancelling = service.cancel(job.id).await?;
            run.await
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
            let jobs = service(config, database_url.as_deref()).await?;
            let engagement = config.engagement.clone().ok_or_else(|| {
                ScorchError::Job("no engagement authorization configured for scan job".to_string())
            })?;
            let request = DastJobRequest::new(target, profile, engagement)
                .with_modules(modules.as_deref().map(comma_separated))
                .with_skip(skip.as_deref().map_or_else(Vec::new, comma_separated));
            let job = jobs.submit(request).await?;
            print_json(&run_foreground(&jobs, job).await?)
        }
        JobCommands::List { database_url } => {
            let jobs = service(config, database_url.as_deref()).await?;
            print_json(&jobs.list().await?)
        }
        JobCommands::Status { id, database_url } => {
            let jobs = service(config, database_url.as_deref()).await?;
            print_json(&jobs.get(parse_job_id(&id)?).await?)
        }
        JobCommands::Cancel { id, database_url } => {
            let jobs = service(config, database_url.as_deref()).await?;
            print_json(&jobs.cancel(parse_job_id(&id)?).await?)
        }
        JobCommands::Recover { database_url } => {
            let jobs = service(config, database_url.as_deref()).await?;
            print_json(&jobs.recover_interrupted().await?)
        }
        JobCommands::Resume { id, database_url } => {
            let jobs = service(config, database_url.as_deref()).await?;
            let job = jobs.resume(parse_job_id(&id)?).await?;
            print_json(&run_foreground(&jobs, job).await?)
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
