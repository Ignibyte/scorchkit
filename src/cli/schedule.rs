//! Scan schedule management CLI handlers.
//!
//! Provides `schedule create/list/show/enable/disable/delete/run-due`
//! commands for managing recurring scan schedules per project.

use std::sync::Arc;

use colored::Colorize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::scan_context::ScanContext;
use crate::engine::target::Target;
use crate::runner::orchestrator::Orchestrator;
use crate::storage::{findings, scans, schedules};

/// Create a new scan schedule.
///
/// # Errors
///
/// Returns an error if the project is not found, the cron expression is
/// invalid, or the database query fails.
pub async fn create(
    pool: &PgPool,
    project_ref: &str,
    target_url: &str,
    cron_expression: &str,
    profile: &str,
) -> Result<()> {
    let project = crate::cli::project::resolve_project(pool, project_ref).await?;
    let schedule =
        schedules::create_schedule(pool, project.id, target_url, profile, cron_expression).await?;

    println!("{} Schedule created.", "success:".green().bold());
    println!("        ID: {}", schedule.id.to_string().dimmed());
    println!("   Project: {}", project.name.cyan());
    println!("    Target: {}", schedule.target_url.cyan());
    println!("      Cron: {}", schedule.cron_expression);
    println!("   Profile: {}", schedule.profile);
    println!("  Next run: {}", schedule.next_run.format("%Y-%m-%d %H:%M UTC"));
    Ok(())
}

/// List schedules for a project.
///
/// # Errors
///
/// Returns an error if the project is not found or the database query fails.
pub async fn list(pool: &PgPool, project_ref: &str) -> Result<()> {
    let project = crate::cli::project::resolve_project(pool, project_ref).await?;
    let schedule_list = schedules::list_schedules(pool, project.id).await?;

    if schedule_list.is_empty() {
        println!("{} No schedules for '{}'.", "note:".dimmed(), project.name);
        return Ok(());
    }

    println!("{} for '{}'", "Schedules".bold().underline(), project.name.cyan());
    println!();
    for s in &schedule_list {
        let status = if s.enabled { "enabled".green() } else { "disabled".red() };
        println!(
            "  {} [{}] {} → {} ({})",
            s.id.to_string().dimmed(),
            status,
            s.cron_expression,
            s.target_url.cyan(),
            s.profile,
        );
        println!(
            "    Next: {}  Last: {}",
            s.next_run.format("%Y-%m-%d %H:%M UTC"),
            s.last_run.map_or_else(
                || "never".to_string(),
                |t| t.format("%Y-%m-%d %H:%M UTC").to_string(),
            ),
        );
    }
    println!();
    Ok(())
}

/// Show details for a single schedule.
///
/// # Errors
///
/// Returns an error if the schedule UUID is invalid or not found.
pub async fn show(pool: &PgPool, id_str: &str) -> Result<()> {
    let id = Uuid::parse_str(id_str)
        .map_err(|e| ScorchError::Config(format!("invalid schedule UUID '{id_str}': {e}")))?;
    let schedule = schedules::get_schedule(pool, id)
        .await?
        .ok_or_else(|| ScorchError::Config(format!("schedule '{id_str}' not found")))?;

    println!("{}", "Schedule Details".bold().underline());
    println!();
    println!("        ID: {}", schedule.id.to_string().dimmed());
    println!("   Project: {}", schedule.project_id.to_string().dimmed());
    println!("    Target: {}", schedule.target_url.cyan());
    println!("      Cron: {}", schedule.cron_expression);
    println!("   Profile: {}", schedule.profile);
    let status = if schedule.enabled { "enabled".green() } else { "disabled".red() };
    println!("    Status: {status}");
    println!("  Next run: {}", schedule.next_run.format("%Y-%m-%d %H:%M UTC"));
    println!(
        "  Last run: {}",
        schedule
            .last_run
            .map_or_else(|| "never".to_string(), |t| t.format("%Y-%m-%d %H:%M UTC").to_string(),),
    );
    println!("   Created: {}", schedule.created_at.format("%Y-%m-%d %H:%M UTC"));
    println!();
    Ok(())
}

/// Enable a schedule.
///
/// # Errors
///
/// Returns an error if the schedule UUID is invalid or the database fails.
pub async fn enable(pool: &PgPool, id_str: &str) -> Result<()> {
    let id = Uuid::parse_str(id_str)
        .map_err(|e| ScorchError::Config(format!("invalid schedule UUID '{id_str}': {e}")))?;
    let updated = schedules::update_schedule_enabled(pool, id, true).await?;
    if updated {
        println!("{} Schedule enabled.", "success:".green().bold());
    } else {
        println!("{} Schedule not found.", "warning:".yellow().bold());
    }
    Ok(())
}

/// Disable a schedule.
///
/// # Errors
///
/// Returns an error if the schedule UUID is invalid or the database fails.
pub async fn disable(pool: &PgPool, id_str: &str) -> Result<()> {
    let id = Uuid::parse_str(id_str)
        .map_err(|e| ScorchError::Config(format!("invalid schedule UUID '{id_str}': {e}")))?;
    let updated = schedules::update_schedule_enabled(pool, id, false).await?;
    if updated {
        println!("{} Schedule disabled.", "success:".green().bold());
    } else {
        println!("{} Schedule not found.", "warning:".yellow().bold());
    }
    Ok(())
}

/// Delete a schedule.
///
/// # Errors
///
/// Returns an error if the schedule UUID is invalid or the database fails.
pub async fn delete(pool: &PgPool, id_str: &str) -> Result<()> {
    let id = Uuid::parse_str(id_str)
        .map_err(|e| ScorchError::Config(format!("invalid schedule UUID '{id_str}': {e}")))?;
    let deleted = schedules::delete_schedule(pool, id).await?;
    if deleted {
        println!("{} Schedule deleted.", "success:".green().bold());
    } else {
        println!("{} Schedule not found.", "warning:".yellow().bold());
    }
    Ok(())
}

/// Find and execute all due schedules.
///
/// For each due schedule: resolve project → parse target → build HTTP client →
/// run Orchestrator → persist results → update schedule timestamps.
///
/// Scan failures for individual schedules are logged but do not abort the batch.
///
/// # Errors
///
/// Returns an error if the database connection fails. Individual scan
/// errors are logged and skipped.
pub async fn run_due(pool: &PgPool, config: &Arc<AppConfig>) -> Result<()> {
    let due = schedules::find_due_schedules(pool).await?;

    if due.is_empty() {
        println!("{} No schedules are due.", "note:".dimmed());
        return Ok(());
    }

    println!(
        "{} {} schedule{} due",
        "Running".bold(),
        due.len(),
        if due.len() == 1 { "" } else { "s" }
    );
    println!();

    for schedule in &due {
        println!(
            "  {} {} → {}",
            "SCAN".cyan().bold(),
            schedule.cron_expression,
            schedule.target_url.cyan(),
        );

        match execute_scheduled_scan(pool, config, schedule).await {
            Ok((new_findings, total_findings)) => {
                println!(
                    "    {} {} finding{} ({} new)",
                    "OK".green().bold(),
                    total_findings,
                    if total_findings == 1 { "" } else { "s" },
                    new_findings,
                );
                if let Err(e) = schedules::mark_schedule_run(pool, schedule).await {
                    println!("    {} Failed to update schedule: {e}", "WARN".yellow().bold());
                }
            }
            Err(e) => {
                println!("    {} {e}", "FAIL".red().bold());
            }
        }
    }

    println!();
    Ok(())
}

/// Execute a single scheduled scan and persist results.
async fn execute_scheduled_scan(
    pool: &PgPool,
    config: &Arc<AppConfig>,
    schedule: &crate::storage::models::ScanSchedule,
) -> Result<(usize, usize)> {
    let project = crate::storage::projects::get_project(pool, schedule.project_id)
        .await?
        .ok_or_else(|| ScorchError::Config(format!("project {} not found", schedule.project_id)))?;

    let target = Target::parse(&schedule.target_url)?;

    let http_client = reqwest::Client::builder()
        .user_agent(&config.scan.user_agent)
        .timeout(std::time::Duration::from_secs(config.scan.timeout_seconds))
        .cookie_store(true)
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| ScorchError::Config(format!("failed to build HTTP client: {e}")))?;

    let ctx = ScanContext::new(target, Arc::clone(config), http_client);
    let mut orchestrator = Orchestrator::new(ctx);
    orchestrator.register_default_modules();
    orchestrator.apply_profile(&schedule.profile);

    let result = orchestrator.run(true).await?;
    let total_findings = result.findings.len();

    let modules_run = result.modules_run.clone();
    let modules_skipped: Vec<String> =
        result.modules_skipped.iter().map(|(id, _)| id.clone()).collect();
    let summary_json = serde_json::to_value(&result.summary)?;

    let scan = scans::save_scan(
        pool,
        project.id,
        result.target.url.as_str(),
        &schedule.profile,
        result.started_at,
        Some(result.completed_at),
        &modules_run,
        &modules_skipped,
        &summary_json,
    )
    .await?;

    let new_count = findings::save_findings(pool, project.id, scan.id, &result.findings).await?;

    Ok((new_count, total_findings))
}
