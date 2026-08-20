//! Scan schedule management CLI handlers.
//!
//! Provides `schedule create/list/show/enable/disable/delete/run-due`
//! commands for managing recurring scan schedules per project.

use std::sync::Arc;

use colored::Colorize;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::policy::Engagement;
use crate::engine::target::Target;
use crate::facade::Engine;
use crate::report::terminal::escape_terminal_text;
use crate::storage::models::ScanSchedule;
use crate::storage::{findings, scans, schedules};

/// Final state of one scheduled scan attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledScanStatus {
    /// The scan persisted and the schedule advanced.
    Success,
    /// The scan or schedule update failed.
    Error,
}

/// Structured result for one schedule in a due-scan batch.
#[derive(Debug, Clone, Serialize)]
pub struct ScheduledScanOutcome {
    /// Schedule that was attempted.
    pub schedule_id: Uuid,
    /// Canonical scan target.
    pub target: String,
    /// Cron expression active for the attempt.
    pub cron: String,
    /// Whether execution and timestamp advancement succeeded.
    pub status: ScheduledScanStatus,
    /// Findings not previously recorded for the project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_findings: Option<usize>,
    /// Total findings emitted by this scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_findings: Option<usize>,
    /// Failure detail when the outcome is `Error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Create a new scan schedule.
///
/// # Errors
///
/// Returns an error if the project is not found, the cron expression is
/// invalid, or the database query fails.
pub async fn create(
    config: &Arc<AppConfig>,
    pool: &PgPool,
    project_ref: &str,
    target_url: &str,
    cron_expression: &str,
    profile: &str,
) -> Result<()> {
    let project = crate::cli::project::resolve_project(pool, project_ref).await?;
    let target = Target::parse(target_url)?;
    let registered = crate::storage::projects::list_targets(pool, project.id)
        .await?
        .into_iter()
        .any(|entry| Target::parse(&entry.url).is_ok_and(|candidate| candidate.url == target.url));
    if !registered {
        return Err(ScorchError::Config(format!(
            "scheduled target '{}' is not registered to project '{}'",
            target.url, project.name
        )));
    }

    let engine = Engine::new(Arc::clone(config));
    engine.authorize_web_scan_for_profile(&target.url, profile)?;
    let engagement = engine.engagement().ok_or_else(|| {
        ScorchError::Config(
            "schedule creation denied: no engagement authorization is configured".to_string(),
        )
    })?;
    let schedule = schedules::create_schedule(
        pool,
        project.id,
        target.url.as_str(),
        profile,
        cron_expression,
        engagement,
    )
    .await?;

    println!("{} Schedule created.", "success:".green().bold());
    println!("        ID: {}", schedule.id.to_string().dimmed());
    println!("   Project: {}", escape_terminal_text(&project.name).cyan());
    println!("    Target: {}", escape_terminal_text(&schedule.target_url).cyan());
    println!("      Cron: {}", escape_terminal_text(&schedule.cron_expression));
    println!("   Profile: {}", escape_terminal_text(&schedule.profile));
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
        println!(
            "{} No schedules for '{}'.",
            "note:".dimmed(),
            escape_terminal_text(&project.name)
        );
        return Ok(());
    }

    println!(
        "{} for '{}'",
        "Schedules".bold().underline(),
        escape_terminal_text(&project.name).cyan()
    );
    println!();
    for s in &schedule_list {
        let status = if s.enabled { "enabled".green() } else { "disabled".red() };
        println!(
            "  {} [{}] {} → {} ({})",
            s.id.to_string().dimmed(),
            status,
            escape_terminal_text(&s.cron_expression),
            escape_terminal_text(&s.target_url).cyan(),
            escape_terminal_text(&s.profile),
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
    println!("    Target: {}", escape_terminal_text(&schedule.target_url).cyan());
    println!("      Cron: {}", escape_terminal_text(&schedule.cron_expression));
    println!("   Profile: {}", escape_terminal_text(&schedule.profile));
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
    let outcomes = execute_due_schedules(pool, config).await?;

    if outcomes.is_empty() {
        println!("{} No schedules are due.", "note:".dimmed());
        return Ok(());
    }

    println!(
        "{} {} schedule{} due",
        "Running".bold(),
        outcomes.len(),
        if outcomes.len() == 1 { "" } else { "s" }
    );
    println!();

    for outcome in outcomes {
        println!(
            "  {} {} → {}",
            "SCAN".cyan().bold(),
            escape_terminal_text(&outcome.cron),
            escape_terminal_text(&outcome.target).cyan()
        );
        match outcome.status {
            ScheduledScanStatus::Success => {
                let new_findings = outcome.new_findings.unwrap_or_default();
                let total_findings = outcome.total_findings.unwrap_or_default();
                println!(
                    "    {} {} finding{} ({} new)",
                    "OK".green().bold(),
                    total_findings,
                    if total_findings == 1 { "" } else { "s" },
                    new_findings,
                );
            }
            ScheduledScanStatus::Error => {
                println!(
                    "    {} {}",
                    "FAIL".red().bold(),
                    escape_terminal_text(
                        outcome.error.as_deref().unwrap_or("scheduled scan failed")
                    )
                );
            }
        }
    }

    println!();
    Ok(())
}

/// Execute each currently due schedule exactly once and return structured outcomes.
///
/// A short `FOR UPDATE SKIP LOCKED` transaction claims and advances due rows.
/// The transaction commits before any scan begins, so a one-connection pool
/// remains live and overlapping callers cannot execute the same occurrence.
///
/// # Errors
///
/// Returns an error if due rows cannot be claimed. Individual scan failures are
/// returned as outcomes.
pub async fn execute_due_schedules(
    pool: &PgPool,
    config: &Arc<AppConfig>,
) -> Result<Vec<ScheduledScanOutcome>> {
    let due = schedules::claim_due_schedules(pool).await?;
    let mut outcomes = Vec::with_capacity(due.len());
    for schedule in &due {
        let outcome = match execute_scheduled_scan(pool, config, schedule).await {
            Ok((new_findings, total_findings)) => ScheduledScanOutcome {
                schedule_id: schedule.id,
                target: schedule.target_url.clone(),
                cron: schedule.cron_expression.clone(),
                status: ScheduledScanStatus::Success,
                new_findings: Some(new_findings),
                total_findings: Some(total_findings),
                error: None,
            },
            Err(error) => ScheduledScanOutcome {
                schedule_id: schedule.id,
                target: schedule.target_url.clone(),
                cron: schedule.cron_expression.clone(),
                status: ScheduledScanStatus::Error,
                new_findings: None,
                total_findings: None,
                error: Some(error.to_string()),
            },
        };
        outcomes.push(outcome);
    }

    Ok(outcomes)
}

/// Execute a single scheduled scan and persist results.
async fn execute_scheduled_scan(
    pool: &PgPool,
    config: &Arc<AppConfig>,
    schedule: &ScanSchedule,
) -> Result<(usize, usize)> {
    let project = crate::storage::projects::get_project(pool, schedule.project_id)
        .await?
        .ok_or_else(|| ScorchError::Config(format!("project {} not found", schedule.project_id)))?;

    let target = Target::parse(&schedule.target_url)?;
    let registered_targets = crate::storage::projects::list_targets(pool, project.id).await?;
    let registered = registered_targets
        .iter()
        .any(|entry| Target::parse(&entry.url).is_ok_and(|candidate| candidate.url == target.url));
    if !registered {
        return Err(ScorchError::Config(format!(
            "scheduled target '{}' is not registered to project '{}'",
            target.url, project.name
        )));
    }

    let stored_engagement = schedule_engagement(schedule)?;
    let active_engagement = config.engagement.as_ref().ok_or_else(|| {
        ScorchError::Config(
            "scheduled scan denied: no engagement authorization is configured".to_string(),
        )
    })?;
    if active_engagement != &stored_engagement {
        return Err(ScorchError::Config(format!(
            "scheduled scan {} denied: active engagement does not match its authorization snapshot",
            schedule.id
        )));
    }

    let engine = Engine::for_engagement(Arc::clone(config), Arc::new(stored_engagement));
    let result = engine.scan_with_profile(target.url.as_str(), &schedule.profile).await?;
    let total_findings = result.findings.len();

    let modules_run = result.modules_run.clone();
    let modules_skipped: Vec<String> =
        result.modules_skipped.iter().map(|(id, _)| id.clone()).collect();
    let summary_json = serde_json::to_value(&result.summary)?;

    let scan = scans::save_scan_with_evidence(
        pool,
        project.id,
        result.target.url.as_str(),
        &schedule.profile,
        result.started_at,
        Some(result.completed_at),
        &modules_run,
        &modules_skipped,
        &summary_json,
        &scans::execution_evidence(&result),
    )
    .await?;

    let new_count = findings::save_findings(pool, project.id, scan.id, &result.findings).await?;

    Ok((new_count, total_findings))
}

fn schedule_engagement(schedule: &ScanSchedule) -> Result<Engagement> {
    let snapshot = schedule.engagement_snapshot.clone().ok_or_else(|| {
        ScorchError::Config(format!(
            "scheduled scan {} denied: no engagement authorization snapshot is stored; recreate the schedule",
            schedule.id
        ))
    })?;
    serde_json::from_value(snapshot).map_err(|error| {
        ScorchError::Config(format!(
            "scheduled scan {} denied: invalid engagement authorization snapshot: {error}",
            schedule.id
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn database_pool() -> Option<PgPool> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::storage::connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("database connection failed: {error}"));
        crate::storage::migrate::run_migrations(&pool)
            .await
            .unwrap_or_else(|error| panic!("database migration failed: {error}"));
        Some(pool)
    }

    #[tokio::test]
    async fn schedule_creation_requires_registration_and_engagement() {
        let Some(pool) = database_pool().await else { return };
        let project_name = format!("cli-schedule-policy-{}", Uuid::new_v4());
        let project = crate::storage::projects::create_project(&pool, &project_name, "fixture")
            .await
            .expect("create project");
        crate::storage::projects::add_target(&pool, project.id, "https://example.com", "fixture")
            .await
            .expect("register target");

        let result = create(
            &Arc::new(AppConfig::default()),
            &pool,
            &project_name,
            "https://example.com",
            "0 0 * * *",
            "quick",
        )
        .await;
        let schedule_count =
            schedules::list_schedules(&pool, project.id).await.expect("list schedules").len();
        crate::storage::projects::delete_project(&pool, project.id).await.expect("delete project");

        assert!(
            result.is_err_and(|error| error.to_string().contains("no engagement authorization")),
            "schedule creation must fail at the engagement boundary"
        );
        assert_eq!(schedule_count, 0);
    }

    #[tokio::test]
    async fn schedule_query_commands_reject_missing_or_malformed_references() {
        let Some(pool) = database_pool().await else { return };
        let missing = format!("missing-schedule-project-{}", Uuid::new_v4());
        assert!(list(&pool, &missing)
            .await
            .is_err_and(|error| error.to_string().contains("not found")));
        assert!(show(&pool, "not-a-uuid")
            .await
            .is_err_and(|error| error.to_string().contains("invalid schedule UUID")));

        pool.close().await;
        assert!(
            run_due(&pool, &Arc::new(AppConfig::default())).await.is_err(),
            "run-due must propagate a closed database pool"
        );
    }
}
