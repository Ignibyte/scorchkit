//! Project and target management CLI handlers.
//!
//! Provides `project create/list/show/delete` and `project target add/remove/list`
//! commands for managing security assessment projects and their associated targets.

use colored::Colorize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::engine::error::{Result, ScorchError};
use crate::storage::{findings, projects, scans};

/// Create a new project.
///
/// # Errors
///
/// Returns an error if the project name already exists or the database query fails.
pub async fn create(pool: &PgPool, name: &str, description: Option<&str>) -> Result<()> {
    let desc = description.unwrap_or("");
    let project = projects::create_project(pool, name, desc).await?;

    println!("{} Project created.", "success:".green().bold());
    println!("      ID: {}", project.id.to_string().dimmed());
    println!("    Name: {}", project.name.cyan());
    if !project.description.is_empty() {
        println!("    Desc: {}", project.description);
    }
    Ok(())
}

/// List all projects.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn list(pool: &PgPool) -> Result<()> {
    let projects = projects::list_projects(pool).await?;

    if projects.is_empty() {
        println!("{}", "No projects found.".dimmed());
        return Ok(());
    }

    println!("{}", "Projects".bold().underline());
    println!();
    for p in &projects {
        let scan_count = scans::list_scans(pool, p.id).await?.len();
        let finding_count = findings::list_findings(pool, p.id).await?.len();
        println!(
            "  {} {} ({} scan{}, {} finding{})",
            p.name.cyan().bold(),
            p.id.to_string().dimmed(),
            scan_count,
            if scan_count == 1 { "" } else { "s" },
            finding_count,
            if finding_count == 1 { "" } else { "s" },
        );
        if !p.description.is_empty() {
            println!("    {}", p.description.dimmed());
        }
    }
    println!();
    Ok(())
}

/// Show details for a single project.
///
/// # Errors
///
/// Returns an error if the project is not found or the database query fails.
pub async fn show(pool: &PgPool, project_ref: &str) -> Result<()> {
    let project = resolve_project(pool, project_ref).await?;

    let targets = projects::list_targets(pool, project.id).await?;
    let scan_list = scans::list_scans(pool, project.id).await?;
    let finding_list = findings::list_findings(pool, project.id).await?;

    println!("{}", "Project Details".bold().underline());
    println!();
    println!("        ID: {}", project.id.to_string().dimmed());
    println!("      Name: {}", project.name.cyan().bold());
    println!(
        "      Desc: {}",
        if project.description.is_empty() { "-" } else { &project.description }
    );
    println!("   Created: {}", project.created_at.format("%Y-%m-%d %H:%M UTC"));
    println!("   Updated: {}", project.updated_at.format("%Y-%m-%d %H:%M UTC"));
    println!("   Targets: {}", targets.len());
    println!("     Scans: {}", scan_list.len());
    println!("  Findings: {}", finding_list.len());

    if !targets.is_empty() {
        println!();
        println!("  {}", "Targets".bold());
        for t in &targets {
            let label_part =
                if t.label.is_empty() { String::new() } else { format!(" ({})", t.label) };
            println!("    {} {}{}", t.id.to_string().dimmed(), t.url.cyan(), label_part);
        }
    }

    if !scan_list.is_empty() {
        println!();
        println!("  {} (last 5)", "Recent Scans".bold());
        for s in scan_list.iter().take(5) {
            let status = if s.completed_at.is_some() { "done".green() } else { "running".yellow() };
            println!(
                "    {} {} → {} [{}]",
                s.id.to_string().dimmed(),
                s.started_at.format("%Y-%m-%d %H:%M"),
                s.target_url.cyan(),
                status,
            );
        }
    }

    println!();
    Ok(())
}

/// Delete a project.
///
/// # Errors
///
/// Returns an error if the project is not found or the database query fails.
pub async fn delete(pool: &PgPool, project_ref: &str, force: bool) -> Result<()> {
    let project = resolve_project(pool, project_ref).await?;

    if !force {
        println!(
            "{} This will delete project '{}' and ALL associated data (targets, scans, findings).",
            "warning:".yellow().bold(),
            project.name,
        );
        println!("Re-run with --force to confirm.");
        return Ok(());
    }

    let deleted = projects::delete_project(pool, project.id).await?;
    if deleted {
        println!("{} Project '{}' deleted.", "success:".green().bold(), project.name);
    }
    Ok(())
}

/// Add a target to a project.
///
/// # Errors
///
/// Returns an error if the project is not found, the target URL is a
/// duplicate, or the database query fails.
pub async fn target_add(
    pool: &PgPool,
    project_ref: &str,
    url: &str,
    label: Option<&str>,
) -> Result<()> {
    let project = resolve_project(pool, project_ref).await?;
    let target = projects::add_target(pool, project.id, url, label.unwrap_or("")).await?;

    println!("{} Target added to '{}'.", "success:".green().bold(), project.name);
    println!("    ID: {}", target.id.to_string().dimmed());
    println!("   URL: {}", target.url.cyan());
    Ok(())
}

/// Remove a target from a project.
///
/// # Errors
///
/// Returns an error if the project is not found, the target UUID is invalid,
/// or the database query fails.
pub async fn target_remove(pool: &PgPool, project_ref: &str, target_id_str: &str) -> Result<()> {
    // Verify project exists
    let _project = resolve_project(pool, project_ref).await?;

    let target_id = Uuid::parse_str(target_id_str)
        .map_err(|e| ScorchError::Config(format!("invalid target UUID '{target_id_str}': {e}")))?;

    let removed = projects::remove_target(pool, target_id).await?;
    if removed {
        println!("{} Target removed.", "success:".green().bold());
    } else {
        println!("{} Target not found.", "warning:".yellow().bold());
    }
    Ok(())
}

/// List targets for a project.
///
/// # Errors
///
/// Returns an error if the project is not found or the database query fails.
pub async fn target_list(pool: &PgPool, project_ref: &str) -> Result<()> {
    let project = resolve_project(pool, project_ref).await?;
    let targets = projects::list_targets(pool, project.id).await?;

    if targets.is_empty() {
        println!("{} No targets for '{}'.", "note:".dimmed(), project.name);
        return Ok(());
    }

    println!("{} for '{}'", "Targets".bold().underline(), project.name.cyan());
    println!();
    for t in &targets {
        let label_part = if t.label.is_empty() { String::new() } else { format!(" ({})", t.label) };
        println!("  {} {}{}", t.id.to_string().dimmed(), t.url.cyan(), label_part);
    }
    println!();
    Ok(())
}

/// Show posture metrics and trend analysis for a project.
///
/// Renders a colored terminal dashboard showing scan summary, finding
/// breakdown by severity and status, regression alerts, trend direction,
/// and top unresolved findings.
///
/// # Errors
///
/// Returns an error if the project is not found or the database query fails.
pub async fn status(pool: &PgPool, project_ref: &str) -> Result<()> {
    let project = resolve_project(pool, project_ref).await?;
    let metrics =
        crate::storage::metrics::build_posture_metrics(pool, project.id, &project.name).await?;

    println!();
    println!("{}  {}", "Security Posture".bold().underline(), metrics.project_name.cyan().bold());
    println!("{}", "━".repeat(60).dimmed());

    // Scan summary
    println!();
    println!("  {}", "Scan History".bold());
    println!("    Total scans:   {}", metrics.scan_summary.total_scans.to_string().cyan());
    println!("    Last 30 days:  {}", metrics.scan_summary.scans_last_30_days.to_string().cyan());
    if let Some(ref date) = metrics.scan_summary.latest_scan_date {
        println!("    Latest scan:   {}", date.cyan());
    } else {
        println!("    Latest scan:   {}", "none".dimmed());
    }

    // Finding summary
    println!();
    println!("  {}", "Finding Summary".bold());
    println!("    Total:    {}", metrics.finding_summary.total_findings.to_string().cyan());
    println!(
        "    Active:   {}",
        format_count_colored(metrics.finding_summary.active_findings, true)
    );
    println!(
        "    Resolved: {}",
        format_count_colored(metrics.finding_summary.resolved_findings, false)
    );

    // Severity breakdown
    if !metrics.severity_breakdown.is_empty() {
        println!();
        println!("  {}", "By Severity".bold());
        for sc in &metrics.severity_breakdown {
            let label = format_severity_colored(&sc.severity);
            println!("    {:<12} {}", label, sc.count);
        }
    }

    // Status breakdown
    if !metrics.status_breakdown.is_empty() {
        println!();
        println!("  {}", "By Status".bold());
        for sc in &metrics.status_breakdown {
            println!("    {:<16} {}", sc.status, sc.count);
        }
    }

    // Trend
    println!();
    println!("  {}", "Trend".bold());
    let trend_display = match metrics.trend {
        crate::storage::metrics::TrendDirection::Improving => {
            metrics.trend.label().green().bold().to_string()
        }
        crate::storage::metrics::TrendDirection::Declining => {
            metrics.trend.label().red().bold().to_string()
        }
        crate::storage::metrics::TrendDirection::Stable => {
            metrics.trend.label().yellow().bold().to_string()
        }
    };
    println!("    Direction: {trend_display}");
    println!(
        "    MTTR:      {}",
        metrics.mttr_days.map_or_else(
            || "n/a (requires status change tracking)".dimmed().to_string(),
            |d| format!("{d:.1} days"),
        )
    );

    // Regressions
    if !metrics.regressions.is_empty() {
        println!();
        println!("  {} ({})", "Regressions".red().bold(), metrics.regressions.len());
        for r in &metrics.regressions {
            println!(
                "    {} {} [{}] was {}",
                format_severity_colored(&r.severity),
                r.title,
                r.module_id.dimmed(),
                r.previous_status.yellow()
            );
        }
    }

    // Top unresolved
    if !metrics.top_unresolved.is_empty() {
        println!();
        println!("  {}", "Top Unresolved".bold());
        for f in &metrics.top_unresolved {
            println!(
                "    {} {} ({}, seen {}x, since {})",
                format_severity_colored(&f.severity),
                f.title,
                f.status.dimmed(),
                f.seen_count,
                f.first_seen.dimmed(),
            );
        }
    }

    println!();
    Ok(())
}

/// Show module effectiveness intelligence for a project.
///
/// Displays per-module statistics: run count, findings, severity
/// breakdown, and effectiveness score — sorted by total findings.
///
/// # Errors
///
/// Returns an error if the project is not found or the database query fails.
pub async fn intelligence(pool: &PgPool, project_ref: &str) -> Result<()> {
    let project = resolve_project(pool, project_ref).await?;
    let intel = crate::storage::intelligence::get_intelligence(pool, project.id).await?;

    println!();
    println!("{}  {}", "Module Intelligence".bold().underline(), project.name.cyan().bold());
    println!("{}", "━".repeat(60).dimmed());

    if let Some(ref profile) = intel.target_profile {
        println!();
        println!("  {}", "Target Profile".bold());
        if let Some(ref s) = profile.server {
            println!("    Server:  {}", s.cyan());
        }
        if let Some(ref c) = profile.cms {
            println!("    CMS:     {}", c.green());
        }
        if !profile.technologies.is_empty() {
            println!("    Tech:    {}", profile.technologies.join(", "));
        }
        if let Some(ref w) = profile.waf {
            println!("    WAF:     {}", w.yellow());
        }
    }

    println!();
    println!("  Total scans: {}", intel.total_scans.to_string().cyan());
    if let Some(ref updated) = intel.last_updated {
        println!("  Last updated: {}", updated.dimmed());
    }

    if intel.modules.is_empty() {
        println!();
        println!("  {} No module data yet. Run a scan with --project first.", "note:".dimmed());
        println!();
        return Ok(());
    }

    // Sort by total_findings descending
    let mut sorted: Vec<_> = intel.modules.iter().collect();
    sorted.sort_by(|a, b| b.1.total_findings.cmp(&a.1.total_findings).then_with(|| a.0.cmp(b.0)));

    println!();
    println!(
        "  {:<20} {:>5} {:>8} {:>4} {:>4} {:>4} {:>4} {:>4} {:>6}",
        "Module".bold(),
        "Runs".bold(),
        "Findings".bold(),
        "C".red().bold(),
        "H".red(),
        "M".yellow(),
        "L".green(),
        "I".blue(),
        "Score".bold(),
    );
    println!("  {}", "─".repeat(58).dimmed());

    for (id, stats) in &sorted {
        println!(
            "  {:<20} {:>5} {:>8} {:>4} {:>4} {:>4} {:>4} {:>4} {:>6.1}",
            id.cyan(),
            stats.total_runs,
            stats.total_findings,
            stats.critical,
            stats.high,
            stats.medium,
            stats.low,
            stats.info,
            stats.effectiveness_score,
        );
    }

    println!();
    Ok(())
}

/// Format a severity label with appropriate color.
fn format_severity_colored(severity: &str) -> String {
    match severity {
        "critical" => "critical".red().bold().to_string(),
        "high" => "high".red().to_string(),
        "medium" => "medium".yellow().to_string(),
        "low" => "low".green().to_string(),
        "info" => "info".blue().to_string(),
        other => other.dimmed().to_string(),
    }
}

/// Format a count with color based on whether high values are bad.
fn format_count_colored(count: usize, high_is_bad: bool) -> String {
    let s = count.to_string();
    if count == 0 {
        if high_is_bad {
            s.green().to_string()
        } else {
            s.dimmed().to_string()
        }
    } else if high_is_bad {
        s.yellow().to_string()
    } else {
        s.green().to_string()
    }
}

/// Resolve a project reference (name or UUID) to a `Project`.
///
/// # Errors
///
/// Returns an error if the project is not found by name or UUID,
/// or if the database query fails.
pub async fn resolve_project(
    pool: &PgPool,
    project_ref: &str,
) -> Result<crate::storage::models::Project> {
    // Try as UUID first
    if let Ok(uuid) = Uuid::parse_str(project_ref) {
        if let Some(project) = projects::get_project(pool, uuid).await? {
            return Ok(project);
        }
    }

    // Fall back to name lookup
    projects::get_project_by_name(pool, project_ref)
        .await?
        .ok_or_else(|| ScorchError::Config(format!("project '{project_ref}' not found")))
}

/// List scan history for a project.
///
/// # Errors
///
/// Returns an error if the project is not found or the database query fails.
pub async fn list_scans(pool: &PgPool, project_ref: &str) -> Result<()> {
    let project = resolve_project(pool, project_ref).await?;
    let scan_list = scans::list_scans(pool, project.id).await?;

    if scan_list.is_empty() {
        println!("No scans found for project '{}'.", project.name);
        return Ok(());
    }

    println!(
        "Scan history for '{}' ({} scan{})\n",
        project.name.cyan().bold(),
        scan_list.len(),
        if scan_list.len() == 1 { "" } else { "s" }
    );

    for scan in &scan_list {
        let duration = scan.completed_at.map_or_else(
            || "running".to_string(),
            |end| {
                let secs = (end - scan.started_at).num_seconds();
                if secs < 60 {
                    format!("{secs}s")
                } else {
                    format!("{}m {}s", secs / 60, secs % 60)
                }
            },
        );

        let summary: serde_json::Value = scan.summary.clone();
        let total = summary.get("total_findings").and_then(serde_json::Value::as_u64).unwrap_or(0);

        println!(
            "  {} {} | {} | {} modules | {} findings | {}",
            scan.id.to_string().dimmed(),
            scan.started_at.format("%Y-%m-%d %H:%M").to_string().dimmed(),
            scan.profile.cyan(),
            scan.modules_run.len(),
            total,
            duration.dimmed(),
        );
    }

    println!();
    println!("  Use {} to see details for a specific scan.", "project scan-show <id>".dimmed());
    Ok(())
}

/// Show detailed information for a specific scan.
///
/// # Errors
///
/// Returns an error if the scan is not found or the database query fails.
pub async fn show_scan(pool: &PgPool, id_str: &str) -> Result<()> {
    let id = Uuid::parse_str(id_str)
        .map_err(|e| ScorchError::Config(format!("invalid scan UUID '{id_str}': {e}")))?;

    let scan = scans::get_scan(pool, id)
        .await?
        .ok_or_else(|| ScorchError::Config(format!("scan '{id_str}' not found")))?;

    println!("{}", "Scan Details".bold().underline());
    println!();
    println!("        ID: {}", scan.id.to_string().dimmed());
    println!("    Target: {}", scan.target_url.cyan());
    println!("   Profile: {}", scan.profile.cyan());
    println!("   Started: {}", scan.started_at.format("%Y-%m-%d %H:%M:%S UTC"));
    if let Some(end) = scan.completed_at {
        let secs = (end - scan.started_at).num_seconds();
        println!("  Duration: {secs}s");
    }

    let summary: serde_json::Value = scan.summary.clone();
    println!();
    println!("  {}", "Summary".bold());
    if let Some(total) = summary.get("total_findings").and_then(serde_json::Value::as_u64) {
        println!("    Total findings: {}", total.to_string().bold());
    }
    for (key, label) in [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Info"),
    ] {
        if let Some(count) = summary.get(key).and_then(serde_json::Value::as_u64) {
            if count > 0 {
                println!("    {label}: {count}");
            }
        }
    }

    println!();
    println!("  {} ({})", "Modules Run".bold(), scan.modules_run.len());
    for m in &scan.modules_run {
        println!("    {}", m.cyan());
    }

    if !scan.modules_skipped.is_empty() {
        println!();
        println!("  {} ({})", "Modules Skipped".bold(), scan.modules_skipped.len());
        for m in &scan.modules_skipped {
            println!("    {}", m.dimmed());
        }
    }

    println!();
    Ok(())
}
