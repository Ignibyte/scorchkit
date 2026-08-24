//! Project and target management CLI handlers.
//!
//! Provides `project create/list/show/delete` and `project target add/remove/list`
//! commands for managing security assessment projects and their associated targets.

use colored::{ColoredString, Colorize};
use sqlx::PgPool;
use uuid::Uuid;

use super::control_adapter::LocalControlClient;
use crate::engine::error::{Result, ScorchError};
use crate::report::terminal::escape_terminal_text;
use crate::storage::intelligence::TargetProfile;
use crate::storage::{findings, projects, scans};
use scorchkit_control::{ControlCommandV1, ControlQueryV1, ControlResultV1};

#[derive(Debug, Default, PartialEq, Eq)]
struct TargetProfileDisplay {
    server: Option<String>,
    cms: Option<String>,
    technologies: Option<String>,
    waf: Option<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ProjectShowSections {
    targets: bool,
    recent_scans: bool,
}

impl ProjectShowSections {
    const fn from_counts(targets: usize, scans: usize) -> Self {
        Self { targets: targets > 0, recent_scans: scans > 0 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProjectStatusSection {
    Severity,
    Status,
    Regressions,
    TopUnresolved,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ProjectStatusSections(Vec<ProjectStatusSection>);

impl ProjectStatusSections {
    fn from_counts(
        severity: usize,
        status: usize,
        regressions: usize,
        top_unresolved: usize,
    ) -> Self {
        let mut sections = Vec::with_capacity(4);
        if severity > 0 {
            sections.push(ProjectStatusSection::Severity);
        }
        if status > 0 {
            sections.push(ProjectStatusSection::Status);
        }
        if regressions > 0 {
            sections.push(ProjectStatusSection::Regressions);
        }
        if top_unresolved > 0 {
            sections.push(ProjectStatusSection::TopUnresolved);
        }
        Self(sections)
    }

    fn from_metrics(metrics: &crate::storage::metrics::PostureMetrics) -> Self {
        Self::from_counts(
            metrics.severity_breakdown.len(),
            metrics.status_breakdown.len(),
            metrics.regressions.len(),
            metrics.top_unresolved.len(),
        )
    }

    fn contains(&self, section: ProjectStatusSection) -> bool {
        self.0.contains(&section)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ScanDetailSections {
    modules_skipped: bool,
}

impl ScanDetailSections {
    const fn from_skipped_count(modules_skipped: usize) -> Self {
        Self { modules_skipped: modules_skipped > 0 }
    }
}

fn project_description_line(description: &str) -> Option<String> {
    (!description.is_empty()).then(|| format!("    Desc: {}", escape_terminal_text(description)))
}

fn target_profile_display(profile: &TargetProfile) -> TargetProfileDisplay {
    TargetProfileDisplay {
        server: profile.server.as_deref().map(escape_terminal_text),
        cms: profile.cms.as_deref().map(escape_terminal_text),
        technologies: (!profile.technologies.is_empty())
            .then(|| escape_terminal_text(&profile.technologies.join(", "))),
        waf: profile.waf.as_deref().map(escape_terminal_text),
    }
}

/// Create a project through the shared control application service.
///
/// # Errors
///
/// Returns an error when authorization, validation, or durable creation fails.
pub(super) async fn control_create(
    control: &LocalControlClient,
    name: &str,
    description: Option<&str>,
) -> Result<()> {
    let result = control
        .command(ControlCommandV1::CreateProject {
            name: name.to_string(),
            description: description.unwrap_or("").to_string(),
        })
        .await?;
    let ControlResultV1::Project(project) = result else {
        return Err(ScorchError::Config(
            "control service returned an unexpected project result".to_string(),
        ));
    };
    println!("{} Project created.", "success:".green().bold());
    println!("      ID: {}", project.id.to_string().dimmed());
    println!("    Name: {}", escape_terminal_text(&project.name).cyan());
    if let Some(description) = project_description_line(&project.description) {
        println!("{description}");
    }
    Ok(())
}

/// List projects through bounded control queries.
///
/// # Errors
///
/// Returns an error when a bounded control query or report projection fails.
pub(super) async fn control_list(control: &LocalControlClient) -> Result<()> {
    let projects = control.projects().await?;
    if projects.is_empty() {
        println!("{}", "No projects found.".dimmed());
        return Ok(());
    }
    println!("{}", "Projects".bold().underline());
    println!();
    for project in projects {
        let result =
            control.query(ControlQueryV1::GetProjectReport { project_id: project.id }).await?;
        let ControlResultV1::Report(report) = result else {
            return Err(ScorchError::Config(
                "control service returned an unexpected report result".to_string(),
            ));
        };
        println!(
            "  {} {} ({} scan{}, {} finding{})",
            escape_terminal_text(&project.name).cyan().bold(),
            project.id.to_string().dimmed(),
            report.scan_count,
            if report.scan_count == 1 { "" } else { "s" },
            report.finding_count,
            if report.finding_count == 1 { "" } else { "s" },
        );
        if !project.description.is_empty() {
            println!("    {}", escape_terminal_text(&project.description).dimmed());
        }
    }
    println!();
    Ok(())
}

/// Show project control state without exposing a storage handle.
///
/// # Errors
///
/// Returns an error when the project is absent or a canonical control read fails.
pub(super) async fn control_show(control: &LocalControlClient, project_ref: &str) -> Result<()> {
    let project = control.project(project_ref).await?;
    let targets = control.targets(project.id).await?;
    let result = control.query(ControlQueryV1::GetProjectReport { project_id: project.id }).await?;
    let ControlResultV1::Report(report) = result else {
        return Err(ScorchError::Config(
            "control service returned an unexpected report result".to_string(),
        ));
    };
    println!("{}\n", "Project Details".bold().underline());
    println!("        ID: {}", project.id.to_string().dimmed());
    println!("      Name: {}", escape_terminal_text(&project.name).cyan().bold());
    println!(
        "      Desc: {}",
        if project.description.is_empty() {
            "-".to_string()
        } else {
            escape_terminal_text(&project.description)
        }
    );
    println!("   Created: {}", project.created_at.format("%Y-%m-%d %H:%M UTC"));
    println!("   Updated: {}", project.updated_at.format("%Y-%m-%d %H:%M UTC"));
    println!("   Targets: {}", report.target_count);
    println!("     Scans: {}", report.scan_count);
    println!("  Findings: {}", report.finding_count);
    if !targets.is_empty() {
        println!("\n  {}", "Targets".bold());
        for target in targets {
            let label = if target.label.is_empty() {
                String::new()
            } else {
                format!(" ({})", escape_terminal_text(&target.label))
            };
            println!(
                "    {} {}{}",
                target.id.to_string().dimmed(),
                escape_terminal_text(&target.url).cyan(),
                label
            );
        }
    }
    println!();
    Ok(())
}

/// Delete a project through the shared control command.
///
/// # Errors
///
/// Returns an error when lookup, policy authorization, or durable deletion fails.
pub(super) async fn control_delete(
    control: &LocalControlClient,
    project_ref: &str,
    force: bool,
) -> Result<()> {
    let project = control.project(project_ref).await?;
    if !force {
        println!(
            "{} This will delete project '{}' and ALL associated data (targets, scans, findings).",
            "warning:".yellow().bold(),
            escape_terminal_text(&project.name),
        );
        println!("Re-run with --force to confirm.");
        return Ok(());
    }
    let result = control.command(ControlCommandV1::DeleteProject { id: project.id }).await?;
    if matches!(result, ControlResultV1::Acknowledged { changed: true, .. }) {
        println!(
            "{} Project '{}' deleted.",
            "success:".green().bold(),
            escape_terminal_text(&project.name)
        );
    }
    Ok(())
}

/// Add a target through the policy-authorized control command.
///
/// # Errors
///
/// Returns an error when project lookup, target authorization, or storage fails.
pub(super) async fn control_target_add(
    control: &LocalControlClient,
    project_ref: &str,
    url: &str,
    label: Option<&str>,
) -> Result<()> {
    let project = control.project(project_ref).await?;
    let result = control
        .command(ControlCommandV1::AddTarget {
            project_id: project.id,
            url: url.to_string(),
            label: label.unwrap_or("").to_string(),
        })
        .await?;
    let ControlResultV1::Target(target) = result else {
        return Err(ScorchError::Config(
            "control service returned an unexpected target result".to_string(),
        ));
    };
    println!(
        "{} Target added to '{}'.",
        "success:".green().bold(),
        escape_terminal_text(&project.name)
    );
    println!("    ID: {}", target.id.to_string().dimmed());
    println!("   URL: {}", escape_terminal_text(&target.url).cyan());
    Ok(())
}

/// Remove a target through the policy-authorized control command.
///
/// # Errors
///
/// Returns an error when IDs, policy authorization, ownership, or storage are invalid.
pub(super) async fn control_target_remove(
    control: &LocalControlClient,
    project_ref: &str,
    target_id_str: &str,
) -> Result<()> {
    let project = control.project(project_ref).await?;
    let target_id = Uuid::parse_str(target_id_str).map_err(|error| {
        ScorchError::Config(format!("invalid target UUID '{target_id_str}': {error}"))
    })?;
    let result = control
        .command(ControlCommandV1::RemoveTarget { project_id: project.id, target_id })
        .await?;
    if matches!(result, ControlResultV1::Acknowledged { changed: true, .. }) {
        println!("{} Target removed.", "success:".green().bold());
    } else {
        println!("{} Target not found.", "warning:".yellow().bold());
    }
    Ok(())
}

/// List project targets through bounded control queries.
///
/// # Errors
///
/// Returns an error when project lookup or a bounded target query fails.
pub(super) async fn control_target_list(
    control: &LocalControlClient,
    project_ref: &str,
) -> Result<()> {
    let project = control.project(project_ref).await?;
    let targets = control.targets(project.id).await?;
    if targets.is_empty() {
        println!("{} No targets for '{}'.", "note:".dimmed(), escape_terminal_text(&project.name));
        return Ok(());
    }
    println!(
        "{} for '{}'\n",
        "Targets".bold().underline(),
        escape_terminal_text(&project.name).cyan()
    );
    for target in targets {
        let label = if target.label.is_empty() {
            String::new()
        } else {
            format!(" ({})", escape_terminal_text(&target.label))
        };
        println!(
            "  {} {}{}",
            target.id.to_string().dimmed(),
            escape_terminal_text(&target.url).cyan(),
            label
        );
    }
    println!();
    Ok(())
}

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
    println!("    Name: {}", escape_terminal_text(&project.name).cyan());
    if let Some(description) = project_description_line(&project.description) {
        println!("{description}");
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
            escape_terminal_text(&p.name).cyan().bold(),
            p.id.to_string().dimmed(),
            scan_count,
            if scan_count == 1 { "" } else { "s" },
            finding_count,
            if finding_count == 1 { "" } else { "s" },
        );
        if !p.description.is_empty() {
            println!("    {}", escape_terminal_text(&p.description).dimmed());
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
    let sections = ProjectShowSections::from_counts(targets.len(), scan_list.len());

    println!("{}", "Project Details".bold().underline());
    println!();
    println!("        ID: {}", project.id.to_string().dimmed());
    println!("      Name: {}", escape_terminal_text(&project.name).cyan().bold());
    println!(
        "      Desc: {}",
        if project.description.is_empty() {
            "-".to_string()
        } else {
            escape_terminal_text(&project.description)
        }
    );
    println!("   Created: {}", project.created_at.format("%Y-%m-%d %H:%M UTC"));
    println!("   Updated: {}", project.updated_at.format("%Y-%m-%d %H:%M UTC"));
    println!("   Targets: {}", targets.len());
    println!("     Scans: {}", scan_list.len());
    println!("  Findings: {}", finding_list.len());

    if sections.targets {
        println!();
        println!("  {}", "Targets".bold());
        for t in &targets {
            let label_part = if t.label.is_empty() {
                String::new()
            } else {
                format!(" ({})", escape_terminal_text(&t.label))
            };
            println!(
                "    {} {}{}",
                t.id.to_string().dimmed(),
                escape_terminal_text(&t.url).cyan(),
                label_part
            );
        }
    }

    if sections.recent_scans {
        println!();
        println!("  {} (last 5)", "Recent Scans".bold());
        for s in scan_list.iter().take(5) {
            let status = if s.completed_at.is_some() { "done".green() } else { "running".yellow() };
            println!(
                "    {} {} → {} [{}]",
                s.id.to_string().dimmed(),
                s.started_at.format("%Y-%m-%d %H:%M"),
                escape_terminal_text(&s.target_url).cyan(),
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
            escape_terminal_text(&project.name),
        );
        println!("Re-run with --force to confirm.");
        return Ok(());
    }

    let deleted = projects::delete_project(pool, project.id).await?;
    if deleted {
        println!(
            "{} Project '{}' deleted.",
            "success:".green().bold(),
            escape_terminal_text(&project.name)
        );
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

    println!(
        "{} Target added to '{}'.",
        "success:".green().bold(),
        escape_terminal_text(&project.name)
    );
    println!("    ID: {}", target.id.to_string().dimmed());
    println!("   URL: {}", escape_terminal_text(&target.url).cyan());
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
    let project = resolve_project(pool, project_ref).await?;

    let target_id = Uuid::parse_str(target_id_str)
        .map_err(|e| ScorchError::Config(format!("invalid target UUID '{target_id_str}': {e}")))?;

    let removed = projects::remove_target(pool, project.id, target_id).await?;
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
        println!("{} No targets for '{}'.", "note:".dimmed(), escape_terminal_text(&project.name));
        return Ok(());
    }

    println!(
        "{} for '{}'",
        "Targets".bold().underline(),
        escape_terminal_text(&project.name).cyan()
    );
    println!();
    for t in &targets {
        let label_part = if t.label.is_empty() {
            String::new()
        } else {
            format!(" ({})", escape_terminal_text(&t.label))
        };
        println!(
            "  {} {}{}",
            t.id.to_string().dimmed(),
            escape_terminal_text(&t.url).cyan(),
            label_part
        );
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
    let sections = ProjectStatusSections::from_metrics(&metrics);

    println!();
    println!(
        "{}  {}",
        "Security Posture".bold().underline(),
        escape_terminal_text(&metrics.project_name).cyan().bold()
    );
    println!("{}", "━".repeat(60).dimmed());

    // Scan summary
    println!();
    println!("  {}", "Scan History".bold());
    println!("    Total scans:   {}", metrics.scan_summary.total_scans.to_string().cyan());
    println!("    Last 30 days:  {}", metrics.scan_summary.scans_last_30_days.to_string().cyan());
    if let Some(ref date) = metrics.scan_summary.latest_scan_date {
        println!("    Latest scan:   {}", escape_terminal_text(date).cyan());
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
    if sections.contains(ProjectStatusSection::Severity) {
        println!();
        println!("  {}", "By Severity".bold());
        for sc in &metrics.severity_breakdown {
            let label = format_severity_colored(&sc.severity);
            println!("    {:<12} {}", label, sc.count);
        }
    }

    // Status breakdown
    if sections.contains(ProjectStatusSection::Status) {
        println!();
        println!("  {}", "By Status".bold());
        for sc in &metrics.status_breakdown {
            println!("    {:<16} {}", escape_terminal_text(&sc.status), sc.count);
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
    if sections.contains(ProjectStatusSection::Regressions) {
        println!();
        println!("  {} ({})", "Regressions".red().bold(), metrics.regressions.len());
        for r in &metrics.regressions {
            println!(
                "    {} {} [{}] was {}",
                format_severity_colored(&r.severity),
                escape_terminal_text(&r.title),
                escape_terminal_text(&r.module_id).dimmed(),
                escape_terminal_text(&r.previous_status).yellow()
            );
        }
    }

    // Top unresolved
    if sections.contains(ProjectStatusSection::TopUnresolved) {
        println!();
        println!("  {}", "Top Unresolved".bold());
        for f in &metrics.top_unresolved {
            println!(
                "    {} {} ({}, seen {}x, since {})",
                format_severity_colored(&f.severity),
                escape_terminal_text(&f.title),
                escape_terminal_text(&f.status).dimmed(),
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
    println!(
        "{}  {}",
        "Module Intelligence".bold().underline(),
        escape_terminal_text(&project.name).cyan().bold()
    );
    println!("{}", "━".repeat(60).dimmed());

    if let Some(ref profile) = intel.target_profile {
        let display = target_profile_display(profile);
        println!();
        println!("  {}", "Target Profile".bold());
        if let Some(server) = display.server {
            println!("    Server:  {}", server.cyan());
        }
        if let Some(cms) = display.cms {
            println!("    CMS:     {}", cms.green());
        }
        if let Some(technologies) = display.technologies {
            println!("    Tech:    {technologies}");
        }
        if let Some(waf) = display.waf {
            println!("    WAF:     {}", waf.yellow());
        }
    }

    println!();
    println!("  Total scans: {}", intel.total_scans.to_string().cyan());
    if let Some(ref updated) = intel.last_updated {
        println!("  Last updated: {}", escape_terminal_text(updated).dimmed());
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
            escape_terminal_text(id).cyan(),
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
fn format_severity_colored(severity: &str) -> ColoredString {
    let safe = escape_terminal_text(severity);
    match severity {
        "critical" => safe.red().bold(),
        "high" => safe.red(),
        "medium" => safe.yellow(),
        "low" => safe.green(),
        "info" => safe.blue(),
        _ => safe.dimmed(),
    }
}

/// Format a count with color based on whether high values are bad.
fn format_count_colored(count: usize, high_is_bad: bool) -> ColoredString {
    let s = count.to_string();
    if count == 0 {
        if high_is_bad {
            s.green()
        } else {
            s.dimmed()
        }
    } else if high_is_bad {
        s.yellow()
    } else {
        s.green()
    }
}

fn format_scan_duration(
    started_at: chrono::DateTime<chrono::Utc>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
) -> String {
    completed_at.map_or_else(
        || "running".to_string(),
        |end| {
            let seconds = (end - started_at).num_seconds();
            if seconds < 60 {
                format!("{seconds}s")
            } else {
                format!("{}m {}s", seconds / 60, seconds % 60)
            }
        },
    )
}

const fn visible_summary_count(count: u64) -> Option<u64> {
    if count > 0 {
        Some(count)
    } else {
        None
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
        println!("No scans found for project '{}'.", escape_terminal_text(&project.name));
        return Ok(());
    }

    println!(
        "Scan history for '{}' ({} scan{})\n",
        escape_terminal_text(&project.name).cyan().bold(),
        scan_list.len(),
        if scan_list.len() == 1 { "" } else { "s" }
    );

    for scan in &scan_list {
        let duration = format_scan_duration(scan.started_at, scan.completed_at);

        let summary: serde_json::Value = scan.summary.clone();
        let total = summary.get("total_findings").and_then(serde_json::Value::as_u64).unwrap_or(0);

        println!(
            "  {} {} | {} | {} modules | {} findings | {}",
            scan.id.to_string().dimmed(),
            scan.started_at.format("%Y-%m-%d %H:%M").to_string().dimmed(),
            escape_terminal_text(&scan.profile).cyan(),
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
    println!("    Target: {}", escape_terminal_text(&scan.target_url).cyan());
    println!("   Profile: {}", escape_terminal_text(&scan.profile).cyan());
    println!("   Started: {}", scan.started_at.format("%Y-%m-%d %H:%M:%S UTC"));
    if let Some(end) = scan.completed_at {
        let secs = (end - scan.started_at).num_seconds();
        println!("  Duration: {secs}s");
    }

    let summary: serde_json::Value = scan.summary.clone();
    let sections = ScanDetailSections::from_skipped_count(scan.modules_skipped.len());
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
        if let Some(count) =
            summary.get(key).and_then(serde_json::Value::as_u64).and_then(visible_summary_count)
        {
            println!("    {label}: {count}");
        }
    }

    println!();
    println!("  {} ({})", "Modules Run".bold(), scan.modules_run.len());
    for m in &scan.modules_run {
        println!("    {}", escape_terminal_text(m).cyan());
    }

    if sections.modules_skipped {
        println!();
        println!("  {} ({})", "Modules Skipped".bold(), scan.modules_skipped.len());
        for m in &scan.modules_skipped {
            println!("    {}", escape_terminal_text(m).dimmed());
        }
    }

    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use colored::{Color, Styles};

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
    async fn project_and_target_commands_persist_their_lifecycle() {
        let Some(pool) = database_pool().await else { return };
        let name = format!("cli-project-lifecycle-{}", Uuid::new_v4());

        let created = create(&pool, &name, Some("fixture description")).await;
        let Some(project) =
            projects::get_project_by_name(&pool, &name).await.expect("query created project")
        else {
            assert!(created.is_err(), "successful create must persist the project");
            return;
        };

        let confirmation_required = delete(&pool, &name, false).await;
        let survived_confirmation = projects::get_project(&pool, project.id)
            .await
            .expect("query project after confirmation warning")
            .is_some();

        let added = target_add(&pool, &name, "https://example.com", Some("fixture")).await;
        let targets_after_add =
            projects::list_targets(&pool, project.id).await.expect("list targets after add");
        let removed = if let Some(target) = targets_after_add.first() {
            target_remove(&pool, &name, &target.id.to_string()).await
        } else {
            Ok(())
        };
        let targets_after_remove = projects::list_targets(&pool, project.id)
            .await
            .expect("list targets after remove")
            .len();

        let deleted = delete(&pool, &name, true).await;
        let gone = projects::get_project(&pool, project.id)
            .await
            .expect("query deleted project")
            .is_none();

        assert!(created.is_ok(), "project creation failed: {created:?}");
        assert!(confirmation_required.is_ok());
        assert!(survived_confirmation, "force=false must preserve the project");
        assert!(added.is_ok(), "target add failed: {added:?}");
        assert_eq!(targets_after_add.len(), 1, "target add must persist exactly one target");
        assert!(removed.is_ok(), "target remove failed: {removed:?}");
        assert_eq!(targets_after_remove, 0, "target remove must delete the target");
        assert!(deleted.is_ok(), "project deletion failed: {deleted:?}");
        assert!(gone, "force=true must delete the project");
    }

    #[tokio::test]
    async fn project_query_commands_reject_missing_or_malformed_references() {
        let Some(pool) = database_pool().await else { return };
        let missing = format!("missing-project-{}", Uuid::new_v4());

        for result in [
            show(&pool, &missing).await,
            status(&pool, &missing).await,
            target_list(&pool, &missing).await,
            intelligence(&pool, &missing).await,
            list_scans(&pool, &missing).await,
        ] {
            assert!(
                result.is_err_and(|error| error.to_string().contains("not found")),
                "missing project must not produce a successful command"
            );
        }
        assert!(show_scan(&pool, "not-a-uuid")
            .await
            .is_err_and(|error| error.to_string().contains("invalid scan UUID")));
    }

    #[test]
    fn severity_and_count_formatters_have_exact_styles() {
        let severities = [
            ("critical", Some(Color::Red), Some(Styles::Bold)),
            ("high", Some(Color::Red), None),
            ("medium", Some(Color::Yellow), None),
            ("low", Some(Color::Green), None),
            ("info", Some(Color::Blue), None),
            ("custom\u{1b}", None, Some(Styles::Dimmed)),
        ];
        for (input, color, style) in severities {
            let rendered = format_severity_colored(input);
            assert_eq!(rendered.input, escape_terminal_text(input));
            assert_eq!(rendered.fgcolor, color);
            if let Some(style) = style {
                assert!(rendered.style.contains(style));
            }
        }

        let zero_bad = format_count_colored(0, true);
        assert_eq!(zero_bad.input, "0");
        assert_eq!(zero_bad.fgcolor, Some(Color::Green));
        assert!(!zero_bad.style.contains(Styles::Dimmed));

        let zero_good = format_count_colored(0, false);
        assert_eq!(zero_good.input, "0");
        assert_eq!(zero_good.fgcolor, None);
        assert!(zero_good.style.contains(Styles::Dimmed));

        let nonzero_bad = format_count_colored(7, true);
        assert_eq!(nonzero_bad.input, "7");
        assert_eq!(nonzero_bad.fgcolor, Some(Color::Yellow));

        let nonzero_good = format_count_colored(7, false);
        assert_eq!(nonzero_good.input, "7");
        assert_eq!(nonzero_good.fgcolor, Some(Color::Green));
    }

    #[test]
    fn project_section_predicates_cover_every_presence_combination() {
        assert_eq!(ProjectShowSections::from_counts(0, 0), ProjectShowSections::default());
        assert_eq!(
            ProjectShowSections::from_counts(1, 0),
            ProjectShowSections { targets: true, recent_scans: false }
        );
        assert_eq!(
            ProjectShowSections::from_counts(0, 1),
            ProjectShowSections { targets: false, recent_scans: true }
        );
        assert_eq!(
            ProjectShowSections::from_counts(2, 3),
            ProjectShowSections { targets: true, recent_scans: true }
        );

        assert_eq!(
            ProjectStatusSections::from_counts(0, 0, 0, 0),
            ProjectStatusSections::default()
        );
        let expected = [
            ProjectStatusSections(vec![ProjectStatusSection::Severity]),
            ProjectStatusSections(vec![ProjectStatusSection::Status]),
            ProjectStatusSections(vec![ProjectStatusSection::Regressions]),
            ProjectStatusSections(vec![ProjectStatusSection::TopUnresolved]),
        ];
        for (counts, expected) in [
            ((1, 0, 0, 0), &expected[0]),
            ((0, 1, 0, 0), &expected[1]),
            ((0, 0, 1, 0), &expected[2]),
            ((0, 0, 0, 1), &expected[3]),
        ] {
            let actual = ProjectStatusSections::from_counts(counts.0, counts.1, counts.2, counts.3);
            assert_eq!(&actual, expected);
        }

        let metrics = crate::storage::metrics::PostureMetrics {
            project_name: "fixture".to_string(),
            scan_summary: crate::storage::metrics::ScanSummary {
                total_scans: 0,
                latest_scan_date: None,
                latest_scan_id: None,
                scans_last_30_days: 0,
            },
            finding_summary: crate::storage::metrics::FindingSummary {
                total_findings: 1,
                active_findings: 1,
                resolved_findings: 0,
            },
            severity_breakdown: vec![crate::storage::metrics::SeverityCount {
                severity: "high".to_string(),
                count: 1,
            }],
            status_breakdown: Vec::new(),
            regressions: Vec::new(),
            top_unresolved: Vec::new(),
            trend: crate::storage::metrics::TrendDirection::Declining,
            mttr_days: None,
        };
        let metric_sections = ProjectStatusSections::from_metrics(&metrics);
        assert!(metric_sections.contains(ProjectStatusSection::Severity));
        assert!(!metric_sections.contains(ProjectStatusSection::Status));

        assert_eq!(ScanDetailSections::from_skipped_count(0), ScanDetailSections::default());
        assert_eq!(
            ScanDetailSections::from_skipped_count(2),
            ScanDetailSections { modules_skipped: true }
        );
    }

    #[test]
    fn scan_duration_and_visible_counts_pin_boundaries() {
        let started = chrono::Utc::now();
        assert_eq!(format_scan_duration(started, None), "running");
        assert_eq!(
            format_scan_duration(started, Some(started + chrono::TimeDelta::seconds(59))),
            "59s"
        );
        assert_eq!(
            format_scan_duration(started, Some(started + chrono::TimeDelta::seconds(60))),
            "1m 0s"
        );
        assert_eq!(
            format_scan_duration(started, Some(started + chrono::TimeDelta::seconds(61))),
            "1m 1s"
        );
        assert_eq!(visible_summary_count(0), None);
        assert_eq!(visible_summary_count(1), Some(1));
        assert_eq!(visible_summary_count(9), Some(9));
    }

    #[test]
    fn optional_project_description_is_explicit_and_terminal_safe() {
        assert_eq!(project_description_line(""), None);
        assert_eq!(
            project_description_line("fixture\u{1b}"),
            Some("    Desc: fixture\\u{1b}".to_string())
        );
    }

    #[test]
    fn target_profile_display_preserves_present_fields_and_omits_empty_technology() {
        let without_technology = TargetProfile {
            server: Some("nginx\u{1b}".to_string()),
            cms: Some("WordPress".to_string()),
            technologies: Vec::new(),
            waf: Some("Cloudflare".to_string()),
            is_https: true,
        };
        assert_eq!(
            target_profile_display(&without_technology),
            TargetProfileDisplay {
                server: Some("nginx\\u{1b}".to_string()),
                cms: Some("WordPress".to_string()),
                technologies: None,
                waf: Some("Cloudflare".to_string()),
            }
        );

        let with_technology = TargetProfile {
            technologies: vec!["Rust".to_string(), "HTMX\u{1b}".to_string()],
            ..TargetProfile::default()
        };
        assert_eq!(
            target_profile_display(&with_technology),
            TargetProfileDisplay {
                server: None,
                cms: None,
                technologies: Some("Rust, HTMX\\u{1b}".to_string()),
                waf: None,
            }
        );
    }
}
