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
