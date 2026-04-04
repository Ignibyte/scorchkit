//! Finding query and lifecycle management CLI handlers.
//!
//! Provides `finding list/show/status` commands for querying tracked
//! vulnerability findings and updating their lifecycle status.

use colored::Colorize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::engine::error::{Result, ScorchError};
use crate::storage::findings;
use crate::storage::models::VulnStatus;

/// List findings for a project with optional filters.
///
/// # Errors
///
/// Returns an error if the project is not found, the filter values are
/// invalid, or the database query fails.
pub async fn list(
    pool: &PgPool,
    project_ref: &str,
    severity: Option<&str>,
    status: Option<&str>,
) -> Result<()> {
    let project = super::project::resolve_project(pool, project_ref).await?;

    let finding_list = match (severity, status) {
        (Some(sev), _) => findings::find_by_severity(pool, project.id, sev).await?,
        (_, Some(st)) => {
            let vuln_status = VulnStatus::from_db(st).ok_or_else(|| {
                ScorchError::Config(format!(
                    "invalid status '{st}'. \
                     Valid: new, acknowledged, false_positive, remediated, verified"
                ))
            })?;
            findings::find_by_status(pool, project.id, vuln_status).await?
        }
        _ => findings::list_findings(pool, project.id).await?,
    };

    if finding_list.is_empty() {
        println!("{} No findings for '{}'.", "note:".dimmed(), project.name);
        return Ok(());
    }

    println!(
        "{} for '{}' ({} total)",
        "Findings".bold().underline(),
        project.name.cyan(),
        finding_list.len(),
    );
    println!();

    for f in &finding_list {
        let severity_colored = colorize_severity(&f.severity);
        let status_colored = colorize_status(&f.status);
        println!(
            "  {} {} {} [{}] ({})",
            f.id.to_string().dimmed(),
            severity_colored,
            f.title,
            status_colored,
            format!("seen {}x", f.seen_count).dimmed(),
        );
        println!("    {}", f.affected_target.dimmed());
    }
    println!();
    Ok(())
}

/// Show details for a single finding.
///
/// # Errors
///
/// Returns an error if the finding UUID is invalid, the finding is not
/// found, or the database query fails.
pub async fn show(pool: &PgPool, id_str: &str) -> Result<()> {
    let id = Uuid::parse_str(id_str)
        .map_err(|e| ScorchError::Config(format!("invalid finding UUID '{id_str}': {e}")))?;

    let finding = findings::get_finding(pool, id)
        .await?
        .ok_or_else(|| ScorchError::Config(format!("finding '{id_str}' not found")))?;

    println!("{}", "Finding Details".bold().underline());
    println!();
    println!("          ID: {}", finding.id.to_string().dimmed());
    println!("       Title: {}", finding.title.bold());
    println!("    Severity: {}", colorize_severity(&finding.severity));
    println!("      Status: {}", colorize_status(&finding.status));
    println!("      Module: {}", finding.module_id.cyan());
    println!("      Target: {}", finding.affected_target);
    println!("  First seen: {}", finding.first_seen.format("%Y-%m-%d %H:%M UTC"));
    println!("   Last seen: {}", finding.last_seen.format("%Y-%m-%d %H:%M UTC"));
    println!("  Seen count: {}", finding.seen_count);

    println!();
    println!("  {}", "Description".bold());
    println!("  {}", finding.description);

    if let Some(ref evidence) = finding.evidence {
        println!();
        println!("  {}", "Evidence".bold());
        println!("  {evidence}");
    }

    if let Some(ref remediation) = finding.remediation {
        println!();
        println!("  {}", "Remediation".bold());
        println!("  {remediation}");
    }

    if let Some(ref owasp) = finding.owasp_category {
        println!();
        println!("  OWASP: {owasp}");
    }
    if let Some(cwe) = finding.cwe_id {
        println!("     CWE: CWE-{cwe}");
    }

    if let Some(ref note) = finding.status_note {
        println!();
        println!("  {}", "Status Note".bold());
        println!("  {note}");
    }

    println!();
    Ok(())
}

/// Update the lifecycle status of a finding.
///
/// # Errors
///
/// Returns an error if the finding UUID is invalid, the status string
/// is not a valid lifecycle status, or the database query fails.
pub async fn update_status(
    pool: &PgPool,
    id_str: &str,
    status_str: &str,
    note: Option<&str>,
) -> Result<()> {
    let id = Uuid::parse_str(id_str)
        .map_err(|e| ScorchError::Config(format!("invalid finding UUID '{id_str}': {e}")))?;

    let status = VulnStatus::from_db(status_str).ok_or_else(|| {
        ScorchError::Config(format!(
            "invalid status '{status_str}'. \
             Valid: new, acknowledged, false_positive, wont_fix, accepted_risk, remediated, verified"
        ))
    })?;

    let updated = findings::update_finding_status(pool, id, status, note).await?;

    if updated {
        println!(
            "{} Finding status updated to '{}'.",
            "success:".green().bold(),
            colorize_status(status.as_db_str()),
        );
        if let Some(n) = note {
            println!("  Note: {n}");
        }
    } else {
        println!("{} Finding not found.", "warning:".yellow().bold());
    }
    Ok(())
}

/// Colorize a severity string for terminal output.
fn colorize_severity(severity: &str) -> String {
    match severity {
        "critical" => "CRITICAL".red().bold().to_string(),
        "high" => "HIGH".red().to_string(),
        "medium" => "MEDIUM".yellow().to_string(),
        "low" => "LOW".blue().to_string(),
        "info" => "INFO".dimmed().to_string(),
        other => other.to_string(),
    }
}

/// Colorize a vulnerability status string for terminal output.
fn colorize_status(status: &str) -> String {
    match status {
        "new" => "new".red().to_string(),
        "acknowledged" => "acknowledged".yellow().to_string(),
        "false_positive" => "false_positive".dimmed().to_string(),
        "remediated" => "remediated".cyan().to_string(),
        "verified" => "verified".green().to_string(),
        other => other.to_string(),
    }
}
