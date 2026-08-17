//! Finding query and lifecycle management CLI handlers.
//!
//! Provides `finding list/show/status` commands for querying tracked
//! vulnerability findings and updating their lifecycle status.

use colored::{ColoredString, Colorize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::engine::error::{Result, ScorchError};
use crate::report::terminal::escape_terminal_text;
use crate::storage::findings;
use crate::storage::models::{TrackedFinding, VulnStatus};

#[derive(Debug, PartialEq, Eq)]
enum FindingFilter<'a> {
    Severity(&'a str),
    Status(VulnStatus),
    All,
}

fn parse_finding_filter<'a>(
    severity: Option<&'a str>,
    status: Option<&str>,
) -> Result<FindingFilter<'a>> {
    if let Some(severity) = severity {
        return Ok(FindingFilter::Severity(severity));
    }
    if let Some(status) = status {
        return VulnStatus::from_db(status).map(FindingFilter::Status).ok_or_else(|| {
            ScorchError::Config(format!(
                "invalid status '{status}'. Valid: new, acknowledged, false_positive, \
                 wont_fix, accepted_risk, remediated, verified"
            ))
        });
    }
    Ok(FindingFilter::All)
}

async fn load_filtered_findings(
    pool: &PgPool,
    project_id: Uuid,
    filter: FindingFilter<'_>,
) -> Result<Vec<TrackedFinding>> {
    match filter {
        FindingFilter::Severity(severity) => {
            findings::find_by_severity(pool, project_id, severity).await
        }
        FindingFilter::Status(status) => findings::find_by_status(pool, project_id, status).await,
        FindingFilter::All => findings::list_findings(pool, project_id).await,
    }
}

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

    let filter = parse_finding_filter(severity, status)?;
    let finding_list = load_filtered_findings(pool, project.id, filter).await?;

    if finding_list.is_empty() {
        println!("{} No findings for '{}'.", "note:".dimmed(), project.name);
        return Ok(());
    }

    println!(
        "{} for '{}' ({} total)",
        "Findings".bold().underline(),
        escape_terminal_text(&project.name).cyan(),
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
            escape_terminal_text(&f.title),
            status_colored,
            format!("seen {}x", f.seen_count).dimmed(),
        );
        println!("    {}", escape_terminal_text(&f.affected_target).dimmed());
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
    println!("       Title: {}", escape_terminal_text(&finding.title).bold());
    println!("    Severity: {}", colorize_severity(&finding.severity));
    println!("      Status: {}", colorize_status(&finding.status));
    println!("      Module: {}", escape_terminal_text(&finding.module_id).cyan());
    println!("      Target: {}", escape_terminal_text(&finding.affected_target));
    println!("  First seen: {}", finding.first_seen.format("%Y-%m-%d %H:%M UTC"));
    println!("   Last seen: {}", finding.last_seen.format("%Y-%m-%d %H:%M UTC"));
    println!("  Seen count: {}", finding.seen_count);

    println!();
    println!("  {}", "Description".bold());
    println!("  {}", escape_terminal_text(&finding.description));

    if let Some(ref evidence) = finding.evidence {
        println!();
        println!("  {}", "Evidence".bold());
        println!("  {}", escape_terminal_text(evidence));
    }

    if let Some(ref remediation) = finding.remediation {
        println!();
        println!("  {}", "Remediation".bold());
        println!("  {}", escape_terminal_text(remediation));
    }

    if let Some(ref owasp) = finding.owasp_category {
        println!();
        println!("  OWASP: {}", escape_terminal_text(owasp));
    }
    if let Some(cwe) = finding.cwe_id {
        println!("     CWE: CWE-{cwe}");
    }

    if let Some(ref note) = finding.status_note {
        println!();
        println!("  {}", "Status Note".bold());
        println!("  {}", escape_terminal_text(note));
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
            println!("  Note: {}", escape_terminal_text(n));
        }
    } else {
        println!("{} Finding not found.", "warning:".yellow().bold());
    }
    Ok(())
}

/// Colorize a severity string for terminal output.
fn colorize_severity(severity: &str) -> ColoredString {
    let safe = escape_terminal_text(severity);
    match severity {
        "critical" => safe.to_uppercase().red().bold(),
        "high" => safe.to_uppercase().red(),
        "medium" => safe.to_uppercase().yellow(),
        "low" => safe.to_uppercase().blue(),
        "info" => safe.to_uppercase().dimmed(),
        _ => safe.normal(),
    }
}

/// Colorize a vulnerability status string for terminal output.
fn colorize_status(status: &str) -> ColoredString {
    let safe = escape_terminal_text(status);
    match status {
        "new" => safe.red(),
        "acknowledged" => safe.yellow(),
        "false_positive" => safe.dimmed(),
        "remediated" => safe.cyan(),
        "verified" => safe.green(),
        _ => safe.normal(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::finding::Finding;
    use crate::engine::severity::Severity;
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
    async fn finding_commands_reject_missing_or_malformed_references() {
        let Some(pool) = database_pool().await else { return };
        let missing = format!("missing-finding-project-{}", Uuid::new_v4());

        assert!(list(&pool, &missing, None, None)
            .await
            .is_err_and(|error| error.to_string().contains("not found")));
        assert!(show(&pool, "not-a-uuid")
            .await
            .is_err_and(|error| error.to_string().contains("invalid finding UUID")));
        assert!(update_status(&pool, "not-a-uuid", "new", None)
            .await
            .is_err_and(|error| error.to_string().contains("invalid finding UUID")));
    }

    #[test]
    fn finding_filter_preserves_precedence_and_validates_status() {
        assert_eq!(
            parse_finding_filter(Some("critical"), Some("invalid"))
                .expect("severity takes precedence"),
            FindingFilter::Severity("critical")
        );
        assert_eq!(
            parse_finding_filter(None, Some("acknowledged")).expect("valid status"),
            FindingFilter::Status(VulnStatus::Acknowledged)
        );
        assert_eq!(parse_finding_filter(None, None).expect("all findings"), FindingFilter::All);
        let error = parse_finding_filter(None, Some("invalid")).expect_err("invalid status");
        assert!(error.to_string().contains("wont_fix"));
        assert!(error.to_string().contains("accepted_risk"));
    }

    #[test]
    fn severity_and_status_styles_are_complete_and_terminal_safe() {
        let severities = [
            ("critical", "CRITICAL", Some(Color::Red), Some(Styles::Bold)),
            ("high", "HIGH", Some(Color::Red), None),
            ("medium", "MEDIUM", Some(Color::Yellow), None),
            ("low", "LOW", Some(Color::Blue), None),
            ("info", "INFO", None, Some(Styles::Dimmed)),
            ("unknown\u{1b}", "unknown\\u{1b}", None, None),
        ];
        for (input, text, color, style) in severities {
            let rendered = colorize_severity(input);
            assert_eq!(rendered.input, text);
            assert_eq!(rendered.fgcolor, color);
            if let Some(style) = style {
                assert!(rendered.style.contains(style));
            }
        }

        let statuses = [
            ("new", Some(Color::Red), None),
            ("acknowledged", Some(Color::Yellow), None),
            ("false_positive", None, Some(Styles::Dimmed)),
            ("wont_fix", None, None),
            ("accepted_risk", None, None),
            ("remediated", Some(Color::Cyan), None),
            ("verified", Some(Color::Green), None),
        ];
        for (input, color, style) in statuses {
            let rendered = colorize_status(input);
            assert_eq!(rendered.input, input);
            assert_eq!(rendered.fgcolor, color);
            if let Some(style) = style {
                assert!(rendered.style.contains(style));
            }
        }
        assert_eq!(colorize_status("unknown\u{202e}").input, "unknown\\u{202e}");
    }

    #[tokio::test]
    async fn filtered_queries_observe_severity_status_and_all_branches() {
        let Some(pool) = database_pool().await else { return };
        let name = format!("cli-finding-filter-{}", Uuid::new_v4());
        let project = crate::storage::projects::create_project(&pool, &name, "fixture")
            .await
            .expect("create project");
        let now = chrono::Utc::now();
        let scan = crate::storage::scans::save_scan(
            &pool,
            project.id,
            "https://owned.example",
            "quick",
            now,
            Some(now),
            &[],
            &[],
            &serde_json::json!({"total_findings": 2}),
        )
        .await
        .expect("save scan");
        let fixture_findings = vec![
            Finding::new(
                "fixture",
                Severity::Critical,
                "Critical fixture",
                "critical",
                "https://owned.example/critical",
            ),
            Finding::new(
                "fixture",
                Severity::Low,
                "Low fixture",
                "low",
                "https://owned.example/low",
            ),
        ];
        findings::save_findings(&pool, project.id, scan.id, &fixture_findings)
            .await
            .expect("save findings");
        let all = load_filtered_findings(&pool, project.id, FindingFilter::All)
            .await
            .expect("all findings");
        let critical =
            load_filtered_findings(&pool, project.id, FindingFilter::Severity("critical"))
                .await
                .expect("critical findings");
        let low = all.iter().find(|finding| finding.severity == "low").expect("low finding");
        findings::update_finding_status(&pool, low.id, VulnStatus::Acknowledged, None)
            .await
            .expect("update status");
        let acknowledged = load_filtered_findings(
            &pool,
            project.id,
            FindingFilter::Status(VulnStatus::Acknowledged),
        )
        .await
        .expect("acknowledged findings");
        crate::storage::projects::delete_project(&pool, project.id).await.expect("delete project");

        assert_eq!(all.len(), 2);
        assert_eq!(critical.len(), 1);
        assert_eq!(critical[0].title, "Critical fixture");
        assert_eq!(acknowledged.len(), 1);
        assert_eq!(acknowledged[0].title, "Low fixture");
    }
}
