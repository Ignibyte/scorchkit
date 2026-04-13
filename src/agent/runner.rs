//! Autonomous scan agent — drives the full recon→plan→scan→analyze loop.
//!
//! Orchestrates existing subsystems (`Orchestrator`, `ScanPlanner`, `AiAnalyst`)
//! into a single autonomous command. Each phase prints progress and handles
//! failures gracefully — AI failures fall back to profile-based scanning,
//! analysis failures are non-fatal.

use std::sync::Arc;

use colored::Colorize;

use crate::ai::analyst::AiAnalyst;
use crate::ai::planner::ScanPlanner;
use crate::ai::prompts::AnalysisFocus;
use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::module_trait::ModuleCategory;
use crate::engine::scan_context::ScanContext;
use crate::engine::scan_result::ScanResult;
use crate::engine::target::Target;
use crate::runner::orchestrator::Orchestrator;

/// Phase status for terminal display.
enum PhaseResult {
    Pass(String),
    Warn(String),
    Skip(String),
}

/// Print a phase header.
fn phase_header(num: u8, name: &str) {
    println!();
    println!("  {} {} {}", format!("[{num}/6]").dimmed(), ">>".cyan().bold(), name.bold());
}

/// Print a phase result.
fn phase_result(result: &PhaseResult) {
    match result {
        PhaseResult::Pass(msg) => println!("     {} {}", "PASS".green().bold(), msg),
        PhaseResult::Warn(msg) => println!("     {} {}", "WARN".yellow().bold(), msg),
        PhaseResult::Skip(msg) => println!("     {} {}", "SKIP".dimmed(), msg.dimmed()),
    }
}

/// Run the autonomous scan agent loop.
///
/// Executes a full pentest engagement: recon → plan → scan → analyze → report.
/// Each phase is independent — AI failures are non-fatal and fall back to
/// profile-based scanning.
///
/// # Errors
///
/// Returns an error if target parsing fails, the scan itself fails, or
/// database persistence fails (when `--project` is specified).
pub async fn run_autonomous(
    config: &Arc<AppConfig>,
    target_str: &str,
    depth: &str,
    project_name: Option<&str>,
    database_url: Option<&str>,
) -> Result<()> {
    println!();
    println!("{}", "ScorchKit Autonomous Agent".bold().underline());
    println!("{}", "━".repeat(50).dimmed());

    // ── Phase 1: Setup ──────────────────────────────────────────────
    phase_header(1, "Setup");

    let target = Target::parse(target_str)?;
    println!("     Target: {}", target.url.as_str().cyan());
    println!("     Depth:  {}", depth.cyan());
    if let Some(name) = project_name {
        println!("     Project: {}", name.cyan());
    }
    phase_result(&PhaseResult::Pass("Target validated".to_string()));

    // ── Phase 2: Reconnaissance ─────────────────────────────────────
    phase_header(2, "Reconnaissance");

    let http_client = build_agent_http_client()?;
    let ctx = ScanContext::new(target.clone(), config.clone(), http_client.clone());
    let mut recon_orchestrator = Orchestrator::new(ctx);
    recon_orchestrator.register_default_modules();
    recon_orchestrator.filter_by_category(ModuleCategory::Recon);

    let recon_result = recon_orchestrator.run(true).await?;
    let recon_findings = recon_result.findings.len();
    let recon_modules = recon_result.modules_run.len();
    phase_result(&PhaseResult::Pass(format!("{recon_modules} modules, {recon_findings} findings")));

    // ── Phase 3: AI Planning ────────────────────────────────────────
    phase_header(3, "AI Planning");
    let plan_module_ids = run_ai_planning(config, &target, depth).await;

    // ── Phase 4: Vulnerability Scan ─────────────────────────────────
    phase_header(4, "Vulnerability Scan");

    let scan_ctx = ScanContext::new(target.clone(), config.clone(), http_client);
    let mut scan_orchestrator = Orchestrator::new(scan_ctx);
    scan_orchestrator.register_default_modules();

    // Apply plan or profile
    if let Some(ref ids) = plan_module_ids {
        scan_orchestrator.filter_by_ids(ids);
    } else {
        scan_orchestrator.apply_profile(depth);
    }

    // Rate limiting delay if configured
    if config.scan.rate_limit > 0 {
        println!("     Rate limit: {} req/s", config.scan.rate_limit.to_string().yellow());
    }

    let scan_result = scan_orchestrator.run(false).await?;
    let total_findings = scan_result.findings.len();
    let modules_run = scan_result.modules_run.len();
    let modules_skipped = scan_result.modules_skipped.len();

    phase_result(&PhaseResult::Pass(format!(
        "{modules_run} modules run, {modules_skipped} skipped, {total_findings} findings"
    )));

    // Print finding severity summary
    print_finding_summary(&scan_result);

    // ── Phase 5: AI Analysis ────────────────────────────────────────
    phase_header(5, "AI Analysis");
    run_ai_analysis(config, &scan_result).await;

    // ── Phase 6: Persist & Report ───────────────────────────────────
    phase_header(6, "Persist & Report");

    // Save report file
    let report_path = crate::report::json::save_report(&scan_result, &config.report)?;
    println!("     Report: {}", report_path.display().to_string().cyan());

    // Database persistence
    #[cfg(feature = "storage")]
    if let Some(name) = project_name {
        persist_agent_results(config, name, database_url, &scan_result).await?;
    }

    #[cfg(not(feature = "storage"))]
    if project_name.is_some() {
        let _ = database_url;
        phase_result(&PhaseResult::Warn("--project requires storage feature".to_string()));
    }

    phase_result(&PhaseResult::Pass("Complete".to_string()));

    // ── Summary ─────────────────────────────────────────────────────
    println!();
    println!("{}", "━".repeat(50).dimmed());
    println!(
        "  {} {} findings across {} modules",
        "Done:".green().bold(),
        total_findings,
        modules_run
    );
    println!();

    Ok(())
}

/// Run AI planning phase. Returns module IDs if successful, None on fallback.
async fn run_ai_planning(
    config: &Arc<AppConfig>,
    target: &Target,
    depth: &str,
) -> Option<Vec<String>> {
    if !config.ai.enabled {
        phase_result(&PhaseResult::Skip("AI disabled in config".to_string()));
        return None;
    }

    let planner = ScanPlanner::from_config(&config.ai);
    if !planner.is_available() {
        phase_result(&PhaseResult::Skip("Claude CLI not available — using profile".to_string()));
        return None;
    }

    match planner.plan(target, config).await {
        Ok(plan) => {
            let count = plan.recommendations.len();
            phase_result(&PhaseResult::Pass(format!(
                "{count} modules recommended — {}",
                plan.overall_strategy
            )));
            Some(plan.recommendations.iter().map(|r| r.module_id.clone()).collect())
        }
        Err(e) => {
            phase_result(&PhaseResult::Warn(format!(
                "Planning failed: {e} — using {depth} profile"
            )));
            None
        }
    }
}

/// Run AI analysis phase on scan results.
async fn run_ai_analysis(config: &Arc<AppConfig>, scan_result: &ScanResult) {
    if !config.ai.enabled {
        phase_result(&PhaseResult::Skip("AI disabled".to_string()));
        return;
    }

    if scan_result.findings.is_empty() {
        phase_result(&PhaseResult::Skip("No findings to analyze".to_string()));
        return;
    }

    let analyst = AiAnalyst::from_config(&config.ai);
    match analyst.analyze(scan_result, AnalysisFocus::Summary, None).await {
        Ok(analysis) => {
            phase_result(&PhaseResult::Pass("Analysis complete".to_string()));
            crate::ai::analyst::print_analysis(&analysis);
        }
        Err(e) => {
            phase_result(&PhaseResult::Warn(format!("Analysis failed: {e}")));
        }
    }
}

/// Build an HTTP client for agent operations.
fn build_agent_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(10))
        .cookie_store(true)
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| ScorchError::Config(format!("failed to build HTTP client: {e}")))
}

/// Print a compact severity summary of findings.
fn print_finding_summary(result: &ScanResult) {
    use crate::engine::severity::Severity;

    let (mut crit, mut high, mut med, mut low, mut info) = (0usize, 0, 0, 0, 0);
    for finding in &result.findings {
        match finding.severity {
            Severity::Critical => crit += 1,
            Severity::High => high += 1,
            Severity::Medium => med += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }

    if crit + high + med + low + info > 0 {
        println!(
            "     Severity: {} {} {} {} {}",
            if crit > 0 {
                format!("{crit}C").red().bold().to_string()
            } else {
                "0C".dimmed().to_string()
            },
            if high > 0 { format!("{high}H").red().to_string() } else { "0H".dimmed().to_string() },
            if med > 0 {
                format!("{med}M").yellow().to_string()
            } else {
                "0M".dimmed().to_string()
            },
            if low > 0 { format!("{low}L").green().to_string() } else { "0L".dimmed().to_string() },
            format!("{info}I").dimmed(),
        );
    }
}

/// Persist agent scan results to the database.
#[cfg(feature = "storage")]
async fn persist_agent_results(
    config: &Arc<AppConfig>,
    project_name: &str,
    database_url: Option<&str>,
    result: &ScanResult,
) -> Result<()> {
    let pool = crate::storage::connect_from_config(&config.database, database_url).await?;
    let project = crate::cli::project::resolve_project(&pool, project_name).await?;

    let modules_run: Vec<String> = result.modules_run.clone();
    let modules_skipped: Vec<String> =
        result.modules_skipped.iter().map(|(id, _)| id.clone()).collect();
    let summary_json = serde_json::to_value(&result.summary)?;

    let scan = crate::storage::scans::save_scan(
        &pool,
        project.id,
        result.target.url.as_str(),
        "agent",
        result.started_at,
        Some(result.completed_at),
        &modules_run,
        &modules_skipped,
        &summary_json,
    )
    .await?;

    let new_count =
        crate::storage::findings::save_findings(&pool, project.id, scan.id, &result.findings)
            .await?;

    // Update intelligence
    if let Err(e) =
        crate::storage::intelligence::update_intelligence(&pool, project.id, result).await
    {
        println!("     {} Intelligence update failed: {e}", "WARN".yellow().bold());
    }

    let updated = result.findings.len() - new_count;
    println!(
        "     {} Project '{}': {} new, {} updated",
        "DB".cyan().bold(),
        project_name.cyan(),
        new_count,
        updated,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_agent_http_client() {
        let client = build_agent_http_client();
        assert!(client.is_ok(), "Should build HTTP client");
    }

    #[test]
    fn test_print_finding_summary_empty() {
        let result = ScanResult {
            scan_id: "test".to_string(),
            target: Target::parse("https://example.com").expect("parse"),
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            findings: vec![],
            modules_run: vec![],
            modules_skipped: vec![],
            summary: crate::engine::scan_result::ScanSummary::from_findings(&[]),
        };
        // Should not panic on empty findings
        print_finding_summary(&result);
    }

    #[test]
    fn test_phase_result_variants() {
        // Just verify no panics
        phase_result(&PhaseResult::Pass("test".to_string()));
        phase_result(&PhaseResult::Warn("test".to_string()));
        phase_result(&PhaseResult::Skip("test".to_string()));
    }
}
