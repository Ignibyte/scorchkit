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
use crate::engine::error::Result;
#[cfg(any(feature = "storage", test))]
use crate::engine::error::ScorchError;
use crate::engine::module_trait::ModuleCategory;
use crate::engine::policy::{Capability, EffectClass, PolicyTarget};
use crate::engine::scan_result::ScanResult;
use crate::engine::target::Target;
use crate::report::terminal::escape_terminal_text;
use crate::runner::orchestrator::Orchestrator;

/// Phase status for terminal display.
#[derive(Debug, PartialEq, Eq)]
enum PhaseResult {
    Pass(String),
    Warn(String),
    Skip(String),
}

#[derive(Debug, PartialEq, Eq)]
struct AiPlanningOutcome {
    module_ids: Option<Vec<String>>,
    phase: PhaseResult,
}

#[derive(Debug, PartialEq, Eq)]
struct AiAnalysisOutcome {
    rendered_analysis: Option<String>,
    phase: PhaseResult,
}

/// Render a phase header for a host-owned terminal sink.
fn render_phase_header(num: u8, name: &str) -> String {
    format!(
        "\n  {} {} {}\n",
        format!("[{num}/6]").dimmed(),
        ">>".cyan().bold(),
        escape_terminal_text(name).bold()
    )
}

/// Render a phase result for a host-owned terminal sink.
fn render_phase_result(result: &PhaseResult) -> String {
    match result {
        PhaseResult::Pass(message) => {
            format!("     {} {}\n", "PASS".green().bold(), escape_terminal_text(message))
        }
        PhaseResult::Warn(message) => {
            format!("     {} {}\n", "WARN".yellow().bold(), escape_terminal_text(message))
        }
        PhaseResult::Skip(message) => {
            format!("     {} {}\n", "SKIP".dimmed(), escape_terminal_text(message).dimmed())
        }
    }
}

fn rate_limit_notice(rate_limit: u32) -> Option<String> {
    (rate_limit > 0).then(|| format!("Rate limit: {} req/s", rate_limit.to_string().yellow()))
}

#[cfg(any(feature = "storage", test))]
fn updated_finding_count(total: usize, new_count: usize) -> Result<usize> {
    total.checked_sub(new_count).ok_or_else(|| {
        ScorchError::Database(format!(
            "finding persistence reported {new_count} new rows for only {total} findings"
        ))
    })
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
    print!("{}", render_phase_header(1, "Setup"));

    let target = Target::parse(target_str)?;
    println!("     Target: {}", escape_terminal_text(target.url.as_str()).cyan());
    println!("     Depth:  {}", escape_terminal_text(depth).cyan());
    if let Some(name) = project_name {
        println!("     Project: {}", escape_terminal_text(name).cyan());
    }
    print!("{}", render_phase_result(&PhaseResult::Pass("Target validated".to_string())));

    // ── Phase 2: Reconnaissance ─────────────────────────────────────
    print!("{}", render_phase_header(2, "Reconnaissance"));

    let engine = crate::facade::Engine::new(Arc::clone(config));
    let ctx = engine.dast_context_for_target(target.clone(), "quick")?;
    let mut recon_orchestrator = Orchestrator::new(ctx);
    recon_orchestrator.register_default_modules();
    recon_orchestrator.apply_profile("quick");
    recon_orchestrator.filter_by_category(ModuleCategory::Recon);

    let recon_result = recon_orchestrator.run(true).await?;
    let recon_findings = recon_result.findings.len();
    let recon_modules = recon_result.modules_run.len();
    print!(
        "{}",
        render_phase_result(&PhaseResult::Pass(format!(
            "{recon_modules} modules, {recon_findings} findings"
        )))
    );

    // ── Phase 3: AI Planning ────────────────────────────────────────
    print!("{}", render_phase_header(3, "AI Planning"));
    let planning_outcome = run_ai_planning(config, &target, depth).await;
    print!("{}", render_phase_result(&planning_outcome.phase));
    let plan_module_ids = planning_outcome.module_ids;

    // ── Phase 4: Vulnerability Scan ─────────────────────────────────
    print!("{}", render_phase_header(4, "Vulnerability Scan"));

    let scan_ctx = engine.dast_context_for_target(target.clone(), depth)?;
    let mut scan_orchestrator = Orchestrator::new(scan_ctx);
    scan_orchestrator.register_default_modules();

    // Apply plan or profile
    if let Some(ref ids) = plan_module_ids {
        scan_orchestrator.filter_by_ids(ids);
    } else {
        scan_orchestrator.apply_profile(depth);
    }

    // Rate limiting delay if configured
    if let Some(notice) = rate_limit_notice(config.scan.rate_limit) {
        println!("     {notice}");
    }

    let scan_result = scan_orchestrator.run(false).await?;
    let total_findings = scan_result.findings.len();
    let modules_run = scan_result.modules_run.len();
    let modules_skipped = scan_result.modules_skipped.len();

    let scan_phase = if scan_result.has_failed_modules() {
        PhaseResult::Warn(format!(
            "degraded: {modules_run} modules run, {modules_skipped} skipped or failed, {total_findings} findings"
        ))
    } else {
        PhaseResult::Pass(format!(
            "{modules_run} modules run, {modules_skipped} skipped, {total_findings} findings"
        ))
    };
    print!("{}", render_phase_result(&scan_phase));

    // Print finding severity summary
    if let Some(summary) = render_finding_summary(&scan_result) {
        print!("{summary}");
    }

    // ── Phase 5: AI Analysis ────────────────────────────────────────
    print!("{}", render_phase_header(5, "AI Analysis"));
    let analysis_outcome = run_ai_analysis(config, &scan_result).await;
    print!("{}", render_phase_result(&analysis_outcome.phase));
    if let Some(rendered) = analysis_outcome.rendered_analysis {
        print!("{rendered}");
    }

    // ── Phase 6: Persist & Report ───────────────────────────────────
    print!("{}", render_phase_header(6, "Persist & Report"));

    // Save report file
    let report_path = crate::report::json::save_report(&scan_result, &config.report)?;
    println!("     Report: {}", escape_terminal_text(&report_path.display().to_string()).cyan());

    // Database persistence
    #[cfg(feature = "storage")]
    if let Some(name) = project_name {
        persist_agent_results(config, name, database_url, &scan_result).await?;
    }

    #[cfg(not(feature = "storage"))]
    if project_name.is_some() {
        let _ = database_url;
        print!(
            "{}",
            render_phase_result(&PhaseResult::Warn(
                "--project requires storage feature".to_string()
            ))
        );
    }

    print!("{}", render_phase_result(&PhaseResult::Pass("Complete".to_string())));

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
) -> AiPlanningOutcome {
    if !config.ai.enabled {
        return AiPlanningOutcome {
            module_ids: None,
            phase: PhaseResult::Skip("AI disabled in config".to_string()),
        };
    }

    let planner = ScanPlanner::from_config(&config.ai);
    if !planner.is_available() {
        return AiPlanningOutcome {
            module_ids: None,
            phase: PhaseResult::Skip(format!(
                "{} not available — using profile",
                planner.provider_name()
            )),
        };
    }

    let engine = crate::facade::Engine::new(Arc::clone(config));
    if let Err(error) = engine.dast_context_for_target(target.clone(), "quick") {
        return AiPlanningOutcome {
            module_ids: None,
            phase: PhaseResult::Warn(format!("Planning denied: {error}")),
        };
    }
    if let Err(error) = engine.require_authorized(
        PolicyTarget::Web(target.url.clone()),
        Capability::ExternalTool,
        EffectClass::ActiveSafe,
    ) {
        return AiPlanningOutcome {
            module_ids: None,
            phase: PhaseResult::Warn(format!("Planning denied: {error}")),
        };
    }

    match planner.plan(target, &engine).await {
        Ok(plan) => {
            let count = plan.recommendations.len();
            AiPlanningOutcome {
                module_ids: Some(
                    plan.recommendations
                        .iter()
                        .map(|recommendation| recommendation.module_id.clone())
                        .collect(),
                ),
                phase: PhaseResult::Pass(format!(
                    "{count} modules recommended — {}",
                    plan.overall_strategy
                )),
            }
        }
        Err(error) => AiPlanningOutcome {
            module_ids: None,
            phase: PhaseResult::Warn(format!("Planning failed: {error} — using {depth} profile")),
        },
    }
}

/// Run AI analysis phase on scan results.
async fn run_ai_analysis(config: &Arc<AppConfig>, scan_result: &ScanResult) -> AiAnalysisOutcome {
    if !config.ai.enabled {
        return AiAnalysisOutcome {
            rendered_analysis: None,
            phase: PhaseResult::Skip("AI disabled".to_string()),
        };
    }

    if scan_result.findings.is_empty() {
        return AiAnalysisOutcome {
            rendered_analysis: None,
            phase: PhaseResult::Skip("No findings to analyze".to_string()),
        };
    }

    let analyst = AiAnalyst::from_config(&config.ai);
    if let Err(error) = crate::facade::Engine::new(Arc::clone(config)).require_authorized(
        PolicyTarget::Web(scan_result.target.url.clone()),
        Capability::ExternalTool,
        EffectClass::Passive,
    ) {
        return AiAnalysisOutcome {
            rendered_analysis: None,
            phase: PhaseResult::Warn(format!("Analysis denied: {error}")),
        };
    }
    match analyst.analyze(scan_result, AnalysisFocus::Summary, None).await {
        Ok(analysis) => AiAnalysisOutcome {
            rendered_analysis: Some(crate::ai::analyst::render_analysis(&analysis)),
            phase: PhaseResult::Pass("Analysis complete".to_string()),
        },
        Err(error) => AiAnalysisOutcome {
            rendered_analysis: None,
            phase: PhaseResult::Warn(format!("Analysis failed: {error}")),
        },
    }
}

/// Render a compact severity summary of findings.
fn render_finding_summary(result: &ScanResult) -> Option<String> {
    let summary = &result.summary;
    (summary.total_findings > 0).then(|| {
        format!(
            "     Severity: {} {} {} {} {}\n",
            if summary.critical > 0 {
                format!("{}C", summary.critical).red().bold().to_string()
            } else {
                "0C".dimmed().to_string()
            },
            if summary.high > 0 {
                format!("{}H", summary.high).red().to_string()
            } else {
                "0H".dimmed().to_string()
            },
            if summary.medium > 0 {
                format!("{}M", summary.medium).yellow().to_string()
            } else {
                "0M".dimmed().to_string()
            },
            if summary.low > 0 {
                format!("{}L", summary.low).green().to_string()
            } else {
                "0L".dimmed().to_string()
            },
            format!("{}I", summary.info).dimmed(),
        )
    })
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
        println!(
            "     {} Intelligence update failed: {}",
            "WARN".yellow().bold(),
            crate::report::terminal::escape_terminal_text(&e.to_string())
        );
    }

    let updated = updated_finding_count(result.findings.len(), new_count)?;
    println!(
        "     {} Project '{}': {} new, {} updated",
        "DB".cyan().bold(),
        escape_terminal_text(project_name).cyan(),
        new_count,
        updated,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_result(findings: Vec<crate::engine::finding::Finding>) -> ScanResult {
        ScanResult {
            scan_id: "test".to_string(),
            target: Target::parse("https://example.com").expect("parse target"),
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            summary: crate::engine::scan_result::ScanSummary::from_findings(&findings),
            findings,
            modules_run: vec!["fixture".to_string()],
            modules_skipped: vec![],
            module_outcomes: vec![],
            execution_status: crate::engine::scan_result::ScanExecutionStatus::Complete,
        }
    }

    #[test]
    fn test_agent_http_client_uses_engine_authorization() {
        let target = Target::parse("https://example.com").expect("parse target");
        let policy = crate::engine::policy::EngagementPolicy::default()
            .allow_scope(crate::engine::scope::ScopeRule::parse("example.com").expect("scope"))
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::ActiveSafe);
        let engine = crate::facade::Engine::for_engagement(
            Arc::new(AppConfig::default()),
            Arc::new(crate::engine::policy::Engagement::new("test", policy)),
        );
        assert!(
            engine.authorized_web_client(&target.url, EffectClass::ActiveSafe, false).is_ok(),
            "authorized agent client should build"
        );
    }

    fn finding(
        severity: crate::engine::severity::Severity,
        title: &str,
    ) -> crate::engine::finding::Finding {
        crate::engine::finding::Finding::new(
            "fixture",
            severity,
            title,
            "fixture",
            "https://example.com",
        )
    }

    #[test]
    fn finding_summary_distinguishes_empty_and_asymmetric_counts() {
        use crate::engine::severity::Severity;

        let result = scan_result(vec![]);
        assert_eq!(render_finding_summary(&result), None);

        let result = scan_result(vec![
            finding(Severity::Critical, "critical one"),
            finding(Severity::Critical, "critical two"),
            finding(Severity::High, "high"),
            finding(Severity::Medium, "medium one"),
            finding(Severity::Medium, "medium two"),
            finding(Severity::Medium, "medium three"),
            finding(Severity::Low, "low"),
            finding(Severity::Info, "info one"),
            finding(Severity::Info, "info two"),
            finding(Severity::Info, "info three"),
            finding(Severity::Info, "info four"),
        ]);
        let rendered = render_finding_summary(&result).expect("nonempty summary");
        for expected in ["Severity:", "2C", "1H", "3M", "1L", "4I"] {
            assert!(rendered.contains(expected), "summary omitted {expected:?}: {rendered:?}");
        }
        assert!(rendered.ends_with('\n'));
    }

    #[test]
    fn phase_header_is_exact_and_terminal_safe() {
        let rendered = render_phase_header(3, "AI\u{1b} Planning");
        assert!(rendered.starts_with('\n'));
        assert!(rendered.contains("[3/6]"));
        assert!(rendered.contains(">>"));
        assert!(rendered.contains("AI\\u{1b} Planning"));
        assert!(rendered.ends_with('\n'));
    }

    #[test]
    fn phase_result_rendering_is_exact_and_terminal_safe() {
        let pass = render_phase_result(&PhaseResult::Pass("passed\u{1b}".to_string()));
        assert!(pass.contains("PASS"));
        assert!(pass.contains("passed\\u{1b}"));
        assert!(pass.ends_with('\n'));

        let warning = render_phase_result(&PhaseResult::Warn("warning".to_string()));
        assert!(warning.contains("WARN"));
        assert!(warning.contains("warning"));

        let skipped = render_phase_result(&PhaseResult::Skip("skipped".to_string()));
        assert!(skipped.contains("SKIP"));
        assert!(skipped.contains("skipped"));
    }

    #[test]
    fn rate_limit_notice_and_persistence_counts_pin_boundaries() {
        assert_eq!(rate_limit_notice(0), None);
        let notice = rate_limit_notice(1).expect("positive rate limit should be visible");
        assert!(notice.contains("Rate limit:"));
        assert!(notice.contains('1'));
        assert!(notice.contains("req/s"));

        assert_eq!(updated_finding_count(5, 2).expect("valid persistence counts"), 3);
        assert_eq!(updated_finding_count(0, 0).expect("empty persistence counts"), 0);
        let error = updated_finding_count(2, 3).expect_err("impossible count must fail");
        assert_eq!(
            error.to_string(),
            "database error: finding persistence reported 3 new rows for only 2 findings"
        );
    }

    #[tokio::test]
    async fn planning_outcomes_distinguish_disabled_unavailable_and_denied() {
        let target = Target::parse("https://example.com").expect("parse target");

        let disabled_config = Arc::new(AppConfig {
            ai: crate::config::AiConfig { enabled: false, ..Default::default() },
            ..AppConfig::default()
        });
        assert_eq!(
            run_ai_planning(&disabled_config, &target, "quick").await,
            AiPlanningOutcome {
                module_ids: None,
                phase: PhaseResult::Skip("AI disabled in config".to_string()),
            }
        );

        let unavailable_config = Arc::new(AppConfig {
            ai: crate::config::AiConfig {
                binary: Some("scorchkit-test-ai-provider-does-not-exist".to_string()),
                ..Default::default()
            },
            ..AppConfig::default()
        });
        assert_eq!(
            run_ai_planning(&unavailable_config, &target, "quick").await,
            AiPlanningOutcome {
                module_ids: None,
                phase: PhaseResult::Skip("Codex CLI not available — using profile".to_string()),
            }
        );

        let current_executable = std::env::current_exe()
            .unwrap_or_else(|error| panic!("failed to resolve test executable: {error}"));
        let denied_config = Arc::new(AppConfig {
            ai: crate::config::AiConfig {
                binary: Some(current_executable.display().to_string()),
                ..Default::default()
            },
            ..AppConfig::default()
        });
        let denied = run_ai_planning(&denied_config, &target, "quick").await;
        assert!(denied.module_ids.is_none());
        assert!(matches!(
            denied.phase,
            PhaseResult::Warn(message) if message.contains("no engagement authorization")
        ));
    }

    #[tokio::test]
    async fn analysis_outcomes_distinguish_disabled_empty_and_denied() {
        let disabled_config = Arc::new(AppConfig {
            ai: crate::config::AiConfig { enabled: false, ..Default::default() },
            ..AppConfig::default()
        });
        assert_eq!(
            run_ai_analysis(&disabled_config, &scan_result(vec![])).await,
            AiAnalysisOutcome {
                rendered_analysis: None,
                phase: PhaseResult::Skip("AI disabled".to_string()),
            }
        );

        let default_config = Arc::new(AppConfig::default());
        assert_eq!(
            run_ai_analysis(&default_config, &scan_result(vec![])).await,
            AiAnalysisOutcome {
                rendered_analysis: None,
                phase: PhaseResult::Skip("No findings to analyze".to_string()),
            }
        );

        let finding = crate::engine::finding::Finding::new(
            "fixture",
            crate::engine::severity::Severity::High,
            "Fixture finding",
            "fixture",
            "https://example.com",
        );
        let denied = run_ai_analysis(&default_config, &scan_result(vec![finding])).await;
        assert!(denied.rendered_analysis.is_none());
        assert!(matches!(
            denied.phase,
            PhaseResult::Warn(message) if message.contains("no engagement authorization")
        ));
    }

    #[tokio::test]
    async fn autonomous_agent_denies_before_effects_without_engagement() {
        let result = run_autonomous(
            &Arc::new(AppConfig::default()),
            "http://127.0.0.1:9",
            "quick",
            None,
            None,
        )
        .await;
        assert!(
            result.is_err_and(|error| error.to_string().contains("no engagement authorization")),
            "autonomous execution must fail before loopback I/O"
        );
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn agent_persistence_writes_scan_and_findings() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = crate::storage::connect(&database_url).await.expect("database connection");
        crate::storage::migrate::run_migrations(&pool).await.expect("database migrations");
        let project_name = format!("agent-persist-{}", uuid::Uuid::new_v4());
        let project = crate::storage::projects::create_project(&pool, &project_name, "fixture")
            .await
            .expect("create project");
        let finding = crate::engine::finding::Finding::new(
            "fixture",
            crate::engine::severity::Severity::High,
            "Persisted finding",
            "fixture",
            "https://example.com",
        );
        let result = scan_result(vec![finding]);

        let persisted = persist_agent_results(
            &Arc::new(AppConfig::default()),
            &project_name,
            Some(&database_url),
            &result,
        )
        .await;
        let scan_count =
            crate::storage::scans::list_scans(&pool, project.id).await.expect("list scans").len();
        let finding_count = crate::storage::findings::list_findings(&pool, project.id)
            .await
            .expect("list findings")
            .len();
        crate::storage::projects::delete_project(&pool, project.id).await.expect("delete project");

        assert!(persisted.is_ok(), "agent persistence failed: {persisted:?}");
        assert_eq!(scan_count, 1);
        assert_eq!(finding_count, 1);
    }
}
