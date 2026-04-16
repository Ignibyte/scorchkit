use std::sync::Arc;

use colored::Colorize;

use crate::ai::analyst::{self, AiAnalyst};
use crate::ai::prompts::AnalysisFocus;
use crate::cli::args::{self, Cli, Commands, OutputFormat};
use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::module_trait::ModuleCategory;
use crate::engine::scan_context::ScanContext;
use crate::engine::scan_result::ScanResult;
use crate::engine::target::Target;
use crate::report;
use crate::runner::orchestrator::Orchestrator;

/// Execute the CLI command.
///
/// # Errors
///
/// Returns an error if the dispatched subcommand fails.
// JUSTIFICATION: CLI dispatch function — match arms are the natural structure;
// extraction would scatter dispatch logic
#[allow(clippy::too_many_lines)]
pub async fn execute(cli: Cli) -> Result<()> {
    let config = AppConfig::load(cli.config.as_deref())?;
    let config = Arc::new(config);

    match cli.command {
        Commands::Run {
            target,
            targets_file,
            resume,
            modules,
            skip,
            analyze,
            plan,
            profile,
            template,
            proxy,
            min_confidence,
            insecure,
            scope,
            exclude,
            code,
            project,
            database_url,
        } => {
            // Apply CLI overrides to config
            let config = {
                let mut c = (*config).clone();
                if let Some(ref p) = proxy {
                    c.scan.proxy = Some(p.clone());
                }
                if insecure {
                    c.scan.insecure = true;
                }
                if let Some(ref s) = scope {
                    c.scan.scope_include = vec![s.clone()];
                }
                if let Some(ref e) = exclude {
                    c.scan.scope_exclude = vec![e.clone()];
                }
                Arc::new(c)
            };

            // Handle --resume: load checkpoint and run with resume
            if let Some(ref checkpoint_file) = resume {
                use crate::runner::checkpoint;
                let cp = checkpoint::load_checkpoint(checkpoint_file)?;
                if !cli.quiet {
                    println!(
                        "{} Resuming scan {} for {}",
                        ">>>".cyan().bold(),
                        cp.scan_id,
                        cp.target.cyan()
                    );
                }
                return run_scan_with_resume(
                    &config,
                    &cp,
                    modules,
                    skip,
                    cli.output,
                    cli.quiet,
                    analyze,
                    plan,
                    min_confidence,
                    project.as_deref(),
                    database_url.as_deref(),
                )
                .await;
            }

            // Build target list: single target or from file
            let target_list = if let Some(ref file) = targets_file {
                crate::engine::target::parse_targets_file(file)?
            } else if let Some(ref t) = target {
                vec![t.clone()]
            } else {
                return Err(ScorchError::Config(
                    "either <target> or --targets-file is required".to_string(),
                ));
            };

            let total = target_list.len();
            let mut errors = Vec::new();

            for (i, target_str) in target_list.iter().enumerate() {
                if total > 1 && !cli.quiet {
                    println!(
                        "\n{} Scanning target {}/{}: {}",
                        ">>>".cyan().bold(),
                        i + 1,
                        total,
                        target_str.cyan()
                    );
                }

                if let Err(e) = run_scan(
                    &config,
                    target_str,
                    modules.clone(),
                    skip.clone(),
                    None,
                    cli.output.clone(),
                    cli.quiet,
                    analyze,
                    plan,
                    &profile,
                    template.as_deref(),
                    min_confidence,
                    code.as_deref(),
                    project.as_deref(),
                    database_url.as_deref(),
                )
                .await
                {
                    if total > 1 {
                        // Multi-target: log error and continue
                        if !cli.quiet {
                            println!("{} Target {} failed: {e}", "ERR".red().bold(), target_str);
                        }
                        errors.push((target_str.clone(), e.to_string()));
                    } else {
                        // Single target: propagate error
                        return Err(e);
                    }
                }
            }

            // Print multi-target summary
            if total > 1 && !cli.quiet {
                println!("\n{}", "━".repeat(50).dimmed());
                println!(
                    "  {} target{} scanned, {} failed",
                    total,
                    if total == 1 { "" } else { "s" },
                    errors.len()
                );
                for (t, e) in &errors {
                    println!("    {} {}: {}", "✗".red(), t, e);
                }
                println!("{}", "━".repeat(50).dimmed());
            }

            Ok(())
        }

        Commands::Recon { target, modules } => {
            run_scan(
                &config,
                &target,
                modules,
                None,
                Some(ModuleCategory::Recon),
                cli.output,
                cli.quiet,
                false,
                false,
                "standard",
                None,
                None,
                None,
                None,
                None,
            )
            .await
        }

        Commands::Scan { target, modules } => {
            run_scan(
                &config,
                &target,
                modules,
                None,
                Some(ModuleCategory::Scanner),
                cli.output,
                cli.quiet,
                false,
                false,
                "standard",
                None,
                None,
                None,
                None,
                None,
            )
            .await
        }

        Commands::Analyze { report, focus, project, database_url } => {
            run_analyze(&config, &report, &focus, project.as_deref(), database_url.as_deref()).await
        }

        Commands::Diff { baseline, current } => run_diff(&baseline, &current),

        Commands::Modules { check_tools } => {
            list_modules(check_tools);
            Ok(())
        }

        Commands::Init { target, project, database_url } => {
            super::init::run_init(target.as_deref(), project.as_deref(), database_url.as_deref())
                .await
        }

        Commands::Doctor { deep } => super::doctor::run_doctor(deep),

        Commands::Agent { target, depth, project, database_url } => {
            crate::agent::runner::run_autonomous(
                &config,
                &target,
                &depth,
                project.as_deref(),
                database_url.as_deref(),
            )
            .await
        }

        Commands::Code {
            path,
            language,
            modules,
            skip,
            profile,
            analyze,
            project: _project,
            database_url: _database_url,
        } => run_code_scan(&path, language, modules, skip, &profile, analyze, &config).await,

        Commands::Completions { shell } => {
            args::print_completions(shell);
            Ok(())
        }

        #[cfg(feature = "storage")]
        Commands::Db { command } => run_db_command(&config, command).await,

        #[cfg(feature = "storage")]
        Commands::Project { command } => run_project_command(&config, command).await,

        #[cfg(feature = "storage")]
        Commands::Finding { command } => run_finding_command(&config, command).await,

        #[cfg(feature = "storage")]
        Commands::Schedule { command } => run_schedule_command(&config, command).await,

        #[cfg(feature = "mcp")]
        Commands::Serve => crate::cli::serve::run_serve(&config).await,

        #[cfg(feature = "infra")]
        Commands::Infra { target, profile, modules, skip, quiet } => {
            run_infra(&config, &target, &profile, modules.as_deref(), skip.as_deref(), quiet).await
        }

        #[cfg(feature = "infra")]
        Commands::Assess { url, code, infra, cloud, profile, quiet } => {
            run_assess(
                &config,
                url.as_deref(),
                code.as_deref(),
                infra.as_deref(),
                cloud.as_deref(),
                &profile,
                quiet,
            )
            .await
        }

        #[cfg(feature = "cloud")]
        Commands::Cloud { target, profile, modules, skip, quiet } => {
            run_cloud(&config, &target, &profile, modules.as_deref(), skip.as_deref(), quiet).await
        }
    }
}

/// Run a unified DAST + SAST + Infra assessment.
///
/// At least one of `url`, `code`, or `infra` must be `Some`. The three
/// orchestrators run concurrently via `tokio::join!`; failures in any
/// domain are logged at `warn` and the remaining results are returned
/// merged into a single [`crate::engine::scan_result::ScanResult`].
///
/// # Errors
///
/// Returns [`crate::engine::error::ScorchError::Config`] if every input
/// is `None`. Returns the first available error only when every provided
/// domain failed.
#[cfg(feature = "infra")]
pub async fn run_assess(
    config: &std::sync::Arc<crate::config::AppConfig>,
    url: Option<&str>,
    code: Option<&std::path::Path>,
    infra: Option<&str>,
    cloud: Option<&str>,
    profile: &str,
    quiet: bool,
) -> crate::engine::error::Result<()> {
    use crate::engine::error::ScorchError;

    if url.is_none() && code.is_none() && infra.is_none() && cloud.is_none() {
        return Err(ScorchError::Config(
            "assess requires at least one of --url, --code, --infra, or --cloud".to_string(),
        ));
    }

    let engine = crate::facade::Engine::new(std::sync::Arc::clone(config));
    // Apply profile via individual calls since full_assessment doesn't take a profile;
    // for the simplest v1 we pass the profile to each underlying orchestrator through
    // a dedicated helper. Until that helper exists, we use the default profile path —
    // callers who need per-domain profile tuning should use `run --code` directly.
    let _ = profile;

    let result = engine.full_assessment(url, code, infra, cloud).await?;
    if !quiet {
        crate::report::terminal::print_report(&result);
    }
    Ok(())
}

/// Execute an infrastructure scan against `target`.
///
/// Parses the target string via [`crate::engine::infra_target::InfraTarget::parse`], constructs a
/// fresh [`crate::engine::infra_context::InfraContext`], applies the profile and module filters,
/// runs the orchestrator, and prints the resulting
/// [`crate::engine::scan_result::ScanResult`] via the terminal reporter.
///
/// # Errors
///
/// Returns [`crate::engine::error::ScorchError::InvalidTarget`] for
/// unparseable target strings, and propagates any orchestrator failure.
#[cfg(feature = "infra")]
pub async fn run_infra(
    config: &std::sync::Arc<crate::config::AppConfig>,
    target: &str,
    profile: &str,
    modules: Option<&str>,
    skip: Option<&str>,
    quiet: bool,
) -> crate::engine::error::Result<()> {
    use crate::engine::infra_context::InfraContext;
    use crate::engine::infra_target::InfraTarget;
    use crate::runner::infra_orchestrator::InfraOrchestrator;

    let infra_target = InfraTarget::parse(target)?;
    let http_client = build_http_client(config)?;
    let ctx = InfraContext::new(infra_target, std::sync::Arc::clone(config), http_client);
    let mut orch = InfraOrchestrator::new(ctx);
    orch.register_default_modules();
    orch.apply_profile(profile);

    if let Some(ids) = modules {
        let list: Vec<String> = ids.split(',').map(|s| s.trim().to_string()).collect();
        orch.filter_by_ids(&list);
    }
    if let Some(ids) = skip {
        let list: Vec<String> = ids.split(',').map(|s| s.trim().to_string()).collect();
        orch.exclude_by_ids(&list);
    }

    let result = orch.run(quiet).await?;
    crate::report::terminal::print_report(&result);
    Ok(())
}

/// Execute a cloud-posture scan against `target` (WORK-150).
///
/// Parses the target via [`crate::engine::cloud_target::CloudTarget::parse`],
/// constructs a [`crate::engine::cloud_context::CloudContext`], applies
/// the profile and module filters, runs the orchestrator, and prints
/// the resulting [`crate::engine::scan_result::ScanResult`].
///
/// At WORK-150 the registry is empty so any scan returns zero
/// findings. WORK-151+ will populate it.
///
/// # Errors
///
/// Returns [`crate::engine::error::ScorchError::InvalidTarget`] for
/// unparseable targets and propagates any orchestrator failure.
#[cfg(feature = "cloud")]
pub async fn run_cloud(
    config: &std::sync::Arc<crate::config::AppConfig>,
    target: &str,
    profile: &str,
    modules: Option<&str>,
    skip: Option<&str>,
    quiet: bool,
) -> crate::engine::error::Result<()> {
    use crate::engine::cloud_context::CloudContext;
    use crate::engine::cloud_target::CloudTarget;
    use crate::runner::cloud_orchestrator::CloudOrchestrator;

    let cloud_target = CloudTarget::parse(target)?;
    let ctx = CloudContext::new(cloud_target, std::sync::Arc::clone(config));
    let mut orch = CloudOrchestrator::new(ctx);
    orch.register_default_modules();
    orch.apply_profile(profile);

    if let Some(ids) = modules {
        let list: Vec<String> = ids.split(',').map(|s| s.trim().to_string()).collect();
        orch.filter_by_ids(&list);
    }
    if let Some(ids) = skip {
        let list: Vec<String> = ids.split(',').map(|s| s.trim().to_string()).collect();
        orch.exclude_by_ids(&list);
    }

    let result = orch.run(quiet).await?;
    crate::report::terminal::print_report(&result);
    Ok(())
}

/// Dispatch database subcommands.
#[cfg(feature = "storage")]
async fn run_db_command(config: &Arc<AppConfig>, command: args::DbCommands) -> Result<()> {
    match command {
        args::DbCommands::Migrate => crate::cli::db::run_migrate(config).await,
    }
}

/// Dispatch project subcommands.
#[cfg(feature = "storage")]
async fn run_project_command(
    config: &Arc<AppConfig>,
    command: args::ProjectCommands,
) -> Result<()> {
    let pool = crate::storage::connect_from_config(&config.database, None).await?;

    match command {
        args::ProjectCommands::Create { name, description } => {
            crate::cli::project::create(&pool, &name, description.as_deref()).await
        }
        args::ProjectCommands::List => crate::cli::project::list(&pool).await,
        args::ProjectCommands::Show { project } => crate::cli::project::show(&pool, &project).await,
        args::ProjectCommands::Delete { project, force } => {
            crate::cli::project::delete(&pool, &project, force).await
        }
        args::ProjectCommands::Status { project } => {
            crate::cli::project::status(&pool, &project).await
        }
        args::ProjectCommands::Intelligence { project } => {
            crate::cli::project::intelligence(&pool, &project).await
        }
        args::ProjectCommands::Target { command: target_cmd } => {
            run_target_command(&pool, target_cmd).await
        }
        args::ProjectCommands::Scans { project } => {
            crate::cli::project::list_scans(&pool, &project).await
        }
        args::ProjectCommands::ScanShow { id } => crate::cli::project::show_scan(&pool, &id).await,
    }
}

/// Dispatch target subcommands.
#[cfg(feature = "storage")]
async fn run_target_command(pool: &sqlx::PgPool, command: args::TargetCommands) -> Result<()> {
    match command {
        args::TargetCommands::Add { project, url, label } => {
            crate::cli::project::target_add(pool, &project, &url, label.as_deref()).await
        }
        args::TargetCommands::Remove { project, id } => {
            crate::cli::project::target_remove(pool, &project, &id).await
        }
        args::TargetCommands::List { project } => {
            crate::cli::project::target_list(pool, &project).await
        }
    }
}

/// Dispatch finding subcommands.
#[cfg(feature = "storage")]
async fn run_finding_command(
    config: &Arc<AppConfig>,
    command: args::FindingCommands,
) -> Result<()> {
    let pool = crate::storage::connect_from_config(&config.database, None).await?;

    match command {
        args::FindingCommands::List { project, severity, status } => {
            crate::cli::finding::list(&pool, &project, severity.as_deref(), status.as_deref()).await
        }
        args::FindingCommands::Show { id } => crate::cli::finding::show(&pool, &id).await,
        args::FindingCommands::Status { id, status, note } => {
            crate::cli::finding::update_status(&pool, &id, &status, note.as_deref()).await
        }
    }
}

/// Dispatch schedule subcommands.
#[cfg(feature = "storage")]
async fn run_schedule_command(
    config: &Arc<AppConfig>,
    command: args::ScheduleCommands,
) -> Result<()> {
    let pool = crate::storage::connect_from_config(&config.database, None).await?;

    match command {
        args::ScheduleCommands::Create { project, target, cron, profile } => {
            crate::cli::schedule::create(&pool, &project, &target, &cron, &profile).await
        }
        args::ScheduleCommands::List { project } => {
            crate::cli::schedule::list(&pool, &project).await
        }
        args::ScheduleCommands::Show { id } => crate::cli::schedule::show(&pool, &id).await,
        args::ScheduleCommands::Enable { id } => crate::cli::schedule::enable(&pool, &id).await,
        args::ScheduleCommands::Disable { id } => crate::cli::schedule::disable(&pool, &id).await,
        args::ScheduleCommands::Delete { id } => crate::cli::schedule::delete(&pool, &id).await,
        args::ScheduleCommands::RunDue => crate::cli::schedule::run_due(&pool, config).await,
    }
}

/// Resume an interrupted scan from a checkpoint file.
// JUSTIFICATION: Resume mirrors run_scan's parameter set minus target (from checkpoint)
#[allow(clippy::too_many_arguments)]
async fn run_scan_with_resume(
    config: &Arc<AppConfig>,
    checkpoint: &crate::runner::checkpoint::ScanCheckpoint,
    modules: Option<String>,
    skip: Option<String>,
    output_format: Option<OutputFormat>,
    quiet: bool,
    analyze: bool,
    _plan: bool,
    min_confidence: Option<f64>,
    project_name: Option<&str>,
    database_url: Option<&str>,
) -> Result<()> {
    use crate::runner::checkpoint;

    let target = Target::parse(&checkpoint.target)?;
    let http_client = build_http_client(config)?;
    let ctx = ScanContext::new(target, Arc::clone(config), http_client);

    let module_filter: Option<Vec<String>> =
        modules.map(|m| m.split(',').map(|s| s.trim().to_string()).collect());
    let skip_filter: Option<Vec<String>> =
        skip.map(|s| s.split(',').map(|s| s.trim().to_string()).collect());

    let mut orchestrator = Orchestrator::new(ctx);
    orchestrator.register_default_modules();
    let hook_runner = crate::engine::hook_runner::HookRunner::new(&config.hooks);
    orchestrator.set_hook_runner(hook_runner);
    orchestrator.apply_profile(&checkpoint.profile);

    if let Some(ref include) = module_filter {
        orchestrator.filter_by_ids(include);
    }
    if let Some(ref exclude) = skip_filter {
        orchestrator.exclude_by_ids(exclude);
    }

    let cp_path = checkpoint::checkpoint_path(&config.report.output_dir, &checkpoint.scan_id);
    let mut result = orchestrator.run_with_checkpoint(quiet, &cp_path, Some(checkpoint)).await?;

    if let Some(min_conf) = min_confidence {
        result.filter_by_confidence(min_conf);
    }

    // Save report
    match output_format {
        Some(OutputFormat::Json) | None => {
            let path = report::json::save_report(&result, &config.report)?;
            if !quiet {
                println!("\n{} {}", "Report saved:".green().bold(), path.display());
            }
        }
        Some(OutputFormat::Html) => {
            let path = report::html::save_report(&result, &config.report)?;
            if !quiet {
                println!("\n{} {}", "HTML report saved:".green().bold(), path.display());
            }
        }
        Some(OutputFormat::Sarif) => {
            let path = report::sarif::save_report(&result, &config.report)?;
            if !quiet {
                println!("\n{} {}", "SARIF report saved:".green().bold(), path.display());
            }
        }
        Some(OutputFormat::Pdf) => {
            let path = report::pdf::save_report(&result, &config.report)?;
            if !quiet {
                println!("\n{} {}", "PDF report saved:".green().bold(), path.display());
            }
        }
        _ => {}
    }

    if !quiet {
        report::terminal::print_report(&result);
    }

    if matches!(output_format, Some(OutputFormat::Json)) {
        let json = serde_json::to_string_pretty(&result)?;
        println!("{json}");
    }

    // Persist to database if --project was specified
    if let Some(name) = project_name {
        persist_scan_results(config, name, database_url, &result, quiet).await?;
    }

    // AI analysis
    let should_analyze = analyze || config.ai.auto_analyze;
    if should_analyze && config.ai.enabled {
        use crate::ai::prompts::AnalysisFocus;
        run_ai_analysis(config, &result, AnalysisFocus::Summary, quiet, None).await?;
    }

    Ok(())
}

// JUSTIFICATION: run_scan maps directly to CLI flag combinations; bundling into a struct
// would add indirection for an internal dispatch function with no external callers.
#[allow(clippy::too_many_arguments)]
// JUSTIFICATION: CLI dispatch function — match arms are the natural structure;
// extraction would scatter dispatch logic
// JUSTIFICATION: run_scan is the CLI dispatch hub — many parameters reflect CLI flags
#[allow(clippy::too_many_lines)]
async fn run_scan(
    config: &Arc<AppConfig>,
    target_str: &str,
    modules: Option<String>,
    skip: Option<String>,
    category_filter: Option<ModuleCategory>,
    output_format: Option<OutputFormat>,
    quiet: bool,
    analyze: bool,
    plan: bool,
    profile: &str,
    template: Option<&str>,
    min_confidence: Option<f64>,
    code_path: Option<&std::path::Path>,
    project_name: Option<&str>,
    database_url: Option<&str>,
) -> Result<()> {
    let target = Target::parse(target_str)?;

    if !quiet {
        println!();
        println!(
            "{}  {}",
            "ScorchKit".red().bold(),
            format!("v{}", env!("CARGO_PKG_VERSION")).dimmed()
        );
        println!("{}", "━".repeat(50).dimmed());
        println!("  Target: {}", target.url.as_str().cyan());
        if let Some(ref domain) = target.domain {
            let d: &str = domain;
            println!("  Domain: {}", d.cyan());
        }
        println!("    Port: {}", target.port.to_string().cyan());
        println!("     TLS: {}", if target.is_https { "yes".green() } else { "no".yellow() });
        println!(" Profile: {}", profile.cyan());
        if config.auth.bearer_token.is_some()
            || config.auth.cookies.is_some()
            || config.auth.username.is_some()
        {
            println!("    Auth: {}", "configured".green());
        }
        if project_name.is_some() {
            println!(" Project: {}", project_name.unwrap_or("").cyan());
        }
        println!("{}", "━".repeat(50).dimmed());
        println!();
    }

    // AI-guided scan planning runs before the main orchestrator (it uses its own recon pass)
    let ai_plan = if plan && config.ai.enabled {
        let planner = crate::ai::planner::ScanPlanner::from_config(&config.ai);
        if planner.is_available() {
            if !quiet {
                println!("{} Running AI-guided scan planning...", "AI".cyan().bold());
            }
            match planner.plan(&target, config).await {
                Ok(p) => Some(p),
                Err(e) => {
                    if !quiet {
                        println!(
                            "{} Scan planning failed: {e} — falling back to '{profile}' profile",
                            "note:".yellow(),
                        );
                    }
                    None
                }
            }
        } else {
            if !quiet {
                println!(
                    "{} claude CLI not found — falling back to '{profile}' profile",
                    "note:".yellow(),
                );
            }
            None
        }
    } else {
        None
    };

    let http_client = build_http_client(config)?;
    let ctx = ScanContext::new(target, Arc::clone(config), http_client);

    let module_filter: Option<Vec<String>> =
        modules.map(|m| m.split(',').map(|s| s.trim().to_string()).collect());
    let skip_filter: Option<Vec<String>> =
        skip.map(|s| s.split(',').map(|s| s.trim().to_string()).collect());

    let mut orchestrator = Orchestrator::new(ctx);
    orchestrator.register_default_modules();

    // Set up lifecycle hooks
    let hook_runner = crate::engine::hook_runner::HookRunner::new(&config.hooks);
    orchestrator.set_hook_runner(hook_runner);

    // Apply AI plan or fall back to profile
    if let Some(ref scan_plan) = ai_plan {
        if !quiet {
            println!(
                "{} Plan: {} module{} recommended — {}",
                "AI".cyan().bold(),
                scan_plan.recommendations.len(),
                if scan_plan.recommendations.len() == 1 { "" } else { "s" },
                scan_plan.overall_strategy.dimmed(),
            );
            println!();
        }
        if scan_plan.recommendations.is_empty() {
            if !quiet {
                println!("{} Empty plan — falling back to '{}' profile", "note:".yellow(), profile,);
            }
            orchestrator.apply_profile(profile);
        } else {
            let planned_ids: Vec<String> =
                scan_plan.recommendations.iter().map(|r| r.module_id.clone()).collect();
            orchestrator.filter_by_ids(&planned_ids);
        }
    } else if let Some(tmpl) = template {
        if !orchestrator.apply_template(tmpl) {
            return Err(ScorchError::Config(format!(
                "unknown template '{tmpl}'. Available: web-app, api, graphql, wordpress, spa, network, full"
            )));
        }
        if !quiet {
            println!("{} Using template: {}", "Template:".cyan().bold(), tmpl.cyan());
        }
    } else {
        orchestrator.apply_profile(profile);
    }

    if let Some(category) = category_filter {
        orchestrator.filter_by_category(category);
    }
    if let Some(ref include) = module_filter {
        orchestrator.filter_by_ids(include);
    }
    if let Some(ref exclude) = skip_filter {
        orchestrator.exclude_by_ids(exclude);
    }

    // Run with checkpoint support (enables --resume on future interrupted scans)
    let cp_path = crate::runner::checkpoint::checkpoint_path(
        &config.report.output_dir,
        &uuid::Uuid::new_v4().to_string(),
    );
    let mut result = orchestrator.run_with_checkpoint(quiet, &cp_path, None).await?;

    // If --code was specified, run SAST concurrently and merge results
    if let Some(path) = code_path {
        if !quiet {
            println!("\n{} Running SAST code scan on {}...", "CODE".cyan().bold(), path.display());
        }
        let code_ctx = crate::engine::code_context::CodeContext::new(
            path.to_path_buf(),
            None,
            Arc::clone(config),
        );
        let mut code_orchestrator =
            crate::runner::code_orchestrator::CodeOrchestrator::new(code_ctx);
        code_orchestrator.register_default_modules();

        match code_orchestrator.run().await {
            Ok(code_result) => {
                let code_count = code_result.findings.len();
                result.merge(code_result);
                if !quiet {
                    println!(
                        "  {} SAST scan complete: {} code findings merged",
                        "✓".green().bold(),
                        code_count
                    );
                }
            }
            Err(e) => {
                if !quiet {
                    println!(
                        "  {} SAST scan failed (DAST results preserved): {e}",
                        "WARN".yellow().bold()
                    );
                }
            }
        }
    }

    // Apply confidence filter before reporting (but after persistence-eligible collection)
    if let Some(min_conf) = min_confidence {
        result.filter_by_confidence(min_conf);
    }

    // Save report
    match output_format {
        Some(OutputFormat::Json) | None => {
            let path = report::json::save_report(&result, &config.report)?;
            if !quiet {
                println!("\n{} {}", "Report saved:".green().bold(), path.display());
            }
        }
        Some(OutputFormat::Html) => {
            let path = report::html::save_report(&result, &config.report)?;
            if !quiet {
                println!("\n{} {}", "HTML report saved:".green().bold(), path.display());
            }
        }
        Some(OutputFormat::Sarif) => {
            let path = report::sarif::save_report(&result, &config.report)?;
            if !quiet {
                println!("\n{} {}", "SARIF report saved:".green().bold(), path.display());
            }
        }
        Some(OutputFormat::Pdf) => {
            let path = report::pdf::save_report(&result, &config.report)?;
            if !quiet {
                println!("\n{} {}", "PDF report saved:".green().bold(), path.display());
            }
        }
        _ => {}
    }

    if !quiet {
        report::terminal::print_report(&result);
    }

    if matches!(output_format, Some(OutputFormat::Json)) {
        let json = serde_json::to_string_pretty(&result)?;
        println!("{json}");
    }

    // Persist to database if --project was specified
    if let Some(name) = project_name {
        persist_scan_results(config, name, database_url, &result, quiet).await?;
    }

    // AI analysis
    let should_analyze = analyze || config.ai.auto_analyze;
    if should_analyze && config.ai.enabled {
        run_ai_analysis(config, &result, AnalysisFocus::Summary, quiet, None).await?;
    }

    Ok(())
}

/// Persist scan results to the database under a named project.
#[cfg(feature = "storage")]
async fn persist_scan_results(
    config: &Arc<AppConfig>,
    project_name: &str,
    database_url: Option<&str>,
    result: &ScanResult,
    quiet: bool,
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
        "standard",
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

    // Update project intelligence with scan results
    if let Err(e) =
        crate::storage::intelligence::update_intelligence(&pool, project.id, result).await
    {
        if !quiet {
            println!("\n{} Intelligence update failed: {e}", "warning:".yellow().bold());
        }
    }

    if !quiet {
        let updated = result.findings.len() - new_count;
        println!(
            "\n{} Saved to project '{}': {} new finding{}, {} updated",
            "DB".cyan().bold(),
            project.name.cyan(),
            new_count,
            if new_count == 1 { "" } else { "s" },
            updated,
        );
    }

    Ok(())
}

/// Stub for when storage feature is not compiled.
#[cfg(not(feature = "storage"))]
// JUSTIFICATION: Must match the async signature of the storage-enabled version
// because the caller in run_scan() always calls with .await.
#[allow(clippy::unused_async)]
async fn persist_scan_results(
    _config: &Arc<AppConfig>,
    _project_name: &str,
    _database_url: Option<&str>,
    _result: &ScanResult,
    _quiet: bool,
) -> Result<()> {
    Err(ScorchError::Config(
        "--project requires the 'storage' feature. Rebuild with: \
         cargo build --features storage"
            .to_string(),
    ))
}

async fn run_analyze(
    config: &Arc<AppConfig>,
    report_path: &std::path::Path,
    focus_str: &str,
    project_name: Option<&str>,
    database_url: Option<&str>,
) -> Result<()> {
    if !report_path.exists() {
        return Err(ScorchError::Report(format!(
            "report file not found: {}",
            report_path.display()
        )));
    }

    let result = report::json::load_report(report_path)?;
    let focus = AnalysisFocus::parse(focus_str);

    println!();
    println!(
        "{}  Analyzing {} findings from scan {}",
        "ScorchKit".red().bold(),
        result.summary.total_findings,
        result.scan_id.dimmed()
    );

    let project_context = build_analyze_project_context(config, project_name, database_url).await?;

    run_ai_analysis(config, &result, focus, false, project_context.as_ref()).await
}

fn run_diff(baseline_path: &std::path::Path, current_path: &std::path::Path) -> Result<()> {
    let baseline = report::json::load_report(baseline_path)?;
    let current = report::json::load_report(current_path)?;

    report::diff::print_diff(&baseline, &current);
    Ok(())
}

async fn run_ai_analysis(
    config: &Arc<AppConfig>,
    result: &ScanResult,
    focus: AnalysisFocus,
    quiet: bool,
    project_context: Option<&crate::ai::types::ProjectContext>,
) -> Result<()> {
    if !config.ai.enabled {
        if !quiet {
            println!("\n{} AI analysis is disabled in config.", "note:".yellow());
        }
        return Ok(());
    }

    let ai = AiAnalyst::from_config(&config.ai);

    if !ai.is_available() {
        if !quiet {
            println!(
                "\n{} claude CLI not found. Install Claude Code to enable AI analysis.",
                "note:".yellow()
            );
        }
        return Ok(());
    }

    if !quiet {
        println!(
            "\n{} Running {} analysis with Claude...",
            "AI".cyan().bold(),
            focus.label().dimmed()
        );
    }

    match ai.analyze(result, focus, project_context).await {
        Ok(analysis) => {
            analyst::print_analysis(&analysis);
        }
        Err(e) => {
            if !quiet {
                println!("\n{} AI analysis failed: {e}", "error:".red().bold());
            }
        }
    }

    Ok(())
}

/// Build project context for the analyze command when --project is specified.
#[cfg(feature = "storage")]
async fn build_analyze_project_context(
    config: &Arc<AppConfig>,
    project_name: Option<&str>,
    database_url: Option<&str>,
) -> Result<Option<crate::ai::types::ProjectContext>> {
    let Some(name) = project_name else {
        return Ok(None);
    };

    let pool = crate::storage::connect_from_config(&config.database, database_url).await?;
    let project = crate::cli::project::resolve_project(&pool, name).await?;

    let ctx =
        crate::storage::context::build_project_context(&pool, project.id, &project.name).await?;

    Ok(Some(ctx))
}

/// Stub for when storage feature is not compiled.
#[cfg(not(feature = "storage"))]
// JUSTIFICATION: Must match the async signature of the storage-enabled version
// because the caller in run_analyze() always calls with .await.
#[allow(clippy::unused_async)]
async fn build_analyze_project_context(
    _config: &Arc<AppConfig>,
    project_name: Option<&str>,
    _database_url: Option<&str>,
) -> Result<Option<crate::ai::types::ProjectContext>> {
    if project_name.is_some() {
        return Err(ScorchError::Config(
            "--project requires the 'storage' feature. Rebuild with: \
             cargo build --features storage"
                .to_string(),
        ));
    }
    Ok(None)
}

/// Execute a code scan using the code orchestrator.
// JUSTIFICATION: Code scan maps directly to CLI flag combinations — same pattern as run_scan
#[allow(clippy::too_many_arguments)]
async fn run_code_scan(
    path: &std::path::Path,
    language: Option<String>,
    modules: Option<String>,
    skip: Option<String>,
    profile: &str,
    analyze: bool,
    config: &Arc<AppConfig>,
) -> Result<()> {
    use crate::engine::code_context::CodeContext;
    use crate::runner::code_orchestrator::CodeOrchestrator;

    let abs_path = std::fs::canonicalize(path).map_err(|e| ScorchError::InvalidTarget {
        target: path.display().to_string(),
        reason: e.to_string(),
    })?;

    println!();
    println!(
        "{}  {}",
        "ScorchKit".red().bold(),
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed()
    );
    println!("{}", "━".repeat(50).dimmed());
    println!("    Mode: {}", "Code Analysis (SAST)".cyan());
    println!("    Path: {}", abs_path.display().to_string().cyan());

    let ctx = CodeContext::new(abs_path, language.clone(), Arc::clone(config));

    if let Some(ref lang) = ctx.language {
        println!("Language: {}", lang.cyan());
    }
    if !ctx.manifests.is_empty() {
        println!(
            "Manifests: {}",
            ctx.manifests
                .iter()
                .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
                .collect::<Vec<_>>()
                .join(", ")
                .cyan()
        );
    }
    println!(" Profile: {}", profile.cyan());
    println!("{}", "━".repeat(50).dimmed());
    println!();

    let mut orchestrator = CodeOrchestrator::new(ctx);
    orchestrator.register_default_modules();
    let hook_runner = crate::engine::hook_runner::HookRunner::new(&config.hooks);
    orchestrator.set_hook_runner(hook_runner);
    orchestrator.apply_profile(profile);

    if let Some(ref mods) = modules {
        let ids: Vec<String> = mods.split(',').map(|s| s.trim().to_string()).collect();
        orchestrator.filter_by_ids(&ids);
    }
    if let Some(ref skip_ids) = skip {
        let ids: Vec<String> = skip_ids.split(',').map(|s| s.trim().to_string()).collect();
        orchestrator.exclude_by_ids(&ids);
    }

    let result = orchestrator.run().await?;

    // Display results using existing terminal reporter
    report::terminal::print_report(&result);

    // Save JSON report
    let report_path = report::json::save_report(&result, &config.report)?;
    println!("\n{} {}", "Report saved:".green().bold(), report_path.display());

    // AI analysis
    let should_analyze = analyze || config.ai.auto_analyze;
    if should_analyze && config.ai.enabled {
        use crate::ai::prompts::AnalysisFocus;
        run_ai_analysis(config, &result, AnalysisFocus::Summary, false, None).await?;
    }

    Ok(())
}

fn list_modules(check_tools: bool) {
    let modules = crate::runner::orchestrator::all_modules();

    println!();
    println!("{}", "Available Modules".bold().underline());
    println!();

    for module in &modules {
        let tool_status = if module.requires_external_tool() {
            let tool = module.required_tool().unwrap_or("unknown");
            if check_tools {
                if is_tool_available(tool) {
                    format!(" [{}]", tool.green())
                } else {
                    format!(" [{} - {}]", tool.red(), "not found".red())
                }
            } else {
                format!(" [requires: {tool}]")
            }
        } else {
            " [built-in]".dimmed().to_string()
        };

        println!(
            "  {:>8} | {:<20} {}{}",
            module.category().to_string().dimmed(),
            module.id().cyan(),
            module.description(),
            tool_status,
        );
    }
    println!();
}

fn build_http_client(config: &AppConfig) -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();

    // Add auth headers
    if let Some(ref token) = config.auth.bearer_token {
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
    }
    if let Some(ref username) = config.auth.username {
        let password = config.auth.password.as_deref().unwrap_or("");
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{username}:{password}"),
        );
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Basic {encoded}")) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
    }
    if let Some(ref cookies) = config.auth.cookies {
        if let Ok(val) = reqwest::header::HeaderValue::from_str(cookies) {
            headers.insert(reqwest::header::COOKIE, val);
        }
    }
    if let (Some(ref name), Some(ref value)) =
        (&config.auth.custom_header, &config.auth.custom_header_value)
    {
        if let (Ok(header_name), Ok(header_val)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_val);
        }
    }

    // Add custom scan headers
    for (name, value) in &config.scan.headers {
        if let (Ok(header_name), Ok(header_val)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_val);
        }
    }

    let mut builder = reqwest::Client::builder()
        .user_agent(&config.scan.user_agent)
        .timeout(std::time::Duration::from_secs(config.scan.timeout_seconds))
        .default_headers(headers)
        .cookie_store(true)
        .danger_accept_invalid_certs(config.scan.insecure);

    if config.scan.follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::limited(config.scan.max_redirects));
    } else {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    // Proxy support (Burp Suite, ZAP, etc.)
    if let Some(ref proxy_url) = config.scan.proxy {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| ScorchError::Config(format!("invalid proxy URL '{proxy_url}': {e}")))?;
        builder = builder.proxy(proxy);
    }

    builder.build().map_err(|e| ScorchError::Config(format!("failed to build HTTP client: {e}")))
}

fn is_tool_available(tool: &str) -> bool {
    super::doctor::is_tool_available(tool)
}
