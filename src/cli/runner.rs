use std::io::Read;
use std::sync::Arc;

use colored::Colorize;

use crate::ai::analyst::{self, AiAnalyst};
use crate::ai::prompts::AnalysisFocus;
use crate::cli::args::{self, Cli, Commands, OutputFormat};
use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::module_trait::ModuleCategory;
use crate::engine::scan_result::ScanResult;
use crate::engine::target::Target;
use crate::report;
use crate::runner::orchestrator::Orchestrator;

#[cfg(any(feature = "infra", feature = "cloud", test))]
const fn effective_quiet(command_quiet: bool, global_quiet: bool) -> bool {
    command_quiet || global_quiet
}

const fn should_run_ai(requested: bool, automatic: bool, enabled: bool) -> bool {
    (requested || automatic) && enabled
}

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
                            println!(
                                "{} Target {} failed: {}",
                                "ERR".red().bold(),
                                crate::report::terminal::escape_terminal_text(target_str),
                                crate::report::terminal::escape_terminal_text(&e.to_string())
                            );
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
                    println!(
                        "    {} {}: {}",
                        "✗".red(),
                        crate::report::terminal::escape_terminal_text(t),
                        crate::report::terminal::escape_terminal_text(e)
                    );
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

        Commands::Modules { check_tools, include_compatibility } => {
            list_modules(&config, check_tools, include_compatibility)
        }

        Commands::Catalog { command } => run_catalog_command(&config, command),

        Commands::Init { target, project, database_url } => {
            super::init::run_init(target.as_deref(), project.as_deref(), database_url.as_deref())
                .await
        }

        Commands::Doctor { deep } => super::doctor::run_doctor(deep).await,

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
        } => {
            run_code_scan(
                &path, language, modules, skip, &profile, analyze, &config, cli.output, cli.quiet,
            )
            .await
        }

        Commands::SupplyChain { command } => {
            run_supply_chain_command(&config, command, cli.output, cli.quiet).await
        }

        Commands::Dast { request } => {
            run_application_dast(&config, &request, cli.output, cli.quiet).await
        }

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

        #[cfg(feature = "storage")]
        Commands::Job { command } => {
            Box::pin(crate::cli::job::run_job_command(&config, command)).await
        }

        #[cfg(feature = "storage")]
        Commands::Webhook { command } => {
            crate::cli::webhook::run_webhook_command(&config, command).await
        }

        #[cfg(feature = "mcp")]
        Commands::Serve { remote } => Box::pin(crate::cli::serve::run_serve(&config, remote)).await,

        #[cfg(feature = "control-api")]
        Commands::ControlApi { database_url } => {
            crate::cli::control_api::run_control_api(&config, database_url.as_deref()).await
        }

        #[cfg(feature = "team")]
        Commands::TeamApi => crate::cli::team::run_team_api(config).await,

        #[cfg(feature = "infra")]
        Commands::Infra { target, profile, modules, skip, quiet } => {
            run_infra(
                &config,
                &target,
                &profile,
                modules.as_deref(),
                skip.as_deref(),
                effective_quiet(quiet, cli.quiet),
                cli.output,
            )
            .await
        }

        #[cfg(feature = "infra")]
        Commands::Assess { url, code, infra, cloud, profile, quiet } => {
            run_assess(
                &config,
                AssessmentTargets {
                    url: url.as_deref(),
                    code: code.as_deref(),
                    infra: infra.as_deref(),
                    cloud: cloud.as_deref(),
                },
                &profile,
                effective_quiet(quiet, cli.quiet),
                cli.output,
            )
            .await
        }

        #[cfg(feature = "cloud")]
        Commands::Cloud { target, profile, modules, skip, quiet } => {
            run_cloud(
                &config,
                &target,
                &profile,
                modules.as_deref(),
                skip.as_deref(),
                effective_quiet(quiet, cli.quiet),
                cli.output,
            )
            .await
        }
    }
}

async fn run_application_dast(
    config: &Arc<AppConfig>,
    request_path: &std::path::Path,
    output_format: Option<OutputFormat>,
    quiet: bool,
) -> Result<()> {
    const REQUEST_LIMIT_BYTES: usize = 1024 * 1024;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(request_path)?;
    if !file.metadata()?.is_file() {
        return Err(ScorchError::Config(
            "application DAST request must be one regular file".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(REQUEST_LIMIT_BYTES.min(64 * 1024));
    file.by_ref()
        .take(u64::try_from(REQUEST_LIMIT_BYTES.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    if bytes.len() > REQUEST_LIMIT_BYTES {
        return Err(ScorchError::Config(
            "application DAST request exceeds the 1 MiB input limit".to_string(),
        ));
    }
    let request: crate::application_dast::ApplicationDastRequest = serde_json::from_slice(&bytes)?;
    let result = crate::facade::Engine::new(Arc::clone(config)).application_dast(&request).await?;
    emit_scan_report(&result, config, output_format.as_ref(), quiet).await
}

async fn run_supply_chain_command(
    config: &Arc<AppConfig>,
    command: args::SupplyChainCommands,
    output_format: Option<OutputFormat>,
    quiet: bool,
) -> Result<()> {
    let engine = crate::facade::Engine::new(Arc::clone(config));
    match command {
        args::SupplyChainCommands::Scan { path, kind, profile, revision } => {
            let kind = match kind {
                args::SupplyChainTargetKindArg::SourceDirectory => {
                    scorchkit_core::SupplyChainTargetKind::SourceDirectory
                }
                args::SupplyChainTargetKindArg::DirectoryArtifact => {
                    scorchkit_core::SupplyChainTargetKind::DirectoryArtifact
                }
                args::SupplyChainTargetKindArg::FileArtifact => {
                    scorchkit_core::SupplyChainTargetKind::FileArtifact
                }
                args::SupplyChainTargetKindArg::OciArchive => {
                    scorchkit_core::SupplyChainTargetKind::OciArchive
                }
                args::SupplyChainTargetKindArg::OciLayout => {
                    scorchkit_core::SupplyChainTargetKind::OciLayout
                }
                args::SupplyChainTargetKindArg::CycloneDxSbom => {
                    scorchkit_core::SupplyChainTargetKind::CycloneDxSbom
                }
            };
            let result =
                engine.supply_chain_scan_with_profile(&path, kind, &profile, revision).await?;
            emit_scan_report(&result, config, output_format.as_ref(), quiet).await
        }
        args::SupplyChainCommands::CacheStatus => {
            let snapshots = engine.supply_chain_cache_status()?;
            println!("{}", serde_json::to_string_pretty(&snapshots)?);
            Ok(())
        }
        args::SupplyChainCommands::CacheRefresh { request } => {
            let metadata = std::fs::metadata(&request)?;
            if metadata.len() > 1024 * 1024 {
                return Err(ScorchError::Config(
                    "provider refresh request exceeds the 1 MiB metadata limit".to_string(),
                ));
            }
            let bytes = std::fs::read(&request)?;
            let request: crate::supply_chain::ProviderRefreshRequest =
                serde_json::from_slice(&bytes)?;
            let snapshot = engine.supply_chain_cache_refresh(&request).await?;
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
            Ok(())
        }
    }
}

/// Save and render one scan result according to the global CLI output contract.
async fn emit_scan_report(
    result: &ScanResult,
    config: &AppConfig,
    output_format: Option<&OutputFormat>,
    quiet: bool,
) -> Result<()> {
    let saved_report = match output_format {
        None | Some(OutputFormat::Json) => {
            let path = report::json::save_report(result, &config.report)?;
            Some(("Report saved:", path))
        }
        Some(OutputFormat::Html) => {
            let path = report::html::save_report(result, &config.report)?;
            Some(("HTML report saved:", path))
        }
        Some(OutputFormat::Sarif) => {
            let path = report::sarif::save_report(result, &config.report)?;
            Some(("SARIF report saved:", path))
        }
        Some(OutputFormat::Pdf) => {
            let path = report::pdf::save_report(result, &config.report).await?;
            Some(("PDF report saved:", path))
        }
        Some(OutputFormat::Terminal) => None,
    };

    if !quiet {
        if let Some((label, path)) = saved_report {
            println!("\n{} {}", label.green().bold(), path.display());
        }
        report::terminal::print_report(result);
    }
    if matches!(output_format, Some(OutputFormat::Json)) {
        println!("{}", serde_json::to_string_pretty(result)?);
    }
    Ok(())
}

/// Optional targets accepted by the unified assessment command.
#[cfg(feature = "infra")]
struct AssessmentTargets<'a> {
    url: Option<&'a str>,
    code: Option<&'a std::path::Path>,
    infra: Option<&'a str>,
    cloud: Option<&'a str>,
}

/// Run a unified DAST, SAST, infrastructure, and cloud assessment.
///
/// Requested family orchestrators run concurrently; successful results are merged into one
/// [`crate::engine::scan_result::ScanResult`]. The selected profile and global report format apply
/// to every family.
///
/// # Errors
///
/// Returns [`crate::engine::error::ScorchError::Config`] if every target is absent. Returns the
/// first available error only when every requested family failed.
#[cfg(feature = "infra")]
async fn run_assess(
    config: &std::sync::Arc<crate::config::AppConfig>,
    targets: AssessmentTargets<'_>,
    profile: &str,
    quiet: bool,
    output_format: Option<OutputFormat>,
) -> crate::engine::error::Result<()> {
    use crate::engine::error::ScorchError;

    if targets.url.is_none()
        && targets.code.is_none()
        && targets.infra.is_none()
        && targets.cloud.is_none()
    {
        return Err(ScorchError::Config(
            "assess requires at least one of --url, --code, --infra, or --cloud".to_string(),
        ));
    }

    let engine = crate::facade::Engine::new(std::sync::Arc::clone(config));
    let result = engine
        .full_assessment_with_profile(
            targets.url,
            targets.code,
            targets.infra,
            targets.cloud,
            profile,
        )
        .await?;
    emit_scan_report(&result, config, output_format.as_ref(), quiet).await?;
    Ok(())
}

/// Execute an infrastructure scan against `target`.
///
/// Builds an authorized [`crate::engine::infra_context::InfraContext`] through the facade, injects
/// the configured CVE lookup, applies profile and module filters, and sends the result through the
/// global report contract.
///
/// # Errors
///
/// Returns [`crate::engine::error::ScorchError::InvalidTarget`] for
/// unparsable target strings, and propagates any orchestrator failure.
#[cfg(feature = "infra")]
pub async fn run_infra(
    config: &std::sync::Arc<crate::config::AppConfig>,
    target: &str,
    profile: &str,
    modules: Option<&str>,
    skip: Option<&str>,
    quiet: bool,
    output_format: Option<OutputFormat>,
) -> crate::engine::error::Result<()> {
    use crate::infra::cve_lookup::build_cve_lookup;
    use crate::infra::cve_match::CveMatchModule;
    use crate::runner::infra_orchestrator::InfraOrchestrator;

    crate::facade::validate_scan_profile(profile)?;
    let engine = crate::facade::Engine::new(Arc::clone(config));
    let ctx = engine.infra_context(target)?;
    let mut orch = InfraOrchestrator::new(ctx);
    orch.register_default_modules();
    let engagement = engine.engagement().ok_or_else(|| {
        ScorchError::Config("CVE lookup denied: no engagement authorization is configured".into())
    })?;
    if let Some(lookup) = build_cve_lookup(config, Arc::new(engagement.clone()))? {
        orch.add_module(Box::new(CveMatchModule::new(lookup)));
    }
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
    emit_scan_report(&result, config, output_format.as_ref(), quiet).await?;
    Ok(())
}

/// Execute a cloud-posture scan against `target` (WORK-150).
///
/// Parses the target via [`crate::engine::cloud_target::CloudTarget::parse`],
/// constructs a [`crate::engine::cloud_context::CloudContext`], applies the profile and module
/// filters, runs the orchestrator, and sends the result through the global report contract.
///
/// # Errors
///
/// Returns [`crate::engine::error::ScorchError::InvalidTarget`] for
/// unparsable targets and propagates any orchestrator failure.
#[cfg(feature = "cloud")]
pub async fn run_cloud(
    config: &std::sync::Arc<crate::config::AppConfig>,
    target: &str,
    profile: &str,
    modules: Option<&str>,
    skip: Option<&str>,
    quiet: bool,
    output_format: Option<OutputFormat>,
) -> crate::engine::error::Result<()> {
    use crate::runner::cloud_orchestrator::CloudOrchestrator;

    crate::facade::validate_scan_profile(profile)?;
    let ctx = crate::facade::Engine::new(Arc::clone(config)).cloud_context(target)?;
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
    emit_scan_report(&result, config, output_format.as_ref(), quiet).await?;
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
    let service =
        crate::control::ControlService::persistent(Arc::clone(config), pool.clone(), None);
    let control = crate::cli::control_adapter::LocalControlClient::new(config, service);

    match command {
        args::ProjectCommands::Create { name, description } => {
            crate::cli::project::control_create(&control, &name, description.as_deref()).await
        }
        args::ProjectCommands::List => crate::cli::project::control_list(&control).await,
        args::ProjectCommands::Show { project } => {
            crate::cli::project::control_show(&control, &project).await
        }
        args::ProjectCommands::Delete { project, force } => {
            crate::cli::project::control_delete(&control, &project, force).await
        }
        args::ProjectCommands::Status { project } => {
            crate::cli::project::status(&pool, &project).await
        }
        args::ProjectCommands::Intelligence { project } => {
            crate::cli::project::intelligence(&pool, &project).await
        }
        args::ProjectCommands::Target { command: target_cmd } => {
            run_target_command(&control, target_cmd).await
        }
        args::ProjectCommands::Scans { project } => {
            crate::cli::project::list_scans(&pool, &project).await
        }
        args::ProjectCommands::ScanShow { id } => crate::cli::project::show_scan(&pool, &id).await,
    }
}

/// Dispatch target subcommands.
#[cfg(feature = "storage")]
async fn run_target_command(
    control: &crate::cli::control_adapter::LocalControlClient,
    command: args::TargetCommands,
) -> Result<()> {
    match command {
        args::TargetCommands::Add { project, url, label } => {
            crate::cli::project::control_target_add(control, &project, &url, label.as_deref()).await
        }
        args::TargetCommands::Remove { project, id } => {
            crate::cli::project::control_target_remove(control, &project, &id).await
        }
        args::TargetCommands::List { project } => {
            crate::cli::project::control_target_list(control, &project).await
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
    let service =
        crate::control::ControlService::persistent(Arc::clone(config), pool.clone(), None);
    let control = crate::cli::control_adapter::LocalControlClient::new(config, service);

    match command {
        args::FindingCommands::List { project, severity, status } => {
            crate::cli::finding::control_list(
                &control,
                &project,
                severity.as_deref(),
                status.as_deref(),
            )
            .await
        }
        args::FindingCommands::Show { id } => {
            crate::cli::finding::control_show(&control, &id).await
        }
        args::FindingCommands::Status { id, status, note } => {
            crate::cli::finding::update_status(&control, &id, &status, note.as_deref()).await
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
            crate::cli::schedule::create(config, &pool, &project, &target, &cron, &profile).await
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

    let engine = crate::facade::Engine::new(Arc::clone(config));
    let ctx = engine.dast_context(&checkpoint.target, &checkpoint.profile)?;

    let module_filter: Option<Vec<String>> =
        modules.map(|m| m.split(',').map(|s| s.trim().to_string()).collect());
    let skip_filter: Option<Vec<String>> =
        skip.map(|s| s.split(',').map(|s| s.trim().to_string()).collect());

    let mut orchestrator = Orchestrator::new(ctx);
    orchestrator.register_default_modules();
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

    emit_scan_report(&result, config, output_format.as_ref(), quiet).await?;

    // Persist to database if --project was specified
    if let Some(name) = project_name {
        persist_scan_results(config, name, database_url, &result, quiet).await?;
    }

    // AI analysis
    if should_run_ai(analyze, config.ai.auto_analyze, config.ai.enabled) {
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
            let planning_engine = crate::facade::Engine::new(Arc::clone(config));
            planning_engine.dast_context_for_target(target.clone(), "quick")?;
            planning_engine.require_authorized(
                crate::engine::policy::PolicyTarget::Web(target.url.clone()),
                crate::engine::policy::Capability::ExternalTool,
                crate::engine::policy::EffectClass::ActiveSafe,
            )?;
            match planner.plan(&target, &planning_engine).await {
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
                    "{} {} not found — falling back to '{profile}' profile",
                    "note:".yellow(),
                    planner.provider_name(),
                );
            }
            None
        }
    } else {
        None
    };

    let engine = crate::facade::Engine::new(Arc::clone(config));
    let ctx = engine.dast_context_for_target(target, profile)?;

    let module_filter: Option<Vec<String>> =
        modules.map(|m| m.split(',').map(|s| s.trim().to_string()).collect());
    let skip_filter: Option<Vec<String>> =
        skip.map(|s| s.split(',').map(|s| s.trim().to_string()).collect());

    let mut orchestrator = Orchestrator::new(ctx);
    orchestrator.register_default_modules();

    // Apply AI plan or fall back to profile
    if let Some(ref scan_plan) = ai_plan {
        if crate::runner::progress::is_visible(quiet) {
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
            if let Some(message) = empty_plan_fallback_message(quiet, profile) {
                println!("{} {message}", "note:".yellow());
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
                "unknown template '{tmpl}'. Available: web-app, api, graphql, wordpress, spa, network, compatibility, full"
            )));
        }
        if !quiet {
            println!("{} Using template: {}", "Template:".cyan().bold(), tmpl.cyan());
        }
    } else if let Some(ref include) = module_filter {
        orchestrator.apply_selection(profile, Some(include));
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
        let code_ctx = engine.code_context(path, None)?;
        let mut code_orchestrator =
            crate::runner::code_orchestrator::CodeOrchestrator::new(code_ctx);
        code_orchestrator.register_default_modules();
        code_orchestrator.apply_profile(profile);

        match code_orchestrator.run_quiet(quiet).await {
            Ok(code_result) => {
                let code_count = code_result.findings.len();
                let code_degraded = code_result.has_failed_modules();
                result.merge(code_result);
                if !quiet {
                    if code_degraded {
                        println!(
                            "  {} SAST scan degraded: {} code findings preserved; see module outcomes",
                            "WARN".yellow().bold(),
                            code_count
                        );
                    } else {
                        println!(
                            "  {} SAST scan complete: {} code findings merged",
                            "✓".green().bold(),
                            code_count
                        );
                    }
                }
            }
            Err(e) => {
                let message = crate::engine::observation::redact_text(&e.to_string());
                result.record_execution_failure("code-scan", &message);
                if !quiet {
                    println!(
                        "  {} SAST scan failed (DAST results preserved): {}",
                        "WARN".yellow().bold(),
                        crate::report::terminal::escape_terminal_text(&message)
                    );
                }
            }
        }
    }

    // Apply confidence filter before reporting (but after persistence-eligible collection)
    if let Some(min_conf) = min_confidence {
        result.filter_by_confidence(min_conf);
    }

    emit_scan_report(&result, config, output_format.as_ref(), quiet).await?;

    // Persist to database if --project was specified
    if let Some(name) = project_name {
        persist_scan_results(config, name, database_url, &result, quiet).await?;
    }

    // AI analysis
    if should_run_ai(analyze, config.ai.auto_analyze, config.ai.enabled) {
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

    let scan = crate::storage::scans::save_scan_with_evidence(
        &pool,
        project.id,
        result.target.url.as_str(),
        "standard",
        result.started_at,
        Some(result.completed_at),
        &modules_run,
        &modules_skipped,
        &summary_json,
        &crate::storage::scans::execution_evidence(result),
    )
    .await?;

    let new_count =
        crate::storage::findings::save_findings(&pool, project.id, scan.id, &result.findings)
            .await?;

    // Update project intelligence with scan results
    if let Err(e) =
        crate::storage::intelligence::update_intelligence(&pool, project.id, result).await
    {
        if crate::runner::progress::is_visible(quiet) {
            println!(
                "\n{} Intelligence update failed: {}",
                "warning:".yellow().bold(),
                crate::report::terminal::escape_terminal_text(&e.to_string())
            );
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
                "\n{} {} not found. Install or configure the selected AI provider.",
                "note:".yellow(),
                ai.provider_name(),
            );
        }
        return Ok(());
    }

    if !quiet {
        println!(
            "\n{} Running {} analysis with {}...",
            "AI".cyan().bold(),
            focus.label().dimmed(),
            ai.provider_name(),
        );
    }

    crate::facade::Engine::new(Arc::clone(config)).require_authorized(
        crate::engine::policy::PolicyTarget::Web(result.target.url.clone()),
        crate::engine::policy::Capability::ExternalTool,
        crate::engine::policy::EffectClass::Passive,
    )?;

    match ai.analyze(result, focus, project_context).await {
        Ok(analysis) => {
            print!("{}", analyst::render_analysis(&analysis));
        }
        Err(e) => {
            if !quiet {
                println!(
                    "\n{} AI analysis failed: {}",
                    "error:".red().bold(),
                    crate::report::terminal::escape_terminal_text(&e.to_string())
                );
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
    output_format: Option<OutputFormat>,
    quiet: bool,
) -> Result<()> {
    use crate::runner::code_orchestrator::CodeOrchestrator;

    crate::facade::validate_scan_profile(profile)?;
    let abs_path = std::fs::canonicalize(path).map_err(|e| ScorchError::InvalidTarget {
        target: path.display().to_string(),
        reason: e.to_string(),
    })?;
    let engine = crate::facade::Engine::new(Arc::clone(config));

    if !quiet {
        println!();
        println!(
            "{}  {}",
            "ScorchKit".red().bold(),
            format!("v{}", env!("CARGO_PKG_VERSION")).dimmed()
        );
        println!("{}", "━".repeat(50).dimmed());
        println!("    Mode: {}", "Code Analysis (SAST)".cyan());
        println!("    Path: {}", abs_path.display().to_string().cyan());
    }

    let ctx = engine.code_context(&abs_path, language.as_deref())?;

    if !quiet {
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
    }

    let mut orchestrator = CodeOrchestrator::new(ctx);
    orchestrator.register_default_modules();
    let module_ids = modules
        .as_deref()
        .map(|mods| mods.split(',').map(|id| id.trim().to_string()).collect::<Vec<_>>());
    orchestrator.apply_selection(profile, module_ids.as_deref());
    if let Some(ref skip_ids) = skip {
        let ids: Vec<String> = skip_ids.split(',').map(|s| s.trim().to_string()).collect();
        orchestrator.exclude_by_ids(&ids);
    }

    let mut result = orchestrator.run_quiet(quiet).await?;
    let supply_chain = engine
        .supply_chain_scan_with_profile(
            &abs_path,
            scorchkit_core::SupplyChainTargetKind::SourceDirectory,
            profile,
            None,
        )
        .await?;
    result.merge(supply_chain);
    emit_scan_report(&result, config, output_format.as_ref(), quiet).await?;

    // AI analysis
    if should_run_ai(analyze, config.ai.auto_analyze, config.ai.enabled) {
        use crate::ai::prompts::AnalysisFocus;
        run_ai_analysis(config, &result, AnalysisFocus::Summary, quiet, None).await?;
    }

    Ok(())
}

fn run_catalog_command(config: &AppConfig, command: args::CatalogCommands) -> Result<()> {
    let engagement = config.engagement.as_ref().ok_or_else(|| {
        ScorchError::Config("extension catalog operation has no active engagement".to_string())
    })?;
    let lifecycle = crate::extension::CatalogLifecycle::new(&config.extensions, engagement);
    let value = match command {
        args::CatalogCommands::Inspect { catalog, release } => {
            serde_json::to_value(lifecycle.inspect(&catalog, &release)?)
        }
        args::CatalogCommands::Approve {
            catalog,
            release,
            payload_sha256,
            permission_diff_sha256,
        } => serde_json::to_value(lifecycle.approve(
            &catalog,
            &release,
            &payload_sha256,
            &permission_diff_sha256,
        )?),
        args::CatalogCommands::Activate { approval } => {
            serde_json::to_value(lifecycle.activate(&approval)?)
        }
        args::CatalogCommands::Rollback { extension, approval } => {
            serde_json::to_value(lifecycle.rollback(&extension, &approval)?)
        }
        args::CatalogCommands::Status => serde_json::to_value(lifecycle.status()?),
    }
    .map_err(|_| ScorchError::Config("catalog result cannot be encoded".to_string()))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&value)
            .map_err(|_| ScorchError::Config("catalog result cannot be rendered".to_string()))?
    );
    Ok(())
}

fn list_modules(config: &AppConfig, check_tools: bool, include_compatibility: bool) -> Result<()> {
    let modules = if include_compatibility {
        crate::runner::orchestrator::all_modules()
    } else {
        crate::runner::orchestrator::application_modules()
    };
    let mut module_identities: std::collections::BTreeSet<String> =
        modules.iter().map(|module| module.id().to_string()).collect();

    println!();
    println!("{}", "Available Modules".bold().underline());
    println!();

    for module in &modules {
        let tool_status = if module.requires_external_tool() {
            let tool = module.required_tool().unwrap_or("unknown");
            if check_tools {
                if super::doctor::is_tool_available(tool) {
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
    if !config.extensions.manifests.is_empty() {
        let engagement = config.engagement.as_ref().ok_or_else(|| {
            crate::engine::error::ScorchError::Config(
                "configured extension catalog has no active engagement".to_string(),
            )
        })?;
        for manifest_path in &config.extensions.manifests {
            let loaded = crate::extension::LoadedExtension::load_for_catalog(
                &config.extensions,
                engagement,
                manifest_path,
            )?;
            claim_extension_catalog_identity(&mut module_identities, &loaded.manifest.id)?;
            println!(
                "  {:>8} | {:<20} {}{}",
                ModuleCategory::Scanner.to_string().dimmed(),
                loaded.manifest.id.cyan(),
                loaded.manifest.description,
                " [isolated wasm]".dimmed(),
            );
        }
    }
    if config.extensions.lifecycle_root.is_some() {
        let engagement = config.engagement.as_ref().ok_or_else(|| {
            ScorchError::Config(
                "configured extension lifecycle has no active engagement".to_string(),
            )
        })?;
        let active = crate::extension::CatalogLifecycle::new(&config.extensions, engagement)
            .load_active()?;
        for loaded in active {
            claim_extension_catalog_identity(&mut module_identities, &loaded.manifest.id)?;
            println!(
                "  {:>8} | {:<20} {}{}",
                ModuleCategory::Scanner.to_string().dimmed(),
                loaded.manifest.id.cyan(),
                loaded.manifest.description,
                " [approved catalog wasm]".dimmed(),
            );
        }
    }
    println!();
    Ok(())
}

fn claim_extension_catalog_identity(
    identities: &mut std::collections::BTreeSet<String>,
    identity: &str,
) -> Result<()> {
    if !identities.insert(identity.to_string()) {
        return Err(crate::engine::error::ScorchError::Config(format!(
            "duplicate extension module identity '{}'",
            crate::engine::observation::redact_text(identity)
        )));
    }
    Ok(())
}

fn empty_plan_fallback_message(quiet: bool, profile: &str) -> Option<String> {
    if quiet {
        None
    } else {
        Some(format!("Empty plan — falling back to '{profile}' profile"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;

    use super::{
        claim_extension_catalog_identity, effective_quiet, emit_scan_report,
        empty_plan_fallback_message, run_ai_analysis, run_application_dast,
        run_supply_chain_command, should_run_ai,
    };
    #[cfg(feature = "storage")]
    use super::{persist_scan_results, run_finding_command};
    #[cfg(feature = "infra")]
    use super::{run_assess, AssessmentTargets};
    #[cfg(all(feature = "infra", feature = "cloud"))]
    use super::{run_cloud, run_code_scan, run_infra};
    use crate::cli::args::OutputFormat;
    use crate::config::AppConfig;
    use crate::engine::scan_result::ScanResult;
    use crate::engine::target::Target;

    #[test]
    fn empty_plan_message_respects_quiet_mode() {
        assert_eq!(empty_plan_fallback_message(true, "quick"), None);
        assert_eq!(
            empty_plan_fallback_message(false, "standard"),
            Some("Empty plan — falling back to 'standard' profile".to_string())
        );
    }

    #[test]
    fn extension_catalog_identity_claims_reject_every_duplicate() {
        let mut identities = std::collections::BTreeSet::from(["headers".to_string()]);
        assert!(claim_extension_catalog_identity(&mut identities, "fixture.extension").is_ok());
        assert!(claim_extension_catalog_identity(&mut identities, "fixture.extension").is_err());
        assert!(claim_extension_catalog_identity(&mut identities, "headers").is_err());
        assert_eq!(identities.len(), 2);
    }

    #[test]
    fn command_and_global_quiet_flags_compose_as_a_logical_or() {
        assert!(!effective_quiet(false, false));
        assert!(effective_quiet(true, false));
        assert!(effective_quiet(false, true));
        assert!(effective_quiet(true, true));
    }

    #[test]
    fn explicit_and_automatic_ai_requests_require_an_enabled_provider() {
        assert!(!should_run_ai(false, false, false));
        assert!(!should_run_ai(false, false, true));
        assert!(!should_run_ai(true, false, false));
        assert!(!should_run_ai(false, true, false));
        assert!(should_run_ai(true, false, true));
        assert!(should_run_ai(false, true, true));
        assert!(should_run_ai(true, true, true));
    }

    fn output_contract_result() -> ScanResult {
        ScanResult::new(
            "output-contract".to_string(),
            Target::parse("http://127.0.0.1:8080").expect("loopback target"),
            Utc::now(),
            Vec::new(),
            vec!["fixture".to_string()],
            Vec::new(),
        )
    }

    #[tokio::test]
    async fn report_output_selection_controls_artifact_creation() {
        let temporary = tempfile::tempdir().expect("temporary report root");
        let mut config = AppConfig::default();
        config.report.output_dir = temporary.path().join("reports");
        let result = output_contract_result();

        emit_scan_report(&result, &config, None, true).await.expect("default JSON report");
        assert!(config.report.output_dir.join("scorchkit-output-contract.json").is_file());

        std::fs::remove_dir_all(&config.report.output_dir).expect("remove default report");
        let terminal = OutputFormat::Terminal;
        emit_scan_report(&result, &config, Some(&terminal), true)
            .await
            .expect("terminal-only report");
        assert!(
            !config.report.output_dir.exists(),
            "terminal output must not create a report artifact"
        );

        let sarif = OutputFormat::Sarif;
        emit_scan_report(&result, &config, Some(&sarif), true).await.expect("SARIF report");
        assert!(config.report.output_dir.join("scorchkit-output-contract.sarif").is_file());
    }

    #[tokio::test]
    async fn ai_analysis_requires_policy_before_starting_an_available_provider() {
        let mut config = AppConfig::default();
        config.ai.enabled = true;
        config.ai.binary = Some("/bin/sh".to_string());

        let error = run_ai_analysis(
            &Arc::new(config),
            &output_contract_result(),
            crate::ai::prompts::AnalysisFocus::Summary,
            true,
            None,
        )
        .await
        .expect_err("AI analysis without an engagement must fail before provider execution");

        assert!(
            error.to_string().contains("no engagement authorization"),
            "unexpected AI policy error: {error}"
        );
    }

    #[cfg(feature = "infra")]
    #[tokio::test]
    async fn assessment_requires_a_target_and_denies_before_effects() {
        let config = Arc::new(AppConfig::default());
        let absent = run_assess(
            &config,
            AssessmentTargets { url: None, code: None, infra: None, cloud: None },
            "quick",
            true,
            None,
        )
        .await;
        assert_eq!(
            absent.expect_err("assessment without targets must fail").to_string(),
            "configuration error: assess requires at least one of --url, --code, --infra, or --cloud"
        );

        let denied = run_assess(
            &config,
            AssessmentTargets {
                url: Some("http://127.0.0.1:9"),
                code: None,
                infra: None,
                cloud: None,
            },
            "quick",
            true,
            None,
        )
        .await;
        assert!(
            denied.is_err_and(|error| error.to_string().contains("no engagement authorization")),
            "assessment must distinguish a present denied target from no target"
        );
    }

    #[cfg(all(feature = "infra", feature = "cloud"))]
    #[tokio::test]
    async fn family_cli_entry_points_deny_without_engagement() {
        let config = Arc::new(AppConfig::default());

        let infrastructure = run_infra(&config, "127.0.0.1", "quick", None, None, true, None).await;
        assert!(
            infrastructure
                .is_err_and(|error| error.to_string().contains("no engagement authorization")),
            "infrastructure CLI must fail before network effects"
        );

        let cloud = run_cloud(&config, "aws:123456789012", "quick", None, None, true, None).await;
        assert!(
            cloud.is_err_and(|error| error.to_string().contains("no engagement authorization")),
            "cloud CLI must fail before credential or process effects"
        );

        let code_path = std::env::current_dir()
            .unwrap_or_else(|error| panic!("failed to resolve test working directory: {error}"));
        let code = run_code_scan(
            &code_path,
            Some("rust".to_string()),
            None,
            None,
            "quick",
            false,
            &config,
            None,
            true,
        )
        .await;
        assert!(
            code.is_err_and(|error| error.to_string().contains("no engagement authorization")),
            "code CLI must fail before source traversal"
        );
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn cli_persistence_writes_scan_record() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = crate::storage::connect(&database_url).await.expect("database connection");
        crate::storage::migrate::run_migrations(&pool).await.expect("database migrations");
        let project_name = format!("cli-persist-{}", uuid::Uuid::new_v4());
        let project = crate::storage::projects::create_project(&pool, &project_name, "fixture")
            .await
            .expect("create project");

        let persisted = persist_scan_results(
            &Arc::new(AppConfig::default()),
            &project_name,
            Some(&database_url),
            &output_contract_result(),
            true,
        )
        .await;
        let scan_count =
            crate::storage::scans::list_scans(&pool, project.id).await.expect("list scans").len();
        crate::storage::projects::delete_project(&pool, project.id).await.expect("delete project");

        assert!(persisted.is_ok(), "CLI persistence failed: {persisted:?}");
        assert_eq!(scan_count, 1);
    }

    #[test]
    fn sast_completion_output_remains_suppressed_in_quiet_mode() {
        let production =
            include_str!("runner.rs").split("#[cfg(test)]").next().expect("production source");
        let compact: String = production.split_whitespace().collect();
        assert!(compact.contains("result.merge(code_result);if!quiet{ifcode_degraded{"));
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn finding_dispatch_propagates_handler_or_storage_errors() {
        let result = run_finding_command(
            &Arc::new(AppConfig::default()),
            crate::cli::args::FindingCommands::Show { id: "not-a-uuid".to_string() },
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn provider_refresh_request_limit_preserves_the_exact_one_mibibyte_boundary() {
        for size in [1024 * 1024, 2049] {
            let directory = tempfile::tempdir().expect("request directory");
            let request = directory.path().join("request.json");
            std::fs::write(&request, vec![b' '; size]).expect("request fixture");
            let error = run_supply_chain_command(
                &Arc::new(AppConfig::default()),
                crate::cli::args::SupplyChainCommands::CacheRefresh { request },
                None,
                true,
            )
            .await
            .expect_err("blank JSON request must fail parsing after the size check");
            assert!(
                !error.to_string().contains("exceeds the 1 MiB metadata limit"),
                "boundary request was rejected by the wrong limit: {error}"
            );
        }
    }

    #[tokio::test]
    async fn application_dast_request_limit_preserves_the_exact_one_mibibyte_boundary() {
        for size in [2, 2049, 1024 * 1024] {
            let directory = tempfile::tempdir().expect("request directory");
            let request = directory.path().join("request.json");
            std::fs::write(&request, vec![b' '; size]).expect("request fixture");
            let error = run_application_dast(&Arc::new(AppConfig::default()), &request, None, true)
                .await
                .expect_err("blank JSON must fail parsing after the size check");
            assert!(
                !error.to_string().contains("exceeds the 1 MiB input limit"),
                "boundary request was rejected by the wrong limit: {error}"
            );
        }

        let directory = tempfile::tempdir().expect("request directory");
        let request = directory.path().join("oversized.json");
        std::fs::write(&request, vec![b' '; 1024 * 1024 + 2]).expect("oversized request");
        let error = run_application_dast(&Arc::new(AppConfig::default()), &request, None, true)
            .await
            .expect_err("oversized request must fail");
        assert!(error.to_string().contains("exceeds the 1 MiB input limit"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn application_dast_request_requires_a_regular_file() {
        let directory = tempfile::tempdir().expect("request directory");
        let error =
            run_application_dast(&Arc::new(AppConfig::default()), directory.path(), None, true)
                .await
                .expect_err("a directory is not a request file");
        assert!(error.to_string().contains("request must be one regular file"));
    }
}
