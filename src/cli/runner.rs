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
pub async fn execute(cli: Cli) -> Result<()> {
    let config = AppConfig::load(cli.config.as_deref())?;
    let config = Arc::new(config);

    match cli.command {
        Commands::Run {
            target,
            modules,
            skip,
            analyze,
            profile,
            proxy,
            scope,
            exclude,
            project,
            database_url,
        } => {
            // Apply CLI overrides to config
            let config = {
                let mut c = (*config).clone();
                if let Some(ref p) = proxy {
                    c.scan.proxy = Some(p.clone());
                }
                if let Some(ref s) = scope {
                    c.scan.scope_include = vec![s.clone()];
                }
                if let Some(ref e) = exclude {
                    c.scan.scope_exclude = vec![e.clone()];
                }
                Arc::new(c)
            };
            run_scan(
                &config,
                &target,
                modules,
                skip,
                None,
                cli.output,
                cli.quiet,
                analyze,
                &profile,
                project.as_deref(),
                database_url.as_deref(),
            )
            .await
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
                "standard",
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
                "standard",
                None,
                None,
            )
            .await
        }

        Commands::Analyze { report, focus, project, database_url } => {
            run_analyze(&config, &report, &focus, project.as_deref(), database_url.as_deref()).await
        }

        Commands::Diff { baseline, current } => run_diff(&baseline, &current),

        Commands::Modules { check_tools } => list_modules(check_tools),

        Commands::Init => init_config(),

        Commands::Doctor => run_doctor(),

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

        #[cfg(feature = "mcp")]
        Commands::Serve => crate::cli::serve::run_serve(&config).await,
    }
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
        args::ProjectCommands::Target { command: target_cmd } => {
            run_target_command(&pool, target_cmd).await
        }
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
        args::FindingCommands::Status { id, status } => {
            crate::cli::finding::update_status(&pool, &id, &status).await
        }
    }
}

// JUSTIFICATION: run_scan maps directly to CLI flag combinations; bundling into a struct
// would add indirection for an internal dispatch function with no external callers.
#[allow(clippy::too_many_arguments)]
async fn run_scan(
    config: &Arc<AppConfig>,
    target_str: &str,
    modules: Option<String>,
    skip: Option<String>,
    category_filter: Option<ModuleCategory>,
    output_format: Option<OutputFormat>,
    quiet: bool,
    analyze: bool,
    profile: &str,
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

    let http_client = build_http_client(config)?;
    let ctx = ScanContext::new(target, Arc::clone(config), http_client);

    let module_filter: Option<Vec<String>> =
        modules.map(|m| m.split(',').map(|s| s.trim().to_string()).collect());
    let skip_filter: Option<Vec<String>> =
        skip.map(|s| s.split(',').map(|s| s.trim().to_string()).collect());

    let mut orchestrator = Orchestrator::new(ctx);
    orchestrator.register_default_modules();
    orchestrator.apply_profile(profile);

    if let Some(category) = category_filter {
        orchestrator.filter_by_category(category);
    }
    if let Some(ref include) = module_filter {
        orchestrator.filter_by_ids(include);
    }
    if let Some(ref exclude) = skip_filter {
        orchestrator.exclude_by_ids(exclude);
    }

    let result = orchestrator.run(quiet).await?;

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

fn run_doctor() -> Result<()> {
    println!();
    println!("{}", "ScorchKit Doctor".bold().underline());
    println!();

    let tools: &[(&str, &str, &str)] = &[
        // (binary, display name, category)
        ("nmap", "Nmap", "Network"),
        ("nikto", "Nikto", "Web Scanner"),
        ("nuclei", "Nuclei", "Web Scanner"),
        ("zap.sh", "OWASP ZAP", "Web Scanner"),
        ("wpscan", "WPScan", "CMS Scanner"),
        ("droopescan", "Droopescan", "CMS Scanner"),
        ("sqlmap", "SQLMap", "Injection"),
        ("dalfox", "Dalfox", "XSS"),
        ("feroxbuster", "Feroxbuster", "Discovery"),
        ("ffuf", "ffuf", "Fuzzer"),
        ("arjun", "Arjun", "Param Discovery"),
        ("cewl", "CeWL", "Wordlist"),
        ("sslyze", "SSLyze", "TLS/SSL"),
        ("testssl.sh", "testssl.sh", "TLS/SSL"),
        ("amass", "Amass", "Subdomain"),
        ("subfinder", "Subfinder", "Subdomain"),
        ("httpx", "httpx", "HTTP Probe"),
        ("theHarvester", "theHarvester", "OSINT"),
        ("wafw00f", "wafw00f", "WAF Detection"),
        ("hydra", "Hydra", "Credentials"),
        ("msfconsole", "Metasploit", "Exploit"),
        ("claude", "Claude Code", "AI Analysis"),
    ];

    let mut installed = 0;
    let mut missing = 0;

    for &(binary, name, category) in tools {
        let available = is_tool_available(binary);
        if available {
            installed += 1;
            println!(
                "  {} {:<20} {:<16} {}",
                "OK".green().bold(),
                name,
                category.dimmed(),
                which_path(binary).dimmed()
            );
        } else {
            missing += 1;
            println!("  {} {:<20} {}", "--".red(), name, category.dimmed());
        }
    }

    println!();
    println!("  {}/{} tools installed", installed.to_string().green().bold(), installed + missing);

    if missing > 0 {
        println!("  See {} for install instructions", "docs/tools-checklist.md".cyan());
    }

    println!();
    Ok(())
}

fn which_path(tool: &str) -> String {
    std::process::Command::new("which")
        .arg(tool)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
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

fn list_modules(check_tools: bool) -> Result<()> {
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

    Ok(())
}

fn init_config() -> Result<()> {
    let path = std::path::Path::new("config.toml");
    if path.exists() {
        println!("{} config.toml already exists", "warning:".yellow().bold());
        return Ok(());
    }
    let content = AppConfig::default_toml()?;
    std::fs::write(path, content)?;
    println!("{} config.toml created", "success:".green().bold());
    Ok(())
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
        .danger_accept_invalid_certs(false);

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
    std::process::Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
