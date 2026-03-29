//! MCP tool implementations.
//!
//! The business logic is in `pub` methods on `ScorchKitServer` (the main
//! `impl` block). The `#[tool_router]` block contains thin `#[tool]`
//! wrappers that delegate to the public methods. Tests call the public
//! methods directly.

use std::sync::Arc;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use uuid::Uuid;

use super::server::ScorchKitServer;
use super::types::{
    AnalyzeFindingsParams, FindingListParams, FindingRefParams, FindingUpdateStatusParams,
    ProjectCreateParams, ProjectDeleteParams, ProjectRefParams, ProjectScanParams,
    ProjectStatusParams, ScanParams, TargetAddParams, TargetRemoveParams,
};
use crate::engine::error::ScorchError;
use crate::engine::scan_context::ScanContext;
use crate::engine::target::Target;
use crate::runner::orchestrator::Orchestrator;
use crate::storage::{context, findings, metrics, projects, scans};

/// Helper to resolve a project by name or UUID.
async fn resolve_project(
    pool: &sqlx::PgPool,
    project_ref: &str,
) -> Result<crate::storage::models::Project, ScorchError> {
    if let Ok(uuid) = Uuid::parse_str(project_ref) {
        if let Some(project) = projects::get_project(pool, uuid).await? {
            return Ok(project);
        }
    }
    projects::get_project_by_name(pool, project_ref)
        .await?
        .ok_or_else(|| ScorchError::Config(format!("project '{project_ref}' not found")))
}

/// Public business logic methods — called by both `#[tool]` wrappers and tests.
impl ScorchKitServer {
    /// List all available scan modules as JSON.
    #[must_use]
    pub fn do_list_modules(&self) -> String {
        let modules = crate::runner::orchestrator::all_modules();
        let info: Vec<serde_json::Value> = modules
            .iter()
            .map(|m| {
                serde_json::json!({
                    "id": m.id(),
                    "name": m.name(),
                    "category": m.category().to_string(),
                    "description": m.description(),
                    "requires_external_tool": m.requires_external_tool(),
                    "required_tool": m.required_tool(),
                })
            })
            .collect();
        serde_json::to_string_pretty(&info).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    /// Check which external tools are installed as JSON.
    #[must_use]
    pub fn do_check_tools(&self) -> String {
        let tools = [
            "nmap",
            "nikto",
            "nuclei",
            "zap.sh",
            "wpscan",
            "droopescan",
            "sqlmap",
            "dalfox",
            "feroxbuster",
            "ffuf",
            "arjun",
            "cewl",
            "sslyze",
            "testssl.sh",
            "amass",
            "subfinder",
            "httpx",
            "theHarvester",
            "wafw00f",
            "hydra",
            "msfconsole",
        ];
        let results: Vec<serde_json::Value> = tools
            .iter()
            .map(|&t| {
                let available = std::process::Command::new("which")
                    .arg(t)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                serde_json::json!({ "tool": t, "installed": available })
            })
            .collect();
        serde_json::to_string_pretty(&results).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    /// Run a scan against a target URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the target URL is invalid, the HTTP client cannot
    /// be built, or the scan fails.
    pub async fn do_scan(&self, params: ScanParams) -> Result<String, String> {
        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        let http_client = build_scan_client(&self.config).map_err(|e| e.to_string())?;
        let ctx = ScanContext::new(target, Arc::clone(&self.config), http_client);

        let module_filter: Option<Vec<String>> =
            params.modules.map(|m| m.split(',').map(|s| s.trim().to_string()).collect());
        let skip_filter: Option<Vec<String>> =
            params.skip.map(|s| s.split(',').map(|s| s.trim().to_string()).collect());

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile(&params.profile);

        if let Some(ref include) = module_filter {
            orchestrator.filter_by_ids(include);
        }
        if let Some(ref exclude) = skip_filter {
            orchestrator.exclude_by_ids(exclude);
        }

        let result = orchestrator.run(true).await.map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
    }

    /// Create a new project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project name already exists or the database fails.
    pub async fn do_project_create(&self, params: ProjectCreateParams) -> Result<String, String> {
        let desc = params.description.as_deref().unwrap_or("");
        let project = projects::create_project(&self.pool, &params.name, desc)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&project).map_err(|e| e.to_string())
    }

    /// List all projects.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn do_project_list(&self) -> Result<String, String> {
        let project_list = projects::list_projects(&self.pool).await.map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&project_list).map_err(|e| e.to_string())
    }

    /// Show project details.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_project_show(&self, params: ProjectRefParams) -> Result<String, String> {
        let project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;
        let targets =
            projects::list_targets(&self.pool, project.id).await.map_err(|e| e.to_string())?;
        let scan_list =
            scans::list_scans(&self.pool, project.id).await.map_err(|e| e.to_string())?;
        let finding_list =
            findings::list_findings(&self.pool, project.id).await.map_err(|e| e.to_string())?;

        let result = serde_json::json!({
            "project": project,
            "targets": targets,
            "scan_count": scan_list.len(),
            "finding_count": finding_list.len(),
            "recent_scans": scan_list.iter().take(5).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
    }

    /// Delete a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_project_delete(&self, params: ProjectDeleteParams) -> Result<String, String> {
        let project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;

        if !params.force {
            return Ok(format!(
                "{{\"warning\": \"This will delete project '{}' and ALL associated data. \
                 Set force=true to confirm.\"}}",
                project.name
            ));
        }

        projects::delete_project(&self.pool, project.id).await.map_err(|e| e.to_string())?;
        Ok(format!("{{\"deleted\": true, \"project\": \"{}\"}}", project.name))
    }

    /// Scan within a project, persisting results.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found, the scan fails, or persistence fails.
    pub async fn do_project_scan(&self, params: ProjectScanParams) -> Result<String, String> {
        let project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;
        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        let http_client = build_scan_client(&self.config).map_err(|e| e.to_string())?;
        let ctx = ScanContext::new(target, Arc::clone(&self.config), http_client);

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile(&params.profile);

        let result = orchestrator.run(true).await.map_err(|e| e.to_string())?;

        let modules_run = result.modules_run.clone();
        let modules_skipped: Vec<String> =
            result.modules_skipped.iter().map(|(id, _)| id.clone()).collect();
        let summary_json = serde_json::to_value(&result.summary).map_err(|e| e.to_string())?;

        let scan = scans::save_scan(
            &self.pool,
            project.id,
            result.target.url.as_str(),
            &params.profile,
            result.started_at,
            Some(result.completed_at),
            &modules_run,
            &modules_skipped,
            &summary_json,
        )
        .await
        .map_err(|e| e.to_string())?;

        let new_count = findings::save_findings(&self.pool, project.id, scan.id, &result.findings)
            .await
            .map_err(|e| e.to_string())?;

        let output = serde_json::json!({
            "scan_id": scan.id,
            "project": project.name,
            "target": result.target.url.as_str(),
            "findings_total": result.findings.len(),
            "findings_new": new_count,
            "findings_updated": result.findings.len() - new_count,
            "summary": result.summary,
        });
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }

    /// List findings for a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_project_findings(&self, params: FindingListParams) -> Result<String, String> {
        let project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;

        let finding_list = match (params.severity.as_deref(), params.status.as_deref()) {
            (Some(sev), _) => findings::find_by_severity(&self.pool, project.id, sev)
                .await
                .map_err(|e| e.to_string())?,
            (_, Some(st)) => {
                let vuln_status =
                    crate::storage::models::VulnStatus::from_db(st).ok_or_else(|| {
                        format!(
                            "invalid status '{st}'. \
                             Valid: new, acknowledged, false_positive, remediated, verified"
                        )
                    })?;
                findings::find_by_status(&self.pool, project.id, vuln_status)
                    .await
                    .map_err(|e| e.to_string())?
            }
            _ => {
                findings::list_findings(&self.pool, project.id).await.map_err(|e| e.to_string())?
            }
        };

        serde_json::to_string_pretty(&finding_list).map_err(|e| e.to_string())
    }

    /// Show a single finding.
    ///
    /// # Errors
    ///
    /// Returns an error if the UUID is invalid or the finding is not found.
    pub async fn do_finding_show(&self, params: FindingRefParams) -> Result<String, String> {
        let id = Uuid::parse_str(&params.id)
            .map_err(|e| format!("invalid finding UUID '{}': {e}", params.id))?;
        let finding = findings::get_finding(&self.pool, id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("finding '{}' not found", params.id))?;
        serde_json::to_string_pretty(&finding).map_err(|e| e.to_string())
    }

    /// Update a finding's lifecycle status.
    ///
    /// # Errors
    ///
    /// Returns an error if the UUID is invalid, the status is invalid, or
    /// the finding is not found.
    pub async fn do_finding_update_status(
        &self,
        params: FindingUpdateStatusParams,
    ) -> Result<String, String> {
        let id = Uuid::parse_str(&params.id)
            .map_err(|e| format!("invalid finding UUID '{}': {e}", params.id))?;
        let status =
            crate::storage::models::VulnStatus::from_db(&params.status).ok_or_else(|| {
                format!(
                    "invalid status '{}'. \
                     Valid: new, acknowledged, false_positive, remediated, verified",
                    params.status
                )
            })?;

        let updated = findings::update_finding_status(&self.pool, id, status)
            .await
            .map_err(|e| e.to_string())?;

        if updated {
            Ok(format!(
                "{{\"updated\": true, \"id\": \"{id}\", \"status\": \"{}\"}}",
                params.status
            ))
        } else {
            Err(format!("finding '{id}' not found"))
        }
    }

    /// Add a target to a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_target_add(&self, params: TargetAddParams) -> Result<String, String> {
        let project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;
        let label = params.label.as_deref().unwrap_or("");
        let target = projects::add_target(&self.pool, project.id, &params.url, label)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&target).map_err(|e| e.to_string())
    }

    /// List targets for a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_target_list(&self, params: ProjectRefParams) -> Result<String, String> {
        let project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;
        let targets =
            projects::list_targets(&self.pool, project.id).await.map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&targets).map_err(|e| e.to_string())
    }

    /// Remove a target from a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project/target is not found or the database fails.
    pub async fn do_target_remove(&self, params: TargetRemoveParams) -> Result<String, String> {
        let _project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;
        let target_id = Uuid::parse_str(&params.id)
            .map_err(|e| format!("invalid target UUID '{}': {e}", params.id))?;
        let removed =
            projects::remove_target(&self.pool, target_id).await.map_err(|e| e.to_string())?;
        if removed {
            Ok(format!("{{\"removed\": true, \"id\": \"{target_id}\"}}"))
        } else {
            Err(format!("target '{}' not found", params.id))
        }
    }

    /// Run database migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if migration execution fails.
    pub async fn do_db_migrate(&self) -> Result<String, String> {
        crate::storage::migrate::run_migrations(&self.pool).await.map_err(|e| e.to_string())?;
        Ok("{\"success\": true, \"message\": \"Database migrations complete\"}".to_string())
    }

    /// Get security posture metrics and trend analysis for a project.
    ///
    /// Returns aggregate metrics including severity/status breakdowns,
    /// regression detection, trend direction, and top unresolved findings.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_project_status(&self, params: ProjectStatusParams) -> Result<String, String> {
        let project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;
        let posture = metrics::build_posture_metrics(&self.pool, project.id, &project.name)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&posture).map_err(|e| e.to_string())
    }

    /// Analyze findings for a project using AI with structured output.
    ///
    /// Loads findings from the database, builds project context for trend
    /// awareness, runs Claude analysis, and returns structured JSON results.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found, the AI analyst is
    /// unavailable, or the analysis subprocess fails.
    pub async fn do_analyze_findings(
        &self,
        params: AnalyzeFindingsParams,
    ) -> Result<String, String> {
        let project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;

        let focus = crate::ai::prompts::AnalysisFocus::parse(&params.focus);

        // Load findings: from specific scan or all project findings
        let tracked_findings = if let Some(ref scan_id_str) = params.scan_id {
            let scan_id = Uuid::parse_str(scan_id_str)
                .map_err(|e| format!("invalid scan UUID '{scan_id_str}': {e}"))?;
            findings::find_by_scan(&self.pool, scan_id).await.map_err(|e| e.to_string())?
        } else {
            findings::list_findings(&self.pool, project.id).await.map_err(|e| e.to_string())?
        };

        if tracked_findings.is_empty() {
            return Ok("{\"analysis\": {\"type\": \"raw\", \"content\": \
                       \"No findings to analyze.\"}, \"cost_usd\": null}"
                .to_string());
        }

        // Convert tracked findings back to engine Findings via raw_finding JSON
        let engine_findings: Vec<crate::engine::finding::Finding> = tracked_findings
            .iter()
            .filter_map(|tf| serde_json::from_value(tf.raw_finding.clone()).ok())
            .collect();

        // Build a minimal ScanResult for the analyzer
        let scan_records =
            scans::list_scans(&self.pool, project.id).await.map_err(|e| e.to_string())?;
        let target_url = scan_records.first().map(|s| s.target_url.as_str()).unwrap_or("unknown");
        let target = crate::engine::target::Target::parse(target_url).map_err(|e| e.to_string())?;
        let scan_result = crate::engine::scan_result::ScanResult::new(
            Uuid::new_v4().to_string(),
            target,
            chrono::Utc::now(),
            engine_findings,
            Vec::new(),
            Vec::new(),
        );

        // Build project context for trend-aware analysis
        let project_context = context::build_project_context(&self.pool, project.id, &project.name)
            .await
            .map_err(|e| e.to_string())?;

        // Run AI analysis
        if !self.config.ai.enabled {
            return Err("AI analysis is disabled in config".to_string());
        }

        let analyst = crate::ai::analyst::AiAnalyst::from_config(&self.config.ai);
        if !analyst.is_available() {
            return Err(
                "claude CLI not found. Install Claude Code to enable AI analysis.".to_string()
            );
        }

        let analysis = analyst
            .analyze(&scan_result, focus, Some(&project_context))
            .await
            .map_err(|e| e.to_string())?;

        let output = serde_json::json!({
            "project": project.name,
            "focus": analysis.focus.label(),
            "analysis": analysis.analysis,
            "cost_usd": analysis.cost_usd,
            "model": analysis.model,
        });

        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }
}

/// `#[tool_router]` — thin wrappers that delegate to `do_*` public methods.
#[tool_router(vis = "pub(crate)")]
impl ScorchKitServer {
    #[tool(description = "List all available scan modules")]
    async fn list_modules(&self) -> String {
        self.do_list_modules()
    }

    #[tool(description = "Check which external security tools are installed")]
    async fn check_tools(&self) -> String {
        self.do_check_tools()
    }

    #[tool(description = "Run a security scan against a target URL")]
    async fn scan(&self, params: Parameters<ScanParams>) -> Result<String, String> {
        self.do_scan(params.0).await
    }

    #[tool(description = "Create a new security assessment project")]
    async fn project_create(
        &self,
        params: Parameters<ProjectCreateParams>,
    ) -> Result<String, String> {
        self.do_project_create(params.0).await
    }

    #[tool(description = "List all security assessment projects")]
    async fn project_list(&self) -> Result<String, String> {
        self.do_project_list().await
    }

    #[tool(description = "Show project details including targets, scans, and findings")]
    async fn project_show(&self, params: Parameters<ProjectRefParams>) -> Result<String, String> {
        self.do_project_show(params.0).await
    }

    #[tool(description = "Delete a project and all associated data (requires force=true)")]
    async fn project_delete(
        &self,
        params: Parameters<ProjectDeleteParams>,
    ) -> Result<String, String> {
        self.do_project_delete(params.0).await
    }

    #[tool(description = "Run a scan within a project, persisting results to the database")]
    async fn project_scan(&self, params: Parameters<ProjectScanParams>) -> Result<String, String> {
        self.do_project_scan(params.0).await
    }

    #[tool(description = "List vulnerability findings for a project")]
    async fn project_findings(
        &self,
        params: Parameters<FindingListParams>,
    ) -> Result<String, String> {
        self.do_project_findings(params.0).await
    }

    #[tool(description = "Show details for a single vulnerability finding")]
    async fn finding_show(&self, params: Parameters<FindingRefParams>) -> Result<String, String> {
        self.do_finding_show(params.0).await
    }

    #[tool(
        description = "Update the lifecycle status of a finding (new/acknowledged/false_positive/remediated/verified)"
    )]
    async fn finding_update_status(
        &self,
        params: Parameters<FindingUpdateStatusParams>,
    ) -> Result<String, String> {
        self.do_finding_update_status(params.0).await
    }

    #[tool(description = "Add a target URL to a project")]
    async fn target_add(&self, params: Parameters<TargetAddParams>) -> Result<String, String> {
        self.do_target_add(params.0).await
    }

    #[tool(description = "List all targets for a project")]
    async fn target_list(&self, params: Parameters<ProjectRefParams>) -> Result<String, String> {
        self.do_target_list(params.0).await
    }

    #[tool(description = "Remove a target from a project")]
    async fn target_remove(
        &self,
        params: Parameters<TargetRemoveParams>,
    ) -> Result<String, String> {
        self.do_target_remove(params.0).await
    }

    #[tool(description = "Run pending database migrations")]
    async fn db_migrate(&self) -> Result<String, String> {
        self.do_db_migrate().await
    }

    #[tool(
        description = "Get security posture metrics, trend analysis, regressions, and top unresolved findings for a project"
    )]
    async fn project_status(
        &self,
        params: Parameters<ProjectStatusParams>,
    ) -> Result<String, String> {
        self.do_project_status(params.0).await
    }

    #[tool(
        description = "Analyze project findings using AI with structured JSON output (summary/prioritize/remediate/filter)"
    )]
    async fn analyze_findings(
        &self,
        params: Parameters<AnalyzeFindingsParams>,
    ) -> Result<String, String> {
        self.do_analyze_findings(params.0).await
    }
}

/// Build an HTTP client for scan operations, applying proxy from config.
fn build_scan_client(config: &crate::config::AppConfig) -> Result<reqwest::Client, ScorchError> {
    let mut builder = reqwest::Client::builder()
        .user_agent(&config.scan.user_agent)
        .timeout(std::time::Duration::from_secs(config.scan.timeout_seconds))
        .cookie_store(true)
        .danger_accept_invalid_certs(false);

    if config.scan.follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::limited(config.scan.max_redirects));
    } else {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    if let Some(ref proxy_url) = config.scan.proxy {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| ScorchError::Config(format!("invalid proxy URL '{proxy_url}': {e}")))?;
        builder = builder.proxy(proxy);
    }

    builder.build().map_err(|e| ScorchError::Config(format!("failed to build HTTP client: {e}")))
}
