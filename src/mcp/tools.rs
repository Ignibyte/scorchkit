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

use super::contract::{McpCallContext, McpToolCallResult};
use super::server::ScorchKitServer;
use super::types::{
    AnalyzeFindingsParams, AutoScanParams, CorrelateFindingsParams, FindingListParams,
    FindingRefParams, FindingUpdateStatusParams, PlanScanParams, ProjectCreateParams,
    ProjectDeleteParams, ProjectRefParams, ProjectScanParams, ProjectStatusParams,
    ScanJobRefParams, ScanParams, ScanProgressParams, ScheduleScanParams, TargetAddParams,
    TargetIntelligenceParams, TargetRemoveParams,
};
use crate::engine::error::ScorchError;
use crate::engine::policy::{Capability, EffectClass, PolicyTarget};
use crate::engine::target::Target;
use crate::facade::Engine;
use crate::runner::job::{DastJobRequest, ScanJob, ScanJobState};
use crate::runner::orchestrator::Orchestrator;
use crate::storage::{context, findings, metrics, projects, scans, schedules};

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

fn comma_separated(value: &str) -> Vec<String> {
    value.split(',').map(str::trim).filter(|item| !item.is_empty()).map(str::to_string).collect()
}

fn job_id(value: &str) -> Result<Uuid, String> {
    Uuid::parse_str(value).map_err(|error| format!("invalid scan job UUID '{value}': {error}"))
}

fn completed_job_result(job: ScanJob) -> Result<String, String> {
    match job.state {
        ScanJobState::Succeeded => serde_json::to_string_pretty(
            job.result.as_ref().ok_or_else(|| "successful scan job has no result".to_string())?,
        )
        .map_err(|error| error.to_string()),
        _ => Err(job.error.unwrap_or_else(|| format!("scan job ended in {}", job.state.as_str()))),
    }
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
                let available = crate::runner::subprocess::is_tool_available(t);
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
        let job = self.submit_scan_job(params).await?;
        completed_job_result(self.jobs.run(job.id).await.map_err(|error| error.to_string())?)
    }

    /// Submit a stateless DAST job and return before scanner modules complete.
    ///
    /// # Errors
    ///
    /// Returns an error when authorization, request validation, or initial persistence fails.
    pub async fn do_scan_job_start(&self, params: ScanParams) -> Result<String, String> {
        let job = self.submit_scan_job(params).await?;
        let response = serde_json::to_string_pretty(&job).map_err(|error| error.to_string())?;
        let jobs = self.jobs.clone();
        tokio::spawn(async move {
            if let Err(error) = jobs.run(job.id).await {
                tracing::warn!(job_id = %job.id, %error, "scan job runner stopped");
            }
        });
        Ok(response)
    }

    /// Return the complete persisted state of one scan job.
    ///
    /// # Errors
    ///
    /// Returns an error when the UUID is invalid or the job does not exist.
    pub async fn do_scan_job_status(&self, params: ScanJobRefParams) -> Result<String, String> {
        let job =
            self.jobs.get(job_id(&params.job_id)?).await.map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&job).map_err(|error| error.to_string())
    }

    /// Persist and signal cancellation for a queued or running job.
    ///
    /// # Errors
    ///
    /// Returns an error when the UUID is invalid, missing, or no longer cancellable.
    pub async fn do_scan_job_cancel(&self, params: ScanJobRefParams) -> Result<String, String> {
        let job =
            self.jobs.cancel(job_id(&params.job_id)?).await.map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&job).map_err(|error| error.to_string())
    }

    /// Create and start a successor attempt for an interrupted job.
    ///
    /// # Errors
    ///
    /// Returns an error when the job is not interrupted or current authorization differs.
    pub async fn do_scan_job_resume(&self, params: ScanJobRefParams) -> Result<String, String> {
        let job =
            self.jobs.resume(job_id(&params.job_id)?).await.map_err(|error| error.to_string())?;
        let response = serde_json::to_string_pretty(&job).map_err(|error| error.to_string())?;
        let jobs = self.jobs.clone();
        tokio::spawn(async move {
            if let Err(error) = jobs.run(job.id).await {
                tracing::warn!(job_id = %job.id, %error, "resumed scan job runner stopped");
            }
        });
        Ok(response)
    }

    async fn submit_scan_job(&self, params: ScanParams) -> Result<ScanJob, String> {
        let engagement = self
            .config
            .engagement
            .clone()
            .ok_or_else(|| "no engagement authorization configured for scan job".to_string())?;
        let request = DastJobRequest::new(params.target, params.profile, engagement)
            .with_modules(params.modules.as_deref().map(comma_separated))
            .with_skip(params.skip.as_deref().map_or_else(Vec::new, comma_separated));
        self.jobs.submit(request).await.map_err(|error| error.to_string())
    }

    /// Create a new project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project name already exists or the database fails.
    pub async fn do_project_create(&self, params: ProjectCreateParams) -> Result<String, String> {
        let desc = params.description.as_deref().unwrap_or("");
        let project = projects::create_project(self.require_pool()?, &params.name, desc)
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
        let project_list =
            projects::list_projects(self.require_pool()?).await.map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&project_list).map_err(|e| e.to_string())
    }

    /// Show project details.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_project_show(&self, params: ProjectRefParams) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let targets = projects::list_targets(self.require_pool()?, project.id)
            .await
            .map_err(|e| e.to_string())?;
        let scan_list =
            scans::list_scans(self.require_pool()?, project.id).await.map_err(|e| e.to_string())?;
        let finding_list = findings::list_findings(self.require_pool()?, project.id)
            .await
            .map_err(|e| e.to_string())?;

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
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;

        if !params.force {
            return Ok(format!(
                "{{\"warning\": \"This will delete project '{}' and ALL associated data. \
                 Set force=true to confirm.\"}}",
                project.name
            ));
        }

        projects::delete_project(self.require_pool()?, project.id)
            .await
            .map_err(|e| e.to_string())?;
        Ok(format!("{{\"deleted\": true, \"project\": \"{}\"}}", project.name))
    }

    /// Scan within a project, persisting results.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found, the scan fails, or persistence fails.
    pub async fn do_project_scan(&self, params: ProjectScanParams) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        require_registered_project_target(self.require_pool()?, project.id, &target)
            .await
            .map_err(|e| e.to_string())?;
        let engine = Engine::new(Arc::clone(&self.config));
        let ctx =
            engine.dast_context_for_target(target, &params.profile).map_err(|e| e.to_string())?;

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile(&params.profile);
        if let Some(modules) = params.modules.as_deref() {
            orchestrator.filter_by_ids(&comma_separated(modules));
        }
        if let Some(skip) = params.skip.as_deref() {
            orchestrator.exclude_by_ids(&comma_separated(skip));
        }

        let result = orchestrator.run(true).await.map_err(|e| e.to_string())?;

        let modules_run = result.modules_run.clone();
        let modules_skipped: Vec<String> =
            result.modules_skipped.iter().map(|(id, _)| id.clone()).collect();
        let summary_json = serde_json::to_value(&result.summary).map_err(|e| e.to_string())?;

        let scan = scans::save_scan(
            self.require_pool()?,
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

        let new_count =
            findings::save_findings(self.require_pool()?, project.id, scan.id, &result.findings)
                .await
                .map_err(|e| e.to_string())?;

        let output = serde_json::json!({
            "scan_id": scan.id,
            "project": project.name,
            "target": result.target.url.as_str(),
            "modules_run": modules_run,
            "modules_skipped": modules_skipped,
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
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;

        let finding_list = match (params.severity.as_deref(), params.status.as_deref()) {
            (Some(sev), _) => findings::find_by_severity(self.require_pool()?, project.id, sev)
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
                findings::find_by_status(self.require_pool()?, project.id, vuln_status)
                    .await
                    .map_err(|e| e.to_string())?
            }
            _ => findings::list_findings(self.require_pool()?, project.id)
                .await
                .map_err(|e| e.to_string())?,
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
        let finding = findings::get_finding(self.require_pool()?, id)
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

        let updated = findings::update_finding_status(self.require_pool()?, id, status, None)
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
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let label = params.label.as_deref().unwrap_or("");
        let target = projects::add_target(self.require_pool()?, project.id, &params.url, label)
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
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let targets = projects::list_targets(self.require_pool()?, project.id)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&targets).map_err(|e| e.to_string())
    }

    /// Remove a target from a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project/target is not found or the database fails.
    pub async fn do_target_remove(&self, params: TargetRemoveParams) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let target_id = Uuid::parse_str(&params.id)
            .map_err(|e| format!("invalid target UUID '{}': {e}", params.id))?;
        let removed = projects::remove_target(self.require_pool()?, project.id, target_id)
            .await
            .map_err(|e| e.to_string())?;
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
        crate::storage::migrate::run_migrations(self.require_pool()?)
            .await
            .map_err(|e| e.to_string())?;
        Ok("{\"success\": true, \"message\": \"Database migrations complete\"}".to_string())
    }

    /// Create a recurring scan schedule for a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found, the cron expression
    /// is invalid, or the database fails.
    pub async fn do_schedule_scan(&self, params: ScheduleScanParams) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        require_registered_project_target(self.require_pool()?, project.id, &target)
            .await
            .map_err(|e| e.to_string())?;
        let engine = Engine::new(Arc::clone(&self.config));
        engine
            .authorize_web_scan_for_profile(&target.url, &params.profile)
            .map_err(|e| e.to_string())?;
        let schedule = schedules::create_schedule(
            self.require_pool()?,
            project.id,
            target.url.as_str(),
            &params.profile,
            &params.cron,
            engine.engagement().ok_or_else(|| {
                "schedule creation denied: no engagement authorization is configured".to_string()
            })?,
        )
        .await
        .map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&schedule).map_err(|e| e.to_string())
    }

    /// Find and execute all due scan schedules.
    ///
    /// Returns a summary of executed scans and their results.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails. Individual scan
    /// failures are captured in the results, not propagated.
    pub async fn do_run_due_scans(&self) -> Result<String, String> {
        let outcomes =
            crate::cli::schedule::execute_due_schedules(self.require_pool()?, &self.config)
                .await
                .map_err(|e| e.to_string())?;

        if outcomes.is_empty() {
            return Ok("{\"executed\": 0, \"message\": \"No schedules are due\"}".to_string());
        }

        let executed = outcomes.len();
        let output = serde_json::json!({
            "executed": executed,
            "results": outcomes,
        });
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
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
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let posture =
            metrics::build_posture_metrics(self.require_pool()?, project.id, &project.name)
                .await
                .map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&posture).map_err(|e| e.to_string())
    }

    /// Run AI-guided scan planning: recon first, then the configured provider decides modules.
    ///
    /// Returns a structured [`crate::ai::types::ScanPlan`] as JSON without executing the scan.
    /// The MCP client can inspect and approve the plan before calling `scan`
    /// or `project-scan` to execute.
    ///
    /// # Errors
    ///
    /// Returns an error if the target URL is invalid, AI is disabled, or
    /// the configured provider is unavailable.
    pub async fn do_plan_scan(&self, params: PlanScanParams) -> Result<String, String> {
        if !self.config.ai.enabled {
            return Err("AI is disabled in config — scan planning requires AI".to_string());
        }

        let planner = crate::ai::planner::ScanPlanner::from_config(&self.config.ai);
        if !planner.is_available() {
            return Err(format!(
                "{} not found. Install or configure the selected AI provider.",
                planner.provider_name()
            ));
        }

        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        let engine = Engine::new(Arc::clone(&self.config));
        engine.dast_context_for_target(target.clone(), "quick").map_err(|e| e.to_string())?;
        engine
            .require_authorized(
                PolicyTarget::Web(target.url.clone()),
                Capability::ExternalTool,
                EffectClass::ActiveSafe,
            )
            .map_err(|e| e.to_string())?;
        let plan = planner.plan(&target, &engine).await.map_err(|e| e.to_string())?;

        serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())
    }

    /// Analyze findings for a project using AI with structured output.
    ///
    /// Loads findings from the database, builds project context for trend
    /// awareness, runs provider-neutral AI analysis, and returns structured JSON results.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found, the AI analyst is
    /// unavailable, or the analysis subprocess fails.
    pub async fn do_analyze_findings(
        &self,
        params: AnalyzeFindingsParams,
    ) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;

        let focus = crate::ai::prompts::AnalysisFocus::parse(&params.focus);

        // Load findings: from specific scan or all project findings
        let tracked_findings = if let Some(ref scan_id_str) = params.scan_id {
            let scan_id = Uuid::parse_str(scan_id_str)
                .map_err(|e| format!("invalid scan UUID '{scan_id_str}': {e}"))?;
            findings::find_by_scan(self.require_pool()?, scan_id)
                .await
                .map_err(|e| e.to_string())?
        } else {
            findings::list_findings(self.require_pool()?, project.id)
                .await
                .map_err(|e| e.to_string())?
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
            scans::list_scans(self.require_pool()?, project.id).await.map_err(|e| e.to_string())?;
        let target_url = scan_records.first().map_or("unknown", |s| s.target_url.as_str());
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
        let project_context =
            context::build_project_context(self.require_pool()?, project.id, &project.name)
                .await
                .map_err(|e| e.to_string())?;

        // Run AI analysis
        if !self.config.ai.enabled {
            return Err("AI analysis is disabled in config".to_string());
        }

        let analyst = crate::ai::analyst::AiAnalyst::from_config(&self.config.ai);
        if !analyst.is_available() {
            return Err(format!(
                "{} not found. Install or configure the selected AI provider.",
                analyst.provider_name()
            ));
        }

        Engine::new(Arc::clone(&self.config))
            .require_authorized(
                PolicyTarget::Web(scan_result.target.url.clone()),
                Capability::ExternalTool,
                EffectClass::Passive,
            )
            .map_err(|e| e.to_string())?;

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

    /// Run a full scan engagement in one call: parse target, build orchestrator,
    /// run scan with the specified profile, and optionally persist results to
    /// a project.
    ///
    /// This is the "one-shot" scanning tool — an MCP agent can call this instead of
    /// manually composing `scan` + `project_scan`. Does NOT include AI
    /// planning or analysis (use `plan_scan` and `analyze_findings` separately).
    ///
    /// # Errors
    ///
    /// Returns an error if the target URL is invalid, the HTTP client cannot
    /// be built, the scan fails, or project persistence fails.
    pub async fn do_auto_scan(&self, params: AutoScanParams) -> Result<String, String> {
        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        let project = if let Some(project_ref) = params.project.as_deref() {
            let project = resolve_project(self.require_pool()?, project_ref)
                .await
                .map_err(|e| e.to_string())?;
            require_registered_project_target(self.require_pool()?, project.id, &target)
                .await
                .map_err(|e| e.to_string())?;
            Some(project)
        } else {
            None
        };
        let engine = Engine::new(Arc::clone(&self.config));
        let ctx =
            engine.dast_context_for_target(target, &params.profile).map_err(|e| e.to_string())?;

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile(&params.profile);

        let result = orchestrator.run(true).await.map_err(|e| e.to_string())?;

        // Optionally persist to project
        if let Some(project) = project {
            let modules_run: Vec<String> = result.modules_run.iter().map(String::clone).collect();
            let modules_skipped: Vec<String> = result
                .modules_skipped
                .iter()
                .map(|(id, reason)| format!("{id}: {reason}"))
                .collect();
            let summary_json = serde_json::to_value(&result.summary).map_err(|e| e.to_string())?;

            let scan_record = scans::save_scan(
                self.require_pool()?,
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
            let saved_count = findings::save_findings(
                self.require_pool()?,
                project.id,
                scan_record.id,
                &result.findings,
            )
            .await
            .map_err(|e| e.to_string())?;

            let output = serde_json::json!({
                "scan_id": result.scan_id,
                "target": result.target.raw,
                "profile": params.profile,
                "project": project.name,
                "persisted": true,
                "findings_saved": saved_count,
                "summary": {
                    "total": result.summary.total_findings,
                    "critical": result.summary.critical,
                    "high": result.summary.high,
                    "medium": result.summary.medium,
                    "low": result.summary.low,
                    "info": result.summary.info,
                },
                "modules_run": result.modules_run.len(),
                "duration_seconds": (result.completed_at - result.started_at).num_seconds(),
            });
            return serde_json::to_string_pretty(&output).map_err(|e| e.to_string());
        }

        // No project — return full scan result
        let output = serde_json::json!({
            "scan_id": result.scan_id,
            "target": result.target.raw,
            "profile": params.profile,
            "persisted": false,
            "summary": {
                "total": result.summary.total_findings,
                "critical": result.summary.critical,
                "high": result.summary.high,
                "medium": result.summary.medium,
                "low": result.summary.low,
                "info": result.summary.info,
            },
            "modules_run": result.modules_run.len(),
            "duration_seconds": (result.completed_at - result.started_at).num_seconds(),
            "top_findings": result.findings.iter().take(5).map(|f| {
                serde_json::json!({
                    "severity": f.severity.to_string(),
                    "title": &f.title,
                    "target": &f.affected_target,
                })
            }).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }

    /// Run recon-only modules against a target for consolidated intelligence.
    ///
    /// Executes only modules with `ModuleCategory::Recon` — headers, tech
    /// detection, discovery, subdomain enumeration, crawling, DNS security.
    /// Returns a consolidated briefing without any active vulnerability scanning.
    ///
    /// # Errors
    ///
    /// Returns an error if the target is invalid, the HTTP client cannot be
    /// built, or the recon scan fails.
    pub async fn do_target_intelligence(
        &self,
        params: TargetIntelligenceParams,
    ) -> Result<String, String> {
        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        let engine = Engine::new(Arc::clone(&self.config));
        let ctx = engine.dast_context_for_target(target, "quick").map_err(|e| e.to_string())?;

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.filter_by_category(crate::engine::module_trait::ModuleCategory::Recon);

        let result = orchestrator.run(true).await.map_err(|e| e.to_string())?;

        let output = serde_json::json!({
            "target": result.target.raw,
            "recon_modules_run": result.modules_run,
            "total_findings": result.summary.total_findings,
            "duration_seconds": (result.completed_at - result.started_at).num_seconds(),
            "intelligence": result.findings.iter().map(|f| {
                serde_json::json!({
                    "module": &f.module_id,
                    "severity": f.severity.to_string(),
                    "title": &f.title,
                    "description": &f.description,
                    "target": &f.affected_target,
                    "evidence": &f.evidence,
                })
            }).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }

    /// Get the status of the most recent scan for a project.
    ///
    /// Queries the database for the latest scan record and returns metadata
    /// including scan ID, target, timing, module count, and finding count.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database query fails.
    pub async fn do_scan_progress(&self, params: ScanProgressParams) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let scan_records =
            scans::list_scans(self.require_pool()?, project.id).await.map_err(|e| e.to_string())?;

        let Some(latest) = scan_records.first() else {
            return Ok(serde_json::json!({
                "project": project.name,
                "status": "no_scans",
                "message": "No scans have been run for this project yet.",
            })
            .to_string());
        };

        let finding_count = findings::list_findings(self.require_pool()?, project.id)
            .await
            .map_err(|e| e.to_string())?
            .len();

        let status = if latest.completed_at.is_some() { "complete" } else { "in_progress" };

        let output = serde_json::json!({
            "project": project.name,
            "status": status,
            "latest_scan": {
                "scan_id": latest.id.to_string(),
                "target": &latest.target_url,
                "profile": &latest.profile,
                "started_at": latest.started_at.to_rfc3339(),
                "completed_at": latest.completed_at.map(|d| d.to_rfc3339()),
                "modules_run": latest.modules_run,
            },
            "total_scans": scan_records.len(),
            "total_tracked_findings": finding_count,
        });
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }

    /// Correlate project findings into attack chains using rule-based
    /// pattern matching.
    ///
    /// Loads all findings for a project and applies correlation rules
    /// based on module IDs, OWASP categories, and CWE relationships
    /// to identify compound attack paths where multiple findings
    /// create escalated risk.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database query fails.
    pub async fn do_correlate_findings(
        &self,
        params: CorrelateFindingsParams,
    ) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let tracked_findings = findings::list_findings(self.require_pool()?, project.id)
            .await
            .map_err(|e| e.to_string())?;

        let correlation_findings: Vec<super::prompts::CorrelationFinding> = tracked_findings
            .iter()
            .map(|f| super::prompts::CorrelationFinding {
                id: f.id.to_string(),
                module_id: f.module_id.clone(),
                title: f.title.clone(),
                severity: f.severity.clone(),
            })
            .collect();

        let chains = super::prompts::correlate_attack_chains(&correlation_findings);

        let output = serde_json::json!({
            "project": project.name,
            "total_findings_analyzed": tracked_findings.len(),
            "attack_chains_found": chains.len(),
            "chains": chains,
        });

        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }

    /// List all available SAST code scanning modules as JSON.
    #[must_use]
    pub fn do_list_code_modules(&self) -> String {
        let modules = crate::runner::code_orchestrator::all_code_modules();
        let info: Vec<serde_json::Value> = modules
            .iter()
            .map(|m| {
                serde_json::json!({
                    "id": m.id(),
                    "name": m.name(),
                    "category": m.category().to_string(),
                    "description": m.description(),
                    "languages": m.languages(),
                    "requires_external_tool": m.requires_external_tool(),
                    "required_tool": m.required_tool(),
                })
            })
            .collect();
        serde_json::to_string_pretty(&info).unwrap_or_else(|_| "[]".to_string())
    }

    /// Run a SAST code scan on a filesystem path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or the scan fails.
    pub async fn do_scan_code(
        &self,
        params: super::types::CodeScanParams,
    ) -> Result<String, String> {
        let path = std::path::PathBuf::from(&params.path);
        if !path.exists() {
            return Err(format!("path '{}' does not exist", params.path));
        }

        let ctx = Engine::new(Arc::clone(&self.config))
            .code_context(&path, params.language.as_deref())
            .map_err(|e| e.to_string())?;

        let mut orchestrator = crate::runner::code_orchestrator::CodeOrchestrator::new(ctx);
        orchestrator.register_default_modules();

        // Apply language filter if specified
        if let Some(ref lang) = params.language {
            orchestrator.filter_by_language(lang);
        }

        // Apply module include/exclude filters
        if let Some(ref modules) = params.modules {
            let ids: Vec<String> = modules.split(',').map(|s| s.trim().to_string()).collect();
            orchestrator.filter_by_ids(&ids);
        }
        if let Some(ref skip) = params.skip {
            let ids: Vec<String> = skip.split(',').map(|s| s.trim().to_string()).collect();
            orchestrator.exclude_by_ids(&ids);
        }

        let result = orchestrator.run().await.map_err(|e| e.to_string())?;

        serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
    }
}

/// `#[tool_router]` — thin wrappers that delegate to `do_*` public methods.
#[tool_router(vis = "pub(crate)")]
impl ScorchKitServer {
    #[tool(description = "List all available scan modules with their categories, descriptions, \
        and external tool requirements. Use this first to understand what scanning capabilities \
        are available. Returns JSON array. Use check_tools to verify external tool installation.")]
    async fn list_modules(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, Ok(self.do_list_modules()))
    }

    #[tool(description = "Check which external security tools (nmap, nuclei, sqlmap, etc.) are \
        installed on the system. Call this before using the 'thorough' scan profile to know \
        which external tool wrappers will be available. Returns JSON array with tool name and \
        installed status.")]
    async fn check_tools(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, Ok(self.do_check_tools()))
    }

    #[tool(description = "Run a security scan against a target URL without project persistence. \
        Use for quick ad-hoc testing when you don't need to track results over time. Set \
        profile to 'quick' for safe recon, 'standard' for built-ins, 'thorough' for \
        non-restricted external tools, or 'pentest' for explicitly authorized credential/exploit \
        modules. Use 'modules' to run only specific module IDs, or 'skip' to exclude specific \
        ones. Prefer project_scan when you want results persisted and deduplicated. Returns \
        JSON with findings array, summary statistics, and scan metadata.")]
    async fn scan(
        &self,
        context: McpCallContext,
        params: Parameters<ScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan(params.0).await)
    }

    #[tool(description = "Start an authorized DAST scan as a cancellable background job. Returns \
        the queued job record immediately. Poll scan_job_status with the returned id; use \
        scan_job_cancel to stop work. PostgreSQL is optional for stateless MCP sessions.")]
    async fn scan_job_start(
        &self,
        context: McpCallContext,
        params: Parameters<ScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan_job_start(params.0).await)
    }

    #[tool(
        description = "Read one scan job's lifecycle, module progress, partial completed-module \
        findings, terminal error, and final result by job UUID."
    )]
    async fn scan_job_status(
        &self,
        context: McpCallContext,
        params: Parameters<ScanJobRefParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan_job_status(params.0).await)
    }

    #[tool(
        description = "Cancel a queued or running scan job by UUID. Cancellation is idempotent \
        while pending or already cancelled and preserves completed-module evidence."
    )]
    async fn scan_job_cancel(
        &self,
        context: McpCallContext,
        params: Parameters<ScanJobRefParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan_job_cancel(params.0).await)
    }

    #[tool(description = "Resume an interrupted scan job under the current unchanged engagement. \
        Creates a linked successor attempt and skips modules whose findings were durably committed.")]
    async fn scan_job_resume(
        &self,
        context: McpCallContext,
        params: Parameters<ScanJobRefParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan_job_resume(params.0).await)
    }

    #[tool(description = "AI-guided scan planning: runs recon modules first to gather target \
        intelligence, then uses the configured AI provider to analyze the tech stack and recommend which scanner \
        modules to run. Returns a structured plan with module recommendations, priorities, and \
        rationale — does NOT execute the scan. Review the plan, then use project_scan with the \
        recommended modules. Requires AI to be enabled in config. Falls back gracefully if \
        the configured provider is unavailable.")]
    async fn plan_scan(
        &self,
        context: McpCallContext,
        params: Parameters<PlanScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_plan_scan(params.0).await)
    }

    #[tool(description = "Create a new security assessment project for tracking scans, findings, \
        and security posture over time. Projects are the foundation for persistent scanning — \
        create one before using project_scan. The name must be unique. After creating, use \
        target_add to register URLs to scan. Returns the created project as JSON with its UUID.")]
    async fn project_create(
        &self,
        context: McpCallContext,
        params: Parameters<ProjectCreateParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_create(params.0).await)
    }

    #[tool(
        description = "List all security assessment projects. Use to discover existing projects \
        before creating a new one. Returns JSON array of projects with name, description, and \
        timestamps. You can reference projects by name (not UUID) in all other project tools."
    )]
    async fn project_list(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_list().await)
    }

    #[tool(
        description = "Show detailed information about a project including registered targets, \
        recent scans, and finding counts. Use to get an overview before running scans or \
        analyzing findings. Accepts project name or UUID. Returns JSON with project metadata, \
        targets array, scan count, finding count, and the 5 most recent scans."
    )]
    async fn project_show(
        &self,
        context: McpCallContext,
        params: Parameters<ProjectRefParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_show(params.0).await)
    }

    #[tool(description = "Delete a project and ALL associated data (targets, scans, findings, \
        schedules). This is destructive and irreversible. Set force=true to confirm deletion — \
        without it, returns a warning instead. Use only when the user explicitly asks to remove \
        a project.")]
    async fn project_delete(
        &self,
        context: McpCallContext,
        params: Parameters<ProjectDeleteParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_delete(params.0).await)
    }

    #[tool(description = "Run a security scan within a project, automatically persisting results \
        to the database. Findings are deduplicated across scans — the same vulnerability found \
        again increments seen_count instead of creating a duplicate. This is the primary \
        scanning tool for tracked assessments. Use profile 'quick' for recon, 'standard' for \
        built-in assessment, 'thorough' for a non-restricted deep dive, or 'pentest' only with \
        explicit credential/exploit grants. Use modules for approved plan_scan recommendations \
        and skip for exclusions. Returns JSON with scan ID, actual run/skipped module lists, finding \
        counts (total, new, updated), and summary.")]
    async fn project_scan(
        &self,
        context: McpCallContext,
        params: Parameters<ProjectScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_scan(params.0).await)
    }

    #[tool(
        description = "List vulnerability findings for a project. Filter by severity (critical, \
        high, medium, low, info) or by lifecycle status (new, acknowledged, false_positive, \
        remediated, verified). Without filters, returns all findings. Use after project_scan to \
        review results. Each finding includes module ID, severity, title, description, affected \
        target, evidence, and remediation guidance. Returns JSON array."
    )]
    async fn project_findings(
        &self,
        context: McpCallContext,
        params: Parameters<FindingListParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_findings(params.0).await)
    }

    #[tool(description = "Show full details for a single vulnerability finding by UUID. Use when \
        you need the complete evidence, remediation guidance, OWASP category, CWE ID, and raw \
        finding data for a specific issue. Get finding UUIDs from project_findings. Returns \
        JSON with all finding fields.")]
    async fn finding_show(
        &self,
        context: McpCallContext,
        params: Parameters<FindingRefParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_finding_show(params.0).await)
    }

    #[tool(description = "Update the lifecycle status of a vulnerability finding. Transition \
        through: new (just found) -> acknowledged (confirmed real) -> remediated (fix applied) \
        -> verified (fix confirmed by rescan). Or mark as false_positive to exclude from active \
        counts. Only update status when the user directs you to — do not auto-triage findings. \
        Returns confirmation with the new status.")]
    async fn finding_update_status(
        &self,
        context: McpCallContext,
        params: Parameters<FindingUpdateStatusParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_finding_update_status(params.0).await)
    }

    #[tool(description = "Add a target URL to a project for tracking. Targets represent the URLs \
        that will be scanned within a project. Add targets before running project_scan. Each \
        target can have an optional human-readable label. Returns the created target with its \
        UUID.")]
    async fn target_add(
        &self,
        context: McpCallContext,
        params: Parameters<TargetAddParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_target_add(params.0).await)
    }

    #[tool(description = "List all registered target URLs for a project. Use to see what targets \
        are configured before scanning. Returns JSON array of targets with URL, label, and \
        creation timestamp.")]
    async fn target_list(
        &self,
        context: McpCallContext,
        params: Parameters<ProjectRefParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_target_list(params.0).await)
    }

    #[tool(
        description = "Remove a target URL from a project by target UUID. Get target UUIDs from \
        target_list. Does not delete any scan data or findings associated with the target."
    )]
    async fn target_remove(
        &self,
        context: McpCallContext,
        params: Parameters<TargetRemoveParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_target_remove(params.0).await)
    }

    #[tool(
        description = "Run pending database migrations to initialize or update the schema. Call \
        this on first use before any project or scan operations. Safe to call multiple times — \
        already-applied migrations are skipped. Returns success confirmation."
    )]
    async fn db_migrate(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_db_migrate().await)
    }

    #[tool(
        description = "Create a recurring scan schedule for a project using a cron expression. \
        Schedules are not executed automatically — use run_due_scans to trigger overdue \
        schedules (wire into system cron for automation). Example cron: '0 0 * * *' for daily \
        at midnight, '0 */6 * * *' for every 6 hours. Returns the created schedule with next \
        run time."
    )]
    async fn schedule_scan(
        &self,
        context: McpCallContext,
        params: Parameters<ScheduleScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_schedule_scan(params.0).await)
    }

    #[tool(description = "Execute all scan schedules that are currently due. This is an explicit \
        trigger, not a background daemon — call it when you want overdue schedules to run. \
        Each schedule runs independently; individual failures don't abort the batch. Returns \
        JSON with execution count and per-schedule results.")]
    async fn run_due_scans(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_run_due_scans().await)
    }

    #[tool(description = "Get security posture metrics and trend analysis for a project. Returns \
        aggregate data: severity breakdown (critical to info), status breakdown (new to \
        verified), regression detection (previously remediated findings that reappeared), trend \
        direction (improving/declining/stable), and top 10 unresolved findings ranked by \
        severity. Use after scanning to assess overall security health. Returns structured JSON.")]
    async fn project_status(
        &self,
        context: McpCallContext,
        params: Parameters<ProjectStatusParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_status(params.0).await)
    }

    #[tool(
        description = "Analyze project findings using the configured AI provider with structured JSON output. \
        Set focus to: 'summary' for executive overview with risk score, 'prioritize' for \
        findings ranked by exploitability with attack chains, 'remediate' for fix steps with \
        effort estimates and code examples, or 'filter' for false positive classification with \
        confidence scores. Optionally specify scan_id to analyze a specific scan's findings \
        instead of all project findings. Requires AI enabled in config."
    )]
    async fn analyze_findings(
        &self,
        context: McpCallContext,
        params: Parameters<AnalyzeFindingsParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_analyze_findings(params.0).await)
    }

    #[tool(description = "Run a complete security scan in one call. Parses the target, applies \
        the scan profile (quick/standard/thorough/pentest), executes all matching modules, and optionally \
        persists results to a project for tracking. This is the 'one-shot' scanning tool — use \
        it when you want results fast without manually composing scan + project_scan. Does NOT \
        include AI planning or analysis — compose with plan_scan and analyze_findings for a full \
        AI-driven engagement. Returns JSON with scan summary, finding counts, and top findings.")]
    async fn auto_scan(
        &self,
        context: McpCallContext,
        params: Parameters<AutoScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_auto_scan(params.0).await)
    }

    #[tool(description = "Gather consolidated target intelligence using recon-only modules. Runs \
        headers analysis, technology detection, endpoint discovery, subdomain enumeration, web \
        crawling, and DNS security checks — without any active vulnerability scanning. Use this \
        as the first step in an engagement to understand the target's attack surface before \
        deciding which scanner modules to deploy. Returns structured JSON with all recon findings \
        organized by module.")]
    async fn target_intelligence(
        &self,
        context: McpCallContext,
        params: Parameters<TargetIntelligenceParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_target_intelligence(params.0).await)
    }

    #[tool(description = "Check the status of the most recent scan for a project. Returns the \
        latest scan record with scan ID, target URL, profile used, start/completion times, \
        finding count, and modules run. Also shows total scan count and tracked finding count \
        for the project. Use after running auto_scan or project_scan to verify completion and \
        review results.")]
    async fn scan_progress(
        &self,
        context: McpCallContext,
        params: Parameters<ScanProgressParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan_progress(params.0).await)
    }

    #[tool(description = "Correlate project findings into attack chains. Analyzes all findings \
        for a project and identifies compound vulnerabilities where multiple findings combine \
        to create escalated risk. Example: XSS + missing CSP = session hijacking chain. \
        Returns JSON with attack chain names, severity escalation, narrative descriptions, \
        contributing finding IDs, and remediation priority. Use after scanning to understand \
        how individual findings relate and prioritize fixes by attack path impact.")]
    async fn correlate_findings(
        &self,
        context: McpCallContext,
        params: Parameters<CorrelateFindingsParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_correlate_findings(params.0).await)
    }

    #[tool(
        description = "List all available SAST (Static Application Security Testing) code scanning \
        modules with their categories, language support, and external tool requirements. Use this \
        to understand what code scanning capabilities are available before calling scan_code. \
        Returns JSON array with module id, name, category (sast/sca/secrets/iac/container), \
        supported languages, and tool requirements."
    )]
    async fn list_code_modules(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, Ok(self.do_list_code_modules()))
    }

    #[tool(description = "Run SAST (Static Application Security Testing) on source code at the \
        given filesystem path. Auto-detects project language from manifest files (Cargo.toml, \
        package.json, go.mod, etc.). Runs built-in analyzers (dependency auditor) and external \
        tool wrappers (Semgrep, OSV-Scanner, Gitleaks, Bandit, Gosec, Checkov, Grype, etc.) \
        based on detected language. Use 'language' to override auto-detection. Use 'modules' \
        to run only specific module IDs, or 'skip' to exclude specific ones. Returns JSON with \
        findings array and scan metadata, same format as the scan tool.")]
    async fn scan_code(
        &self,
        context: McpCallContext,
        params: Parameters<super::types::CodeScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan_code(params.0).await)
    }
}

async fn require_registered_project_target(
    pool: &sqlx::PgPool,
    project_id: Uuid,
    requested: &Target,
) -> Result<(), ScorchError> {
    let registered = projects::list_targets(pool, project_id).await?.into_iter().any(|entry| {
        Target::parse(&entry.url).is_ok_and(|candidate| candidate.url == requested.url)
    });
    if registered {
        Ok(())
    } else {
        Err(ScorchError::Config(format!(
            "target '{}' is not registered to project {project_id}",
            requested.url
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::engine::policy::{Engagement, EngagementPolicy};
    use crate::engine::scope::ScopeRule;
    use chrono::Utc;

    fn job_server() -> ScorchKitServer {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::Exact("localhost".to_string()))
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::ActiveSafe);
        let engagement = Engagement::new("mcp-job-wrapper-test", policy);
        let config = AppConfig { engagement: Some(engagement), ..AppConfig::default() };
        ScorchKitServer::new_stateless(Arc::new(config))
    }

    fn job_request(server: &ScorchKitServer) -> DastJobRequest {
        DastJobRequest::new(
            "http://localhost:1",
            "quick",
            server.config.engagement.clone().expect("job engagement"),
        )
        .with_modules(Some(vec!["headers".to_string()]))
    }

    #[test]
    fn completed_job_result_rejects_missing_success_payload() {
        let mut job = ScanJob::new(
            DastJobRequest::new(
                "http://localhost:1",
                "quick",
                Engagement::new("result-test", EngagementPolicy::default()),
            ),
            Uuid::new_v4(),
        );
        job.state = ScanJobState::Succeeded;
        let error = completed_job_result(job).expect_err("success requires a persisted result");
        assert_eq!(error, "successful scan job has no result");
    }

    #[tokio::test]
    async fn job_tool_wrappers_preserve_cancel_and_resume_payloads() {
        let server = job_server();
        let cancelled_job = server.jobs.submit(job_request(&server)).await.expect("submit cancel");
        let cancelled_json = server
            .scan_job_cancel(
                McpCallContext::test("scan_job_cancel"),
                Parameters(ScanJobRefParams { job_id: cancelled_job.id.to_string() }),
            )
            .await;
        let cancelled: ScanJob =
            serde_json::from_str(cancelled_json.legacy_text()).expect("decode cancellation");
        assert_eq!(cancelled.id, cancelled_job.id);
        assert_eq!(cancelled.state, ScanJobState::Cancelled);

        let abandoned = server.jobs.submit(job_request(&server)).await.expect("submit resume");
        let mut running = abandoned.clone();
        running.state = ScanJobState::Running;
        running.revision = 1;
        running.started_at = Some(Utc::now());
        running.updated_at = Utc::now();
        running.lease_expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        assert!(server
            .jobs
            .store()
            .compare_and_swap(0, &running)
            .await
            .expect("persist abandoned job"));
        let recovered = server.jobs.recover_interrupted().await.expect("recover abandoned job");
        assert_eq!(recovered.len(), 1);

        let resumed_json = server
            .scan_job_resume(
                McpCallContext::test("scan_job_resume"),
                Parameters(ScanJobRefParams { job_id: abandoned.id.to_string() }),
            )
            .await;
        let resumed: ScanJob =
            serde_json::from_str(resumed_json.legacy_text()).expect("decode resumed job");
        assert_eq!(resumed.parent_job_id, Some(abandoned.id));
        assert_eq!(resumed.state, ScanJobState::Queued);
    }
}
