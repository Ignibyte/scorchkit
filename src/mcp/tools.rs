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
    AnalyzeFindingsParams, AutoScanParams, CorrelateFindingsParams, FindingListParams,
    FindingRefParams, FindingUpdateStatusParams, PlanScanParams, ProjectCreateParams,
    ProjectDeleteParams, ProjectRefParams, ProjectScanParams, ProjectStatusParams, ScanParams,
    ScanProgressParams, ScheduleScanParams, TargetAddParams, TargetIntelligenceParams,
    TargetRemoveParams,
};
use crate::engine::error::ScorchError;
use crate::engine::scan_context::ScanContext;
use crate::engine::target::Target;
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

        let updated = findings::update_finding_status(&self.pool, id, status, None)
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

    /// Create a recurring scan schedule for a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found, the cron expression
    /// is invalid, or the database fails.
    pub async fn do_schedule_scan(&self, params: ScheduleScanParams) -> Result<String, String> {
        let project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;
        let schedule = schedules::create_schedule(
            &self.pool,
            project.id,
            &params.target,
            &params.profile,
            &params.cron,
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
        let due = schedules::find_due_schedules(&self.pool).await.map_err(|e| e.to_string())?;

        if due.is_empty() {
            return Ok("{\"executed\": 0, \"message\": \"No schedules are due\"}".to_string());
        }

        let mut results = Vec::new();
        for schedule in &due {
            let outcome = match crate::cli::schedule::run_due(&self.pool, &self.config).await {
                Ok(()) => serde_json::json!({
                    "schedule_id": schedule.id.to_string(),
                    "target": &schedule.target_url,
                    "status": "success",
                }),
                Err(e) => serde_json::json!({
                    "schedule_id": schedule.id.to_string(),
                    "target": &schedule.target_url,
                    "status": "error",
                    "error": e.to_string(),
                }),
            };
            results.push(outcome);
        }

        let output = serde_json::json!({
            "executed": due.len(),
            "results": results,
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
        let project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;
        let posture = metrics::build_posture_metrics(&self.pool, project.id, &project.name)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&posture).map_err(|e| e.to_string())
    }

    /// Run AI-guided scan planning: recon first, then Claude decides modules.
    ///
    /// Returns a structured [`ScanPlan`] as JSON without executing the scan.
    /// The MCP client can inspect and approve the plan before calling `scan`
    /// or `project-scan` to execute.
    ///
    /// # Errors
    ///
    /// Returns an error if the target URL is invalid, AI is disabled, or
    /// the Claude CLI is unavailable.
    pub async fn do_plan_scan(&self, params: PlanScanParams) -> Result<String, String> {
        if !self.config.ai.enabled {
            return Err("AI is disabled in config — scan planning requires AI".to_string());
        }

        let planner = crate::ai::planner::ScanPlanner::from_config(&self.config.ai);
        if !planner.is_available() {
            return Err(
                "claude CLI not found. Install Claude Code to enable AI scan planning.".to_string()
            );
        }

        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        let plan = planner.plan(&target, &self.config).await.map_err(|e| e.to_string())?;

        serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())
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

    /// Run a full scan engagement in one call: parse target, build orchestrator,
    /// run scan with the specified profile, and optionally persist results to
    /// a project.
    ///
    /// This is the "one-shot" scanning tool — Claude can call this instead of
    /// manually composing `scan` + `project_scan`. Does NOT include AI
    /// planning or analysis (use `plan_scan` and `analyze_findings` separately).
    ///
    /// # Errors
    ///
    /// Returns an error if the target URL is invalid, the HTTP client cannot
    /// be built, the scan fails, or project persistence fails.
    pub async fn do_auto_scan(&self, params: AutoScanParams) -> Result<String, String> {
        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        let http_client = build_scan_client(&self.config).map_err(|e| e.to_string())?;
        let ctx = ScanContext::new(target, Arc::clone(&self.config), http_client);

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile(&params.profile);

        let result = orchestrator.run(true).await.map_err(|e| e.to_string())?;

        // Optionally persist to project
        if let Some(ref project_name) = params.project {
            let project =
                resolve_project(&self.pool, project_name).await.map_err(|e| e.to_string())?;
            let modules_run: Vec<String> = result.modules_run.iter().map(String::clone).collect();
            let modules_skipped: Vec<String> = result
                .modules_skipped
                .iter()
                .map(|(id, reason)| format!("{id}: {reason}"))
                .collect();
            let summary_json = serde_json::to_value(&result.summary).map_err(|e| e.to_string())?;

            let scan_record = scans::save_scan(
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
            let saved_count =
                findings::save_findings(&self.pool, project.id, scan_record.id, &result.findings)
                    .await
                    .map_err(|e| e.to_string())?;

            let output = serde_json::json!({
                "scan_id": result.scan_id,
                "target": result.target.raw,
                "profile": params.profile,
                "project": project_name,
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
        let http_client = build_scan_client(&self.config).map_err(|e| e.to_string())?;
        let ctx = ScanContext::new(target, Arc::clone(&self.config), http_client);

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
        let project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;
        let scan_records =
            scans::list_scans(&self.pool, project.id).await.map_err(|e| e.to_string())?;

        let Some(latest) = scan_records.first() else {
            return Ok(serde_json::json!({
                "project": project.name,
                "status": "no_scans",
                "message": "No scans have been run for this project yet.",
            })
            .to_string());
        };

        let finding_count =
            findings::list_findings(&self.pool, project.id).await.map_err(|e| e.to_string())?.len();

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
        let project =
            resolve_project(&self.pool, &params.project).await.map_err(|e| e.to_string())?;
        let tracked_findings =
            findings::list_findings(&self.pool, project.id).await.map_err(|e| e.to_string())?;

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

        let ctx = crate::engine::code_context::CodeContext::new(
            path,
            params.language.clone(),
            Arc::clone(&self.config),
        );

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
    #[tool(
        description = "List all 41 available scan modules with their categories, descriptions, \
        and external tool requirements. Use this first to understand what scanning capabilities \
        are available. Returns JSON array. Use check_tools to verify external tool installation."
    )]
    async fn list_modules(&self) -> String {
        self.do_list_modules()
    }

    #[tool(description = "Check which external security tools (nmap, nuclei, sqlmap, etc.) are \
        installed on the system. Call this before using the 'thorough' scan profile to know \
        which external tool wrappers will be available. Returns JSON array with tool name and \
        installed status.")]
    async fn check_tools(&self) -> String {
        self.do_check_tools()
    }

    #[tool(description = "Run a security scan against a target URL without project persistence. \
        Use for quick ad-hoc testing when you don't need to track results over time. Set \
        profile to 'quick' for fast recon (4 modules: headers, tech, ssl, misconfig), \
        'standard' for all 20 built-in modules, or 'thorough' for all 41 including external \
        tools. Use 'modules' to run only specific module IDs, or 'skip' to exclude specific \
        ones. Prefer project_scan when you want results persisted and deduplicated. Returns \
        JSON with findings array, summary statistics, and scan metadata.")]
    async fn scan(&self, params: Parameters<ScanParams>) -> Result<String, String> {
        self.do_scan(params.0).await
    }

    #[tool(description = "AI-guided scan planning: runs recon modules first to gather target \
        intelligence, then uses Claude to analyze the tech stack and recommend which scanner \
        modules to run. Returns a structured plan with module recommendations, priorities, and \
        rationale — does NOT execute the scan. Review the plan, then use project_scan with the \
        recommended modules. Requires AI to be enabled in config. Falls back gracefully if \
        Claude CLI is unavailable.")]
    async fn plan_scan(&self, params: Parameters<PlanScanParams>) -> Result<String, String> {
        self.do_plan_scan(params.0).await
    }

    #[tool(description = "Create a new security assessment project for tracking scans, findings, \
        and security posture over time. Projects are the foundation for persistent scanning — \
        create one before using project_scan. The name must be unique. After creating, use \
        target_add to register URLs to scan. Returns the created project as JSON with its UUID.")]
    async fn project_create(
        &self,
        params: Parameters<ProjectCreateParams>,
    ) -> Result<String, String> {
        self.do_project_create(params.0).await
    }

    #[tool(
        description = "List all security assessment projects. Use to discover existing projects \
        before creating a new one. Returns JSON array of projects with name, description, and \
        timestamps. You can reference projects by name (not UUID) in all other project tools."
    )]
    async fn project_list(&self) -> Result<String, String> {
        self.do_project_list().await
    }

    #[tool(
        description = "Show detailed information about a project including registered targets, \
        recent scans, and finding counts. Use to get an overview before running scans or \
        analyzing findings. Accepts project name or UUID. Returns JSON with project metadata, \
        targets array, scan count, finding count, and the 5 most recent scans."
    )]
    async fn project_show(&self, params: Parameters<ProjectRefParams>) -> Result<String, String> {
        self.do_project_show(params.0).await
    }

    #[tool(description = "Delete a project and ALL associated data (targets, scans, findings, \
        schedules). This is destructive and irreversible. Set force=true to confirm deletion — \
        without it, returns a warning instead. Use only when the user explicitly asks to remove \
        a project.")]
    async fn project_delete(
        &self,
        params: Parameters<ProjectDeleteParams>,
    ) -> Result<String, String> {
        self.do_project_delete(params.0).await
    }

    #[tool(description = "Run a security scan within a project, automatically persisting results \
        to the database. Findings are deduplicated across scans — the same vulnerability found \
        again increments seen_count instead of creating a duplicate. This is the primary \
        scanning tool for tracked assessments. Use profile 'quick' for recon, 'standard' for \
        full assessment, 'thorough' for deep dive. Returns JSON with scan ID, finding counts \
        (total, new, updated), and summary.")]
    async fn project_scan(&self, params: Parameters<ProjectScanParams>) -> Result<String, String> {
        self.do_project_scan(params.0).await
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
        params: Parameters<FindingListParams>,
    ) -> Result<String, String> {
        self.do_project_findings(params.0).await
    }

    #[tool(description = "Show full details for a single vulnerability finding by UUID. Use when \
        you need the complete evidence, remediation guidance, OWASP category, CWE ID, and raw \
        finding data for a specific issue. Get finding UUIDs from project_findings. Returns \
        JSON with all finding fields.")]
    async fn finding_show(&self, params: Parameters<FindingRefParams>) -> Result<String, String> {
        self.do_finding_show(params.0).await
    }

    #[tool(description = "Update the lifecycle status of a vulnerability finding. Transition \
        through: new (just found) -> acknowledged (confirmed real) -> remediated (fix applied) \
        -> verified (fix confirmed by rescan). Or mark as false_positive to exclude from active \
        counts. Only update status when the user directs you to — do not auto-triage findings. \
        Returns confirmation with the new status.")]
    async fn finding_update_status(
        &self,
        params: Parameters<FindingUpdateStatusParams>,
    ) -> Result<String, String> {
        self.do_finding_update_status(params.0).await
    }

    #[tool(description = "Add a target URL to a project for tracking. Targets represent the URLs \
        that will be scanned within a project. Add targets before running project_scan. Each \
        target can have an optional human-readable label. Returns the created target with its \
        UUID.")]
    async fn target_add(&self, params: Parameters<TargetAddParams>) -> Result<String, String> {
        self.do_target_add(params.0).await
    }

    #[tool(description = "List all registered target URLs for a project. Use to see what targets \
        are configured before scanning. Returns JSON array of targets with URL, label, and \
        creation timestamp.")]
    async fn target_list(&self, params: Parameters<ProjectRefParams>) -> Result<String, String> {
        self.do_target_list(params.0).await
    }

    #[tool(
        description = "Remove a target URL from a project by target UUID. Get target UUIDs from \
        target_list. Does not delete any scan data or findings associated with the target."
    )]
    async fn target_remove(
        &self,
        params: Parameters<TargetRemoveParams>,
    ) -> Result<String, String> {
        self.do_target_remove(params.0).await
    }

    #[tool(
        description = "Run pending database migrations to initialize or update the schema. Call \
        this on first use before any project or scan operations. Safe to call multiple times — \
        already-applied migrations are skipped. Returns success confirmation."
    )]
    async fn db_migrate(&self) -> Result<String, String> {
        self.do_db_migrate().await
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
        params: Parameters<ScheduleScanParams>,
    ) -> Result<String, String> {
        self.do_schedule_scan(params.0).await
    }

    #[tool(description = "Execute all scan schedules that are currently due. This is an explicit \
        trigger, not a background daemon — call it when you want overdue schedules to run. \
        Each schedule runs independently; individual failures don't abort the batch. Returns \
        JSON with execution count and per-schedule results.")]
    async fn run_due_scans(&self) -> Result<String, String> {
        self.do_run_due_scans().await
    }

    #[tool(description = "Get security posture metrics and trend analysis for a project. Returns \
        aggregate data: severity breakdown (critical to info), status breakdown (new to \
        verified), regression detection (previously remediated findings that reappeared), trend \
        direction (improving/declining/stable), and top 10 unresolved findings ranked by \
        severity. Use after scanning to assess overall security health. Returns structured JSON.")]
    async fn project_status(
        &self,
        params: Parameters<ProjectStatusParams>,
    ) -> Result<String, String> {
        self.do_project_status(params.0).await
    }

    #[tool(description = "Analyze project findings using Claude AI with structured JSON output. \
        Set focus to: 'summary' for executive overview with risk score, 'prioritize' for \
        findings ranked by exploitability with attack chains, 'remediate' for fix steps with \
        effort estimates and code examples, or 'filter' for false positive classification with \
        confidence scores. Optionally specify scan_id to analyze a specific scan's findings \
        instead of all project findings. Requires AI enabled in config.")]
    async fn analyze_findings(
        &self,
        params: Parameters<AnalyzeFindingsParams>,
    ) -> Result<String, String> {
        self.do_analyze_findings(params.0).await
    }

    #[tool(description = "Run a complete security scan in one call. Parses the target, applies \
        the scan profile (quick/standard/thorough), executes all matching modules, and optionally \
        persists results to a project for tracking. This is the 'one-shot' scanning tool — use \
        it when you want results fast without manually composing scan + project_scan. Does NOT \
        include AI planning or analysis — compose with plan_scan and analyze_findings for a full \
        AI-driven engagement. Returns JSON with scan summary, finding counts, and top findings.")]
    async fn auto_scan(&self, params: Parameters<AutoScanParams>) -> Result<String, String> {
        self.do_auto_scan(params.0).await
    }

    #[tool(description = "Gather consolidated target intelligence using recon-only modules. Runs \
        headers analysis, technology detection, endpoint discovery, subdomain enumeration, web \
        crawling, and DNS security checks — without any active vulnerability scanning. Use this \
        as the first step in an engagement to understand the target's attack surface before \
        deciding which scanner modules to deploy. Returns structured JSON with all recon findings \
        organized by module.")]
    async fn target_intelligence(
        &self,
        params: Parameters<TargetIntelligenceParams>,
    ) -> Result<String, String> {
        self.do_target_intelligence(params.0).await
    }

    #[tool(description = "Check the status of the most recent scan for a project. Returns the \
        latest scan record with scan ID, target URL, profile used, start/completion times, \
        finding count, and modules run. Also shows total scan count and tracked finding count \
        for the project. Use after running auto_scan or project_scan to verify completion and \
        review results.")]
    async fn scan_progress(
        &self,
        params: Parameters<ScanProgressParams>,
    ) -> Result<String, String> {
        self.do_scan_progress(params.0).await
    }

    #[tool(description = "Correlate project findings into attack chains. Analyzes all findings \
        for a project and identifies compound vulnerabilities where multiple findings combine \
        to create escalated risk. Example: XSS + missing CSP = session hijacking chain. \
        Returns JSON with attack chain names, severity escalation, narrative descriptions, \
        contributing finding IDs, and remediation priority. Use after scanning to understand \
        how individual findings relate and prioritize fixes by attack path impact.")]
    async fn correlate_findings(
        &self,
        params: Parameters<CorrelateFindingsParams>,
    ) -> Result<String, String> {
        self.do_correlate_findings(params.0).await
    }

    #[tool(
        description = "List all available SAST (Static Application Security Testing) code scanning \
        modules with their categories, language support, and external tool requirements. Use this \
        to understand what code scanning capabilities are available before calling scan_code. \
        Returns JSON array with module id, name, category (sast/sca/secrets/iac/container), \
        supported languages, and tool requirements."
    )]
    async fn list_code_modules(&self) -> String {
        self.do_list_code_modules()
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
        params: Parameters<super::types::CodeScanParams>,
    ) -> Result<String, String> {
        self.do_scan_code(params.0).await
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
