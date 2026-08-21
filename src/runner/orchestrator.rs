use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use colored::Colorize;
use futures_util::FutureExt;
use uuid::Uuid;

use crate::engine::audit_log::subscribe_audit_log_if_enabled;
use crate::engine::error::Result;
use crate::engine::events::ScanEvent;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::scan_result::ScanResult;
use crate::runner::job::{JobProgressSink, JobProgressUpdate};
use crate::runner::job_executor::{
    cancel_on_token, ensure_not_cancelled, CancellationToken, JobExecutor, JobOutcome,
};
use crate::runner::progress;
use crate::runner::subprocess::missing_required_tool;

/// Returns all available modules (recon + scanner + external tools).
#[must_use]
pub fn all_modules() -> Vec<Box<dyn ScanModule>> {
    let mut modules: Vec<Box<dyn ScanModule>> = Vec::new();
    modules.extend(crate::recon::register_modules());
    modules.extend(crate::scanner::register_modules());
    modules.extend(crate::tools::register_modules());
    modules
}

/// Return modules in the default application-security product catalog.
#[must_use]
pub fn application_modules() -> Vec<Box<dyn ScanModule>> {
    all_modules()
        .into_iter()
        .filter(|module| module.descriptor().adapter.is_application_security())
        .collect()
}

/// Return modules retained only for explicit compatibility workflows.
#[must_use]
pub fn compatibility_modules() -> Vec<Box<dyn ScanModule>> {
    all_modules()
        .into_iter()
        .filter(|module| !module.descriptor().adapter.is_application_security())
        .collect()
}

/// Modules withheld from every implicit profile below `pentest`.
fn is_credential_or_exploit_module(module: &dyn ScanModule) -> bool {
    matches!(
        module.descriptor().adapter.strongest_effect,
        crate::engine::policy::EffectClass::CredentialTest
            | crate::engine::policy::EffectClass::Exploit
    )
}

/// Orchestrates scan module execution with concurrency control.
pub struct Orchestrator {
    ctx: ScanContext,
    modules: Vec<Box<dyn ScanModule>>,
    hook_runner: crate::engine::hook_runner::HookRunner,
    job_progress: Option<Arc<dyn JobProgressSink>>,
}

impl Orchestrator {
    #[must_use]
    pub fn new(ctx: ScanContext) -> Self {
        let hook_runner = crate::engine::hook_runner::HookRunner::new(&ctx.config.hooks);
        Self { ctx, modules: Vec::new(), hook_runner, job_progress: None }
    }

    pub fn register_default_modules(&mut self) {
        self.modules = all_modules();

        // Load user-defined plugins if configured
        if let Some(ref plugins_dir) = self.ctx.config.scan.plugins_dir {
            let plugins = super::plugin::load_plugins(plugins_dir);
            self.modules.extend(plugins);
        }

        // Load YAML rule engine if rules directory is configured
        if let Some(ref rules_dir) = self.ctx.config.scan.rules_dir {
            let rules = super::rule_engine::load_rules(rules_dir);
            if !rules.is_empty() {
                self.modules.push(Box::new(super::rule_engine::RuleEngineModule::new(rules)));
            }
        }
    }

    /// Add one trusted module to this policy-sealed scan runner.
    pub fn add_module(&mut self, module: Box<dyn ScanModule>) {
        self.modules.push(module);
    }

    pub fn filter_by_category(&mut self, category: ModuleCategory) {
        self.modules.retain(|m| m.category() == category);
    }

    pub fn filter_by_ids(&mut self, ids: &[String]) {
        self.modules.retain(|m| ids.iter().any(|id| id == m.id()));
    }

    pub fn exclude_by_ids(&mut self, ids: &[String]) {
        self.modules.retain(|m| !ids.iter().any(|id| id == m.id()));
    }

    /// Apply an implicit application profile or an explicit module-ID selection.
    pub fn apply_selection(&mut self, profile: &str, explicit_ids: Option<&[String]>) {
        if !matches!(profile, "quick" | "standard" | "thorough" | "pentest") {
            self.modules.clear();
            return;
        }
        if let Some(ids) = explicit_ids {
            self.filter_by_ids(ids);
        } else {
            self.apply_profile(profile);
        }
    }

    /// Number of modules selected for this orchestrator run.
    #[must_use]
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Attach the reliable module-boundary sink owned by a scan job.
    pub fn set_job_progress_sink(&mut self, sink: Arc<dyn JobProgressSink>) {
        self.job_progress = Some(sink);
    }

    /// Filter modules by scan profile.
    pub fn apply_profile(&mut self, profile: &str) {
        if !matches!(profile, "quick" | "standard" | "thorough" | "pentest") {
            self.modules.clear();
            return;
        }
        self.modules.retain(|module| module.descriptor().adapter.is_application_security());
        match profile {
            "quick" => {
                self.modules.retain(|m| {
                    !m.requires_external_tool()
                        && matches!(m.id(), "headers" | "tech" | "ssl" | "misconfig")
                });
            }
            "standard" => self.modules.retain(|module| !module.requires_external_tool()),
            "thorough" => {
                self.modules.retain(|module| !is_credential_or_exploit_module(module.as_ref()));
            }
            _ => {}
        }
    }

    /// Apply a named scan template — a curated set of modules for a target type.
    ///
    /// Returns `true` if the template was found and applied, `false` otherwise.
    // JUSTIFICATION: Template definitions are declarative data — splitting the match arms
    // into separate functions would scatter the template catalog across multiple locations
    #[allow(clippy::too_many_lines)]
    pub fn apply_template(&mut self, template: &str) -> bool {
        let module_ids: &[&str] = match template {
            "web-app" => &[
                "headers",
                "tech",
                "ssl",
                "misconfig",
                "csrf",
                "injection",
                "xss",
                "ssrf",
                "xxe",
                "path_traversal",
                "ssti",
                "redirect",
                "sensitive",
                "auth-session",
                "upload",
                "clickjacking",
                "cors-deep",
                "csp-deep",
                "crawler",
                "discovery",
                "dom_xss",
                "crlf",
                "host_header",
                "ratelimit",
                "js_analysis",
            ],
            "api" => &[
                "headers",
                "ssl",
                "misconfig",
                "injection",
                "nosql",
                "api-security",
                "api-schema",
                "cors-deep",
                "jwt",
                "ratelimit",
                "auth-session",
                "idor",
                "mass_assignment",
                "ssrf",
                "sensitive",
            ],
            "graphql" => &[
                "headers",
                "ssl",
                "graphql",
                "injection",
                "cors-deep",
                "jwt",
                "auth-session",
                "ratelimit",
                "sensitive",
                "nosql",
            ],
            "wordpress" => &[
                "headers",
                "tech",
                "ssl",
                "misconfig",
                "discovery",
                "wpscan",
                "nuclei",
                "xss",
                "injection",
                "sensitive",
                "crawler",
            ],
            "spa" => &[
                "headers",
                "ssl",
                "cors-deep",
                "csp-deep",
                "dom_xss",
                "js_analysis",
                "xss",
                "api-security",
                "jwt",
                "clickjacking",
                "sensitive",
                "crawler",
            ],
            "network" => &[
                "ssl",
                "headers",
                "dns-security",
                "subdomain",
                "cloud",
                "smuggling",
                "cname_takeover",
                "nmap",
                "sslyze",
                "testssl",
                "dnsx",
                "dnsrecon",
            ],
            "full" => {
                self.apply_profile("thorough");
                return true;
            }
            "compatibility" => {
                self.modules
                    .retain(|module| !module.descriptor().adapter.is_application_security());
                return true;
            }
            _ => return false,
        };

        if !module_ids.is_empty() {
            self.modules.retain(|m| module_ids.contains(&m.id()));
        }
        true
    }

    /// List all available scan template names and their descriptions.
    #[must_use]
    pub fn list_templates() -> Vec<(&'static str, &'static str, usize)> {
        vec![
            ("web-app", "Standard web application assessment", 25),
            ("api", "REST API security testing", 15),
            ("graphql", "GraphQL API security testing", 10),
            ("wordpress", "WordPress-specific assessment", 11),
            ("spa", "Single-page application (React/Vue/Angular)", 12),
            ("network", "Network infrastructure & DNS", 12),
            ("full", "All application modules (same as --profile thorough)", 66),
            ("compatibility", "Explicit non-application compatibility catalog", 22),
        ]
    }

    /// Run all registered modules concurrently (up to `max_concurrent_modules`).
    ///
    /// # Errors
    ///
    /// Returns an error for invalid execution budgets, caller-independent batch timeout, or a
    /// fatal scan error.
    // JUSTIFICATION: Hook integration at pre-scan, post-module, and post-scan points
    // adds necessary lifecycle instrumentation that is cohesive within the run loop
    #[allow(clippy::too_many_lines)]
    pub async fn run(&self, quiet: bool) -> Result<ScanResult> {
        let cancellation = CancellationToken::new();
        self.run_with_cancellation(quiet, &cancellation).await
    }

    /// Run registered DAST modules with caller-controlled cancellation.
    ///
    /// Recon producers complete before scanner consumers. Modules within each phase share the
    /// configured concurrency and wall-time budgets.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid execution budgets, caller cancellation, batch deadline, or a
    /// fatal hook or orchestration failure. Individual module failures remain non-fatal outcomes.
    // JUSTIFICATION: Hook and phase integration form one lifecycle transaction; extraction would
    // split ordered event and finding commits from their owning scan state.
    #[allow(clippy::too_many_lines)]
    pub async fn run_with_cancellation(
        &self,
        quiet: bool,
        cancellation: &CancellationToken,
    ) -> Result<ScanResult> {
        let started_at = Utc::now();
        let scan_started = Instant::now();
        let scan_id = Uuid::new_v4().to_string();
        let executor = JobExecutor::from_scan_config(&self.ctx.config.scan)?;

        // Wire the built-in audit-log handler before the first publish so no
        // lifecycle events are lost. The JoinHandle is dropped (tokio detaches).
        let _audit_log_handle =
            subscribe_audit_log_if_enabled(&self.ctx.config.audit_log, &self.ctx.events);

        self.ctx.events.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: self.ctx.target.url.as_str().to_string(),
        });

        if progress::is_visible(quiet) {
            println!(
                "{} {} module{}",
                "Running".bold(),
                self.modules.len(),
                if self.modules.len() == 1 { "" } else { "s" }
            );
            println!();
        }

        // Separate modules into runnable and skipped
        let mut runnable: Vec<&dyn ScanModule> = Vec::new();
        let mut modules_skipped: Vec<(String, String)> = Vec::new();

        for module in &self.modules {
            if let Some(tool) =
                missing_required_tool(module.requires_external_tool(), module.required_tool())
            {
                if progress::is_visible(quiet) {
                    println!(
                        "  {} {} (requires: {})",
                        "SKIP".yellow().bold(),
                        module.name(),
                        tool.dimmed()
                    );
                }
                let reason = format!("external tool '{tool}' not found");
                self.ctx.events.publish(ScanEvent::ModuleSkipped {
                    scan_id: scan_id.clone(),
                    module_id: module.id().to_string(),
                    reason: reason.clone(),
                });
                if let Some(sink) = &self.job_progress {
                    sink.publish(JobProgressUpdate::Skipped {
                        module_id: module.id().to_string(),
                    })?;
                }
                modules_skipped.push((module.id().to_string(), reason));
                continue;
            }
            runnable.push(module.as_ref());
        }

        // Fire pre-scan hooks
        if self.hook_runner.has_hooks(crate::engine::hook_runner::HookPoint::PreScan) {
            let module_ids: Vec<&str> = runnable.iter().map(|m| m.id()).collect();
            let pre_scan_data = serde_json::json!({
                "target": self.ctx.target.url.as_str(),
                "profile": self.ctx.config.scan.profile,
                "modules": module_ids,
            });
            // Pre-scan hooks can modify data but we don't apply changes in v1
            // (future: parse modified modules list)
            let _ = cancel_on_token(
                cancellation,
                self.hook_runner.execute(
                    crate::engine::hook_runner::HookPoint::PreScan,
                    &pre_scan_data,
                    &self.ctx,
                ),
            )
            .await?;
        }

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut modules_run: Vec<String> = Vec::new();
        let (recon, scanners): (Vec<_>, Vec<_>) =
            runnable.into_iter().partition(|module| module.category() == ModuleCategory::Recon);

        let batches: [Vec<&dyn ScanModule>; 2] = (recon, scanners).into();
        for batch in batches {
            let outcomes = execute_scan_modules(
                batch,
                &self.ctx,
                &scan_id,
                quiet,
                &executor,
                cancellation,
                self.job_progress.as_ref(),
            )
            .await?;
            for outcome in outcomes {
                let duration_ms = u64::try_from(outcome.duration().as_millis()).unwrap_or(u64::MAX);
                let ModuleExecution { module_id, module_name, result } = outcome.into_output()?;
                match result {
                    Ok(findings) => {
                        // Fire post-module hooks in deterministic executor order.
                        let findings = if self
                            .hook_runner
                            .has_hooks(crate::engine::hook_runner::HookPoint::PostModule)
                        {
                            let module_data = serde_json::json!({
                                "module_id": &module_id,
                                "module_name": &module_name,
                                "findings": &findings,
                                "finding_count": findings.len(),
                            });
                            if let Some(modified) = cancel_on_token(
                                cancellation,
                                self.hook_runner.execute(
                                    crate::engine::hook_runner::HookPoint::PostModule,
                                    &module_data,
                                    &self.ctx,
                                ),
                            )
                            .await?
                            {
                                modified["findings"]
                                    .as_array()
                                    .and_then(|array| {
                                        serde_json::from_value::<Vec<Finding>>(
                                            serde_json::Value::Array(array.clone()),
                                        )
                                        .ok()
                                    })
                                    .unwrap_or(findings)
                            } else {
                                findings
                            }
                        } else {
                            findings
                        };

                        for finding in &findings {
                            self.ctx.events.publish(ScanEvent::FindingProduced {
                                scan_id: scan_id.clone(),
                                module_id: module_id.clone(),
                                finding: Box::new(finding.clone()),
                            });
                        }
                        self.ctx.events.publish(ScanEvent::ModuleCompleted {
                            scan_id: scan_id.clone(),
                            module_id: module_id.clone(),
                            findings_count: findings.len(),
                            duration_ms,
                        });
                        if let Some(sink) = &self.job_progress {
                            sink.publish(JobProgressUpdate::Completed {
                                module_id: module_id.clone(),
                                findings: findings.clone(),
                            })?;
                        }
                        modules_run.push(module_id);
                        all_findings.extend(findings);
                    }
                    Err(error) => {
                        let error = error.to_string();
                        self.ctx.events.publish(ScanEvent::ModuleError {
                            scan_id: scan_id.clone(),
                            module_id: module_id.clone(),
                            error: error.clone(),
                        });
                        if let Some(sink) = &self.job_progress {
                            sink.publish(JobProgressUpdate::Failed {
                                module_id: module_id.clone(),
                            })?;
                        }
                        modules_skipped.push((module_id, error));
                    }
                }
            }
        }

        all_findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

        // Fire post-scan hooks
        if self.hook_runner.has_hooks(crate::engine::hook_runner::HookPoint::PostScan) {
            let post_scan_data = serde_json::json!({
                "scan_id": &scan_id,
                "target": self.ctx.target.url.as_str(),
                "total_findings": all_findings.len(),
                "summary": {
                    "critical": all_findings.iter().filter(|f| f.severity == crate::engine::severity::Severity::Critical).count(),
                    "high": all_findings.iter().filter(|f| f.severity == crate::engine::severity::Severity::High).count(),
                },
            });
            let _ = cancel_on_token(
                cancellation,
                self.hook_runner.execute(
                    crate::engine::hook_runner::HookPoint::PostScan,
                    &post_scan_data,
                    &self.ctx,
                ),
            )
            .await?;
        }

        ensure_not_cancelled(cancellation)?;
        let total_duration_ms =
            u64::try_from(scan_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.ctx.events.publish(ScanEvent::ScanCompleted {
            scan_id: scan_id.clone(),
            total_findings: all_findings.len(),
            duration_ms: total_duration_ms,
        });

        Ok(ScanResult::new(
            scan_id,
            self.ctx.target.clone(),
            started_at,
            all_findings,
            modules_run,
            modules_skipped,
        ))
    }

    /// Run all modules with checkpoint support for resume-on-interrupt.
    ///
    /// After each module completes, a checkpoint file is saved. If `resume_from`
    /// is provided, completed modules are skipped and their findings are merged.
    /// The checkpoint file is deleted on successful scan completion.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid execution budgets or a fatal scan error.
    // JUSTIFICATION: Checkpoint logic is a cohesive unit — module loop + checkpoint save + resume display;
    // splitting would scatter the checkpoint lifecycle across multiple functions
    #[allow(clippy::too_many_lines)]
    pub async fn run_with_checkpoint(
        &self,
        quiet: bool,
        checkpoint_path: &std::path::Path,
        resume_from: Option<&super::checkpoint::ScanCheckpoint>,
    ) -> Result<ScanResult> {
        use super::checkpoint;

        let started_at = resume_from.map_or_else(Utc::now, |cp| cp.started_at);
        let scan_started = Instant::now();
        let scan_id =
            resume_from.map_or_else(|| Uuid::new_v4().to_string(), |cp| cp.scan_id.clone());
        let _validated_budget = JobExecutor::from_scan_config(&self.ctx.config.scan)?;

        let _audit_log_handle =
            subscribe_audit_log_if_enabled(&self.ctx.config.audit_log, &self.ctx.events);

        self.ctx.events.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: self.ctx.target.url.as_str().to_string(),
        });

        // Initialize checkpoint state from resume or fresh
        let mut cp = resume_from.map_or_else(
            || {
                let module_ids: Vec<String> =
                    self.modules.iter().map(|m| m.id().to_string()).collect();
                let config_hash = checkpoint::hash_config(
                    &self.ctx.config.scan.profile,
                    &module_ids,
                    self.ctx.target.url.as_str(),
                );
                checkpoint::ScanCheckpoint::new(
                    &scan_id,
                    self.ctx.target.url.as_str(),
                    &self.ctx.config.scan.profile,
                    config_hash,
                )
            },
            Clone::clone,
        );

        let resumed_count = cp.completed_modules.len();
        if progress::has_visible_items(resumed_count, quiet) {
            println!(
                "{} {} module{} already complete from checkpoint",
                "Resuming:".cyan().bold(),
                resumed_count,
                if resumed_count == 1 { "" } else { "s" }
            );
        }

        // Filter to modules that haven't completed yet
        let mut runnable: Vec<&dyn ScanModule> = Vec::new();
        let mut modules_skipped: Vec<(String, String)> = Vec::new();

        for module in &self.modules {
            if cp.is_completed(module.id()) {
                continue; // Already done in previous run
            }
            if let Some(tool) =
                missing_required_tool(module.requires_external_tool(), module.required_tool())
            {
                if progress::is_visible(quiet) {
                    println!(
                        "  {} {} (requires: {})",
                        "SKIP".yellow().bold(),
                        module.name(),
                        tool.dimmed()
                    );
                }
                let reason = format!("external tool '{tool}' not found");
                self.ctx.events.publish(ScanEvent::ModuleSkipped {
                    scan_id: scan_id.clone(),
                    module_id: module.id().to_string(),
                    reason: reason.clone(),
                });
                modules_skipped.push((module.id().to_string(), reason));
                continue;
            }
            runnable.push(module.as_ref());
        }

        if progress::is_visible(quiet) {
            let total = runnable.len() + resumed_count;
            println!(
                "{} {}/{} module{} remaining",
                "Running".bold(),
                runnable.len(),
                total,
                if runnable.len() == 1 { "" } else { "s" }
            );
            println!();
        }

        // Checkpoint mode intentionally remains serial so each completed module is durable before
        // the next begins. SK-029 owns concurrent partial recovery.
        for module in runnable {
            let module_name = module.name().to_string();
            let module_id = module.id().to_string();
            let spinner =
                progress::is_visible(quiet).then(|| progress::module_spinner(&module_name));

            self.ctx.events.publish(ScanEvent::ModuleStarted {
                scan_id: scan_id.clone(),
                module_id: module_id.clone(),
                module_name: module_name.clone(),
            });
            let module_started = Instant::now();

            let result = module.run(&self.ctx).await;
            let duration_ms =
                u64::try_from(module_started.elapsed().as_millis()).unwrap_or(u64::MAX);

            match result {
                Ok(findings) => {
                    if let Some(pb) = &spinner {
                        progress::finish_success(pb, &module_name, findings.len());
                    }
                    for finding in &findings {
                        self.ctx.events.publish(ScanEvent::FindingProduced {
                            scan_id: scan_id.clone(),
                            module_id: module_id.clone(),
                            finding: Box::new(finding.clone()),
                        });
                    }
                    self.ctx.events.publish(ScanEvent::ModuleCompleted {
                        scan_id: scan_id.clone(),
                        module_id: module_id.clone(),
                        findings_count: findings.len(),
                        duration_ms,
                    });
                    cp.record_module(&module_id, &findings);
                    // Save checkpoint after each module
                    let _ = checkpoint::save_checkpoint(&cp, checkpoint_path);
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if let Some(pb) = &spinner {
                        progress::finish_error(pb, &module_name, &err_str);
                    }
                    self.ctx.events.publish(ScanEvent::ModuleError {
                        scan_id: scan_id.clone(),
                        module_id: module_id.clone(),
                        error: err_str.clone(),
                    });
                    modules_skipped.push((module_id, err_str));
                }
            }
        }

        // Scan complete — remove checkpoint file
        checkpoint::remove_checkpoint(checkpoint_path);

        let modules_run = cp.completed_modules.clone();
        let mut all_findings = cp.findings;
        all_findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

        let total_duration_ms =
            u64::try_from(scan_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.ctx.events.publish(ScanEvent::ScanCompleted {
            scan_id: scan_id.clone(),
            total_findings: all_findings.len(),
            duration_ms: total_duration_ms,
        });

        Ok(ScanResult::new(
            scan_id,
            self.ctx.target.clone(),
            started_at,
            all_findings,
            modules_run,
            modules_skipped,
        ))
    }

    /// Run modules in two phases: recon first, then scanners/tools.
    ///
    /// This enables inter-module data sharing — recon modules publish
    /// discovered data (URLs, forms, technologies) that scanner modules
    /// consume via `ScanContext::shared_data`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid execution budgets, caller cancellation, batch deadline, or a
    /// fatal scan error.
    pub async fn run_phased(&mut self, quiet: bool) -> Result<ScanResult> {
        let cancellation = CancellationToken::new();
        self.run_phased_with_cancellation(quiet, &cancellation).await
    }

    /// Run the explicit two-phase DAST mode with caller-controlled cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid execution budgets, caller cancellation, batch deadline, or a
    /// fatal orchestration failure. Individual module failures remain non-fatal outcomes.
    pub async fn run_phased_with_cancellation(
        &mut self,
        quiet: bool,
        cancellation: &CancellationToken,
    ) -> Result<ScanResult> {
        let started_at = Utc::now();
        let scan_started = Instant::now();
        let scan_id = Uuid::new_v4().to_string();
        let executor = JobExecutor::from_scan_config(&self.ctx.config.scan)?;

        let _audit_log_handle =
            subscribe_audit_log_if_enabled(&self.ctx.config.audit_log, &self.ctx.events);

        self.ctx.events.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: self.ctx.target.url.as_str().to_string(),
        });

        // Partition modules into recon and non-recon
        let (recon, scanners): (Vec<_>, Vec<_>) = self
            .modules
            .iter()
            .map(std::convert::AsRef::as_ref)
            .partition(|module| module.category() == ModuleCategory::Recon);

        if progress::is_visible(quiet) {
            println!(
                "{} {} recon + {} scanner module{}",
                "Phased scan:".bold(),
                recon.len(),
                scanners.len(),
                if recon.len() + scanners.len() == 1 { "" } else { "s" }
            );
            println!();
        }

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut modules_run: Vec<String> = Vec::new();
        let mut modules_skipped: Vec<(String, String)> = Vec::new();

        // Phase 1: Run recon modules
        run_module_batch(
            &recon,
            &self.ctx,
            &scan_id,
            quiet,
            &executor,
            cancellation,
            self.job_progress.as_ref(),
            &mut all_findings,
            &mut modules_run,
            &mut modules_skipped,
        )
        .await?;

        if progress::has_visible_items(scanners.len(), quiet) {
            println!(
                "\n{} Recon complete — shared data available for scanners\n",
                ">>>".cyan().bold()
            );
        }

        // Phase 2: Run scanner/tool modules (can read shared data from recon)
        run_module_batch(
            &scanners,
            &self.ctx,
            &scan_id,
            quiet,
            &executor,
            cancellation,
            self.job_progress.as_ref(),
            &mut all_findings,
            &mut modules_run,
            &mut modules_skipped,
        )
        .await?;

        all_findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

        ensure_not_cancelled(cancellation)?;
        let total_duration_ms =
            u64::try_from(scan_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.ctx.events.publish(ScanEvent::ScanCompleted {
            scan_id: scan_id.clone(),
            total_findings: all_findings.len(),
            duration_ms: total_duration_ms,
        });

        Ok(ScanResult::new(
            scan_id,
            self.ctx.target.clone(),
            started_at,
            all_findings,
            modules_run,
            modules_skipped,
        ))
    }
}

struct ModuleExecution {
    module_id: String,
    module_name: String,
    result: Result<Vec<Finding>>,
}

async fn execute_scan_modules<'module>(
    modules: Vec<&'module dyn ScanModule>,
    ctx: &'module ScanContext,
    scan_id: &str,
    quiet: bool,
    executor: &JobExecutor,
    cancellation: &CancellationToken,
    progress_sink: Option<&Arc<dyn JobProgressSink>>,
) -> Result<Vec<JobOutcome<Result<ModuleExecution>>>> {
    let mut jobs = Vec::with_capacity(modules.len());
    for module in modules {
        let scan_id = scan_id.to_string();
        let progress_sink = progress_sink.cloned();
        jobs.push(
            async move {
                let module_name = module.name().to_string();
                let module_id = module.id().to_string();
                if let Some(sink) = &progress_sink {
                    sink.publish(JobProgressUpdate::Started { module_id: module_id.clone() })?;
                }
                let spinner =
                    progress::is_visible(quiet).then(|| progress::module_spinner(&module_name));
                ctx.events.publish(ScanEvent::ModuleStarted {
                    scan_id,
                    module_id: module_id.clone(),
                    module_name: module_name.clone(),
                });
                let result = module.run(ctx).await;
                match &result {
                    Ok(findings) => {
                        if let Some(spinner) = &spinner {
                            progress::finish_success(spinner, &module_name, findings.len());
                        }
                    }
                    Err(error) => {
                        if let Some(spinner) = &spinner {
                            progress::finish_error(spinner, &module_name, &error.to_string());
                        }
                    }
                }
                Ok(ModuleExecution { module_id, module_name, result })
            }
            .boxed(),
        );
    }
    executor.execute(jobs, cancellation).await
}

/// Run a batch of modules concurrently, collecting findings and status.
// JUSTIFICATION: Mutable result accumulators keep phased result/event commits in one helper call.
#[allow(clippy::too_many_arguments)]
async fn run_module_batch(
    modules: &[&dyn ScanModule],
    ctx: &crate::engine::scan_context::ScanContext,
    scan_id: &str,
    quiet: bool,
    executor: &JobExecutor,
    cancellation: &CancellationToken,
    progress_sink: Option<&Arc<dyn JobProgressSink>>,
    findings: &mut Vec<Finding>,
    modules_run: &mut Vec<String>,
    modules_skipped: &mut Vec<(String, String)>,
) -> Result<()> {
    let mut runnable: Vec<&dyn ScanModule> = Vec::new();

    for &module in modules {
        if let Some(tool) =
            missing_required_tool(module.requires_external_tool(), module.required_tool())
        {
            if progress::is_visible(quiet) {
                println!(
                    "  {} {} (requires: {})",
                    "SKIP".yellow().bold(),
                    module.name(),
                    tool.dimmed()
                );
            }
            let reason = format!("external tool '{tool}' not found");
            ctx.events.publish(ScanEvent::ModuleSkipped {
                scan_id: scan_id.to_string(),
                module_id: module.id().to_string(),
                reason: reason.clone(),
            });
            if let Some(sink) = progress_sink {
                sink.publish(JobProgressUpdate::Skipped { module_id: module.id().to_string() })?;
            }
            modules_skipped.push((module.id().to_string(), reason));
            continue;
        }
        runnable.push(module);
    }

    let outcomes =
        execute_scan_modules(runnable, ctx, scan_id, quiet, executor, cancellation, progress_sink)
            .await?;
    for outcome in outcomes {
        let duration_ms = u64::try_from(outcome.duration().as_millis()).unwrap_or(u64::MAX);
        let ModuleExecution { module_id, result, .. } = outcome.into_output()?;

        match result {
            Ok(found) => {
                for finding in &found {
                    ctx.events.publish(ScanEvent::FindingProduced {
                        scan_id: scan_id.to_string(),
                        module_id: module_id.clone(),
                        finding: Box::new(finding.clone()),
                    });
                }
                ctx.events.publish(ScanEvent::ModuleCompleted {
                    scan_id: scan_id.to_string(),
                    module_id: module_id.clone(),
                    findings_count: found.len(),
                    duration_ms,
                });
                if let Some(sink) = progress_sink {
                    sink.publish(JobProgressUpdate::Completed {
                        module_id: module_id.clone(),
                        findings: found.clone(),
                    })?;
                }
                modules_run.push(module_id);
                findings.extend(found);
            }
            Err(e) => {
                let err_str = e.to_string();
                ctx.events.publish(ScanEvent::ModuleError {
                    scan_id: scan_id.to_string(),
                    module_id: module_id.clone(),
                    error: err_str.clone(),
                });
                if let Some(sink) = progress_sink {
                    sink.publish(JobProgressUpdate::Failed { module_id: module_id.clone() })?;
                }
                modules_skipped.push((module_id, err_str));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::engine::events::{subscribe_handler, EventBus, EventHandler, ScanEvent};
    use crate::engine::finding::Finding;
    use crate::engine::module_trait::{ModuleCategory, ScanModule};
    use crate::engine::severity::Severity;
    use crate::engine::target::Target;
    use async_trait::async_trait;
    use std::sync::Mutex;

    #[test]
    fn assessment_profiles_quarantine_credential_and_exploit_modules() {
        let target = Target::parse("https://example.com").expect("parse target");
        let config = Arc::new(AppConfig::default());
        let http_client = reqwest::Client::builder().build().expect("http client");

        let mut standard = Orchestrator::new(ScanContext::new(
            target.clone(),
            Arc::clone(&config),
            http_client.clone(),
            Vec::new(),
        ));
        standard.register_default_modules();
        standard.apply_profile("standard");
        assert!(standard.modules.iter().all(|module| !module.requires_external_tool()));

        let mut thorough = Orchestrator::new(ScanContext::new(
            target.clone(),
            Arc::clone(&config),
            http_client.clone(),
            Vec::new(),
        ));
        thorough.register_default_modules();
        thorough.apply_profile("thorough");
        assert!(thorough
            .modules
            .iter()
            .all(|module| !is_credential_or_exploit_module(module.as_ref())));

        let mut pentest =
            Orchestrator::new(ScanContext::new(target, config, http_client, Vec::new()));
        pentest.register_default_modules();
        pentest.apply_profile("pentest");
        assert!(pentest.modules.iter().any(|module| module.id() == "commix"));
        for compatibility in ["hydra", "kerbrute", "metasploit", "nxc", "smbmap"] {
            assert!(!pentest.modules.iter().any(|module| module.id() == compatibility));
        }
    }

    struct OkModule;

    #[async_trait]
    impl ScanModule for OkModule {
        fn name(&self) -> &'static str {
            "OK"
        }
        fn id(&self) -> &'static str {
            "ok"
        }
        fn category(&self) -> ModuleCategory {
            ModuleCategory::Recon
        }
        fn description(&self) -> &'static str {
            "test module producing one finding"
        }
        async fn run(&self, _ctx: &ScanContext) -> Result<Vec<Finding>> {
            Ok(vec![Finding::new(
                "ok",
                Severity::Low,
                "fixture finding",
                "emitted by test module",
                "https://example.com",
            )])
        }
    }

    struct FixtureModule {
        module_id: &'static str,
        category: ModuleCategory,
        required_tool: Option<&'static str>,
        findings: usize,
    }

    struct SharedDataProducer;

    #[async_trait]
    impl ScanModule for SharedDataProducer {
        fn name(&self) -> &'static str {
            "shared-data producer"
        }

        fn id(&self) -> &'static str {
            "producer"
        }

        fn category(&self) -> ModuleCategory {
            ModuleCategory::Recon
        }

        fn description(&self) -> &'static str {
            "publishes a DAST executor dependency fixture"
        }

        async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            ctx.shared_data.publish(
                crate::engine::shared_data::keys::URLS,
                vec!["https://example.com/produced".to_string()],
            );
            Ok(Vec::new())
        }
    }

    struct SharedDataConsumer;

    #[async_trait]
    impl ScanModule for SharedDataConsumer {
        fn name(&self) -> &'static str {
            "shared-data consumer"
        }

        fn id(&self) -> &'static str {
            "consumer"
        }

        fn category(&self) -> ModuleCategory {
            ModuleCategory::Scanner
        }

        fn description(&self) -> &'static str {
            "reads a DAST executor dependency fixture"
        }

        async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
            let urls = ctx.shared_data.get(crate::engine::shared_data::keys::URLS);
            if urls.is_empty() {
                return Err(crate::engine::error::ScorchError::Config(
                    "scanner ran before recon producer".to_string(),
                ));
            }
            Ok(vec![Finding::new(
                "consumer",
                Severity::Low,
                "producer data observed",
                "scanner observed recon data",
                urls.first().cloned().unwrap_or_default(),
            )])
        }
    }

    #[async_trait]
    impl ScanModule for FixtureModule {
        fn name(&self) -> &'static str {
            "fixture"
        }

        fn id(&self) -> &'static str {
            self.module_id
        }

        fn category(&self) -> ModuleCategory {
            self.category
        }

        fn description(&self) -> &'static str {
            "orchestrator contract fixture"
        }

        async fn run(&self, _ctx: &ScanContext) -> Result<Vec<Finding>> {
            Ok((0..self.findings)
                .map(|index| {
                    Finding::new(
                        self.module_id,
                        Severity::Low,
                        format!("fixture finding {index}"),
                        "fixture",
                        "https://example.com",
                    )
                })
                .collect())
        }

        fn requires_external_tool(&self) -> bool {
            self.required_tool.is_some()
        }

        fn required_tool(&self) -> Option<&str> {
            self.required_tool
        }
    }

    fn fixture_context() -> ScanContext {
        let target = Target::parse("https://example.com").expect("parse target");
        ScanContext::new(target, Arc::new(AppConfig::default()), reqwest::Client::new(), Vec::new())
    }

    fn profile_fixture() -> Orchestrator {
        let mut orchestrator = Orchestrator::new(fixture_context());
        for (module_id, required_tool) in [
            ("headers", None),
            ("tech", Some("scorchkit-profile-tool-that-does-not-exist")),
            ("crawler", None),
            ("commix", Some("commix")),
        ] {
            orchestrator.add_module(Box::new(FixtureModule {
                module_id,
                category: ModuleCategory::Scanner,
                required_tool,
                findings: 0,
            }));
        }
        orchestrator
    }

    fn module_ids(orchestrator: &Orchestrator) -> Vec<&str> {
        orchestrator.modules.iter().map(|module| module.id()).collect()
    }

    #[test]
    fn profile_selection_has_exact_non_vacuous_membership() {
        let modules = all_modules();
        for restricted in ["commix", "hydra", "kerbrute", "metasploit", "nxc", "smbmap"] {
            let module = modules
                .iter()
                .find(|module| module.id() == restricted)
                .unwrap_or_else(|| panic!("missing profile fixture module {restricted}"));
            assert!(is_credential_or_exploit_module(module.as_ref()));
        }
        for allowed in ["headers", "tech", "crawler", "nuclei"] {
            let module = modules
                .iter()
                .find(|module| module.id() == allowed)
                .unwrap_or_else(|| panic!("missing profile fixture module {allowed}"));
            assert!(!is_credential_or_exploit_module(module.as_ref()));
        }

        let mut quick = profile_fixture();
        quick.apply_profile("quick");
        assert_eq!(module_ids(&quick), ["headers"]);

        let mut standard = profile_fixture();
        standard.apply_profile("standard");
        assert_eq!(module_ids(&standard), ["headers", "crawler"]);

        let mut thorough = profile_fixture();
        thorough.apply_profile("thorough");
        assert_eq!(module_ids(&thorough), ["headers", "tech", "crawler"]);

        let mut pentest = profile_fixture();
        pentest.apply_profile("pentest");
        assert_eq!(module_ids(&pentest), ["headers", "tech", "crawler", "commix"]);

        let mut unknown = profile_fixture();
        unknown.apply_profile("unknown");
        assert!(unknown.modules.is_empty());
    }

    #[test]
    fn named_templates_match_their_declared_catalog_sizes() {
        let templates = Orchestrator::list_templates();
        assert_eq!(templates.len(), 8);
        assert_eq!(
            templates.iter().map(|(name, _, _)| *name).collect::<Vec<_>>(),
            ["web-app", "api", "graphql", "wordpress", "spa", "network", "full", "compatibility",]
        );
        for (template, description, expected_count) in templates {
            assert!(!description.is_empty(), "template {template} needs a description");
            let mut orchestrator = Orchestrator::new(fixture_context());
            orchestrator.register_default_modules();
            assert!(orchestrator.apply_template(template), "missing template {template}");
            assert_eq!(orchestrator.module_count(), expected_count, "template {template}");
        }
    }

    #[test]
    fn explicit_module_selection_can_reach_compatibility_catalog() {
        let mut orchestrator = Orchestrator::new(fixture_context());
        orchestrator.register_default_modules();
        orchestrator
            .apply_selection("standard", Some(&["nmap".to_string(), "metasploit".to_string()]));
        let selected = module_ids(&orchestrator);
        assert_eq!(selected.len(), 2);
        assert!(selected.contains(&"nmap"));
        assert!(selected.contains(&"metasploit"));

        let mut unknown = Orchestrator::new(fixture_context());
        unknown.register_default_modules();
        unknown.apply_selection("unknown", Some(&["nmap".to_string()]));
        assert_eq!(unknown.module_count(), 0);
    }

    #[tokio::test]
    async fn every_dast_execution_mode_records_missing_tools_and_runnable_modules() {
        let missing = || {
            Box::new(FixtureModule {
                module_id: "missing",
                category: ModuleCategory::Recon,
                required_tool: Some("scorchkit-orchestrator-tool-that-does-not-exist"),
                findings: 1,
            }) as Box<dyn ScanModule>
        };

        let mut normal = Orchestrator::new(fixture_context());
        normal.add_module(missing());
        let normal_result = normal.run(true).await.expect("normal scan");
        assert!(normal_result.modules_run.is_empty());
        assert_eq!(normal_result.modules_skipped.len(), 1);
        assert_eq!(normal_result.modules_skipped[0].0, "missing");

        let checkpoint_dir = tempfile::tempdir().expect("checkpoint directory");
        let checkpoint_path = checkpoint_dir.path().join("scan.json");
        let mut checkpointed = Orchestrator::new(fixture_context());
        checkpointed.add_module(missing());
        let checkpoint_result = checkpointed
            .run_with_checkpoint(true, &checkpoint_path, None)
            .await
            .expect("checkpoint scan");
        assert!(checkpoint_result.modules_run.is_empty());
        assert_eq!(checkpoint_result.modules_skipped.len(), 1);
        assert_eq!(checkpoint_result.modules_skipped[0].0, "missing");

        let mut phased = Orchestrator::new(fixture_context());
        phased.add_module(missing());
        phased.add_module(Box::new(FixtureModule {
            module_id: "runnable",
            category: ModuleCategory::Scanner,
            required_tool: None,
            findings: 1,
        }));
        let phased_result = phased.run_phased(true).await.expect("phased scan");
        assert_eq!(phased_result.modules_run, ["runnable"]);
        assert_eq!(phased_result.modules_skipped.len(), 1);
        assert_eq!(phased_result.modules_skipped[0].0, "missing");
        assert_eq!(phased_result.findings.len(), 1);
    }

    #[tokio::test]
    async fn standard_dast_run_finishes_recon_before_scanner_consumers() {
        let mut orchestrator = Orchestrator::new(fixture_context());
        // Register the consumer first to prove category phases, not insertion order, provide the
        // dependency barrier.
        orchestrator.add_module(Box::new(SharedDataConsumer));
        orchestrator.add_module(Box::new(SharedDataProducer));

        let result = orchestrator.run(true).await.expect("dependency-aware DAST scan");

        assert_eq!(result.modules_run, ["producer", "consumer"]);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].module_id, "consumer");
    }

    #[tokio::test]
    async fn explicit_phased_dast_run_finishes_recon_before_scanner_consumers() {
        let mut orchestrator = Orchestrator::new(fixture_context());
        // Register the consumer first so reversing the explicit phase partition is observable.
        orchestrator.add_module(Box::new(SharedDataConsumer));
        orchestrator.add_module(Box::new(SharedDataProducer));

        let result = orchestrator.run_phased(true).await.expect("explicit phased DAST scan");

        assert_eq!(result.modules_run, ["producer", "consumer"]);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].module_id, "consumer");
    }

    struct CollectingHandler {
        events: Arc<Mutex<Vec<ScanEvent>>>,
    }

    #[async_trait]
    impl EventHandler for CollectingHandler {
        async fn handle(&self, event: ScanEvent) -> std::result::Result<(), String> {
            self.events.lock().map_err(|e| e.to_string())?.push(event);
            Ok(())
        }
    }

    fn discriminant(event: &ScanEvent) -> &'static str {
        match event {
            ScanEvent::ScanStarted { .. } => "ScanStarted",
            ScanEvent::ModuleStarted { .. } => "ModuleStarted",
            ScanEvent::ModuleCompleted { .. } => "ModuleCompleted",
            ScanEvent::ModuleSkipped { .. } => "ModuleSkipped",
            ScanEvent::ModuleError { .. } => "ModuleError",
            ScanEvent::FindingProduced { .. } => "FindingProduced",
            ScanEvent::ScanCompleted { .. } => "ScanCompleted",
            ScanEvent::Custom { .. } => "Custom",
        }
    }

    /// Regression test #6: Orchestrator emits the expected lifecycle event
    /// sequence when running a single test module.
    #[tokio::test]
    async fn test_orchestrator_emits_scan_events() {
        let target = Target::parse("https://example.com").expect("parse target");
        let config = Arc::new(AppConfig::default());
        let http_client = reqwest::Client::builder().build().expect("http client");
        let ctx = ScanContext::new(target, config, http_client, Vec::new());

        let collected: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<dyn EventHandler> =
            Arc::new(CollectingHandler { events: collected.clone() });
        let bus: EventBus = ctx.events.clone();
        let join = subscribe_handler(&bus, handler);

        let mut orch = Orchestrator::new(ctx);
        orch.modules.push(Box::new(OkModule));

        let result = orch.run(true).await.expect("scan");
        assert_eq!(result.findings.len(), 1);

        // Drop the bus on the orchestrator side so the handler loop exits.
        drop(orch);
        drop(bus);
        join.await.expect("handler join");

        let events = collected.lock().expect("lock");
        let names: Vec<&str> = events.iter().map(discriminant).collect();
        assert_eq!(
            names,
            vec![
                "ScanStarted",
                "ModuleStarted",
                "FindingProduced",
                "ModuleCompleted",
                "ScanCompleted",
            ],
            "event sequence"
        );
        drop(events);
    }
}
