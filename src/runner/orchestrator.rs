use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use colored::Colorize;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::engine::audit_log::subscribe_audit_log_if_enabled;
use crate::engine::error::Result;
use crate::engine::events::ScanEvent;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::scan_result::ScanResult;
use crate::runner::progress;

/// Returns all available modules (recon + scanner + external tools).
#[must_use]
pub fn all_modules() -> Vec<Box<dyn ScanModule>> {
    let mut modules: Vec<Box<dyn ScanModule>> = Vec::new();
    modules.extend(crate::recon::register_modules());
    modules.extend(crate::scanner::register_modules());
    modules.extend(crate::tools::register_modules());
    modules
}

/// Orchestrates scan module execution with concurrency control.
pub struct Orchestrator {
    ctx: ScanContext,
    modules: Vec<Box<dyn ScanModule>>,
    hook_runner: Option<crate::engine::hook_runner::HookRunner>,
}

impl Orchestrator {
    #[must_use]
    pub fn new(ctx: ScanContext) -> Self {
        Self { ctx, modules: Vec::new(), hook_runner: None }
    }

    /// Set the hook runner for lifecycle hooks.
    pub fn set_hook_runner(&mut self, runner: crate::engine::hook_runner::HookRunner) {
        self.hook_runner = Some(runner);
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

    pub fn filter_by_category(&mut self, category: ModuleCategory) {
        self.modules.retain(|m| m.category() == category);
    }

    pub fn filter_by_ids(&mut self, ids: &[String]) {
        self.modules.retain(|m| ids.iter().any(|id| id == m.id()));
    }

    pub fn exclude_by_ids(&mut self, ids: &[String]) {
        self.modules.retain(|m| !ids.iter().any(|id| id == m.id()));
    }

    /// Filter modules by scan profile.
    pub fn apply_profile(&mut self, profile: &str) {
        if profile == "quick" {
            // Quick: only fast built-in modules
            self.modules.retain(|m| {
                !m.requires_external_tool()
                    && matches!(m.id(), "headers" | "tech" | "ssl" | "misconfig")
            });
        }
        // Thorough and standard: keep all modules (default behavior)
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
                "auth",
                "upload",
                "clickjacking",
                "cors",
                "csp",
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
                "api",
                "api_schema",
                "cors",
                "jwt",
                "ratelimit",
                "auth",
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
                "cors",
                "jwt",
                "auth",
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
                "cors",
                "csp",
                "dom_xss",
                "js_analysis",
                "xss",
                "api",
                "jwt",
                "clickjacking",
                "sensitive",
                "crawler",
            ],
            "network" => &[
                "ssl",
                "headers",
                "dns",
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
            "full" => &[], // Empty means keep all — same as thorough
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
            ("full", "All modules (same as --profile thorough)", 77),
        ]
    }

    /// Run all registered modules concurrently (up to `max_concurrent_modules`).
    ///
    /// # Errors
    ///
    /// Returns an error if the semaphore is closed or a fatal scan error occurs.
    // JUSTIFICATION: Hook integration at pre-scan, post-module, and post-scan points
    // adds necessary lifecycle instrumentation that is cohesive within the run loop
    #[allow(clippy::too_many_lines)]
    pub async fn run(&self, quiet: bool) -> Result<ScanResult> {
        let started_at = Utc::now();
        let scan_started = Instant::now();
        let scan_id = Uuid::new_v4().to_string();
        let max_concurrent = self.ctx.config.scan.max_concurrent_modules;

        // Wire the built-in audit-log handler before the first publish so no
        // lifecycle events are lost. The JoinHandle is dropped (tokio detaches).
        let _audit_log_handle =
            subscribe_audit_log_if_enabled(&self.ctx.config.audit_log, &self.ctx.events);

        self.ctx.events.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: self.ctx.target.url.as_str().to_string(),
        });

        if !quiet {
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
            if module.requires_external_tool() {
                if let Some(tool) = module.required_tool() {
                    if !is_tool_installed(tool) {
                        if !quiet {
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
                }
            }
            runnable.push(module.as_ref());
        }

        // Fire pre-scan hooks
        if let Some(ref runner) = self.hook_runner {
            if runner.has_hooks(crate::engine::hook_runner::HookPoint::PreScan) {
                let module_ids: Vec<&str> = runnable.iter().map(|m| m.id()).collect();
                let pre_scan_data = serde_json::json!({
                    "target": self.ctx.target.url.as_str(),
                    "profile": self.ctx.config.scan.profile,
                    "modules": module_ids,
                });
                // Pre-scan hooks can modify data but we don't apply changes in v1
                // (future: parse modified modules list)
                let _ = runner
                    .execute(crate::engine::hook_runner::HookPoint::PreScan, &pre_scan_data)
                    .await;
            }
        }

        // Run modules concurrently with semaphore
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let ctx = &self.ctx;
        let mut handles = Vec::new();

        for module in runnable {
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
                crate::engine::error::ScorchError::Cancelled {
                    reason: format!("semaphore error: {e}"),
                }
            })?;

            let module_name = module.name().to_string();
            let module_id = module.id().to_string();

            let spinner = if quiet { None } else { Some(progress::module_spinner(&module_name)) };

            self.ctx.events.publish(ScanEvent::ModuleStarted {
                scan_id: scan_id.clone(),
                module_id: module_id.clone(),
                module_name: module_name.clone(),
            });
            let module_started = Instant::now();

            // Run the module
            let result = module.run(ctx).await;
            drop(permit);
            let duration_ms =
                u64::try_from(module_started.elapsed().as_millis()).unwrap_or(u64::MAX);

            match result {
                Ok(findings) => {
                    if let Some(pb) = &spinner {
                        progress::finish_success(pb, &module_name, findings.len());
                    }

                    // Fire post-module hooks
                    let findings = if let Some(ref runner) = self.hook_runner {
                        if runner.has_hooks(crate::engine::hook_runner::HookPoint::PostModule) {
                            let module_data = serde_json::json!({
                                "module_id": &module_id,
                                "module_name": &module_name,
                                "findings": &findings,
                                "finding_count": findings.len(),
                            });
                            if let Some(modified) = runner
                                .execute(
                                    crate::engine::hook_runner::HookPoint::PostModule,
                                    &module_data,
                                )
                                .await
                            {
                                // Try to extract modified findings
                                modified["findings"]
                                    .as_array()
                                    .and_then(|arr| {
                                        serde_json::from_value::<Vec<Finding>>(
                                            serde_json::Value::Array(arr.clone()),
                                        )
                                        .ok()
                                    })
                                    .unwrap_or(findings)
                            } else {
                                findings
                            }
                        } else {
                            findings
                        }
                    } else {
                        findings
                    };

                    // Emit one FindingProduced event per finding, then ModuleCompleted.
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

                    handles.push((module_id, Ok(findings)));
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
                    handles.push((module_id, Err(err_str)));
                }
            }
        }

        // Collect results
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut modules_run: Vec<String> = Vec::new();

        for (module_id, result) in handles {
            match result {
                Ok(findings) => {
                    modules_run.push(module_id);
                    all_findings.extend(findings);
                }
                Err(err_str) => {
                    modules_skipped.push((module_id, err_str));
                }
            }
        }

        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        // Fire post-scan hooks
        if let Some(ref runner) = self.hook_runner {
            if runner.has_hooks(crate::engine::hook_runner::HookPoint::PostScan) {
                let post_scan_data = serde_json::json!({
                    "scan_id": &scan_id,
                    "target": self.ctx.target.url.as_str(),
                    "total_findings": all_findings.len(),
                    "summary": {
                        "critical": all_findings.iter().filter(|f| f.severity == crate::engine::severity::Severity::Critical).count(),
                        "high": all_findings.iter().filter(|f| f.severity == crate::engine::severity::Severity::High).count(),
                    },
                });
                let _ = runner
                    .execute(crate::engine::hook_runner::HookPoint::PostScan, &post_scan_data)
                    .await;
            }
        }

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
    /// Returns an error if the semaphore is closed or a fatal scan error occurs.
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
        let max_concurrent = self.ctx.config.scan.max_concurrent_modules;

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
        if resumed_count > 0 && !quiet {
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
            if module.requires_external_tool() {
                if let Some(tool) = module.required_tool() {
                    if !is_tool_installed(tool) {
                        if !quiet {
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
                }
            }
            runnable.push(module.as_ref());
        }

        if !quiet {
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

        // Run remaining modules with semaphore
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let ctx = &self.ctx;

        for module in runnable {
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
                crate::engine::error::ScorchError::Cancelled {
                    reason: format!("semaphore error: {e}"),
                }
            })?;

            let module_name = module.name().to_string();
            let module_id = module.id().to_string();
            let spinner = if quiet { None } else { Some(progress::module_spinner(&module_name)) };

            self.ctx.events.publish(ScanEvent::ModuleStarted {
                scan_id: scan_id.clone(),
                module_id: module_id.clone(),
                module_name: module_name.clone(),
            });
            let module_started = Instant::now();

            let result = module.run(ctx).await;
            drop(permit);
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
        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

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
    /// Returns an error if the semaphore is closed or a fatal scan error occurs.
    pub async fn run_phased(&mut self, quiet: bool) -> Result<ScanResult> {
        let started_at = Utc::now();
        let scan_started = Instant::now();
        let scan_id = Uuid::new_v4().to_string();
        let max_concurrent = self.ctx.config.scan.max_concurrent_modules;

        let _audit_log_handle =
            subscribe_audit_log_if_enabled(&self.ctx.config.audit_log, &self.ctx.events);

        self.ctx.events.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: self.ctx.target.url.as_str().to_string(),
        });

        // Partition modules into recon and non-recon
        let (recon, scanners): (Vec<_>, Vec<_>) =
            self.modules.iter().partition(|m| m.category() == ModuleCategory::Recon);

        if !quiet {
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
            max_concurrent,
            quiet,
            &mut all_findings,
            &mut modules_run,
            &mut modules_skipped,
        )
        .await?;

        if !quiet && !scanners.is_empty() {
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
            max_concurrent,
            quiet,
            &mut all_findings,
            &mut modules_run,
            &mut modules_skipped,
        )
        .await?;

        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

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

/// Run a batch of modules concurrently, collecting findings and status.
// JUSTIFICATION: Vec<Box<dyn ScanModule>> is the module storage type; &[&Box] is natural for partitioned references
#[allow(clippy::borrowed_box, clippy::too_many_arguments)]
async fn run_module_batch(
    modules: &[&Box<dyn ScanModule>],
    ctx: &crate::engine::scan_context::ScanContext,
    scan_id: &str,
    max_concurrent: usize,
    quiet: bool,
    findings: &mut Vec<Finding>,
    modules_run: &mut Vec<String>,
    modules_skipped: &mut Vec<(String, String)>,
) -> Result<()> {
    let semaphore = Arc::new(Semaphore::new(max_concurrent));

    for module in modules {
        if module.requires_external_tool() {
            if let Some(tool) = module.required_tool() {
                if !is_tool_installed(tool) {
                    if !quiet {
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
                    modules_skipped.push((module.id().to_string(), reason));
                    continue;
                }
            }
        }

        let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
            crate::engine::error::ScorchError::Cancelled { reason: format!("semaphore error: {e}") }
        })?;

        let module_name = module.name().to_string();
        let module_id = module.id().to_string();
        let spinner = if quiet { None } else { Some(progress::module_spinner(&module_name)) };

        ctx.events.publish(ScanEvent::ModuleStarted {
            scan_id: scan_id.to_string(),
            module_id: module_id.clone(),
            module_name: module_name.clone(),
        });
        let module_started = Instant::now();

        let result = module.run(ctx).await;
        drop(permit);
        let duration_ms = u64::try_from(module_started.elapsed().as_millis()).unwrap_or(u64::MAX);

        match result {
            Ok(found) => {
                if let Some(pb) = &spinner {
                    progress::finish_success(pb, &module_name, found.len());
                }
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
                modules_run.push(module_id);
                findings.extend(found);
            }
            Err(e) => {
                let err_str = e.to_string();
                if let Some(pb) = &spinner {
                    progress::finish_error(pb, &module_name, &err_str);
                }
                ctx.events.publish(ScanEvent::ModuleError {
                    scan_id: scan_id.to_string(),
                    module_id: module_id.clone(),
                    error: err_str.clone(),
                });
                modules_skipped.push((module_id, err_str));
            }
        }
    }

    Ok(())
}

fn is_tool_installed(tool: &str) -> bool {
    std::process::Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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

    struct OkModule;

    #[async_trait]
    impl ScanModule for OkModule {
        fn name(&self) -> &str {
            "OK"
        }
        fn id(&self) -> &str {
            "ok"
        }
        fn category(&self) -> ModuleCategory {
            ModuleCategory::Recon
        }
        fn description(&self) -> &str {
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
        let ctx = ScanContext::new(target, config, http_client);

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
    }
}
