use std::sync::Arc;

use chrono::Utc;
use colored::Colorize;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::engine::error::Result;
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
}

impl Orchestrator {
    #[must_use]
    pub fn new(ctx: ScanContext) -> Self {
        Self { ctx, modules: Vec::new() }
    }

    pub fn register_default_modules(&mut self) {
        self.modules = all_modules();

        // Load user-defined plugins if configured
        if let Some(ref plugins_dir) = self.ctx.config.scan.plugins_dir {
            let plugins = super::plugin::load_plugins(plugins_dir);
            self.modules.extend(plugins);
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
    pub async fn run(&self, quiet: bool) -> Result<ScanResult> {
        let started_at = Utc::now();
        let scan_id = Uuid::new_v4().to_string();
        let max_concurrent = self.ctx.config.scan.max_concurrent_modules;

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
                        modules_skipped.push((
                            module.id().to_string(),
                            format!("external tool '{tool}' not found"),
                        ));
                        continue;
                    }
                }
            }
            runnable.push(module.as_ref());
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

            // Run the module
            let result = module.run(ctx).await;
            drop(permit);

            match result {
                Ok(findings) => {
                    if let Some(pb) = &spinner {
                        progress::finish_success(pb, &module_name, findings.len());
                    }
                    handles.push((module_id, Ok(findings)));
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if let Some(pb) = &spinner {
                        progress::finish_error(pb, &module_name, &err_str);
                    }
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
        let scan_id =
            resume_from.map_or_else(|| Uuid::new_v4().to_string(), |cp| cp.scan_id.clone());
        let max_concurrent = self.ctx.config.scan.max_concurrent_modules;

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
                        modules_skipped.push((
                            module.id().to_string(),
                            format!("external tool '{tool}' not found"),
                        ));
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

            let result = module.run(ctx).await;
            drop(permit);

            match result {
                Ok(findings) => {
                    if let Some(pb) = &spinner {
                        progress::finish_success(pb, &module_name, findings.len());
                    }
                    cp.record_module(&module_id, &findings);
                    // Save checkpoint after each module
                    let _ = checkpoint::save_checkpoint(&cp, checkpoint_path);
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if let Some(pb) = &spinner {
                        progress::finish_error(pb, &module_name, &err_str);
                    }
                    modules_skipped.push((module_id, err_str));
                }
            }
        }

        // Scan complete — remove checkpoint file
        checkpoint::remove_checkpoint(checkpoint_path);

        let modules_run = cp.completed_modules.clone();
        let mut all_findings = cp.findings;
        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

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
        let scan_id = Uuid::new_v4().to_string();
        let max_concurrent = self.ctx.config.scan.max_concurrent_modules;

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
            max_concurrent,
            quiet,
            &mut all_findings,
            &mut modules_run,
            &mut modules_skipped,
        )
        .await?;

        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

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
#[allow(clippy::borrowed_box)]
async fn run_module_batch(
    modules: &[&Box<dyn ScanModule>],
    ctx: &crate::engine::scan_context::ScanContext,
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
                    modules_skipped.push((
                        module.id().to_string(),
                        format!("external tool '{tool}' not found"),
                    ));
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

        let result = module.run(ctx).await;
        drop(permit);

        match result {
            Ok(found) => {
                if let Some(pb) = &spinner {
                    progress::finish_success(pb, &module_name, found.len());
                }
                modules_run.push(module_id);
                findings.extend(found);
            }
            Err(e) => {
                let err_str = e.to_string();
                if let Some(pb) = &spinner {
                    progress::finish_error(pb, &module_name, &err_str);
                }
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
