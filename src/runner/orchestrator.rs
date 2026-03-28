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
        match profile {
            "quick" => {
                // Quick: only fast built-in modules
                self.modules.retain(|m| {
                    !m.requires_external_tool()
                        && matches!(m.id(), "headers" | "tech" | "ssl" | "misconfig")
                });
            }
            "thorough" => {
                // Thorough: keep everything
            }
            _ => {
                // Standard: built-in + available external tools (default behavior)
            }
        }
    }

    /// Run all registered modules concurrently (up to max_concurrent_modules).
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
}

fn is_tool_installed(tool: &str) -> bool {
    std::process::Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
