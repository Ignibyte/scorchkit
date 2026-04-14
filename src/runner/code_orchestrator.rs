//! Code scanning orchestrator — concurrent execution of SAST modules.
//!
//! Mirrors the DAST `Orchestrator` but operates on `CodeModule` trait objects
//! with `CodeContext` instead of `ScanModule` with `ScanContext`.

use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use colored::Colorize;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::engine::audit_log::subscribe_audit_log_if_enabled;
use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::events::ScanEvent;
use crate::engine::finding::Finding;
use crate::engine::scan_result::{ScanResult, ScanSummary};
use crate::engine::target::Target;
use crate::runner::progress;

/// Returns all registered code analysis modules.
#[must_use]
pub fn all_code_modules() -> Vec<Box<dyn CodeModule>> {
    let mut modules: Vec<Box<dyn CodeModule>> = Vec::new();
    modules.extend(crate::sast::register_modules());
    modules.extend(crate::sast_tools::register_modules());
    modules
}

/// Orchestrates code module execution with concurrency control.
pub struct CodeOrchestrator {
    /// Code scanning context.
    ctx: CodeContext,
    /// Registered code modules.
    modules: Vec<Box<dyn CodeModule>>,
    /// Optional lifecycle hook runner.
    hook_runner: Option<crate::engine::hook_runner::HookRunner>,
}

impl CodeOrchestrator {
    /// Create a new code orchestrator.
    #[must_use]
    pub fn new(ctx: CodeContext) -> Self {
        Self { ctx, modules: Vec::new(), hook_runner: None }
    }

    /// Set the hook runner for lifecycle hooks.
    pub fn set_hook_runner(&mut self, runner: crate::engine::hook_runner::HookRunner) {
        self.hook_runner = Some(runner);
    }

    /// Register all available code analysis modules.
    pub fn register_default_modules(&mut self) {
        self.modules = all_code_modules();
    }

    /// Filter modules to only those matching the given category.
    pub fn filter_by_category(&mut self, category: CodeCategory) {
        self.modules.retain(|m| m.category() == category);
    }

    /// Keep only modules with IDs in the given list.
    pub fn filter_by_ids(&mut self, ids: &[String]) {
        self.modules.retain(|m| ids.iter().any(|id| id == m.id()));
    }

    /// Remove modules with IDs in the given list.
    pub fn exclude_by_ids(&mut self, ids: &[String]) {
        self.modules.retain(|m| !ids.iter().any(|id| id == m.id()));
    }

    /// Filter modules to those supporting the given language.
    ///
    /// Modules with an empty `languages()` list are considered language-agnostic
    /// and are always retained.
    pub fn filter_by_language(&mut self, language: &str) {
        self.modules.retain(|m| {
            let langs = m.languages();
            langs.is_empty() || langs.iter().any(|l| l.eq_ignore_ascii_case(language))
        });
    }

    /// Apply a code scan profile.
    ///
    /// - `quick`: secrets + SCA only (Gitleaks + OSV-Scanner)
    /// - `standard`: all modules (default)
    /// - `thorough`: all modules
    pub fn apply_profile(&mut self, profile: &str) {
        if profile == "quick" {
            self.modules
                .retain(|m| matches!(m.category(), CodeCategory::Secrets | CodeCategory::Sca));
        }
    }

    /// Run all registered modules and collect findings.
    ///
    /// # Errors
    ///
    /// Returns an error if the target path cannot be converted to a Target.
    // JUSTIFICATION: Event emission at scan start, module start, module complete,
    // module error, and scan complete adds necessary lifecycle instrumentation
    // that is cohesive within the run loop and not worth splitting.
    #[allow(clippy::too_many_lines)]
    pub async fn run(&self) -> Result<ScanResult> {
        let started_at = Utc::now();
        let scan_started = Instant::now();
        let scan_id = Uuid::new_v4().to_string();
        let max_concurrent = self.ctx.config.scan.max_concurrent_modules;
        let semaphore = Arc::new(Semaphore::new(max_concurrent));

        let _audit_log_handle =
            subscribe_audit_log_if_enabled(&self.ctx.config.audit_log, &self.ctx.events);

        self.ctx.events.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: self.ctx.path.display().to_string(),
        });

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut modules_run: Vec<String> = Vec::new();
        let mut modules_skipped: Vec<(String, String)> = Vec::new();

        // Check tool availability and filter
        let mut runnable: Vec<&dyn CodeModule> = Vec::new();
        for module in &self.modules {
            if module.requires_external_tool() {
                if let Some(tool) = module.required_tool() {
                    if !crate::cli::doctor::is_tool_available(tool) {
                        println!(
                            "  {} {} (requires: {})",
                            "SKIP".yellow().bold(),
                            module.name(),
                            tool.dimmed()
                        );
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

        let total = runnable.len();

        if total == 0 {
            println!(
                "{}",
                "No code analysis modules available. Install semgrep, osv-scanner, or gitleaks."
                    .yellow()
            );
        } else {
            println!(
                "{} {} code analysis module{}",
                "Running".bold(),
                total,
                if total == 1 { "" } else { "s" }
            );
            println!();
        }

        // Run modules with semaphore
        for module in runnable {
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
                crate::engine::error::ScorchError::Cancelled {
                    reason: format!("semaphore error: {e}"),
                }
            })?;

            let module_name = module.name().to_string();
            let module_id = module.id().to_string();

            let spinner = progress::module_spinner(&module_name);

            self.ctx.events.publish(ScanEvent::ModuleStarted {
                scan_id: scan_id.clone(),
                module_id: module_id.clone(),
                module_name: module_name.clone(),
            });
            let module_started = Instant::now();

            let result = module.run(&self.ctx).await;
            drop(permit);
            let duration_ms =
                u64::try_from(module_started.elapsed().as_millis()).unwrap_or(u64::MAX);

            match result {
                Ok(findings) => {
                    progress::finish_success(&spinner, &module_name, findings.len());
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
                    all_findings.extend(findings);
                    modules_run.push(module_id);
                }
                Err(e) => {
                    let err_str = e.to_string();
                    progress::finish_error(&spinner, &module_name, &err_str);
                    self.ctx.events.publish(ScanEvent::ModuleError {
                        scan_id: scan_id.clone(),
                        module_id: module_id.clone(),
                        error: err_str.clone(),
                    });
                    modules_skipped.push((module_id, err_str));
                }
            }
        }

        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        let target = Target::from_path(&self.ctx.path)?;
        let summary = ScanSummary::from_findings(&all_findings);

        let total_duration_ms =
            u64::try_from(scan_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.ctx.events.publish(ScanEvent::ScanCompleted {
            scan_id: scan_id.clone(),
            total_findings: all_findings.len(),
            duration_ms: total_duration_ms,
        });

        Ok(ScanResult {
            scan_id,
            target,
            started_at,
            completed_at: Utc::now(),
            findings: all_findings,
            modules_run,
            modules_skipped,
            summary,
        })
    }
}
