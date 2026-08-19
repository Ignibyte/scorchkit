//! Code scanning orchestrator — concurrent execution of SAST modules.
//!
//! Mirrors the DAST `Orchestrator` but operates on `CodeModule` trait objects
//! with `CodeContext` instead of `ScanModule` with `ScanContext`.

use std::time::Instant;

use chrono::Utc;
use colored::Colorize;
use futures_util::FutureExt;
use uuid::Uuid;

use crate::engine::audit_log::subscribe_audit_log_if_enabled;
use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::events::ScanEvent;
use crate::engine::finding::Finding;
use crate::engine::scan_result::{ScanResult, ScanSummary};
use crate::engine::target::Target;
use crate::runner::job_executor::{
    cancel_on_token, ensure_not_cancelled, CancellationToken, JobExecutor,
};
use crate::runner::progress;
use crate::runner::subprocess::missing_required_tool;

/// Returns all registered code analysis modules.
#[must_use]
pub fn all_code_modules() -> Vec<Box<dyn CodeModule>> {
    let mut modules: Vec<Box<dyn CodeModule>> = Vec::new();
    modules.extend(crate::sast::register_modules());
    modules.extend(crate::sast_tools::register_modules());
    modules
}

/// Return code modules in the default application-security catalog.
#[must_use]
pub fn application_code_modules() -> Vec<Box<dyn CodeModule>> {
    all_code_modules()
        .into_iter()
        .filter(|module| module.descriptor().adapter.is_application_security())
        .collect()
}

/// Return code modules retained only for explicit compatibility use.
#[must_use]
pub fn compatibility_code_modules() -> Vec<Box<dyn CodeModule>> {
    all_code_modules()
        .into_iter()
        .filter(|module| !module.descriptor().adapter.is_application_security())
        .collect()
}

/// Orchestrates code module execution with concurrency control.
pub struct CodeOrchestrator {
    /// Code scanning context.
    ctx: CodeContext,
    /// Registered code modules.
    modules: Vec<Box<dyn CodeModule>>,
    /// Lifecycle hook runner, automatically derived from context configuration.
    hook_runner: crate::engine::hook_runner::HookRunner,
}

impl CodeOrchestrator {
    /// Create a new code orchestrator.
    #[must_use]
    pub fn new(ctx: CodeContext) -> Self {
        let hook_runner = crate::engine::hook_runner::HookRunner::new(&ctx.config.hooks);
        Self { ctx, modules: Vec::new(), hook_runner }
    }

    /// Register all available code analysis modules.
    pub fn register_default_modules(&mut self) {
        self.modules = all_code_modules();
    }

    /// Add one trusted module to this policy-sealed code runner.
    pub fn add_module(&mut self, module: Box<dyn CodeModule>) {
        self.modules.push(module);
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
    /// - `standard`: all application code modules (default)
    /// - `thorough`: all application code modules
    /// - `pentest`: all application code modules
    pub fn apply_profile(&mut self, profile: &str) {
        if !matches!(profile, "quick" | "standard" | "thorough" | "pentest") {
            self.modules.clear();
            return;
        }
        self.modules.retain(|module| module.descriptor().adapter.is_application_security());
        if profile == "quick" {
            self.modules
                .retain(|m| matches!(m.category(), CodeCategory::Secrets | CodeCategory::Sca));
        }
    }

    /// Run all registered modules without writing terminal progress.
    ///
    /// # Errors
    ///
    /// Returns an error if the target path cannot be converted to a Target.
    pub async fn run(&self) -> Result<ScanResult> {
        let cancellation = CancellationToken::new();
        self.run_with_cancellation(&cancellation).await
    }

    /// Run all registered modules with caller-controlled cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error if the target path cannot be converted to a target, the caller cancels,
    /// the batch exceeds its wall-time budget, or a fatal hook error occurs.
    pub async fn run_with_cancellation(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<ScanResult> {
        self.run_quiet_with_cancellation(true, cancellation).await
    }

    /// Run registered modules while optionally suppressing terminal progress.
    ///
    /// Events and the returned result are identical in quiet mode. This keeps
    /// library and combined-assessment execution independent of terminal output.
    ///
    /// # Errors
    ///
    /// Returns an error if the target path cannot be converted to a target or a fatal hook or
    /// orchestration error occurs.
    // JUSTIFICATION: Event emission at scan start, module start, module complete,
    // module error, and scan complete adds necessary lifecycle instrumentation
    // that is cohesive within the run loop and not worth splitting.
    #[allow(clippy::too_many_lines)]
    pub async fn run_quiet(&self, quiet: bool) -> Result<ScanResult> {
        let cancellation = CancellationToken::new();
        self.run_quiet_with_cancellation(quiet, &cancellation).await
    }

    /// Run registered modules with explicit terminal visibility and cancellation control.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration is invalid, the caller cancels, the batch exceeds its
    /// wall-time budget, target conversion fails, or a fatal hook error occurs.
    // JUSTIFICATION: Hook integration and deterministic result commits share scan-owned state;
    // splitting them would duplicate or obscure the lifecycle contract.
    #[allow(clippy::too_many_lines)]
    pub async fn run_quiet_with_cancellation(
        &self,
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
            target: self.ctx.path.display().to_string(),
        });

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut modules_run: Vec<String> = Vec::new();
        let mut modules_skipped: Vec<(String, String)> = Vec::new();

        // Check tool availability and filter
        let mut runnable: Vec<&dyn CodeModule> = Vec::new();
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
                modules_skipped.push((module.id().to_string(), reason));
                continue;
            }
            runnable.push(module.as_ref());
        }

        let total = runnable.len();

        if progress::has_no_visible_items(total, quiet) {
            println!(
                "{}",
                "No code analysis modules available. Install semgrep, osv-scanner, or gitleaks."
                    .yellow()
            );
        } else if progress::has_visible_items(total, quiet) {
            println!(
                "{} {} code analysis module{}",
                "Running".bold(),
                total,
                if total == 1 { "" } else { "s" }
            );
            println!();
        }

        if self.hook_runner.has_hooks(crate::engine::hook_runner::HookPoint::PreScan) {
            let module_ids: Vec<&str> = runnable.iter().map(|module| module.id()).collect();
            let pre_scan_data = serde_json::json!({
                "target": self.ctx.path.display().to_string(),
                "modules": module_ids,
            });
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

        let ctx = &self.ctx;
        let mut jobs = Vec::with_capacity(runnable.len());
        for module in runnable {
            let scan_id = scan_id.clone();
            jobs.push(
                async move {
                    let module_name = module.name().to_string();
                    let module_id = module.id().to_string();
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
                    (module_id, module_name, result)
                }
                .boxed(),
            );
        }
        let outcomes = executor.execute(jobs, cancellation).await?;

        for outcome in outcomes {
            let duration_ms = u64::try_from(outcome.duration().as_millis()).unwrap_or(u64::MAX);
            let (module_id, module_name, result) = outcome.into_output();
            match result {
                Ok(findings) => {
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
                    all_findings.extend(findings);
                    modules_run.push(module_id);
                }
                Err(e) => {
                    let err_str = e.to_string();
                    self.ctx.events.publish(ScanEvent::ModuleError {
                        scan_id: scan_id.clone(),
                        module_id: module_id.clone(),
                        error: err_str.clone(),
                    });
                    modules_skipped.push((module_id, err_str));
                }
            }
        }

        all_findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

        let target = Target::from_path(&self.ctx.path)?;
        let summary = ScanSummary::from_findings(&all_findings);

        if self.hook_runner.has_hooks(crate::engine::hook_runner::HookPoint::PostScan) {
            let post_scan_data = serde_json::json!({
                "scan_id": &scan_id,
                "target": self.ctx.path.display().to_string(),
                "total_findings": all_findings.len(),
                "summary": &summary,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::config::AppConfig;

    struct StubModule {
        module_id: &'static str,
        category: CodeCategory,
        required_tool: Option<&'static str>,
        findings: usize,
    }

    #[async_trait::async_trait]
    impl CodeModule for StubModule {
        fn name(&self) -> &'static str {
            "stub"
        }

        fn id(&self) -> &'static str {
            self.module_id
        }

        fn category(&self) -> CodeCategory {
            self.category
        }

        fn description(&self) -> &'static str {
            "code orchestrator contract fixture"
        }

        async fn run(&self, _ctx: &CodeContext) -> Result<Vec<Finding>> {
            Ok((0..self.findings)
                .map(|index| {
                    Finding::new(
                        self.module_id,
                        crate::engine::severity::Severity::Low,
                        format!("fixture finding {index}"),
                        "fixture",
                        "code://fixture",
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

    fn fixture(root: &std::path::Path) -> CodeOrchestrator {
        let context = CodeContext::new(
            root.to_path_buf(),
            Some("rust".to_string()),
            Arc::new(AppConfig::default()),
            Vec::new(),
        );
        CodeOrchestrator::new(context)
    }

    fn profile_fixture(root: &std::path::Path) -> CodeOrchestrator {
        let mut orchestrator = fixture(root);
        orchestrator.add_module(Box::new(StubModule {
            module_id: "secrets",
            category: CodeCategory::Secrets,
            required_tool: None,
            findings: 0,
        }));
        orchestrator.add_module(Box::new(StubModule {
            module_id: "sast",
            category: CodeCategory::Sast,
            required_tool: None,
            findings: 0,
        }));
        orchestrator
    }

    #[test]
    fn unknown_profile_clears_code_modules() {
        let root = tempfile::tempdir().expect("code fixture root");
        let context = CodeContext::new(
            root.path().to_path_buf(),
            Some("rust".to_string()),
            Arc::new(AppConfig::default()),
            Vec::new(),
        );
        let mut orchestrator = CodeOrchestrator::new(context);
        orchestrator.register_default_modules();
        assert!(!orchestrator.modules.is_empty());

        orchestrator.apply_profile("invalid");

        assert!(orchestrator.modules.is_empty());
    }

    #[test]
    fn code_profiles_select_exact_module_categories() {
        let root = tempfile::tempdir().expect("code fixture root");

        let mut quick = profile_fixture(root.path());
        quick.apply_profile("quick");
        assert_eq!(quick.modules.iter().map(|module| module.id()).collect::<Vec<_>>(), ["secrets"]);

        for profile in ["standard", "thorough", "pentest"] {
            let mut orchestrator = profile_fixture(root.path());
            orchestrator.apply_profile(profile);
            assert_eq!(
                orchestrator.modules.iter().map(|module| module.id()).collect::<Vec<_>>(),
                ["secrets", "sast"],
                "profile {profile}"
            );
        }
    }

    #[test]
    fn code_compatibility_modules_require_explicit_selection() {
        let root = tempfile::tempdir().expect("code fixture root");

        let mut implicit = fixture(root.path());
        implicit.register_default_modules();
        implicit.apply_profile("standard");
        assert!(!implicit.modules.iter().any(|module| module.id() == "scoutsuite"));

        let mut explicit = fixture(root.path());
        explicit.register_default_modules();
        explicit.apply_selection("standard", Some(&["scoutsuite".to_string()]));
        assert_eq!(
            explicit.modules.iter().map(|module| module.id()).collect::<Vec<_>>(),
            ["scoutsuite"]
        );

        let mut unknown = fixture(root.path());
        unknown.register_default_modules();
        unknown.apply_selection("unknown", Some(&["scoutsuite".to_string()]));
        assert!(unknown.modules.is_empty());
    }

    #[tokio::test]
    async fn code_runner_skips_a_declared_missing_tool() {
        let root = tempfile::tempdir().expect("code fixture root");
        let mut orchestrator = fixture(root.path());
        orchestrator.add_module(Box::new(StubModule {
            module_id: "missing",
            category: CodeCategory::Sast,
            required_tool: Some("scorchkit-code-tool-that-does-not-exist"),
            findings: 1,
        }));

        let result = orchestrator.run_quiet(true).await.expect("code scan");

        assert!(result.modules_run.is_empty());
        assert_eq!(result.modules_skipped.len(), 1);
        assert_eq!(result.modules_skipped[0].0, "missing");
        assert!(result.findings.is_empty());
    }
}
