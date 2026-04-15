//! Cloud-posture scan orchestrator — concurrent execution of
//! [`CloudModule`]s.
//!
//! Mirrors [`crate::runner::infra_orchestrator::InfraOrchestrator`]
//! structurally. Emits the same [`crate::engine::events::ScanEvent`]
//! lifecycle sequence and wires the built-in audit-log subscriber at
//! the top of `run()`.
//!
//! ## Intentional duplication with `InfraOrchestrator`
//!
//! This file is ~90% identical to `infra_orchestrator.rs`. The
//! duplication is deliberate at the WORK-150 stage: the concrete
//! orchestrators remain readable and separately verifiable, while
//! refactoring both into a generic `Orchestrator<M: Module, C:
//! Context, T: TargetLike>` is a separate pipeline to run once the
//! count is 3+ and more pattern signal emerges.

use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use colored::Colorize;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::engine::audit_log::subscribe_audit_log_if_enabled;
use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_module::{CloudCategory, CloudModule};
use crate::engine::error::Result;
use crate::engine::events::ScanEvent;
use crate::engine::finding::Finding;
use crate::engine::scan_result::{ScanResult, ScanSummary};
use crate::engine::target::Target;
use crate::runner::progress;

/// Returns all registered cloud modules (currently none — populated
/// starting with WORK-151).
#[must_use]
pub fn all_cloud_modules() -> Vec<Box<dyn CloudModule>> {
    crate::cloud::register_modules()
}

/// Orchestrates concurrent cloud-posture module execution.
pub struct CloudOrchestrator {
    ctx: CloudContext,
    modules: Vec<Box<dyn CloudModule>>,
    hook_runner: Option<crate::engine::hook_runner::HookRunner>,
}

impl CloudOrchestrator {
    /// Create a new orchestrator bound to the given context.
    #[must_use]
    pub fn new(ctx: CloudContext) -> Self {
        Self { ctx, modules: Vec::new(), hook_runner: None }
    }

    /// Attach a hook runner for `pre_scan` / `post_module` / `post_scan`
    /// script invocations.
    pub fn set_hook_runner(&mut self, runner: crate::engine::hook_runner::HookRunner) {
        self.hook_runner = Some(runner);
    }

    /// Register every built-in cloud module (empty at WORK-150).
    pub fn register_default_modules(&mut self) {
        self.modules = all_cloud_modules();
    }

    /// Append an additional [`CloudModule`] to the registered set.
    pub fn add_module(&mut self, module: Box<dyn CloudModule>) {
        self.modules.push(module);
    }

    /// Keep only modules matching the given category.
    pub fn filter_by_category(&mut self, category: CloudCategory) {
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

    /// Apply a profile name: `quick` keeps only
    /// [`CloudCategory::Iam`] (fastest, no resource enumeration);
    /// anything else keeps all registered modules.
    pub fn apply_profile(&mut self, profile: &str) {
        if profile == "quick" {
            self.modules.retain(|m| m.category() == CloudCategory::Iam);
        }
    }

    /// Run all registered modules concurrently (up to
    /// `config.scan.max_concurrent_modules`).
    ///
    /// Emits [`ScanEvent::ScanStarted`] → per-module
    /// `ModuleStarted`/`FindingProduced`/`ModuleCompleted`/`ModuleError`/
    /// `ModuleSkipped` → [`ScanEvent::ScanCompleted`], matching the
    /// other orchestrators' lifecycle contract.
    ///
    /// An empty module registry is a valid state — the orchestrator
    /// emits `ScanStarted` + `ScanCompleted` with zero findings and
    /// returns normally. This is exercised by
    /// `test_cloud_orchestrator_empty_module_list` and is important
    /// because [`crate::cloud::register_modules`] currently returns
    /// an empty `Vec` until WORK-151+ populate it.
    ///
    /// # Errors
    ///
    /// Returns an error if the semaphore is closed or a fatal scan
    /// error occurs. Individual module failures are non-fatal.
    // JUSTIFICATION: Event emission across scan start, module start,
    // module complete, module error, and scan complete forms a cohesive
    // lifecycle block — splitting would scatter the publication sites
    // without improving clarity (matches InfraOrchestrator).
    #[allow(clippy::too_many_lines)]
    pub async fn run(&self, quiet: bool) -> Result<ScanResult> {
        let started_at = Utc::now();
        let scan_started = Instant::now();
        let scan_id = Uuid::new_v4().to_string();
        let max_concurrent = self.ctx.config.scan.max_concurrent_modules;

        let _audit_log_handle =
            subscribe_audit_log_if_enabled(&self.ctx.config.audit_log, &self.ctx.events);

        let target_display = self.ctx.target.display_raw();
        self.ctx.events.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: target_display.clone(),
        });

        if !quiet {
            println!(
                "{} {} cloud module{}",
                "Running".bold(),
                self.modules.len(),
                if self.modules.len() == 1 { "" } else { "s" }
            );
            println!();
        }

        let mut runnable: Vec<&dyn CloudModule> = Vec::new();
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

        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let ctx = &self.ctx;
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut modules_run: Vec<String> = Vec::new();

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
                    modules_run.push(module_id);
                    all_findings.extend(findings);
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

        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        let total_duration_ms =
            u64::try_from(scan_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.ctx.events.publish(ScanEvent::ScanCompleted {
            scan_id: scan_id.clone(),
            total_findings: all_findings.len(),
            duration_ms: total_duration_ms,
        });

        let target = Target::from_cloud(&target_display)?;
        let summary = ScanSummary::from_findings(&all_findings);

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
    use crate::engine::cloud_target::CloudTarget;
    use crate::engine::events::{subscribe_handler, EventBus, EventHandler};
    use crate::engine::severity::Severity;
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct StubModule {
        cat: CloudCategory,
        module_id: &'static str,
        findings: usize,
    }

    #[async_trait]
    impl CloudModule for StubModule {
        fn name(&self) -> &str {
            "stub"
        }
        fn id(&self) -> &str {
            self.module_id
        }
        fn category(&self) -> CloudCategory {
            self.cat
        }
        fn description(&self) -> &str {
            "stub cloud module for tests"
        }
        async fn run(&self, _ctx: &CloudContext) -> Result<Vec<Finding>> {
            Ok((0..self.findings)
                .map(|i| {
                    Finding::new(
                        self.module_id,
                        Severity::Info,
                        format!("stub finding {i}"),
                        "stub",
                        "cloud://stub",
                    )
                })
                .collect())
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

    fn fixture_ctx() -> CloudContext {
        CloudContext::new(CloudTarget::All, Arc::new(AppConfig::default()))
    }

    /// Regression: empty module registry (WORK-150 state) still emits
    /// `ScanStarted` + `ScanCompleted` and returns a well-formed
    /// `ScanResult` with zero findings, no panic on the empty-loop
    /// path.
    #[tokio::test]
    async fn test_cloud_orchestrator_empty_module_list() {
        let ctx = fixture_ctx();
        let collected: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<dyn EventHandler> =
            Arc::new(CollectingHandler { events: collected.clone() });
        let bus: EventBus = ctx.events.clone();
        let join = subscribe_handler(&bus, handler);

        let orch = CloudOrchestrator::new(ctx);
        assert!(orch.modules.is_empty(), "WORK-150 registry is empty");

        let result = orch.run(true).await.expect("empty-registry scan");
        assert_eq!(result.findings.len(), 0);
        assert!(result.modules_run.is_empty());
        assert!(result.modules_skipped.is_empty());

        drop(orch);
        drop(bus);
        join.await.expect("handler join");

        let events = collected.lock().expect("lock");
        let names: Vec<&str> = events.iter().map(discriminant).collect();
        assert_eq!(
            names,
            vec!["ScanStarted", "ScanCompleted"],
            "empty registry emits only the scan boundary events"
        );
    }

    /// Regression: single stub module produces the full 5-event
    /// lifecycle sequence.
    #[tokio::test]
    async fn test_cloud_orchestrator_emits_scan_events() {
        let ctx = fixture_ctx();
        let collected: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<dyn EventHandler> =
            Arc::new(CollectingHandler { events: collected.clone() });
        let bus: EventBus = ctx.events.clone();
        let join = subscribe_handler(&bus, handler);

        let mut orch = CloudOrchestrator::new(ctx);
        orch.modules.push(Box::new(StubModule {
            cat: CloudCategory::Iam,
            module_id: "stub",
            findings: 1,
        }));

        let result = orch.run(true).await.expect("scan");
        assert_eq!(result.findings.len(), 1);

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

    #[tokio::test]
    async fn test_cloud_orchestrator_filter_by_category() {
        let ctx = fixture_ctx();
        let mut orch = CloudOrchestrator::new(ctx);
        orch.modules.push(Box::new(StubModule {
            cat: CloudCategory::Iam,
            module_id: "a",
            findings: 0,
        }));
        orch.modules.push(Box::new(StubModule {
            cat: CloudCategory::Storage,
            module_id: "b",
            findings: 0,
        }));
        orch.filter_by_category(CloudCategory::Storage);
        assert_eq!(orch.modules.len(), 1);
        assert_eq!(orch.modules[0].id(), "b");
    }

    #[tokio::test]
    async fn test_cloud_orchestrator_filter_and_exclude_by_ids() {
        let ctx = fixture_ctx();
        let mut orch = CloudOrchestrator::new(ctx);
        orch.modules.push(Box::new(StubModule {
            cat: CloudCategory::Iam,
            module_id: "alpha",
            findings: 0,
        }));
        orch.modules.push(Box::new(StubModule {
            cat: CloudCategory::Network,
            module_id: "beta",
            findings: 0,
        }));
        orch.filter_by_ids(&["alpha".to_string()]);
        assert_eq!(orch.modules.len(), 1);
        assert_eq!(orch.modules[0].id(), "alpha");

        orch.modules.push(Box::new(StubModule {
            cat: CloudCategory::Network,
            module_id: "beta",
            findings: 0,
        }));
        orch.exclude_by_ids(&["beta".to_string()]);
        assert_eq!(orch.modules.len(), 1);
        assert_eq!(orch.modules[0].id(), "alpha");
    }
}
