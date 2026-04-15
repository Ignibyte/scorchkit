//! Infrastructure scan orchestrator — concurrent execution of `InfraModule`s.
//!
//! Mirrors [`crate::runner::orchestrator::Orchestrator`] (DAST) and
//! [`crate::runner::code_orchestrator::CodeOrchestrator`] (SAST). Emits the
//! same [`crate::engine::events::ScanEvent`] lifecycle sequence and wires
//! the built-in audit-log subscriber at the top of `run()`.

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
use crate::engine::infra_context::InfraContext;
use crate::engine::infra_module::{InfraCategory, InfraModule};
use crate::engine::scan_result::{ScanResult, ScanSummary};
use crate::engine::target::Target;
use crate::runner::progress;

/// Returns all registered infra modules.
#[must_use]
pub fn all_infra_modules() -> Vec<Box<dyn InfraModule>> {
    crate::infra::register_modules()
}

/// Orchestrates concurrent infra-module execution.
pub struct InfraOrchestrator {
    /// Shared context passed to every module.
    ctx: InfraContext,
    /// Registered infra modules.
    modules: Vec<Box<dyn InfraModule>>,
    /// Optional lifecycle hook runner (reuses DAST hook system).
    hook_runner: Option<crate::engine::hook_runner::HookRunner>,
}

impl InfraOrchestrator {
    /// Create a new orchestrator bound to the given context.
    #[must_use]
    pub fn new(ctx: InfraContext) -> Self {
        Self { ctx, modules: Vec::new(), hook_runner: None }
    }

    /// Attach a hook runner for `pre_scan`, `post_module`, and `post_scan`
    /// script invocations.
    pub fn set_hook_runner(&mut self, runner: crate::engine::hook_runner::HookRunner) {
        self.hook_runner = Some(runner);
    }

    /// Register every built-in infra module.
    pub fn register_default_modules(&mut self) {
        self.modules = all_infra_modules();
    }

    /// Append an additional [`InfraModule`] to the registered set.
    ///
    /// Used by [`crate::facade::Engine::infra_scan`] to layer
    /// construction-injected modules (currently
    /// [`crate::infra::cve_match::CveMatchModule`]) on top of the
    /// defaults from [`Self::register_default_modules`].
    pub fn add_module(&mut self, module: Box<dyn InfraModule>) {
        self.modules.push(module);
    }

    /// Keep only modules matching the given category.
    pub fn filter_by_category(&mut self, category: InfraCategory) {
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

    /// Apply a profile name: `quick` keeps only `PortScan`; anything else
    /// keeps all registered modules.
    pub fn apply_profile(&mut self, profile: &str) {
        if profile == "quick" {
            self.modules.retain(|m| m.category() == InfraCategory::PortScan);
        }
    }

    /// Run all registered modules concurrently (up to
    /// `config.scan.max_concurrent_modules`).
    ///
    /// Emits [`ScanEvent::ScanStarted`] → per-module
    /// `ModuleStarted`/`FindingProduced`/`ModuleCompleted`/`ModuleError`/
    /// `ModuleSkipped` → [`ScanEvent::ScanCompleted`], matching the DAST
    /// orchestrator's lifecycle contract.
    ///
    /// # Errors
    ///
    /// Returns an error if the semaphore is closed or a fatal scan error
    /// occurs. Individual module failures are non-fatal.
    // JUSTIFICATION: Event emission at scan start, module start, module
    // complete, module error, and scan complete forms a cohesive lifecycle
    // block inside the run loop — splitting would scatter the publication
    // sites without improving clarity.
    #[allow(clippy::too_many_lines)]
    pub async fn run(&self, quiet: bool) -> Result<ScanResult> {
        let started_at = Utc::now();
        let scan_started = Instant::now();
        let scan_id = Uuid::new_v4().to_string();
        let max_concurrent = self.ctx.config.scan.max_concurrent_modules;

        // Wire the built-in audit-log handler before the first publish so no
        // lifecycle events are lost. JoinHandle detaches on drop.
        let _audit_log_handle =
            subscribe_audit_log_if_enabled(&self.ctx.config.audit_log, &self.ctx.events);

        let target_display = self.ctx.target.display_raw();
        self.ctx.events.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: target_display.clone(),
        });

        if !quiet {
            println!(
                "{} {} infra module{}",
                "Running".bold(),
                self.modules.len(),
                if self.modules.len() == 1 { "" } else { "s" }
            );
            println!();
        }

        // Split into runnable / skipped based on external-tool availability.
        let mut runnable: Vec<&dyn InfraModule> = Vec::new();
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

        let target = Target::from_infra(&target_display)?;
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
    use crate::engine::events::{subscribe_handler, EventBus, EventHandler};
    use crate::engine::infra_target::InfraTarget;
    use crate::engine::severity::Severity;
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    struct StubModule {
        cat: InfraCategory,
        module_id: &'static str,
        findings: usize,
    }

    #[async_trait]
    impl InfraModule for StubModule {
        fn name(&self) -> &str {
            "stub"
        }
        fn id(&self) -> &str {
            self.module_id
        }
        fn category(&self) -> InfraCategory {
            self.cat
        }
        fn description(&self) -> &str {
            "stub infra module for tests"
        }
        async fn run(&self, _ctx: &InfraContext) -> Result<Vec<Finding>> {
            Ok((0..self.findings)
                .map(|i| {
                    Finding::new(
                        self.module_id,
                        Severity::Info,
                        format!("stub finding {i}"),
                        "stub",
                        "infra://stub",
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

    fn fixture_ctx() -> InfraContext {
        let target = InfraTarget::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let config = Arc::new(AppConfig::default());
        let client = reqwest::Client::builder().build().expect("client");
        InfraContext::new(target, config, client)
    }

    /// Regression: `InfraOrchestrator` emits the expected lifecycle event
    /// sequence when running a single stub module that produces one finding.
    #[tokio::test]
    async fn test_infra_orchestrator_emits_scan_events() {
        let ctx = fixture_ctx();
        let collected: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<dyn EventHandler> =
            Arc::new(CollectingHandler { events: collected.clone() });
        let bus: EventBus = ctx.events.clone();
        let join = subscribe_handler(&bus, handler);

        let mut orch = InfraOrchestrator::new(ctx);
        orch.modules.push(Box::new(StubModule {
            cat: InfraCategory::PortScan,
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

    /// `filter_by_category` retains only matching modules.
    #[tokio::test]
    async fn test_infra_orchestrator_filter_by_category() {
        let ctx = fixture_ctx();
        let mut orch = InfraOrchestrator::new(ctx);
        orch.modules.push(Box::new(StubModule {
            cat: InfraCategory::PortScan,
            module_id: "a",
            findings: 0,
        }));
        orch.modules.push(Box::new(StubModule {
            cat: InfraCategory::Dns,
            module_id: "b",
            findings: 0,
        }));
        orch.filter_by_category(InfraCategory::Dns);
        assert_eq!(orch.modules.len(), 1);
        assert_eq!(orch.modules[0].id(), "b");
    }

    /// `filter_by_ids` keeps only the named modules; `exclude_by_ids` drops them.
    #[tokio::test]
    async fn test_infra_orchestrator_filter_and_exclude_by_ids() {
        let ctx = fixture_ctx();
        let mut orch = InfraOrchestrator::new(ctx);
        orch.modules.push(Box::new(StubModule {
            cat: InfraCategory::PortScan,
            module_id: "alpha",
            findings: 0,
        }));
        orch.modules.push(Box::new(StubModule {
            cat: InfraCategory::Dns,
            module_id: "beta",
            findings: 0,
        }));
        orch.filter_by_ids(&["alpha".to_string()]);
        assert_eq!(orch.modules.len(), 1);
        assert_eq!(orch.modules[0].id(), "alpha");

        orch.modules.push(Box::new(StubModule {
            cat: InfraCategory::Dns,
            module_id: "beta",
            findings: 0,
        }));
        orch.exclude_by_ids(&["beta".to_string()]);
        assert_eq!(orch.modules.len(), 1);
        assert_eq!(orch.modules[0].id(), "alpha");
    }
}
