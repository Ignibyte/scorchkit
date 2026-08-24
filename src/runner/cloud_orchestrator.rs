//! Cloud-posture scan orchestrator — concurrent execution of
//! [`CloudModule`]s.
//!
//! Mirrors [`crate::runner::infra_orchestrator::InfraOrchestrator`]
//! structurally. Emits the same [`crate::engine::events::ScanEvent`]
//! lifecycle sequence and wires the built-in audit-log subscriber at
//! the top of `run()`.
//!
//! The shared job executor owns scheduling, budgets, and cancellation. This family adapter remains
//! concrete so cloud target conversion, findings, events, and policy-sealed context behavior do not
//! leak into a generic runner.

use std::time::Instant;

#[cfg(test)]
use std::sync::Arc;

use chrono::Utc;
use colored::Colorize;
use futures_util::FutureExt;
use uuid::Uuid;

use crate::engine::audit_log::subscribe_audit_log_if_enabled;
use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_module::{CloudCategory, CloudModule};
use crate::engine::error::Result;
use crate::engine::events::ScanEvent;
use crate::engine::finding::Finding;
use crate::engine::scan_result::{ScanResult, ScanSummary};
use crate::engine::target::Target;
use crate::runner::job_executor::{ensure_not_cancelled, CancellationToken, JobExecutor};
use crate::runner::progress;
use crate::runner::subprocess::missing_required_tool;

/// Returns the policy-supported built-in cloud modules.
#[must_use]
pub fn all_cloud_modules() -> Vec<Box<dyn CloudModule>> {
    crate::cloud::register_modules()
}

/// Orchestrates concurrent cloud-posture module execution.
pub struct CloudOrchestrator {
    ctx: CloudContext,
    modules: Vec<Box<dyn CloudModule>>,
}

impl CloudOrchestrator {
    /// Create a new orchestrator bound to the given context.
    #[must_use]
    pub fn new(ctx: CloudContext) -> Self {
        Self { ctx, modules: Vec::new() }
    }

    /// Register every policy-supported built-in cloud module.
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

    /// Apply a profile name. `quick` keeps only [`CloudCategory::Iam`]; the other supported
    /// profiles keep all registered modules. An unknown name clears the registry so low-level
    /// callers fail closed.
    pub fn apply_profile(&mut self, profile: &str) {
        match profile {
            "quick" => self.modules.retain(|m| m.category() == CloudCategory::Iam),
            "standard" | "thorough" | "pentest" => {}
            _ => self.modules.clear(),
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
    /// An empty module registry is a valid state — callers may deliberately
    /// filter every registered module. The orchestrator
    /// emits `ScanStarted` + `ScanCompleted` with zero findings and
    /// returns normally. This is exercised by
    /// `test_cloud_orchestrator_empty_module_list`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid execution budgets, batch deadline, or a fatal scan error.
    /// Individual module failures are non-fatal.
    // JUSTIFICATION: Event emission across scan start, module start,
    // module complete, module error, and scan complete forms a cohesive
    // lifecycle block — splitting would scatter the publication sites
    // without improving clarity (matches InfraOrchestrator).
    #[allow(clippy::too_many_lines)]
    pub async fn run(&self, quiet: bool) -> Result<ScanResult> {
        let cancellation = CancellationToken::new();
        self.run_with_cancellation(quiet, &cancellation).await
    }

    /// Run registered cloud modules with caller-controlled cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid execution budgets, caller cancellation, batch deadline,
    /// target conversion, or another fatal orchestration failure. Individual module failures are
    /// retained as skipped-module outcomes.
    // JUSTIFICATION: Module event commits and deterministic result assembly share scan-owned state;
    // extraction would scatter the cloud lifecycle contract.
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

        let _audit_log_handle =
            subscribe_audit_log_if_enabled(&self.ctx.config.audit_log, &self.ctx.events);

        let target_display = self.ctx.target.display_raw();
        self.ctx.events.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: target_display.clone(),
        });

        if progress::is_visible(quiet) {
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

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut modules_run: Vec<String> = Vec::new();

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
                    (module_id, result)
                }
                .boxed(),
            );
        }
        let outcomes = executor.execute(jobs, cancellation).await?;

        for outcome in outcomes {
            let duration_ms = u64::try_from(outcome.duration().as_millis()).unwrap_or(u64::MAX);
            let (module_id, result) = outcome.into_output();

            match result {
                Ok(findings) => {
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
        let target = Target::from_cloud(&target_display)?;
        let summary = ScanSummary::from_findings(&all_findings);

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
            module_outcomes: Vec::new(),
            execution_status: crate::engine::scan_result::ScanExecutionStatus::Complete,
            supply_chain: None,
            application_dast: None,
            application_pentest: None,
            adapter_executions: Vec::new(),
            pipeline_outcomes: Vec::new(),
            summary,
        })
    }
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

    struct MissingToolModule;

    #[async_trait]
    impl CloudModule for MissingToolModule {
        fn name(&self) -> &'static str {
            "missing"
        }

        fn id(&self) -> &'static str {
            "missing"
        }

        fn category(&self) -> CloudCategory {
            CloudCategory::Iam
        }

        fn description(&self) -> &'static str {
            "missing tool fixture"
        }

        async fn run(&self, _ctx: &CloudContext) -> Result<Vec<Finding>> {
            Ok(vec![Finding::new(
                "missing",
                Severity::Low,
                "unexpected execution",
                "fixture",
                "cloud://fixture",
            )])
        }

        fn requires_external_tool(&self) -> bool {
            true
        }

        fn required_tool(&self) -> Option<&str> {
            Some("scorchkit-cloud-tool-that-does-not-exist")
        }
    }

    #[async_trait]
    impl CloudModule for StubModule {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn id(&self) -> &str {
            self.module_id
        }
        fn category(&self) -> CloudCategory {
            self.cat
        }
        fn description(&self) -> &'static str {
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
            ScanEvent::PipelineProcessorOutcome { .. } => "PipelineProcessorOutcome",
            ScanEvent::ScanCompleted { .. } => "ScanCompleted",
            ScanEvent::Custom { .. } => "Custom",
        }
    }

    fn fixture_ctx() -> CloudContext {
        CloudContext::new(CloudTarget::All, Arc::new(AppConfig::default()), Vec::new())
    }

    #[test]
    fn unknown_profile_clears_cloud_modules() {
        let mut orchestrator = CloudOrchestrator::new(fixture_ctx());
        orchestrator.modules.push(Box::new(StubModule {
            cat: CloudCategory::Iam,
            module_id: "stub",
            findings: 0,
        }));

        orchestrator.apply_profile("invalid");

        assert!(orchestrator.modules.is_empty());
    }

    fn profile_fixture() -> CloudOrchestrator {
        let mut orchestrator = CloudOrchestrator::new(fixture_ctx());
        orchestrator.add_module(Box::new(StubModule {
            cat: CloudCategory::Iam,
            module_id: "iam",
            findings: 0,
        }));
        orchestrator.add_module(Box::new(StubModule {
            cat: CloudCategory::Storage,
            module_id: "storage",
            findings: 0,
        }));
        orchestrator
    }

    #[test]
    fn cloud_profiles_select_exact_module_categories() {
        let mut quick = profile_fixture();
        quick.apply_profile("quick");
        assert_eq!(quick.modules.iter().map(|module| module.id()).collect::<Vec<_>>(), ["iam"]);

        for profile in ["standard", "thorough", "pentest"] {
            let mut orchestrator = profile_fixture();
            orchestrator.apply_profile(profile);
            assert_eq!(
                orchestrator.modules.iter().map(|module| module.id()).collect::<Vec<_>>(),
                ["iam", "storage"],
                "profile {profile}"
            );
        }
    }

    #[tokio::test]
    async fn cloud_runner_skips_a_declared_missing_tool() {
        let mut orchestrator = CloudOrchestrator::new(fixture_ctx());
        orchestrator.add_module(Box::new(MissingToolModule));

        let result = orchestrator.run(true).await.expect("cloud scan");

        assert!(result.modules_run.is_empty());
        assert_eq!(result.modules_skipped.len(), 1);
        assert_eq!(result.modules_skipped[0].0, "missing");
        assert!(result.findings.is_empty());
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
        drop(events);
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
        drop(events);
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
