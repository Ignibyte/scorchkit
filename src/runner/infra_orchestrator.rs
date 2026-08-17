//! Infrastructure scan orchestrator — concurrent execution of `InfraModule`s.
//!
//! Mirrors [`crate::runner::orchestrator::Orchestrator`] (DAST) and
//! [`crate::runner::code_orchestrator::CodeOrchestrator`] (SAST). Emits the
//! same [`crate::engine::events::ScanEvent`] lifecycle sequence and wires
//! the built-in audit-log subscriber at the top of `run()`.

use std::time::Instant;

#[cfg(test)]
use std::sync::Arc;

use chrono::Utc;
use colored::Colorize;
use futures_util::FutureExt;
use uuid::Uuid;

use crate::engine::audit_log::subscribe_audit_log_if_enabled;
use crate::engine::error::Result;
use crate::engine::events::ScanEvent;
use crate::engine::finding::Finding;
use crate::engine::infra_context::InfraContext;
use crate::engine::infra_module::{InfraCategory, InfraModule};
use crate::engine::scan_result::{ScanResult, ScanSummary};
use crate::engine::target::Target;
use crate::runner::job_executor::{ensure_not_cancelled, CancellationToken, JobExecutor};
use crate::runner::progress;
use crate::runner::subprocess::missing_required_tool;

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
}

impl InfraOrchestrator {
    /// Create a new orchestrator bound to the given context.
    #[must_use]
    pub fn new(ctx: InfraContext) -> Self {
        Self { ctx, modules: Vec::new() }
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

    /// Apply a profile name. `quick` keeps only `PortScan`; the other supported profiles keep all
    /// registered modules. An unknown name clears the registry so low-level callers fail closed.
    pub fn apply_profile(&mut self, profile: &str) {
        match profile {
            "quick" => self.modules.retain(|m| m.category() == InfraCategory::PortScan),
            "standard" | "thorough" | "pentest" => {}
            _ => self.modules.clear(),
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
    /// Returns an error for invalid execution budgets, batch deadline, or a fatal scan error.
    /// Individual module failures are non-fatal.
    // JUSTIFICATION: Event emission at scan start, module start, module
    // complete, module error, and scan complete forms a cohesive lifecycle
    // block inside the run loop — splitting would scatter the publication
    // sites without improving clarity.
    #[allow(clippy::too_many_lines)]
    pub async fn run(&self, quiet: bool) -> Result<ScanResult> {
        let cancellation = CancellationToken::new();
        self.run_with_cancellation(quiet, &cancellation).await
    }

    /// Run registered infrastructure modules with caller-controlled cancellation.
    ///
    /// Fingerprint producers finish before CVE consumers, while modules inside each phase share
    /// the configured concurrency and wall-time budgets.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid execution budgets, caller cancellation, batch deadline,
    /// target conversion, or another fatal orchestration failure. Individual module failures are
    /// retained as skipped-module outcomes.
    // JUSTIFICATION: Producer phases, event commits, and result assembly share scan-owned state;
    // keeping the transaction together makes the dependency barrier reviewable.
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
        // lifecycle events are lost. JoinHandle detaches on drop.
        let _audit_log_handle =
            subscribe_audit_log_if_enabled(&self.ctx.config.audit_log, &self.ctx.events);

        let target_display = self.ctx.target.display_raw();
        self.ctx.events.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: target_display.clone(),
        });

        if progress::is_visible(quiet) {
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

        let (producers, consumers): (Vec<_>, Vec<_>) =
            runnable.into_iter().partition(|module| module.category() != InfraCategory::CveMatch);
        let batches: [Vec<&dyn InfraModule>; 2] = (producers, consumers).into();
        for batch in batches {
            let ctx = &self.ctx;
            let mut jobs = Vec::with_capacity(batch.len());
            for module in batch {
                let scan_id = scan_id.clone();
                jobs.push(
                    async move {
                        let module_name = module.name().to_string();
                        let module_id = module.id().to_string();
                        let spinner = progress::is_visible(quiet)
                            .then(|| progress::module_spinner(&module_name));
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
                                    progress::finish_error(
                                        spinner,
                                        &module_name,
                                        &error.to_string(),
                                    );
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
                    Err(error) => {
                        let error = error.to_string();
                        self.ctx.events.publish(ScanEvent::ModuleError {
                            scan_id: scan_id.clone(),
                            module_id: module_id.clone(),
                            error: error.clone(),
                        });
                        modules_skipped.push((module_id, error));
                    }
                }
            }
        }

        all_findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
        let target = Target::from_infra(&target_display)?;
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
            summary,
        })
    }
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

    struct MissingToolModule;

    struct FingerprintProducer;

    #[async_trait]
    impl InfraModule for FingerprintProducer {
        fn name(&self) -> &'static str {
            "fingerprint producer"
        }

        fn id(&self) -> &'static str {
            "fingerprint_producer"
        }

        fn category(&self) -> InfraCategory {
            InfraCategory::PortScan
        }

        fn description(&self) -> &'static str {
            "publishes an infrastructure executor dependency fixture"
        }

        async fn run(&self, ctx: &InfraContext) -> Result<Vec<Finding>> {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            crate::engine::service_fingerprint::publish_fingerprints(
                &ctx.shared_data,
                &[crate::engine::service_fingerprint::ServiceFingerprint {
                    port: 443,
                    protocol: "tcp".to_string(),
                    service_name: "https".to_string(),
                    product: Some("fixture".to_string()),
                    version: Some("1".to_string()),
                    cpe: Some("cpe:2.3:a:fixture:fixture:1:*:*:*:*:*:*:*".to_string()),
                }],
            );
            Ok(Vec::new())
        }
    }

    struct FingerprintConsumer;

    #[async_trait]
    impl InfraModule for FingerprintConsumer {
        fn name(&self) -> &'static str {
            "fingerprint consumer"
        }

        fn id(&self) -> &'static str {
            "fingerprint_consumer"
        }

        fn category(&self) -> InfraCategory {
            InfraCategory::CveMatch
        }

        fn description(&self) -> &'static str {
            "reads an infrastructure executor dependency fixture"
        }

        async fn run(&self, ctx: &InfraContext) -> Result<Vec<Finding>> {
            let fingerprints =
                crate::engine::service_fingerprint::read_fingerprints(&ctx.shared_data);
            if fingerprints.is_empty() {
                return Err(crate::engine::error::ScorchError::Config(
                    "CVE consumer ran before fingerprint producer".to_string(),
                ));
            }
            Ok(vec![Finding::new(
                "fingerprint_consumer",
                Severity::Low,
                "producer fingerprints observed",
                "CVE consumer observed fingerprint data",
                "infra://fixture",
            )])
        }
    }

    #[async_trait]
    impl InfraModule for MissingToolModule {
        fn name(&self) -> &'static str {
            "missing"
        }

        fn id(&self) -> &'static str {
            "missing"
        }

        fn category(&self) -> InfraCategory {
            InfraCategory::PortScan
        }

        fn description(&self) -> &'static str {
            "missing tool fixture"
        }

        async fn run(&self, _ctx: &InfraContext) -> Result<Vec<Finding>> {
            Ok(vec![Finding::new(
                "missing",
                Severity::Low,
                "unexpected execution",
                "fixture",
                "infra://fixture",
            )])
        }

        fn requires_external_tool(&self) -> bool {
            true
        }

        fn required_tool(&self) -> Option<&str> {
            Some("scorchkit-infra-tool-that-does-not-exist")
        }
    }

    #[async_trait]
    impl InfraModule for StubModule {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn id(&self) -> &str {
            self.module_id
        }
        fn category(&self) -> InfraCategory {
            self.cat
        }
        fn description(&self) -> &'static str {
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
        let target = InfraTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let config = Arc::new(AppConfig::default());
        InfraContext::new(target, config, Vec::new())
    }

    #[test]
    fn unknown_profile_clears_infrastructure_modules() {
        let mut orchestrator = InfraOrchestrator::new(fixture_ctx());
        orchestrator.modules.push(Box::new(StubModule {
            cat: InfraCategory::PortScan,
            module_id: "stub",
            findings: 0,
        }));

        orchestrator.apply_profile("invalid");

        assert!(orchestrator.modules.is_empty());
    }

    fn profile_fixture() -> InfraOrchestrator {
        let mut orchestrator = InfraOrchestrator::new(fixture_ctx());
        orchestrator.add_module(Box::new(StubModule {
            cat: InfraCategory::PortScan,
            module_id: "port",
            findings: 0,
        }));
        orchestrator.add_module(Box::new(StubModule {
            cat: InfraCategory::Dns,
            module_id: "dns",
            findings: 0,
        }));
        orchestrator
    }

    #[test]
    fn infrastructure_profiles_select_exact_module_categories() {
        let mut quick = profile_fixture();
        quick.apply_profile("quick");
        assert_eq!(quick.modules.iter().map(|module| module.id()).collect::<Vec<_>>(), ["port"]);

        for profile in ["standard", "thorough", "pentest"] {
            let mut orchestrator = profile_fixture();
            orchestrator.apply_profile(profile);
            assert_eq!(
                orchestrator.modules.iter().map(|module| module.id()).collect::<Vec<_>>(),
                ["port", "dns"],
                "profile {profile}"
            );
        }
    }

    #[tokio::test]
    async fn infrastructure_runner_skips_a_declared_missing_tool() {
        let mut orchestrator = InfraOrchestrator::new(fixture_ctx());
        orchestrator.add_module(Box::new(MissingToolModule));

        let result = orchestrator.run(true).await.expect("infrastructure scan");

        assert!(result.modules_run.is_empty());
        assert_eq!(result.modules_skipped.len(), 1);
        assert_eq!(result.modules_skipped[0].0, "missing");
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn infrastructure_run_finishes_fingerprint_producers_before_cve_consumers() {
        let mut orchestrator = InfraOrchestrator::new(fixture_ctx());
        // Register the consumer first to prove its category defines the dependency barrier.
        orchestrator.add_module(Box::new(FingerprintConsumer));
        orchestrator.add_module(Box::new(FingerprintProducer));

        let result = orchestrator.run(true).await.expect("dependency-aware infrastructure scan");

        assert_eq!(result.modules_run, ["fingerprint_producer", "fingerprint_consumer"]);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].module_id, "fingerprint_consumer");
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
        drop(events);
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
