//! Compatibility re-exports for the extracted bounded executor.

pub(crate) use scorchkit_executor::{cancel_on_token, ensure_not_cancelled};
pub use scorchkit_executor::{CancellationToken, ExecutionBudget, JobExecutor, JobOutcome};

#[cfg(test)]
mod tests {
    #[cfg(feature = "infra")]
    use std::net::{IpAddr, Ipv4Addr};
    #[cfg(unix)]
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use futures_util::FutureExt;

    use super::*;
    use crate::config::AppConfig;
    #[cfg(feature = "cloud")]
    use crate::engine::cloud_context::CloudContext;
    #[cfg(feature = "cloud")]
    use crate::engine::cloud_module::{CloudCategory, CloudModule};
    #[cfg(feature = "cloud")]
    use crate::engine::cloud_target::CloudTarget;
    use crate::engine::code_context::CodeContext;
    use crate::engine::code_module::{CodeCategory, CodeModule};
    use crate::engine::error::{Result, ScorchError};
    use crate::engine::finding::Finding;
    #[cfg(feature = "infra")]
    use crate::engine::infra_context::InfraContext;
    #[cfg(feature = "infra")]
    use crate::engine::infra_module::{InfraCategory, InfraModule};
    #[cfg(feature = "infra")]
    use crate::engine::infra_target::InfraTarget;
    use crate::engine::module_trait::{ModuleCategory, ScanModule};
    use crate::engine::scan_context::ScanContext;
    use crate::engine::scan_result::ScanResult;
    use crate::engine::severity::Severity;
    use crate::engine::target::Target;
    #[cfg(feature = "cloud")]
    use crate::runner::cloud_orchestrator::CloudOrchestrator;
    use crate::runner::code_orchestrator::CodeOrchestrator;
    #[cfg(feature = "infra")]
    use crate::runner::infra_orchestrator::InfraOrchestrator;
    use crate::runner::orchestrator::Orchestrator;
    #[cfg(unix)]
    use crate::runner::subprocess::{SystemToolExecutor, ToolExecutor, ToolInvocation};

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[derive(Debug, Default)]
    struct ContractTracker {
        active: AtomicUsize,
        high_water: AtomicUsize,
        starts: AtomicUsize,
    }

    struct ContractModule {
        module_id: &'static str,
        delay: Duration,
        tracker: Arc<ContractTracker>,
    }

    impl ContractModule {
        fn new(module_id: &'static str, delay: Duration, tracker: Arc<ContractTracker>) -> Self {
            Self { module_id, delay, tracker }
        }

        async fn execute_contract(&self, affected_target: &str) -> Result<Vec<Finding>> {
            self.tracker.starts.fetch_add(1, Ordering::SeqCst);
            let active = self.tracker.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.tracker.high_water.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.tracker.active.fetch_sub(1, Ordering::SeqCst);
            Ok(vec![Finding::new(
                self.module_id,
                Severity::Low,
                format!("{} contract finding", self.module_id),
                "shared executor family contract",
                affected_target,
            )])
        }
    }

    #[async_trait::async_trait]
    impl ScanModule for ContractModule {
        fn name(&self) -> &'static str {
            self.module_id
        }

        fn id(&self) -> &'static str {
            self.module_id
        }

        fn category(&self) -> ModuleCategory {
            ModuleCategory::Scanner
        }

        fn description(&self) -> &'static str {
            "shared executor DAST contract fixture"
        }

        async fn run(&self, _ctx: &ScanContext) -> Result<Vec<Finding>> {
            self.execute_contract("http://127.0.0.1/contract").await
        }
    }

    #[async_trait::async_trait]
    impl CodeModule for ContractModule {
        fn name(&self) -> &'static str {
            self.module_id
        }

        fn id(&self) -> &'static str {
            self.module_id
        }

        fn category(&self) -> CodeCategory {
            CodeCategory::Sast
        }

        fn description(&self) -> &'static str {
            "shared executor SAST contract fixture"
        }

        async fn run(&self, _ctx: &CodeContext) -> Result<Vec<Finding>> {
            self.execute_contract("code://contract").await
        }
    }

    #[cfg(feature = "infra")]
    #[async_trait::async_trait]
    impl InfraModule for ContractModule {
        fn name(&self) -> &'static str {
            self.module_id
        }

        fn id(&self) -> &'static str {
            self.module_id
        }

        fn category(&self) -> InfraCategory {
            InfraCategory::Dns
        }

        fn description(&self) -> &'static str {
            "shared executor infrastructure contract fixture"
        }

        async fn run(&self, _ctx: &InfraContext) -> Result<Vec<Finding>> {
            self.execute_contract("infra://contract").await
        }
    }

    #[cfg(feature = "cloud")]
    #[async_trait::async_trait]
    impl CloudModule for ContractModule {
        fn name(&self) -> &'static str {
            self.module_id
        }

        fn id(&self) -> &'static str {
            self.module_id
        }

        fn category(&self) -> CloudCategory {
            CloudCategory::Iam
        }

        fn description(&self) -> &'static str {
            "shared executor cloud contract fixture"
        }

        async fn run(&self, _ctx: &CloudContext) -> Result<Vec<Finding>> {
            self.execute_contract("cloud://contract").await
        }
    }

    fn contract_config() -> Arc<AppConfig> {
        let mut config = AppConfig::default();
        config.scan.max_concurrent_modules = 2;
        config.scan.timeout_seconds = 2;
        Arc::new(config)
    }

    fn contract_modules(tracker: &Arc<ContractTracker>) -> [ContractModule; 2] {
        [
            ContractModule::new("slow", Duration::from_millis(60), Arc::clone(tracker)),
            ContractModule::new("fast", Duration::from_millis(5), Arc::clone(tracker)),
        ]
    }

    fn assert_family_contract(result: &ScanResult, tracker: &ContractTracker) {
        assert_eq!(result.modules_run, ["slow", "fast"]);
        assert_eq!(
            result.findings.iter().map(|finding| finding.module_id.as_str()).collect::<Vec<_>>(),
            ["slow", "fast"]
        );
        assert_eq!(tracker.starts.load(Ordering::SeqCst), 2);
        assert_eq!(tracker.high_water.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn dast_family_passes_the_shared_executor_contract() {
        let tracker = Arc::new(ContractTracker::default());
        let target = Target::parse("http://127.0.0.1").expect("DAST target");
        let client = reqwest::Client::builder().build().expect("DAST client");
        let context = ScanContext::new(target, contract_config(), client, Vec::new());
        let mut orchestrator = Orchestrator::new(context);
        for module in contract_modules(&tracker) {
            orchestrator.add_module(Box::new(module));
        }

        let result = orchestrator.run(true).await.expect("DAST contract scan");

        assert_family_contract(&result, &tracker);
    }

    #[tokio::test]
    async fn sast_family_passes_the_shared_executor_contract() {
        let directory = tempfile::tempdir().expect("SAST root");
        let tracker = Arc::new(ContractTracker::default());
        let context = CodeContext::new(
            directory.path().to_path_buf(),
            Some("rust".to_string()),
            contract_config(),
            Vec::new(),
        );
        let mut orchestrator = CodeOrchestrator::new(context);
        for module in contract_modules(&tracker) {
            orchestrator.add_module(Box::new(module));
        }

        let result = orchestrator.run().await.expect("SAST contract scan");

        assert_family_contract(&result, &tracker);
    }

    #[cfg(feature = "infra")]
    #[tokio::test]
    async fn infrastructure_family_passes_the_shared_executor_contract() {
        let tracker = Arc::new(ContractTracker::default());
        let target = InfraTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let context = InfraContext::new(target, contract_config(), Vec::new());
        let mut orchestrator = InfraOrchestrator::new(context);
        for module in contract_modules(&tracker) {
            orchestrator.add_module(Box::new(module));
        }

        let result = orchestrator.run(true).await.expect("infrastructure contract scan");

        assert_family_contract(&result, &tracker);
    }

    #[cfg(feature = "cloud")]
    #[tokio::test]
    async fn cloud_family_passes_the_shared_executor_contract() {
        let tracker = Arc::new(ContractTracker::default());
        let context = CloudContext::new(CloudTarget::All, contract_config(), Vec::new());
        let mut orchestrator = CloudOrchestrator::new(context);
        for module in contract_modules(&tracker) {
            orchestrator.add_module(Box::new(module));
        }

        let result = orchestrator.run(true).await.expect("cloud contract scan");

        assert_family_contract(&result, &tracker);
    }

    #[cfg(all(feature = "infra", feature = "cloud"))]
    #[tokio::test]
    async fn all_families_forward_pre_cancellation_without_starting_modules() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let dast_tracker = Arc::new(ContractTracker::default());
        let target = Target::parse("http://127.0.0.1").expect("DAST target");
        let client = reqwest::Client::builder().build().expect("DAST client");
        let mut dast =
            Orchestrator::new(ScanContext::new(target, contract_config(), client, Vec::new()));
        dast.add_module(Box::new(ContractModule::new(
            "dast",
            Duration::from_secs(1),
            Arc::clone(&dast_tracker),
        )));
        assert!(matches!(
            dast.run_with_cancellation(true, &cancellation).await,
            Err(ScorchError::Cancelled { .. })
        ));

        let directory = tempfile::tempdir().expect("SAST root");
        let sast_tracker = Arc::new(ContractTracker::default());
        let mut sast = CodeOrchestrator::new(CodeContext::new(
            directory.path().to_path_buf(),
            Some("rust".to_string()),
            contract_config(),
            Vec::new(),
        ));
        sast.add_module(Box::new(ContractModule::new(
            "sast",
            Duration::from_secs(1),
            Arc::clone(&sast_tracker),
        )));
        assert!(matches!(
            sast.run_with_cancellation(&cancellation).await,
            Err(ScorchError::Cancelled { .. })
        ));

        let infra_tracker = Arc::new(ContractTracker::default());
        let target = InfraTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let mut infra =
            InfraOrchestrator::new(InfraContext::new(target, contract_config(), Vec::new()));
        infra.add_module(Box::new(ContractModule::new(
            "infra",
            Duration::from_secs(1),
            Arc::clone(&infra_tracker),
        )));
        assert!(matches!(
            infra.run_with_cancellation(true, &cancellation).await,
            Err(ScorchError::Cancelled { .. })
        ));

        let cloud_tracker = Arc::new(ContractTracker::default());
        let mut cloud = CloudOrchestrator::new(CloudContext::new(
            CloudTarget::All,
            contract_config(),
            Vec::new(),
        ));
        cloud.add_module(Box::new(ContractModule::new(
            "cloud",
            Duration::from_secs(1),
            Arc::clone(&cloud_tracker),
        )));
        assert!(matches!(
            cloud.run_with_cancellation(true, &cancellation).await,
            Err(ScorchError::Cancelled { .. })
        ));

        for tracker in [dast_tracker, sast_tracker, infra_tracker, cloud_tracker] {
            assert_eq!(tracker.starts.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn zero_resource_budgets_fail_closed() {
        assert!(matches!(
            ExecutionBudget::new(0, Duration::from_secs(1)),
            Err(ScorchError::Config(message))
                if message == "scan.max_concurrent_modules must be greater than zero"
        ));
        assert!(matches!(
            ExecutionBudget::new(1, Duration::ZERO),
            Err(ScorchError::Config(message))
                if message == "scan.timeout_seconds must be greater than zero"
        ));
    }

    #[test]
    fn final_cancellation_check_rejects_a_cancelled_token() {
        let cancellation = CancellationToken::new();
        assert!(ensure_not_cancelled(&cancellation).is_ok());

        cancellation.cancel();

        assert!(matches!(ensure_not_cancelled(&cancellation), Err(ScorchError::Cancelled { .. })));
    }

    #[tokio::test]
    async fn jobs_overlap_within_the_limit_and_outcomes_keep_submission_order() {
        let executor = JobExecutor::new(
            ExecutionBudget::new(2, Duration::from_secs(2)).expect("valid budget"),
        );
        let active = Arc::new(AtomicUsize::new(0));
        let high_water = Arc::new(AtomicUsize::new(0));

        let jobs = [80_u64, 10, 30, 5]
            .into_iter()
            .map(|delay_ms| {
                let active = Arc::clone(&active);
                let high_water = Arc::clone(&high_water);
                async move {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    high_water.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    delay_ms
                }
                .boxed()
            })
            .collect();
        let outcomes =
            executor.execute(jobs, &CancellationToken::new()).await.expect("bounded jobs");

        assert_eq!(high_water.load(Ordering::SeqCst), 2);
        assert_eq!(outcomes.iter().map(JobOutcome::ordinal).collect::<Vec<_>>(), [0, 1, 2, 3]);
        assert_eq!(
            outcomes.into_iter().map(JobOutcome::into_output).collect::<Vec<_>>(),
            [80, 10, 30, 5]
        );
    }

    #[tokio::test]
    async fn pre_cancelled_token_does_not_start_work() {
        let executor = JobExecutor::new(
            ExecutionBudget::new(1, Duration::from_secs(1)).expect("valid budget"),
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let starts = AtomicUsize::new(0);

        let result = executor
            .execute(
                vec![async {
                    starts.fetch_add(1, Ordering::SeqCst);
                }
                .boxed()],
                &cancellation,
            )
            .await;

        assert!(matches!(result, Err(ScorchError::Cancelled { .. })));
        assert_eq!(starts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancellation_drops_an_adjacent_effect_future() {
        let cancellation = CancellationToken::new();
        let cancel_from_task = cancellation.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_by_future = Arc::clone(&dropped);
        let future = async move {
            let _drop_flag = DropFlag(dropped_by_future);
            std::future::pending::<Result<()>>().await
        };
        let run = cancel_on_token(&cancellation, future);
        tokio::pin!(run);

        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(20)) => cancel_from_task.cancel(),
            result = &mut run => panic!("adjacent effect ended before cancellation: {result:?}"),
        }
        let result = tokio::time::timeout(Duration::from_secs(1), &mut run)
            .await
            .expect("bounded adjacent-effect cancellation");

        assert!(matches!(result, Err(ScorchError::Cancelled { .. })));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancellation_drops_active_and_queued_jobs() {
        let executor = JobExecutor::new(
            ExecutionBudget::new(1, Duration::from_secs(5)).expect("valid budget"),
        );
        let cancellation = CancellationToken::new();
        let cancel_from_task = cancellation.clone();
        let starts = Arc::new(AtomicUsize::new(0));
        let starts_in_job = Arc::clone(&starts);
        let jobs = [(), ()]
            .into_iter()
            .map(move |()| {
                let starts = Arc::clone(&starts_in_job);
                async move {
                    starts.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                }
                .boxed()
            })
            .collect();
        let run = executor.execute(jobs, &cancellation);
        tokio::pin!(run);

        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(20)) => cancel_from_task.cancel(),
            result = &mut run => panic!("job batch ended before cancellation: {result:?}"),
        }
        let result = tokio::time::timeout(Duration::from_secs(1), &mut run)
            .await
            .expect("bounded cancellation");

        assert!(matches!(result, Err(ScorchError::Cancelled { .. })));
        assert_eq!(starts.load(Ordering::SeqCst), 1, "queued job must not start");
    }

    #[tokio::test]
    async fn wall_time_budget_drops_active_work() {
        let executor = JobExecutor::new(
            ExecutionBudget::new(1, Duration::from_millis(20)).expect("valid budget"),
        );
        let result = executor
            .execute(vec![std::future::pending::<()>().boxed()], &CancellationToken::new())
            .await;

        assert!(matches!(
            result,
            Err(ScorchError::Cancelled { reason }) if reason.contains("wall-time budget")
        ));
    }

    #[tokio::test]
    async fn cancellation_releases_a_pending_loopback_http_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let (request_seen_tx, request_seen_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept loopback request");
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                let read = socket.read(&mut byte).await.expect("read request");
                assert_ne!(read, 0, "client closed before request headers completed");
                request.push(byte[0]);
            }
            let _ = request_seen_tx.send(());
            let read = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut byte))
                .await
                .expect("HTTP connection did not close within cancellation bound")
                .expect("read connection close");
            assert_eq!(read, 0, "cancelled HTTP connection remained open");
        });

        let client = reqwest::Client::builder().build().expect("test HTTP client");
        let url = format!("http://{address}/pending");
        let executor = JobExecutor::new(
            ExecutionBudget::new(1, Duration::from_secs(5)).expect("valid budget"),
        );
        let cancellation = CancellationToken::new();
        let cancellation_for_run = cancellation.clone();
        let execution = tokio::spawn(async move {
            let job = async move {
                client.get(url).header(reqwest::header::CONNECTION, "close").send().await
            }
            .boxed();
            executor.execute(vec![job], &cancellation_for_run).await
        });

        request_seen_rx.await.expect("request reached loopback server");
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), execution)
            .await
            .expect("executor cancellation bound")
            .expect("executor task");
        assert!(matches!(result, Err(ScorchError::Cancelled { .. })));
        server.await.expect("loopback server task");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_terminates_an_owned_process_tree() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("executor-cancel-descendant.pid");
        let pid_path = pid_file.to_string_lossy().into_owned();
        let command = "sleep 60 </dev/null >/dev/null 2>&1 & printf '%s' \"$!\" > \"$1\"; wait";
        let invocation = ToolInvocation::strict(
            "sh",
            &["-c", command, "scorchkit-executor-cancel", &pid_path],
            Duration::from_secs(30),
        );
        let executor = JobExecutor::new(
            ExecutionBudget::new(1, Duration::from_secs(5)).expect("valid budget"),
        );
        let cancellation = CancellationToken::new();
        let cancellation_for_run = cancellation.clone();
        let execution = tokio::spawn(async move {
            executor
                .execute(
                    vec![async move { SystemToolExecutor.execute(invocation).await }.boxed()],
                    &cancellation_for_run,
                )
                .await
        });

        wait_for_file(&pid_file).await;
        let descendant = read_pid(&pid_file);
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), execution)
            .await
            .expect("executor cancellation bound")
            .expect("executor task");
        assert!(matches!(result, Err(ScorchError::Cancelled { .. })));
        assert_process_exits(descendant).await;
    }

    #[cfg(unix)]
    async fn wait_for_file(path: &Path) {
        for _ in 0..200 {
            if path.metadata().is_ok_and(|metadata| metadata.len() > 0) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("process fixture did not publish its PID");
    }

    #[cfg(unix)]
    fn read_pid(path: &Path) -> rustix::process::Pid {
        let raw = std::fs::read_to_string(path)
            .expect("read descendant PID")
            .parse::<i32>()
            .expect("parse descendant PID");
        rustix::process::Pid::from_raw(raw).expect("positive descendant PID")
    }

    #[cfg(unix)]
    async fn assert_process_exits(pid: rustix::process::Pid) {
        for _ in 0..200 {
            if matches!(rustix::process::test_kill_process(pid), Err(rustix::io::Errno::SRCH)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("descendant process {pid:?} survived executor cancellation");
    }
}
