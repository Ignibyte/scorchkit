//! Scan job lifecycle contracts over authorized loopback effects.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use httpmock::MockServer;
use scorchkit::config::AppConfig;
use scorchkit::engine::finding::Finding;
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::scope::ScopeRule;
use scorchkit::engine::severity::Severity;
use scorchkit::runner::job::{
    DastJobRequest, InMemoryJobStore, JobStore, ScanJobService, ScanJobState,
};
use scorchkit::webhooks::WebhookService;
use scorchkit_executor::webhook::{InMemoryWebhookStore, WebhookDelivery, WebhookStore};

fn engagement() -> Engagement {
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::Cidr {
            network: u32::from(std::net::Ipv4Addr::new(127, 0, 0, 0)),
            mask: u32::MAX << 24,
        })
        .allow_scope(ScopeRule::CidrV6 { network: 1, mask: u128::MAX })
        .allow_capability(Capability::DastScan)
        .allow_capability(Capability::ExternalTool)
        .allow_effect(EffectClass::Passive)
        .allow_effect(EffectClass::ActiveSafe)
        .allow_effect(EffectClass::Intrusive);
    let mut engagement = Engagement::new("job-lifecycle-test", policy);
    engagement.id = uuid::Uuid::from_u128(0x4a4f_4253_434f_5243_484b_4954_5445_5354);
    engagement
}

fn config() -> Arc<AppConfig> {
    let mut config = AppConfig { engagement: Some(engagement()), ..AppConfig::default() };
    config.scan.timeout_seconds = 8;
    config.scan.max_concurrent_modules = 1;
    Arc::new(config)
}

fn request(server: &MockServer, engagement: Engagement) -> DastJobRequest {
    DastJobRequest::new(server.base_url(), "quick", engagement)
        .with_modules(Some(vec!["headers".to_string()]))
}

async fn wait_for_state(
    jobs: &ScanJobService,
    id: uuid::Uuid,
    expected: ScanJobState,
) -> Result<scorchkit::runner::job::ScanJob, Box<dyn std::error::Error>> {
    Ok(tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let job = jobs.get(id).await?;
            if job.state == expected {
                return Ok::<_, scorchkit::engine::error::ScorchError>(job);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??)
}

#[tokio::test]
async fn authorized_loopback_job_persists_progress_and_result_without_duplicates(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start_async().await;
    let _mock = server
        .mock_async(|when, then| {
            when.any_request();
            then.status(200)
                .header("content-type", "text/html")
                .header("server", "scorchkit-job-test")
                .body("<html><body>ok</body></html>");
        })
        .await;
    let config = config();
    let jobs = ScanJobService::in_memory(Arc::clone(&config));
    let queued = jobs.submit(request(&server, engagement())).await?;

    assert_eq!(queued.state, ScanJobState::Queued);
    let finished = jobs.run(queued.id).await?;

    assert_eq!(finished.state, ScanJobState::Succeeded);
    assert_eq!(finished.progress.total_modules, 1);
    assert_eq!(finished.progress.completed_modules, ["headers"]);
    assert!(finished.progress.active_modules.is_empty());
    let Some(result) = finished.result else {
        panic!("successful job must contain a result");
    };
    assert_eq!(result.modules_run, ["headers"]);
    assert_eq!(result.findings.len(), finished.progress.findings.len());
    assert_eq!(result.summary.total_findings, result.findings.len());
    Ok(())
}

#[tokio::test]
async fn webhook_enqueue_failure_does_not_change_successful_scan_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start_async().await;
    let _mock = server
        .mock_async(|when, then| {
            when.any_request();
            then.status(200).header("content-type", "text/html").body("<html>ok</html>");
        })
        .await;
    let destination: scorchkit::config::WebhookConfig =
        serde_json::from_value(serde_json::json!({
            "id": "full-queue",
            "url": "https://hooks.example.test/delivery",
            "events": ["scan_completed"],
            "max_pending": 1
        }))?;
    let webhook_store = Arc::new(InMemoryWebhookStore::new());
    let existing = WebhookDelivery::new(
        destination.destination_id(),
        "scan_completed".to_string(),
        serde_json::json!({"schema":"scorchkit.webhook-event/v1"}),
        engagement(),
        destination.max_attempts,
    );
    webhook_store.create(&existing, 1).await?;
    let webhooks = Arc::new(WebhookService::new(&[destination], webhook_store.clone())?);
    let config = config();
    let jobs = ScanJobService::in_memory(Arc::clone(&config)).with_webhooks(webhooks);
    let queued = jobs.submit(request(&server, engagement())).await?;

    let finished = jobs.run(queued.id).await?;

    assert_eq!(finished.state, ScanJobState::Succeeded);
    assert_eq!(webhook_store.list().await?.len(), 1, "failed enqueue must not exceed capacity");
    Ok(())
}

#[tokio::test]
async fn cross_service_cancel_signals_owner_and_preserves_terminal_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start_async().await;
    let _mock = server
        .mock_async(|when, then| {
            when.any_request();
            then.delay(Duration::from_secs(5)).status(200).body("slow");
        })
        .await;
    let config = config();
    let store = Arc::new(InMemoryJobStore::new());
    let owner = ScanJobService::new(Arc::clone(&config), store.clone());
    let controller = ScanJobService::new(Arc::clone(&config), store.clone());
    let second_controller = ScanJobService::new(Arc::clone(&config), store);
    let queued = owner.submit(request(&server, engagement())).await?;
    let owner_task = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.run(queued.id).await })
    };
    let _running = wait_for_state(&owner, queued.id, ScanJobState::Running).await?;

    let (first_cancel, second_cancel) =
        tokio::join!(controller.cancel(queued.id), second_controller.cancel(queued.id));
    assert_eq!(first_cancel?.state, ScanJobState::Cancelling);
    assert_eq!(second_cancel?.state, ScanJobState::Cancelling);
    let finished = tokio::time::timeout(Duration::from_secs(3), owner_task).await???;
    assert_eq!(finished.state, ScanJobState::Cancelled);
    assert!(finished.result.is_none());
    assert!(finished.progress.active_modules.is_empty());
    Ok(())
}

#[tokio::test]
async fn expired_lease_recovers_partial_evidence_and_resume_reauthorizes(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start_async().await;
    let config = config();
    let store = Arc::new(InMemoryJobStore::new());
    let first = ScanJobService::new(Arc::clone(&config), store.clone());
    let queued = first.submit(request(&server, engagement())).await?;

    let mut abandoned = queued.clone();
    abandoned.state = ScanJobState::Running;
    abandoned.revision = 1;
    abandoned.lease_expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
    abandoned.started_at = Some(Utc::now());
    abandoned.updated_at = Utc::now();
    abandoned.progress.total_modules = 2;
    abandoned.progress.completed_modules.push("headers".to_string());
    abandoned.progress.active_modules.push("ssl".to_string());
    abandoned.progress.findings.push(Finding::new(
        "headers",
        Severity::Low,
        "partial evidence",
        "completed module evidence",
        server.base_url(),
    ));
    assert!(store.compare_and_swap(0, &abandoned).await?);

    let resumed_owner = ScanJobService::new(Arc::clone(&config), store.clone());
    let recovered = resumed_owner.recover_interrupted().await?;
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].state, ScanJobState::Interrupted);
    assert!(recovered[0].progress.active_modules.is_empty());
    assert_eq!(recovered[0].progress.findings.len(), 1);

    let competing_owner = ScanJobService::new(Arc::clone(&config), store.clone());
    let (first_resume, second_resume) =
        tokio::join!(resumed_owner.resume(queued.id), competing_owner.resume(queued.id));
    assert!(first_resume.is_ok() ^ second_resume.is_ok(), "exactly one resume must win");
    let successor = first_resume.or(second_resume)?;
    assert_eq!(successor.parent_job_id, Some(queued.id));
    assert_eq!(successor.attempt, 2);
    assert_eq!(successor.progress.completed_modules, ["headers"]);
    assert_eq!(successor.progress.findings.len(), 1);

    let mut changed = (*config).clone();
    let mut changed_engagement = engagement();
    changed_engagement.enabled = false;
    changed.engagement = Some(changed_engagement);
    let changed_service = ScanJobService::new(Arc::new(changed), store);
    let result = changed_service.resume(queued.id).await;
    let Err(error) = result else {
        panic!("changed engagement must not resume stored work");
    };
    assert!(error.to_string().contains("does not match the current engagement"));
    Ok(())
}
