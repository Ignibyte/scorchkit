//! Durable, provider-neutral scan job lifecycle.
//!
//! Jobs own authorization snapshots, lifecycle state, progress, cancellation, and recovery. The
//! storage contract is independent of `PostgreSQL` and host transports; MCP and CLI are adapters.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::policy::Engagement;
use crate::engine::scan_result::{ScanResult, ScanSummary};
use crate::engine::target::Target;
use crate::facade::Engine;
use crate::runner::job_executor::CancellationToken;
use crate::runner::orchestrator::Orchestrator;

const MAX_CAS_ATTEMPTS: usize = 32;
const JOB_LIST_LIMIT: usize = 1_000;
const PROGRESS_CHANNEL_CAPACITY: usize = 512;
const LEASE_SECONDS: i64 = 15;
const HEARTBEAT_MILLISECONDS: u64 = 500;
const LEASE_REFRESH_TICKS: u8 = 10;

fn lease_deadline() -> DateTime<Utc> {
    Utc::now() + chrono::Duration::seconds(LEASE_SECONDS)
}

/// Immutable DAST request captured by a scan job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DastJobRequest {
    /// Target URL authorized for this job.
    pub target: String,
    /// Named scan profile.
    pub profile: String,
    /// Optional explicit module allow-list.
    pub modules: Option<Vec<String>>,
    /// Explicit module deny-list.
    pub skip: Vec<String>,
    /// Exact engagement in force when the request was accepted.
    pub engagement: Engagement,
}

impl DastJobRequest {
    /// Create a DAST job request.
    #[must_use]
    pub fn new(
        target: impl Into<String>,
        profile: impl Into<String>,
        engagement: Engagement,
    ) -> Self {
        Self {
            target: target.into(),
            profile: profile.into(),
            modules: None,
            skip: Vec::new(),
            engagement,
        }
    }

    /// Set the explicit module allow-list.
    #[must_use]
    pub fn with_modules(mut self, modules: Option<Vec<String>>) -> Self {
        self.modules = modules;
        self
    }

    /// Set the explicit module deny-list.
    #[must_use]
    pub fn with_skip(mut self, skip: Vec<String>) -> Self {
        self.skip = skip;
        self
    }
}

/// Persisted scan job lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanJobState {
    /// Accepted and stored, but not yet running.
    Queued,
    /// Scanner work is active.
    Running,
    /// Cancellation is persisted and the active token has been signalled.
    Cancelling,
    /// Scanner work stopped because cancellation was requested.
    Cancelled,
    /// Scanner work and terminal persistence completed successfully.
    Succeeded,
    /// Scanner or lifecycle persistence failed.
    Failed,
    /// A prior process abandoned a nonterminal job.
    Interrupted,
}

impl ScanJobState {
    /// Return whether this state can no longer execute.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Cancelled | Self::Succeeded | Self::Failed | Self::Interrupted)
    }

    /// Stable database and wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Cancelling => "cancelling",
            Self::Cancelled => "cancelled",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        }
    }

    const fn allows(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Queued, Self::Running | Self::Cancelled | Self::Interrupted)
                | (
                    Self::Running,
                    Self::Cancelling | Self::Succeeded | Self::Failed | Self::Interrupted
                )
                | (Self::Cancelling, Self::Cancelled | Self::Failed | Self::Interrupted)
        )
    }
}

/// Recoverable progress committed by module boundary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanJobProgress {
    /// Number of selected modules, including unavailable tools.
    pub total_modules: usize,
    /// Modules currently being polled.
    pub active_modules: Vec<String>,
    /// Modules whose findings were committed atomically with completion.
    pub completed_modules: Vec<String>,
    /// Modules skipped before execution.
    pub skipped_modules: Vec<String>,
    /// Modules that returned an error.
    pub failed_modules: Vec<String>,
    /// Findings produced by completed modules only.
    pub findings: Vec<Finding>,
}

impl ScanJobProgress {
    /// Number of modules with a durable outcome.
    #[must_use]
    pub const fn processed_modules(&self) -> usize {
        self.completed_modules.len() + self.skipped_modules.len() + self.failed_modules.len()
    }

    fn normalize(&mut self) {
        self.active_modules.sort();
        self.active_modules.dedup();
        self.completed_modules.sort();
        self.completed_modules.dedup();
        self.skipped_modules.sort();
        self.skipped_modules.dedup();
        self.failed_modules.sort();
        self.failed_modules.dedup();
    }
}

/// One persisted scan attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    /// Unique attempt identifier.
    pub id: Uuid,
    /// First attempt in this recovery chain.
    pub root_job_id: Uuid,
    /// Prior interrupted attempt, if this is a resume.
    pub parent_job_id: Option<Uuid>,
    /// One-based attempt number.
    pub attempt: u32,
    /// Immutable authorized request.
    pub request: DastJobRequest,
    /// Current lifecycle state.
    pub state: ScanJobState,
    /// Optimistic-lock revision.
    pub revision: u64,
    /// Process instance currently responsible for this attempt.
    pub owner_id: Option<Uuid>,
    /// Bounded ownership lease used to distinguish abandoned work from another live process.
    pub lease_expires_at: Option<DateTime<Utc>>,
    /// Durable module-level progress.
    pub progress: ScanJobProgress,
    /// Complete result, present only after success.
    pub result: Option<ScanResult>,
    /// Terminal or diagnostic error text.
    pub error: Option<String>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// First running timestamp.
    pub started_at: Option<DateTime<Utc>>,
    /// Last mutation timestamp.
    pub updated_at: DateTime<Utc>,
    /// Terminal timestamp.
    pub finished_at: Option<DateTime<Utc>>,
}

/// Append-only audit event recorded with a persisted job revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanJobAuditEvent {
    /// Job whose state was committed.
    pub job_id: Uuid,
    /// Exact committed revision.
    pub revision: u64,
    /// Lifecycle state at that revision.
    pub state: ScanJobState,
    /// Timestamp of the committed job mutation.
    pub occurred_at: DateTime<Utc>,
}

impl From<&ScanJob> for ScanJobAuditEvent {
    fn from(job: &ScanJob) -> Self {
        Self {
            job_id: job.id,
            revision: job.revision,
            state: job.state,
            occurred_at: job.updated_at,
        }
    }
}

impl ScanJob {
    /// Create a queued first attempt.
    #[must_use]
    pub fn new(request: DastJobRequest, owner_id: Uuid) -> Self {
        let id = Uuid::new_v4();
        let now = Utc::now();
        Self {
            id,
            root_job_id: id,
            parent_job_id: None,
            attempt: 1,
            request,
            state: ScanJobState::Queued,
            revision: 0,
            owner_id: Some(owner_id),
            lease_expires_at: Some(lease_deadline()),
            progress: ScanJobProgress::default(),
            result: None,
            error: None,
            created_at: now,
            started_at: None,
            updated_at: now,
            finished_at: None,
        }
    }

    /// Create a queued successor that retains only safely completed work.
    #[must_use]
    pub fn successor(interrupted: &Self, owner_id: Uuid) -> Self {
        let mut successor = Self::new(interrupted.request.clone(), owner_id);
        successor.root_job_id = interrupted.root_job_id;
        successor.parent_job_id = Some(interrupted.id);
        successor.attempt = interrupted.attempt.saturating_add(1);
        successor.progress.total_modules = interrupted.progress.total_modules;
        successor.progress.completed_modules.clone_from(&interrupted.progress.completed_modules);
        successor.progress.findings.clone_from(&interrupted.progress.findings);
        successor
    }

    fn transition(&mut self, next: ScanJobState, now: DateTime<Utc>) -> Result<()> {
        if !self.state.allows(next) {
            return Err(ScorchError::Job(format!(
                "illegal scan job transition {} -> {}",
                self.state.as_str(),
                next.as_str()
            )));
        }
        self.state = next;
        if next == ScanJobState::Running {
            self.started_at.get_or_insert(now);
        }
        if next.is_terminal() {
            self.finished_at = Some(now);
            self.progress.active_modules.clear();
        }
        Ok(())
    }

    pub(crate) fn validate_create(&self) -> Result<()> {
        let valid_identity = if self.attempt == 1 {
            self.root_job_id == self.id && self.parent_job_id.is_none()
        } else {
            self.parent_job_id.is_some()
        };
        let valid_queued_state = self.state == ScanJobState::Queued
            && self.revision == 0
            && self.owner_id.is_some()
            && self.lease_expires_at.is_some()
            && self.progress.active_modules.is_empty()
            && self.progress.skipped_modules.is_empty()
            && self.progress.failed_modules.is_empty()
            && self.result.is_none()
            && self.error.is_none()
            && self.started_at.is_none()
            && self.finished_at.is_none();
        if !valid_queued_state || !valid_identity {
            return Err(ScorchError::Job(format!(
                "scan job {} is not a valid queued attempt",
                self.id
            )));
        }
        if self.attempt == 1
            && (self.progress.total_modules != 0
                || !self.progress.completed_modules.is_empty()
                || !self.progress.findings.is_empty())
        {
            return Err(ScorchError::Job(format!(
                "first scan job attempt {} cannot contain recovered progress",
                self.id
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_successor(&self, parent: &Self) -> Result<()> {
        let expected_attempt = parent
            .attempt
            .checked_add(1)
            .ok_or_else(|| ScorchError::Job(format!("scan job {} attempt overflow", parent.id)))?;
        let findings_match = serde_json::to_value(&self.progress.findings)?
            == serde_json::to_value(&parent.progress.findings)?;
        let valid_lineage = parent.state == ScanJobState::Interrupted
            && self.parent_job_id == Some(parent.id)
            && self.root_job_id == parent.root_job_id
            && self.attempt == expected_attempt
            && self.request == parent.request
            && self.progress.total_modules == parent.progress.total_modules
            && self.progress.completed_modules == parent.progress.completed_modules
            && findings_match;
        if !valid_lineage {
            return Err(ScorchError::Job(format!(
                "scan job {} is not a valid successor of {}",
                self.id, parent.id
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_replacement(
        &self,
        existing: &Self,
        expected_revision: u64,
    ) -> Result<()> {
        let immutable_changed = self.id != existing.id
            || self.root_job_id != existing.root_job_id
            || self.parent_job_id != existing.parent_job_id
            || self.attempt != existing.attempt
            || self.request != existing.request
            || self.created_at != existing.created_at;
        if immutable_changed {
            return Err(ScorchError::Job(format!(
                "scan job {} attempted to change immutable identity or request fields",
                existing.id
            )));
        }
        let next_revision = expected_revision.checked_add(1).ok_or_else(|| {
            ScorchError::Job(format!("scan job {} revision overflow", existing.id))
        })?;
        if existing.revision != expected_revision || self.revision != next_revision {
            return Err(ScorchError::Job(format!(
                "scan job {} replacement revision is inconsistent",
                existing.id
            )));
        }
        let same_active_state = self.state == existing.state
            && matches!(self.state, ScanJobState::Running | ScanJobState::Cancelling);
        if existing.state.is_terminal()
            || (!same_active_state && !existing.state.allows(self.state))
        {
            return Err(ScorchError::Job(format!(
                "illegal scan job store transition {} -> {}",
                existing.state.as_str(),
                self.state.as_str()
            )));
        }
        if self.updated_at < existing.updated_at {
            return Err(ScorchError::Job(format!(
                "scan job {} update timestamp moved backwards",
                existing.id
            )));
        }
        Ok(())
    }
}

/// Reliable module-boundary update emitted by a DAST orchestrator.
#[derive(Debug, Clone)]
pub enum JobProgressUpdate {
    /// A module began polling.
    Started { module_id: String },
    /// A module completed and its findings may now be recovered safely.
    Completed { module_id: String, findings: Vec<Finding> },
    /// A module was unavailable or excluded by a runtime prerequisite.
    Skipped { module_id: String },
    /// A module returned a nonfatal scan error.
    Failed { module_id: String },
}

/// Reliable progress boundary used by family adapters.
pub trait JobProgressSink: Send + Sync {
    /// Publish one owned module update.
    ///
    /// # Errors
    ///
    /// Returns an error when the lifecycle owner is no longer available to persist the update.
    fn publish(&self, update: JobProgressUpdate) -> Result<()>;
}

/// Persistence contract for scan jobs.
#[async_trait]
pub trait JobStore: Send + Sync {
    /// Insert a new job. Duplicate IDs are rejected.
    async fn create(&self, job: &ScanJob) -> Result<()>;
    /// Load one job.
    async fn get(&self, id: Uuid) -> Result<Option<ScanJob>>;
    /// List at most 1,000 jobs in deterministic creation order.
    async fn list(&self) -> Result<Vec<ScanJob>>;
    /// List one bounded batch of expired nonterminal jobs in deterministic order.
    async fn list_recoverable(&self, now: DateTime<Utc>) -> Result<Vec<ScanJob>>;
    /// Replace one job only if its current revision equals `expected_revision`.
    async fn compare_and_swap(&self, expected_revision: u64, job: &ScanJob) -> Result<bool>;
    /// Read the append-only revision audit trail for one job.
    async fn audit_events(&self, id: Uuid) -> Result<Vec<ScanJobAuditEvent>>;
}

/// Process-local store used by stateless MCP sessions and library callers.
#[derive(Debug, Default)]
pub struct InMemoryJobStore {
    state: RwLock<InMemoryJobState>,
}

#[derive(Debug, Default)]
struct InMemoryJobState {
    jobs: BTreeMap<(DateTime<Utc>, Uuid), ScanJob>,
    audit_events: HashMap<Uuid, Vec<ScanJobAuditEvent>>,
}

impl InMemoryJobStore {
    /// Create an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl JobStore for InMemoryJobStore {
    async fn create(&self, job: &ScanJob) -> Result<()> {
        job.validate_create()?;
        let mut state = self.state.write().await;
        if state.jobs.values().any(|existing| existing.id == job.id) {
            return Err(ScorchError::Job(format!("scan job {} already exists", job.id)));
        }
        if let Some(parent_id) = job.parent_job_id {
            let parent =
                state.jobs.values().find(|existing| existing.id == parent_id).ok_or_else(|| {
                    ScorchError::Job(format!("scan job parent {parent_id} was not found"))
                })?;
            job.validate_successor(parent)?;
            if state.jobs.values().any(|existing| existing.parent_job_id == Some(parent_id)) {
                return Err(ScorchError::Job(format!(
                    "scan job parent {parent_id} already has a successor"
                )));
            }
        }
        if state.jobs.values().any(|existing| {
            existing.root_job_id == job.root_job_id && existing.attempt == job.attempt
        }) {
            return Err(ScorchError::Job(format!(
                "scan job root {} already has attempt {}",
                job.root_job_id, job.attempt
            )));
        }
        state.jobs.insert((job.created_at, job.id), job.clone());
        state.audit_events.entry(job.id).or_default().push(job.into());
        drop(state);
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ScanJob>> {
        Ok(self.state.read().await.jobs.values().find(|job| job.id == id).cloned())
    }

    async fn list(&self) -> Result<Vec<ScanJob>> {
        Ok(self.state.read().await.jobs.values().take(JOB_LIST_LIMIT).cloned().collect())
    }

    async fn list_recoverable(&self, now: DateTime<Utc>) -> Result<Vec<ScanJob>> {
        Ok(self
            .state
            .read()
            .await
            .jobs
            .values()
            .filter(|job| {
                !job.state.is_terminal()
                    && job.lease_expires_at.is_none_or(|deadline| deadline <= now)
            })
            .take(JOB_LIST_LIMIT)
            .cloned()
            .collect())
    }

    async fn compare_and_swap(&self, expected_revision: u64, job: &ScanJob) -> Result<bool> {
        let mut state = self.state.write().await;
        let updated = if let Some(existing) =
            state.jobs.values_mut().find(|existing| existing.id == job.id)
        {
            if existing.revision == expected_revision {
                job.validate_replacement(existing, expected_revision)?;
                existing.clone_from(job);
                true
            } else {
                false
            }
        } else {
            false
        };
        if updated {
            state.audit_events.entry(job.id).or_default().push(job.into());
        }
        drop(state);
        Ok(updated)
    }

    async fn audit_events(&self, id: Uuid) -> Result<Vec<ScanJobAuditEvent>> {
        Ok(self.state.read().await.audit_events.get(&id).cloned().unwrap_or_default())
    }
}

#[derive(Clone)]
struct ChannelProgressSink {
    sender: mpsc::Sender<JobProgressUpdate>,
}

impl JobProgressSink for ChannelProgressSink {
    fn publish(&self, update: JobProgressUpdate) -> Result<()> {
        self.sender.try_send(update).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => ScorchError::Job(format!(
                "scan job progress exceeded the bounded {PROGRESS_CHANNEL_CAPACITY}-update buffer"
            )),
            mpsc::error::TrySendError::Closed(_) => {
                ScorchError::Job("scan job progress writer stopped".to_string())
            }
        })
    }
}

struct ActiveRunGuard {
    id: Uuid,
    active: Arc<StdMutex<HashMap<Uuid, CancellationToken>>>,
    cancellation: CancellationToken,
    heartbeat_stop: Option<CancellationToken>,
}

impl ActiveRunGuard {
    const fn new(
        id: Uuid,
        active: Arc<StdMutex<HashMap<Uuid, CancellationToken>>>,
        cancellation: CancellationToken,
    ) -> Self {
        Self { id, active, cancellation, heartbeat_stop: None }
    }

    fn track_heartbeat(&mut self, stop: CancellationToken) {
        self.heartbeat_stop = Some(stop);
    }
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(stop) = &self.heartbeat_stop {
            stop.cancel();
        }
        self.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&self.id);
    }
}

/// DAST job control plane shared by CLI and MCP adapters.
#[derive(Clone)]
pub struct ScanJobService {
    config: Arc<AppConfig>,
    store: Arc<dyn JobStore>,
    active: Arc<StdMutex<HashMap<Uuid, CancellationToken>>>,
    owner_id: Uuid,
}

impl ScanJobService {
    /// Build a service over an arbitrary job store.
    #[must_use]
    pub fn new(config: Arc<AppConfig>, store: Arc<dyn JobStore>) -> Self {
        Self {
            config,
            store,
            active: Arc::new(StdMutex::new(HashMap::new())),
            owner_id: Uuid::new_v4(),
        }
    }

    /// Build a process-local service suitable for stateless MCP.
    #[must_use]
    pub fn in_memory(config: Arc<AppConfig>) -> Self {
        Self::new(config, Arc::new(InMemoryJobStore::new()))
    }

    /// Borrow the configured store.
    #[must_use]
    pub fn store(&self) -> &Arc<dyn JobStore> {
        &self.store
    }

    /// Validate, authorize, and persist a queued job before execution.
    ///
    /// # Errors
    ///
    /// Returns an error when policy denies the request or the store cannot persist it.
    pub async fn submit(&self, request: DastJobRequest) -> Result<ScanJob> {
        self.authorize_request(&request)?;
        let job = ScanJob::new(request, self.owner_id);
        self.store.create(&job).await?;
        Ok(job)
    }

    /// Load one job or return a typed lifecycle error.
    ///
    /// # Errors
    ///
    /// Returns an error when storage fails or the job does not exist.
    pub async fn get(&self, id: Uuid) -> Result<ScanJob> {
        self.store
            .get(id)
            .await?
            .ok_or_else(|| ScorchError::Job(format!("scan job {id} was not found")))
    }

    /// List at most 1,000 jobs in deterministic creation order.
    ///
    /// # Errors
    ///
    /// Returns an error when storage cannot list the jobs.
    pub async fn list(&self) -> Result<Vec<ScanJob>> {
        self.store.list().await
    }

    /// Execute one queued DAST job in the current task.
    ///
    /// The caller owns process lifetime. MCP may spawn this future; CLI runs it in the foreground.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid lifecycle state, changed authorization, scanner failure, or
    /// durable progress failure. Failures after execution starts are committed to the job when the
    /// store remains available.
    pub async fn run(&self, id: Uuid) -> Result<ScanJob> {
        let queued = self.get(id).await?;
        if queued.state != ScanJobState::Queued {
            return Err(ScorchError::Job(format!(
                "scan job {id} is {}, expected queued",
                queued.state.as_str()
            )));
        }
        if queued.owner_id != Some(self.owner_id) {
            return Err(ScorchError::Job(format!("scan job {id} is owned by another process")));
        }
        self.authorize_request(&queued.request)?;
        let recovered_findings = queued.progress.findings.clone();
        let recovered_modules = queued.progress.completed_modules.clone();

        let mut orchestrator = self.orchestrator_for(&queued)?;

        let total_modules =
            queued.progress.completed_modules.len().saturating_add(orchestrator.module_count());
        let cancellation = CancellationToken::new();
        {
            let mut active = self.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if active.contains_key(&id) {
                return Err(ScorchError::Job(format!(
                    "scan job {id} is already running in this process"
                )));
            }
            active.insert(id, cancellation.clone());
        }
        let mut run_guard = ActiveRunGuard::new(id, Arc::clone(&self.active), cancellation.clone());

        self.mutate(id, |job| {
            job.transition(ScanJobState::Running, Utc::now())?;
            job.progress.total_modules = total_modules;
            job.lease_expires_at = Some(lease_deadline());
            Ok(())
        })
        .await?;

        let (sender, receiver) = mpsc::channel(PROGRESS_CHANNEL_CAPACITY);
        orchestrator.set_job_progress_sink(Arc::new(ChannelProgressSink { sender }));
        let writer_service = self.clone();
        let writer_cancellation = cancellation.clone();
        let writer = tokio::spawn(async move {
            let result = writer_service.persist_progress(id, receiver).await;
            if result.is_err() {
                writer_cancellation.cancel();
            }
            result
        });
        let heartbeat_stop = CancellationToken::new();
        run_guard.track_heartbeat(heartbeat_stop.clone());
        let heartbeat_service = self.clone();
        let heartbeat_cancellation = cancellation.clone();
        let heartbeat_stop_task = heartbeat_stop.clone();
        let heartbeat = tokio::spawn(async move {
            heartbeat_service.heartbeat(id, heartbeat_cancellation, heartbeat_stop_task).await
        });

        let scan_result = orchestrator.run_with_cancellation(true, &cancellation).await;
        drop(orchestrator);
        if let Err(error) = Self::finish_control_tasks(writer, heartbeat_stop, heartbeat).await {
            return self.finish_failed(id, error.to_string()).await;
        }
        self.finish_scan(id, scan_result, recovered_findings, recovered_modules).await
    }

    /// Request cancellation. Repeated requests while cancellation is pending or complete are safe.
    ///
    /// # Errors
    ///
    /// Returns an error when the job cannot be loaded, persisted, or legally cancelled.
    pub async fn cancel(&self, id: Uuid) -> Result<ScanJob> {
        let cancelling = self.persist_cancellation(id).await?;
        let active_token =
            self.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&id).cloned();
        if let Some(token) = active_token {
            token.cancel();
        }
        Ok(cancelling)
    }

    /// Mark every abandoned nonterminal job as interrupted and retain its durable progress.
    ///
    /// # Errors
    ///
    /// Returns an error when storage cannot list or update an abandoned job.
    pub async fn recover_interrupted(&self) -> Result<Vec<ScanJob>> {
        let jobs = self.store.list_recoverable(Utc::now()).await?;
        let mut recovered = Vec::new();
        for job in jobs {
            if let Some(interrupted) = self.try_recover(job.id).await? {
                recovered.push(interrupted);
            }
        }
        Ok(recovered)
    }

    /// Create a queued successor for one interrupted attempt after reauthorization.
    ///
    /// # Errors
    ///
    /// Returns an error when the prior attempt is not interrupted, authorization changed, or the
    /// successor cannot be persisted.
    pub async fn resume(&self, id: Uuid) -> Result<ScanJob> {
        let interrupted = self.get(id).await?;
        if interrupted.state != ScanJobState::Interrupted {
            return Err(ScorchError::Job(format!(
                "scan job {id} is {}, expected interrupted",
                interrupted.state.as_str()
            )));
        }
        self.authorize_request(&interrupted.request)?;
        let successor = ScanJob::successor(&interrupted, self.owner_id);
        self.store.create(&successor).await?;
        Ok(successor)
    }

    fn orchestrator_for(&self, job: &ScanJob) -> Result<Orchestrator> {
        let engine = Engine::new(Arc::clone(&self.config));
        let ctx = engine.dast_context(&job.request.target, &job.request.profile)?;
        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile(&job.request.profile);
        if let Some(modules) = &job.request.modules {
            orchestrator.filter_by_ids(modules);
        }
        let mut excluded = job.request.skip.clone();
        excluded.extend(job.progress.completed_modules.iter().cloned());
        if !excluded.is_empty() {
            orchestrator.exclude_by_ids(&excluded);
        }
        Ok(orchestrator)
    }

    async fn finish_control_tasks(
        writer: JoinHandle<Result<()>>,
        heartbeat_stop: CancellationToken,
        heartbeat: JoinHandle<Result<()>>,
    ) -> Result<()> {
        let progress_result = writer
            .await
            .map_err(|error| ScorchError::Job(format!("scan job progress task failed: {error}")))
            .and_then(std::convert::identity);
        heartbeat_stop.cancel();
        let heartbeat_result = heartbeat
            .await
            .map_err(|error| ScorchError::Job(format!("scan job heartbeat task failed: {error}")))
            .and_then(std::convert::identity);
        progress_result?;
        heartbeat_result
    }

    async fn finish_scan(
        &self,
        id: Uuid,
        scan_result: Result<ScanResult>,
        recovered_findings: Vec<Finding>,
        recovered_modules: Vec<String>,
    ) -> Result<ScanJob> {
        match scan_result {
            Ok(mut result) => {
                result.findings.splice(0..0, recovered_findings);
                for module in recovered_modules.into_iter().rev() {
                    if !result.modules_run.contains(&module) {
                        result.modules_run.insert(0, module);
                    }
                }
                result.summary = ScanSummary::from_findings(&result.findings);
                self.mutate(id, |job| {
                    if job.state == ScanJobState::Cancelling {
                        job.transition(ScanJobState::Cancelled, Utc::now())?;
                        job.error = Some("cancelled before successful job commit".to_string());
                    } else {
                        job.transition(ScanJobState::Succeeded, Utc::now())?;
                        job.result = Some(result.clone());
                        job.error = None;
                    }
                    job.owner_id = None;
                    job.lease_expires_at = None;
                    Ok(())
                })
                .await
            }
            Err(ScorchError::Cancelled { reason }) => {
                self.mutate(id, |job| {
                    if job.state == ScanJobState::Running {
                        job.transition(ScanJobState::Cancelling, Utc::now())?;
                    }
                    job.transition(ScanJobState::Cancelled, Utc::now())?;
                    job.error = Some(reason.clone());
                    job.owner_id = None;
                    job.lease_expires_at = None;
                    Ok(())
                })
                .await
            }
            Err(error) => self.finish_failed(id, error.to_string()).await,
        }
    }

    fn authorize_request(&self, request: &DastJobRequest) -> Result<()> {
        let current = self.config.engagement.as_ref().ok_or_else(|| {
            ScorchError::Job("scan job requires current engagement authorization".to_string())
        })?;
        if current != &request.engagement {
            return Err(ScorchError::Job(
                "stored scan job engagement does not match the current engagement".to_string(),
            ));
        }
        let target = Target::parse(&request.target)?;
        if !target.url.username().is_empty() || target.url.password().is_some() {
            return Err(ScorchError::Job(
                "scan job target URLs must not contain embedded credentials".to_string(),
            ));
        }
        let engine = Engine::new(Arc::clone(&self.config));
        let _authorized_context = engine.dast_context(&request.target, &request.profile)?;
        Ok(())
    }

    async fn persist_progress(
        &self,
        id: Uuid,
        mut receiver: mpsc::Receiver<JobProgressUpdate>,
    ) -> Result<()> {
        while let Some(update) = receiver.recv().await {
            self.mutate(id, |job| {
                if !matches!(job.state, ScanJobState::Running | ScanJobState::Cancelling) {
                    return Err(ScorchError::Job(format!(
                        "scan job {id} cannot accept progress while {}",
                        job.state.as_str()
                    )));
                }
                match &update {
                    JobProgressUpdate::Started { module_id } => {
                        if !job.progress.active_modules.contains(module_id) {
                            job.progress.active_modules.push(module_id.clone());
                        }
                    }
                    JobProgressUpdate::Completed { module_id, findings } => {
                        job.progress.active_modules.retain(|active| active != module_id);
                        if !job.progress.completed_modules.contains(module_id) {
                            job.progress.completed_modules.push(module_id.clone());
                            job.progress.findings.extend(findings.clone());
                        }
                    }
                    JobProgressUpdate::Skipped { module_id } => {
                        job.progress.active_modules.retain(|active| active != module_id);
                        if !job.progress.skipped_modules.contains(module_id) {
                            job.progress.skipped_modules.push(module_id.clone());
                        }
                    }
                    JobProgressUpdate::Failed { module_id } => {
                        job.progress.active_modules.retain(|active| active != module_id);
                        if !job.progress.failed_modules.contains(module_id) {
                            job.progress.failed_modules.push(module_id.clone());
                        }
                    }
                }
                job.progress.normalize();
                Ok(())
            })
            .await?;
        }
        Ok(())
    }

    async fn finish_failed(&self, id: Uuid, error: String) -> Result<ScanJob> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let mut candidate = self.get(id).await?;
            if candidate.state.is_terminal() {
                return Ok(candidate);
            }
            if !matches!(candidate.state, ScanJobState::Running | ScanJobState::Cancelling) {
                return Err(ScorchError::Job(format!(
                    "scan job {id} cannot fail while {}",
                    candidate.state.as_str()
                )));
            }
            let expected_revision = candidate.revision;
            candidate.transition(ScanJobState::Failed, Utc::now())?;
            candidate.error = Some(error.clone());
            candidate.owner_id = None;
            candidate.lease_expires_at = None;
            candidate.revision = candidate
                .revision
                .checked_add(1)
                .ok_or_else(|| ScorchError::Job(format!("scan job {id} revision overflow")))?;
            candidate.updated_at = Utc::now();
            if self.store.compare_and_swap(expected_revision, &candidate).await? {
                return Ok(candidate);
            }
        }
        Err(ScorchError::Job(format!(
            "scan job {id} failure commit exceeded {MAX_CAS_ATTEMPTS} revision conflicts"
        )))
    }

    async fn persist_cancellation(&self, id: Uuid) -> Result<ScanJob> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let mut candidate = self.get(id).await?;
            match candidate.state {
                ScanJobState::Cancelling | ScanJobState::Cancelled => return Ok(candidate),
                ScanJobState::Queued => {
                    candidate.transition(ScanJobState::Cancelled, Utc::now())?;
                    candidate.owner_id = None;
                    candidate.lease_expires_at = None;
                }
                ScanJobState::Running => {
                    candidate.transition(ScanJobState::Cancelling, Utc::now())?;
                }
                state => {
                    return Err(ScorchError::Job(format!(
                        "scan job {id} is {} and cannot be cancelled",
                        state.as_str()
                    )));
                }
            }
            let expected_revision = candidate.revision;
            candidate.revision = candidate
                .revision
                .checked_add(1)
                .ok_or_else(|| ScorchError::Job(format!("scan job {id} revision overflow")))?;
            candidate.updated_at = Utc::now();
            if self.store.compare_and_swap(expected_revision, &candidate).await? {
                return Ok(candidate);
            }
        }
        Err(ScorchError::Job(format!(
            "scan job {id} cancellation exceeded {MAX_CAS_ATTEMPTS} revision conflicts"
        )))
    }

    async fn try_recover(&self, id: Uuid) -> Result<Option<ScanJob>> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let mut candidate = self.get(id).await?;
            if candidate.state.is_terminal()
                || candidate.lease_expires_at.is_some_and(|deadline| deadline > Utc::now())
            {
                return Ok(None);
            }
            let expected_revision = candidate.revision;
            candidate.transition(ScanJobState::Interrupted, Utc::now())?;
            candidate.error = Some("job owner exited before terminal commit".to_string());
            candidate.owner_id = None;
            candidate.lease_expires_at = None;
            candidate.revision = candidate
                .revision
                .checked_add(1)
                .ok_or_else(|| ScorchError::Job(format!("scan job {id} revision overflow")))?;
            candidate.updated_at = Utc::now();
            if self.store.compare_and_swap(expected_revision, &candidate).await? {
                return Ok(Some(candidate));
            }
        }
        Err(ScorchError::Job(format!(
            "scan job {id} recovery exceeded {MAX_CAS_ATTEMPTS} revision conflicts"
        )))
    }

    async fn heartbeat(
        &self,
        id: Uuid,
        cancellation: CancellationToken,
        stop: CancellationToken,
    ) -> Result<()> {
        let cancel_on_error = cancellation.clone();
        let result = self.heartbeat_loop(id, cancellation, stop).await;
        if result.is_err() {
            cancel_on_error.cancel();
        }
        result
    }

    async fn heartbeat_loop(
        &self,
        id: Uuid,
        cancellation: CancellationToken,
        stop: CancellationToken,
    ) -> Result<()> {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_millis(HEARTBEAT_MILLISECONDS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut refresh_ticks = 0_u8;
        loop {
            tokio::select! {
                biased;
                () = stop.cancelled() => return Ok(()),
                _ = interval.tick() => {
                    let current = self.get(id).await?;
                    match current.state {
                        ScanJobState::Running | ScanJobState::Cancelling => {
                            if current.state == ScanJobState::Cancelling {
                                cancellation.cancel();
                            }
                            if current.owner_id != Some(self.owner_id) {
                                cancellation.cancel();
                                return Err(ScorchError::Job(format!(
                                    "scan job {id} ownership changed during execution"
                                )));
                            }
                            refresh_ticks = refresh_ticks.saturating_add(1);
                            if refresh_ticks >= LEASE_REFRESH_TICKS {
                                self.mutate(id, |job| {
                                    if matches!(job.state, ScanJobState::Running | ScanJobState::Cancelling)
                                        && job.owner_id == Some(self.owner_id)
                                    {
                                        job.lease_expires_at = Some(lease_deadline());
                                    }
                                    Ok(())
                                })
                                .await?;
                                refresh_ticks = 0;
                            }
                        }
                        ScanJobState::Cancelled
                        | ScanJobState::Succeeded
                        | ScanJobState::Failed
                        | ScanJobState::Interrupted => {
                            cancellation.cancel();
                            return Ok(());
                        }
                        ScanJobState::Queued => {}
                    }
                }
            }
        }
    }

    async fn mutate<F>(&self, id: Uuid, mutation: F) -> Result<ScanJob>
    where
        F: Fn(&mut ScanJob) -> Result<()>,
    {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let mut candidate = self.get(id).await?;
            let expected_revision = candidate.revision;
            mutation(&mut candidate)?;
            candidate.revision = candidate
                .revision
                .checked_add(1)
                .ok_or_else(|| ScorchError::Job(format!("scan job {id} revision overflow")))?;
            candidate.updated_at = Utc::now();
            if self.store.compare_and_swap(expected_revision, &candidate).await? {
                return Ok(candidate);
            }
        }
        Err(ScorchError::Job(format!(
            "scan job {id} could not be updated after {MAX_CAS_ATTEMPTS} revision conflicts"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::policy::{Capability, EffectClass, EngagementPolicy};
    use crate::engine::scope::ScopeRule;
    use crate::engine::target::Target;

    fn request() -> DastJobRequest {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::Exact("localhost".to_string()))
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::ActiveSafe);
        DastJobRequest::new("http://localhost:3000", "quick", Engagement::new("job-test", policy))
    }

    fn result() -> ScanResult {
        ScanResult::new(
            "job-result".to_string(),
            Target::parse("http://localhost:3000").expect("valid target"),
            Utc::now(),
            Vec::new(),
            vec!["headers".to_string()],
            Vec::new(),
        )
    }

    fn assert_invalid_create(mut job: ScanJob, mutate: impl FnOnce(&mut ScanJob)) {
        mutate(&mut job);
        assert!(job.validate_create().is_err(), "forged queued job must be rejected");
    }

    fn assert_invalid_replacement(
        existing: &ScanJob,
        mut candidate: ScanJob,
        expected_revision: u64,
        mutate: impl FnOnce(&mut ScanJob),
    ) {
        mutate(&mut candidate);
        assert!(
            candidate.validate_replacement(existing, expected_revision).is_err(),
            "invalid replacement must be rejected"
        );
    }

    #[test]
    fn lease_deadline_is_in_the_future() {
        let before = Utc::now();
        let deadline = lease_deadline();
        let after = Utc::now() + chrono::Duration::seconds(LEASE_SECONDS + 1);
        assert!(deadline > before);
        assert!(deadline <= after);
    }

    #[test]
    fn progress_counts_and_normalizes_every_outcome_bucket() {
        let mut progress = ScanJobProgress {
            active_modules: vec!["z".to_string(), "a".to_string(), "z".to_string()],
            completed_modules: vec!["b".to_string(), "a".to_string(), "b".to_string()],
            skipped_modules: vec!["d".to_string(), "c".to_string(), "d".to_string()],
            failed_modules: vec!["f".to_string(), "e".to_string(), "f".to_string()],
            ..ScanJobProgress::default()
        };
        assert_eq!(progress.processed_modules(), 9);
        progress.normalize();
        assert_eq!(progress.active_modules, ["a", "z"]);
        assert_eq!(progress.completed_modules, ["a", "b"]);
        assert_eq!(progress.skipped_modules, ["c", "d"]);
        assert_eq!(progress.failed_modules, ["e", "f"]);
    }

    #[test]
    fn transition_table_rejects_terminal_reentry() {
        let mut job = ScanJob::new(request(), Uuid::new_v4());
        job.progress.active_modules.push("headers".to_string());
        let started_at = Utc::now();
        job.transition(ScanJobState::Running, started_at).expect("queued -> running");
        assert_eq!(job.started_at, Some(started_at));
        assert!(job.finished_at.is_none());
        let finished_at = Utc::now();
        job.transition(ScanJobState::Succeeded, finished_at).expect("running -> succeeded");
        assert_eq!(job.started_at, Some(started_at));
        assert_eq!(job.finished_at, Some(finished_at));
        assert!(job.progress.active_modules.is_empty());
        let error = job
            .transition(ScanJobState::Running, Utc::now())
            .expect_err("terminal transition must fail");
        assert!(error.to_string().contains("illegal scan job transition"));
    }

    #[test]
    fn create_validation_checks_every_identity_state_and_progress_field() {
        let pristine = ScanJob::new(request(), Uuid::new_v4());
        pristine.validate_create().expect("new root is valid");

        assert_invalid_create(pristine.clone(), |job| job.root_job_id = Uuid::new_v4());
        assert_invalid_create(pristine.clone(), |job| job.parent_job_id = Some(Uuid::new_v4()));
        assert_invalid_create(pristine.clone(), |job| job.state = ScanJobState::Running);
        assert_invalid_create(pristine.clone(), |job| job.revision = 1);
        assert_invalid_create(pristine.clone(), |job| job.owner_id = None);
        assert_invalid_create(pristine.clone(), |job| job.lease_expires_at = None);
        assert_invalid_create(pristine.clone(), |job| {
            job.progress.active_modules.push("headers".to_string());
        });
        assert_invalid_create(pristine.clone(), |job| {
            job.progress.skipped_modules.push("headers".to_string());
        });
        assert_invalid_create(pristine.clone(), |job| {
            job.progress.failed_modules.push("headers".to_string());
        });
        assert_invalid_create(pristine.clone(), |job| job.result = Some(result()));
        assert_invalid_create(pristine.clone(), |job| job.error = Some("failure".to_string()));
        assert_invalid_create(pristine.clone(), |job| job.started_at = Some(Utc::now()));
        assert_invalid_create(pristine.clone(), |job| job.finished_at = Some(Utc::now()));
        assert_invalid_create(pristine.clone(), |job| job.progress.total_modules = 1);
        assert_invalid_create(pristine.clone(), |job| {
            job.progress.completed_modules.push("headers".to_string());
        });
        assert_invalid_create(pristine.clone(), |job| {
            job.progress.findings.push(Finding::new(
                "headers",
                crate::engine::severity::Severity::Low,
                "header",
                "description",
                "http://localhost:3000",
            ));
        });

        let mut interrupted = pristine;
        interrupted.state = ScanJobState::Interrupted;
        interrupted.progress.total_modules = 1;
        interrupted.progress.completed_modules.push("headers".to_string());
        let successor = ScanJob::successor(&interrupted, Uuid::new_v4());
        successor.validate_create().expect("successor may retain completed progress");
        assert_invalid_create(successor, |job| job.parent_job_id = None);
    }

    #[test]
    fn successor_keeps_only_completed_evidence() {
        let mut interrupted = ScanJob::new(request(), Uuid::new_v4());
        interrupted.progress.total_modules = 3;
        interrupted.progress.completed_modules.push("headers".to_string());
        interrupted.progress.skipped_modules.push("nuclei".to_string());
        interrupted.progress.failed_modules.push("ssl".to_string());
        interrupted.progress.findings.push(Finding::new(
            "headers",
            crate::engine::severity::Severity::Low,
            "header",
            "description",
            "http://localhost:3000",
        ));
        let successor = ScanJob::successor(&interrupted, Uuid::new_v4());
        assert_eq!(successor.parent_job_id, Some(interrupted.id));
        assert_eq!(successor.attempt, 2);
        assert_eq!(successor.progress.completed_modules, ["headers"]);
        assert!(successor.progress.skipped_modules.is_empty());
        assert!(successor.progress.failed_modules.is_empty());
        assert_eq!(successor.progress.findings.len(), 1);
    }

    #[test]
    fn successor_validation_checks_complete_lineage() {
        let mut parent = ScanJob::new(request(), Uuid::new_v4());
        parent.state = ScanJobState::Interrupted;
        parent.progress.total_modules = 1;
        parent.progress.completed_modules.push("headers".to_string());
        let successor = ScanJob::successor(&parent, Uuid::new_v4());
        successor.validate_successor(&parent).expect("successor lineage is valid");

        let mut active_parent = parent.clone();
        active_parent.state = ScanJobState::Running;
        assert!(successor.validate_successor(&active_parent).is_err());
        for forged in [
            {
                let mut job = successor.clone();
                job.parent_job_id = Some(Uuid::new_v4());
                job
            },
            {
                let mut job = successor.clone();
                job.root_job_id = Uuid::new_v4();
                job
            },
            {
                let mut job = successor.clone();
                job.attempt = job.attempt.saturating_add(1);
                job
            },
            {
                let mut job = successor.clone();
                job.request.profile = "standard".to_string();
                job
            },
            {
                let mut job = successor.clone();
                job.progress.total_modules = 2;
                job
            },
            {
                let mut job = successor.clone();
                job.progress.completed_modules.clear();
                job
            },
            {
                let mut job = successor;
                job.progress.findings.push(Finding::new(
                    "headers",
                    crate::engine::severity::Severity::Low,
                    "unexpected",
                    "description",
                    "http://localhost:3000",
                ));
                job
            },
        ] {
            assert!(forged.validate_successor(&parent).is_err());
        }
    }

    #[test]
    fn replacement_validation_checks_all_store_invariants() {
        let existing = ScanJob::new(request(), Uuid::new_v4());
        let mut valid = existing.clone();
        valid.state = ScanJobState::Running;
        valid.revision = 1;
        valid.started_at = Some(existing.updated_at);
        valid.validate_replacement(&existing, 0).expect("queued -> running replacement is valid");

        assert_invalid_replacement(&existing, valid.clone(), 0, |job| job.id = Uuid::new_v4());
        assert_invalid_replacement(&existing, valid.clone(), 0, |job| {
            job.root_job_id = Uuid::new_v4();
        });
        assert_invalid_replacement(&existing, valid.clone(), 0, |job| {
            job.parent_job_id = Some(Uuid::new_v4());
        });
        assert_invalid_replacement(&existing, valid.clone(), 0, |job| job.attempt = 2);
        assert_invalid_replacement(&existing, valid.clone(), 0, |job| {
            job.request.profile = "standard".to_string();
        });
        assert_invalid_replacement(&existing, valid.clone(), 0, |job| {
            job.created_at += chrono::Duration::seconds(1);
        });

        let mut existing_revision_mismatch = valid.clone();
        existing_revision_mismatch.revision = 2;
        assert!(existing_revision_mismatch.validate_replacement(&existing, 1).is_err());
        let mut candidate_revision_mismatch = valid.clone();
        candidate_revision_mismatch.revision = 2;
        assert!(candidate_revision_mismatch.validate_replacement(&existing, 0).is_err());

        let mut queued_reentry = existing.clone();
        queued_reentry.revision = 1;
        assert!(queued_reentry.validate_replacement(&existing, 0).is_err());
        let mut illegal_jump = valid.clone();
        illegal_jump.state = ScanJobState::Succeeded;
        assert!(illegal_jump.validate_replacement(&existing, 0).is_err());

        let mut active = valid;
        active.updated_at += chrono::Duration::seconds(1);
        let mut active_refresh = active.clone();
        active_refresh.revision = 2;
        active_refresh.validate_replacement(&active, 1).expect("running refresh is valid");
        let mut backwards = active_refresh;
        backwards.updated_at = existing.updated_at;
        assert!(backwards.validate_replacement(&active, 1).is_err());

        let mut terminal = active;
        terminal.state = ScanJobState::Succeeded;
        terminal.finished_at = Some(terminal.updated_at);
        let mut terminal_reentry = terminal.clone();
        terminal_reentry.revision = 2;
        assert!(terminal_reentry.validate_replacement(&terminal, 1).is_err());
    }

    #[tokio::test]
    async fn memory_store_compare_and_swap_rejects_stale_revision() {
        let store = InMemoryJobStore::new();
        let job = ScanJob::new(request(), Uuid::new_v4());
        store.create(&job).await.expect("create job");
        let mut updated = job.clone();
        updated.revision = 1;
        updated.state = ScanJobState::Running;
        updated.lease_expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        updated.started_at = Some(Utc::now());
        updated.updated_at = Utc::now();
        assert!(store.compare_and_swap(0, &updated).await.expect("first update"));
        assert!(!store.compare_and_swap(0, &job).await.expect("stale update"));
        assert_eq!(store.get(job.id).await.expect("read job").expect("job").revision, 1);
        assert_eq!(store.list_recoverable(Utc::now()).await.expect("recoverable jobs").len(), 1);
        let mut illegal = updated.clone();
        illegal.revision = 2;
        illegal.request.target = "http://changed.example".to_string();
        illegal.updated_at = Utc::now();
        assert!(store.compare_and_swap(1, &illegal).await.is_err());
        let audit = store.audit_events(job.id).await.expect("read audit events");
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[0].revision, 0);
        assert_eq!(audit[1].revision, 1);

        let fresh = ScanJob::new(request(), Uuid::new_v4());
        store.create(&fresh).await.expect("create independent root job");
        let mut terminal = ScanJob::new(request(), Uuid::new_v4());
        store.create(&terminal).await.expect("create terminal fixture");
        terminal.state = ScanJobState::Cancelled;
        terminal.revision = 1;
        terminal.owner_id = None;
        terminal.lease_expires_at = None;
        terminal.finished_at = Some(Utc::now());
        terminal.updated_at = Utc::now();
        assert!(store.compare_and_swap(0, &terminal).await.expect("cancel terminal fixture"));

        let listed = store.list().await.expect("list jobs");
        assert_eq!(listed.len(), 3);
        let recoverable = store.list_recoverable(Utc::now()).await.expect("recoverable jobs");
        assert_eq!(recoverable.len(), 1);
        assert_eq!(recoverable[0].id, job.id);
    }

    #[test]
    fn active_run_guard_stops_tracked_heartbeat_on_drop() {
        let active = Arc::new(StdMutex::new(HashMap::new()));
        let cancellation = CancellationToken::new();
        let heartbeat_stop = CancellationToken::new();
        let id = Uuid::new_v4();
        active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, cancellation.clone());
        let mut guard = ActiveRunGuard::new(id, Arc::clone(&active), cancellation.clone());
        guard.track_heartbeat(heartbeat_stop.clone());
        drop(guard);
        assert!(cancellation.is_cancelled());
        assert!(heartbeat_stop.is_cancelled());
        assert!(active.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty());
    }

    #[tokio::test]
    async fn service_list_failure_and_live_lease_contracts_are_observable() {
        let job_request = request();
        let config =
            AppConfig { engagement: Some(job_request.engagement.clone()), ..AppConfig::default() };
        let service = ScanJobService::in_memory(Arc::new(config));
        let first = service.submit(job_request.clone()).await.expect("submit first job");
        let second = service.submit(job_request).await.expect("submit second job");
        assert_eq!(service.list().await.expect("list service jobs").len(), 2);
        assert!(service.try_recover(second.id).await.expect("check live lease").is_none());
        assert_eq!(
            service.get(second.id).await.expect("read live job").state,
            ScanJobState::Queued
        );

        service
            .mutate(first.id, |job| job.transition(ScanJobState::Running, Utc::now()))
            .await
            .expect("start failure fixture");
        let failed = service
            .finish_failed(first.id, "scanner failed".to_string())
            .await
            .expect("commit failure");
        assert_eq!(failed.state, ScanJobState::Failed);
        assert_eq!(failed.error.as_deref(), Some("scanner failed"));
    }

    #[tokio::test]
    async fn memory_store_rejects_forged_successor_lineage() {
        let store = InMemoryJobStore::new();
        let root = ScanJob::new(request(), Uuid::new_v4());
        store.create(&root).await.expect("create root job");

        let mut forged = ScanJob::successor(&root, Uuid::new_v4());
        forged.attempt = 9;
        let error = store.create(&forged).await.expect_err("forged lineage must fail");
        assert!(error.to_string().contains("not a valid successor"));
    }

    #[tokio::test]
    async fn dropping_run_future_cleans_up_active_ownership() {
        let server = httpmock::MockServer::start_async().await;
        let _slow = server
            .mock_async(|when, then| {
                when.any_request();
                then.delay(std::time::Duration::from_secs(5)).status(200).body("slow");
            })
            .await;
        let mut job_request = request();
        job_request.target = format!("http://localhost:{}", server.port());
        let mut config =
            AppConfig { engagement: Some(job_request.engagement.clone()), ..AppConfig::default() };
        config.scan.timeout_seconds = 8;
        config.scan.max_concurrent_modules = 1;
        let service = ScanJobService::in_memory(Arc::new(config));
        let queued = service.submit(job_request).await.expect("submit job");
        let runner = {
            let service = service.clone();
            tokio::spawn(async move { service.run(queued.id).await })
        };

        let cancellation = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let state = service.get(queued.id).await.expect("load running job").state;
                let token = service
                    .active
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&queued.id)
                    .cloned();
                if state == ScanJobState::Running {
                    if let Some(token) = token {
                        return token;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("job entered running state");

        runner.abort();
        let join_error = runner.await.expect_err("aborted run must not complete");
        assert!(join_error.is_cancelled());
        assert!(cancellation.is_cancelled());
        assert!(
            service.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty(),
            "dropped run must release its process-local ownership"
        );
    }

    #[tokio::test]
    async fn embedded_target_credentials_are_denied_before_persistence() {
        let job_request = DastJobRequest::new(
            "http://operator:secret@localhost:3000",
            "quick",
            request().engagement,
        );
        let config =
            AppConfig { engagement: Some(job_request.engagement.clone()), ..AppConfig::default() };
        let service = ScanJobService::in_memory(Arc::new(config));
        let error =
            service.submit(job_request).await.expect_err("embedded credentials must be rejected");
        assert!(error.to_string().contains("must not contain embedded credentials"));
        assert!(service.list().await.expect("list jobs").is_empty());
    }
}
