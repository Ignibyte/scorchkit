//! Durable, provider-neutral scan job lifecycle.
//!
//! Jobs own authorization snapshots, lifecycle state, progress, cancellation, and recovery. The
//! storage contract is independent of `PostgreSQL` and host transports; MCP and CLI are adapters.

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use scorchkit_core::error::{Result, ScorchError};
use scorchkit_core::finding::Finding;
use scorchkit_core::scan_result::ScanResult;
use scorchkit_policy::Engagement;

const JOB_LIST_LIMIT: usize = 1_000;
const LEASE_SECONDS: i64 = 15;

#[doc(hidden)]
#[must_use]
pub(crate) fn lease_deadline() -> DateTime<Utc> {
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

    #[doc(hidden)]
    pub(crate) fn normalize(&mut self) {
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

    #[doc(hidden)]
    pub(crate) fn transition(&mut self, next: ScanJobState, now: DateTime<Utc>) -> Result<()> {
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

    #[doc(hidden)]
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

    #[doc(hidden)]
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

    #[doc(hidden)]
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
