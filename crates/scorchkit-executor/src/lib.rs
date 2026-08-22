//! Shared bounded execution and durable job lifecycle contracts.
//!
//! The executor owns scheduling, cancellation, a whole-batch wall-time budget, and deterministic
//! outcome ordering. The scheduler deliberately knows nothing about targets, policy, findings,
//! events, persistence, terminal output, or agent providers. The sibling [`job`] module owns the
//! provider-neutral lifecycle and store contracts used by the composition layer.

pub mod job;
pub mod webhook;

/// Narrow cross-package helpers for composition and storage adapters.
#[doc(hidden)]
pub mod integration {
    use chrono::{DateTime, Utc};
    use scorchkit_core::error::Result;

    use crate::job::{ScanJob, ScanJobProgress, ScanJobState};

    /// Return the next standard ownership-lease deadline.
    #[must_use]
    pub fn lease_deadline() -> DateTime<Utc> {
        crate::job::lease_deadline()
    }

    /// Normalize persisted progress sets before validation.
    pub fn normalize_job_progress(progress: &mut ScanJobProgress) {
        progress.normalize();
    }

    /// Apply one validated lifecycle transition.
    ///
    /// # Errors
    ///
    /// Returns an error when the transition is not permitted.
    pub fn transition_job(job: &mut ScanJob, next: ScanJobState, now: DateTime<Utc>) -> Result<()> {
        job.transition(next, now)
    }

    /// Validate a document before store creation.
    ///
    /// # Errors
    ///
    /// Returns an error when creation invariants do not hold.
    pub fn validate_job_create(job: &ScanJob) -> Result<()> {
        job.validate_create()
    }

    /// Validate a successor attempt against its interrupted parent.
    ///
    /// # Errors
    ///
    /// Returns an error when lineage or retained-progress invariants do not hold.
    pub fn validate_job_successor(job: &ScanJob, parent: &ScanJob) -> Result<()> {
        job.validate_successor(parent)
    }

    /// Validate a compare-and-swap replacement.
    ///
    /// # Errors
    ///
    /// Returns an error when revision, identity, lineage, or state invariants do not hold.
    pub fn validate_job_replacement(
        job: &ScanJob,
        existing: &ScanJob,
        expected_revision: u64,
    ) -> Result<()> {
        job.validate_replacement(existing, expected_revision)
    }
}

/// Narrow webhook lifecycle helpers for composition and storage adapters.
#[doc(hidden)]
pub mod webhook_integration {
    use chrono::{DateTime, Utc};
    use scorchkit_core::error::Result;

    use crate::webhook::{WebhookDelivery, WebhookDeliveryState};

    /// Apply one validated delivery transition.
    pub fn transition_delivery(
        delivery: &mut WebhookDelivery,
        next: WebhookDeliveryState,
        now: DateTime<Utc>,
    ) -> Result<()> {
        delivery.transition(next, now)
    }

    /// Validate a delivery before creation.
    pub fn validate_delivery_create(delivery: &WebhookDelivery) -> Result<()> {
        delivery.validate_create()
    }

    /// Validate a compare-and-swap replacement.
    pub fn validate_delivery_replacement(
        delivery: &WebhookDelivery,
        existing: &WebhookDelivery,
        expected_revision: u64,
    ) -> Result<()> {
        delivery.validate_replacement(existing, expected_revision)
    }
}

use std::future::Future;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use futures_util::stream::{self, StreamExt};
pub use tokio_util::sync::CancellationToken;

use scorchkit_config::ScanConfig;
use scorchkit_core::error::{Result, ScorchError};

/// Await one fallible effect while honoring the scan cancellation token.
///
/// Family orchestrators use this for lifecycle hooks that sit immediately before or after an
/// executor batch. Dropping the future on cancellation preserves the same owned HTTP/process
/// cleanup boundary as dropping an active job.
#[doc(hidden)]
pub async fn cancel_on_token<F, T>(cancellation: &CancellationToken, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(cancelled_by_caller()),
        result = future => result,
    }
}

/// Fail before publishing successful completion when cancellation arrived between await points.
#[doc(hidden)]
pub fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(cancelled_by_caller())
    } else {
        Ok(())
    }
}

fn cancelled_by_caller() -> ScorchError {
    ScorchError::Cancelled { reason: "scan execution cancelled by caller".to_string() }
}

/// Resource limits enforced across one executor batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionBudget {
    max_concurrency: NonZeroUsize,
    wall_time: Duration,
}

impl ExecutionBudget {
    /// Create a validated execution budget.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when either limit is zero.
    pub fn new(max_concurrency: usize, wall_time: Duration) -> Result<Self> {
        let max_concurrency = NonZeroUsize::new(max_concurrency).ok_or_else(|| {
            ScorchError::Config("scan.max_concurrent_modules must be greater than zero".to_string())
        })?;
        if wall_time.is_zero() {
            return Err(ScorchError::Config(
                "scan.timeout_seconds must be greater than zero".to_string(),
            ));
        }
        Ok(Self { max_concurrency, wall_time })
    }

    /// Build the batch budget from scan configuration.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when either configured limit is zero.
    pub fn from_scan_config(config: &ScanConfig) -> Result<Self> {
        Self::new(config.max_concurrent_modules, Duration::from_secs(config.timeout_seconds))
    }

    /// Maximum jobs that may be polled concurrently.
    #[must_use]
    pub const fn max_concurrency(self) -> usize {
        self.max_concurrency.get()
    }

    /// Maximum wall time for the complete batch.
    #[must_use]
    pub const fn wall_time(self) -> Duration {
        self.wall_time
    }
}

/// One completed job, labeled with executor-owned ordering and timing data.
#[derive(Debug)]
pub struct JobOutcome<T> {
    ordinal: usize,
    duration: Duration,
    output: T,
}

impl<T> JobOutcome<T> {
    /// Zero-based submission position within this batch.
    #[must_use]
    pub const fn ordinal(&self) -> usize {
        self.ordinal
    }

    /// Wall time spent polling this job.
    #[must_use]
    pub const fn duration(&self) -> Duration {
        self.duration
    }

    /// Borrow the family-owned job output.
    #[must_use]
    pub const fn output(&self) -> &T {
        &self.output
    }

    /// Consume the outcome and return the family-owned output.
    #[must_use]
    pub fn into_output(self) -> T {
        self.output
    }
}

/// Vendor-neutral async job scheduler shared by all scanner families.
#[derive(Clone, Copy, Debug)]
pub struct JobExecutor {
    budget: ExecutionBudget,
}

impl JobExecutor {
    /// Create an executor with an already validated budget.
    #[must_use]
    pub const fn new(budget: ExecutionBudget) -> Self {
        Self { budget }
    }

    /// Create an executor from scan configuration.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when concurrency or timeout is zero.
    pub fn from_scan_config(config: &ScanConfig) -> Result<Self> {
        ExecutionBudget::from_scan_config(config).map(Self::new)
    }

    /// Run a batch with bounded concurrency and return outcomes in submission order.
    ///
    /// Individual job errors remain part of `T`; this method only fails for caller cancellation or
    /// exhaustion of the batch wall-time budget. Dropping the bounded stream on either failure also
    /// drops active module futures, which is the cancellation boundary for HTTP requests and owned
    /// subprocess trees.
    ///
    /// # Errors
    ///
    /// Returns [`ScorchError::Cancelled`] when the token is cancelled or the batch exceeds its
    /// wall-time budget.
    pub async fn execute<'job, T>(
        &self,
        jobs: Vec<BoxFuture<'job, T>>,
        cancellation: &CancellationToken,
    ) -> Result<Vec<JobOutcome<T>>>
    where
        T: Send + 'job,
    {
        let mut scheduled = Vec::with_capacity(jobs.len());
        for (ordinal, job) in jobs.into_iter().enumerate() {
            scheduled.push(run_job(ordinal, job));
        }
        let execution = stream::iter(scheduled)
            .buffer_unordered(self.budget.max_concurrency())
            .collect::<Vec<_>>();

        tokio::pin!(execution);
        let mut outcomes = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(cancelled_by_caller());
            }
            result = tokio::time::timeout(self.budget.wall_time(), &mut execution) => {
                result.map_err(|_| ScorchError::Cancelled {
                    reason: format!(
                        "job batch exceeded wall-time budget of {:?}",
                        self.budget.wall_time(),
                    ),
                })?
            }
        };
        outcomes.sort_by_key(JobOutcome::ordinal);
        Ok(outcomes)
    }
}

async fn run_job<T>(ordinal: usize, job: BoxFuture<'_, T>) -> JobOutcome<T> {
    let started = Instant::now();
    let output = job.await;
    JobOutcome { ordinal, duration: started.elapsed(), output }
}
