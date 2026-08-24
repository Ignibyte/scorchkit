//! Bounded ordered event replay over authoritative job-store commits.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::engine::error::{Result, ScorchError};
use crate::runner::job::{JobStore, ScanJob, ScanJobAuditEvent};
use scorchkit_control::{
    ControlErrorCodeV1, ControlErrorV1, ControlEventBatchV1, ControlEventKindV1, ControlEventV1,
    EventCursorV1,
};

struct JournalState {
    next_sequence: u64,
    events: VecDeque<ControlEventV1>,
}

/// Process-local bounded ordered journal used for replay and live fanout.
pub struct ControlEventJournal {
    capacity: usize,
    max_event_bytes: usize,
    state: Mutex<JournalState>,
    sender: broadcast::Sender<ControlEventV1>,
}

impl std::fmt::Debug for ControlEventJournal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlEventJournal")
            .field("capacity", &self.capacity)
            .field("max_event_bytes", &self.max_event_bytes)
            .finish_non_exhaustive()
    }
}

impl ControlEventJournal {
    /// Create one bounded journal and fanout channel.
    #[must_use]
    pub fn new(capacity: usize, max_event_bytes: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self {
            capacity: capacity.max(1),
            max_event_bytes,
            state: Mutex::new(JournalState { next_sequence: 1, events: VecDeque::new() }),
            sender,
        }
    }

    /// Replay events strictly after the supplied sequence.
    ///
    /// # Errors
    ///
    /// Returns an expired or future cursor error when replay continuity cannot be proven.
    pub fn replay(
        &self,
        cursor: EventCursorV1,
    ) -> std::result::Result<ControlEventBatchV1, ControlErrorV1> {
        cursor.validate()?;
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let latest = state.next_sequence.saturating_sub(1);
        if cursor.after_sequence > latest {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::EventCursorFuture,
                "control event cursor is ahead of the journal",
            ));
        }
        let oldest = state.events.front().map_or(state.next_sequence, |event| event.sequence);
        if cursor.after_sequence.saturating_add(1) < oldest {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::EventCursorExpired,
                "control event cursor predates retained history",
            )
            .with_details(
                serde_json::json!({ "oldestSequence": oldest, "latestSequence": latest }),
            ));
        }
        let limit = usize::from(cursor.limit);
        let events: Vec<_> = state
            .events
            .iter()
            .filter(|event| event.sequence > cursor.after_sequence)
            .take(limit)
            .cloned()
            .collect();
        let next_sequence = events.last().map_or(cursor.after_sequence, |event| event.sequence);
        let has_more = state.events.iter().any(|event| event.sequence > next_sequence);
        drop(state);
        Ok(ControlEventBatchV1 { events, next_sequence, has_more })
    }

    /// Subscribe to newly committed events after obtaining a replay batch.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<ControlEventV1> {
        self.sender.subscribe()
    }

    fn publish_job(&self, job: &ScanJob, kind: ControlEventKindV1) -> Result<()> {
        let payload = serde_json::json!({
            "state": job.state.as_str(),
            "processedModules": job.progress.processed_modules(),
            "totalModules": job.progress.total_modules,
            "findingCount": job.progress.findings.len(),
        });
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let sequence = state.next_sequence;
        let event = ControlEventV1 {
            schema_version: scorchkit_control::event::CONTROL_EVENT_SCHEMA_V1.to_string(),
            sequence,
            kind,
            resource_type: "job".to_string(),
            resource_id: job.id,
            resource_revision: job.revision,
            occurred_at: job.updated_at,
            payload,
        };
        let serialized_bytes = serde_json::to_vec(&event)?.len();
        if serialized_bytes > self.max_event_bytes {
            return Err(ScorchError::Job(format!(
                "control job event exceeded the {} byte journal limit",
                self.max_event_bytes
            )));
        }
        state.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| ScorchError::Job("control event sequence exhausted u64".to_string()))?;
        state.events.push_back(event.clone());
        while state.events.len() > self.capacity {
            state.events.pop_front();
        }
        drop(state);
        let _subscriber_count = self.sender.send(event);
        Ok(())
    }

    #[cfg(test)]
    fn latest_sequence(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next_sequence
            .saturating_sub(1)
    }
}

/// `JobStore` decorator that emits only successful durable revisions.
pub struct JournaledJobStore {
    inner: Arc<dyn JobStore>,
    journal: Arc<ControlEventJournal>,
}

impl std::fmt::Debug for JournaledJobStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("JournaledJobStore").finish_non_exhaustive()
    }
}

impl JournaledJobStore {
    /// Wrap an existing lifecycle-enforcing store.
    #[must_use]
    pub fn new(inner: Arc<dyn JobStore>, journal: Arc<ControlEventJournal>) -> Self {
        Self { inner, journal }
    }
}

#[async_trait]
impl JobStore for JournaledJobStore {
    async fn create(&self, job: &ScanJob) -> Result<()> {
        self.inner.create(job).await?;
        self.journal.publish_job(job, ControlEventKindV1::JobCreated)
    }

    async fn get(&self, id: Uuid) -> Result<Option<ScanJob>> {
        self.inner.get(id).await
    }

    async fn list(&self) -> Result<Vec<ScanJob>> {
        self.inner.list().await
    }

    async fn list_page(&self, after: Option<Uuid>, limit: usize) -> Result<Vec<ScanJob>> {
        self.inner.list_page(after, limit).await
    }

    async fn list_recoverable(&self, now: DateTime<Utc>) -> Result<Vec<ScanJob>> {
        self.inner.list_recoverable(now).await
    }

    async fn list_recoverable_bounded(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<ScanJob>> {
        self.inner.list_recoverable_bounded(now, limit).await
    }

    async fn compare_and_swap(&self, expected_revision: u64, job: &ScanJob) -> Result<bool> {
        let changed = self.inner.compare_and_swap(expected_revision, job).await?;
        if changed {
            self.journal.publish_job(job, ControlEventKindV1::JobChanged)?;
        }
        Ok(changed)
    }

    async fn audit_events(&self, id: Uuid) -> Result<Vec<ScanJobAuditEvent>> {
        self.inner.audit_events(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
    use crate::engine::scope::ScopeRule;
    use crate::runner::job::{DastJobRequest, InMemoryJobStore, ScanJob, ScanJobState};

    fn job() -> ScanJob {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.test").expect("scope"))
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::Passive);
        ScanJob::new(
            DastJobRequest::new(
                "https://example.test/",
                "quick",
                Engagement::new("journal", policy),
            ),
            Uuid::new_v4(),
        )
    }

    #[tokio::test]
    async fn successful_create_emits_and_rejected_create_does_not() {
        let journal = Arc::new(ControlEventJournal::new(4, 4_096));
        let store = JournaledJobStore::new(Arc::new(InMemoryJobStore::new()), Arc::clone(&journal));
        let job = job();
        store.create(&job).await.expect("create");
        assert_eq!(journal.latest_sequence(), 1);
        assert!(store.create(&job).await.is_err());
        assert_eq!(journal.latest_sequence(), 1);
        let replay = journal.replay(EventCursorV1 { after_sequence: 0, limit: 4 }).expect("replay");
        assert_eq!(replay.events.len(), 1);
        assert_eq!(replay.events[0].kind, ControlEventKindV1::JobCreated);
    }

    #[tokio::test]
    async fn stale_compare_and_swap_emits_nothing() {
        let journal = Arc::new(ControlEventJournal::new(4, 4_096));
        let store = JournaledJobStore::new(Arc::new(InMemoryJobStore::new()), Arc::clone(&journal));
        let job = job();
        store.create(&job).await.expect("create");
        assert!(!store.compare_and_swap(99, &job).await.expect("stale"));
        assert_eq!(journal.latest_sequence(), 1);
    }

    #[tokio::test]
    async fn overflow_requires_an_explicit_reconnect_cursor() {
        let journal = Arc::new(ControlEventJournal::new(2, 4_096));
        let store = JournaledJobStore::new(Arc::new(InMemoryJobStore::new()), Arc::clone(&journal));
        for _ in 0..3 {
            store.create(&job()).await.expect("create");
        }
        let expired =
            journal.replay(EventCursorV1 { after_sequence: 0, limit: 2 }).expect_err("expired");
        assert_eq!(expired.code, ControlErrorCodeV1::EventCursorExpired);
        let replay =
            journal.replay(EventCursorV1 { after_sequence: 1, limit: 1 }).expect("oldest retained");
        assert_eq!(replay.events[0].sequence, 2);
        assert!(replay.has_more);
        assert_eq!(
            journal.replay(EventCursorV1 { after_sequence: 4, limit: 1 }).expect_err("future").code,
            ControlErrorCodeV1::EventCursorFuture
        );
    }

    #[test]
    fn minimum_configured_event_budget_accepts_every_job_state() {
        let journal = ControlEventJournal::new(8, 512);
        for state in [
            ScanJobState::Queued,
            ScanJobState::Running,
            ScanJobState::Cancelling,
            ScanJobState::Cancelled,
            ScanJobState::Succeeded,
            ScanJobState::Failed,
            ScanJobState::Interrupted,
        ] {
            let mut job = job();
            job.state = state;
            job.revision = u64::MAX;
            job.progress.total_modules = usize::MAX;
            journal
                .publish_job(&job, ControlEventKindV1::JobChanged)
                .expect("minimum configured event budget");
        }
    }
}
