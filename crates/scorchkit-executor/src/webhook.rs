//! Provider-neutral durable webhook delivery lifecycle.
//!
//! The queue owns redacted payloads, authorization snapshots, optimistic
//! revisions, recoverable leases, bounded attempts, and immutable audit state.
//! HTTP, `PostgreSQL`, CLI, and MCP remain composition adapters.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use scorchkit_core::error::{Result, ScorchError};
use scorchkit_policy::Engagement;

const DELIVERY_LIST_LIMIT: usize = 1_000;

/// Durable delivery lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookDeliveryState {
    /// Persisted and waiting for its due time.
    Queued,
    /// Claimed by a live worker under a bounded lease.
    Delivering,
    /// Destination returned a successful status.
    Succeeded,
    /// Every configured attempt was consumed.
    Exhausted,
}

impl WebhookDeliveryState {
    /// Stable database and wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Delivering => "delivering",
            Self::Succeeded => "succeeded",
            Self::Exhausted => "exhausted",
        }
    }

    /// Whether no later delivery attempt is legal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Exhausted)
    }

    const fn allows(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Queued, Self::Delivering)
                | (Self::Delivering, Self::Queued | Self::Succeeded | Self::Exhausted)
        )
    }
}

/// One durable, already-redacted webhook delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    /// Queue identity.
    pub id: Uuid,
    /// Stable runtime destination lookup key; never the configured URL.
    pub destination_id: String,
    /// Exact serialized event discriminator.
    pub event_kind: String,
    /// Redacted event object, bounded before construction.
    pub payload: serde_json::Value,
    /// Exact engagement snapshot that must authorize every attempt.
    pub engagement: Engagement,
    /// Current lifecycle state.
    pub state: WebhookDeliveryState,
    /// Optimistic-lock revision.
    pub revision: u64,
    /// Number of claims already started.
    pub attempts: u32,
    /// Hard attempt ceiling captured at enqueue time.
    pub max_attempts: u32,
    /// Worker that currently owns a delivering record.
    pub owner_id: Option<Uuid>,
    /// Crash-recovery deadline for current ownership.
    pub lease_expires_at: Option<DateTime<Utc>>,
    /// Earliest time a queued record may be claimed.
    pub next_attempt_at: Option<DateTime<Utc>>,
    /// Sanitized bounded diagnostic from the most recent failure.
    pub last_error: Option<String>,
    /// Last HTTP status, without response headers or body.
    pub last_status: Option<u16>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last committed mutation time.
    pub updated_at: DateTime<Utc>,
    /// Terminal commit time.
    pub finished_at: Option<DateTime<Utc>>,
}

impl WebhookDelivery {
    /// Create one immediately due redacted record.
    #[must_use]
    pub fn new(
        destination_id: String,
        event_kind: String,
        payload: serde_json::Value,
        engagement: Engagement,
        max_attempts: u32,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            destination_id,
            event_kind,
            payload,
            engagement,
            state: WebhookDeliveryState::Queued,
            revision: 0,
            attempts: 0,
            max_attempts,
            owner_id: None,
            lease_expires_at: None,
            next_attempt_at: Some(now),
            last_error: None,
            last_status: None,
            created_at: now,
            updated_at: now,
            finished_at: None,
        }
    }

    pub(crate) fn transition(
        &mut self,
        next: WebhookDeliveryState,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if !self.state.allows(next) {
            return Err(ScorchError::Webhook(format!(
                "illegal delivery transition {} -> {}",
                self.state.as_str(),
                next.as_str()
            )));
        }
        self.state = next;
        if next.is_terminal() {
            self.finished_at = Some(now);
        }
        Ok(())
    }

    pub(crate) fn validate_create(&self) -> Result<()> {
        if self.destination_id.is_empty()
            || self.destination_id.len() > 64
            || self.event_kind.is_empty()
            || self.event_kind.len() > 128
            || self.state != WebhookDeliveryState::Queued
            || self.revision != 0
            || self.attempts != 0
            || !(1..=20).contains(&self.max_attempts)
            || self.owner_id.is_some()
            || self.lease_expires_at.is_some()
            || self.next_attempt_at.is_none_or(|due| due < self.created_at)
            || self.last_error.is_some()
            || self.last_status.is_some()
            || self.finished_at.is_some()
        {
            return Err(ScorchError::Webhook(format!(
                "delivery {} is not a valid queued record",
                self.id
            )));
        }
        if !self.payload.is_object() {
            return Err(ScorchError::Webhook(format!(
                "delivery {} payload must be a JSON object",
                self.id
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_replacement(
        &self,
        existing: &Self,
        expected_revision: u64,
    ) -> Result<()> {
        let immutable = self.id == existing.id
            && self.destination_id == existing.destination_id
            && self.event_kind == existing.event_kind
            && self.payload == existing.payload
            && self.engagement == existing.engagement
            && self.max_attempts == existing.max_attempts
            && self.created_at == existing.created_at;
        if !immutable
            || existing.revision != expected_revision
            || expected_revision.checked_add(1) != Some(self.revision)
            || !existing.state.allows(self.state)
            || self.updated_at < existing.updated_at
            || self.last_error.as_ref().is_some_and(|error| error.len() > 512)
        {
            return Err(ScorchError::Webhook(format!(
                "delivery {} replacement violates immutable or revision invariants",
                self.id
            )));
        }
        match (existing.state, self.state) {
            (WebhookDeliveryState::Queued, WebhookDeliveryState::Delivering) => {
                if self.attempts != existing.attempts.saturating_add(1)
                    || self.attempts > self.max_attempts
                    || self.owner_id.is_none()
                    || self.lease_expires_at.is_none_or(|deadline| deadline <= self.updated_at)
                    || self.next_attempt_at.is_some()
                    || self.finished_at.is_some()
                {
                    return Err(ScorchError::Webhook(format!(
                        "delivery {} has an invalid claim",
                        self.id
                    )));
                }
            }
            (WebhookDeliveryState::Delivering, WebhookDeliveryState::Queued) => {
                if self.attempts != existing.attempts
                    || self.attempts >= self.max_attempts
                    || self.owner_id.is_some()
                    || self.lease_expires_at.is_some()
                    || self.next_attempt_at.is_none_or(|due| due < self.updated_at)
                    || self.finished_at.is_some()
                    || self.last_error.is_none()
                {
                    return Err(ScorchError::Webhook(format!(
                        "delivery {} has an invalid retry",
                        self.id
                    )));
                }
            }
            (
                WebhookDeliveryState::Delivering,
                WebhookDeliveryState::Succeeded | WebhookDeliveryState::Exhausted,
            ) => {
                if self.attempts != existing.attempts
                    || self.owner_id.is_some()
                    || self.lease_expires_at.is_some()
                    || self.next_attempt_at.is_some()
                    || self.finished_at.is_none()
                {
                    return Err(ScorchError::Webhook(format!(
                        "delivery {} has an invalid terminal commit",
                        self.id
                    )));
                }
                if self.state == WebhookDeliveryState::Succeeded
                    && (self.last_error.is_some()
                        || !self.last_status.is_some_and(|status| (200..300).contains(&status)))
                {
                    return Err(ScorchError::Webhook(format!(
                        "delivery {} has an invalid success result",
                        self.id
                    )));
                }
                if self.state == WebhookDeliveryState::Exhausted
                    && (self.attempts < self.max_attempts || self.last_error.is_none())
                {
                    return Err(ScorchError::Webhook(format!(
                        "delivery {} exhausted before its attempt bound",
                        self.id
                    )));
                }
            }
            _ => {
                return Err(ScorchError::Webhook(format!(
                    "delivery {} has an invalid state replacement",
                    self.id
                )));
            }
        }
        Ok(())
    }
}

/// Compact immutable audit event paired with one delivery revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookDeliveryAuditEvent {
    /// Delivery whose mutation committed.
    pub delivery_id: Uuid,
    /// Exact committed revision.
    pub revision: u64,
    /// State at that revision.
    pub state: WebhookDeliveryState,
    /// Started attempt count at that revision.
    pub attempts: u32,
    /// Sanitized diagnostic present on retry or exhaustion revisions.
    #[serde(default)]
    pub last_error: Option<String>,
    /// Remote status metadata without headers or body.
    #[serde(default)]
    pub last_status: Option<u16>,
    /// Mutation timestamp.
    pub occurred_at: DateTime<Utc>,
}

impl From<&WebhookDelivery> for WebhookDeliveryAuditEvent {
    fn from(delivery: &WebhookDelivery) -> Self {
        Self {
            delivery_id: delivery.id,
            revision: delivery.revision,
            state: delivery.state,
            attempts: delivery.attempts,
            last_error: delivery.last_error.clone(),
            last_status: delivery.last_status,
            occurred_at: delivery.updated_at,
        }
    }
}

/// Durable queue contract independent of its storage provider.
#[async_trait]
pub trait WebhookStore: Send + Sync {
    /// Persist an initial record and its audit event if capacity remains.
    async fn create(&self, delivery: &WebhookDelivery, max_pending: usize) -> Result<()>;
    /// Load one record.
    async fn get(&self, id: Uuid) -> Result<Option<WebhookDelivery>>;
    /// List a deterministic bounded projection.
    async fn list(&self) -> Result<Vec<WebhookDelivery>>;
    /// List queued work whose due time has arrived.
    async fn list_due(&self, now: DateTime<Utc>, limit: usize) -> Result<Vec<WebhookDelivery>>;
    /// List delivering work whose ownership lease expired.
    async fn list_recoverable(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<WebhookDelivery>>;
    /// Replace exactly one expected revision and append its audit event atomically.
    async fn compare_and_swap(
        &self,
        expected_revision: u64,
        delivery: &WebhookDelivery,
    ) -> Result<bool>;
    /// Read immutable audit history for one delivery.
    async fn audit_events(&self, id: Uuid) -> Result<Vec<WebhookDeliveryAuditEvent>>;
}

/// Deterministic in-memory store for contract and composition tests.
#[derive(Debug, Default)]
pub struct InMemoryWebhookStore {
    state: RwLock<InMemoryWebhookState>,
}

#[derive(Debug, Default)]
struct InMemoryWebhookState {
    deliveries: HashMap<Uuid, WebhookDelivery>,
    audits: HashMap<Uuid, Vec<WebhookDeliveryAuditEvent>>,
}

impl InMemoryWebhookStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

fn sort_deliveries(deliveries: &mut [WebhookDelivery]) {
    deliveries.sort_by_key(|delivery| (delivery.created_at, delivery.id));
}

#[async_trait]
impl WebhookStore for InMemoryWebhookStore {
    async fn create(&self, delivery: &WebhookDelivery, max_pending: usize) -> Result<()> {
        delivery.validate_create()?;
        let mut state = self.state.write().await;
        if state.deliveries.contains_key(&delivery.id) {
            return Err(ScorchError::Webhook(format!("delivery {} already exists", delivery.id)));
        }
        let pending = state
            .deliveries
            .values()
            .filter(|existing| {
                existing.destination_id == delivery.destination_id && !existing.state.is_terminal()
            })
            .count();
        if pending >= max_pending {
            return Err(ScorchError::Webhook(format!(
                "destination '{}' pending queue reached its configured bound",
                delivery.destination_id
            )));
        }
        state.deliveries.insert(delivery.id, delivery.clone());
        state.audits.insert(delivery.id, vec![WebhookDeliveryAuditEvent::from(delivery)]);
        drop(state);
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<WebhookDelivery>> {
        Ok(self.state.read().await.deliveries.get(&id).cloned())
    }

    async fn list(&self) -> Result<Vec<WebhookDelivery>> {
        let mut deliveries: Vec<_> = self.state.read().await.deliveries.values().cloned().collect();
        sort_deliveries(&mut deliveries);
        deliveries.truncate(DELIVERY_LIST_LIMIT);
        Ok(deliveries)
    }

    async fn list_due(&self, now: DateTime<Utc>, limit: usize) -> Result<Vec<WebhookDelivery>> {
        let mut deliveries: Vec<_> = self
            .state
            .read()
            .await
            .deliveries
            .values()
            .filter(|delivery| {
                delivery.state == WebhookDeliveryState::Queued
                    && delivery.next_attempt_at.is_some_and(|due| due <= now)
            })
            .cloned()
            .collect();
        deliveries
            .sort_by_key(|delivery| (delivery.next_attempt_at, delivery.created_at, delivery.id));
        deliveries.truncate(limit.min(DELIVERY_LIST_LIMIT));
        Ok(deliveries)
    }

    async fn list_recoverable(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<WebhookDelivery>> {
        let mut deliveries: Vec<_> = self
            .state
            .read()
            .await
            .deliveries
            .values()
            .filter(|delivery| {
                delivery.state == WebhookDeliveryState::Delivering
                    && delivery.lease_expires_at.is_none_or(|deadline| deadline <= now)
            })
            .cloned()
            .collect();
        deliveries
            .sort_by_key(|delivery| (delivery.lease_expires_at, delivery.created_at, delivery.id));
        deliveries.truncate(limit.min(DELIVERY_LIST_LIMIT));
        Ok(deliveries)
    }

    async fn compare_and_swap(
        &self,
        expected_revision: u64,
        delivery: &WebhookDelivery,
    ) -> Result<bool> {
        let mut state = self.state.write().await;
        let Some(existing) = state.deliveries.get(&delivery.id) else {
            return Ok(false);
        };
        if existing.revision != expected_revision {
            return Ok(false);
        }
        delivery.validate_replacement(existing, expected_revision)?;
        state.deliveries.insert(delivery.id, delivery.clone());
        state
            .audits
            .entry(delivery.id)
            .or_default()
            .push(WebhookDeliveryAuditEvent::from(delivery));
        drop(state);
        Ok(true)
    }

    async fn audit_events(&self, id: Uuid) -> Result<Vec<WebhookDeliveryAuditEvent>> {
        Ok(self.state.read().await.audits.get(&id).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scorchkit_policy::EngagementPolicy;

    fn fixture() -> WebhookDelivery {
        WebhookDelivery::new(
            "primary".to_string(),
            "scan_completed".to_string(),
            serde_json::json!({"event": "scan_completed"}),
            Engagement::new("fixture", EngagementPolicy::default()),
            2,
        )
    }

    fn claimed(existing: &WebhookDelivery, now: DateTime<Utc>) -> WebhookDelivery {
        let mut delivery = existing.clone();
        delivery.transition(WebhookDeliveryState::Delivering, now).unwrap();
        delivery.revision = existing.revision + 1;
        delivery.attempts = existing.attempts + 1;
        delivery.owner_id = Some(Uuid::new_v4());
        delivery.lease_expires_at = Some(now + chrono::Duration::seconds(15));
        delivery.next_attempt_at = None;
        delivery.updated_at = now;
        delivery
    }

    fn retried(existing: &WebhookDelivery, now: DateTime<Utc>) -> WebhookDelivery {
        let mut delivery = existing.clone();
        delivery.transition(WebhookDeliveryState::Queued, now).unwrap();
        delivery.revision = existing.revision + 1;
        delivery.owner_id = None;
        delivery.lease_expires_at = None;
        delivery.next_attempt_at = Some(now);
        delivery.last_error = Some("sanitized failure".to_string());
        delivery.last_status = None;
        delivery.updated_at = now;
        delivery
    }

    fn succeeded(existing: &WebhookDelivery, now: DateTime<Utc>) -> WebhookDelivery {
        let mut delivery = existing.clone();
        delivery.transition(WebhookDeliveryState::Succeeded, now).unwrap();
        delivery.revision = existing.revision + 1;
        delivery.owner_id = None;
        delivery.lease_expires_at = None;
        delivery.next_attempt_at = None;
        delivery.last_error = None;
        delivery.last_status = Some(204);
        delivery.updated_at = now;
        delivery
    }

    fn exhausted(existing: &WebhookDelivery, now: DateTime<Utc>) -> WebhookDelivery {
        let mut delivery = existing.clone();
        delivery.transition(WebhookDeliveryState::Exhausted, now).unwrap();
        delivery.revision = existing.revision + 1;
        delivery.owner_id = None;
        delivery.lease_expires_at = None;
        delivery.next_attempt_at = None;
        delivery.last_error = Some("sanitized failure".to_string());
        delivery.last_status = None;
        delivery.updated_at = now;
        delivery
    }

    #[test]
    fn delivery_state_transition_matrix_is_exact() {
        let states = [
            WebhookDeliveryState::Queued,
            WebhookDeliveryState::Delivering,
            WebhookDeliveryState::Succeeded,
            WebhookDeliveryState::Exhausted,
        ];
        for from in states {
            for to in states {
                let expected = matches!(
                    (from, to),
                    (WebhookDeliveryState::Queued, WebhookDeliveryState::Delivering)
                        | (
                            WebhookDeliveryState::Delivering,
                            WebhookDeliveryState::Queued
                                | WebhookDeliveryState::Succeeded
                                | WebhookDeliveryState::Exhausted
                        )
                );
                assert_eq!(from.allows(to), expected, "{from:?} -> {to:?}");
            }
        }
    }

    #[test]
    fn create_validation_pins_every_independent_invariant() {
        fn rejects(mutator: impl FnOnce(&mut WebhookDelivery)) {
            let mut delivery = fixture();
            mutator(&mut delivery);
            assert!(delivery.validate_create().is_err());
            assert!(crate::webhook_integration::validate_delivery_create(&delivery).is_err());
        }

        let mut boundary = fixture();
        boundary.destination_id = "d".repeat(64);
        boundary.event_kind = "e".repeat(128);
        boundary.max_attempts = 20;
        boundary.next_attempt_at = Some(boundary.created_at);
        assert!(boundary.validate_create().is_ok());
        assert!(crate::webhook_integration::validate_delivery_create(&boundary).is_ok());

        rejects(|delivery| delivery.destination_id.clear());
        rejects(|delivery| delivery.destination_id = "d".repeat(65));
        rejects(|delivery| delivery.event_kind.clear());
        rejects(|delivery| delivery.event_kind = "e".repeat(129));
        rejects(|delivery| delivery.state = WebhookDeliveryState::Delivering);
        rejects(|delivery| delivery.revision = 1);
        rejects(|delivery| delivery.attempts = 1);
        rejects(|delivery| delivery.max_attempts = 0);
        rejects(|delivery| delivery.max_attempts = 21);
        rejects(|delivery| delivery.owner_id = Some(Uuid::new_v4()));
        rejects(|delivery| delivery.lease_expires_at = Some(Utc::now()));
        rejects(|delivery| delivery.next_attempt_at = None);
        rejects(|delivery| {
            delivery.next_attempt_at = Some(delivery.created_at - chrono::Duration::nanoseconds(1));
        });
        rejects(|delivery| delivery.last_error = Some("failure".to_string()));
        rejects(|delivery| delivery.last_status = Some(500));
        rejects(|delivery| delivery.finished_at = Some(Utc::now()));
        rejects(|delivery| delivery.payload = serde_json::json!([]));
    }

    #[test]
    fn replacement_validation_pins_claim_and_common_invariants() {
        fn rejects(
            existing: &WebhookDelivery,
            candidate: &WebhookDelivery,
            expected_revision: u64,
        ) {
            assert!(candidate.validate_replacement(existing, expected_revision).is_err());
            assert!(crate::webhook_integration::validate_delivery_replacement(
                candidate,
                existing,
                expected_revision
            )
            .is_err());
        }

        let initial = fixture();
        let claim_time = initial.updated_at + chrono::Duration::milliseconds(1);
        let claim = claimed(&initial, claim_time);
        assert!(claim.validate_replacement(&initial, 0).is_ok());
        assert!(
            crate::webhook_integration::validate_delivery_replacement(&claim, &initial, 0).is_ok()
        );

        let mut invalid = claim.clone();
        invalid.id = Uuid::new_v4();
        rejects(&initial, &invalid, 0);
        let mut invalid = claim.clone();
        invalid.destination_id.push('x');
        rejects(&initial, &invalid, 0);
        let mut invalid = claim.clone();
        invalid.event_kind.push('x');
        rejects(&initial, &invalid, 0);
        let mut invalid = claim.clone();
        invalid.payload = serde_json::json!({"changed":true});
        rejects(&initial, &invalid, 0);
        let mut invalid = claim.clone();
        invalid.engagement.name.push('x');
        rejects(&initial, &invalid, 0);
        let mut invalid = claim.clone();
        invalid.max_attempts += 1;
        rejects(&initial, &invalid, 0);
        let mut invalid = claim.clone();
        invalid.created_at += chrono::Duration::milliseconds(1);
        rejects(&initial, &invalid, 0);
        rejects(&initial, &claim, 1);
        let mut invalid = claim.clone();
        invalid.revision = 2;
        rejects(&initial, &invalid, 0);
        let mut invalid = claim.clone();
        invalid.state = WebhookDeliveryState::Queued;
        rejects(&initial, &invalid, 0);
        let mut invalid = claim.clone();
        invalid.updated_at = initial.updated_at - chrono::Duration::nanoseconds(1);
        rejects(&initial, &invalid, 0);
        let mut bounded_error = claim.clone();
        bounded_error.last_error = Some("e".repeat(512));
        assert!(bounded_error.validate_replacement(&initial, 0).is_ok());
        bounded_error.last_error = Some("e".repeat(513));
        rejects(&initial, &bounded_error, 0);

        let mut invalid = claim.clone();
        invalid.attempts = initial.attempts;
        rejects(&initial, &invalid, 0);
        let mut at_limit = initial.clone();
        at_limit.attempts = at_limit.max_attempts;
        let over_limit = claimed(&at_limit, claim_time);
        rejects(&at_limit, &over_limit, 0);
        let mut invalid = claim.clone();
        invalid.owner_id = None;
        rejects(&initial, &invalid, 0);
        let mut invalid = claim.clone();
        invalid.lease_expires_at = None;
        rejects(&initial, &invalid, 0);
        let mut invalid = claim.clone();
        invalid.lease_expires_at = Some(invalid.updated_at);
        rejects(&initial, &invalid, 0);
        let mut invalid = claim.clone();
        invalid.next_attempt_at = Some(invalid.updated_at);
        rejects(&initial, &invalid, 0);
        let mut invalid = claim;
        invalid.finished_at = Some(invalid.updated_at);
        rejects(&initial, &invalid, 0);
    }

    #[test]
    fn replacement_validation_pins_retry_and_terminal_invariants() {
        fn rejects(
            existing: &WebhookDelivery,
            candidate: &WebhookDelivery,
            expected_revision: u64,
        ) {
            assert!(candidate.validate_replacement(existing, expected_revision).is_err());
            assert!(crate::webhook_integration::validate_delivery_replacement(
                candidate,
                existing,
                expected_revision
            )
            .is_err());
        }

        let initial = fixture();
        let claim_time = initial.updated_at + chrono::Duration::milliseconds(1);
        let claim = claimed(&initial, claim_time);
        let retry_time = claim.updated_at + chrono::Duration::milliseconds(1);
        let retry = retried(&claim, retry_time);
        assert!(retry.validate_replacement(&claim, 1).is_ok());
        let mut invalid = retry.clone();
        invalid.attempts = 0;
        rejects(&claim, &invalid, 1);
        let one_attempt = {
            let mut value = fixture();
            value.max_attempts = 1;
            value
        };
        let one_claim = claimed(&one_attempt, claim_time);
        let invalid = retried(&one_claim, retry_time);
        rejects(&one_claim, &invalid, 1);
        let mut invalid = retry.clone();
        invalid.owner_id = Some(Uuid::new_v4());
        rejects(&claim, &invalid, 1);
        let mut invalid = retry.clone();
        invalid.lease_expires_at = Some(retry_time);
        rejects(&claim, &invalid, 1);
        let mut invalid = retry.clone();
        invalid.next_attempt_at = None;
        rejects(&claim, &invalid, 1);
        let mut invalid = retry.clone();
        invalid.next_attempt_at = Some(retry_time - chrono::Duration::nanoseconds(1));
        rejects(&claim, &invalid, 1);
        let mut invalid = retry.clone();
        invalid.finished_at = Some(retry_time);
        rejects(&claim, &invalid, 1);
        let mut invalid = retry;
        invalid.last_error = None;
        rejects(&claim, &invalid, 1);

        let success_time = claim.updated_at + chrono::Duration::milliseconds(1);
        let success = succeeded(&claim, success_time);
        assert!(success.validate_replacement(&claim, 1).is_ok());
        for status in [200, 299] {
            let mut boundary = success.clone();
            boundary.last_status = Some(status);
            assert!(boundary.validate_replacement(&claim, 1).is_ok());
        }
        for status in [None, Some(199), Some(300)] {
            let mut invalid = success.clone();
            invalid.last_status = status;
            rejects(&claim, &invalid, 1);
        }
        let mut invalid = success.clone();
        invalid.last_error = Some("failure".to_string());
        rejects(&claim, &invalid, 1);
        let mut invalid = success.clone();
        invalid.attempts += 1;
        rejects(&claim, &invalid, 1);
        let mut invalid = success.clone();
        invalid.owner_id = Some(Uuid::new_v4());
        rejects(&claim, &invalid, 1);
        let mut invalid = success.clone();
        invalid.lease_expires_at = Some(success_time);
        rejects(&claim, &invalid, 1);
        let mut invalid = success.clone();
        invalid.next_attempt_at = Some(success_time);
        rejects(&claim, &invalid, 1);
        let mut invalid = success;
        invalid.finished_at = None;
        rejects(&claim, &invalid, 1);

        let terminal_claim = claimed(&one_attempt, claim_time);
        let exhausted_delivery = exhausted(&terminal_claim, success_time);
        assert!(exhausted_delivery.validate_replacement(&terminal_claim, 1).is_ok());
        let mut invalid = exhausted_delivery;
        invalid.last_error = None;
        rejects(&terminal_claim, &invalid, 1);
        let premature = exhausted(&claim, success_time);
        rejects(&claim, &premature, 1);
    }

    #[tokio::test]
    async fn store_enforces_capacity_cas_and_audit_parity() {
        let store = InMemoryWebhookStore::new();
        let first = fixture();
        store.create(&first, 1).await.unwrap();
        assert!(store.create(&fixture(), 1).await.unwrap_err().to_string().contains("bound"));

        let mut claimed = first.clone();
        let now = Utc::now();
        claimed.transition(WebhookDeliveryState::Delivering, now).unwrap();
        claimed.revision = 1;
        claimed.attempts = 1;
        claimed.owner_id = Some(Uuid::new_v4());
        claimed.lease_expires_at = Some(now + chrono::Duration::seconds(15));
        claimed.next_attempt_at = None;
        claimed.updated_at = now;
        assert!(store.compare_and_swap(0, &claimed).await.unwrap());
        assert!(!store.compare_and_swap(0, &claimed).await.unwrap());
        assert_eq!(store.audit_events(first.id).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn due_and_recoverable_lists_are_bounded_and_state_specific() {
        let store = InMemoryWebhookStore::new();
        let first = fixture();
        store.create(&first, 2).await.unwrap();
        assert_eq!(store.list_due(Utc::now(), 1).await.unwrap().len(), 1);
        assert!(store.list_recoverable(Utc::now(), 1).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn store_orders_and_selects_due_recoverable_and_capacity_cross_cases() {
        let now = Utc::now();
        let store = InMemoryWebhookStore::new();

        let mut later = fixture();
        later.created_at = now + chrono::Duration::seconds(2);
        later.updated_at = later.created_at;
        later.next_attempt_at = Some(later.created_at);
        later.destination_id = "ordered-later".to_string();
        let mut earlier = fixture();
        earlier.created_at = now + chrono::Duration::seconds(1);
        earlier.updated_at = earlier.created_at;
        earlier.next_attempt_at = Some(earlier.created_at);
        earlier.destination_id = "ordered-earlier".to_string();
        store.create(&later, 10).await.unwrap();
        store.create(&earlier, 10).await.unwrap();
        let listed = store.list().await.unwrap();
        assert_eq!(listed[0].id, earlier.id);
        assert_eq!(listed[1].id, later.id);

        let mut due = fixture();
        due.destination_id = "due".to_string();
        due.created_at = now - chrono::Duration::seconds(3);
        due.updated_at = due.created_at;
        due.next_attempt_at = Some(now);
        store.create(&due, 10).await.unwrap();
        let mut future = fixture();
        future.destination_id = "future".to_string();
        future.created_at = now - chrono::Duration::seconds(2);
        future.updated_at = future.created_at;
        future.next_attempt_at = Some(now + chrono::Duration::seconds(1));
        store.create(&future, 10).await.unwrap();
        let mut in_flight = fixture();
        in_flight.destination_id = "in-flight".to_string();
        in_flight.created_at = now - chrono::Duration::seconds(2);
        in_flight.updated_at = in_flight.created_at;
        in_flight.next_attempt_at = Some(in_flight.created_at);
        store.create(&in_flight, 10).await.unwrap();
        let active = claimed(&in_flight, now - chrono::Duration::seconds(1));
        assert!(store.compare_and_swap(0, &active).await.unwrap());
        let due_ids: Vec<_> =
            store.list_due(now, 10).await.unwrap().into_iter().map(|item| item.id).collect();
        assert!(due_ids.contains(&due.id));
        assert!(!due_ids.contains(&future.id));
        assert!(!due_ids.contains(&in_flight.id));

        let mut expired_source = fixture();
        expired_source.destination_id = "expired".to_string();
        expired_source.created_at = now - chrono::Duration::seconds(4);
        expired_source.updated_at = expired_source.created_at;
        expired_source.next_attempt_at = Some(expired_source.created_at);
        store.create(&expired_source, 10).await.unwrap();
        let expired = claimed(&expired_source, now - chrono::Duration::seconds(2));
        let mut expired = expired;
        expired.lease_expires_at = Some(now);
        assert!(store.compare_and_swap(0, &expired).await.unwrap());
        let recoverable_ids: Vec<_> = store
            .list_recoverable(now, 10)
            .await
            .unwrap()
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert!(recoverable_ids.contains(&expired_source.id));
        assert!(!recoverable_ids.contains(&in_flight.id));

        let other_destination_store = InMemoryWebhookStore::new();
        let mut other = fixture();
        other.destination_id = "other".to_string();
        other_destination_store.create(&other, 1).await.unwrap();
        let mut primary = fixture();
        primary.destination_id = "primary".to_string();
        assert!(other_destination_store.create(&primary, 1).await.is_ok());

        let terminal_store = InMemoryWebhookStore::new();
        let mut terminal_source = fixture();
        terminal_source.max_attempts = 1;
        terminal_store.create(&terminal_source, 1).await.unwrap();
        let terminal_claim = claimed(&terminal_source, now + chrono::Duration::seconds(1));
        assert!(terminal_store.compare_and_swap(0, &terminal_claim).await.unwrap());
        let terminal = succeeded(&terminal_claim, now + chrono::Duration::seconds(2));
        assert!(terminal_store.compare_and_swap(1, &terminal).await.unwrap());
        assert!(terminal_store.create(&fixture(), 1).await.is_ok());
    }

    #[test]
    fn replacement_rejects_payload_and_early_exhaustion_mutation() {
        let initial = fixture();
        let mut replacement = initial.clone();
        let now = Utc::now();
        replacement.transition(WebhookDeliveryState::Delivering, now).unwrap();
        replacement.revision = 1;
        replacement.attempts = 1;
        replacement.owner_id = Some(Uuid::new_v4());
        replacement.lease_expires_at = Some(now + chrono::Duration::seconds(15));
        replacement.next_attempt_at = None;
        replacement.updated_at = now;
        replacement.payload = serde_json::json!({"changed": true});
        assert!(replacement.validate_replacement(&initial, 0).is_err());
    }
}
