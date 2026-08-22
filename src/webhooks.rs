//! Policy-owned durable webhook enqueue and delivery service.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use reqwest::header::{HeaderValue, AUTHORIZATION};
use serde::Serialize;
use url::Url;
use uuid::Uuid;

use crate::config::WebhookConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::events::{DurableEventSink, ScanEvent};
use crate::engine::observation::redact_text;
use crate::engine::policy::{Capability, EffectClass, Engagement};
use crate::engine::policy_http::{build_service_client, RedirectMode};
use scorchkit_executor::webhook::{
    WebhookDelivery, WebhookDeliveryAuditEvent, WebhookDeliveryState, WebhookStore,
};

const DEFAULT_LEASE_SECONDS: u64 = 30;
const LEASE_GRACE_SECONDS: u64 = 5;
const DELIVERY_LIST_LIMIT: usize = 1_000;
const EVENT_SCHEMA: &str = "scorchkit.webhook-event/v1";

/// Bounded result of one recovery and due-delivery worker pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct WebhookWorkerSummary {
    /// Expired claims returned to queued or exhausted state.
    pub recovered: usize,
    /// Due records successfully claimed.
    pub claimed: usize,
    /// Attempts that reached a successful terminal state.
    pub succeeded: usize,
    /// Attempts requeued for a later retry.
    pub retried: usize,
    /// Attempts that reached exhausted terminal state.
    pub exhausted: usize,
    /// Due records skipped after a concurrent writer won the claim.
    pub conflicts: usize,
}

#[derive(Debug)]
struct AttemptFailure {
    message: String,
    status: Option<u16>,
}

/// Application service for redacted enqueueing and authorized delivery.
#[derive(Clone)]
pub struct WebhookService {
    destinations: Arc<BTreeMap<String, WebhookConfig>>,
    store: Arc<dyn WebhookStore>,
    owner_id: Uuid,
}

impl std::fmt::Debug for WebhookService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebhookService")
            .field("destination_ids", &self.destinations.keys().collect::<Vec<_>>())
            .field("owner_id", &self.owner_id)
            .finish_non_exhaustive()
    }
}

impl WebhookService {
    /// Validate destinations and bind an arbitrary durable store.
    ///
    /// # Errors
    ///
    /// Returns a credential-safe configuration error before any store or network effect.
    pub fn new(destinations: &[WebhookConfig], store: Arc<dyn WebhookStore>) -> Result<Self> {
        let mut configured = BTreeMap::new();
        for destination in destinations {
            destination.validate().map_err(ScorchError::Config)?;
            let id = destination.destination_id();
            if configured.insert(id.clone(), destination.clone()).is_some() {
                return Err(ScorchError::Config(format!(
                    "duplicate webhook destination id '{id}'"
                )));
            }
        }
        Ok(Self { destinations: Arc::new(configured), store, owner_id: Uuid::new_v4() })
    }

    /// Whether the service has any configured destination.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.destinations.is_empty()
    }

    /// Borrow the provider-neutral store.
    #[must_use]
    pub const fn store(&self) -> &Arc<dyn WebhookStore> {
        &self.store
    }

    /// Build a sink bound to the exact engagement that produced its events.
    #[must_use]
    pub fn sink(self: &Arc<Self>, engagement: Engagement) -> Arc<dyn DurableEventSink> {
        Arc::new(WebhookEventSink { service: Arc::clone(self), engagement })
    }

    /// Redact and enqueue one event for every matching destination.
    ///
    /// Redaction and size checks complete before the first call to the store.
    ///
    /// # Errors
    ///
    /// Returns a sanitized serialization, bound, capacity, or storage error.
    pub async fn enqueue_event(&self, event: &ScanEvent, engagement: &Engagement) -> Result<usize> {
        let kind = event_kind(event);
        let matching: Vec<_> =
            self.destinations.values().filter(|destination| destination.accepts(kind)).collect();
        if matching.is_empty() {
            return Ok(0);
        }

        let serialized = serde_json::to_string(event)?;
        let redacted = redact_text(&serialized);
        let event_value: serde_json::Value = serde_json::from_str(&redacted).map_err(|_| {
            ScorchError::Webhook("redacted webhook event was not valid JSON".to_string())
        })?;
        let payload = serde_json::json!({
            "schema": EVENT_SCHEMA,
            "event_kind": kind,
            "event": event_value,
        });
        let payload_size = serde_json::to_vec(&payload)?.len();
        for destination in &matching {
            if payload_size > destination.max_payload_bytes {
                return Err(ScorchError::Webhook(format!(
                    "destination '{}' rejected an event above its redacted payload bound",
                    destination.destination_id()
                )));
            }
        }

        let mut enqueued = 0usize;
        let mut failed = 0usize;
        for destination in matching {
            let delivery = WebhookDelivery::new(
                destination.destination_id(),
                kind.to_string(),
                payload.clone(),
                engagement.clone(),
                destination.max_attempts,
            );
            match self.store.create(&delivery, destination.max_pending).await {
                Ok(()) => enqueued = enqueued.saturating_add(1),
                Err(_) => failed = failed.saturating_add(1),
            }
        }
        if failed > 0 {
            return Err(ScorchError::Webhook(format!(
                "failed to persist {failed} of {} matching webhook deliveries",
                enqueued.saturating_add(failed)
            )));
        }
        Ok(enqueued)
    }

    /// Load one queue record.
    ///
    /// # Errors
    ///
    /// Returns a storage error or a typed not-found error.
    pub async fn get(&self, id: Uuid) -> Result<WebhookDelivery> {
        self.store
            .get(id)
            .await?
            .ok_or_else(|| ScorchError::Webhook(format!("delivery {id} was not found")))
    }

    /// List at most 1,000 queue records in deterministic creation order.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable store cannot be read.
    pub async fn list(&self) -> Result<Vec<WebhookDelivery>> {
        self.store.list().await
    }

    /// Return immutable audit history for one queue record.
    ///
    /// # Errors
    ///
    /// Returns a storage error or a typed not-found error.
    pub async fn audit_events(&self, id: Uuid) -> Result<Vec<WebhookDeliveryAuditEvent>> {
        if self.store.get(id).await?.is_none() {
            return Err(ScorchError::Webhook(format!("delivery {id} was not found")));
        }
        self.store.audit_events(id).await
    }

    /// Recover expired claims, then process one bounded due batch.
    ///
    /// # Errors
    ///
    /// Returns an error for durable-store failure or lost worker ownership.
    pub async fn run_due(&self) -> Result<WebhookWorkerSummary> {
        let mut summary = WebhookWorkerSummary {
            recovered: self.recover_expired().await?,
            ..WebhookWorkerSummary::default()
        };
        let due = self.store.list_due(Utc::now(), 100).await?;
        let mut destination_claims = BTreeMap::<String, usize>::new();
        for queued in due {
            let batch_size = self
                .destinations
                .get(&queued.destination_id)
                .map_or(1, |destination| destination.batch_size);
            let claimed_for_destination =
                destination_claims.get(&queued.destination_id).copied().unwrap_or_default();
            if claimed_for_destination >= batch_size {
                continue;
            }
            let destination_id = queued.destination_id.clone();
            let Some(claimed) = self.claim(queued).await? else {
                summary.conflicts = summary.conflicts.saturating_add(1);
                continue;
            };
            destination_claims.insert(destination_id, claimed_for_destination.saturating_add(1));
            summary.claimed = summary.claimed.saturating_add(1);
            match self.attempt(&claimed).await {
                Ok(status) => {
                    self.finish_success(claimed, status).await?;
                    summary.succeeded = summary.succeeded.saturating_add(1);
                }
                Err(failure) => {
                    let state = self.finish_failure(claimed, failure).await?;
                    if state == WebhookDeliveryState::Exhausted {
                        summary.exhausted = summary.exhausted.saturating_add(1);
                    } else {
                        summary.retried = summary.retried.saturating_add(1);
                    }
                }
            }
        }
        Ok(summary)
    }

    async fn recover_expired(&self) -> Result<usize> {
        let records = self.store.list_recoverable(Utc::now(), DELIVERY_LIST_LIMIT).await?;
        let mut recovered = 0usize;
        for record in records {
            if self.recover_one(record).await? {
                recovered = recovered.saturating_add(1);
            }
        }
        Ok(recovered)
    }

    async fn recover_one(&self, mut delivery: WebhookDelivery) -> Result<bool> {
        let expected_revision = delivery.revision;
        let now = Utc::now();
        let terminal = delivery.attempts >= delivery.max_attempts;
        scorchkit_executor::webhook_integration::transition_delivery(
            &mut delivery,
            if terminal { WebhookDeliveryState::Exhausted } else { WebhookDeliveryState::Queued },
            now,
        )?;
        delivery.owner_id = None;
        delivery.lease_expires_at = None;
        delivery.next_attempt_at = (!terminal).then_some(now);
        delivery.last_error = Some("delivery owner exited before attempt commit".to_string());
        delivery.last_status = None;
        delivery.updated_at = now;
        delivery.revision = next_revision(delivery.id, delivery.revision)?;
        self.store.compare_and_swap(expected_revision, &delivery).await
    }

    async fn claim(&self, mut delivery: WebhookDelivery) -> Result<Option<WebhookDelivery>> {
        let expected_revision = delivery.revision;
        let now = Utc::now();
        scorchkit_executor::webhook_integration::transition_delivery(
            &mut delivery,
            WebhookDeliveryState::Delivering,
            now,
        )?;
        delivery.attempts = delivery.attempts.checked_add(1).ok_or_else(|| {
            ScorchError::Webhook(format!("delivery {} attempt overflow", delivery.id))
        })?;
        delivery.owner_id = Some(self.owner_id);
        let lease_seconds = self
            .destinations
            .get(&delivery.destination_id)
            .map_or(DEFAULT_LEASE_SECONDS, |destination| {
                destination.timeout_seconds.saturating_add(LEASE_GRACE_SECONDS)
            });
        delivery.lease_expires_at =
            Some(now + chrono::Duration::seconds(i64::try_from(lease_seconds).unwrap_or(i64::MAX)));
        delivery.next_attempt_at = None;
        delivery.updated_at = now;
        delivery.revision = next_revision(delivery.id, delivery.revision)?;
        if self.store.compare_and_swap(expected_revision, &delivery).await? {
            Ok(Some(delivery))
        } else {
            Ok(None)
        }
    }

    async fn attempt(
        &self,
        delivery: &WebhookDelivery,
    ) -> std::result::Result<u16, AttemptFailure> {
        let Some(destination) = self.destinations.get(&delivery.destination_id) else {
            return Err(AttemptFailure {
                message: "configured destination is unavailable".to_string(),
                status: None,
            });
        };
        if destination.validate().is_err() {
            return Err(AttemptFailure {
                message: "configured destination is invalid".to_string(),
                status: None,
            });
        }
        let endpoint = Url::parse(&destination.url).map_err(|_| AttemptFailure {
            message: "configured destination is invalid".to_string(),
            status: None,
        })?;
        let client = build_service_client(
            Arc::new(delivery.engagement.clone()),
            &endpoint,
            Capability::WebhookDelivery,
            EffectClass::ActiveSafe,
            "scorchkit-webhook/3",
            Duration::from_secs(destination.timeout_seconds),
            RedirectMode::Follow { max_redirects: destination.max_redirects },
        )
        .map_err(|_| AttemptFailure {
            message: "destination denied or client construction failed".to_string(),
            status: None,
        })?;

        let serialized_payload =
            serde_json::to_string(&delivery.payload).map_err(|_| AttemptFailure {
                message: "stored redacted payload is invalid".to_string(),
                status: None,
            })?;
        let redacted_payload = redact_text(&serialized_payload);
        let request_payload: serde_json::Value =
            serde_json::from_str(&redacted_payload).map_err(|_| AttemptFailure {
                message: "stored redacted payload is invalid".to_string(),
                status: None,
            })?;
        let payload_size = serde_json::to_vec(&request_payload)
            .map_err(|_| AttemptFailure {
                message: "stored redacted payload is invalid".to_string(),
                status: None,
            })?
            .len();
        if payload_size > destination.max_payload_bytes {
            return Err(AttemptFailure {
                message: "stored redacted payload exceeds the current destination bound"
                    .to_string(),
                status: None,
            });
        }

        let mut request = client
            .post(endpoint)
            .header("x-scorchkit-delivery-id", delivery.id.to_string())
            .header("x-scorchkit-delivery-attempt", delivery.attempts.to_string())
            .json(&request_payload);
        if let Some(environment) = &destination.authorization_env {
            let secret = std::env::var(environment).map_err(|_| AttemptFailure {
                message: "authorization environment variable is unavailable".to_string(),
                status: None,
            })?;
            if secret.is_empty() || secret.len() > 8_192 {
                return Err(AttemptFailure {
                    message: "authorization header value is invalid".to_string(),
                    status: None,
                });
            }
            let value = HeaderValue::from_str(&secret).map_err(|_| AttemptFailure {
                message: "authorization header value is invalid".to_string(),
                status: None,
            })?;
            request = request.header(AUTHORIZATION, value);
        }
        let response = request.send().await.map_err(|_| AttemptFailure {
            message: "destination transport failed".to_string(),
            status: None,
        })?;
        let status = response.status();
        drop(response);
        if status.is_success() {
            Ok(status.as_u16())
        } else {
            Err(AttemptFailure {
                message: format!("destination returned HTTP status {}", status.as_u16()),
                status: Some(status.as_u16()),
            })
        }
    }

    async fn finish_success(&self, mut delivery: WebhookDelivery, status: u16) -> Result<()> {
        let expected_revision = delivery.revision;
        let now = Utc::now();
        scorchkit_executor::webhook_integration::transition_delivery(
            &mut delivery,
            WebhookDeliveryState::Succeeded,
            now,
        )?;
        delivery.owner_id = None;
        delivery.lease_expires_at = None;
        delivery.next_attempt_at = None;
        delivery.last_error = None;
        delivery.last_status = Some(status);
        delivery.updated_at = now;
        delivery.revision = next_revision(delivery.id, delivery.revision)?;
        if self.store.compare_and_swap(expected_revision, &delivery).await? {
            Ok(())
        } else {
            Err(ScorchError::Webhook(format!(
                "delivery {} success commit lost ownership",
                delivery.id
            )))
        }
    }

    async fn finish_failure(
        &self,
        mut delivery: WebhookDelivery,
        failure: AttemptFailure,
    ) -> Result<WebhookDeliveryState> {
        let expected_revision = delivery.revision;
        let now = Utc::now();
        let exhausted = delivery.attempts >= delivery.max_attempts;
        let state =
            if exhausted { WebhookDeliveryState::Exhausted } else { WebhookDeliveryState::Queued };
        scorchkit_executor::webhook_integration::transition_delivery(&mut delivery, state, now)?;
        delivery.owner_id = None;
        delivery.lease_expires_at = None;
        delivery.next_attempt_at =
            if exhausted { None } else { Some(now + self.retry_delay(&delivery)) };
        delivery.last_error = Some(redact_text(&failure.message).chars().take(512).collect());
        delivery.last_status = failure.status;
        delivery.updated_at = now;
        delivery.revision = next_revision(delivery.id, delivery.revision)?;
        if self.store.compare_and_swap(expected_revision, &delivery).await? {
            Ok(state)
        } else {
            Err(ScorchError::Webhook(format!(
                "delivery {} failure commit lost ownership",
                delivery.id
            )))
        }
    }

    fn retry_delay(&self, delivery: &WebhookDelivery) -> chrono::Duration {
        let (initial, maximum) = self
            .destinations
            .get(&delivery.destination_id)
            .map_or((5_u64, 300_u64), |destination| {
                (destination.backoff_seconds, destination.max_backoff_seconds)
            });
        let exponent = delivery.attempts.saturating_sub(1).min(20);
        let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
        let seconds = initial.saturating_mul(multiplier).min(maximum);
        chrono::Duration::seconds(i64::try_from(seconds).unwrap_or(i64::MAX))
    }
}

fn next_revision(id: Uuid, revision: u64) -> Result<u64> {
    revision
        .checked_add(1)
        .ok_or_else(|| ScorchError::Webhook(format!("delivery {id} revision overflow")))
}

const fn event_kind(event: &ScanEvent) -> &'static str {
    match event {
        ScanEvent::ScanStarted { .. } => "scan_started",
        ScanEvent::ModuleStarted { .. } => "module_started",
        ScanEvent::ModuleCompleted { .. } => "module_completed",
        ScanEvent::ModuleSkipped { .. } => "module_skipped",
        ScanEvent::ModuleError { .. } => "module_error",
        ScanEvent::FindingProduced { .. } => "finding_produced",
        ScanEvent::ScanCompleted { .. } => "scan_completed",
        ScanEvent::Custom { .. } => "custom",
    }
}

struct WebhookEventSink {
    service: Arc<WebhookService>,
    engagement: Engagement,
}

#[async_trait]
impl DurableEventSink for WebhookEventSink {
    async fn persist(&self, event: &ScanEvent) -> std::result::Result<(), String> {
        self.service
            .enqueue_event(event, &self.engagement)
            .await
            .map(|_| ())
            .map_err(|_| "webhook enqueue failed; inspect durable queue diagnostics".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scorchkit_executor::webhook::InMemoryWebhookStore;
    use scorchkit_policy::{EngagementPolicy, ScopeRule};

    fn config(url: &str) -> WebhookConfig {
        serde_json::from_value(serde_json::json!({
            "id": "primary",
            "url": url,
            "events": ["scan_completed"],
            "max_attempts": 1,
            "timeout_seconds": 2,
            "backoff_seconds": 1,
            "max_backoff_seconds": 1
        }))
        .unwrap()
    }

    fn engagement(scope: &str) -> Engagement {
        Engagement::new(
            "webhook fixture",
            EngagementPolicy::default()
                .allow_scope(ScopeRule::parse(scope).unwrap())
                .allow_capability(Capability::WebhookDelivery)
                .allow_effect(EffectClass::ActiveSafe),
        )
    }

    #[test]
    fn service_enablement_and_debug_are_exact_and_secret_safe() {
        let empty = WebhookService::new(&[], Arc::new(InMemoryWebhookStore::new())).unwrap();
        assert!(!empty.is_enabled());
        assert!(format!("{empty:?}").contains("destination_ids: []"));

        let configured = WebhookService::new(
            &[config("https://hooks.example.test/private-path")],
            Arc::new(InMemoryWebhookStore::new()),
        )
        .unwrap();
        assert!(configured.is_enabled());
        let debug = format!("{configured:?}");
        assert!(debug.contains("primary"));
        assert!(!debug.contains("hooks.example.test"));
        assert!(!debug.contains("private-path"));
    }

    #[tokio::test]
    async fn enqueue_payload_bound_accepts_exact_size_and_rejects_one_less() {
        let event = ScanEvent::ScanCompleted {
            scan_id: "scan-boundary".to_string(),
            total_findings: 0,
            duration_ms: 1,
        };
        let serialized = serde_json::to_string(&event).unwrap();
        let event_value: serde_json::Value =
            serde_json::from_str(&redact_text(&serialized)).unwrap();
        let payload = serde_json::json!({
            "schema": EVENT_SCHEMA,
            "event_kind": event_kind(&event),
            "event": event_value,
        });
        let exact_size = serde_json::to_vec(&payload).unwrap().len();

        let mut exact = config("https://hooks.example.test/delivery");
        exact.max_payload_bytes = exact_size;
        let exact_store = Arc::new(InMemoryWebhookStore::new());
        let exact_service = WebhookService::new(&[exact], exact_store.clone()).unwrap();
        assert_eq!(
            exact_service.enqueue_event(&event, &engagement("example.test")).await.unwrap(),
            1
        );
        assert_eq!(exact_store.list().await.unwrap().len(), 1);

        let mut one_less = config("https://hooks.example.test/delivery");
        one_less.max_payload_bytes = exact_size - 1;
        let rejected_store = Arc::new(InMemoryWebhookStore::new());
        let rejected_service = WebhookService::new(&[one_less], rejected_store.clone()).unwrap();
        assert!(rejected_service.enqueue_event(&event, &engagement("example.test")).await.is_err());
        assert!(rejected_store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn partial_enqueue_and_real_sink_failure_are_reported_without_rollback() {
        let store = Arc::new(InMemoryWebhookStore::new());
        let mut first = config("https://hooks.example.test/first");
        first.id = Some("first".to_string());
        let mut full = config("https://hooks.example.test/full");
        full.id = Some("full".to_string());
        full.max_pending = 1;
        let occupied = WebhookDelivery::new(
            "full".to_string(),
            "scan_completed".to_string(),
            serde_json::json!({"schema":EVENT_SCHEMA}),
            engagement("example.test"),
            1,
        );
        store.create(&occupied, 1).await.unwrap();
        let service = Arc::new(WebhookService::new(&[first, full], store.clone()).unwrap());
        let event = ScanEvent::ScanCompleted {
            scan_id: "scan-partial".to_string(),
            total_findings: 0,
            duration_ms: 1,
        };
        let error = service.enqueue_event(&event, &engagement("example.test")).await.unwrap_err();
        assert!(error.to_string().contains("failed to persist 1 of 2"));
        assert_eq!(store.list().await.unwrap().len(), 2);

        let sink_error =
            service.sink(engagement("example.test")).persist(&event).await.unwrap_err();
        assert_eq!(sink_error, "webhook enqueue failed; inspect durable queue diagnostics");
    }

    #[tokio::test]
    async fn enqueue_filters_and_redacts_before_store() {
        let store = Arc::new(InMemoryWebhookStore::new());
        let mut destination = config("https://hooks.example.test/delivery");
        destination.events = vec!["custom".to_string()];
        let service = WebhookService::new(&[destination], store.clone()).unwrap();
        let ignored = ScanEvent::ScanStarted {
            scan_id: "ignored".to_string(),
            target: "https://example.test".to_string(),
        };
        assert_eq!(service.enqueue_event(&ignored, &engagement("example.test")).await.unwrap(), 0);
        let event = ScanEvent::Custom {
            kind: "fixture.completed".to_string(),
            data: serde_json::json!({"authorization": "Bearer secret-canary"}),
        };
        assert_eq!(service.enqueue_event(&event, &engagement("example.test")).await.unwrap(), 1);
        let serialized = serde_json::to_string(&store.list().await.unwrap()).unwrap();
        assert!(!serialized.contains("secret-canary"));
        assert!(!serialized.contains("hooks.example.test"));
    }

    #[tokio::test]
    async fn authorized_attempt_succeeds_without_reading_response_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 8_192];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.contains("scan_completed"));
            assert!(request.to_ascii_lowercase().contains("x-scorchkit-delivery-id:"));
            assert!(request.to_ascii_lowercase().contains("x-scorchkit-delivery-attempt: 1"));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let store = Arc::new(InMemoryWebhookStore::new());
        let service =
            WebhookService::new(&[config(&format!("http://{address}/delivery"))], store).unwrap();
        let event = ScanEvent::ScanCompleted {
            scan_id: "scan-1".to_string(),
            total_findings: 0,
            duration_ms: 1,
        };
        service.enqueue_event(&event, &engagement("127.0.0.1")).await.unwrap();
        let summary = service.run_due().await.unwrap();
        assert_eq!(summary.succeeded, 1);
        assert_eq!(service.list().await.unwrap()[0].state, WebhookDeliveryState::Succeeded);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn denied_destination_exhausts_without_a_network_effect() {
        let store = Arc::new(InMemoryWebhookStore::new());
        let service = WebhookService::new(&[config("http://127.0.0.1:9/delivery")], store).unwrap();
        let event = ScanEvent::ScanCompleted {
            scan_id: "scan-1".to_string(),
            total_findings: 0,
            duration_ms: 1,
        };
        service.enqueue_event(&event, &engagement("example.test")).await.unwrap();
        let summary = service.run_due().await.unwrap();
        assert_eq!(summary.exhausted, 1);
        let record = service.list().await.unwrap().remove(0);
        assert_eq!(record.state, WebhookDeliveryState::Exhausted);
        assert_eq!(
            record.last_error.as_deref(),
            Some("destination denied or client construction failed")
        );
        let audit = service.audit_events(record.id).await.unwrap();
        assert_eq!(
            audit.last().and_then(|event| event.last_error.as_deref()),
            record.last_error.as_deref()
        );
    }

    #[tokio::test]
    async fn worker_enforces_each_destination_batch_bound() {
        let mut first = config("http://127.0.0.1:9/first");
        first.id = Some("first".to_string());
        first.batch_size = 1;
        let mut second = config("http://127.0.0.1:9/second");
        second.id = Some("second".to_string());
        second.batch_size = 2;
        let service =
            WebhookService::new(&[first, second], Arc::new(InMemoryWebhookStore::new())).unwrap();
        let event = ScanEvent::ScanCompleted {
            scan_id: "scan-1".to_string(),
            total_findings: 0,
            duration_ms: 1,
        };
        for _ in 0..3 {
            assert_eq!(
                service.enqueue_event(&event, &engagement("example.test")).await.unwrap(),
                2
            );
        }

        let summary = service.run_due().await.unwrap();
        assert_eq!(summary.claimed, 3);
        assert_eq!(summary.exhausted, 3);
        let records = service.list().await.unwrap();
        let exhausted_for = |destination: &str| {
            records
                .iter()
                .filter(|delivery| {
                    delivery.destination_id == destination
                        && delivery.state == WebhookDeliveryState::Exhausted
                })
                .count()
        };
        assert_eq!(exhausted_for("first"), 1);
        assert_eq!(exhausted_for("second"), 2);
    }

    #[tokio::test]
    async fn worker_recovers_expired_leases_and_pins_retry_due_time() {
        let now = Utc::now();
        let store = Arc::new(InMemoryWebhookStore::new());
        let mut destination = config("http://127.0.0.1:9/delivery");
        destination.max_attempts = 2;
        destination.backoff_seconds = 1;
        destination.max_backoff_seconds = 1;
        let service = WebhookService::new(&[destination], store.clone()).unwrap();

        let event = ScanEvent::ScanCompleted {
            scan_id: "scan-retry".to_string(),
            total_findings: 0,
            duration_ms: 1,
        };
        service.enqueue_event(&event, &engagement("example.test")).await.unwrap();
        let retry_summary = service.run_due().await.unwrap();
        assert_eq!(retry_summary.retried, 1);
        let retried = service.list().await.unwrap().remove(0);
        assert_eq!(retried.state, WebhookDeliveryState::Queued);
        assert_eq!(
            retried.next_attempt_at.unwrap() - retried.updated_at,
            chrono::Duration::seconds(1)
        );

        let mut recoverable = WebhookDelivery::new(
            "primary".to_string(),
            "scan_completed".to_string(),
            serde_json::json!({"schema":EVENT_SCHEMA}),
            engagement("example.test"),
            2,
        );
        recoverable.created_at = now - chrono::Duration::seconds(20);
        recoverable.updated_at = recoverable.created_at;
        recoverable.next_attempt_at = Some(recoverable.created_at);
        store.create(&recoverable, 100).await.unwrap();
        let mut claimed = recoverable.clone();
        let claim_time = now - chrono::Duration::seconds(10);
        scorchkit_executor::webhook_integration::transition_delivery(
            &mut claimed,
            WebhookDeliveryState::Delivering,
            claim_time,
        )
        .unwrap();
        claimed.revision = 1;
        claimed.attempts = 1;
        claimed.owner_id = Some(Uuid::new_v4());
        claimed.lease_expires_at = Some(now - chrono::Duration::seconds(1));
        claimed.next_attempt_at = None;
        claimed.updated_at = claim_time;
        assert!(store.compare_and_swap(0, &claimed).await.unwrap());

        let mut terminal_source = recoverable.clone();
        terminal_source.id = Uuid::new_v4();
        terminal_source.max_attempts = 1;
        store.create(&terminal_source, 100).await.unwrap();
        let mut terminal_claim = terminal_source.clone();
        scorchkit_executor::webhook_integration::transition_delivery(
            &mut terminal_claim,
            WebhookDeliveryState::Delivering,
            claim_time,
        )
        .unwrap();
        terminal_claim.revision = 1;
        terminal_claim.attempts = 1;
        terminal_claim.owner_id = Some(Uuid::new_v4());
        terminal_claim.lease_expires_at = Some(now - chrono::Duration::seconds(1));
        terminal_claim.next_attempt_at = None;
        terminal_claim.updated_at = claim_time;
        assert!(store.compare_and_swap(0, &terminal_claim).await.unwrap());

        let summary = service.run_due().await.unwrap();
        assert_eq!(summary.recovered, 2);
        assert_eq!(summary.claimed, 1);
        assert_eq!(summary.exhausted, 1);
        let recoverable_audit = service.audit_events(recoverable.id).await.unwrap();
        assert!(recoverable_audit
            .iter()
            .any(|event| event.state == WebhookDeliveryState::Queued && event.revision == 2));
        let terminal_audit = service.audit_events(terminal_source.id).await.unwrap();
        assert_eq!(terminal_audit.last().unwrap().state, WebhookDeliveryState::Exhausted);

        let conflict_store = Arc::new(InMemoryWebhookStore::new());
        let conflict_service =
            WebhookService::new(&[config("http://127.0.0.1:9/delivery")], conflict_store).unwrap();
        assert!(!conflict_service.recover_one(claimed).await.unwrap());
    }

    #[tokio::test]
    async fn network_construction_revalidates_redaction_and_lease_covers_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 8_192];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(!request.contains("network-redaction-canary"));
            assert!(request.contains("REDACTED"));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let mut destination = config(&format!("http://{address}/delivery"));
        let store = Arc::new(InMemoryWebhookStore::new());
        let direct = WebhookDelivery::new(
            destination.destination_id(),
            "scan_completed".to_string(),
            serde_json::json!({"authorization":"Bearer network-redaction-canary"}),
            engagement("127.0.0.1"),
            1,
        );
        let redacted_payload = redact_text(&serde_json::to_string(&direct.payload).unwrap());
        let request_payload: serde_json::Value = serde_json::from_str(&redacted_payload).unwrap();
        let exact_size = serde_json::to_vec(&request_payload).unwrap().len();
        destination.max_payload_bytes = exact_size;
        store.create(&direct, destination.max_pending).await.unwrap();
        let service = WebhookService::new(std::slice::from_ref(&destination), store).unwrap();
        let claimed = service.claim(direct).await.unwrap().unwrap();
        let lease = claimed.lease_expires_at.unwrap() - claimed.updated_at;
        assert!(
            lease
                >= chrono::Duration::seconds(
                    i64::try_from(destination.timeout_seconds + LEASE_GRACE_SECONDS).unwrap()
                )
        );
        assert_eq!(service.attempt(&claimed).await.unwrap(), 204);
        server.await.unwrap();

        let mut smaller = destination;
        smaller.max_payload_bytes = exact_size - 1;
        let smaller_service =
            WebhookService::new(&[smaller], Arc::new(InMemoryWebhookStore::new())).unwrap();
        assert_eq!(
            smaller_service.attempt(&claimed).await.unwrap_err().message,
            "stored redacted payload exceeds the current destination bound"
        );
    }

    #[test]
    fn authorization_secret_is_runtime_only_and_absent_from_state_and_audit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const ENVIRONMENT: &str = "SCORCHKIT_TEST_WEBHOOK_AUTHORIZATION";
        let _environment_guard = crate::TEST_ENVIRONMENT_LOCK.lock().unwrap();
        let authorization_value = format!("Bearer {}-{}", "fixture", "auth-value");
        std::env::set_var(ENVIRONMENT, &authorization_value);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let expected_authorization = authorization_value.clone();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 8_192];
                let read = stream.read(&mut request).await.unwrap();
                assert!(
                    String::from_utf8_lossy(&request[..read]).contains(&expected_authorization)
                );
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            });
            let mut destination = config(&format!("http://{address}/delivery"));
            destination.authorization_env = Some(ENVIRONMENT.to_string());
            destination.max_redirects = 0;
            let store = Arc::new(InMemoryWebhookStore::new());
            let service = WebhookService::new(&[destination], store).unwrap();
            let event = ScanEvent::ScanCompleted {
                scan_id: "scan-1".to_string(),
                total_findings: 0,
                duration_ms: 1,
            };
            service.enqueue_event(&event, &engagement("127.0.0.1")).await.unwrap();
            assert_eq!(service.run_due().await.unwrap().succeeded, 1);
            server.await.unwrap();

            let delivery = service.list().await.unwrap().remove(0);
            let state = serde_json::to_string(&delivery).unwrap();
            let audit =
                serde_json::to_string(&service.audit_events(delivery.id).await.unwrap()).unwrap();
            assert!(!state.contains(&authorization_value));
            assert!(!audit.contains(&authorization_value));
            assert!(!format!("{service:?}").contains(&authorization_value));

            std::env::remove_var(ENVIRONMENT);
            let mut missing_destination = config("http://127.0.0.1:9/delivery");
            missing_destination.authorization_env = Some(ENVIRONMENT.to_string());
            missing_destination.max_redirects = 0;
            let missing_service = WebhookService::new(
                &[missing_destination],
                Arc::new(InMemoryWebhookStore::new()),
            )
            .unwrap();
            missing_service
                .enqueue_event(&event, &engagement("127.0.0.1"))
                .await
                .unwrap();
            assert_eq!(missing_service.run_due().await.unwrap().exhausted, 1);
            let missing = missing_service.list().await.unwrap().remove(0);
            assert_eq!(
                missing.last_error.as_deref(),
                Some("authorization environment variable is unavailable")
            );
            assert!(!missing.last_error.as_deref().unwrap().contains(ENVIRONMENT));

        });
        std::env::remove_var(ENVIRONMENT);
    }

    #[test]
    fn authorization_header_size_boundaries_are_exact() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const ENVIRONMENT: &str = "SCORCHKIT_TEST_WEBHOOK_AUTHORIZATION_BOUND";
        let _environment_guard = crate::TEST_ENVIRONMENT_LOCK.lock().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let event = ScanEvent::ScanCompleted {
                scan_id: "scan-auth-bound".to_string(),
                total_findings: 0,
                duration_ms: 1,
            };
            for invalid_value in [String::new(), "A".repeat(8_193)] {
                std::env::set_var(ENVIRONMENT, invalid_value);
                let mut destination = config("http://127.0.0.1:9/delivery");
                destination.authorization_env = Some(ENVIRONMENT.to_string());
                destination.max_redirects = 0;
                let service =
                    WebhookService::new(&[destination], Arc::new(InMemoryWebhookStore::new()))
                        .unwrap();
                service.enqueue_event(&event, &engagement("127.0.0.1")).await.unwrap();
                assert_eq!(service.run_due().await.unwrap().exhausted, 1);
                assert_eq!(
                    service.list().await.unwrap()[0].last_error.as_deref(),
                    Some("authorization header value is invalid")
                );
            }

            std::env::set_var(ENVIRONMENT, "A".repeat(8_192));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 1_024];
                let _ = stream.read(&mut request).await.unwrap();
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            });
            let mut destination = config(&format!("http://{address}/delivery"));
            destination.authorization_env = Some(ENVIRONMENT.to_string());
            destination.max_redirects = 0;
            let service =
                WebhookService::new(&[destination], Arc::new(InMemoryWebhookStore::new())).unwrap();
            service.enqueue_event(&event, &engagement("127.0.0.1")).await.unwrap();
            assert_eq!(service.run_due().await.unwrap().succeeded, 1);
            server.await.unwrap();
        });
        std::env::remove_var(ENVIRONMENT);
    }
}
