//! In-process event bus for scan lifecycle events.
//!
//! Provides a `tokio::broadcast`-based pub/sub channel so orchestrators can
//! emit typed lifecycle events and multiple subscribers can react to them
//! independently. Events are owned (no lifetimes) and `Clone` so the broadcast
//! channel can fan them out. Publishing is fire-and-forget — publishers never
//! block on handlers, and handler errors are logged but do not affect the scan.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() {
//! use scorchkit::engine::events::{EventBus, ScanEvent};
//!
//! let bus = EventBus::default();
//! let mut rx = bus.subscribe();
//!
//! bus.publish(ScanEvent::ScanStarted {
//!     scan_id: "abc".to_string(),
//!     target: "https://example.com".to_string(),
//! });
//!
//! if let Ok(event) = rx.recv().await {
//!     println!("received: {event:?}");
//! }
//! # }
//! ```
//!
//! # Custom events
//!
//! Modules can publish arbitrary typed events via `ScanEvent::Custom`:
//!
//! ```no_run
//! use scorchkit::engine::events::{EventBus, ScanEvent};
//! use serde_json::json;
//!
//! # let bus = EventBus::default();
//! bus.publish(ScanEvent::Custom {
//!     kind: "crawler.depth-reached".to_string(),
//!     data: json!({ "depth": 3, "url": "https://example.com/admin" }),
//! });
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::finding::Finding;

/// Default capacity for the broadcast channel.
///
/// Large enough that normal scans won't lag any reasonable subscriber, small
/// enough to bound memory at ~a few KB per subscriber in the worst case.
pub const DEFAULT_CAPACITY: usize = 256;

/// Scan lifecycle events emitted by orchestrators.
///
/// All variants carry owned data so the event can be cloned and delivered to
/// multiple subscribers through a `tokio::broadcast` channel.
///
/// `Serialize` is derived so built-in handlers (e.g.
/// [`crate::engine::audit_log::AuditLogHandler`]) can emit events as JSON.
/// Variant and field names are part of the on-the-wire format — renaming
/// is a breaking change for any consumer parsing the serialized output.
#[derive(Debug, Clone, serde::Serialize)]
pub enum ScanEvent {
    /// A scan has begun. Emitted once per orchestrator run before any modules.
    ScanStarted {
        /// UUID of the scan.
        scan_id: String,
        /// Target URL or path as a string.
        target: String,
    },
    /// A module is about to execute.
    ModuleStarted {
        /// UUID of the scan this module belongs to.
        scan_id: String,
        /// Module ID (e.g. `headers`, `ssl`).
        module_id: String,
        /// Human-readable module name.
        module_name: String,
    },
    /// A module completed successfully.
    ModuleCompleted {
        /// UUID of the scan this module belongs to.
        scan_id: String,
        /// Module ID.
        module_id: String,
        /// Number of findings produced by this module.
        findings_count: usize,
        /// Module execution time in milliseconds.
        duration_ms: u64,
    },
    /// A module was skipped — typically because a required external tool is
    /// not installed.
    ModuleSkipped {
        /// UUID of the scan.
        scan_id: String,
        /// Module ID.
        module_id: String,
        /// Human-readable reason.
        reason: String,
    },
    /// A module returned an error. The scan continues with other modules.
    ModuleError {
        /// UUID of the scan.
        scan_id: String,
        /// Module ID.
        module_id: String,
        /// Stringified error.
        error: String,
    },
    /// A single finding was produced by a module.
    FindingProduced {
        /// UUID of the scan.
        scan_id: String,
        /// Module that produced the finding.
        module_id: String,
        /// The finding (boxed so this variant doesn't dominate the enum size).
        ///
        /// Deref through the `Box` transparently: `finding.title` works as
        /// usual in pattern matches and accessors.
        finding: Box<Finding>,
    },
    /// The scan has completed. Emitted once at the very end.
    ScanCompleted {
        /// UUID of the scan.
        scan_id: String,
        /// Total finding count across all modules.
        total_findings: usize,
        /// Total scan duration in milliseconds.
        duration_ms: u64,
    },
    /// A module-emitted custom event.
    ///
    /// Use for domain-specific telemetry that doesn't fit a core lifecycle
    /// variant. Kinds follow a dotted-namespace convention
    /// (e.g. `"crawler.depth-reached"`, `"waf.detected"`); the convention is
    /// documented, not enforced.
    Custom {
        /// Namespaced event kind identifier.
        kind: String,
        /// Arbitrary typed payload. Use `serde_json::to_value(my_struct)`
        /// to encode typed data and `serde_json::from_value(data)` to decode.
        data: serde_json::Value,
    },
}

/// Broadcast channel for scan events.
///
/// Cheaply cloneable — each clone shares the same underlying channel so
/// publishers and subscribers created from clones all talk to the same bus.
#[derive(Clone, Debug)]
pub struct EventBus {
    sender: broadcast::Sender<ScanEvent>,
}

impl EventBus {
    /// Create an event bus with a custom buffer capacity.
    ///
    /// The capacity bounds how many events a slow subscriber can fall behind
    /// by before events are dropped for that subscriber. Publishing is never
    /// blocked by slow subscribers.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _rx) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publish an event to all current subscribers.
    ///
    /// Fire-and-forget: if there are no subscribers, the event is silently
    /// dropped. This is a normal, non-error condition — observability events
    /// without observers are a no-op.
    pub fn publish(&self, event: ScanEvent) {
        // `send` returns an error only when there are zero receivers. That is
        // a normal no-op for observability-style events — log at debug and
        // continue.
        if let Err(e) = self.sender.send(event) {
            debug!("event bus: no subscribers — {e}");
        }
    }

    /// Create a new subscriber receiver.
    ///
    /// Each subscriber receives every event published after it subscribed.
    /// If a subscriber falls more than `capacity` events behind, the oldest
    /// events are dropped and the receiver sees a `Lagged` error on the next
    /// `recv`.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<ScanEvent> {
        self.sender.subscribe()
    }

    /// Returns the current number of active subscribers.
    ///
    /// Primarily useful for tests and diagnostics.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

/// Async trait for event subscribers.
///
/// Implementations receive scan events as they are published. Handler return
/// values are advisory — errors are logged at `warn` and do not propagate
/// back to the publisher.
#[async_trait]
pub trait EventHandler: Send + Sync {
    /// Handle a single scan event.
    ///
    /// # Errors
    ///
    /// Implementations may return `Err(message)` for diagnostic purposes;
    /// errors are logged but do not abort the scan or other handlers.
    async fn handle(&self, event: ScanEvent) -> Result<(), String>;
}

/// Spawn a background task that drives `handler` with every event published
/// on `bus` until the bus is dropped.
///
/// The returned `JoinHandle` can be awaited if the caller wants to wait for
/// the handler loop to finish (which happens when all `EventBus` clones are
/// dropped and the channel closes). Typically callers fire-and-forget.
#[must_use]
pub fn subscribe_handler(bus: &EventBus, handler: Arc<dyn EventHandler>) -> JoinHandle<()> {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Err(e) = handler.handle(event).await {
                        warn!("event handler error: {e}");
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("event handler lagged — dropped {n} events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// Spawn a background task like [`subscribe_handler`], but only drive the
/// handler for events where `predicate(&event)` returns `true`.
///
/// The predicate is evaluated on the subscriber's receive task — filtering
/// is free for the publisher and for other subscribers. Lagged and closed
/// semantics are identical to [`subscribe_handler`].
///
/// ```no_run
/// # use std::sync::Arc;
/// # use scorchkit::engine::events::{EventBus, EventHandler, ScanEvent, subscribe_filtered};
/// # use scorchkit::engine::severity::Severity;
/// # async fn example(bus: &EventBus, handler: Arc<dyn EventHandler>) {
/// // Only deliver High/Critical FindingProduced events:
/// let join = subscribe_filtered(bus, handler, |event| {
///     matches!(
///         event,
///         ScanEvent::FindingProduced { finding, .. }
///             if matches!(finding.severity, Severity::High | Severity::Critical)
///     )
/// });
/// # drop(join);
/// # }
/// ```
#[must_use]
pub fn subscribe_filtered<F>(
    bus: &EventBus,
    handler: Arc<dyn EventHandler>,
    predicate: F,
) -> JoinHandle<()>
where
    F: Fn(&ScanEvent) -> bool + Send + Sync + 'static,
{
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if !predicate(&event) {
                        continue;
                    }
                    if let Err(e) = handler.handle(event).await {
                        warn!("event handler error: {e}");
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("event handler lagged — dropped {n} events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::severity::Severity;
    use std::sync::Mutex;
    use std::time::Duration;

    fn sample_event() -> ScanEvent {
        ScanEvent::ScanStarted {
            scan_id: "scan-1".to_string(),
            target: "https://example.com".to_string(),
        }
    }

    /// Verify a single subscriber receives a published event.
    #[tokio::test]
    async fn test_event_bus_publish_subscribe() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        bus.publish(sample_event());
        let received = rx.recv().await.expect("receive");
        assert!(matches!(received, ScanEvent::ScanStarted { .. }));
    }

    /// Verify fanout to multiple subscribers — both receive the same event.
    #[tokio::test]
    async fn test_event_bus_multiple_subscribers() {
        let bus = EventBus::new(16);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
        bus.publish(sample_event());
        let e1 = rx1.recv().await.expect("rx1");
        let e2 = rx2.recv().await.expect("rx2");
        assert!(matches!(e1, ScanEvent::ScanStarted { .. }));
        assert!(matches!(e2, ScanEvent::ScanStarted { .. }));
    }

    /// Verify publishing with zero subscribers is a silent no-op.
    #[tokio::test]
    async fn test_event_bus_no_subscribers() {
        let bus = EventBus::new(16);
        assert_eq!(bus.subscriber_count(), 0);
        // Should not panic, should not error to the caller.
        bus.publish(sample_event());
    }

    /// Verify `EventBus::default()` is usable and accepts events.
    #[tokio::test]
    async fn test_event_bus_default_capacity() {
        let bus = EventBus::default();
        let mut rx = bus.subscribe();
        bus.publish(ScanEvent::ScanCompleted {
            scan_id: "x".to_string(),
            total_findings: 0,
            duration_ms: 1,
        });
        assert!(matches!(rx.recv().await, Ok(ScanEvent::ScanCompleted { .. })));
    }

    #[derive(Default)]
    struct CollectingHandler {
        received: Arc<Mutex<Vec<ScanEvent>>>,
    }

    #[async_trait]
    impl EventHandler for CollectingHandler {
        async fn handle(&self, event: ScanEvent) -> Result<(), String> {
            self.received.lock().map_err(|e| e.to_string())?.push(event);
            Ok(())
        }
    }

    /// Verify `subscribe_handler` delivers events to an `EventHandler`.
    #[tokio::test]
    async fn test_subscribe_handler_receives_all() {
        let bus = EventBus::new(16);
        let received: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(CollectingHandler { received: received.clone() });
        let join = subscribe_handler(&bus, handler);

        bus.publish(sample_event());
        bus.publish(ScanEvent::ScanCompleted {
            scan_id: "scan-1".to_string(),
            total_findings: 0,
            duration_ms: 1,
        });

        // Give the spawned task a chance to drain the channel, then close
        // the bus so the subscribe_handler loop exits cleanly.
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(bus);
        join.await.expect("join");

        let got = received.lock().expect("lock");
        assert_eq!(got.len(), 2);
        assert!(matches!(got[0], ScanEvent::ScanStarted { .. }));
        assert!(matches!(got[1], ScanEvent::ScanCompleted { .. }));
    }

    struct FailingHandler;

    #[async_trait]
    impl EventHandler for FailingHandler {
        async fn handle(&self, _event: ScanEvent) -> Result<(), String> {
            Err("intentional failure".to_string())
        }
    }

    /// A handler returning `Err` is logged but does not abort the loop or
    /// affect other subscribers.
    #[tokio::test]
    async fn test_handler_error_does_not_abort_scan() {
        let bus = EventBus::new(16);
        let received: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let good = Arc::new(CollectingHandler { received: received.clone() });
        let bad = Arc::new(FailingHandler);

        let j_bad = subscribe_handler(&bus, bad);
        let j_good = subscribe_handler(&bus, good);

        bus.publish(sample_event());
        bus.publish(ScanEvent::ModuleStarted {
            scan_id: "scan-1".to_string(),
            module_id: "headers".to_string(),
            module_name: "Security Headers".to_string(),
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(bus);
        j_bad.await.expect("j_bad");
        j_good.await.expect("j_good");

        // The good handler got both events despite the bad one failing.
        assert_eq!(received.lock().expect("lock").len(), 2);
    }

    /// Regression: a `FindingProduced` event carries an owned `Finding` that
    /// can be fanned out to multiple subscribers without sharing.
    #[tokio::test]
    async fn test_finding_produced_fanout() {
        let bus = EventBus::new(16);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let finding = Finding::new(
            "headers",
            Severity::Medium,
            "missing HSTS",
            "no Strict-Transport-Security header",
            "https://example.com",
        );
        bus.publish(ScanEvent::FindingProduced {
            scan_id: "scan-1".to_string(),
            module_id: "headers".to_string(),
            finding: Box::new(finding),
        });

        let e1 = rx1.recv().await.expect("rx1");
        let e2 = rx2.recv().await.expect("rx2");
        match (e1, e2) {
            (
                ScanEvent::FindingProduced { finding: f1, .. },
                ScanEvent::FindingProduced { finding: f2, .. },
            ) => {
                assert_eq!(f1.title, "missing HSTS");
                assert_eq!(f2.title, "missing HSTS");
            }
            other => panic!("unexpected events: {other:?}"),
        }
    }

    // ---------------------------------------------------------------------
    // WORK-098 (v2b.1) — Custom events + subscribe_filtered
    // ---------------------------------------------------------------------

    /// Regression: `ScanEvent::Custom` publishes and is received with kind +
    /// data intact.
    #[tokio::test]
    async fn test_custom_event_round_trip() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        bus.publish(ScanEvent::Custom {
            kind: "crawler.depth-reached".to_string(),
            data: serde_json::json!({ "depth": 3, "url": "https://example.com/admin" }),
        });
        match rx.recv().await.expect("receive") {
            ScanEvent::Custom { kind, data } => {
                assert_eq!(kind, "crawler.depth-reached");
                assert_eq!(data["depth"], 3);
                assert_eq!(data["url"], "https://example.com/admin");
            }
            other => panic!("expected Custom, got {other:?}"),
        }
    }

    /// Regression: `subscribe_filtered` invokes the handler when the
    /// predicate returns true.
    #[tokio::test]
    async fn test_subscribe_filtered_delivers_matching() {
        let bus = EventBus::new(16);
        let received: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(CollectingHandler { received: received.clone() });

        // Always-true predicate — every event should be delivered.
        let join = subscribe_filtered(&bus, handler, |_| true);

        bus.publish(sample_event());
        bus.publish(ScanEvent::ScanCompleted {
            scan_id: "scan-1".to_string(),
            total_findings: 0,
            duration_ms: 1,
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(bus);
        join.await.expect("join");

        assert_eq!(received.lock().expect("lock").len(), 2);
    }

    /// Regression: `subscribe_filtered` drops events the predicate rejects.
    #[tokio::test]
    async fn test_subscribe_filtered_drops_non_matching() {
        let bus = EventBus::new(16);
        let received: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(CollectingHandler { received: received.clone() });

        // Only ScanCompleted — ScanStarted should be dropped.
        let join =
            subscribe_filtered(&bus, handler, |e| matches!(e, ScanEvent::ScanCompleted { .. }));

        bus.publish(sample_event()); // ScanStarted — dropped
        bus.publish(ScanEvent::ScanCompleted {
            scan_id: "scan-1".to_string(),
            total_findings: 0,
            duration_ms: 1,
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(bus);
        join.await.expect("join");

        let got = received.lock().expect("lock");
        assert_eq!(got.len(), 1);
        assert!(matches!(got[0], ScanEvent::ScanCompleted { .. }));
    }

    /// Two filtered handlers with disjoint predicates each only see their
    /// own matches — no crosstalk between filters.
    #[tokio::test]
    async fn test_subscribe_filtered_multi_predicate_isolation() {
        let bus = EventBus::new(16);

        let started: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let completed: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let h_started = Arc::new(CollectingHandler { received: started.clone() });
        let h_completed = Arc::new(CollectingHandler { received: completed.clone() });

        let j1 =
            subscribe_filtered(&bus, h_started, |e| matches!(e, ScanEvent::ScanStarted { .. }));
        let j2 =
            subscribe_filtered(&bus, h_completed, |e| matches!(e, ScanEvent::ScanCompleted { .. }));

        bus.publish(sample_event()); // ScanStarted
        bus.publish(ScanEvent::ScanCompleted {
            scan_id: "scan-1".to_string(),
            total_findings: 0,
            duration_ms: 1,
        });
        bus.publish(sample_event()); // ScanStarted again

        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(bus);
        j1.await.expect("j1");
        j2.await.expect("j2");

        assert_eq!(started.lock().expect("lock").len(), 2);
        assert_eq!(completed.lock().expect("lock").len(), 1);
    }

    /// `subscribe_handler` and `subscribe_filtered` on the same bus coexist:
    /// the unfiltered handler sees every event, the filtered one only its
    /// matches.
    #[tokio::test]
    async fn test_subscribe_filtered_coexists_with_unfiltered() {
        let bus = EventBus::new(16);

        let all: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let completed_only: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let h_all = Arc::new(CollectingHandler { received: all.clone() });
        let h_completed = Arc::new(CollectingHandler { received: completed_only.clone() });

        let j1 = subscribe_handler(&bus, h_all);
        let j2 =
            subscribe_filtered(&bus, h_completed, |e| matches!(e, ScanEvent::ScanCompleted { .. }));

        bus.publish(sample_event());
        bus.publish(ScanEvent::ScanCompleted {
            scan_id: "scan-1".to_string(),
            total_findings: 0,
            duration_ms: 1,
        });
        bus.publish(ScanEvent::ModuleSkipped {
            scan_id: "scan-1".to_string(),
            module_id: "ssl".to_string(),
            reason: "missing tool".to_string(),
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(bus);
        j1.await.expect("j1");
        j2.await.expect("j2");

        assert_eq!(all.lock().expect("lock").len(), 3);
        assert_eq!(completed_only.lock().expect("lock").len(), 1);
    }

    /// Realistic pattern: filter for `FindingProduced` events where severity
    /// is High or Critical.
    #[tokio::test]
    async fn test_subscribe_filtered_severity_predicate() {
        let bus = EventBus::new(16);
        let received: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(CollectingHandler { received: received.clone() });

        let join = subscribe_filtered(&bus, handler, |e| {
            matches!(
                e,
                ScanEvent::FindingProduced { finding, .. }
                    if matches!(finding.severity, Severity::High | Severity::Critical)
            )
        });

        let low =
            Finding::new("headers", Severity::Low, "cookie hint", "weak", "https://example.com");
        let high = Finding::new(
            "injection",
            Severity::High,
            "SQLi confirmed",
            "error-based",
            "https://example.com/search?q=1",
        );
        let critical = Finding::new(
            "rce",
            Severity::Critical,
            "remote code exec",
            "shell pop",
            "https://example.com/upload",
        );

        bus.publish(ScanEvent::FindingProduced {
            scan_id: "s".to_string(),
            module_id: "headers".to_string(),
            finding: Box::new(low),
        });
        bus.publish(ScanEvent::FindingProduced {
            scan_id: "s".to_string(),
            module_id: "injection".to_string(),
            finding: Box::new(high),
        });
        bus.publish(ScanEvent::FindingProduced {
            scan_id: "s".to_string(),
            module_id: "rce".to_string(),
            finding: Box::new(critical),
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(bus);
        join.await.expect("join");

        // Only the High and Critical findings should have been delivered.
        let got = received.lock().expect("lock");
        assert_eq!(got.len(), 2);
        for event in got.iter() {
            match event {
                ScanEvent::FindingProduced { finding, .. } => {
                    assert!(matches!(finding.severity, Severity::High | Severity::Critical));
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }
    }
}
