//! Webhook notification system for scan lifecycle events.
//!
//! Fires JSON payloads to configured webhook URLs when scans start,
//! complete, or discover findings. Notifications are async and
//! fire-and-forget — failures are logged but never block scanning.

use serde::Serialize;
use tracing::warn;

/// A scan lifecycle event that can trigger webhook notifications.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ScanEvent {
    /// Fired when a scan begins.
    ScanStarted {
        /// Scan UUID.
        scan_id: String,
        /// Target URL being scanned.
        target: String,
        /// Scan profile (quick/standard/thorough).
        profile: String,
        /// Number of modules to run.
        module_count: usize,
    },
    /// Fired when a scan completes.
    ScanCompleted {
        /// Scan UUID.
        scan_id: String,
        /// Target URL that was scanned.
        target: String,
        /// Total findings discovered.
        finding_count: usize,
        /// Duration in seconds.
        duration_seconds: i64,
    },
    /// Fired when a critical or high severity finding is discovered.
    FindingDiscovered {
        /// Scan UUID.
        scan_id: String,
        /// Module that found it.
        module_id: String,
        /// Finding severity.
        severity: String,
        /// Finding title.
        title: String,
        /// Affected target.
        affected_target: String,
    },
}

/// Configuration for a webhook endpoint.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct WebhookConfig {
    /// URL to POST event payloads to.
    pub url: String,
    /// Optional filter: only send these event types.
    /// If empty/None, sends all events.
    #[serde(default)]
    pub events: Vec<String>,
}

impl ScanEvent {
    /// Get the event type name for filtering.
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::ScanStarted { .. } => "scan_started",
            Self::ScanCompleted { .. } => "scan_completed",
            Self::FindingDiscovered { .. } => "finding_discovered",
        }
    }
}

/// Send a scan event to all configured webhooks.
///
/// Spawns async tasks for each webhook — never blocks the caller.
/// Failed deliveries are logged as warnings.
pub fn notify(webhooks: &[WebhookConfig], event: &ScanEvent) {
    for hook in webhooks {
        if !hook.events.is_empty() && !hook.events.iter().any(|e| e == event.event_type()) {
            continue;
        }

        let url = hook.url.clone();
        let payload = match serde_json::to_string(event) {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to serialize webhook event: {e}");
                continue;
            }
        };

        tokio::spawn(async move {
            let client = reqwest::Client::new();
            if let Err(e) = client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(payload)
                .send()
                .await
            {
                warn!("Webhook delivery failed to {url}: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify scan event serialization produces correct JSON.
    #[test]
    fn test_scan_event_serialize() {
        let event = ScanEvent::ScanStarted {
            scan_id: "abc-123".to_string(),
            target: "https://example.com".to_string(),
            profile: "standard".to_string(),
            module_count: 20,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"scan_started\""));
        assert!(json.contains("\"scan_id\":\"abc-123\""));
        assert!(json.contains("\"module_count\":20"));
    }

    /// Verify webhook config defaults.
    #[test]
    fn test_webhook_config_default() {
        let json = r#"{"url": "https://hooks.example.com/scan"}"#;
        let config: WebhookConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.url, "https://hooks.example.com/scan");
        assert!(config.events.is_empty());
    }

    /// Verify event type filter matching.
    #[test]
    fn test_event_filter() {
        let hook = WebhookConfig {
            url: "https://hooks.example.com".to_string(),
            events: vec!["scan_completed".to_string()],
        };

        let started = ScanEvent::ScanStarted {
            scan_id: "x".to_string(),
            target: "t".to_string(),
            profile: "quick".to_string(),
            module_count: 4,
        };

        let completed = ScanEvent::ScanCompleted {
            scan_id: "x".to_string(),
            target: "t".to_string(),
            finding_count: 5,
            duration_seconds: 30,
        };

        // Filter should exclude scan_started
        assert!(!hook.events.is_empty());
        assert!(!hook.events.iter().any(|e| e == started.event_type()));
        assert!(hook.events.iter().any(|e| e == completed.event_type()));
    }
}
