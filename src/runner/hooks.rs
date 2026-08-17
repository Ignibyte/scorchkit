//! Webhook configuration.
//!
//! Delivery is intentionally unavailable until webhook destinations can be
//! authorized through the same engagement policy as every other network
//! effect. Keeping only the serializable configuration shape preserves config
//! compatibility without exposing an unguarded sender.

use std::fmt;

use serde::Serialize;

/// Configuration for a webhook endpoint.
#[derive(Clone, Serialize, serde::Deserialize)]
pub struct WebhookConfig {
    /// URL to POST event payloads to.
    pub url: String,
    /// Optional filter: only send these event types.
    /// If empty/None, sends all events.
    #[serde(default)]
    pub events: Vec<String>,
}

impl fmt::Debug for WebhookConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookConfig")
            .field("url", &"<configured>")
            .field("events", &self.events)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify webhook config defaults.
    #[test]
    fn test_webhook_config_default() {
        let json = r#"{"url": "https://hooks.example.com/scan"}"#;
        let config: WebhookConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.url, "https://hooks.example.com/scan");
        assert!(config.events.is_empty());
    }

    #[test]
    fn webhook_debug_hides_credential_bearing_url() {
        let config = WebhookConfig {
            url: "https://user:webhook-secret@hooks.example/path?token=query-secret".to_string(),
            events: vec!["scan_completed".to_string()],
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("webhook-secret"));
        assert!(!rendered.contains("query-secret"));
        assert!(rendered.contains("<configured>"));
        assert!(rendered.contains("scan_completed"));
    }
}
