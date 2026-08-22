//! Webhook configuration.
//!
//! Secrets remain indirect and runtime-only. Durable queue records refer to a
//! stable destination identity rather than copying the configured URL.

use std::fmt;

use serde::Serialize;
use url::Url;

const DEFAULT_MAX_PENDING: usize = 1_000;
const DEFAULT_MAX_PAYLOAD_BYTES: usize = 256 * 1_024;
const DEFAULT_MAX_ATTEMPTS: u32 = 5;
const DEFAULT_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_BACKOFF_SECONDS: u64 = 5;
const DEFAULT_MAX_BACKOFF_SECONDS: u64 = 300;
const DEFAULT_MAX_REDIRECTS: usize = 3;
const DEFAULT_BATCH_SIZE: usize = 25;
const SUPPORTED_EVENT_KINDS: [&str; 8] = [
    "scan_started",
    "module_started",
    "module_completed",
    "module_skipped",
    "module_error",
    "finding_produced",
    "scan_completed",
    "custom",
];

const fn default_max_pending() -> usize {
    DEFAULT_MAX_PENDING
}

const fn default_max_payload_bytes() -> usize {
    DEFAULT_MAX_PAYLOAD_BYTES
}

const fn default_max_attempts() -> u32 {
    DEFAULT_MAX_ATTEMPTS
}

const fn default_timeout_seconds() -> u64 {
    DEFAULT_TIMEOUT_SECONDS
}

const fn default_backoff_seconds() -> u64 {
    DEFAULT_BACKOFF_SECONDS
}

const fn default_max_backoff_seconds() -> u64 {
    DEFAULT_MAX_BACKOFF_SECONDS
}

const fn default_max_redirects() -> usize {
    DEFAULT_MAX_REDIRECTS
}

const fn default_batch_size() -> usize {
    DEFAULT_BATCH_SIZE
}

/// Configuration for a webhook endpoint.
#[derive(Clone, Serialize, serde::Deserialize)]
pub struct WebhookConfig {
    /// Stable operator-selected destination ID. A deterministic URL digest is
    /// used when this is absent so legacy URL-only configuration remains valid.
    #[serde(default)]
    pub id: Option<String>,
    /// URL to POST event payloads to.
    pub url: String,
    /// Optional filter: only send these event types.
    /// If empty/None, sends all events.
    #[serde(default)]
    pub events: Vec<String>,
    /// Environment variable containing the complete `Authorization` header.
    #[serde(default)]
    pub authorization_env: Option<String>,
    /// Maximum nonterminal records for this destination.
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,
    /// Maximum serialized redacted event payload.
    #[serde(default = "default_max_payload_bytes")]
    pub max_payload_bytes: usize,
    /// Total attempts, including the first request.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// Per-request deadline.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    /// Initial retry delay.
    #[serde(default = "default_backoff_seconds")]
    pub backoff_seconds: u64,
    /// Maximum retry delay after exponential growth.
    #[serde(default = "default_max_backoff_seconds")]
    pub max_backoff_seconds: u64,
    /// Maximum authorized redirects for one attempt.
    #[serde(default = "default_max_redirects")]
    pub max_redirects: usize,
    /// Maximum records claimed by one worker pass.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

impl WebhookConfig {
    /// Return the explicit ID or a deterministic non-secret digest identity.
    #[must_use]
    pub fn destination_id(&self) -> String {
        self.id.clone().unwrap_or_else(|| {
            let digest = scorchkit_core::sha256_hex(self.url.as_bytes());
            format!("webhook-{}", &digest[..16])
        })
    }

    /// Validate all destination and worker bounds before an effect or store write.
    ///
    /// # Errors
    ///
    /// Returns a credential-safe message for unsupported or unbounded configuration.
    pub fn validate(&self) -> Result<(), String> {
        let destination_id = self.destination_id();
        if destination_id.is_empty()
            || destination_id.len() > 64
            || !destination_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err("webhook id must be 1-64 ASCII letters, digits, '-', '_', or '.'".into());
        }
        let parsed = Url::parse(&self.url)
            .map_err(|_| format!("webhook destination '{destination_id}' has an invalid URL"))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(format!(
                "webhook destination '{destination_id}' must use a host-bearing HTTP(S) URL"
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(format!(
                "webhook destination '{destination_id}' must not embed URL credentials"
            ));
        }
        if parsed.fragment().is_some() {
            return Err(format!(
                "webhook destination '{destination_id}' must not contain a URL fragment"
            ));
        }
        if let Some(environment) = &self.authorization_env {
            if environment.is_empty()
                || environment.len() > 128
                || !environment.bytes().enumerate().all(|(index, byte)| {
                    byte == b'_'
                        || byte.is_ascii_uppercase()
                        || (index > 0 && byte.is_ascii_digit())
                })
            {
                return Err(format!(
                    "webhook destination '{destination_id}' has an invalid authorization environment variable"
                ));
            }
        }
        if self.events.len() > 64
            || self.events.iter().any(|event| {
                event.is_empty()
                    || event.len() > 128
                    || !event.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
                    || !SUPPORTED_EVENT_KINDS.contains(&event.as_str())
            })
        {
            return Err(format!(
                "webhook destination '{destination_id}' has an invalid event filter"
            ));
        }
        if !(1..=100_000).contains(&self.max_pending) {
            return Err(format!(
                "webhook destination '{destination_id}' max_pending must be 1-100000"
            ));
        }
        if !(1..=1_048_576).contains(&self.max_payload_bytes) {
            return Err(format!(
                "webhook destination '{destination_id}' max_payload_bytes must be 1-1048576"
            ));
        }
        if !(1..=20).contains(&self.max_attempts) {
            return Err(format!(
                "webhook destination '{destination_id}' max_attempts must be 1-20"
            ));
        }
        if !(1..=300).contains(&self.timeout_seconds) {
            return Err(format!(
                "webhook destination '{destination_id}' timeout_seconds must be 1-300"
            ));
        }
        if !(1..=3_600).contains(&self.backoff_seconds)
            || !(self.backoff_seconds..=86_400).contains(&self.max_backoff_seconds)
        {
            return Err(format!(
                "webhook destination '{destination_id}' retry backoff bounds are invalid"
            ));
        }
        if self.max_redirects > 10 {
            return Err(format!(
                "webhook destination '{destination_id}' max_redirects must be 0-10"
            ));
        }
        if self.authorization_env.is_some() && self.max_redirects != 0 {
            return Err(format!(
                "webhook destination '{destination_id}' with authorization must set max_redirects to 0"
            ));
        }
        if !(1..=100).contains(&self.batch_size) {
            return Err(format!("webhook destination '{destination_id}' batch_size must be 1-100"));
        }
        Ok(())
    }

    /// Return whether this destination accepts an exact event kind.
    #[must_use]
    pub fn accepts(&self, event_kind: &str) -> bool {
        self.events.is_empty() || self.events.iter().any(|configured| configured == event_kind)
    }
}

impl fmt::Debug for WebhookConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookConfig")
            .field("id", &self.id)
            .field("url", &"<configured>")
            .field("events", &self.events)
            .field("authorization_env", &self.authorization_env)
            .field("max_pending", &self.max_pending)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .field("max_attempts", &self.max_attempts)
            .field("timeout_seconds", &self.timeout_seconds)
            .field("backoff_seconds", &self.backoff_seconds)
            .field("max_backoff_seconds", &self.max_backoff_seconds)
            .field("max_redirects", &self.max_redirects)
            .field("batch_size", &self.batch_size)
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
        assert_eq!(config.max_pending, DEFAULT_MAX_PENDING);
        assert_eq!(config.max_payload_bytes, 262_144);
        assert_eq!(config.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert_eq!(config.timeout_seconds, DEFAULT_TIMEOUT_SECONDS);
        assert_eq!(config.backoff_seconds, DEFAULT_BACKOFF_SECONDS);
        assert_eq!(config.max_backoff_seconds, DEFAULT_MAX_BACKOFF_SECONDS);
        assert_eq!(config.max_redirects, DEFAULT_MAX_REDIRECTS);
        assert_eq!(config.batch_size, DEFAULT_BATCH_SIZE);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn webhook_debug_hides_credential_bearing_url() {
        let config = WebhookConfig {
            id: Some("primary".to_string()),
            url: "https://user:webhook-secret@hooks.example/path?token=query-secret".to_string(),
            events: vec!["scan_completed".to_string()],
            authorization_env: Some("SCORCHKIT_WEBHOOK_AUTH".to_string()),
            max_pending: DEFAULT_MAX_PENDING,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            backoff_seconds: DEFAULT_BACKOFF_SECONDS,
            max_backoff_seconds: DEFAULT_MAX_BACKOFF_SECONDS,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            batch_size: DEFAULT_BATCH_SIZE,
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("webhook-secret"));
        assert!(!rendered.contains("query-secret"));
        assert!(rendered.contains("<configured>"));
        assert!(rendered.contains("scan_completed"));
    }

    #[test]
    fn legacy_destination_identity_is_deterministic_and_does_not_expose_url() {
        let config: WebhookConfig =
            serde_json::from_str(r#"{"url":"https://hooks.example.test/secret-path"}"#).unwrap();
        assert_eq!(config.destination_id(), config.destination_id());
        assert!(config.destination_id().starts_with("webhook-"));
        assert!(!config.destination_id().contains("secret-path"));
    }

    #[test]
    fn validation_rejects_credentials_and_unbounded_settings() {
        let mut config: WebhookConfig = serde_json::from_str(
            r#"{"id":"primary","url":"https://user:secret@hooks.example.test/path"}"#,
        )
        .unwrap();
        assert!(config.validate().unwrap_err().contains("must not embed"));
        config.url = "https://hooks.example.test/path".to_string();
        config.max_attempts = 0;
        assert!(config.validate().unwrap_err().contains("max_attempts"));
        config.max_attempts = DEFAULT_MAX_ATTEMPTS;
        config.authorization_env = Some("SCORCHKIT_WEBHOOK_AUTH".to_string());
        assert!(config.validate().unwrap_err().contains("max_redirects to 0"));
    }

    fn valid_config() -> WebhookConfig {
        serde_json::from_str(r#"{"id":"primary","url":"https://hooks.example.test/path"}"#).unwrap()
    }

    #[test]
    fn validation_pins_identity_url_and_authorization_boundaries() {
        let mut config = valid_config();
        config.id = Some("x".repeat(64));
        assert!(config.validate().is_ok());
        for invalid in [String::new(), "x".repeat(65), "not/valid".to_string()] {
            config.id = Some(invalid);
            assert!(config.validate().is_err());
        }

        config = valid_config();
        config.url = "ftp://hooks.example.test/path".to_string();
        assert!(config.validate().is_err());
        config.url = "https://user@hooks.example.test/path".to_string();
        assert!(config.validate().is_err());
        config.url = "https://:value@hooks.example.test/path".to_string();
        assert!(config.validate().is_err());
        config.url = "https://hooks.example.test/path#fragment".to_string();
        assert!(config.validate().is_err());

        config = valid_config();
        config.max_redirects = 0;
        for invalid in
            [String::new(), "A".repeat(129), "lowercase".to_string(), "1INVALID".to_string()]
        {
            config.authorization_env = Some(invalid);
            assert!(config.validate().is_err());
        }
        for valid in ["A1".to_string(), "A".repeat(128)] {
            config.authorization_env = Some(valid);
            assert!(config.validate().is_ok());
        }
    }

    #[test]
    fn validation_pins_event_and_worker_boundaries() {
        let mut config = valid_config();
        config.events = vec!["scan_completed".to_string(); 64];
        assert!(config.validate().is_ok());
        config.events.push("scan_started".to_string());
        assert!(config.validate().is_err());
        for invalid in
            [String::new(), "x".repeat(129), "scan/completed".to_string(), "unknown".to_string()]
        {
            config.events = vec![invalid];
            assert!(config.validate().is_err());
        }
        config.events = SUPPORTED_EVENT_KINDS.iter().map(ToString::to_string).collect();
        assert!(config.validate().is_ok());

        config = valid_config();
        for invalid in [0, 100_001] {
            config.max_pending = invalid;
            assert!(config.validate().is_err());
        }
        for valid in [1, 100_000] {
            config.max_pending = valid;
            assert!(config.validate().is_ok());
        }
        config = valid_config();
        for invalid in [0, 1_048_577] {
            config.max_payload_bytes = invalid;
            assert!(config.validate().is_err());
        }
        for valid in [1, 1_048_576] {
            config.max_payload_bytes = valid;
            assert!(config.validate().is_ok());
        }
        config = valid_config();
        for invalid in [0, 21] {
            config.max_attempts = invalid;
            assert!(config.validate().is_err());
        }
        for valid in [1, 20] {
            config.max_attempts = valid;
            assert!(config.validate().is_ok());
        }
        config = valid_config();
        for invalid in [0, 301] {
            config.timeout_seconds = invalid;
            assert!(config.validate().is_err());
        }
        for valid in [1, 300] {
            config.timeout_seconds = valid;
            assert!(config.validate().is_ok());
        }

        config = valid_config();
        config.backoff_seconds = 0;
        assert!(config.validate().is_err());
        config = valid_config();
        config.backoff_seconds = 3_601;
        assert!(config.validate().is_err());
        config = valid_config();
        config.backoff_seconds = 10;
        config.max_backoff_seconds = 9;
        assert!(config.validate().is_err());
        config.max_backoff_seconds = 86_401;
        assert!(config.validate().is_err());
        config.backoff_seconds = 3_600;
        config.max_backoff_seconds = 86_400;
        assert!(config.validate().is_ok());

        config = valid_config();
        config.max_redirects = 10;
        assert!(config.validate().is_ok());
        config.max_redirects = 11;
        assert!(config.validate().is_err());
        config = valid_config();
        for invalid in [0, 101] {
            config.batch_size = invalid;
            assert!(config.validate().is_err());
        }
        for valid in [1, 100] {
            config.batch_size = valid;
            assert!(config.validate().is_ok());
        }
    }
}
