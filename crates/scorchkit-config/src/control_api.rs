//! Local control API transport configuration.
//!
//! Credential values remain environment-indirect. This module owns only serializable listener,
//! principal-binding, and resource bounds; the root transport resolves credentials at startup.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum accepted control request body.
pub const MAX_CONTROL_API_BODY_BYTES: usize = 1_048_576;
/// Maximum serialized control response.
pub const MAX_CONTROL_API_RESPONSE_BYTES: usize = 16 * 1_048_576;
/// Maximum admitted requests.
pub const MAX_CONTROL_API_CONCURRENT_REQUESTS: usize = 64;
/// Maximum retained replay events.
pub const MAX_CONTROL_API_JOURNAL_EVENTS: usize = 65_536;
/// Maximum one event payload.
pub const MAX_CONTROL_API_EVENT_BYTES: usize = 1_048_576;
/// Maximum live event subscribers.
pub const MAX_CONTROL_API_SUBSCRIBERS: usize = 128;
/// Maximum configurable page size, equal to the v1 protocol ceiling.
pub const MAX_CONTROL_API_PAGE_SIZE: u16 = 200;

const DEFAULT_BODY_BYTES: usize = 262_144;
const DEFAULT_RESPONSE_BYTES: usize = 4 * 1_048_576;
const DEFAULT_CONCURRENT_REQUESTS: usize = 16;
const DEFAULT_JOURNAL_EVENTS: usize = 4_096;
const DEFAULT_EVENT_BYTES: usize = 262_144;
const DEFAULT_SUBSCRIBERS: usize = 32;
const DEFAULT_PAGE_SIZE: u16 = 50;
const MIN_BODY_BYTES: usize = 256;
const MIN_RESPONSE_BYTES: usize = 1_024;
const MIN_EVENT_BYTES: usize = 512;

const fn default_body_bytes() -> usize {
    DEFAULT_BODY_BYTES
}

const fn default_response_bytes() -> usize {
    DEFAULT_RESPONSE_BYTES
}

const fn default_concurrent_requests() -> usize {
    DEFAULT_CONCURRENT_REQUESTS
}

const fn default_journal_events() -> usize {
    DEFAULT_JOURNAL_EVENTS
}

const fn default_event_bytes() -> usize {
    DEFAULT_EVENT_BYTES
}

const fn default_subscribers() -> usize {
    DEFAULT_SUBSCRIBERS
}

const fn default_page_size() -> u16 {
    DEFAULT_PAGE_SIZE
}

/// Explicit bearer-authenticated loopback control host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlApiConfig {
    /// Explicit loopback listener.
    pub bind: Option<SocketAddr>,
    /// Stable transport-owned subject.
    pub subject: Option<String>,
    /// Exact configured engagement to which this principal is bound.
    pub engagement_id: Option<Uuid>,
    /// Environment variable containing the bearer credential.
    pub token_env: Option<String>,
    /// Maximum request body before JSON parsing.
    #[serde(default = "default_body_bytes")]
    pub max_body_bytes: usize,
    /// Maximum serialized response or replay body.
    #[serde(default = "default_response_bytes")]
    pub max_response_bytes: usize,
    /// Maximum admitted requests.
    #[serde(default = "default_concurrent_requests")]
    pub max_concurrent_requests: usize,
    /// Number of newest ordered events retained for replay.
    #[serde(default = "default_journal_events")]
    pub max_journal_events: usize,
    /// Maximum serialized event size.
    #[serde(default = "default_event_bytes")]
    pub max_event_bytes: usize,
    /// Maximum simultaneous event streams.
    #[serde(default = "default_subscribers")]
    pub max_subscribers: usize,
    /// Default and maximum host-selected page size.
    #[serde(default = "default_page_size")]
    pub default_page_size: u16,
}

impl Default for ControlApiConfig {
    fn default() -> Self {
        Self {
            bind: None,
            subject: None,
            engagement_id: None,
            token_env: None,
            max_body_bytes: DEFAULT_BODY_BYTES,
            max_response_bytes: DEFAULT_RESPONSE_BYTES,
            max_concurrent_requests: DEFAULT_CONCURRENT_REQUESTS,
            max_journal_events: DEFAULT_JOURNAL_EVENTS,
            max_event_bytes: DEFAULT_EVENT_BYTES,
            max_subscribers: DEFAULT_SUBSCRIBERS,
            default_page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

impl ControlApiConfig {
    /// Validate the complete listener shape before credential lookup or binding.
    ///
    /// # Errors
    ///
    /// Returns a credential-safe error for an absent, exposed, malformed, or unbounded setting.
    pub fn validate(&self) -> Result<(), String> {
        let bind = self
            .bind
            .ok_or_else(|| "control API requires an explicit loopback bind address".to_string())?;
        if !bind.ip().is_loopback() {
            return Err(
                "control API must bind to loopback; remote control requires the authenticated MCP profile until team isolation exists"
                    .to_string(),
            );
        }
        validate_identifier(self.subject.as_deref(), "subject", false)?;
        if self.engagement_id.is_none() {
            return Err("control API requires an exact engagement_id binding".to_string());
        }
        validate_identifier(self.token_env.as_deref(), "token_env", true)?;
        validate_bound_range(
            self.max_body_bytes,
            MIN_BODY_BYTES,
            MAX_CONTROL_API_BODY_BYTES,
            "max_body_bytes",
        )?;
        validate_bound_range(
            self.max_response_bytes,
            MIN_RESPONSE_BYTES,
            MAX_CONTROL_API_RESPONSE_BYTES,
            "max_response_bytes",
        )?;
        validate_bound(
            self.max_concurrent_requests,
            MAX_CONTROL_API_CONCURRENT_REQUESTS,
            "max_concurrent_requests",
        )?;
        validate_bound(
            self.max_journal_events,
            MAX_CONTROL_API_JOURNAL_EVENTS,
            "max_journal_events",
        )?;
        validate_bound_range(
            self.max_event_bytes,
            MIN_EVENT_BYTES,
            MAX_CONTROL_API_EVENT_BYTES,
            "max_event_bytes",
        )?;
        if self.max_event_bytes > self.max_response_bytes {
            return Err("control API max_event_bytes cannot exceed max_response_bytes".to_string());
        }
        validate_bound(self.max_subscribers, MAX_CONTROL_API_SUBSCRIBERS, "max_subscribers")?;
        if !(1..=MAX_CONTROL_API_PAGE_SIZE).contains(&self.default_page_size) {
            return Err("control API default_page_size must be 1-200".to_string());
        }
        Ok(())
    }
}

fn validate_identifier(
    value: Option<&str>,
    label: &str,
    environment_name: bool,
) -> Result<(), String> {
    let value = value.ok_or_else(|| format!("control API requires {label}"))?;
    let common_invalid = value.is_empty()
        || value.len() > 256
        || !value.is_ascii()
        || value.trim() != value
        || value.bytes().any(|byte| byte.is_ascii_control());
    let environment_invalid = environment_name
        && (!value.bytes().next().is_some_and(|byte| byte == b'_' || byte.is_ascii_uppercase())
            || value
                .bytes()
                .any(|byte| byte != b'_' && !byte.is_ascii_uppercase() && !byte.is_ascii_digit()));
    if common_invalid || environment_invalid {
        return Err(format!("control API {label} is malformed"));
    }
    Ok(())
}

fn validate_bound(value: usize, maximum: usize, label: &str) -> Result<(), String> {
    if !(1..=maximum).contains(&value) {
        return Err(format!("control API {label} must be 1-{maximum}"));
    }
    Ok(())
}

fn validate_bound_range(
    value: usize,
    minimum: usize,
    maximum: usize,
    label: &str,
) -> Result<(), String> {
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("control API {label} must be {minimum}-{maximum}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> ControlApiConfig {
        ControlApiConfig {
            bind: Some("127.0.0.1:7444".parse().expect("socket")),
            subject: Some("local-operator".to_string()),
            engagement_id: Some(Uuid::new_v4()),
            token_env: Some("SCORCHKIT_CONTROL_TOKEN".to_string()),
            ..ControlApiConfig::default()
        }
    }

    #[test]
    fn default_is_inert_and_complete_explicit_shape_is_valid() {
        assert!(ControlApiConfig::default().validate().is_err());
        valid().validate().expect("valid control API");
    }

    #[test]
    fn exposed_listener_and_each_missing_binding_field_fail() {
        let mut exposed = valid();
        exposed.bind = Some("0.0.0.0:7444".parse().expect("socket"));
        assert!(exposed.validate().expect_err("exposed").contains("loopback"));

        let mut missing_subject = valid();
        missing_subject.subject = None;
        assert!(missing_subject.validate().is_err());
        let mut missing_engagement = valid();
        missing_engagement.engagement_id = None;
        assert!(missing_engagement.validate().is_err());
        let mut missing_token = valid();
        missing_token.token_env = None;
        assert!(missing_token.validate().is_err());
    }

    #[test]
    fn every_resource_boundary_and_compound_relation_is_checked() {
        let cases: &[fn(&mut ControlApiConfig)] = &[
            |config| config.max_body_bytes = 0,
            |config| config.max_response_bytes = MAX_CONTROL_API_RESPONSE_BYTES + 1,
            |config| config.max_concurrent_requests = 0,
            |config| config.max_journal_events = MAX_CONTROL_API_JOURNAL_EVENTS + 1,
            |config| config.max_event_bytes = 0,
            |config| config.max_subscribers = MAX_CONTROL_API_SUBSCRIBERS + 1,
            |config| config.default_page_size = 0,
            |config| config.default_page_size = MAX_CONTROL_API_PAGE_SIZE + 1,
            |config| {
                config.max_response_bytes = MIN_RESPONSE_BYTES;
                config.max_event_bytes = MIN_RESPONSE_BYTES + 1;
            },
        ];
        for mutate in cases {
            let mut config = valid();
            mutate(&mut config);
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn token_environment_is_portable_and_secret_indirect() {
        for name in ["lowercase", "1PREFIX", "HAS-DASH", "HAS SPACE", ""] {
            let mut config = valid();
            config.token_env = Some(name.to_string());
            assert!(config.validate().is_err(), "accepted {name:?}");
        }
        let debug = format!("{:?}", valid());
        assert!(debug.contains("SCORCHKIT_CONTROL_TOKEN"));
        assert!(!debug.contains("secret-value"));
    }
}
