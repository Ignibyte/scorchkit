//! Remote MCP transport configuration.
//!
//! Authentication values remain environment-indirect. This module owns only
//! serializable policy and bounds; the root transport adapter resolves and
//! hashes credentials at startup.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

/// Maximum configured principals for one remote host.
pub const MAX_REMOTE_MCP_BINDINGS: usize = 32;
/// Maximum accepted MCP request body.
pub const MAX_REMOTE_MCP_BODY_BYTES: usize = 1_048_576;
/// Maximum concurrent requests admitted to one remote host.
pub const MAX_REMOTE_MCP_CONCURRENT_REQUESTS: usize = 64;
/// Maximum live MCP sessions owned by one principal.
pub const MAX_REMOTE_MCP_SESSIONS_PER_PRINCIPAL: usize = 64;

const MAX_REMOTE_MCP_AUTHORITIES: usize = 32;
const DEFAULT_BODY_BYTES: usize = 262_144;
const DEFAULT_CONCURRENT_REQUESTS: usize = 16;
const DEFAULT_SESSIONS_PER_PRINCIPAL: usize = 8;

const fn default_body_bytes() -> usize {
    DEFAULT_BODY_BYTES
}

const fn default_concurrent_requests() -> usize {
    DEFAULT_CONCURRENT_REQUESTS
}

const fn default_sessions_per_principal() -> usize {
    DEFAULT_SESSIONS_PER_PRINCIPAL
}

/// MCP host configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct McpConfig {
    /// Optional authenticated remote transport. Local stdio is independent.
    pub remote: Option<RemoteMcpConfig>,
}

/// Supported TLS ownership for the remote backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteMcpTlsTermination {
    /// A same-host reverse proxy terminates TLS and connects to this loopback backend.
    TrustedReverseProxy,
}

/// One authenticated transport principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteMcpPrincipalBinding {
    /// Stable transport-owned subject returned in MCP result envelopes.
    pub subject: String,
    /// Exact configured engagement that this principal may use.
    pub engagement_id: Uuid,
    /// Environment variable containing the bearer token value.
    pub token_env: String,
}

/// Authenticated Streamable HTTP MCP transport configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RemoteMcpConfig {
    /// Explicit loopback socket used by the trusted same-host proxy.
    pub bind: Option<SocketAddr>,
    /// Explicit TLS termination ownership.
    pub tls_termination: Option<RemoteMcpTlsTermination>,
    /// Exact public authorities accepted in the HTTP `Host` header.
    pub allowed_hosts: Vec<String>,
    /// Exact HTTPS browser origins accepted when `Origin` is present.
    pub allowed_origins: Vec<String>,
    /// Maximum request body before MCP protocol parsing.
    #[serde(default = "default_body_bytes")]
    pub max_body_bytes: usize,
    /// Maximum admitted requests across all principals.
    #[serde(default = "default_concurrent_requests")]
    pub max_concurrent_requests: usize,
    /// Maximum live stateful sessions for each principal.
    #[serde(default = "default_sessions_per_principal")]
    pub max_sessions_per_principal: usize,
    /// Credential-to-principal bindings.
    pub bindings: Vec<RemoteMcpPrincipalBinding>,
}

impl Default for RemoteMcpConfig {
    fn default() -> Self {
        Self {
            bind: None,
            tls_termination: None,
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
            max_body_bytes: DEFAULT_BODY_BYTES,
            max_concurrent_requests: DEFAULT_CONCURRENT_REQUESTS,
            max_sessions_per_principal: DEFAULT_SESSIONS_PER_PRINCIPAL,
            bindings: Vec::new(),
        }
    }
}

impl RemoteMcpConfig {
    /// Validate the provider-neutral transport shape before credential lookup or listening.
    ///
    /// # Errors
    ///
    /// Returns a credential-safe error when any transport, authority, resource, or binding bound
    /// is absent or invalid.
    pub fn validate(&self) -> Result<(), String> {
        let bind = self
            .bind
            .ok_or_else(|| "remote MCP requires an explicit backend bind address".to_string())?;
        if !bind.ip().is_loopback() {
            return Err("remote MCP trusted-proxy backend must bind to loopback".to_string());
        }
        if self.tls_termination != Some(RemoteMcpTlsTermination::TrustedReverseProxy) {
            return Err("remote MCP requires tls_termination = 'trusted_reverse_proxy'".to_string());
        }
        validate_bounds(
            self.max_body_bytes,
            self.max_concurrent_requests,
            self.max_sessions_per_principal,
        )?;
        validate_hosts(&self.allowed_hosts)?;
        validate_origins(&self.allowed_origins)?;
        validate_bindings(&self.bindings)
    }
}

fn validate_bounds(body: usize, concurrent: usize, sessions: usize) -> Result<(), String> {
    if !(1..=MAX_REMOTE_MCP_BODY_BYTES).contains(&body) {
        return Err("remote MCP max_body_bytes must be 1-1048576".to_string());
    }
    if !(1..=MAX_REMOTE_MCP_CONCURRENT_REQUESTS).contains(&concurrent) {
        return Err("remote MCP max_concurrent_requests must be 1-64".to_string());
    }
    if !(1..=MAX_REMOTE_MCP_SESSIONS_PER_PRINCIPAL).contains(&sessions) {
        return Err("remote MCP max_sessions_per_principal must be 1-64".to_string());
    }
    Ok(())
}

fn validate_hosts(hosts: &[String]) -> Result<(), String> {
    if hosts.is_empty() || hosts.len() > MAX_REMOTE_MCP_AUTHORITIES {
        return Err("remote MCP allowed_hosts must contain 1-32 authorities".to_string());
    }
    let mut unique = BTreeSet::new();
    for host in hosts {
        let parsed = Url::parse(&format!("https://{host}/"));
        if host.is_empty()
            || host.len() > 255
            || !host.is_ascii()
            || host.trim() != host
            || host.ends_with(':')
            || host.contains("//")
            || host.bytes().any(|byte| {
                byte.is_ascii_whitespace()
                    || matches!(byte, b'/' | b'\\' | b'%' | b'@' | b'#' | b'?')
            })
            || !parsed.as_ref().is_ok_and(|parsed| parsed.host_str().is_some())
            || !unique.insert(host.to_ascii_lowercase())
        {
            return Err(
                "remote MCP allowed_hosts must be unique bounded ASCII authorities".to_string()
            );
        }
    }
    Ok(())
}

fn validate_origins(origins: &[String]) -> Result<(), String> {
    if origins.is_empty() || origins.len() > MAX_REMOTE_MCP_AUTHORITIES {
        return Err("remote MCP allowed_origins must contain 1-32 HTTPS origins".to_string());
    }
    let mut unique = BTreeSet::new();
    for origin in origins {
        let parsed = Url::parse(origin)
            .map_err(|_| "remote MCP allowed_origins contains an invalid origin".to_string())?;
        let canonical = parsed.origin().ascii_serialization();
        let canonical_with_slash = format!("{canonical}/");
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || (origin != &canonical && origin != &canonical_with_slash)
            || !unique.insert(canonical)
        {
            return Err(
                "remote MCP allowed_origins must be unique host-bearing HTTPS origins".to_string()
            );
        }
    }
    Ok(())
}

fn validate_bindings(bindings: &[RemoteMcpPrincipalBinding]) -> Result<(), String> {
    if bindings.is_empty() || bindings.len() > MAX_REMOTE_MCP_BINDINGS {
        return Err("remote MCP bindings must contain 1-32 principals".to_string());
    }
    let mut subjects = BTreeSet::new();
    let mut environments = BTreeSet::new();
    for binding in bindings {
        if !valid_subject(&binding.subject) || !subjects.insert(binding.subject.clone()) {
            return Err(
                "remote MCP binding subjects must be unique bounded identifiers".to_string()
            );
        }
        if !valid_token_environment(&binding.token_env)
            || !environments.insert(binding.token_env.clone())
        {
            return Err(
                "remote MCP token environment references must be unique SCORCHKIT_MCP_* names"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn valid_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= 128
        && subject.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@' | b'/')
        })
}

fn valid_token_environment(environment: &str) -> bool {
    environment.len() > "SCORCHKIT_MCP_".len()
        && environment.len() <= 128
        && environment.starts_with("SCORCHKIT_MCP_")
        && environment
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(subject: &str, environment: &str) -> RemoteMcpPrincipalBinding {
        RemoteMcpPrincipalBinding {
            subject: subject.to_string(),
            engagement_id: Uuid::from_u128(1),
            token_env: environment.to_string(),
        }
    }

    fn valid_config() -> RemoteMcpConfig {
        RemoteMcpConfig {
            bind: Some("127.0.0.1:7443".parse().expect("socket")),
            tls_termination: Some(RemoteMcpTlsTermination::TrustedReverseProxy),
            allowed_hosts: vec!["security.example.test".to_string()],
            allowed_origins: vec!["https://console.example.test".to_string()],
            bindings: vec![binding("operator@example.test", "SCORCHKIT_MCP_OPERATOR_TOKEN")],
            ..RemoteMcpConfig::default()
        }
    }

    #[test]
    fn remote_defaults_are_bounded_but_incomplete() {
        let config = RemoteMcpConfig::default();
        assert_eq!(config.max_body_bytes, DEFAULT_BODY_BYTES);
        assert_eq!(config.max_concurrent_requests, DEFAULT_CONCURRENT_REQUESTS);
        assert_eq!(config.max_sessions_per_principal, DEFAULT_SESSIONS_PER_PRINCIPAL);
        assert!(config.validate().is_err());
        assert!(McpConfig::default().remote.is_none());
    }

    #[test]
    fn valid_remote_configuration_round_trips() {
        let config = McpConfig { remote: Some(valid_config()) };
        let encoded = toml::to_string(&config).expect("serialize remote MCP");
        assert!(!encoded.contains("bearer"));
        let decoded: McpConfig = toml::from_str(&encoded).expect("deserialize remote MCP");
        assert_eq!(decoded, config);
        decoded.remote.expect("remote config").validate().expect("valid config");
    }

    #[test]
    fn omitted_remote_resource_bounds_use_the_documented_defaults() {
        let decoded: RemoteMcpConfig = toml::from_str(
            r#"
bind = "127.0.0.1:7443"
tls_termination = "trusted_reverse_proxy"
allowed_hosts = ["security.example.test"]
allowed_origins = ["https://console.example.test"]

[[bindings]]
subject = "operator@example.test"
engagement_id = "00000000-0000-0000-0000-000000000001"
token_env = "SCORCHKIT_MCP_OPERATOR_TOKEN"
"#,
        )
        .expect("deserialize omitted remote bounds");

        assert_eq!(decoded.max_body_bytes, DEFAULT_BODY_BYTES);
        assert_eq!(decoded.max_concurrent_requests, DEFAULT_CONCURRENT_REQUESTS);
        assert_eq!(decoded.max_sessions_per_principal, DEFAULT_SESSIONS_PER_PRINCIPAL);
        decoded.validate().expect("defaulted remote config");
    }

    #[test]
    fn listener_and_tls_policy_fail_independently() {
        let mut config = valid_config();
        config.bind = None;
        assert!(config.validate().unwrap_err().contains("bind address"));

        let mut config = valid_config();
        config.bind = Some("0.0.0.0:7443".parse().expect("socket"));
        assert!(config.validate().unwrap_err().contains("loopback"));

        let mut config = valid_config();
        config.bind = Some("192.0.2.1:7443".parse().expect("socket"));
        assert!(config.validate().unwrap_err().contains("loopback"));

        let mut config = valid_config();
        config.tls_termination = None;
        assert!(config.validate().unwrap_err().contains("tls_termination"));
    }

    #[test]
    fn every_resource_bound_has_exact_edges() {
        for (body, concurrent, sessions, valid) in [
            (0, 1, 1, false),
            (1, 1, 1, true),
            (MAX_REMOTE_MCP_BODY_BYTES, 1, 1, true),
            (MAX_REMOTE_MCP_BODY_BYTES + 1, 1, 1, false),
            (1, 0, 1, false),
            (1, MAX_REMOTE_MCP_CONCURRENT_REQUESTS, 1, true),
            (1, MAX_REMOTE_MCP_CONCURRENT_REQUESTS + 1, 1, false),
            (1, 1, 0, false),
            (1, 1, MAX_REMOTE_MCP_SESSIONS_PER_PRINCIPAL, true),
            (1, 1, MAX_REMOTE_MCP_SESSIONS_PER_PRINCIPAL + 1, false),
        ] {
            assert_eq!(validate_bounds(body, concurrent, sessions).is_ok(), valid);
        }
    }

    #[test]
    fn host_allowlist_rejects_each_invalid_shape() {
        assert!(validate_hosts(&[]).is_err());
        let unique = (0..=MAX_REMOTE_MCP_AUTHORITIES)
            .map(|index| format!("host-{index}.example.test"))
            .collect::<Vec<_>>();
        assert!(validate_hosts(&unique[..MAX_REMOTE_MCP_AUTHORITIES]).is_ok());
        assert!(validate_hosts(&unique).is_err());
        for invalid in [
            "",
            " host",
            "host ",
            "https://host",
            "user@host",
            "host/path",
            "host?query",
            "host#fragment",
            "host:",
            "host:not-a-port",
            "host:65536",
            "host\\other",
            "host%2eother",
            "höst",
        ] {
            assert!(validate_hosts(&[invalid.to_string()]).is_err(), "accepted {invalid:?}");
        }
        assert!(validate_hosts(&["HOST".to_string(), "host".to_string()]).is_err());
        assert!(validate_hosts(&["example.test:443".to_string()]).is_ok());
        assert!(validate_hosts(&["[::1]:7443".to_string()]).is_ok());

        let boundary = format!(
            "{}.{}.{}.{}:80",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(60)
        );
        let over = format!(
            "{}.{}.{}.{}:80",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(boundary.len(), 255);
        assert_eq!(over.len(), 256);
        assert!(validate_hosts(&[boundary]).is_ok());
        assert!(validate_hosts(&[over]).is_err());
    }

    #[test]
    fn origin_allowlist_requires_unique_https_origins() {
        assert!(validate_origins(&[]).is_err());
        let unique = (0..=MAX_REMOTE_MCP_AUTHORITIES)
            .map(|index| format!("https://origin-{index}.example.test"))
            .collect::<Vec<_>>();
        assert!(validate_origins(&unique[..MAX_REMOTE_MCP_AUTHORITIES]).is_ok());
        assert!(validate_origins(&unique).is_err());
        for invalid in [
            "not-an-origin",
            "http://example.test",
            "https:///missing",
            "https://user@example.test",
            "https://example.test/path",
            "https://example.test?query",
            "https://example.test#fragment",
        ] {
            assert!(validate_origins(&[invalid.to_string()]).is_err(), "accepted {invalid:?}");
        }
        assert!(validate_origins(&[
            "https://EXAMPLE.test".to_string(),
            "https://example.test/".to_string(),
        ])
        .is_err());
        assert!(validate_origins(&["https://example.test:8443".to_string()]).is_ok());
    }

    #[test]
    fn binding_identifiers_and_references_are_bounded_and_unique() {
        assert!(validate_bindings(&[]).is_err());
        let unique = (0..=MAX_REMOTE_MCP_BINDINGS)
            .map(|index| {
                binding(&format!("subject-{index}"), &format!("SCORCHKIT_MCP_TOKEN_{index}"))
            })
            .collect::<Vec<_>>();
        assert!(validate_bindings(&unique[..MAX_REMOTE_MCP_BINDINGS]).is_ok());
        assert!(validate_bindings(&unique).is_err());
        for invalid in ["", "contains space", "bad!", &"x".repeat(129)] {
            assert!(!valid_subject(invalid), "accepted {invalid:?}");
        }
        for valid in ["a", "operator@example.test", "oidc:issuer/subject-1"] {
            assert!(valid_subject(valid), "rejected {valid:?}");
        }
        for invalid in [
            "",
            "SCORCHKIT_MCP_",
            "SCORCHKIT_TOKEN",
            "SCORCHKIT_MCP_lower",
            "SCORCHKIT_MCP_BAD-DASH",
            &format!("SCORCHKIT_MCP_{}", "X".repeat(129)),
        ] {
            assert!(!valid_token_environment(invalid), "accepted {invalid:?}");
        }
        assert!(valid_token_environment("SCORCHKIT_MCP_OPERATOR_1"));

        let duplicate_subject =
            vec![binding("same", "SCORCHKIT_MCP_FIRST"), binding("same", "SCORCHKIT_MCP_SECOND")];
        assert!(validate_bindings(&duplicate_subject).is_err());
        let duplicate_environment = vec![
            binding("first", "SCORCHKIT_MCP_SHARED"),
            binding("second", "SCORCHKIT_MCP_SHARED"),
        ];
        assert!(validate_bindings(&duplicate_environment).is_err());
    }
}
