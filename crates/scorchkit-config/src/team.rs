//! Optional authenticated team-service deployment configuration.
//!
//! Values are identifiers, policy, and environment references only. The root composition adapter
//! resolves credentials and encryption keys, canonicalizes roots, and connects databases.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Component, PathBuf};

use chrono::Utc;
use scorchkit_control::TeamRoleV1;
use scorchkit_policy::{Capability, EffectClass, Engagement, ScopeRule};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

/// Maximum configured isolation cells.
pub const MAX_TEAM_CELLS: usize = 32;
/// Maximum authenticated bindings across all cells.
pub const MAX_TEAM_BINDINGS: usize = 128;
/// Maximum decryption keys retained per cell.
pub const MAX_TEAM_KEYS_PER_CELL: usize = 8;
/// Maximum accepted team API request body.
pub const MAX_TEAM_BODY_BYTES: usize = 8_388_608;
/// Maximum serialized response.
pub const MAX_TEAM_RESPONSE_BYTES: usize = 8_388_608;
/// Maximum concurrent admitted requests.
pub const MAX_TEAM_CONCURRENT_REQUESTS: usize = 256;
/// Maximum configured object size.
pub const MAX_TEAM_OBJECT_BYTES: u64 = 67_108_864;
/// Maximum configured objects in one cell.
pub const MAX_TEAM_OBJECTS: u64 = 1_000_000;
/// Maximum configured aggregate plaintext bytes in one cell.
pub const MAX_TEAM_STORAGE_BYTES: u64 = 1_099_511_627_776;
/// Maximum active jobs in one cell.
pub const MAX_TEAM_ACTIVE_JOBS: u32 = 1_024;
/// Maximum retained control events in one cell.
pub const MAX_TEAM_JOURNAL_EVENTS: usize = 65_536;
/// Maximum one serialized control event.
pub const MAX_TEAM_EVENT_BYTES: usize = 1_048_576;
/// Maximum simultaneous event readers in one cell.
pub const MAX_TEAM_SUBSCRIBERS: usize = 128;
/// Maximum control page size in one cell.
pub const MAX_TEAM_PAGE_SIZE: u16 = 200;
/// Maximum request rate per minute in one cell.
pub const MAX_TEAM_REQUESTS_PER_MINUTE: u32 = 60_000;
/// Maximum retention duration.
pub const MAX_TEAM_RETENTION_DAYS: u32 = 3_650;

const DEFAULT_BODY_BYTES: usize = 262_144;
const DEFAULT_RESPONSE_BYTES: usize = 4_194_304;
const DEFAULT_CONCURRENT_REQUESTS: usize = 64;
const DEFAULT_MAX_ACTIVE_JOBS: u32 = 16;
const DEFAULT_MAX_JOURNAL_EVENTS: usize = 4_096;
const DEFAULT_MAX_EVENT_BYTES: usize = 262_144;
const DEFAULT_MAX_SUBSCRIBERS: usize = 32;
const DEFAULT_PAGE_SIZE: u16 = 50;
const DEFAULT_REQUESTS_PER_MINUTE: u32 = 600;
const DEFAULT_MAX_OBJECT_BYTES: u64 = 16_777_216;
const DEFAULT_MAX_OBJECTS: u64 = 100_000;
const DEFAULT_MAX_STORAGE_BYTES: u64 = 107_374_182_400;
const DEFAULT_RETENTION_DAYS: u32 = 90;

const fn default_body_bytes() -> usize {
    DEFAULT_BODY_BYTES
}

const fn default_response_bytes() -> usize {
    DEFAULT_RESPONSE_BYTES
}

const fn default_concurrent_requests() -> usize {
    DEFAULT_CONCURRENT_REQUESTS
}

const fn default_max_active_jobs() -> u32 {
    DEFAULT_MAX_ACTIVE_JOBS
}

const fn default_max_journal_events() -> usize {
    DEFAULT_MAX_JOURNAL_EVENTS
}

const fn default_max_event_bytes() -> usize {
    DEFAULT_MAX_EVENT_BYTES
}

const fn default_max_subscribers() -> usize {
    DEFAULT_MAX_SUBSCRIBERS
}

const fn default_page_size() -> u16 {
    DEFAULT_PAGE_SIZE
}

const fn default_requests_per_minute() -> u32 {
    DEFAULT_REQUESTS_PER_MINUTE
}

const fn default_max_object_bytes() -> u64 {
    DEFAULT_MAX_OBJECT_BYTES
}

const fn default_max_objects() -> u64 {
    DEFAULT_MAX_OBJECTS
}

const fn default_max_storage_bytes() -> u64 {
    DEFAULT_MAX_STORAGE_BYTES
}

const fn default_retention_days() -> u32 {
    DEFAULT_RETENTION_DAYS
}

/// Supported TLS ownership for the team backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamTlsTermination {
    /// A same-host reverse proxy terminates TLS and connects to the loopback backend.
    TrustedReverseProxy,
}

/// One environment-backed encryption key reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamKeyReferenceConfig {
    /// Stable public key identifier used in ciphertext metadata and recovery manifests.
    pub key_id: String,
    /// Environment variable containing exactly 32 key bytes as base64.
    pub key_env: String,
}

/// Cell-local admission and storage budgets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TeamQuotaConfig {
    /// Maximum nonterminal jobs.
    #[serde(default = "default_max_active_jobs")]
    pub max_active_jobs: u32,
    /// Maximum retained replay events.
    #[serde(default = "default_max_journal_events")]
    pub max_journal_events: usize,
    /// Maximum serialized event size.
    #[serde(default = "default_max_event_bytes")]
    pub max_event_bytes: usize,
    /// Maximum simultaneous event readers.
    #[serde(default = "default_max_subscribers")]
    pub max_subscribers: usize,
    /// Default and maximum control page size.
    #[serde(default = "default_page_size")]
    pub default_page_size: u16,
    /// Maximum admitted requests per rolling minute.
    #[serde(default = "default_requests_per_minute")]
    pub max_requests_per_minute: u32,
    /// Maximum plaintext bytes in one object.
    #[serde(default = "default_max_object_bytes")]
    pub max_object_bytes: u64,
    /// Maximum retained object count.
    #[serde(default = "default_max_objects")]
    pub max_objects: u64,
    /// Maximum aggregate retained plaintext bytes.
    #[serde(default = "default_max_storage_bytes")]
    pub max_storage_bytes: u64,
}

impl Default for TeamQuotaConfig {
    fn default() -> Self {
        Self {
            max_active_jobs: DEFAULT_MAX_ACTIVE_JOBS,
            max_journal_events: DEFAULT_MAX_JOURNAL_EVENTS,
            max_event_bytes: DEFAULT_MAX_EVENT_BYTES,
            max_subscribers: DEFAULT_MAX_SUBSCRIBERS,
            default_page_size: DEFAULT_PAGE_SIZE,
            max_requests_per_minute: DEFAULT_REQUESTS_PER_MINUTE,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            max_objects: DEFAULT_MAX_OBJECTS,
            max_storage_bytes: DEFAULT_MAX_STORAGE_BYTES,
        }
    }
}

/// Cell-local mandatory retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TeamRetentionConfig {
    /// Maximum time before an object becomes eligible for deletion.
    #[serde(default = "default_retention_days")]
    pub object_days: u32,
}

impl Default for TeamRetentionConfig {
    fn default() -> Self {
        Self { object_days: DEFAULT_RETENTION_DAYS }
    }
}

/// One hard organization/project isolation cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamCellConfig {
    /// Stable bounded server-side cell identifier.
    pub cell_id: String,
    /// Stable bounded organization identifier.
    pub organization_id: String,
    /// Exact pre-provisioned `ScorchKit` project UUID in this cell database.
    pub project_id: Uuid,
    /// Exact engagement composed into this cell service.
    pub engagement: Engagement,
    /// Environment variable containing this cell's `PostgreSQL` URL.
    pub database_url_env: String,
    /// Dedicated absolute object root.
    pub object_root: PathBuf,
    /// Identifier used for new object encryption.
    pub write_key_id: String,
    /// Active write key and bounded historical decryption keys.
    pub keys: Vec<TeamKeyReferenceConfig>,
    /// Cell-local quotas.
    #[serde(default)]
    pub quotas: TeamQuotaConfig,
    /// Cell-local retention.
    #[serde(default)]
    pub retention: TeamRetentionConfig,
}

/// One credential-to-principal/cell binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamPrincipalBindingConfig {
    /// Stable transport-owned subject.
    pub subject: String,
    /// Exact configured cell selected by this credential.
    pub cell_id: String,
    /// RBAC role that can only narrow the cell engagement.
    pub role: TeamRoleV1,
    /// Environment variable containing the bearer value.
    pub token_env: String,
}

/// Complete optional team HTTP profile.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TeamServiceConfig {
    /// Explicit loopback socket used by the trusted same-host proxy.
    pub bind: Option<SocketAddr>,
    /// Explicit TLS termination ownership.
    pub tls_termination: Option<TeamTlsTermination>,
    /// Exact public HTTPS authorities accepted in Host.
    pub allowed_hosts: Vec<String>,
    /// Exact public HTTPS origins accepted when Origin is present.
    pub allowed_origins: Vec<String>,
    /// Maximum request body before route parsing.
    #[serde(default = "default_body_bytes")]
    pub max_body_bytes: usize,
    /// Maximum serialized response or event frame.
    #[serde(default = "default_response_bytes")]
    pub max_response_bytes: usize,
    /// Maximum concurrent requests across cells.
    #[serde(default = "default_concurrent_requests")]
    pub max_concurrent_requests: usize,
    /// Hard isolation cells.
    pub cells: Vec<TeamCellConfig>,
    /// Credential bindings.
    pub bindings: Vec<TeamPrincipalBindingConfig>,
}

impl std::fmt::Debug for TeamServiceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TeamServiceConfig")
            .field("bind", &self.bind)
            .field("tls_termination", &self.tls_termination)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_origins", &self.allowed_origins)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .field("cell_count", &self.cells.len())
            .field("binding_count", &self.bindings.len())
            .finish()
    }
}

impl Default for TeamServiceConfig {
    fn default() -> Self {
        Self {
            bind: None,
            tls_termination: None,
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
            max_body_bytes: DEFAULT_BODY_BYTES,
            max_response_bytes: DEFAULT_RESPONSE_BYTES,
            max_concurrent_requests: DEFAULT_CONCURRENT_REQUESTS,
            cells: Vec::new(),
            bindings: Vec::new(),
        }
    }
}

impl TeamServiceConfig {
    /// Validate the complete credential-safe shape before environment lookup or effects.
    ///
    /// # Errors
    ///
    /// Returns a safe deterministic message for any missing, duplicate, exposed, or unbounded
    /// setting.
    pub fn validate(&self) -> Result<(), String> {
        let bind = self
            .bind
            .ok_or_else(|| "team service requires an explicit backend bind".to_string())?;
        if !bind.ip().is_loopback() {
            return Err("team service trusted-proxy backend must bind to loopback".to_string());
        }
        if self.tls_termination != Some(TeamTlsTermination::TrustedReverseProxy) {
            return Err("team service requires tls_termination = 'trusted_reverse_proxy'".into());
        }
        if !(256..=MAX_TEAM_BODY_BYTES).contains(&self.max_body_bytes) {
            return Err("team service max_body_bytes must be 256-8388608".into());
        }
        if !(1_024..=MAX_TEAM_RESPONSE_BYTES).contains(&self.max_response_bytes) {
            return Err("team service max_response_bytes must be 1024-8388608".into());
        }
        if !(1..=MAX_TEAM_CONCURRENT_REQUESTS).contains(&self.max_concurrent_requests) {
            return Err("team service max_concurrent_requests must be 1-256".into());
        }
        validate_authorities(&self.allowed_hosts, &self.allowed_origins)?;
        self.validate_cells_and_bindings()
    }

    fn validate_cells_and_bindings(&self) -> Result<(), String> {
        if self.cells.is_empty() || self.cells.len() > MAX_TEAM_CELLS {
            return Err("team service cells must contain 1-32 values".into());
        }
        if self.bindings.is_empty() || self.bindings.len() > MAX_TEAM_BINDINGS {
            return Err("team service bindings must contain 1-128 values".into());
        }
        let mut cells = BTreeSet::new();
        let mut organization_projects = BTreeSet::new();
        let mut secret_environments = BTreeSet::new();
        let mut object_roots = Vec::with_capacity(self.cells.len());
        for cell in &self.cells {
            if cell.quotas.max_event_bytes > self.max_response_bytes {
                return Err(
                    "team service cell max_event_bytes cannot exceed max_response_bytes".into()
                );
            }
            validate_cell(cell, &mut cells, &mut organization_projects, &mut secret_environments)?;
            let canonical = cell
                .object_root
                .canonicalize()
                .map_err(|_| "team service object roots must exist and be canonical".to_string())?;
            if canonical != cell.object_root
                || object_roots.iter().any(|other: &PathBuf| {
                    canonical.starts_with(other) || other.starts_with(&canonical)
                })
            {
                return Err(
                    "team service object roots must be canonical, distinct, and non-overlapping"
                        .into(),
                );
            }
            object_roots.push(canonical);
        }
        let mut subjects_and_cells = BTreeSet::new();
        let mut referenced_cells = BTreeSet::new();
        for binding in &self.bindings {
            if !valid_identifier(&binding.subject)
                || !valid_identifier(&binding.cell_id)
                || !cells.contains(&binding.cell_id)
                || !subjects_and_cells.insert((binding.subject.clone(), binding.cell_id.clone()))
                || !valid_environment(&binding.token_env)
                || !secret_environments.insert(binding.token_env.clone())
            {
                return Err("team service bindings must have unique bounded subjects, known cells, and unique SCORCHKIT_TEAM_* token environments".into());
            }
            referenced_cells.insert(binding.cell_id.clone());
        }
        if referenced_cells != cells {
            return Err("every team service cell requires at least one principal binding".into());
        }
        Ok(())
    }
}

fn validate_cell(
    cell: &TeamCellConfig,
    cells: &mut BTreeSet<String>,
    organization_projects: &mut BTreeSet<(String, Uuid)>,
    secret_environments: &mut BTreeSet<String>,
) -> Result<(), String> {
    if !valid_identifier(&cell.cell_id)
        || !valid_identifier(&cell.organization_id)
        || !cells.insert(cell.cell_id.clone())
        || cell.project_id.is_nil()
        || !organization_projects.insert((cell.organization_id.clone(), cell.project_id))
        || cell.engagement.id.is_nil()
        || !cell.engagement.enabled
        || cell.engagement.expires_at.is_some_and(|expiry| expiry <= Utc::now())
    {
        return Err("team service cells require unique bounded identities, a non-nil project, and an enabled unexpired engagement".into());
    }
    if !valid_environment(&cell.database_url_env)
        || !secret_environments.insert(cell.database_url_env.clone())
    {
        return Err(
            "team service database environments must be unique SCORCHKIT_TEAM_* names".into()
        );
    }
    if !valid_absolute_root(&cell.object_root) {
        return Err("team service object roots must be absolute normalized paths".into());
    }
    let exact_root = ScopeRule::path_prefix(&cell.object_root)
        .map_err(|_| "team service object roots must exist and be canonical".to_string())?;
    if !cell.engagement.policy.allowed_scope.contains(&exact_root)
        || !cell.engagement.policy.capabilities.contains(&Capability::LocalState)
        || !cell.engagement.policy.effects.contains(&EffectClass::Passive)
    {
        return Err(
            "team service object roots require an exact local-state/passive engagement grant"
                .into(),
        );
    }
    if cell.keys.is_empty() || cell.keys.len() > MAX_TEAM_KEYS_PER_CELL {
        return Err("team service cell keys must contain 1-8 values".into());
    }
    let mut key_ids = BTreeSet::new();
    for key in &cell.keys {
        if !valid_identifier(&key.key_id)
            || !key_ids.insert(key.key_id.clone())
            || !valid_environment(&key.key_env)
            || !secret_environments.insert(key.key_env.clone())
        {
            return Err("team service keys require unique bounded IDs and unique SCORCHKIT_TEAM_* environments".into());
        }
    }
    if !key_ids.contains(&cell.write_key_id) {
        return Err("team service write_key_id must identify a configured key".into());
    }
    validate_quotas(&cell.quotas)?;
    if !(1..=MAX_TEAM_RETENTION_DAYS).contains(&cell.retention.object_days) {
        return Err("team service object retention must be 1-3650 days".into());
    }
    Ok(())
}

fn validate_quotas(quotas: &TeamQuotaConfig) -> Result<(), String> {
    if !(1..=MAX_TEAM_ACTIVE_JOBS).contains(&quotas.max_active_jobs)
        || !(1..=MAX_TEAM_JOURNAL_EVENTS).contains(&quotas.max_journal_events)
        || !(512..=MAX_TEAM_EVENT_BYTES).contains(&quotas.max_event_bytes)
        || !(1..=MAX_TEAM_SUBSCRIBERS).contains(&quotas.max_subscribers)
        || !(1..=MAX_TEAM_PAGE_SIZE).contains(&quotas.default_page_size)
        || !(1..=MAX_TEAM_REQUESTS_PER_MINUTE).contains(&quotas.max_requests_per_minute)
        || !(1..=MAX_TEAM_OBJECT_BYTES).contains(&quotas.max_object_bytes)
        || !(1..=MAX_TEAM_OBJECTS).contains(&quotas.max_objects)
        || !(1..=MAX_TEAM_STORAGE_BYTES).contains(&quotas.max_storage_bytes)
        || quotas.max_object_bytes > quotas.max_storage_bytes
    {
        return Err(
            "team service quotas are zero, over hard maxima, or internally inconsistent".into()
        );
    }
    Ok(())
}

fn validate_authorities(hosts: &[String], origins: &[String]) -> Result<(), String> {
    if hosts.is_empty() || hosts.len() > 32 || origins.is_empty() || origins.len() > 32 {
        return Err(
            "team service allowed_hosts and allowed_origins must contain 1-32 values".into()
        );
    }
    let mut unique_hosts = BTreeSet::new();
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
            || !parsed.as_ref().is_ok_and(|url| url.host_str().is_some())
            || !unique_hosts.insert(host.to_ascii_lowercase())
        {
            return Err(
                "team service allowed_hosts must be unique bounded HTTPS authorities".into()
            );
        }
    }
    let mut unique_origins = BTreeSet::new();
    for origin in origins {
        let parsed = Url::parse(origin)
            .map_err(|_| "team service allowed_origins contains an invalid URL".to_string())?;
        let canonical = parsed.origin().ascii_serialization();
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || (origin != &canonical && origin != &format!("{canonical}/"))
            || !unique_origins.insert(canonical)
        {
            return Err("team service allowed_origins must be unique HTTPS origins".into());
        }
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@' | b'/')
        })
}

fn valid_environment(value: &str) -> bool {
    value.len() > "SCORCHKIT_TEAM_".len()
        && value.len() <= 128
        && value.starts_with("SCORCHKIT_TEAM_")
        && value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn valid_absolute_root(path: &std::path::Path) -> bool {
    path.is_absolute()
        && path != std::path::Path::new("/")
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir | Component::CurDir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scorchkit_policy::{Capability, EffectClass, EngagementPolicy, ScopeRule};

    fn cell(id: &str, project: u128) -> TeamCellConfig {
        let root = std::env::temp_dir().join(format!("scorchkit-team-{id}"));
        std::fs::create_dir_all(&root).expect("create team test root");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(&root).expect("absolute root"))
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::Passive);
        TeamCellConfig {
            cell_id: id.into(),
            organization_id: format!("org-{id}"),
            project_id: Uuid::from_u128(project),
            engagement: Engagement::new(id, policy),
            database_url_env: format!("SCORCHKIT_TEAM_{}_DATABASE", id.to_ascii_uppercase()),
            object_root: root,
            write_key_id: "primary".into(),
            keys: vec![TeamKeyReferenceConfig {
                key_id: "primary".into(),
                key_env: format!("SCORCHKIT_TEAM_{}_KEY", id.to_ascii_uppercase()),
            }],
            quotas: TeamQuotaConfig::default(),
            retention: TeamRetentionConfig::default(),
        }
    }

    fn valid() -> TeamServiceConfig {
        TeamServiceConfig {
            bind: Some("127.0.0.1:7445".parse().expect("bind")),
            tls_termination: Some(TeamTlsTermination::TrustedReverseProxy),
            allowed_hosts: vec!["security.example.test".into()],
            allowed_origins: vec!["https://security.example.test".into()],
            cells: vec![cell("alpha", 1)],
            bindings: vec![TeamPrincipalBindingConfig {
                subject: "operator@example.test".into(),
                cell_id: "alpha".into(),
                role: TeamRoleV1::Operator,
                token_env: "SCORCHKIT_TEAM_ALPHA_TOKEN".into(),
            }],
            ..TeamServiceConfig::default()
        }
    }

    #[test]
    fn defaults_are_bounded_and_inert_while_complete_shape_round_trips() {
        let defaults = TeamServiceConfig::default();
        assert!(defaults.validate().is_err());
        assert_eq!(defaults.max_body_bytes, DEFAULT_BODY_BYTES);
        assert_eq!(defaults.max_response_bytes, DEFAULT_RESPONSE_BYTES);
        assert_eq!(defaults.max_concurrent_requests, DEFAULT_CONCURRENT_REQUESTS);
        let quotas = TeamQuotaConfig::default();
        assert_eq!(quotas.max_active_jobs, DEFAULT_MAX_ACTIVE_JOBS);
        assert_eq!(quotas.max_journal_events, DEFAULT_MAX_JOURNAL_EVENTS);
        assert_eq!(quotas.max_event_bytes, DEFAULT_MAX_EVENT_BYTES);
        assert_eq!(quotas.max_subscribers, DEFAULT_MAX_SUBSCRIBERS);
        assert_eq!(quotas.default_page_size, DEFAULT_PAGE_SIZE);
        assert_eq!(quotas.max_requests_per_minute, DEFAULT_REQUESTS_PER_MINUTE);
        assert_eq!(quotas.max_object_bytes, DEFAULT_MAX_OBJECT_BYTES);
        assert_eq!(quotas.max_objects, DEFAULT_MAX_OBJECTS);
        assert_eq!(quotas.max_storage_bytes, DEFAULT_MAX_STORAGE_BYTES);
        assert_eq!(TeamRetentionConfig::default().object_days, DEFAULT_RETENTION_DAYS);
        let config = valid();
        config.validate().expect("valid team config");
        let text = toml::to_string(&config).expect("serialize");
        assert!(!text.contains("secret"));
        let decoded: TeamServiceConfig = toml::from_str(&text).expect("deserialize");
        assert_eq!(decoded, config);

        let debug = format!("{config:?}");
        assert!(debug.contains("TeamServiceConfig"));
        assert!(debug.contains("cell_count: 1"));
        assert!(debug.contains("binding_count: 1"));
        assert!(!debug.contains("SCORCHKIT_TEAM_ALPHA_KEY"));
        assert!(!debug.contains("SCORCHKIT_TEAM_ALPHA_TOKEN"));
    }

    #[test]
    fn omitted_serialized_values_use_every_documented_default() {
        let service: TeamServiceConfig = toml::from_str("").expect("empty service config");
        assert_eq!(service, TeamServiceConfig::default());

        let quotas: TeamQuotaConfig = toml::from_str("").expect("empty quota config");
        assert_eq!(quotas, TeamQuotaConfig::default());

        let retention: TeamRetentionConfig = toml::from_str("").expect("empty retention config");
        assert_eq!(retention, TeamRetentionConfig::default());
    }

    #[test]
    fn listener_authority_and_every_quota_boundary_fail_independently() {
        let cases: &[fn(&mut TeamServiceConfig)] = &[
            |config| config.bind = None,
            |config| config.bind = Some("0.0.0.0:7445".parse().expect("bind")),
            |config| config.tls_termination = None,
            |config| config.allowed_hosts.clear(),
            |config| config.allowed_origins = vec!["http://security.example.test".into()],
            |config| config.max_body_bytes = 255,
            |config| config.max_body_bytes = MAX_TEAM_BODY_BYTES + 1,
            |config| config.max_response_bytes = 1_023,
            |config| config.max_response_bytes = MAX_TEAM_RESPONSE_BYTES + 1,
            |config| config.max_concurrent_requests = 0,
            |config| config.max_concurrent_requests = MAX_TEAM_CONCURRENT_REQUESTS + 1,
            |config| config.cells[0].quotas.max_active_jobs = 0,
            |config| config.cells[0].quotas.max_active_jobs = MAX_TEAM_ACTIVE_JOBS + 1,
            |config| config.cells[0].quotas.max_journal_events = 0,
            |config| config.cells[0].quotas.max_journal_events = MAX_TEAM_JOURNAL_EVENTS + 1,
            |config| config.cells[0].quotas.max_event_bytes = 511,
            |config| config.cells[0].quotas.max_event_bytes = MAX_TEAM_EVENT_BYTES + 1,
            |config| config.cells[0].quotas.max_subscribers = 0,
            |config| config.cells[0].quotas.max_subscribers = MAX_TEAM_SUBSCRIBERS + 1,
            |config| config.cells[0].quotas.default_page_size = 0,
            |config| config.cells[0].quotas.default_page_size = MAX_TEAM_PAGE_SIZE + 1,
            |config| config.cells[0].quotas.max_requests_per_minute = 0,
            |config| {
                config.cells[0].quotas.max_requests_per_minute = MAX_TEAM_REQUESTS_PER_MINUTE + 1;
            },
            |config| config.cells[0].quotas.max_object_bytes = 0,
            |config| config.cells[0].quotas.max_object_bytes = MAX_TEAM_OBJECT_BYTES + 1,
            |config| config.cells[0].quotas.max_objects = 0,
            |config| config.cells[0].quotas.max_objects = MAX_TEAM_OBJECTS + 1,
            |config| config.cells[0].quotas.max_storage_bytes = 0,
            |config| config.cells[0].quotas.max_storage_bytes = MAX_TEAM_STORAGE_BYTES + 1,
            |config| {
                config.cells[0].quotas.max_storage_bytes = 1;
                config.cells[0].quotas.max_object_bytes = 2;
            },
            |config| config.cells[0].retention.object_days = 0,
            |config| config.cells[0].retention.object_days = MAX_TEAM_RETENTION_DAYS + 1,
            |config| config.cells[0].quotas.max_event_bytes = config.max_response_bytes + 1,
        ];
        for mutate in cases {
            let mut config = valid();
            mutate(&mut config);
            assert!(config.validate().is_err());
        }

        let mut maxima = valid();
        maxima.max_body_bytes = MAX_TEAM_BODY_BYTES;
        maxima.max_response_bytes = MAX_TEAM_RESPONSE_BYTES;
        maxima.max_concurrent_requests = MAX_TEAM_CONCURRENT_REQUESTS;
        maxima.cells[0].quotas = TeamQuotaConfig {
            max_active_jobs: MAX_TEAM_ACTIVE_JOBS,
            max_journal_events: MAX_TEAM_JOURNAL_EVENTS,
            max_event_bytes: MAX_TEAM_EVENT_BYTES,
            max_subscribers: MAX_TEAM_SUBSCRIBERS,
            default_page_size: MAX_TEAM_PAGE_SIZE,
            max_requests_per_minute: MAX_TEAM_REQUESTS_PER_MINUTE,
            max_object_bytes: MAX_TEAM_OBJECT_BYTES,
            max_objects: MAX_TEAM_OBJECTS,
            max_storage_bytes: MAX_TEAM_STORAGE_BYTES,
        };
        maxima.cells[0].retention.object_days = MAX_TEAM_RETENTION_DAYS;
        maxima.validate().expect("hard maxima are inclusive");

        let mut minima = valid();
        minima.max_body_bytes = 256;
        minima.max_response_bytes = 1_024;
        minima.max_concurrent_requests = 1;
        minima.cells[0].quotas = TeamQuotaConfig {
            max_active_jobs: 1,
            max_journal_events: 1,
            max_event_bytes: 512,
            max_subscribers: 1,
            default_page_size: 1,
            max_requests_per_minute: 1,
            max_object_bytes: 1,
            max_objects: 1,
            max_storage_bytes: 1,
        };
        minima.cells[0].retention.object_days = 1;
        minima.validate().expect("hard minima are inclusive");
    }

    #[test]
    fn cell_binding_and_secret_environment_collisions_fail_closed() {
        let mut duplicate = valid();
        duplicate.cells.push(cell("alpha", 2));
        assert!(duplicate.validate().is_err());

        let mut unknown = valid();
        unknown.bindings[0].cell_id = "missing".into();
        assert!(unknown.validate().is_err());

        let mut reused_secret = valid();
        reused_secret.bindings[0].token_env = reused_secret.cells[0].keys[0].key_env.clone();
        assert!(reused_secret.validate().is_err());

        let debug = format!("{:?}", valid());
        assert!(!debug.contains("SCORCHKIT_TEAM_ALPHA_KEY"));
        assert!(!debug.contains("SCORCHKIT_TEAM_ALPHA_TOKEN"));
    }

    #[test]
    fn cell_and_binding_identity_clauses_fail_independently() {
        let cases: &[fn(&mut TeamServiceConfig)] = &[
            |config| config.cells.clear(),
            |config| config.bindings.clear(),
            |config| config.cells[0].cell_id.clear(),
            |config| config.cells[0].organization_id = "org alpha".into(),
            |config| config.cells[0].project_id = Uuid::nil(),
            |config| config.cells[0].engagement.id = Uuid::nil(),
            |config| config.cells[0].engagement.enabled = false,
            |config| config.cells[0].engagement.expires_at = Some(Utc::now()),
            |config| config.cells[0].database_url_env = "DATABASE_URL".into(),
            |config| config.cells[0].keys.clear(),
            |config| config.cells[0].keys[0].key_id.clear(),
            |config| config.cells[0].keys[0].key_env = "KEY".into(),
            |config| config.cells[0].write_key_id = "missing".into(),
            |config| config.bindings[0].subject = "operator subject".into(),
            |config| config.bindings[0].cell_id = "missing".into(),
            |config| config.bindings[0].token_env = "TOKEN".into(),
        ];
        for mutate in cases {
            let mut config = valid();
            mutate(&mut config);
            assert!(config.validate().is_err());
        }

        let mut too_many_cells = valid();
        too_many_cells.cells = (0..=MAX_TEAM_CELLS)
            .map(|index| cell(&format!("cell-{index}"), index as u128 + 1))
            .collect();
        assert!(too_many_cells.validate().is_err());

        let mut too_many_bindings = valid();
        too_many_bindings.bindings = (0..=MAX_TEAM_BINDINGS)
            .map(|index| TeamPrincipalBindingConfig {
                subject: format!("subject-{index}"),
                cell_id: "alpha".into(),
                role: TeamRoleV1::Reader,
                token_env: format!("SCORCHKIT_TEAM_TOKEN_{index}"),
            })
            .collect();
        assert!(too_many_bindings.validate().is_err());

        let mut too_many_keys = valid();
        too_many_keys.cells[0].keys = (0..=MAX_TEAM_KEYS_PER_CELL)
            .map(|index| TeamKeyReferenceConfig {
                key_id: format!("key-{index}"),
                key_env: format!("SCORCHKIT_TEAM_KEY_{index}"),
            })
            .collect();
        too_many_keys.cells[0].write_key_id = "key-0".into();
        assert!(too_many_keys.validate().is_err());
    }

    #[test]
    fn cell_binding_and_key_ceilings_are_inclusive() {
        let mut maximum_cells = valid();
        maximum_cells.cells = (0..MAX_TEAM_CELLS)
            .map(|index| cell(&format!("edgecell{index}"), index as u128 + 1))
            .collect();
        maximum_cells.bindings = maximum_cells
            .cells
            .iter()
            .enumerate()
            .map(|(index, cell)| TeamPrincipalBindingConfig {
                subject: format!("edge-subject-{index}"),
                cell_id: cell.cell_id.clone(),
                role: TeamRoleV1::Reader,
                token_env: format!("SCORCHKIT_TEAM_EDGE_TOKEN_{index}"),
            })
            .collect();
        maximum_cells.validate().expect("32 cells are allowed");

        let mut maximum_bindings = valid();
        maximum_bindings.bindings = (0..MAX_TEAM_BINDINGS)
            .map(|index| TeamPrincipalBindingConfig {
                subject: format!("edge-subject-{index}"),
                cell_id: "alpha".into(),
                role: TeamRoleV1::Reader,
                token_env: format!("SCORCHKIT_TEAM_EDGE_BINDING_{index}"),
            })
            .collect();
        maximum_bindings.validate().expect("128 bindings are allowed");

        let mut maximum_keys = valid();
        maximum_keys.cells[0].keys = (0..MAX_TEAM_KEYS_PER_CELL)
            .map(|index| TeamKeyReferenceConfig {
                key_id: format!("edge-key-{index}"),
                key_env: format!("SCORCHKIT_TEAM_EDGE_KEY_{index}"),
            })
            .collect();
        maximum_keys.cells[0].write_key_id = "edge-key-0".into();
        maximum_keys.validate().expect("8 decryption keys are allowed");
    }

    #[test]
    fn dependent_limits_and_authority_ceilings_are_inclusive() {
        let mut event_boundary = valid();
        event_boundary.max_response_bytes = 1_024;
        event_boundary.cells[0].quotas.max_event_bytes = 1_024;
        event_boundary.validate().expect("an event may equal the response ceiling");

        let hosts = (0..32).map(|index| format!("host-{index}.example.test")).collect::<Vec<_>>();
        let origins =
            (0..32).map(|index| format!("https://origin-{index}.example.test")).collect::<Vec<_>>();
        validate_authorities(&hosts, &origins).expect("32 authorities are allowed");

        let longest_host =
            ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(63)].join(".");
        assert_eq!(longest_host.len(), 255);
        validate_authorities(&[longest_host], &["https://security.example.test".into()])
            .expect("a 255-byte authority is allowed");
    }

    #[test]
    fn object_root_requires_its_own_exact_local_state_passive_grant() {
        let mut broader = valid();
        broader.cells[0].engagement.policy.allowed_scope = vec![ScopeRule::path_prefix(
            broader.cells[0].object_root.parent().expect("fixture root parent"),
        )
        .expect("parent scope")];
        assert!(broader.validate().is_err());

        let mut missing_capability = valid();
        missing_capability.cells[0].engagement.policy.capabilities.remove(&Capability::LocalState);
        assert!(missing_capability.validate().is_err());

        let mut missing_effect = valid();
        missing_effect.cells[0].engagement.policy.effects.remove(&EffectClass::Passive);
        assert!(missing_effect.validate().is_err());
    }

    #[test]
    fn authority_identifier_environment_and_root_grammars_are_exact() {
        for hosts in [
            vec![String::new()],
            vec![format!("{}.test", "a".repeat(251))],
            vec!["é.example.test".into()],
            vec![" security.example.test".into()],
            vec!["security.example.test:".into()],
            vec!["security//example.test".into()],
            vec!["security example.test".into()],
            vec!["security/example.test".into()],
            vec!["security\\example.test".into()],
            vec!["security%example.test".into()],
            vec!["user@security.example.test".into()],
            vec!["security.example.test#fragment".into()],
            vec!["security.example.test?query".into()],
            vec!["SECURITY.example.test".into(), "security.example.test".into()],
        ] {
            assert!(
                validate_authorities(&hosts, &["https://security.example.test".into()]).is_err()
            );
        }
        for origins in [
            vec!["not a url".into()],
            vec!["http://security.example.test".into()],
            vec!["https:///missing-host".into()],
            vec!["https://security.example.test/path".into()],
            vec!["https://security.example.test".into(), "https://security.example.test/".into()],
        ] {
            assert!(validate_authorities(&["security.example.test".into()], &origins).is_err());
        }
        assert!(validate_authorities(
            &["security.example.test:443".into()],
            &["https://security.example.test".into()],
        )
        .is_ok());

        assert!(valid_identifier("a-A_1.example:test@path/value"));
        assert!(valid_identifier(&"a".repeat(128)));
        assert!(!valid_identifier(""));
        assert!(!valid_identifier(&"a".repeat(129)));
        assert!(!valid_identifier("contains space"));

        assert!(valid_environment("SCORCHKIT_TEAM_A1_B"));
        assert!(valid_environment(&format!("SCORCHKIT_TEAM_{}", "A".repeat(113))));
        assert!(!valid_environment("SCORCHKIT_TEAM_"));
        assert!(!valid_environment(&format!("SCORCHKIT_TEAM_{}", "A".repeat(114))));
        assert!(!valid_environment("SCORCHKIT_OTHER_VALUE"));
        assert!(!valid_environment("SCORCHKIT_TEAM_lower"));

        assert!(valid_absolute_root(std::path::Path::new("/tmp/scorchkit-team-root")));
        assert!(!valid_absolute_root(std::path::Path::new("relative")));
        assert!(!valid_absolute_root(std::path::Path::new("/")));
        assert!(!valid_absolute_root(std::path::Path::new("/tmp/../tmp/root")));
    }

    #[test]
    fn bounded_configuration_guards_remain_explicit_and_fail_closed() {
        let source = include_str!("team.rs");
        let production = source.split("#[cfg(test)]").next().expect("production source");
        let normalized = production.split_whitespace().collect::<Vec<_>>().join(" ");
        for required in [
            "self.cells.is_empty() || self.cells.len() > MAX_TEAM_CELLS",
            "self.bindings.is_empty() || self.bindings.len() > MAX_TEAM_BINDINGS",
            "cell.quotas.max_event_bytes > self.max_response_bytes",
            "canonical != cell.object_root || object_roots.iter().any",
            "canonical.starts_with(other) || other.starts_with(&canonical)",
            "!valid_identifier(&binding.subject) || !valid_identifier(&binding.cell_id) || !cells.contains(&binding.cell_id) || !subjects_and_cells.insert",
            "!valid_environment(&binding.token_env) || !secret_environments.insert(binding.token_env.clone())",
            "cell.keys.is_empty() || cell.keys.len() > MAX_TEAM_KEYS_PER_CELL",
            "hosts.is_empty() || hosts.len() > 32 || origins.is_empty() || origins.len() > 32",
            "host.is_empty() || host.len() > 255",
        ] {
            assert!(normalized.contains(required), "missing bounded guard: {required}");
        }
    }
}
