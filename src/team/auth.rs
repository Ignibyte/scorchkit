//! Credential- and key-safe startup preparation for the team service.

use base64::Engine as _;
use scorchkit_config::{TeamCellConfig, TeamServiceConfig};
use scorchkit_control::TeamRoleV1;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::engine::error::{Result, ScorchError};

const MIN_BEARER_BYTES: usize = 32;
const MAX_BEARER_BYTES: usize = 4_096;

#[derive(Default)]
struct SecretDigestSet(Vec<Zeroizing<[u8; 32]>>);

impl SecretDigestSet {
    fn insert(&mut self, digest: [u8; 32]) -> bool {
        if self.0.iter().any(|existing| **existing == digest) {
            false
        } else {
            self.0.push(Zeroizing::new(digest));
            true
        }
    }
}

/// One secret-resolved cell. Secret values are deliberately omitted from `Debug`.
#[derive(Clone)]
pub(super) struct PreparedCell {
    pub(super) config: TeamCellConfig,
    pub(super) database_url: Zeroizing<String>,
    pub(super) keys: Vec<(String, Zeroizing<[u8; 32]>)>,
}

impl std::fmt::Debug for PreparedCell {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedCell")
            .field("cell_id", &self.config.cell_id)
            .field("organization_id", &self.config.organization_id)
            .field("project_id", &self.config.project_id)
            .field("key_ids", &self.keys.iter().map(|(id, _)| id).collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// One digest-only bearer binding.
#[derive(Clone)]
pub(super) struct PreparedBinding {
    pub(super) token_digest: Zeroizing<[u8; 32]>,
    pub(super) subject: String,
    pub(super) cell_id: String,
    pub(super) role: TeamRoleV1,
}

impl std::fmt::Debug for PreparedBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedBinding")
            .field("subject", &self.subject)
            .field("cell_id", &self.cell_id)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// Fully resolved service preflight input without plaintext bearers in memory.
#[derive(Clone)]
pub(super) struct PreparedTeamService {
    pub(super) config: TeamServiceConfig,
    pub(super) cells: Vec<PreparedCell>,
    pub(super) bindings: Vec<PreparedBinding>,
}

impl std::fmt::Debug for PreparedTeamService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedTeamService")
            .field("config", &self.config)
            .field("cells", &self.cells)
            .field("binding_count", &self.bindings.len())
            .finish()
    }
}

impl PreparedTeamService {
    pub fn from_config(config: &TeamServiceConfig) -> Result<Self> {
        Self::from_config_with(config, |name| std::env::var(name).ok())
    }

    pub(crate) fn from_config_with(
        config: &TeamServiceConfig,
        mut resolve: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self> {
        config.validate().map_err(ScorchError::Config)?;
        let mut cells = Vec::with_capacity(config.cells.len());
        let mut secret_digests = SecretDigestSet::default();
        for cell in &config.cells {
            let database_url = Zeroizing::new(resolve_required(
                &mut resolve,
                &cell.database_url_env,
                "database URL",
            )?);
            claim_secret(&mut secret_digests, database_url.as_bytes())?;
            if database_url.trim() != database_url.as_str() || database_url.is_empty() {
                return Err(ScorchError::Config(format!(
                    "team database environment '{}' is malformed",
                    cell.database_url_env
                )));
            }
            let mut keys = Vec::with_capacity(cell.keys.len());
            for key in &cell.keys {
                let encoded =
                    Zeroizing::new(resolve_required(&mut resolve, &key.key_env, "encryption key")?);
                claim_secret(&mut secret_digests, encoded.as_bytes())?;
                let decoded = Zeroizing::new(
                    base64::engine::general_purpose::STANDARD.decode(encoded.as_bytes()).map_err(
                        |_| {
                            ScorchError::Config(format!(
                                "team key environment '{}' is not canonical base64",
                                key.key_env
                            ))
                        },
                    )?,
                );
                let key_bytes: Zeroizing<[u8; 32]> =
                    Zeroizing::new(decoded.as_slice().try_into().map_err(|_| {
                        ScorchError::Config(format!(
                            "team key environment '{}' must decode to 32 bytes",
                            key.key_env
                        ))
                    })?);
                if base64::engine::general_purpose::STANDARD.encode(key_bytes.as_ref())
                    != encoded.as_str()
                {
                    return Err(ScorchError::Config(format!(
                        "team key environment '{}' is not canonical base64",
                        key.key_env
                    )));
                }
                keys.push((key.key_id.clone(), key_bytes));
            }
            cells.push(PreparedCell { config: cell.clone(), database_url, keys });
        }

        let mut bindings = Vec::with_capacity(config.bindings.len());
        for binding in &config.bindings {
            let token =
                Zeroizing::new(resolve_required(&mut resolve, &binding.token_env, "bearer token")?);
            validate_token(&token).map_err(|message| {
                ScorchError::Config(format!(
                    "team bearer environment '{}' {message}",
                    binding.token_env
                ))
            })?;
            claim_secret(&mut secret_digests, token.as_bytes())?;
            let digest = Zeroizing::new(token_digest(&token));
            bindings.push(PreparedBinding {
                token_digest: digest,
                subject: binding.subject.clone(),
                cell_id: binding.cell_id.clone(),
                role: binding.role,
            });
        }
        Ok(Self { config: config.clone(), cells, bindings })
    }

    /// Perform a full constant-time digest comparison across every binding.
    #[cfg(test)]
    pub(crate) fn authenticate(&self, bearer: &str) -> Option<&PreparedBinding> {
        authenticate_binding(&self.bindings, bearer)
    }
}

fn claim_secret(digests: &mut SecretDigestSet, value: &[u8]) -> Result<()> {
    if digests.insert(Sha256::digest(value).into()) {
        Ok(())
    } else {
        Err(ScorchError::Config(
            "team secret values must be unique across all environments".to_string(),
        ))
    }
}

pub(super) fn authenticate_binding<'a>(
    bindings: &'a [PreparedBinding],
    bearer: &str,
) -> Option<&'a PreparedBinding> {
    if validate_token(bearer).is_err() {
        return None;
    }
    let digest = Zeroizing::new(token_digest(bearer));
    let mut selected = 0_u64;
    let mut found = Choice::from(0_u8);
    for (index, binding) in bindings.iter().enumerate() {
        let is_match = digest.as_slice().ct_eq(binding.token_digest.as_slice());
        let index = u64::try_from(index).unwrap_or(u64::MAX);
        selected = u64::conditional_select(&selected, &index, is_match);
        found |= is_match;
    }
    if found.unwrap_u8() == 1 {
        usize::try_from(selected).ok().and_then(|index| bindings.get(index))
    } else {
        None
    }
}

fn resolve_required(
    resolve: &mut impl FnMut(&str) -> Option<String>,
    environment: &str,
    label: &str,
) -> Result<String> {
    resolve(environment).ok_or_else(|| {
        ScorchError::Config(format!("team {label} environment '{environment}' is unavailable"))
    })
}

fn validate_token(token: &str) -> std::result::Result<(), &'static str> {
    if !(MIN_BEARER_BYTES..=MAX_BEARER_BYTES).contains(&token.len()) {
        return Err("must contain 32-4096 bytes");
    }
    if !token.is_ascii()
        || token.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err("must contain only non-whitespace printable ASCII");
    }
    Ok(())
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scorchkit_config::{
        TeamKeyReferenceConfig, TeamPrincipalBindingConfig, TeamQuotaConfig, TeamRetentionConfig,
        TeamTlsTermination,
    };
    use scorchkit_policy::{Capability, EffectClass, Engagement, EngagementPolicy, ScopeRule};
    use uuid::Uuid;

    fn config(root: &std::path::Path) -> TeamServiceConfig {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(root).expect("root scope"))
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::Passive);
        TeamServiceConfig {
            bind: Some("127.0.0.1:7445".parse().expect("bind")),
            tls_termination: Some(TeamTlsTermination::TrustedReverseProxy),
            allowed_hosts: vec!["security.example.test".into()],
            allowed_origins: vec!["https://security.example.test".into()],
            max_body_bytes: 4_096,
            max_response_bytes: 1_048_576,
            max_concurrent_requests: 4,
            cells: vec![TeamCellConfig {
                cell_id: "alpha".into(),
                organization_id: "org-alpha".into(),
                project_id: Uuid::from_u128(1),
                engagement: Engagement::new("alpha", policy),
                database_url_env: "SCORCHKIT_TEAM_ALPHA_DATABASE".into(),
                object_root: root.into(),
                write_key_id: "primary".into(),
                keys: vec![TeamKeyReferenceConfig {
                    key_id: "primary".into(),
                    key_env: "SCORCHKIT_TEAM_ALPHA_KEY".into(),
                }],
                quotas: TeamQuotaConfig::default(),
                retention: TeamRetentionConfig::default(),
            }],
            bindings: vec![TeamPrincipalBindingConfig {
                subject: "operator@example.test".into(),
                cell_id: "alpha".into(),
                role: TeamRoleV1::Operator,
                token_env: "SCORCHKIT_TEAM_ALPHA_TOKEN".into(),
            }],
        }
    }

    #[test]
    fn preparation_discards_bearers_and_authenticates_exactly_one_digest() {
        let directory = tempfile::tempdir().expect("root");
        let config = config(directory.path());
        let prepared = PreparedTeamService::from_config_with(&config, |name| match name {
            "SCORCHKIT_TEAM_ALPHA_DATABASE" => Some("postgresql:///alpha".into()),
            "SCORCHKIT_TEAM_ALPHA_KEY" => {
                Some(base64::engine::general_purpose::STANDARD.encode([7_u8; 32]))
            }
            "SCORCHKIT_TEAM_ALPHA_TOKEN" => Some("t".repeat(32)),
            _ => None,
        })
        .expect("prepare");
        assert_eq!(prepared.authenticate(&"t".repeat(32)).expect("binding").cell_id, "alpha");
        assert!(prepared.authenticate(&"x".repeat(32)).is_none());
        let debug = format!("{prepared:?}");
        assert!(debug.contains("PreparedTeamService"));
        assert!(debug.contains("binding_count: 1"));
        assert!(!debug.contains(&"t".repeat(32)));
        assert!(!debug.contains("postgresql:///alpha"));

        let cell_debug = format!("{:?}", prepared.cells[0]);
        assert!(cell_debug.contains("PreparedCell"));
        assert!(cell_debug.contains("cell_id: \"alpha\""));
        assert!(cell_debug.contains("key_ids: [\"primary\"]"));
        assert!(!cell_debug.contains("postgresql:///alpha"));

        let binding_debug = format!("{:?}", prepared.bindings[0]);
        assert!(binding_debug.contains("PreparedBinding"));
        assert!(binding_debug.contains("subject: \"operator@example.test\""));
        assert!(binding_debug.contains("role: Operator"));
        assert!(!binding_debug.contains("token_digest"));
    }

    #[test]
    fn duplicate_actual_bearers_and_invalid_keys_fail_without_echoing_values() {
        let directory = tempfile::tempdir().expect("root");
        let mut duplicate_config = config(directory.path());
        duplicate_config.bindings.push(TeamPrincipalBindingConfig {
            subject: "second@example.test".into(),
            cell_id: "alpha".into(),
            role: TeamRoleV1::Reader,
            token_env: "SCORCHKIT_TEAM_SECOND_TOKEN".into(),
        });
        let error = PreparedTeamService::from_config_with(&duplicate_config, |name| match name {
            "SCORCHKIT_TEAM_ALPHA_DATABASE" => Some("postgresql:///alpha".into()),
            "SCORCHKIT_TEAM_ALPHA_KEY" => Some("not-a-key".into()),
            _ => Some("t".repeat(32)),
        })
        .expect_err("invalid key");
        assert!(!error.to_string().contains("not-a-key"));

        let duplicate =
            PreparedTeamService::from_config_with(&duplicate_config, |name| match name {
                "SCORCHKIT_TEAM_ALPHA_DATABASE" => Some("postgresql:///alpha".into()),
                "SCORCHKIT_TEAM_ALPHA_KEY" => {
                    Some(base64::engine::general_purpose::STANDARD.encode([7_u8; 32]))
                }
                _ => Some("t".repeat(32)),
            })
            .expect_err("duplicate bearer values");
        assert!(duplicate.to_string().contains("secret values must be unique"));

        let mut reused_key = config(directory.path());
        reused_key.cells[0].keys.push(TeamKeyReferenceConfig {
            key_id: "secondary".into(),
            key_env: "SCORCHKIT_TEAM_ALPHA_SECONDARY_KEY".into(),
        });
        let duplicate_key = PreparedTeamService::from_config_with(&reused_key, |name| match name {
            "SCORCHKIT_TEAM_ALPHA_DATABASE" => Some("postgresql:///alpha".into()),
            "SCORCHKIT_TEAM_ALPHA_TOKEN" => Some("t".repeat(32)),
            _ => Some(base64::engine::general_purpose::STANDARD.encode([7_u8; 32])),
        })
        .expect_err("duplicate key values");
        assert!(duplicate_key.to_string().contains("secret values must be unique"));
    }

    #[test]
    fn bearer_validation_exercises_every_length_and_character_clause() {
        assert!(validate_token(&"a".repeat(MIN_BEARER_BYTES)).is_ok());
        assert!(validate_token(&"a".repeat(MAX_BEARER_BYTES)).is_ok());
        assert!(validate_token(&"a".repeat(MIN_BEARER_BYTES - 1)).is_err());
        assert!(validate_token(&"a".repeat(MAX_BEARER_BYTES + 1)).is_err());
        assert!(validate_token(&format!("{} ", "a".repeat(MIN_BEARER_BYTES - 1))).is_err());
        assert!(validate_token(&format!("{}\u{7f}", "a".repeat(MIN_BEARER_BYTES - 1))).is_err());
        assert!(validate_token(&format!("{}é", "a".repeat(MIN_BEARER_BYTES - 2))).is_err());
    }

    #[test]
    fn database_environment_rejects_empty_and_padded_values_independently() {
        for database_url in [String::new(), " postgresql:///alpha".to_string()] {
            let directory = tempfile::tempdir().expect("root");
            let config = config(directory.path());
            let error = PreparedTeamService::from_config_with(&config, |name| match name {
                "SCORCHKIT_TEAM_ALPHA_DATABASE" => Some(database_url.clone()),
                "SCORCHKIT_TEAM_ALPHA_KEY" => {
                    Some(base64::engine::general_purpose::STANDARD.encode([7_u8; 32]))
                }
                "SCORCHKIT_TEAM_ALPHA_TOKEN" => Some("t".repeat(32)),
                _ => None,
            })
            .expect_err("malformed database value");
            assert!(error.to_string().contains("is malformed"));
        }
    }
}
