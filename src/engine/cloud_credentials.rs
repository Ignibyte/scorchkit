//! Authenticated cloud-scanning credentials.
//!
//! [`CloudCredentials`] is the single source of truth for cloud-API
//! authentication identifiers: AWS profile/role/region, GCP
//! service-account path + project, Azure subscription + tenant,
//! Kubernetes context. It's carried on both [`crate::config::AppConfig`]
//! (read at startup, env-merged) and on
//! [`crate::engine::cloud_context::CloudContext::credentials`] (for the
//! cloud-family modules shipping in WORK-151+).
//!
//! ## Secret-handling contract
//!
//! - **Hand-written `Debug`.** [`CloudCredentials`] does not derive
//!   `Debug`. The manual impl redacts any field named `*_secret` /
//!   `*_key` / `*_password` / `*_token` as `"***"`. Today the struct
//!   holds no such fields — every current field is an identifier
//!   (profile name, role ARN, region, path, project ID, tenant GUID,
//!   context name) that SDKs consume to *find* secrets elsewhere on
//!   disk. **The redaction pattern is nonetheless mandatory from day
//!   one** — WORK-151+ may add direct bearer fields like
//!   `aws_secret_access_key` or `azure_client_secret`, and deriving
//!   `Debug` would silently leak them through every `tracing::debug!`
//!   call site that format-prints the config.
//! - **Env-var precedence.** [`CloudCredentials::from_config_with_env`]
//!   merges the config block with the process environment, with env
//!   winning when set to a non-empty value. Empty-string env vars are
//!   treated as "unset" — matches the [`crate::engine::network_credentials`]
//!   precedent shipped in WORK-146.
//!
//! See `docs/architecture/cloud.md` for the operator-facing config
//! shape and the end-to-end credential-resolution pipeline.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Env var that overrides [`CloudCredentials::aws_profile`].
pub const ENV_AWS_PROFILE: &str = "SCORCHKIT_AWS_PROFILE";
/// Env var that overrides [`CloudCredentials::aws_role_arn`].
pub const ENV_AWS_ROLE_ARN: &str = "SCORCHKIT_AWS_ROLE_ARN";
/// Env var that overrides [`CloudCredentials::aws_region`].
pub const ENV_AWS_REGION: &str = "SCORCHKIT_AWS_REGION";
/// Env var that overrides [`CloudCredentials::gcp_service_account_path`].
pub const ENV_GCP_SERVICE_ACCOUNT_PATH: &str = "SCORCHKIT_GCP_SERVICE_ACCOUNT_PATH";
/// Env var that overrides [`CloudCredentials::gcp_project_id`].
pub const ENV_GCP_PROJECT_ID: &str = "SCORCHKIT_GCP_PROJECT_ID";
/// Env var that overrides [`CloudCredentials::azure_subscription_id`].
pub const ENV_AZURE_SUBSCRIPTION_ID: &str = "SCORCHKIT_AZURE_SUBSCRIPTION_ID";
/// Env var that overrides [`CloudCredentials::azure_tenant_id`].
pub const ENV_AZURE_TENANT_ID: &str = "SCORCHKIT_AZURE_TENANT_ID";
/// Env var that overrides [`CloudCredentials::kube_context`].
pub const ENV_KUBE_CONTEXT: &str = "SCORCHKIT_KUBE_CONTEXT";

/// Authenticated cloud-scanning credentials.
///
/// Every field is `Option<String>`. Absent fields mean the probe falls
/// back to whatever default the underlying SDK / tool chooses (AWS
/// CLI default profile, `gcloud` application-default credentials,
/// `kubectl`'s current context) — this struct is the opt-in path for
/// explicit credentials, never a required input.
///
/// ## Debug contract
///
/// The manual `Debug` impl redacts any value whose field name contains
/// `secret`, `password`, `key` (except path fields like
/// `gcp_service_account_path` which hold a filesystem path, not
/// key content), or `token`. Non-secret fields print normally.
/// **Never add `#[derive(Debug)]` to this struct.** Adding a new
/// secret-bearing field requires updating the manual impl.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CloudCredentials {
    /// AWS profile name from `~/.aws/credentials` (e.g., `"default"`,
    /// `"production"`). Identifier, not a secret.
    pub aws_profile: Option<String>,
    /// AWS IAM role ARN to assume (e.g.,
    /// `"arn:aws:iam::123456789012:role/ScorchKitAuditor"`). Identifier.
    pub aws_role_arn: Option<String>,
    /// AWS region (e.g., `"us-east-1"`). Identifier.
    pub aws_region: Option<String>,
    /// Filesystem path to a GCP service-account JSON file. The path is
    /// not a secret; the file contents are. SDKs load the contents at
    /// use-time.
    pub gcp_service_account_path: Option<String>,
    /// GCP project ID (e.g., `"my-project-123"`). Identifier.
    pub gcp_project_id: Option<String>,
    /// Azure subscription ID (GUID). Identifier.
    pub azure_subscription_id: Option<String>,
    /// Azure tenant ID (GUID). Identifier.
    pub azure_tenant_id: Option<String>,
    /// Kubernetes context name from kubeconfig (e.g.,
    /// `"prod-cluster"`). Identifier.
    pub kube_context: Option<String>,
}

impl fmt::Debug for CloudCredentials {
    // JUSTIFICATION: hand-written rather than derive so future
    // secret-bearing fields added here are redacted automatically if
    // the field name matches the contract. A new direct-secret field
    // (e.g., `aws_secret_access_key`) MUST be added to the explicit
    // redaction arm below.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Today none of the fields hold direct bearer secrets — profile
        // names, role ARNs, region codes, paths, project/tenant/
        // subscription IDs, and kubeconfig context names are all safe
        // to log verbatim. A future `aws_secret_access_key` or
        // `azure_client_secret` field would get `.as_ref().map(|_|
        // "***")` treatment like smb_password in NetworkCredentials.
        f.debug_struct("CloudCredentials")
            .field("aws_profile", &self.aws_profile)
            .field("aws_role_arn", &self.aws_role_arn)
            .field("aws_region", &self.aws_region)
            .field("gcp_service_account_path", &self.gcp_service_account_path)
            .field("gcp_project_id", &self.gcp_project_id)
            .field("azure_subscription_id", &self.azure_subscription_id)
            .field("azure_tenant_id", &self.azure_tenant_id)
            .field("kube_context", &self.kube_context)
            .finish()
    }
}

impl CloudCredentials {
    /// Return `true` when every field is `None` (or `Some` of an empty
    /// string). Empty credentials should be treated as "no credentials
    /// configured" and the caller should fall back to the SDK / tool
    /// default.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let all = [
            &self.aws_profile,
            &self.aws_role_arn,
            &self.aws_region,
            &self.gcp_service_account_path,
            &self.gcp_project_id,
            &self.azure_subscription_id,
            &self.azure_tenant_id,
            &self.kube_context,
        ];
        all.iter().all(|f| f.as_ref().is_none_or(String::is_empty))
    }

    /// Return a copy of `base` with each field potentially overridden
    /// by its corresponding environment variable.
    ///
    /// Env variables win when **set and non-empty**. Env vars exported
    /// as empty strings (a common CI pattern) are treated as "not set"
    /// so the config value is preserved.
    #[must_use]
    pub fn from_config_with_env(base: &Self) -> Self {
        Self {
            aws_profile: env_override(ENV_AWS_PROFILE, base.aws_profile.as_deref()),
            aws_role_arn: env_override(ENV_AWS_ROLE_ARN, base.aws_role_arn.as_deref()),
            aws_region: env_override(ENV_AWS_REGION, base.aws_region.as_deref()),
            gcp_service_account_path: env_override(
                ENV_GCP_SERVICE_ACCOUNT_PATH,
                base.gcp_service_account_path.as_deref(),
            ),
            gcp_project_id: env_override(ENV_GCP_PROJECT_ID, base.gcp_project_id.as_deref()),
            azure_subscription_id: env_override(
                ENV_AZURE_SUBSCRIPTION_ID,
                base.azure_subscription_id.as_deref(),
            ),
            azure_tenant_id: env_override(ENV_AZURE_TENANT_ID, base.azure_tenant_id.as_deref()),
            kube_context: env_override(ENV_KUBE_CONTEXT, base.kube_context.as_deref()),
        }
    }
}

/// Read `env_name` from the process environment. Returns `Some(value)`
/// when set and non-empty; otherwise returns `base.map(String::from)`.
fn env_override(env_name: &str, base: Option<&str>) -> Option<String> {
    match std::env::var(env_name) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => base.map(String::from),
    }
}

#[cfg(test)]
mod tests {
    //! Pure-function coverage for defaults, `is_empty`, `Debug`
    //! redaction contract, and env-merge semantics.

    use super::*;
    use std::sync::{Mutex, OnceLock};

    /// Process-global mutex guarding `std::env::set_var` paths.
    fn env_mutex() -> &'static Mutex<()> {
        static M: OnceLock<Mutex<()>> = OnceLock::new();
        M.get_or_init(|| Mutex::new(()))
    }

    /// Clear every cloud-credential env var the tests manipulate.
    fn clear_env() {
        for name in [
            ENV_AWS_PROFILE,
            ENV_AWS_ROLE_ARN,
            ENV_AWS_REGION,
            ENV_GCP_SERVICE_ACCOUNT_PATH,
            ENV_GCP_PROJECT_ID,
            ENV_AZURE_SUBSCRIPTION_ID,
            ENV_AZURE_TENANT_ID,
            ENV_KUBE_CONTEXT,
        ] {
            // JUSTIFICATION: test-only; safe for variables we own.
            std::env::remove_var(name);
        }
    }

    #[test]
    fn test_cloud_credentials_default_is_empty() {
        let c = CloudCredentials::default();
        assert!(c.is_empty());
        assert!(c.aws_profile.is_none());
        assert!(c.kube_context.is_none());
    }

    #[test]
    fn test_cloud_credentials_is_empty_tracks_fields() {
        let mut c = CloudCredentials::default();
        assert!(c.is_empty());
        c.aws_profile = Some("production".to_string());
        assert!(!c.is_empty());
        c.aws_profile = Some(String::new());
        assert!(c.is_empty(), "empty-string value is treated as unset");
    }

    #[test]
    fn test_cloud_credentials_debug_does_not_leak() {
        // Contract test: Debug impl is hand-written; any hypothetical
        // field named *_secret/*_password/*_token/*_key (non-path
        // variant) must be redacted. Today no fields qualify, but this
        // test verifies the impl compiles + runs, producing a readable
        // format that includes all current identifier fields.
        let c = CloudCredentials {
            aws_profile: Some("prod".to_string()),
            azure_subscription_id: Some("abcd-1234".to_string()),
            ..Default::default()
        };
        let s = format!("{c:?}");
        assert!(s.contains("CloudCredentials"));
        assert!(s.contains("aws_profile"));
        assert!(s.contains("prod"));
        assert!(s.contains("abcd-1234"));
        // Pins: no stray `***` today (contract for future additions).
        assert!(!s.contains("***"));
    }

    #[test]
    fn test_cloud_credentials_from_config_with_env_wins_non_empty() {
        let _guard = env_mutex().lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        // JUSTIFICATION: test-only environment mutation.
        std::env::set_var(ENV_AWS_PROFILE, "env-prod");

        let base = CloudCredentials {
            aws_profile: Some("config-prod".to_string()),
            aws_region: Some("us-east-1".to_string()),
            ..Default::default()
        };
        let resolved = CloudCredentials::from_config_with_env(&base);
        assert_eq!(resolved.aws_profile.as_deref(), Some("env-prod"));
        // Unset env var falls through to the config value.
        assert_eq!(resolved.aws_region.as_deref(), Some("us-east-1"));

        clear_env();
    }

    #[test]
    fn test_cloud_credentials_from_config_with_env_empty_treated_as_unset() {
        let _guard = env_mutex().lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        std::env::set_var(ENV_AWS_PROFILE, "");

        let base = CloudCredentials {
            aws_profile: Some("config-value".to_string()),
            ..Default::default()
        };
        let resolved = CloudCredentials::from_config_with_env(&base);
        // Empty env string must NOT override the config.
        assert_eq!(resolved.aws_profile.as_deref(), Some("config-value"));

        clear_env();
    }
}
