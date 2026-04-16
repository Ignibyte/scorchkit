//! Authenticated network scanning credentials.
//!
//! [`NetworkCredentials`] is the single source of truth for authenticated
//! network-layer probes: SSH, SMB, SNMP, and Kerberos. It's carried on
//! both `AppConfig` (read by every tool wrapper via `ctx.config`) and on
//! [`crate::engine::infra_context::InfraContext::credentials`] (for
//! future native infra-family probes).
//!
//! ## Secret-handling contract
//!
//! - **Hand-written `Debug`.** [`NetworkCredentials`] does not derive
//!   `Debug`. The manual impl redacts [`NetworkCredentials::smb_password`]
//!   and [`NetworkCredentials::snmp_community`] as `"***"`. Adding a
//!   new secret-bearing field REQUIRES updating the manual impl — a
//!   future `#[derive(Debug)]` would silently leak the field through
//!   every log and `tracing` event that format-prints the config.
//! - **Env-var precedence.** [`NetworkCredentials::from_config_with_env`]
//!   merges the config block with the process environment, with env
//!   winning when set to a non-empty value. Empty-string env vars are
//!   treated as "unset" — matches the [`crate::config::NvdConfig::api_key`]
//!   / `SCORCHKIT_NVD_API_KEY` convention shipped in WORK-103b and
//!   prevents the common CI pitfall where a variable is exported
//!   unconditionally even when the secret is absent.
//! - **Log redaction.** Tool wrappers that pass secrets via argv call
//!   [`format_redacted_argv`] when emitting `debug!` logs so secrets
//!   never surface in log output. Argv passed to the actual subprocess
//!   stays verbatim — we can't redact what the child tool will read.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Env var that overrides [`NetworkCredentials::ssh_user`].
pub const ENV_SSH_USER: &str = "SCORCHKIT_SSH_USER";
/// Env var that overrides [`NetworkCredentials::ssh_key_path`].
pub const ENV_SSH_KEY_PATH: &str = "SCORCHKIT_SSH_KEY_PATH";
/// Env var that overrides [`NetworkCredentials::smb_username`].
pub const ENV_SMB_USERNAME: &str = "SCORCHKIT_SMB_USERNAME";
/// Env var that overrides [`NetworkCredentials::smb_password`].
pub const ENV_SMB_PASSWORD: &str = "SCORCHKIT_SMB_PASSWORD";
/// Env var that overrides [`NetworkCredentials::snmp_community`].
pub const ENV_SNMP_COMMUNITY: &str = "SCORCHKIT_SNMP_COMMUNITY";
/// Env var that overrides [`NetworkCredentials::kerberos_principal`].
pub const ENV_KERBEROS_PRINCIPAL: &str = "SCORCHKIT_KERBEROS_PRINCIPAL";

/// Authenticated network scanning credentials.
///
/// Every field is `Option<String>`. Absent fields mean the probe falls
/// back to its unauthenticated default (null session / anonymous /
/// default community string / etc.) — this struct is the opt-in path
/// for authenticated scanning, never a required input.
///
/// ## Debug contract
///
/// The manual `Debug` impl redacts [`smb_password`] and
/// [`snmp_community`] as `"***"`. Non-secret fields print normally.
/// **Never add `#[derive(Debug)]` to this struct.**
///
/// [`smb_password`]: Self::smb_password
/// [`snmp_community`]: Self::snmp_community
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkCredentials {
    /// Username for SSH logins (e.g., `"root"`, `"admin"`).
    pub ssh_user: Option<String>,
    /// Filesystem path to an SSH private key file. Not a secret itself
    /// (the file contents are); the path is safe to log.
    pub ssh_key_path: Option<String>,
    /// Username for SMB authentication (e.g., `"DOMAIN\\alice"` or
    /// `"alice@DOMAIN"`).
    pub smb_username: Option<String>,
    /// SMB password. **Redacted in `Debug` output.**
    pub smb_password: Option<String>,
    /// SNMP v1/v2c community string (e.g., `"public"`, `"private"`).
    /// **Redacted in `Debug` output** — communities are bearer secrets.
    pub snmp_community: Option<String>,
    /// Kerberos principal (e.g., `"alice@CORP.EXAMPLE"`). Parsed by
    /// consumers to extract the domain portion when needed.
    pub kerberos_principal: Option<String>,
}

impl fmt::Debug for NetworkCredentials {
    // JUSTIFICATION: hand-written rather than derive so secret-bearing
    // fields are redacted at format time. A new field added here must
    // also decide whether to redact — review flags are intentional.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkCredentials")
            .field("ssh_user", &self.ssh_user)
            .field("ssh_key_path", &self.ssh_key_path)
            .field("smb_username", &self.smb_username)
            .field("smb_password", &self.smb_password.as_ref().map(|_| "***"))
            .field("snmp_community", &self.snmp_community.as_ref().map(|_| "***"))
            .field("kerberos_principal", &self.kerberos_principal)
            .finish()
    }
}

impl NetworkCredentials {
    /// Return `true` when every field is `None` (or `Some` of an empty
    /// string). Empty credentials should be treated as "no credentials
    /// configured" and the caller should fall back to the probe's
    /// unauthenticated default.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let all = [
            &self.ssh_user,
            &self.ssh_key_path,
            &self.smb_username,
            &self.smb_password,
            &self.snmp_community,
            &self.kerberos_principal,
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
            ssh_user: env_override(ENV_SSH_USER, base.ssh_user.as_deref()),
            ssh_key_path: env_override(ENV_SSH_KEY_PATH, base.ssh_key_path.as_deref()),
            smb_username: env_override(ENV_SMB_USERNAME, base.smb_username.as_deref()),
            smb_password: env_override(ENV_SMB_PASSWORD, base.smb_password.as_deref()),
            snmp_community: env_override(ENV_SNMP_COMMUNITY, base.snmp_community.as_deref()),
            kerberos_principal: env_override(
                ENV_KERBEROS_PRINCIPAL,
                base.kerberos_principal.as_deref(),
            ),
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

/// Format a command-line argv for `debug!` logging with values after
/// known secret-carrying flags redacted as `"***"`.
///
/// This does not mutate the argv passed to the subprocess — secrets
/// still reach the child tool. It only affects the string surfaced in
/// log output.
///
/// Secret flags recognized (case-sensitive): `-p`, `--password`, `-c`,
/// `--community`. The value immediately following any of these flags
/// is replaced with `"***"`.
#[must_use]
pub fn format_redacted_argv(args: &[&str]) -> String {
    const SECRET_FLAGS: &[&str] = &["-p", "--password", "-c", "--community"];
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            out.push("***".to_string());
            redact_next = false;
            continue;
        }
        if SECRET_FLAGS.contains(arg) {
            out.push((*arg).to_string());
            redact_next = true;
            continue;
        }
        out.push((*arg).to_string());
    }
    out.join(" ")
}

#[cfg(test)]
mod tests {
    //! Pure-function coverage for the redaction, env-merge, and
    //! `is_empty` helpers.
    //!
    //! Env-merge tests touch `std::env::set_var` which is process-global;
    //! they serialize on a single shared mutex to avoid races with
    //! other concurrent tests that read the same variables.

    use super::*;
    use std::sync::{Mutex, OnceLock};

    /// Process-global mutex guarding `std::env::set_var` test paths.
    /// Parallel tests serialize here so env-var state is deterministic.
    fn env_mutex() -> &'static Mutex<()> {
        static M: OnceLock<Mutex<()>> = OnceLock::new();
        M.get_or_init(|| Mutex::new(()))
    }

    /// Clear every credential env var that the tests manipulate. Keeps
    /// state between tests hermetic.
    fn clear_env() {
        for name in [
            ENV_SSH_USER,
            ENV_SSH_KEY_PATH,
            ENV_SMB_USERNAME,
            ENV_SMB_PASSWORD,
            ENV_SNMP_COMMUNITY,
            ENV_KERBEROS_PRINCIPAL,
        ] {
            // JUSTIFICATION: test-only. `remove_var` is safe in test
            // code for variables we own.
            // Note: no analog needed for SAFETY since set_var/remove_var
            // became safe in stable Rust.
            std::env::remove_var(name);
        }
    }

    // ---- Default + is_empty ----

    #[test]
    fn network_credentials_default_is_all_none() {
        let c = NetworkCredentials::default();
        assert!(c.ssh_user.is_none());
        assert!(c.ssh_key_path.is_none());
        assert!(c.smb_username.is_none());
        assert!(c.smb_password.is_none());
        assert!(c.snmp_community.is_none());
        assert!(c.kerberos_principal.is_none());
    }

    #[test]
    fn network_credentials_is_empty_tracks_fields() {
        let mut c = NetworkCredentials::default();
        assert!(c.is_empty());
        c.smb_username = Some("alice".to_string());
        assert!(!c.is_empty());
        c.smb_username = Some(String::new());
        assert!(c.is_empty(), "empty-string value is treated as unset");
    }

    // ---- Debug redaction ----

    #[test]
    fn network_credentials_debug_redacts_smb_password() {
        let c =
            NetworkCredentials { smb_password: Some("s3cr3t".to_string()), ..Default::default() };
        let s = format!("{c:?}");
        assert!(s.contains("***"), "expected redaction marker: {s}");
        assert!(!s.contains("s3cr3t"), "literal password leaked: {s}");
    }

    #[test]
    fn network_credentials_debug_redacts_snmp_community() {
        let c =
            NetworkCredentials { snmp_community: Some("public".to_string()), ..Default::default() };
        let s = format!("{c:?}");
        assert!(s.contains("***"));
        assert!(!s.contains("public"));
    }

    #[test]
    fn network_credentials_debug_shows_non_secrets() {
        let c = NetworkCredentials {
            ssh_user: Some("root".to_string()),
            ssh_key_path: Some("/home/alice/.ssh/id_ed25519".to_string()),
            smb_username: Some("DOMAIN\\alice".to_string()),
            kerberos_principal: Some("alice@CORP.EXAMPLE".to_string()),
            ..Default::default()
        };
        let s = format!("{c:?}");
        assert!(s.contains("root"));
        assert!(s.contains("/home/alice/.ssh/id_ed25519"));
        assert!(s.contains("DOMAIN\\\\alice"), "expected escaped backslash");
        assert!(s.contains("alice@CORP.EXAMPLE"));
    }

    // ---- from_config_with_env ----

    #[test]
    fn from_config_with_env_prefers_env() {
        let _g = env_mutex().lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        std::env::set_var(ENV_SMB_PASSWORD, "from-env");
        let base = NetworkCredentials {
            smb_password: Some("from-config".to_string()),
            ..Default::default()
        };
        let merged = NetworkCredentials::from_config_with_env(&base);
        assert_eq!(merged.smb_password.as_deref(), Some("from-env"));
        clear_env();
    }

    #[test]
    fn from_config_with_env_falls_through_to_config() {
        let _g = env_mutex().lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        let base =
            NetworkCredentials { smb_username: Some("alice".to_string()), ..Default::default() };
        let merged = NetworkCredentials::from_config_with_env(&base);
        assert_eq!(merged.smb_username.as_deref(), Some("alice"));
    }

    #[test]
    fn from_config_with_env_empty_env_treated_as_unset() {
        let _g = env_mutex().lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        std::env::set_var(ENV_SMB_PASSWORD, "");
        let base = NetworkCredentials {
            smb_password: Some("from-config".to_string()),
            ..Default::default()
        };
        let merged = NetworkCredentials::from_config_with_env(&base);
        assert_eq!(merged.smb_password.as_deref(), Some("from-config"));
        clear_env();
    }

    // ---- format_redacted_argv ----

    #[test]
    fn format_redacted_argv_redacts_password_flag() {
        let args = ["-u", "alice", "-p", "s3cret"];
        let out = format_redacted_argv(&args);
        assert_eq!(out, "-u alice -p ***");
    }

    #[test]
    fn format_redacted_argv_redacts_community_flag() {
        let args = ["-c", "public", "host"];
        let out = format_redacted_argv(&args);
        assert_eq!(out, "-c *** host");
    }

    #[test]
    fn format_redacted_argv_redacts_long_password_flag() {
        let args = ["--password", "hunter2"];
        let out = format_redacted_argv(&args);
        assert_eq!(out, "--password ***");
    }

    #[test]
    fn format_redacted_argv_preserves_non_secret_args() {
        let args = ["smb", "example.com", "-u", "alice", "--no-progress"];
        let out = format_redacted_argv(&args);
        assert_eq!(out, "smb example.com -u alice --no-progress");
    }

    #[test]
    fn format_redacted_argv_handles_trailing_secret_flag() {
        // No value follows `-p` — don't panic, don't fabricate output.
        let args = ["cmd", "-p"];
        let out = format_redacted_argv(&args);
        assert_eq!(out, "cmd -p");
    }

    #[test]
    fn format_redacted_argv_redacts_consecutive_secrets() {
        let args = ["-p", "a", "-c", "b"];
        let out = format_redacted_argv(&args);
        assert_eq!(out, "-p *** -c ***");
    }
}
