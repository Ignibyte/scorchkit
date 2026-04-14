//! CVE backend configuration.
//!
//! [`CveConfig`] is the `[cve]` block of `config.toml`. It carries a
//! [`CveBackendKind`] discriminant plus a [`NvdConfig`] sub-block that
//! describes how to talk to the NIST NVD 2.0 API.
//!
//! Defaults: [`CveBackendKind::Disabled`]. Operators opt in by setting
//! `backend = "nvd"` (or `"mock"` for fixture-based testing) and, for
//! NVD, optionally an `api_key` and `cache_dir`. Without an API key the
//! NVD backend uses NVD's anonymous quota (5 requests / 30 seconds).
//!
//! The lookup factory in [`crate::infra::cve_lookup::build_cve_lookup`]
//! consumes this block to construct a boxed [`crate::engine::cve::CveLookup`].

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level CVE configuration block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CveConfig {
    /// Which backend to use for CVE correlation.
    pub backend: CveBackendKind,
    /// NVD-specific configuration. Read only when `backend == Nvd`.
    pub nvd: NvdConfig,
}

/// Discriminant for CVE backend selection.
///
/// `Disabled` is the default — no CVE module is wired into `assess` and
/// the `cve_match` module is not present in the orchestrator. `Mock`
/// returns a fixture-backed [`crate::infra::cve_mock::MockCveLookup`]
/// (useful for examples and demos). `Nvd` returns a live
/// [`crate::infra::cve_nvd::NvdCveLookup`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CveBackendKind {
    /// CVE correlation off. No module added.
    #[default]
    Disabled,
    /// Empty fixture-backed lookup. Used in examples and tests.
    Mock,
    /// NIST NVD 2.0 CPE search.
    Nvd,
}

/// NVD-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NvdConfig {
    /// Optional NVD API key. Can be overridden by the
    /// `SCORCHKIT_NVD_API_KEY` environment variable, which takes
    /// precedence so operators can ship config files without leaking
    /// secrets. Without a key the anonymous quota (5 req/30s) applies.
    pub api_key: Option<String>,
    /// Override the NVD endpoint base URL. Used by the integration test
    /// suite to point at an `httpmock` server. Defaults to
    /// `https://services.nvd.nist.gov`.
    pub base_url: Option<String>,
    /// Override the cache directory. Defaults to
    /// `$XDG_CACHE_HOME/scorchkit/cve` (or `$HOME/.cache/scorchkit/cve`,
    /// or `./cve-cache` if neither environment variable is set).
    pub cache_dir: Option<PathBuf>,
    /// Cache TTL in seconds. Default: 86400 (24h). Negative caching uses
    /// the same TTL — empty result sets are persisted.
    pub cache_ttl_secs: u64,
}

impl Default for NvdConfig {
    fn default() -> Self {
        Self { api_key: None, base_url: None, cache_dir: None, cache_ttl_secs: 86_400 }
    }
}

#[cfg(test)]
mod tests {
    //! Coverage for `[cve]` config defaults and TOML round-trip.
    //!
    //! These tests pin the contract every other layer relies on: the
    //! default backend is `Disabled`, the default cache TTL is 24 hours,
    //! and a hand-written `[cve]` + `[cve.nvd]` TOML block deserializes
    //! into the typed structs without losing fields.

    use super::*;

    /// Default `CveConfig` is `Disabled` with a no-key NVD sub-config.
    /// Pins the safe-by-default contract: no network calls without
    /// explicit opt-in.
    #[test]
    fn cve_config_default_is_disabled() {
        let cfg = CveConfig::default();
        assert_eq!(cfg.backend, CveBackendKind::Disabled);
        assert!(cfg.nvd.api_key.is_none());
        assert!(cfg.nvd.base_url.is_none());
        assert!(cfg.nvd.cache_dir.is_none());
        assert_eq!(cfg.nvd.cache_ttl_secs, 86_400);
    }

    /// A `[cve]` + `[cve.nvd]` TOML block round-trips through serde. This
    /// is the user-facing schema contract — if this test breaks, an
    /// existing `config.toml` will break too.
    #[test]
    fn cve_config_toml_round_trip() {
        let toml_str = r#"
backend = "nvd"

[nvd]
api_key = "abc-123"
base_url = "http://127.0.0.1:9999"
cache_dir = "/tmp/cve"
cache_ttl_secs = 3600
"#;
        let cfg: CveConfig = toml::from_str(toml_str).expect("parse TOML");
        assert_eq!(cfg.backend, CveBackendKind::Nvd);
        assert_eq!(cfg.nvd.api_key.as_deref(), Some("abc-123"));
        assert_eq!(cfg.nvd.base_url.as_deref(), Some("http://127.0.0.1:9999"));
        assert_eq!(cfg.nvd.cache_dir.as_deref(), Some(std::path::Path::new("/tmp/cve")));
        assert_eq!(cfg.nvd.cache_ttl_secs, 3600);
    }

    /// `CveBackendKind` serialises lowercase. Pins the user-facing string
    /// values that `config.toml` uses (`"disabled"`, `"mock"`, `"nvd"`).
    #[test]
    fn cve_backend_kind_serde_lowercase() {
        for (kind, expected) in [
            (CveBackendKind::Disabled, "\"disabled\""),
            (CveBackendKind::Mock, "\"mock\""),
            (CveBackendKind::Nvd, "\"nvd\""),
        ] {
            let s = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(s, expected);
            let back: CveBackendKind = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, kind);
        }
    }
}
