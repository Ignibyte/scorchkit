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
    /// OSV-specific configuration. Read only when `backend == Osv`.
    pub osv: OsvConfig,
    /// Composite-backend configuration. Read only when
    /// `backend == Composite`. Lists the sub-backends to fan out to;
    /// each sub-backend reads its own `[cve.nvd]` / `[cve.osv]`
    /// sub-block at construction time.
    pub composite: CompositeConfig,
}

// (`OsvConfig` documented at its definition below.)

/// Discriminant for CVE backend selection.
///
/// `Disabled` is the default — no CVE module is wired into `assess` and
/// the `cve_match` module is not present in the orchestrator. `Mock`
/// returns a fixture-backed [`crate::infra::cve_mock::MockCveLookup`]
/// (useful for examples and demos). `Nvd` returns a live
/// [`crate::infra::cve_nvd::NvdCveLookup`]. `Composite` returns a
/// [`crate::infra::cve_multi::MultiCveLookup`] wrapping the
/// sub-backends listed in [`CompositeConfig::sources`].
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
    /// `OSV.dev` v1 query API. Best for language-package CVEs (`npm`,
    /// `PyPI`, `Maven`, ...). Requires CPE → ecosystem translation;
    /// system-software CPEs are skipped.
    Osv,
    /// Fan-out aggregator across multiple sub-backends with dedup by
    /// canonical CVE ID. Consults the `[cve.composite]` sub-block.
    Composite,
}

/// A single sub-backend selected inside [`CompositeConfig::sources`].
///
/// This enum is intentionally **flat** — there is no `Composite`
/// variant, which makes nested Composite construction structurally
/// impossible and removes the need for a runtime nesting check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompositeSource {
    /// Include an [`crate::infra::cve_nvd::NvdCveLookup`] built from `[cve.nvd]`.
    Nvd,
    /// Include an [`crate::infra::cve_osv::OsvCveLookup`] built from `[cve.osv]`.
    Osv,
    /// Include an empty [`crate::infra::cve_mock::MockCveLookup`] (useful in tests).
    Mock,
}

/// Configuration for the Composite backend.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CompositeConfig {
    /// Sub-backends to fan out to. Order is preserved in the dedup
    /// pass — ties on canonical CVE ID + CVSS score go to whichever
    /// source appears first. Must be non-empty when
    /// `backend == Composite` (the factory enforces this).
    pub sources: Vec<CompositeSource>,
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
    /// Enable delta-sync mode. When `true` and a cache entry exists
    /// for a CPE, subsequent queries fetch only records modified since
    /// the cache was written (`lastModStartDate = fetched_at − 1h`) and
    /// merge them with the cached set. Reduces NVD load + scan latency
    /// for operators running frequent scans. Default: `false`.
    pub delta_sync: bool,
}

impl Default for NvdConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            base_url: None,
            cache_dir: None,
            cache_ttl_secs: 86_400,
            delta_sync: false,
        }
    }
}

/// OSV-specific configuration.
///
/// OSV is intentionally keyless (per their FAQ), so there is no
/// `api_key` field. The conservative `max_rps` default of 10 sits well
/// under OSV's documented ~25 QPS fair-use cap to leave headroom for
/// their hidden adaptive throttling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OsvConfig {
    /// Override the OSV endpoint base URL. Used by the integration
    /// test suite to point at an `httpmock` server. Defaults to
    /// `https://api.osv.dev`.
    pub base_url: Option<String>,
    /// Override the cache directory. Defaults to
    /// `$XDG_CACHE_HOME/scorchkit/cve-osv` (or
    /// `$HOME/.cache/scorchkit/cve-osv`, or `./cve-osv-cache` if
    /// neither environment variable is set). Distinct from the NVD
    /// cache to prevent cross-contamination.
    pub cache_dir: Option<PathBuf>,
    /// Cache TTL in seconds. Default: 86400 (24h). Negative caching
    /// uses the same TTL — empty result sets and unmapped CPEs are
    /// persisted.
    pub cache_ttl_secs: u64,
    /// Maximum requests per second. Default: 10 (well under OSV's
    /// ~25 QPS fair-use cap).
    pub max_rps: u32,
}

impl Default for OsvConfig {
    fn default() -> Self {
        Self { base_url: None, cache_dir: None, cache_ttl_secs: 86_400, max_rps: 10 }
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
        assert!(!cfg.nvd.delta_sync, "delta_sync defaults to false (safe-by-default)");
    }

    /// `delta_sync` round-trips through `[cve.nvd]` TOML.
    #[test]
    fn nvd_config_delta_sync_toml_round_trip() {
        let toml_str = r#"
backend = "nvd"

[nvd]
delta_sync = true
cache_ttl_secs = 3600
"#;
        let cfg: CveConfig = toml::from_str(toml_str).expect("parse TOML");
        assert!(cfg.nvd.delta_sync);
        assert_eq!(cfg.nvd.cache_ttl_secs, 3600);
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
    /// values that `config.toml` uses (`"disabled"`, `"mock"`, `"nvd"`,
    /// `"osv"`, `"composite"`).
    #[test]
    fn cve_backend_kind_serde_lowercase() {
        for (kind, expected) in [
            (CveBackendKind::Disabled, "\"disabled\""),
            (CveBackendKind::Mock, "\"mock\""),
            (CveBackendKind::Nvd, "\"nvd\""),
            (CveBackendKind::Osv, "\"osv\""),
            (CveBackendKind::Composite, "\"composite\""),
        ] {
            let s = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(s, expected);
            let back: CveBackendKind = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, kind);
        }
    }

    /// `CompositeSource` serialises lowercase (`"nvd"` / `"osv"` /
    /// `"mock"`) — the operator-facing TOML vocabulary matches
    /// `CveBackendKind`, minus the `Composite` value (flat by design).
    #[test]
    fn composite_source_serde_lowercase() {
        for (kind, expected) in [
            (CompositeSource::Nvd, "\"nvd\""),
            (CompositeSource::Osv, "\"osv\""),
            (CompositeSource::Mock, "\"mock\""),
        ] {
            let s = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(s, expected);
            let back: CompositeSource = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, kind);
        }
    }

    /// `CompositeConfig::default` has no sources. Pins the contract
    /// `build_cve_lookup` relies on when rejecting
    /// `backend = "composite"` without a populated sources list.
    #[test]
    fn composite_config_default_empty_sources() {
        let cfg = CompositeConfig::default();
        assert!(cfg.sources.is_empty());
    }

    /// `[cve] backend = "composite"` + `[cve.composite] sources = [...]`
    /// round-trips through serde. User-facing schema contract.
    #[test]
    fn composite_config_toml_round_trip() {
        let toml_str = r#"
backend = "composite"

[composite]
sources = ["nvd", "osv"]
"#;
        let cfg: CveConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.backend, CveBackendKind::Composite);
        assert_eq!(cfg.composite.sources, vec![CompositeSource::Nvd, CompositeSource::Osv]);
    }

    /// Default `OsvConfig` matches the documented contract: 24h TTL,
    /// 10 RPS, no overrides. This contract is referenced from
    /// `docs/modules/cve-osv.md` — the test pins it.
    #[test]
    fn osv_config_default() {
        let cfg = OsvConfig::default();
        assert!(cfg.base_url.is_none());
        assert!(cfg.cache_dir.is_none());
        assert_eq!(cfg.cache_ttl_secs, 86_400);
        assert_eq!(cfg.max_rps, 10);
    }

    /// A `[cve.osv]` TOML block round-trips through serde, including
    /// every documented field. User-facing schema contract.
    #[test]
    fn osv_config_toml_round_trip() {
        let toml_str = r#"
backend = "osv"

[osv]
base_url = "http://127.0.0.1:9999"
cache_dir = "/tmp/cve-osv"
cache_ttl_secs = 3600
max_rps = 5
"#;
        let cfg: CveConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.backend, CveBackendKind::Osv);
        assert_eq!(cfg.osv.base_url.as_deref(), Some("http://127.0.0.1:9999"));
        assert_eq!(cfg.osv.cache_dir.as_deref(), Some(std::path::Path::new("/tmp/cve-osv")));
        assert_eq!(cfg.osv.cache_ttl_secs, 3600);
        assert_eq!(cfg.osv.max_rps, 5);
    }
}
