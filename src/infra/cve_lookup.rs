//! Backend factory for [`CveLookup`].
//!
//! [`build_cve_lookup`] reads [`crate::config::cve::CveConfig`] and
//! returns a boxed [`CveLookup`] (or `None` when the backend is
//! `Disabled`). This is the single entry point the orchestrator uses
//! to decide whether to attach a [`crate::infra::cve_match::CveMatchModule`].
//!
//! Keeping construction in one place means new backends (e.g. an
//! `OsvCveLookup` later) only require extending this factory and
//! [`crate::config::cve::CveBackendKind`] — no plumbing changes
//! ripple through the orchestrator or the assess command.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::AppConfig;
use crate::config::{CompositeSource, CveBackendKind};
use crate::engine::cve::CveLookup;
use crate::engine::error::{Result, ScorchError};
use crate::engine::policy::{Capability, EffectClass, Engagement, PolicyTarget};

use crate::infra::cve_mock::MockCveLookup;
use crate::infra::cve_multi::MultiCveLookup;
use crate::infra::cve_nvd::NvdCveLookup;
use crate::infra::cve_osv::OsvCveLookup;

/// Build the configured CVE lookup, or `None` when CVE correlation is
/// disabled.
///
/// `Disabled` → `None`. `Mock` → an empty [`MockCveLookup`] (callers
/// can `.with_fixture` on the mock if they need seeded data, but that
/// belongs in tests, not in this factory). `Nvd` → an
/// [`NvdCveLookup`] built from [`crate::config::cve::NvdConfig`].
///
/// # Errors
///
/// Returns whatever error the underlying backend constructor returns —
/// typically [`crate::engine::error::ScorchError::Config`] when the
/// HTTP client cannot be built.
pub fn build_cve_lookup(
    config: &AppConfig,
    engagement: Arc<Engagement>,
) -> Result<Option<Box<dyn CveLookup>>> {
    match config.cve.backend {
        CveBackendKind::Disabled => Ok(None),
        CveBackendKind::Mock => Ok(Some(Box::new(MockCveLookup::new()))),
        CveBackendKind::Nvd => {
            let lookup = NvdCveLookup::from_config(&config.cve.nvd, engagement)?;
            Ok(Some(Box::new(lookup)))
        }
        CveBackendKind::Osv => {
            let lookup = OsvCveLookup::from_config(&config.cve.osv, engagement)?;
            Ok(Some(Box::new(lookup)))
        }
        CveBackendKind::Composite => {
            let sources = &config.cve.composite.sources;
            if sources.is_empty() {
                return Err(ScorchError::Config(
                    "cve.composite.sources must not be empty when backend = \"composite\""
                        .to_string(),
                ));
            }
            let mut built: Vec<Box<dyn CveLookup>> = Vec::with_capacity(sources.len());
            for source in sources {
                built.push(build_composite_source(*source, config, Arc::clone(&engagement))?);
            }
            Ok(Some(Box::new(MultiCveLookup::new(built))))
        }
    }
}

/// Build one sub-backend for inclusion in a [`MultiCveLookup`].
///
/// The flat shape of [`CompositeSource`] (Nvd / Osv / Mock) means
/// nested Composite construction is structurally impossible — there's
/// no branch here that recurses.
fn build_composite_source(
    source: CompositeSource,
    config: &AppConfig,
    engagement: Arc<Engagement>,
) -> Result<Box<dyn CveLookup>> {
    match source {
        CompositeSource::Nvd => {
            let lookup = NvdCveLookup::from_config(&config.cve.nvd, engagement)?;
            Ok(Box::new(lookup))
        }
        CompositeSource::Osv => {
            let lookup = OsvCveLookup::from_config(&config.cve.osv, engagement)?;
            Ok(Box::new(lookup))
        }
        CompositeSource::Mock => Ok(Box::new(MockCveLookup::new())),
    }
}

/// Authorize a CVE provider endpoint and its cache directory without
/// creating either network or filesystem resources.
pub(crate) fn authorize_cve_resources(
    engagement: &Engagement,
    base_url: &str,
    cache_dir: &Path,
) -> Result<(url::Url, PathBuf)> {
    let PolicyTarget::Web(endpoint) = PolicyTarget::web(base_url).map_err(|error| {
        ScorchError::Config(format!("invalid CVE backend URL '{base_url}': {error}"))
    })?
    else {
        unreachable!("PolicyTarget::web always returns a web target");
    };
    engagement
        .authorize(PolicyTarget::Web(endpoint.clone()), Capability::InfraScan, EffectClass::Passive)
        .require()?;

    let canonical_cache = cache_dir.canonicalize().map_err(|error| {
        ScorchError::Config(format!(
            "CVE cache directory '{}' must exist before it can be authorized: {error}",
            cache_dir.display()
        ))
    })?;
    engagement
        .authorize(
            PolicyTarget::Code(canonical_cache.clone()),
            Capability::InfraScan,
            EffectClass::Passive,
        )
        .require()?;
    Ok((endpoint, canonical_cache))
}

#[cfg(test)]
mod tests {
    //! Coverage for the lookup factory dispatch table.
    //!
    //! Each test pins one branch of the `CveBackendKind` match: making
    //! sure `Disabled` returns `None`, `Mock` returns a working mock,
    //! and `Nvd` returns a real backend (without making network calls
    //! — `from_config` is non-blocking).

    use super::*;
    use crate::config::AppConfig;
    use crate::config::CveBackendKind;
    use crate::engine::policy::EngagementPolicy;
    use crate::engine::scope::ScopeRule;

    fn empty_engagement() -> Arc<Engagement> {
        Arc::new(Engagement::new("no effects", EngagementPolicy::default()))
    }

    fn authorize_fixture_backends(cfg: &mut AppConfig) -> (tempfile::TempDir, Arc<Engagement>) {
        let cache = tempfile::tempdir().expect("fixture cache");
        cfg.cve.nvd.base_url = Some("http://127.0.0.1:9".to_string());
        cfg.cve.nvd.cache_dir = Some(cache.path().to_path_buf());
        cfg.cve.osv.base_url = Some("http://127.0.0.1:9".to_string());
        cfg.cve.osv.cache_dir = Some(cache.path().to_path_buf());
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("127.0.0.1").expect("loopback scope"))
            .allow_scope(ScopeRule::path_prefix(cache.path()).expect("cache scope"))
            .allow_capability(Capability::InfraScan)
            .allow_effect(EffectClass::Passive);
        (cache, Arc::new(Engagement::new("CVE factory fixture", policy)))
    }

    /// Default config (backend = Disabled) yields `None`. The
    /// orchestrator then skips wiring the CVE module entirely — the
    /// safe-by-default path.
    #[test]
    fn build_cve_lookup_disabled_returns_none() {
        let cfg = AppConfig::default();
        let result = build_cve_lookup(&cfg, empty_engagement()).expect("ok");
        assert!(result.is_none());
    }

    /// `Mock` backend yields a usable, empty lookup. Demonstrates that
    /// the factory hands callers a working `Box<dyn CveLookup>` without
    /// requiring fixture seeding (operators can layer that on later).
    #[tokio::test]
    async fn build_cve_lookup_mock_returns_mock() {
        let mut cfg = AppConfig::default();
        cfg.cve.backend = CveBackendKind::Mock;
        let lookup = build_cve_lookup(&cfg, empty_engagement()).expect("ok").expect("some");
        // The empty mock returns no records for any CPE.
        let records = lookup.query("cpe:2.3:a:nope:nope:0:*:*:*:*:*:*:*").await.expect("query");
        assert!(records.is_empty());
    }

    /// `Nvd` backend yields a real `NvdCveLookup`. Construction is
    /// non-network, so this test runs in CI without hitting NIST.
    #[test]
    fn build_cve_lookup_nvd_returns_nvd() {
        let mut cfg = AppConfig::default();
        cfg.cve.backend = CveBackendKind::Nvd;
        let (_cache, engagement) = authorize_fixture_backends(&mut cfg);
        let result = build_cve_lookup(&cfg, engagement).expect("ok");
        assert!(result.is_some(), "Nvd backend should yield Some(Box<dyn CveLookup>)");
    }

    /// `Osv` backend yields a real `OsvCveLookup`. Construction is
    /// non-network — exercises the dispatch arm without hitting OSV.
    #[test]
    fn build_cve_lookup_osv_returns_osv() {
        let mut cfg = AppConfig::default();
        cfg.cve.backend = CveBackendKind::Osv;
        let (_cache, engagement) = authorize_fixture_backends(&mut cfg);
        let result = build_cve_lookup(&cfg, engagement).expect("ok");
        assert!(result.is_some(), "Osv backend should yield Some(Box<dyn CveLookup>)");
    }

    /// `Composite` with non-empty sources yields a real `MultiCveLookup`.
    /// Construction is non-network (each sub-backend's `from_config`
    /// is non-blocking) so this test runs in CI without hitting NVD
    /// or OSV.
    #[test]
    fn build_cve_lookup_composite_returns_multi() {
        let mut cfg = AppConfig::default();
        cfg.cve.backend = CveBackendKind::Composite;
        cfg.cve.composite.sources =
            vec![crate::config::CompositeSource::Nvd, crate::config::CompositeSource::Mock];
        let (_cache, engagement) = authorize_fixture_backends(&mut cfg);
        let result = build_cve_lookup(&cfg, engagement).expect("ok");
        assert!(result.is_some(), "Composite backend should yield Some(Box<dyn CveLookup>)");
    }

    /// `Composite` with an empty sources list errors at factory time
    /// rather than silently producing a no-op lookup. Pins the
    /// user-facing contract — misconfiguring fails loud.
    #[test]
    fn build_cve_lookup_composite_empty_sources_errors() {
        let mut cfg = AppConfig::default();
        cfg.cve.backend = CveBackendKind::Composite;
        cfg.cve.composite.sources.clear();
        // `expect_err` needs `Debug` on the Ok side, which
        // `Box<dyn CveLookup>` doesn't implement; match on the Result
        // directly instead.
        match build_cve_lookup(&cfg, empty_engagement()) {
            Err(crate::engine::error::ScorchError::Config(msg)) => {
                assert!(
                    msg.contains("composite.sources"),
                    "message should mention the misconfigured field: {msg}"
                );
            }
            Err(other) => panic!("expected Config error, got {other:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }
}
