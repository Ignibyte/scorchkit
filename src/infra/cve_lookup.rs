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

use crate::config::AppConfig;
use crate::config::{CompositeSource, CveBackendKind};
use crate::engine::cve::CveLookup;
use crate::engine::error::{Result, ScorchError};

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
pub fn build_cve_lookup(config: &AppConfig) -> Result<Option<Box<dyn CveLookup>>> {
    match config.cve.backend {
        CveBackendKind::Disabled => Ok(None),
        CveBackendKind::Mock => Ok(Some(Box::new(MockCveLookup::new()))),
        CveBackendKind::Nvd => {
            let lookup = NvdCveLookup::from_config(&config.cve.nvd)?;
            Ok(Some(Box::new(lookup)))
        }
        CveBackendKind::Osv => {
            let lookup = OsvCveLookup::from_config(&config.cve.osv)?;
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
                built.push(build_composite_source(*source, config)?);
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
) -> Result<Box<dyn CveLookup>> {
    match source {
        CompositeSource::Nvd => {
            let lookup = NvdCveLookup::from_config(&config.cve.nvd)?;
            Ok(Box::new(lookup))
        }
        CompositeSource::Osv => {
            let lookup = OsvCveLookup::from_config(&config.cve.osv)?;
            Ok(Box::new(lookup))
        }
        CompositeSource::Mock => Ok(Box::new(MockCveLookup::new())),
    }
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

    /// Default config (backend = Disabled) yields `None`. The
    /// orchestrator then skips wiring the CVE module entirely — the
    /// safe-by-default path.
    #[test]
    fn build_cve_lookup_disabled_returns_none() {
        let cfg = AppConfig::default();
        let result = build_cve_lookup(&cfg).expect("ok");
        assert!(result.is_none());
    }

    /// `Mock` backend yields a usable, empty lookup. Demonstrates that
    /// the factory hands callers a working `Box<dyn CveLookup>` without
    /// requiring fixture seeding (operators can layer that on later).
    #[tokio::test]
    async fn build_cve_lookup_mock_returns_mock() {
        let mut cfg = AppConfig::default();
        cfg.cve.backend = CveBackendKind::Mock;
        let lookup = build_cve_lookup(&cfg).expect("ok").expect("some");
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
        let result = build_cve_lookup(&cfg).expect("ok");
        assert!(result.is_some(), "Nvd backend should yield Some(Box<dyn CveLookup>)");
    }

    /// `Osv` backend yields a real `OsvCveLookup`. Construction is
    /// non-network — exercises the dispatch arm without hitting OSV.
    #[test]
    fn build_cve_lookup_osv_returns_osv() {
        let mut cfg = AppConfig::default();
        cfg.cve.backend = CveBackendKind::Osv;
        let result = build_cve_lookup(&cfg).expect("ok");
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
        let result = build_cve_lookup(&cfg).expect("ok");
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
        match build_cve_lookup(&cfg) {
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
