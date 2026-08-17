//! End-to-end integration tests for [`scorchkit::infra::cve_osv::OsvCveLookup`].
//!
//! These tests stand up an [`httpmock::MockServer`], point a real
//! `OsvCveLookup` at it via [`scorchkit::config::cve::OsvConfig::base_url`],
//! and exercise the lookup through the public
//! [`scorchkit::engine::cve::CveLookup`] trait. There is no live
//! network — `tests/fixtures/osv/*.json` are the source of truth for
//! the OSV v1 response shape we parse.
//!
//! The final test (`osv_lookup_live_smoke`) hits real api.osv.dev and
//! is `#[ignore]`-gated so it does not run as part of the default
//! suite. Run on demand with `cargo test --features infra --
//! --ignored cve_osv_live`.

#![cfg(feature = "infra")]

use std::sync::Arc;

use httpmock::Method::POST;
use httpmock::MockServer;

use scorchkit::config::cve::OsvConfig;
use scorchkit::config::AppConfig;
use scorchkit::engine::cve::CveLookup;
use scorchkit::engine::infra_context::InfraContext;
use scorchkit::engine::infra_module::InfraModule;
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::service_fingerprint::{publish_fingerprints, ServiceFingerprint};
use scorchkit::infra::cve_match::CveMatchModule;
use scorchkit::infra::cve_osv::{OsvCveLookup, DEFAULT_BASE_URL};
use scorchkit::{Engine, ScopeRule, ScorchError};

const EXPRESS_CPE: &str = "cpe:2.3:a:expressjs:express:4.17.0:*:*:*:*:*:*:*";
const NGINX_CPE: &str = "cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*";
const EXPRESS_FIXTURE: &str = include_str!("fixtures/osv/express_query_response.json");
const EMPTY_FIXTURE: &str = include_str!("fixtures/osv/empty_response.json");

/// Build a fresh `InfraContext` rooted at 127.0.0.1.
fn ctx() -> scorchkit::Result<InfraContext> {
    let config = Arc::new(AppConfig::default());
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::Exact("127.0.0.1".to_string()))
        .allow_capability(Capability::InfraScan)
        .allow_capability(Capability::ExternalTool)
        .allow_effect(EffectClass::ActiveSafe);
    Engine::for_engagement(config, Arc::new(Engagement::new("cve fixture", policy)))
        .infra_context("127.0.0.1")
}

fn lookup_engagement(cfg: &OsvConfig) -> scorchkit::Result<Arc<Engagement>> {
    let base_url = cfg.base_url.as_deref().unwrap_or(DEFAULT_BASE_URL);
    let endpoint = url::Url::parse(base_url)
        .map_err(|error| ScorchError::Config(format!("fixture backend URL: {error}")))?;
    let host = endpoint
        .host_str()
        .ok_or_else(|| ScorchError::Config("fixture backend has no host".to_string()))?
        .to_string();
    let cache_dir = cfg
        .cache_dir
        .as_deref()
        .ok_or_else(|| ScorchError::Config("fixture cache directory missing".to_string()))?;
    let policy = EngagementPolicy::default()
        .allow_scope(
            ScopeRule::parse(&host)
                .ok_or_else(|| ScorchError::Config("invalid backend host scope".to_string()))?,
        )
        .allow_scope(ScopeRule::path_prefix(cache_dir)?)
        .allow_capability(Capability::InfraScan)
        .allow_effect(EffectClass::Passive);
    Ok(Arc::new(Engagement::new("authorized CVE fixture", policy)))
}

async fn live_lookup_engagement(cfg: &OsvConfig) -> scorchkit::Result<Arc<Engagement>> {
    let base_url = cfg.base_url.as_deref().unwrap_or(DEFAULT_BASE_URL);
    let endpoint = url::Url::parse(base_url)
        .map_err(|error| ScorchError::Config(format!("live backend URL: {error}")))?;
    let host = endpoint
        .host_str()
        .ok_or_else(|| ScorchError::Config("live backend has no host".to_string()))?;
    let port = endpoint
        .port_or_known_default()
        .ok_or_else(|| ScorchError::Config("live backend has no port".to_string()))?;
    let mut engagement = (*lookup_engagement(cfg)?).clone();
    for address in tokio::net::lookup_host((host, port)).await? {
        let rule = ScopeRule::parse(&address.ip().to_string())
            .ok_or_else(|| ScorchError::Config("invalid resolved address scope".to_string()))?;
        engagement.policy.allowed_scope.push(rule);
    }
    Ok(Arc::new(engagement))
}

/// Build a `ServiceFingerprint` carrying a CPE.
fn fingerprint_with_cpe(cpe: &str, product: &str, version: &str) -> ServiceFingerprint {
    ServiceFingerprint {
        port: 3000,
        protocol: "tcp".into(),
        service_name: "http".into(),
        product: Some(product.into()),
        version: Some(version.into()),
        cpe: Some(cpe.to_string()),
    }
}

/// Build an `OsvConfig` pointed at `mock_url` with the given tempdir
/// for cache.
const fn mock_config(mock_url: String, cache_dir: std::path::PathBuf) -> OsvConfig {
    OsvConfig {
        base_url: Some(mock_url),
        cache_dir: Some(cache_dir),
        cache_ttl_secs: 3600,
        max_rps: 10,
    }
}

/// End-to-end happy path: mock server returns one CVE for an express
/// CPE; the module emits one finding with the expected ID.
#[tokio::test]
async fn osv_lookup_against_mock_server_emits_findings() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/v1/query");
        then.status(200).header("content-type", "application/json").body(EXPRESS_FIXTURE);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = mock_config(server.base_url(), cache_dir.path().to_path_buf());
    let lookup = OsvCveLookup::from_config(
        &cfg,
        lookup_engagement(&cfg).expect("authorized lookup fixture"),
    )
    .expect("build lookup");
    let module = CveMatchModule::new(Box::new(lookup));

    let ctx = ctx().expect("authorized infra fixture");
    publish_fingerprints(
        &ctx.shared_data,
        &[fingerprint_with_cpe(EXPRESS_CPE, "express", "4.17.0")],
    );
    let findings = module.run(&ctx).await.expect("run");

    mock.assert_calls(1);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].title.contains("GHSA-rv95-896h-c2vc"));
}

/// Cache hit: a second module run replays from disk and never hits
/// the mock again. Pins the load-bearing optimisation.
#[tokio::test]
async fn osv_lookup_caches_after_first_query() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/v1/query");
        then.status(200).header("content-type", "application/json").body(EXPRESS_FIXTURE);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = mock_config(server.base_url(), cache_dir.path().to_path_buf());
    let lookup = OsvCveLookup::from_config(
        &cfg,
        lookup_engagement(&cfg).expect("authorized lookup fixture"),
    )
    .expect("build lookup");

    let first = lookup.query(EXPRESS_CPE).await.expect("first");
    let second = lookup.query(EXPRESS_CPE).await.expect("second");
    assert_eq!(first.len(), 1);
    assert_eq!(first.len(), second.len());
    mock.assert_calls(1);
}

/// Negative caching: an empty OSV response is persisted and replayed
/// from cache on subsequent calls.
#[tokio::test]
async fn osv_lookup_empty_response_is_negative_cached() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/v1/query");
        then.status(200).header("content-type", "application/json").body(EMPTY_FIXTURE);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = mock_config(server.base_url(), cache_dir.path().to_path_buf());
    let lookup = OsvCveLookup::from_config(
        &cfg,
        lookup_engagement(&cfg).expect("authorized lookup fixture"),
    )
    .expect("build lookup");

    let first = lookup.query(EXPRESS_CPE).await.expect("first");
    let second = lookup.query(EXPRESS_CPE).await.expect("second");
    assert!(first.is_empty());
    assert!(second.is_empty());
    mock.assert_calls(1);
}

/// Unmapped CPE (nginx is system software, no OSV ecosystem) should
/// short-circuit before any HTTP request goes out — operators don't
/// burn the rate budget on CPEs OSV can't satisfy.
#[tokio::test]
async fn osv_lookup_unmapped_cpe_returns_empty_no_request() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/v1/query");
        then.status(200).header("content-type", "application/json").body(EMPTY_FIXTURE);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = mock_config(server.base_url(), cache_dir.path().to_path_buf());
    let lookup = OsvCveLookup::from_config(
        &cfg,
        lookup_engagement(&cfg).expect("authorized lookup fixture"),
    )
    .expect("build lookup");

    let records = lookup.query(NGINX_CPE).await.expect("query");
    assert!(records.is_empty());
    mock.assert_calls(0); // no HTTP request issued
}

/// Live smoke test against real api.osv.dev. `#[ignore]`-gated.
/// Asserts only that the call returns successfully — OSV's data
/// drifts day-to-day and we don't pin specific GHSA IDs.
#[tokio::test]
#[ignore = "live network — hits api.osv.dev"]
async fn osv_lookup_live_smoke() {
    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = OsvConfig {
        base_url: None,
        cache_dir: Some(cache_dir.path().to_path_buf()),
        cache_ttl_secs: 3600,
        max_rps: 5,
    };
    let engagement = live_lookup_engagement(&cfg).await.expect("authorize live lookup");
    let lookup = OsvCveLookup::from_config(&cfg, engagement).expect("build lookup");
    // express 4.17.0 has known historical CVEs in the OSV index.
    let cpe = "cpe:2.3:a:expressjs:express:4.17.0:*:*:*:*:*:*:*";
    let records = lookup.query(cpe).await.expect("live query");
    assert!(!records.is_empty(), "real OSV should return vulns for {cpe}");
}
