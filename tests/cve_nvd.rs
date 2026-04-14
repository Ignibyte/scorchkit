//! End-to-end integration tests for [`scorchkit::infra::cve_nvd::NvdCveLookup`].
//!
//! These tests stand up an [`httpmock::MockServer`] in the test
//! process, point a real `NvdCveLookup` at it via
//! [`scorchkit::config::cve::NvdConfig::base_url`], and exercise the
//! lookup through the public [`scorchkit::engine::cve::CveLookup`]
//! trait. There is no live network — the fixture files under
//! `tests/fixtures/nvd/` are the source of truth for the response
//! shape we parse.
//!
//! The third test (`nvd_lookup_live_smoke`) hits real NVD when a key
//! is present in the environment and is `#[ignore]`-gated so it does
//! not run as part of the default suite. Operators can run it on
//! demand with `cargo test --features infra -- --ignored cve_nvd_live`.

#![cfg(feature = "infra")]

use std::env;
use std::sync::Arc;

use httpmock::Method::GET;
use httpmock::MockServer;

use scorchkit::config::cve::NvdConfig;
use scorchkit::config::AppConfig;
use scorchkit::engine::cve::CveLookup;
use scorchkit::engine::infra_context::InfraContext;
use scorchkit::engine::infra_module::InfraModule;
use scorchkit::engine::infra_target::InfraTarget;
use scorchkit::engine::service_fingerprint::{publish_fingerprints, ServiceFingerprint};
use scorchkit::infra::cve_match::CveMatchModule;
use scorchkit::infra::cve_nvd::NvdCveLookup;

const NGINX_CPE: &str = "cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*";
const UNKNOWN_CPE: &str = "cpe:2.3:a:unknownvendor:unknownproduct:0.0.0:*:*:*:*:*:*:*";
const NGINX_FIXTURE: &str = include_str!("fixtures/nvd/nginx_cve_response.json");
const EMPTY_FIXTURE: &str = include_str!("fixtures/nvd/empty_response.json");

/// Build a fresh `InfraContext` rooted at 127.0.0.1.
fn ctx() -> InfraContext {
    let target = InfraTarget::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let config = Arc::new(AppConfig::default());
    let client = reqwest::Client::builder().build().expect("client");
    InfraContext::new(target, config, client)
}

/// Build a `ServiceFingerprint` carrying a CPE — the field
/// [`scorchkit::infra::cve_match::CveMatchModule`] reads.
fn nginx_fingerprint() -> ServiceFingerprint {
    ServiceFingerprint {
        port: 80,
        protocol: "tcp".into(),
        service_name: "http".into(),
        product: Some("nginx".into()),
        version: Some("1.25.3".into()),
        cpe: Some(NGINX_CPE.to_string()),
    }
}

/// End-to-end happy path: mock server returns two CVEs for an nginx
/// CPE; the module emits one finding per CVE with the expected IDs.
#[tokio::test]
async fn nvd_lookup_against_mock_server_emits_findings() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path("/rest/json/cves/2.0").query_param("cpeName", NGINX_CPE);
        then.status(200).header("content-type", "application/json").body(NGINX_FIXTURE);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = NvdConfig {
        api_key: None,
        base_url: Some(server.base_url()),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        cache_ttl_secs: 3600,
    };
    let lookup = NvdCveLookup::from_config(&cfg).expect("build lookup");
    let module = CveMatchModule::new(Box::new(lookup));

    let ctx = ctx();
    publish_fingerprints(&ctx.shared_data, &[nginx_fingerprint()]);
    let findings = module.run(&ctx).await.expect("run");

    mock.assert_calls(1);
    assert_eq!(findings.len(), 2, "expected one finding per CVE in fixture");
    assert!(findings.iter().any(|f| f.title.contains("CVE-2024-7347")));
    assert!(findings.iter().any(|f| f.title.contains("CVE-2023-44487")));
}

/// Cache hit: a second module run replays from disk and never hits
/// the mock again. Pins the load-bearing optimisation that keeps
/// repeat scans inside the rate budget.
#[tokio::test]
async fn nvd_lookup_caches_after_first_query() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path("/rest/json/cves/2.0").query_param("cpeName", NGINX_CPE);
        then.status(200).header("content-type", "application/json").body(NGINX_FIXTURE);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = NvdConfig {
        api_key: None,
        base_url: Some(server.base_url()),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        cache_ttl_secs: 3600,
    };
    let lookup = NvdCveLookup::from_config(&cfg).expect("build lookup");

    // Two direct trait calls — bypasses module overhead so the cache
    // assertion is precise.
    let first = lookup.query(NGINX_CPE).await.expect("first query");
    let second = lookup.query(NGINX_CPE).await.expect("second query");
    assert_eq!(first.len(), 2);
    assert_eq!(first.len(), second.len());
    mock.assert_calls(1); // second call served from cache
}

/// Negative caching: an empty NVD response is persisted and replayed
/// out of the cache on subsequent calls. Without this, every CPE that
/// has zero CVEs would burn one request per scan.
#[tokio::test]
async fn nvd_lookup_empty_response_is_negative_cached() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path("/rest/json/cves/2.0").query_param("cpeName", UNKNOWN_CPE);
        then.status(200).header("content-type", "application/json").body(EMPTY_FIXTURE);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = NvdConfig {
        api_key: None,
        base_url: Some(server.base_url()),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        cache_ttl_secs: 3600,
    };
    let lookup = NvdCveLookup::from_config(&cfg).expect("build lookup");

    let first = lookup.query(UNKNOWN_CPE).await.expect("first");
    let second = lookup.query(UNKNOWN_CPE).await.expect("second");
    assert!(first.is_empty());
    assert!(second.is_empty());
    mock.assert_calls(1);
}

/// Live smoke test against real NVD. `#[ignore]`-gated so it never
/// runs in the default suite. Run on demand with:
///
/// ```text
/// SCORCHKIT_NVD_API_KEY=... cargo test --features infra -- \
///     --ignored cve_nvd_live
/// ```
///
/// Asserts only that the call returns successfully — the live result
/// set changes day-to-day and we don't pin specific CVE IDs.
#[tokio::test]
#[ignore = "live network — requires SCORCHKIT_NVD_API_KEY"]
async fn nvd_lookup_live_smoke() {
    if env::var("SCORCHKIT_NVD_API_KEY").is_err() {
        eprintln!("skipping live test: SCORCHKIT_NVD_API_KEY not set");
        return;
    }
    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = NvdConfig {
        api_key: None, // env var carries the key
        base_url: None,
        cache_dir: Some(cache_dir.path().to_path_buf()),
        cache_ttl_secs: 3600,
    };
    let lookup = NvdCveLookup::from_config(&cfg).expect("build lookup");
    // A historically vulnerable nginx version — should return at least one CVE.
    let cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*";
    let records = lookup.query(cpe).await.expect("live query");
    assert!(!records.is_empty(), "real NVD should return CVEs for {cpe}");
}
