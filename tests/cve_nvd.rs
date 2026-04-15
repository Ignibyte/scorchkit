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
        delta_sync: false,
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
        delta_sync: false,
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
        delta_sync: false,
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
        delta_sync: false,
    };
    let lookup = NvdCveLookup::from_config(&cfg).expect("build lookup");
    // A historically vulnerable nginx version — should return at least one CVE.
    let cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*";
    let records = lookup.query(cpe).await.expect("live query");
    assert!(!records.is_empty(), "real NVD should return CVEs for {cpe}");
}

// =============================================================
// WORK-147: pagination + delta sync integration tests
// =============================================================

/// Build a minimal NVD response body with N synthetic CVEs and the
/// given `totalResults`. Used by the pagination tests to avoid
/// maintaining huge JSON fixtures in the repo.
fn build_page_body(total_results: usize, page_cves: &[(&str, &str)]) -> String {
    let mut vulns = String::new();
    for (i, (id, desc)) in page_cves.iter().enumerate() {
        if i > 0 {
            vulns.push(',');
        }
        vulns.push_str(&format!(
            r#"{{"cve":{{"id":"{id}","descriptions":[{{"lang":"en","value":"{desc}"}}]}}}}"#
        ));
    }
    format!(
        r#"{{"resultsPerPage":10,"startIndex":0,"totalResults":{total_results},"vulnerabilities":[{vulns}]}}"#
    )
}

/// Single-page query (totalResults == returned count): exactly one
/// HTTP call, no pagination loop.
#[tokio::test]
async fn nvd_pagination_single_page_no_extra_calls() {
    let server = MockServer::start_async().await;
    let cpe_small = "cpe:2.3:a:tiny:tiny:1.0:*:*:*:*:*:*:*";
    // totalResults == vulnerabilities.len() → loop must stop after one call.
    let body = build_page_body(1, &[("CVE-2024-0001", "tiny flaw")]);
    let mock = server.mock(|when, then| {
        when.method(GET).path("/rest/json/cves/2.0").query_param("cpeName", cpe_small);
        then.status(200).header("content-type", "application/json").body(body);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = NvdConfig {
        api_key: None,
        base_url: Some(server.base_url()),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        cache_ttl_secs: 3600,
        delta_sync: false,
    };
    let lookup = NvdCveLookup::from_config(&cfg).expect("build lookup");
    let records = lookup.query(cpe_small).await.expect("query");
    assert_eq!(records.len(), 1);
    mock.assert_calls(1);
}

/// Multi-page aggregation: first page has 10 records with
/// `totalResults=15`; second page has 5 records. Query must aggregate
/// to 15 records and advance `startIndex` on the second call.
#[tokio::test]
async fn nvd_pagination_multi_page_aggregates() {
    let server = MockServer::start_async().await;
    let cpe_big = "cpe:2.3:a:big:big:1.0:*:*:*:*:*:*:*";

    let page0: Vec<(&str, &str)> = (0..10)
        .map(|i| match i {
            0 => ("CVE-2024-A000", "page 0 first"),
            1 => ("CVE-2024-A001", "page 0"),
            2 => ("CVE-2024-A002", "page 0"),
            3 => ("CVE-2024-A003", "page 0"),
            4 => ("CVE-2024-A004", "page 0"),
            5 => ("CVE-2024-A005", "page 0"),
            6 => ("CVE-2024-A006", "page 0"),
            7 => ("CVE-2024-A007", "page 0"),
            8 => ("CVE-2024-A008", "page 0"),
            _ => ("CVE-2024-A009", "page 0 last"),
        })
        .collect();
    let page1: Vec<(&str, &str)> = (0..5)
        .map(|i| match i {
            0 => ("CVE-2024-B000", "page 1"),
            1 => ("CVE-2024-B001", "page 1"),
            2 => ("CVE-2024-B002", "page 1"),
            3 => ("CVE-2024-B003", "page 1"),
            _ => ("CVE-2024-B004", "page 1 last"),
        })
        .collect();
    let body0 = build_page_body(15, &page0);
    let body1 = build_page_body(15, &page1);

    let page0_mock = server.mock(|when, then| {
        when.method(GET)
            .path("/rest/json/cves/2.0")
            .query_param("cpeName", cpe_big)
            .query_param_missing("startIndex");
        then.status(200).header("content-type", "application/json").body(body0);
    });
    let page1_mock = server.mock(|when, then| {
        when.method(GET)
            .path("/rest/json/cves/2.0")
            .query_param("cpeName", cpe_big)
            .query_param("startIndex", "10");
        then.status(200).header("content-type", "application/json").body(body1);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = NvdConfig {
        api_key: None,
        base_url: Some(server.base_url()),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        cache_ttl_secs: 3600,
        delta_sync: false,
    };
    let lookup = NvdCveLookup::from_config(&cfg).expect("build lookup");
    let records = lookup.query(cpe_big).await.expect("query");
    assert_eq!(records.len(), 15, "pagination must aggregate all pages");
    page0_mock.assert_calls(1);
    page1_mock.assert_calls(1);
}

/// Zero-records page unconditionally breaks the loop even if
/// `totalResults` still claims more.
#[tokio::test]
async fn nvd_pagination_zero_records_breaks_loop() {
    let server = MockServer::start_async().await;
    let cpe_z = "cpe:2.3:a:zero:zero:1.0:*:*:*:*:*:*:*";
    // Bogus totalResults with an empty page — loop must not retry.
    let body = build_page_body(999, &[]);
    let mock = server.mock(|when, then| {
        when.method(GET).path("/rest/json/cves/2.0").query_param("cpeName", cpe_z);
        then.status(200).header("content-type", "application/json").body(body);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = NvdConfig {
        api_key: None,
        base_url: Some(server.base_url()),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        cache_ttl_secs: 3600,
        delta_sync: false,
    };
    let lookup = NvdCveLookup::from_config(&cfg).expect("build lookup");
    let records = lookup.query(cpe_z).await.expect("query");
    assert!(records.is_empty());
    mock.assert_calls(1);
}

/// With `delta_sync = false` and a cache hit, no HTTP call is made —
/// the cache is served as-is. Verifies the baseline behaviour is
/// unchanged when the flag is off.
#[tokio::test]
async fn nvd_delta_sync_disabled_skips_delta_query() {
    let server = MockServer::start_async().await;
    let cpe_cached = "cpe:2.3:a:cached:cached:1.0:*:*:*:*:*:*:*";
    let body = build_page_body(1, &[("CVE-2024-CACHED", "cached record")]);
    let mock = server.mock(|when, then| {
        when.method(GET).path("/rest/json/cves/2.0").query_param("cpeName", cpe_cached);
        then.status(200).header("content-type", "application/json").body(body);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = NvdConfig {
        api_key: None,
        base_url: Some(server.base_url()),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        cache_ttl_secs: 3600,
        delta_sync: false,
    };
    let lookup = NvdCveLookup::from_config(&cfg).expect("build lookup");

    // First query populates the cache.
    let _ = lookup.query(cpe_cached).await.expect("first query");
    // Second query hits the cache — no additional HTTP call.
    let records = lookup.query(cpe_cached).await.expect("second query");
    assert_eq!(records.len(), 1);
    mock.assert_calls(1);
}

/// With `delta_sync = true` and a cache hit, the query issues an
/// HTTP call carrying `lastModStartDate` and `lastModEndDate`.
#[tokio::test]
async fn nvd_delta_sync_enabled_cache_hit_issues_delta_query() {
    let server = MockServer::start_async().await;
    let cpe_delta = "cpe:2.3:a:delta:delta:1.0:*:*:*:*:*:*:*";
    let body0 = build_page_body(1, &[("CVE-2024-ORIGINAL", "original")]);
    let body1 = build_page_body(1, &[("CVE-2024-NEW", "arrived after cache write")]);

    // First call — no lastModStartDate, populates the cache.
    let initial = server.mock(|when, then| {
        when.method(GET)
            .path("/rest/json/cves/2.0")
            .query_param("cpeName", cpe_delta)
            .query_param_missing("lastModStartDate");
        then.status(200).header("content-type", "application/json").body(body0);
    });
    // Second call — delta-sync passes lastModStartDate + lastModEndDate.
    let delta = server.mock(|when, then| {
        when.method(GET)
            .path("/rest/json/cves/2.0")
            .query_param("cpeName", cpe_delta)
            .query_param_exists("lastModStartDate");
        then.status(200).header("content-type", "application/json").body(body1);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = NvdConfig {
        api_key: None,
        base_url: Some(server.base_url()),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        cache_ttl_secs: 3600,
        delta_sync: true,
    };
    let lookup = NvdCveLookup::from_config(&cfg).expect("build lookup");

    let _initial_records = lookup.query(cpe_delta).await.expect("first query populates cache");
    let merged = lookup.query(cpe_delta).await.expect("second query delta-syncs");
    // Merged result set must include both the cached original and the delta.
    let ids: Vec<&str> = merged.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"CVE-2024-ORIGINAL"), "cached record preserved: {ids:?}");
    assert!(ids.contains(&"CVE-2024-NEW"), "delta record merged: {ids:?}");
    initial.assert_calls(1);
    delta.assert_calls(1);
}

/// With `delta_sync = true` and no cache entry, the first query runs
/// as a full paginated fetch (no `lastModStartDate` param).
#[tokio::test]
async fn nvd_delta_sync_enabled_cache_miss_full_query() {
    let server = MockServer::start_async().await;
    let cpe_fresh = "cpe:2.3:a:fresh:fresh:1.0:*:*:*:*:*:*:*";
    let body = build_page_body(1, &[("CVE-2024-FRESH", "fresh record")]);
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/rest/json/cves/2.0")
            .query_param("cpeName", cpe_fresh)
            .query_param_missing("lastModStartDate");
        then.status(200).header("content-type", "application/json").body(body);
    });

    let cache_dir = tempfile::tempdir().expect("tempdir");
    let cfg = NvdConfig {
        api_key: None,
        base_url: Some(server.base_url()),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        cache_ttl_secs: 3600,
        delta_sync: true,
    };
    let lookup = NvdCveLookup::from_config(&cfg).expect("build lookup");
    let records = lookup.query(cpe_fresh).await.expect("query");
    assert_eq!(records.len(), 1);
    mock.assert_calls(1);
}
