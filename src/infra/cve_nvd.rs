//! NIST NVD 2.0 [`CveLookup`] backend.
//!
//! [`NvdCveLookup`] queries `services.nvd.nist.gov/rest/json/cves/2.0`
//! with a `cpeName` parameter, parses the response into [`CveRecord`]s,
//! caches them on disk via the crate-internal filesystem cache
//! (`crate::infra::cve_cache::FsCache`), and
//! rate-limits outbound requests via [`governor`] to NVD's published
//! quotas (5 req/30s without API key, 50 req/30s with key).
//!
//! ## Architectural notes
//!
//! - **Separate HTTP client.** This lookup builds its own
//!   [`reqwest::Client`] rather than reusing the per-scan client. The
//!   pen-test client carries the user's User-Agent, optional Burp
//!   proxy, and may have TLS verification disabled — none of those are
//!   appropriate for vendor API calls.
//! - **Cache hits skip the rate limiter.** The budget is for *network*
//!   requests; replaying records out of the cache is free.
//! - **Bad API key disables the key for the rest of the session.** If
//!   NVD returns 401/403 once we mark the key as broken (in-process
//!   only) so we don't burn the whole per-fingerprint loop on the same
//!   error — the next call falls back to the anonymous quota.
//! - **Negative caching.** Empty result sets are persisted (see
//!   [`crate::infra::cve_cache`]). Re-querying every empty CPE on
//!   every scan is the most expensive way to use the rate budget.
//! - **Pagination (WORK-147).** The query loop follows `startIndex`
//!   until `records.len() >= totalResults` or the hard
//!   [`MAX_PAGES`] cap trips. A zero-record page unconditionally
//!   breaks the loop so a misbehaving mirror can't trap us. Fixes the
//!   silent-truncation bug that cost records for CPEs matching more
//!   than one NVD page (2000 results).
//! - **Delta sync (WORK-147).** Opt-in via
//!   [`NvdConfig::delta_sync`](crate::config::NvdConfig). When
//!   enabled and a cache entry exists for a CPE, the query passes
//!   `lastModStartDate = fetched_at − 1h safety margin` so only
//!   records modified since the cache write are fetched; they're then
//!   merged into the cached set keyed by CVE ID (delta wins on
//!   collision — it's newer). The merged set is written back to the
//!   cache so subsequent scans continue to benefit.
//!
//! ## Environment overrides
//!
//! - `SCORCHKIT_NVD_API_KEY` — wins over
//!   [`crate::config::cve::NvdConfig::api_key`].

use std::collections::HashMap;
use std::env;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::config::cve::NvdConfig;
use crate::engine::cve::{severity_from_cvss, CveLookup, CveRecord};
use crate::engine::error::{Result, ScorchError};
use crate::engine::severity::Severity;
use crate::infra::cve_cache::FsCache;

/// Environment variable that overrides [`NvdConfig::api_key`].
pub const ENV_API_KEY: &str = "SCORCHKIT_NVD_API_KEY";

/// Default NVD endpoint base.
pub const DEFAULT_BASE_URL: &str = "https://services.nvd.nist.gov";

/// CVE search path appended to `base_url`.
const CVES_PATH: &str = "/rest/json/cves/2.0";

/// Hard cap on pages fetched for a single CPE query.
///
/// At the NVD default of 2000 results per page this is 20,000 records
/// — more than any real CPE returns today and plenty of headroom for
/// the biggest: `nginx`, `openssh`, `apache_httpd`. The cap exists to
/// contain damage if a misbehaving NVD mirror returns a bogus
/// `totalResults` and never advances past `startIndex`.
pub(crate) const MAX_PAGES: usize = 10;

/// Safety margin subtracted from the cache's `fetched_at_unix` when
/// building the `lastModStartDate` parameter for delta sync.
///
/// NVD returns records whose `lastModified` is at or after the
/// supplied timestamp. A small overlap with the cached set means we
/// may fetch a few records we already have — the merge path handles
/// this via dedup by CVE ID. The alternative (requesting the exact
/// cache write time) risks missing records written in the same second
/// as our cache entry if the NVD server clock is slightly ahead of
/// ours.
pub(crate) const DELTA_SAFETY_MARGIN_SECS: u64 = 3600;

/// NVD's anonymous quota — 5 requests per 30 seconds.
// JUSTIFICATION: NonZeroU32::new(5) on a positive literal cannot return
// None; the const-match pattern avoids a runtime unwrap/expect.
const QUOTA_NO_KEY_BURST: NonZeroU32 = match NonZeroU32::new(5) {
    Some(n) => n,
    None => unreachable!(),
};

/// NVD's authenticated quota — 50 requests per 30 seconds.
// JUSTIFICATION: as above, NonZeroU32::new(50) on a positive literal
// cannot return None.
const QUOTA_WITH_KEY_BURST: NonZeroU32 = match NonZeroU32::new(50) {
    Some(n) => n,
    None => unreachable!(),
};

/// 30-second window NVD documents for both quotas.
const QUOTA_PERIOD: Duration = Duration::from_secs(30);

/// Maximum NVD response size we accept. NVD pages cap at ~2000
/// vulnerabilities per call; 5 MB is well above the worst observed
/// payload and small enough to bound memory.
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// NIST NVD 2.0 implementation of [`CveLookup`].
pub struct NvdCveLookup {
    /// Resolved API key (env var > config). `None` means anonymous.
    api_key: Option<String>,
    /// In-process flag set when NVD returns 401/403; subsequent calls
    /// drop the key and use the anonymous quota.
    api_key_disabled: Arc<AtomicBool>,
    /// Endpoint base. Overridden by tests via [`NvdConfig::base_url`].
    base_url: String,
    /// Pre-configured HTTP client. Separate from the scan client.
    http: reqwest::Client,
    /// Token-bucket limiter sized to the appropriate quota.
    limiter: Arc<DirectLimiter>,
    /// On-disk TTL cache (or disabled cache).
    cache: FsCache,
    /// Whether delta-sync is enabled. See
    /// [`NvdConfig::delta_sync`](crate::config::NvdConfig).
    delta_sync: bool,
}

impl std::fmt::Debug for NvdCveLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NvdCveLookup")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<set>"))
            .finish_non_exhaustive()
    }
}

impl NvdCveLookup {
    /// Construct a lookup from a [`NvdConfig`] block.
    ///
    /// Resolves the API key via the
    /// [`SCORCHKIT_NVD_API_KEY`](ENV_API_KEY) env var (taking
    /// precedence) or the config field. Resolves the cache directory
    /// via the config field, then `XDG_CACHE_HOME`, then `HOME/.cache`,
    /// then `./cve-cache`. Sizes the rate limiter according to whether
    /// a key was resolved.
    ///
    /// # Errors
    ///
    /// Returns [`ScorchError::Config`] if the underlying
    /// [`reqwest::Client`] cannot be built.
    pub fn from_config(cfg: &NvdConfig) -> Result<Self> {
        let api_key = resolve_api_key(cfg);
        let base_url = cfg
            .base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();

        let user_agent = format!("ScorchKit-CVE/{}", env!("CARGO_PKG_VERSION"));
        let http = reqwest::Client::builder()
            .user_agent(user_agent)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ScorchError::Config(format!("nvd: failed to build http client: {e}")))?;

        let burst = if api_key.is_some() { QUOTA_WITH_KEY_BURST } else { QUOTA_NO_KEY_BURST };
        let limiter = Arc::new(RateLimiter::direct(quota_for_burst(burst)));

        let cache_dir = cfg.cache_dir.clone().unwrap_or_else(default_cache_dir);
        let cache = FsCache::new(cache_dir, Duration::from_secs(cfg.cache_ttl_secs));

        Ok(Self {
            api_key,
            api_key_disabled: Arc::new(AtomicBool::new(false)),
            base_url,
            http,
            limiter,
            cache,
            delta_sync: cfg.delta_sync,
        })
    }

    /// Effective API key for the current request — `None` if either
    /// unset or disabled by a prior 401/403.
    fn effective_api_key(&self) -> Option<&str> {
        if self.api_key_disabled.load(Ordering::Relaxed) {
            return None;
        }
        self.api_key.as_deref()
    }
}

#[async_trait]
impl CveLookup for NvdCveLookup {
    async fn query(&self, cpe: &str) -> Result<Vec<CveRecord>> {
        // Cache hit branch. With delta-sync disabled, serve straight
        // from cache. With delta-sync enabled, fetch only records
        // modified since the cache was written and merge.
        if let Some((cached_records, fetched_at)) = self.cache.get_with_meta(cpe) {
            if !self.delta_sync {
                return Ok(cached_records);
            }
            let delta_start_ts = fetched_at.saturating_sub(DELTA_SAFETY_MARGIN_SECS);
            let last_mod_start = format_last_mod_start(delta_start_ts);
            debug!(
                "nvd: delta-sync for {cpe} from lastModStartDate={last_mod_start} \
                 (cache write {fetched_at}, margin {DELTA_SAFETY_MARGIN_SECS}s)"
            );
            match self.fetch_all_pages(cpe, Some(last_mod_start.as_str())).await {
                Ok(delta) => {
                    let merged = merge_records_by_cve_id(cached_records.clone(), delta);
                    self.cache.put(cpe, &merged);
                    return Ok(merged);
                }
                Err(e) => {
                    warn!("nvd: delta-sync for {cpe} failed ({e}); serving cached records");
                    return Ok(cached_records);
                }
            }
        }

        // Cache miss — full paginated query.
        let records = self.fetch_all_pages(cpe, None).await?;
        self.cache.put(cpe, &records);
        Ok(records)
    }
}

impl NvdCveLookup {
    /// Fetch every page for `cpe`, optionally constrained to records
    /// modified since `last_mod_start` (RFC 3339). Aggregates records
    /// across pages up to [`MAX_PAGES`]; stops early on a zero-record
    /// page or when the accumulated count reaches `totalResults`.
    async fn fetch_all_pages(
        &self,
        cpe: &str,
        last_mod_start: Option<&str>,
    ) -> Result<Vec<CveRecord>> {
        let mut all_records = Vec::new();
        let mut start_index: usize = 0;
        for page_num in 0..MAX_PAGES {
            self.limiter.until_ready().await;
            let page = self.fetch_page(cpe, start_index, last_mod_start).await?;
            let page_len = page.records.len();
            debug!(
                "nvd: page {page_num} for {cpe} — {page_len} records, \
                 totalResults={} startIndex={start_index}",
                page.total_results
            );
            all_records.extend(page.records);
            if page_len == 0 {
                break;
            }
            if all_records.len() >= page.total_results {
                break;
            }
            start_index = all_records.len();
        }
        if start_index > 0 && all_records.len() == MAX_PAGES * 2000 {
            warn!(
                "nvd: pagination for {cpe} hit MAX_PAGES={MAX_PAGES} cap; \
                 {} records may be truncated",
                all_records.len()
            );
        }
        Ok(all_records)
    }

    /// Issue one HTTP call against the NVD CVE search endpoint and
    /// parse the response into a [`NvdPage`]. Applies the configured
    /// API key (if not disabled from a prior auth failure) and
    /// enforces the response-size cap.
    async fn fetch_page(
        &self,
        cpe: &str,
        start_index: usize,
        last_mod_start: Option<&str>,
    ) -> Result<NvdPage> {
        let url = format!("{}{}", self.base_url, CVES_PATH);
        let start_str = start_index.to_string();
        let mut query_pairs: Vec<(&str, &str)> = vec![("cpeName", cpe)];
        if start_index > 0 {
            query_pairs.push(("startIndex", &start_str));
        }
        let now_str;
        if let Some(lms) = last_mod_start {
            query_pairs.push(("lastModStartDate", lms));
            // NVD requires both bounds when either is supplied.
            now_str = format_last_mod_start(now_unix_secs());
            query_pairs.push(("lastModEndDate", now_str.as_str()));
        }

        let mut req = self.http.get(&url).query(&query_pairs);
        if let Some(key) = self.effective_api_key() {
            req = req.header("apiKey", key);
        }

        let resp =
            req.send().await.map_err(|e| ScorchError::Http { url: url.clone(), source: e })?;
        let status = resp.status();

        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            if self.api_key.is_some() {
                self.api_key_disabled.store(true, Ordering::Relaxed);
                warn!("nvd: API key rejected ({status}); disabling for this session");
            }
            return Err(ScorchError::Config(format!("nvd: auth rejected ({status})")));
        }
        if !status.is_success() {
            return Err(ScorchError::Config(format!("nvd: backend returned {status}")));
        }

        let bytes =
            resp.bytes().await.map_err(|e| ScorchError::Http { url: url.clone(), source: e })?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ScorchError::Config(format!(
                "nvd: response exceeded {MAX_RESPONSE_BYTES} bytes ({} received)",
                bytes.len()
            )));
        }

        parse_nvd_page(&bytes, cpe)
    }
}

/// Build a `Quota` for the given per-30s burst.
fn quota_for_burst(burst: NonZeroU32) -> Quota {
    // `with_period` divided so `burst` cells replenish across the
    // 30-second window — i.e. cells/30s == `burst`. We replenish 1 cell
    // per (30s / burst).
    let per_cell = QUOTA_PERIOD / burst.get();
    // JUSTIFICATION: with_period only returns None when the duration is
    // zero; per_cell > 0 because burst <= u32::MAX and QUOTA_PERIOD is
    // 30s. The let-else keeps us out of unwrap/expect territory.
    let Some(quota) = Quota::with_period(per_cell) else { unreachable!() };
    quota.allow_burst(burst)
}

/// Resolve effective API key: env var beats config.
fn resolve_api_key(cfg: &NvdConfig) -> Option<String> {
    if let Ok(v) = env::var(ENV_API_KEY) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    cfg.api_key.clone().filter(|s| !s.is_empty())
}

/// Default cache directory, honouring `XDG_CACHE_HOME` then `HOME`.
///
/// Falls back to `./cve-cache` so the lookup still works in containers
/// or sandboxes where neither variable is set.
fn default_cache_dir() -> PathBuf {
    if let Ok(xdg) = env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("scorchkit").join("cve");
        }
    }
    if let Ok(home) = env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".cache").join("scorchkit").join("cve");
        }
    }
    PathBuf::from("./cve-cache")
}

// ---------- response parsing ----------

/// One page of NVD response data.
///
/// Holds the parsed records plus the top-level `totalResults` so the
/// caller's pagination loop knows when to stop.
pub(crate) struct NvdPage {
    pub(crate) records: Vec<CveRecord>,
    pub(crate) total_results: usize,
}

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnEntry>,
    /// Total records matching the query across all pages. When
    /// `vulnerabilities.len() < totalResults`, the caller should
    /// advance `startIndex` and fetch the next page.
    #[serde(rename = "totalResults", default)]
    total_results: usize,
}

#[derive(Debug, Deserialize)]
struct NvdVulnEntry {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    metrics: NvdMetrics,
    #[serde(default)]
    references: Vec<NvdReference>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Default, Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31", default)]
    v31: Vec<NvdCvssMetric>,
    #[serde(rename = "cvssMetricV30", default)]
    v30: Vec<NvdCvssMetric>,
    #[serde(rename = "cvssMetricV2", default)]
    v2: Vec<NvdCvssMetric>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssMetric {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
struct NvdCvssData {
    #[serde(rename = "baseScore")]
    base_score: f64,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    url: String,
}

/// Parse a raw NVD 2.0 response into [`CveRecord`]s tagged with the
/// requested `cpe`. Public for `#[cfg(test)]` reuse only.
///
/// Severity is derived from the highest-priority CVSS metric available
/// (v3.1 → v3.0 → v2). Missing metrics map to
/// [`Severity::Info`] / `cvss_score = None` rather than failing the
/// parse.
///
/// # Errors
///
/// Returns [`ScorchError::Json`] if the body is not valid NVD JSON.
pub fn parse_nvd_response(body: &[u8], cpe: &str) -> Result<Vec<CveRecord>> {
    parse_nvd_page(body, cpe).map(|page| page.records)
}

/// Parse an NVD CVE-search response body into an [`NvdPage`] — records
/// + the top-level `totalResults`.
///
/// # Errors
///
/// Returns [`ScorchError::Json`] if the body is not valid NVD JSON.
pub(crate) fn parse_nvd_page(body: &[u8], cpe: &str) -> Result<NvdPage> {
    let resp: NvdResponse = serde_json::from_slice(body)?;
    let total_results = resp.total_results;
    let mut records = Vec::with_capacity(resp.vulnerabilities.len());
    for entry in resp.vulnerabilities {
        records.push(record_from(entry.cve, cpe));
    }
    Ok(NvdPage { records, total_results })
}

/// Merge delta records into a cached set keyed by CVE ID. Delta wins
/// on collision (it's newer). Pure function, unit-testable.
///
/// Used by the delta-sync cache-hit branch of [`NvdCveLookup::query`].
#[must_use]
pub(crate) fn merge_records_by_cve_id(
    cached: Vec<CveRecord>,
    delta: Vec<CveRecord>,
) -> Vec<CveRecord> {
    let mut by_id: HashMap<String, CveRecord> = HashMap::with_capacity(cached.len() + delta.len());
    for rec in cached {
        by_id.insert(rec.id.clone(), rec);
    }
    for rec in delta {
        by_id.insert(rec.id.clone(), rec);
    }
    by_id.into_values().collect()
}

/// Format a Unix timestamp as ISO 8601 / RFC 3339 with millisecond
/// precision, which is what NVD's `lastModStartDate` /
/// `lastModEndDate` parameters expect.
///
/// Pure function. Uses `chrono` (already a direct dep via
/// `Finding::timestamp`).
#[must_use]
pub(crate) fn format_last_mod_start(unix_ts: u64) -> String {
    // `from_timestamp` takes i64; Unix timestamps fit until year 2262.
    let ts_i64 = i64::try_from(unix_ts).unwrap_or(i64::MAX);
    DateTime::<Utc>::from_timestamp(ts_i64, 0)
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_default())
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// Current Unix time as seconds. Same idiom `cve_cache` uses — errors
/// in `duration_since(UNIX_EPOCH)` (impossible on a sane clock) map to
/// 0 rather than panicking.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Build a [`CveRecord`] from one parsed NVD CVE.
fn record_from(cve: NvdCve, cpe: &str) -> CveRecord {
    let description = pick_english_description(&cve.descriptions);
    let cvss_score = pick_best_cvss(&cve.metrics);
    let severity = cvss_score.map_or(Severity::Info, severity_from_cvss);
    let references = cve.references.into_iter().map(|r| r.url).collect();
    CveRecord {
        id: cve.id,
        cvss_score,
        severity,
        description,
        references,
        cpe: cpe.to_string(),
        aliases: Vec::new(),
    }
}

/// Prefer English description; fall back to the first available; empty
/// string if no descriptions at all.
fn pick_english_description(descs: &[NvdDescription]) -> String {
    descs
        .iter()
        .find(|d| d.lang.eq_ignore_ascii_case("en"))
        .or_else(|| descs.first())
        .map(|d| d.value.clone())
        .unwrap_or_default()
}

/// Pick the best CVSS score we have: v3.1 > v3.0 > v2.
fn pick_best_cvss(metrics: &NvdMetrics) -> Option<f64> {
    metrics
        .v31
        .first()
        .or_else(|| metrics.v30.first())
        .or_else(|| metrics.v2.first())
        .map(|m| m.cvss_data.base_score)
}

#[cfg(test)]
mod tests {
    //! Coverage for [`NvdCveLookup`]'s pure pieces — response parsing,
    //! quota selection, env-var override, and key resolution.
    //!
    //! The end-to-end network round-trip lives in
    //! `tests/cve_nvd.rs` against an `httpmock` server.

    use super::*;

    /// A fully-populated NVD response parses every field. Pins the
    /// exact JSON shape the rest of the system depends on.
    #[test]
    fn parse_nvd_response_extracts_records() {
        let body = br#"{
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [
                            {"lang": "en", "value": "Buffer overflow in Acme widget"},
                            {"lang": "es", "value": "Desbordamiento de buffer"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8}}
                            ]
                        },
                        "references": [
                            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
                            {"url": "https://example.test/advisory"}
                        ]
                    }
                }
            ]
        }"#;
        let cpe = "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*";
        let recs = parse_nvd_response(body, cpe).expect("parse");
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.id, "CVE-2024-1234");
        assert_eq!(r.cvss_score, Some(9.8));
        assert_eq!(r.severity, Severity::Critical);
        assert_eq!(r.description, "Buffer overflow in Acme widget");
        assert_eq!(r.references.len(), 2);
        assert_eq!(r.cpe, cpe);
    }

    /// Missing CVSS metrics map to `Severity::Info` and `None` rather
    /// than failing the parse. NVD legitimately publishes CVEs without
    /// scoring during analysis.
    #[test]
    fn parse_nvd_response_handles_missing_cvss() {
        let body = br#"{
            "vulnerabilities": [
                {"cve": {
                    "id": "CVE-2024-9999",
                    "descriptions": [{"lang": "en", "value": "No score yet"}]
                }}
            ]
        }"#;
        let recs = parse_nvd_response(body, "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*").expect("parse");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].cvss_score, None);
        assert_eq!(recs[0].severity, Severity::Info);
    }

    /// An empty `vulnerabilities` array yields zero records and no
    /// error. This is the negative-cache feeder.
    #[test]
    fn parse_nvd_response_handles_empty_vulnerabilities() {
        let body = br#"{"vulnerabilities": []}"#;
        let recs = parse_nvd_response(body, "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*").expect("parse");
        assert!(recs.is_empty());
    }

    /// v3.1 wins when present.
    #[test]
    fn parse_picks_v31_over_v30_and_v2() {
        let body = br#"{
            "vulnerabilities": [
                {"cve": {
                    "id": "CVE-2024-7777",
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "metrics": {
                        "cvssMetricV2":  [{"cvssData": {"baseScore": 1.0}}],
                        "cvssMetricV30": [{"cvssData": {"baseScore": 2.0}}],
                        "cvssMetricV31": [{"cvssData": {"baseScore": 9.0}}]
                    }
                }}
            ]
        }"#;
        let recs = parse_nvd_response(body, "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*").expect("parse");
        assert_eq!(recs[0].cvss_score, Some(9.0));
    }

    /// Without an API key the burst is 5 cells (NVD anonymous quota).
    #[test]
    fn nvd_quota_no_key_is_5_per_30s() {
        let q = quota_for_burst(QUOTA_NO_KEY_BURST);
        assert_eq!(q.burst_size().get(), 5);
    }

    /// With an API key the burst is 50 cells (NVD authenticated quota).
    #[test]
    fn nvd_quota_with_key_is_50_per_30s() {
        let q = quota_for_burst(QUOTA_WITH_KEY_BURST);
        assert_eq!(q.burst_size().get(), 50);
    }

    /// `SCORCHKIT_NVD_API_KEY` overrides the config field. This is the
    /// load-bearing operator workflow — commit a config without a key,
    /// supply the key from the environment.
    #[test]
    fn nvd_env_var_overrides_config_api_key() {
        // Test mutates a process-wide env var; restore on drop.
        struct EnvGuard {
            prior: Option<String>,
        }
        impl EnvGuard {
            fn set(value: &str) -> Self {
                let prior = env::var(ENV_API_KEY).ok();
                env::set_var(ENV_API_KEY, value);
                Self { prior }
            }
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match &self.prior {
                    Some(v) => env::set_var(ENV_API_KEY, v),
                    None => env::remove_var(ENV_API_KEY),
                }
            }
        }

        let _guard = EnvGuard::set("env-wins");
        let cfg = NvdConfig { api_key: Some("config-loses".into()), ..NvdConfig::default() };
        assert_eq!(resolve_api_key(&cfg).as_deref(), Some("env-wins"));
    }

    /// Default cache dir is rooted at `XDG_CACHE_HOME` when set.
    #[test]
    fn default_cache_dir_honours_xdg() {
        let prior_xdg = env::var("XDG_CACHE_HOME").ok();
        let prior_home = env::var("HOME").ok();
        env::set_var("XDG_CACHE_HOME", "/tmp/xdg-test");
        let dir = default_cache_dir();
        // Restore env before asserting so a failure doesn't leak state.
        match prior_xdg {
            Some(v) => env::set_var("XDG_CACHE_HOME", v),
            None => env::remove_var("XDG_CACHE_HOME"),
        }
        match prior_home {
            Some(v) => env::set_var("HOME", v),
            None => env::remove_var("HOME"),
        }
        assert_eq!(dir, PathBuf::from("/tmp/xdg-test/scorchkit/cve"));
    }

    // =============================================================
    // WORK-147: pagination + delta-sync helpers
    // =============================================================

    fn fixture_record(id: &str) -> CveRecord {
        CveRecord {
            id: id.to_string(),
            cvss_score: Some(5.0),
            severity: Severity::Medium,
            description: format!("fixture {id}"),
            references: Vec::new(),
            cpe: "cpe:2.3:a:fixture:*:*:*:*:*:*:*:*:*".to_string(),
            aliases: Vec::new(),
        }
    }

    #[test]
    fn merge_records_by_cve_id_no_overlap() {
        let cached = vec![fixture_record("CVE-2024-1")];
        let delta = vec![fixture_record("CVE-2024-2")];
        let merged = merge_records_by_cve_id(cached, delta);
        assert_eq!(merged.len(), 2);
        let ids: Vec<&str> = merged.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"CVE-2024-1"));
        assert!(ids.contains(&"CVE-2024-2"));
    }

    #[test]
    fn merge_records_by_cve_id_delta_replaces_cached() {
        let mut cached_rec = fixture_record("CVE-2024-1");
        cached_rec.description = "old desc".to_string();
        let mut delta_rec = fixture_record("CVE-2024-1");
        delta_rec.description = "new desc".to_string();
        let merged = merge_records_by_cve_id(vec![cached_rec], vec![delta_rec]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].description, "new desc");
    }

    #[test]
    fn merge_records_by_cve_id_empty_delta_preserves_cached() {
        let cached = vec![fixture_record("CVE-2024-1"), fixture_record("CVE-2024-2")];
        let merged = merge_records_by_cve_id(cached.clone(), Vec::new());
        assert_eq!(merged.len(), cached.len());
    }

    #[test]
    fn merge_records_by_cve_id_empty_cached_returns_delta() {
        let delta = vec![fixture_record("CVE-2024-9")];
        let merged = merge_records_by_cve_id(Vec::new(), delta);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].id, "CVE-2024-9");
    }

    #[test]
    fn format_last_mod_start_rfc3339_shape() {
        // 2024-01-02T03:04:05Z = 1704164645
        let out = format_last_mod_start(1_704_164_645);
        assert!(out.ends_with('Z'), "must be UTC-suffixed: {out}");
        assert!(out.starts_with("2024-01-02T03:04:05"), "unexpected shape: {out}");
        // NVD requires millisecond precision; `.000` is the fractional part.
        assert!(out.contains(".000"), "expected .000 fractional: {out}");
    }

    #[test]
    fn format_last_mod_start_zero_timestamp() {
        let out = format_last_mod_start(0);
        assert_eq!(out, "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn parse_nvd_page_extracts_total_results() {
        let body = br#"{
            "totalResults": 42,
            "vulnerabilities": [
                { "cve": {
                    "id": "CVE-2024-1",
                    "descriptions": [{"lang": "en", "value": "x"}]
                }}
            ]
        }"#;
        let page = parse_nvd_page(body, "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*").expect("parse");
        assert_eq!(page.total_results, 42);
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].id, "CVE-2024-1");
    }

    #[test]
    fn parse_nvd_page_missing_total_results_defaults_to_zero() {
        let body = br#"{"vulnerabilities": []}"#;
        let page = parse_nvd_page(body, "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*").expect("parse");
        assert_eq!(page.total_results, 0);
        assert!(page.records.is_empty());
    }
}
