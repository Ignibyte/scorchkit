//! NIST NVD 2.0 [`CveLookup`] backend.
//!
//! [`NvdCveLookup`] queries `services.nvd.nist.gov/rest/json/cves/2.0`
//! with a `cpeName` parameter, parses the response into [`CveRecord`]s,
//! caches them on disk via [`crate::infra::cve_cache::FsCache`], and
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
//! - **No pagination.** NVD pages cap at 2000 results per call; the
//!   typical CPE returns <50. We take the first page only and document
//!   this as a limitation. A future enhancement can follow
//!   `startIndex`.
//!
//! ## Environment overrides
//!
//! - `SCORCHKIT_NVD_API_KEY` — wins over
//!   [`crate::config::cve::NvdConfig::api_key`].

use std::env;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use serde::Deserialize;
use tracing::warn;

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
        if let Some(records) = self.cache.get(cpe) {
            return Ok(records);
        }

        // Block on the rate limiter only for actual network calls.
        self.limiter.until_ready().await;

        let url = format!("{}{}", self.base_url, CVES_PATH);
        let mut req = self.http.get(&url).query(&[("cpeName", cpe)]);
        if let Some(key) = self.effective_api_key() {
            req = req.header("apiKey", key);
        }

        let resp =
            req.send().await.map_err(|e| ScorchError::Http { url: url.clone(), source: e })?;
        let status = resp.status();

        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            // Disable the key once and let subsequent calls fall back to
            // the anonymous quota — don't burn the per-fingerprint loop.
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

        let records = parse_nvd_response(&bytes, cpe)?;
        self.cache.put(cpe, &records);
        Ok(records)
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

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnEntry>,
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
    let resp: NvdResponse = serde_json::from_slice(body)?;
    let mut out = Vec::with_capacity(resp.vulnerabilities.len());
    for entry in resp.vulnerabilities {
        out.push(record_from(entry.cve, cpe));
    }
    Ok(out)
}

/// Build a [`CveRecord`] from one parsed NVD CVE.
fn record_from(cve: NvdCve, cpe: &str) -> CveRecord {
    let description = pick_english_description(&cve.descriptions);
    let cvss_score = pick_best_cvss(&cve.metrics);
    let severity = cvss_score.map_or(Severity::Info, severity_from_cvss);
    let references = cve.references.into_iter().map(|r| r.url).collect();
    CveRecord { id: cve.id, cvss_score, severity, description, references, cpe: cpe.to_string() }
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
}
