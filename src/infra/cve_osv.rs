//! OSV.dev v1 [`CveLookup`] backend.
//!
//! [`OsvCveLookup`] queries `api.osv.dev/v1/query` with a JSON body of
//! `{"package": {"name", "ecosystem"}, "version"}`, parses the response
//! into [`CveRecord`]s, caches them on disk via
//! the crate-internal filesystem cache
//! (`crate::infra::cve_cache::FsCache`), and rate-limits outbound
//! requests via [`governor`] to a conservative 10 RPS by default
//! (well under OSV's documented ~25 QPS fair-use cap).
//!
//! ## Architectural notes
//!
//! - **Separate HTTP client**, same rationale as [`crate::infra::cve_nvd::NvdCveLookup`]:
//!   pen-test client carries the user's User-Agent / Burp proxy /
//!   insecure-TLS settings — none appropriate for vendor API calls.
//! - **CPE → ecosystem translation** via
//!   [`crate::infra::cpe_purl::cpe_to_package`]. Unmapped CPEs skip the
//!   network entirely (cached as empty + one `warn!` per CPE).
//! - **CVSS vector → numeric score** via
//!   [`crate::engine::cve::cvss_v3_base_score`]. OSV surfaces vectors,
//!   not numerics. Missing/malformed severity → [`Severity::Info`].
//! - **Per-backend cache directory** under `scorchkit/cve-osv/` — kept
//!   distinct from NVD's `scorchkit/cve/` so a wholesale flush of one
//!   backend doesn't take out the other.
//! - **No API key.** OSV is intentionally keyless. There is no
//!   environment-variable override on this backend.

use std::env;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::cve::OsvConfig;
use crate::engine::cve::{cvss_v3_base_score, severity_from_cvss, CveLookup, CveRecord};
use crate::engine::error::{Result, ScorchError};
use crate::engine::severity::Severity;
use crate::infra::cpe_purl::{cpe_to_package, PackageCoord};
use crate::infra::cve_cache::FsCache;

/// Default OSV endpoint base.
pub const DEFAULT_BASE_URL: &str = "https://api.osv.dev";

/// Query path appended to `base_url`.
const QUERY_PATH: &str = "/v1/query";

/// Maximum response size we accept. OSV responses are typically <50 KB
/// even for heavily-vulnerable packages; 5 MB is a safe bound.
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// OSV.dev v1 implementation of [`CveLookup`].
pub struct OsvCveLookup {
    /// Endpoint base. Overridden by tests via [`OsvConfig::base_url`].
    base_url: String,
    /// Pre-configured HTTP client. Separate from the scan client.
    http: reqwest::Client,
    /// Token-bucket limiter sized to `OsvConfig.max_rps`.
    limiter: Arc<DirectLimiter>,
    /// On-disk TTL cache (or disabled cache).
    cache: FsCache,
}

impl std::fmt::Debug for OsvCveLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsvCveLookup").field("base_url", &self.base_url).finish_non_exhaustive()
    }
}

impl OsvCveLookup {
    /// Construct a lookup from an [`OsvConfig`] block.
    ///
    /// Resolves the cache directory via the config field, then
    /// `XDG_CACHE_HOME`, then `HOME/.cache`, then `./cve-osv-cache`.
    /// Sizes the rate limiter to `cfg.max_rps`.
    ///
    /// # Errors
    ///
    /// Returns [`ScorchError::Config`] if the underlying
    /// [`reqwest::Client`] cannot be built or `cfg.max_rps` is zero.
    pub fn from_config(cfg: &OsvConfig) -> Result<Self> {
        let base_url = cfg
            .base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();

        let user_agent = format!("ScorchKit-CVE-OSV/{}", env!("CARGO_PKG_VERSION"));
        let http = reqwest::Client::builder()
            .user_agent(user_agent)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ScorchError::Config(format!("osv: failed to build http client: {e}")))?;

        let burst = NonZeroU32::new(cfg.max_rps)
            .ok_or_else(|| ScorchError::Config("osv: max_rps must be > 0".into()))?;
        let limiter = Arc::new(RateLimiter::direct(quota_for_rps(burst)));

        let cache_dir = cfg.cache_dir.clone().unwrap_or_else(default_cache_dir);
        let cache = FsCache::new(cache_dir, Duration::from_secs(cfg.cache_ttl_secs));

        Ok(Self { base_url, http, limiter, cache })
    }
}

#[async_trait]
impl CveLookup for OsvCveLookup {
    async fn query(&self, cpe: &str) -> Result<Vec<CveRecord>> {
        if let Some(records) = self.cache.get(cpe) {
            return Ok(records);
        }

        // Translate before checking the network — unmapped CPEs are
        // cached as empty so we don't repeat the warn! every scan.
        let Some(coord) = cpe_to_package(cpe) else {
            warn!("osv: no package mapping for {cpe}; skipping (no OSV ecosystem)");
            self.cache.put(cpe, &[]);
            return Ok(Vec::new());
        };

        // Block on the rate limiter only for actual network calls.
        self.limiter.until_ready().await;

        let url = format!("{}{}", self.base_url, QUERY_PATH);
        let body = OsvQueryBody::from(&coord);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.clone(), source: e })?;
        let status = resp.status();
        if !status.is_success() {
            return Err(ScorchError::Config(format!("osv: backend returned {status}")));
        }

        let bytes =
            resp.bytes().await.map_err(|e| ScorchError::Http { url: url.clone(), source: e })?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ScorchError::Config(format!(
                "osv: response exceeded {MAX_RESPONSE_BYTES} bytes ({} received)",
                bytes.len()
            )));
        }

        let records = parse_osv_response(&bytes, cpe)?;
        self.cache.put(cpe, &records);
        Ok(records)
    }
}

/// Build a `Quota` for the given per-second burst.
const fn quota_for_rps(rps: NonZeroU32) -> Quota {
    Quota::per_second(rps)
}

/// Default cache directory — `scorchkit/cve-osv/` under
/// `XDG_CACHE_HOME` or `HOME/.cache`, else `./cve-osv-cache`.
fn default_cache_dir() -> PathBuf {
    if let Ok(xdg) = env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("scorchkit").join("cve-osv");
        }
    }
    if let Ok(home) = env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".cache").join("scorchkit").join("cve-osv");
        }
    }
    PathBuf::from("./cve-osv-cache")
}

// ---------- request / response shapes ----------

#[derive(Debug, Serialize)]
struct OsvQueryBody {
    package: OsvQueryPackage,
    version: String,
}

#[derive(Debug, Serialize)]
struct OsvQueryPackage {
    name: String,
    ecosystem: String,
}

impl From<&PackageCoord> for OsvQueryBody {
    fn from(coord: &PackageCoord) -> Self {
        Self {
            package: OsvQueryPackage {
                name: coord.name.clone(),
                ecosystem: coord.ecosystem.to_string(),
            },
            version: coord.version.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    references: Vec<OsvReference>,
    /// Alternate identifiers for this vulnerability — e.g. a `CVE-YYYY-NNNN`
    /// id when this is a `GHSA-` record. Preserved on [`CveRecord::aliases`]
    /// and consumed by [`crate::infra::cve_multi::MultiCveLookup`] for
    /// cross-backend dedup.
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type", default)]
    type_: String,
    #[serde(default)]
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    url: String,
}

/// Parse a raw OSV v1 response into [`CveRecord`]s tagged with the
/// requested `cpe`. Public for `#[cfg(test)]` reuse only.
///
/// Severity comes from the first `CVSS_V3` entry in the `severity`
/// array, parsed via [`cvss_v3_base_score`]. Missing or malformed
/// severity yields [`Severity::Info`] / `cvss_score = None`.
///
/// # Errors
///
/// Returns [`ScorchError::Json`] if the body is not valid OSV JSON.
pub fn parse_osv_response(body: &[u8], cpe: &str) -> Result<Vec<CveRecord>> {
    let resp: OsvResponse = serde_json::from_slice(body)?;
    let mut out = Vec::with_capacity(resp.vulns.len());
    for v in resp.vulns {
        out.push(record_from(v, cpe));
    }
    Ok(out)
}

fn record_from(v: OsvVuln, cpe: &str) -> CveRecord {
    let cvss_score = pick_best_severity(&v.severity);
    let severity = cvss_score.map_or(Severity::Info, severity_from_cvss);
    let description = if v.summary.is_empty() { v.details } else { v.summary };
    let references = v.references.into_iter().map(|r| r.url).collect();
    CveRecord {
        id: v.id,
        cvss_score,
        severity,
        description,
        references,
        cpe: cpe.to_string(),
        aliases: v.aliases,
    }
}

/// First parseable CVSS v3.x vector from the severity array.
fn pick_best_severity(entries: &[OsvSeverity]) -> Option<f64> {
    for e in entries {
        if e.type_ == "CVSS_V3" {
            if let Some(s) = cvss_v3_base_score(&e.score) {
                return Some(s);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    //! Coverage for [`OsvCveLookup`]'s pure pieces — response parsing,
    //! quota selection, default cache dir.
    //!
    //! End-to-end network round-trips live in `tests/cve_osv.rs`
    //! against an `httpmock` server.

    use super::*;

    /// A fully-populated OSV vuln entry maps every field we surface,
    /// including CVSS_V3 vector → numeric score → severity.
    #[test]
    fn parse_osv_response_extracts_records() {
        let body = br#"{
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "summary": "Critical RCE in widget",
                    "details": "Detailed description",
                    "severity": [
                        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                    ],
                    "references": [
                        {"url": "https://github.com/advisory/abc"},
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999"}
                    ]
                }
            ]
        }"#;
        let cpe = "cpe:2.3:a:expressjs:express:4.17.0:*:*:*:*:*:*:*";
        let recs = parse_osv_response(body, cpe).expect("parse");
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(r.severity, Severity::Critical);
        assert!(r.cvss_score.is_some());
        assert_eq!(r.description, "Critical RCE in widget");
        assert_eq!(r.references.len(), 2);
        assert_eq!(r.cpe, cpe);
    }

    /// Missing severity array → `Severity::Info`, `cvss_score = None`.
    /// Description falls back to `details` when `summary` is empty.
    #[test]
    fn parse_osv_response_handles_missing_severity() {
        let body = br#"{
            "vulns": [
                {"id": "GHSA-aaa", "details": "details only"}
            ]
        }"#;
        let recs =
            parse_osv_response(body, "cpe:2.3:a:expressjs:express:1.0:*:*:*:*:*:*:*").expect("p");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].severity, Severity::Info);
        assert!(recs[0].cvss_score.is_none());
        assert_eq!(recs[0].description, "details only");
    }

    /// Empty `vulns` → empty Vec, no error. Drives the negative-cache
    /// path on the integration side.
    #[test]
    fn parse_osv_response_handles_empty_vulns() {
        let body = br#"{"vulns": []}"#;
        let recs =
            parse_osv_response(body, "cpe:2.3:a:expressjs:express:1.0:*:*:*:*:*:*:*").expect("p");
        assert!(recs.is_empty());
    }

    /// Missing `vulns` key entirely (some OSV deployments omit it for
    /// zero-result responses) is treated identically to an empty array
    /// thanks to `#[serde(default)]`.
    #[test]
    fn parse_osv_response_handles_missing_vulns_key() {
        let body = br#"{}"#;
        let recs =
            parse_osv_response(body, "cpe:2.3:a:expressjs:express:1.0:*:*:*:*:*:*:*").expect("p");
        assert!(recs.is_empty());
    }

    /// OSV responses with `aliases[]` populate the `CveRecord::aliases`
    /// field — this is what [`crate::infra::cve_multi::MultiCveLookup`]
    /// uses for cross-backend dedup.
    #[test]
    fn osv_response_populates_aliases() {
        let body = br#"{
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "aliases": ["CVE-2024-9999", "OSV-2024-5"],
                    "summary": "Alias-bearing record"
                }
            ]
        }"#;
        let recs =
            parse_osv_response(body, "cpe:2.3:a:pkg:widget:1.0:*:*:*:*:*:*:*").expect("parse");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].aliases, vec!["CVE-2024-9999".to_string(), "OSV-2024-5".to_string()]);
    }

    /// Missing `aliases` field → empty `aliases` Vec (via `#[serde(default)]`).
    /// Pins back-compat for existing OSV responses that omit the field.
    #[test]
    fn osv_response_empty_aliases_default() {
        let body = br#"{
            "vulns": [
                {"id": "GHSA-aaa", "summary": "no aliases here"}
            ]
        }"#;
        let recs =
            parse_osv_response(body, "cpe:2.3:a:pkg:widget:1.0:*:*:*:*:*:*:*").expect("parse");
        assert_eq!(recs.len(), 1);
        assert!(recs[0].aliases.is_empty());
    }

    /// Default `OsvConfig::default().max_rps == 10` — the limiter
    /// constructor honours that exact value.
    #[test]
    fn osv_quota_default_is_10_rps() {
        let burst = NonZeroU32::new(10).expect("nonzero literal");
        let q = quota_for_rps(burst);
        assert_eq!(q.burst_size().get(), 10);
    }

    /// `XDG_CACHE_HOME` is honoured for the default cache dir, with
    /// the `cve-osv` suffix that distinguishes this backend's cache
    /// from NVD's.
    #[test]
    fn default_cache_dir_honours_xdg() {
        let prior_xdg = env::var("XDG_CACHE_HOME").ok();
        let prior_home = env::var("HOME").ok();
        env::set_var("XDG_CACHE_HOME", "/tmp/xdg-osv-test");
        let dir = default_cache_dir();
        match prior_xdg {
            Some(v) => env::set_var("XDG_CACHE_HOME", v),
            None => env::remove_var("XDG_CACHE_HOME"),
        }
        match prior_home {
            Some(v) => env::set_var("HOME", v),
            None => env::remove_var("HOME"),
        }
        assert_eq!(dir, PathBuf::from("/tmp/xdg-osv-test/scorchkit/cve-osv"));
    }
}
