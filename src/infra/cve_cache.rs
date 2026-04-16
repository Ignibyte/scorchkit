//! On-disk TTL cache for [`CveRecord`] lookups.
//!
//! Each cache entry is a JSON file under a configurable directory. The
//! filename is `sha256(cpe).json`, content-addressing the CPE so any
//! valid CPE 2.3 string maps to a stable filesystem path without
//! escaping or collisions. The JSON envelope carries the records, the
//! UTC fetch time, and a TTL — entries past their TTL are reported as
//! cache misses on read.
//!
//! Reads never propagate errors. Missing files, corrupt JSON, expired
//! entries, and unreadable directories all map to "miss" so a degraded
//! cache never aborts a scan. Writes log warnings on failure but return
//! success — the caller's records are still valid even if persistence
//! fails. This matches the broader "CVE lookup is best-effort" stance
//! in [`crate::infra::cve_match::CveMatchModule`].
//!
//! Negative caching is intentional: empty result sets are persisted and
//! returned. Most CPEs surfaced during a scan have *zero* known CVEs;
//! re-querying every empty CPE on every scan is the most expensive way
//! to use the rate budget. Operators who want fresh data sooner can
//! lower [`crate::config::cve::NvdConfig::cache_ttl_secs`] or delete
//! the cache directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::engine::cve::CveRecord;

/// File-backed TTL cache. One JSON file per CPE.
#[derive(Debug, Clone)]
pub(crate) struct FsCache {
    /// Directory the cache lives in. Created on construction; if creation
    /// fails the cache disables itself (every read returns `None`, every
    /// write logs and no-ops).
    dir: Option<PathBuf>,
    /// Entries older than this are treated as misses.
    ttl: Duration,
}

/// Persisted envelope. Shape is private to this module so we can evolve
/// it; callers only see `Vec<CveRecord>`.
#[derive(Debug, Serialize, Deserialize)]
struct CacheEnvelope {
    /// Seconds since the Unix epoch when the entry was written.
    fetched_at_unix: u64,
    /// TTL in seconds. Stored alongside the entry so callers can change
    /// the runtime TTL without invalidating older entries with longer
    /// lifetimes.
    ttl_secs: u64,
    /// Records returned by the backend.
    records: Vec<CveRecord>,
}

impl FsCache {
    /// Create a cache rooted at `dir` with the given TTL.
    ///
    /// If `dir` cannot be created the cache is constructed in *disabled*
    /// mode — every `get` returns `None`, every `put` logs at `warn` and
    /// no-ops. This keeps a degraded cache from aborting a scan.
    pub(crate) fn new(dir: PathBuf, ttl: Duration) -> Self {
        match fs::create_dir_all(&dir) {
            Ok(()) => Self { dir: Some(dir), ttl },
            Err(e) => {
                warn!("cve_cache: failed to create {} ({e}); caching disabled", dir.display());
                Self { dir: None, ttl }
            }
        }
    }

    /// Read records for `cpe` from the cache.
    ///
    /// Returns `None` for any failure mode: cache disabled, missing
    /// file, unreadable file, corrupt JSON, or expired entry. Callers
    /// treat all of these the same — issue a fresh backend query.
    pub(crate) fn get(&self, cpe: &str) -> Option<Vec<CveRecord>> {
        self.get_with_meta(cpe).map(|(records, _)| records)
    }

    /// Same as [`Self::get`] but also returns the Unix timestamp when
    /// the entry was written.
    ///
    /// Used by [`crate::infra::cve_nvd::NvdCveLookup`]'s delta-sync
    /// mode: a fresh query is issued with `lastModStartDate` set to
    /// (cache write time − safety margin) so only records modified
    /// since the cache entry are fetched, then merged with the cached
    /// set. Returns `None` for every failure mode (cache disabled,
    /// missing file, corrupt JSON, expired entry) — same contract as
    /// [`Self::get`].
    pub(crate) fn get_with_meta(&self, cpe: &str) -> Option<(Vec<CveRecord>, u64)> {
        let dir = self.dir.as_ref()?;
        let path = path_for_cpe(dir, cpe);
        let bytes = fs::read(&path).ok()?;
        let envelope: CacheEnvelope = match serde_json::from_slice(&bytes) {
            Ok(e) => e,
            Err(e) => {
                warn!("cve_cache: corrupt entry {} ({e}); treating as miss", path.display());
                return None;
            }
        };
        if envelope_is_expired(&envelope, self.ttl) {
            return None;
        }
        Some((envelope.records, envelope.fetched_at_unix))
    }

    /// Write records for `cpe`. Failures log at `warn` and no-op — the
    /// caller's records are still valid.
    pub(crate) fn put(&self, cpe: &str, records: &[CveRecord]) {
        let Some(dir) = self.dir.as_ref() else {
            return;
        };
        let path = path_for_cpe(dir, cpe);
        let envelope = CacheEnvelope {
            fetched_at_unix: now_unix(),
            ttl_secs: self.ttl.as_secs(),
            records: records.to_vec(),
        };
        match serde_json::to_vec(&envelope) {
            Ok(bytes) => {
                if let Err(e) = fs::write(&path, bytes) {
                    warn!("cve_cache: write {} failed ({e}); skipping persist", path.display());
                }
            }
            Err(e) => {
                warn!("cve_cache: serialize for {cpe} failed ({e}); skipping persist");
            }
        }
    }
}

/// Stable content-addressed path for `cpe` under `dir`.
///
/// `sha256(cpe)` hex + `.json`. Pure function so callers and tests can
/// reason about path identity without instantiating a cache.
fn path_for_cpe(dir: &Path, cpe: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(cpe.as_bytes());
    let hex = hex_lowercase(&hasher.finalize());
    dir.join(format!("{hex}.json"))
}

/// Render bytes as lowercase hex. Avoids pulling `hex` as a dep for one call.
fn hex_lowercase(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // JUSTIFICATION: write! into a `String` cannot fail per std docs;
        // ignoring the result here is the documented idiom and clippy
        // accepts it because the receiver is a String.
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Current Unix time as seconds. `SystemTime::now() < UNIX_EPOCH` would
/// only happen on a clock-broken machine; we map that to `0` and let
/// the next read trigger expiry.
fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// True if the envelope's `fetched_at_unix + min(envelope.ttl, runtime)`
/// is in the past.
///
/// We honour the *smaller* of the persisted TTL and the runtime TTL so
/// that lowering the runtime TTL invalidates older entries immediately,
/// while raising it doesn't suddenly extend stale data past its
/// intended life.
fn envelope_is_expired(envelope: &CacheEnvelope, runtime_ttl: Duration) -> bool {
    let effective_ttl = runtime_ttl.as_secs().min(envelope.ttl_secs);
    let expires_at = envelope.fetched_at_unix.saturating_add(effective_ttl);
    now_unix() >= expires_at
}

#[cfg(test)]
mod tests {
    //! Coverage for [`FsCache`] — round-trip, TTL expiry, corruption,
    //! negative caching, and path stability.
    //!
    //! These tests use `tempfile::tempdir()` so cache state stays inside
    //! the test and never touches a real cache directory.

    use super::*;
    use crate::engine::cve::severity_from_cvss;
    use crate::engine::severity::Severity;

    /// Build a `CveRecord` with a deterministic shape for fixtures.
    fn record(id: &str, cpe: &str, score: f64) -> CveRecord {
        CveRecord {
            id: id.to_string(),
            cvss_score: Some(score),
            severity: severity_from_cvss(score),
            description: format!("fixture {id}"),
            references: vec!["https://example.test/adv".to_string()],
            cpe: cpe.to_string(),
            aliases: Vec::new(),
        }
    }

    /// `put` followed by `get` returns the same records. This is the
    /// happy path the rest of the cache contract is built on.
    #[test]
    fn fs_cache_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(dir.path().to_path_buf(), Duration::from_secs(3600));
        let cpe = "cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*";
        cache.put(cpe, &[record("CVE-2024-X", cpe, 9.8)]);
        let got = cache.get(cpe).expect("hit");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "CVE-2024-X");
        assert_eq!(got[0].severity, Severity::Critical);
    }

    /// `get_with_meta` round-trip returns the records AND the Unix
    /// timestamp written by `put`. Used by the delta-sync path.
    #[test]
    fn fs_cache_get_with_meta_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(dir.path().to_path_buf(), Duration::from_secs(3600));
        let cpe = "cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*";
        let before = now_unix();
        cache.put(cpe, &[record("CVE-2024-X", cpe, 9.8)]);
        let (records, fetched_at) = cache.get_with_meta(cpe).expect("hit");
        assert_eq!(records.len(), 1);
        assert!(fetched_at >= before, "fetched_at {fetched_at} < before {before}");
        assert!(fetched_at <= now_unix(), "fetched_at in future");
    }

    /// `get_with_meta` returns `None` on a cache miss — matches the
    /// contract of `get`.
    #[test]
    fn fs_cache_get_with_meta_miss_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(dir.path().to_path_buf(), Duration::from_secs(3600));
        let cpe = "cpe:2.3:a:nonexistent:*:*:*:*:*:*:*:*:*";
        assert!(cache.get_with_meta(cpe).is_none());
    }

    /// Corrupt JSON on disk is treated as a miss — same contract as `get`.
    #[test]
    fn fs_cache_get_with_meta_corrupt_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(dir.path().to_path_buf(), Duration::from_secs(3600));
        let cpe = "cpe:2.3:a:corrupt:*:*:*:*:*:*:*:*:*";
        // Write garbage to the cache file for this CPE.
        let path = path_for_cpe(dir.path(), cpe);
        std::fs::write(&path, b"not json").expect("write");
        assert!(cache.get_with_meta(cpe).is_none());
    }

    /// A zero-length TTL forces every entry to be expired on the next
    /// read. Verifies the expiry path independently of wall-clock waits.
    #[test]
    fn fs_cache_expired_entry_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(dir.path().to_path_buf(), Duration::from_secs(0));
        let cpe = "cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*";
        cache.put(cpe, &[record("CVE-2024-X", cpe, 9.8)]);
        assert!(cache.get(cpe).is_none());
    }

    /// Empty result sets persist. Negative caching is the load-bearing
    /// optimisation — without it every empty-CPE response burns the
    /// rate budget on every scan.
    #[test]
    fn fs_cache_negative_cache_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(dir.path().to_path_buf(), Duration::from_secs(3600));
        let cpe = "cpe:2.3:a:unknown:product:0.0:*:*:*:*:*:*:*";
        cache.put(cpe, &[]);
        let got = cache.get(cpe).expect("hit");
        assert!(got.is_empty());
    }

    /// Unknown CPE returns `None`. The cache is silent about misses —
    /// callers don't need to disambiguate "never written" from
    /// "expired".
    #[test]
    fn fs_cache_missing_file_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(dir.path().to_path_buf(), Duration::from_secs(3600));
        assert!(cache.get("cpe:2.3:a:nope:nope:0:*:*:*:*:*:*:*").is_none());
    }

    /// Garbage on disk is treated as a miss, not an error. Operators
    /// must be able to corrupt or hand-edit cache files without
    /// breaking scans.
    #[test]
    fn fs_cache_corrupt_file_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(dir.path().to_path_buf(), Duration::from_secs(3600));
        let cpe = "cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*";
        let path = path_for_cpe(dir.path(), cpe);
        fs::write(&path, b"not json at all").expect("seed corrupt entry");
        assert!(cache.get(cpe).is_none());
    }

    /// The same CPE always resolves to the same filename. Tests can
    /// build paths without instantiating a cache and operators can
    /// `rm` a single CPE entry by hand.
    #[test]
    fn fs_cache_path_for_cpe_is_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cpe = "cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*";
        let p1 = path_for_cpe(dir.path(), cpe);
        let p2 = path_for_cpe(dir.path(), cpe);
        assert_eq!(p1, p2);
        // sha256 hex is 64 chars + ".json".
        assert!(p1.file_name().and_then(|s| s.to_str()).is_some_and(|s| s.len() == 69));
    }

    /// Different CPEs yield different paths. Sanity check that we're
    /// actually hashing the input, not stripping it.
    #[test]
    fn fs_cache_distinct_cpes_get_distinct_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p1 = path_for_cpe(dir.path(), "cpe:2.3:a:vendor1:product:1:*:*:*:*:*:*:*");
        let p2 = path_for_cpe(dir.path(), "cpe:2.3:a:vendor2:product:1:*:*:*:*:*:*:*");
        assert_ne!(p1, p2);
    }
}
