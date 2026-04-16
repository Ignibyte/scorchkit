//! Multi-backend CVE lookup aggregator.
//!
//! [`MultiCveLookup`] wraps `Vec<Box<dyn CveLookup>>` and implements
//! [`CveLookup`] itself so it can slot into
//! [`crate::infra::cve_match::CveMatchModule`] transparently. Behavior:
//!
//! 1. **Sequential fan-out.** For each call to `query(cpe)`, run each
//!    sub-backend in order. Matches the per-fingerprint sequential
//!    pattern used by `CveMatchModule` — avoids surprising rate-limit
//!    interactions across distinct backends.
//! 2. **Per-sub-backend error isolation.** An individual `Err` is
//!    logged at `warn!` and the sub-backend contributes an empty `Vec`
//!    to the merge. The aggregate call always returns `Ok`.
//! 3. **Dedup by canonical CVE ID.** After merging, records are
//!    collapsed via [`canonical_cve_key`] — prefer a `CVE-YYYY-NNNN`
//!    `id`, else search [`CveRecord::aliases`] for one, else fall back
//!    to the raw `id`. On collision, the record with the **higher
//!    `cvss_score`** wins (`None < Some(0.0)`); equal scores defer to
//!    first-seen.
//!
//! ## Config
//!
//! Selected via `[cve] backend = "composite"` + `[cve.composite]
//! sources = ["nvd", "osv"]`. The factory
//! [`crate::infra::cve_lookup::build_cve_lookup`] builds each
//! sub-backend from its own `[cve.nvd]` / `[cve.osv]` block and wraps
//! the Vec in `MultiCveLookup::new`. Empty `sources` is rejected at
//! construction time — fail loudly on user-facing config mistakes.
//!
//! ## What's out of scope
//!
//! - **Concurrent fan-out.** Sub-backends already own their own rate
//!   limiters; concurrent calls would need a shared futures crate
//!   (dependency churn) for marginal latency win (~500ms per
//!   fingerprint). Revisit in a v2 aggregator pipeline if operators
//!   ask.
//! - **Cross-backend severity reconciliation beyond max-CVSS.**
//!   Picking the higher `cvss_score` is the simplest deterministic
//!   rule; rigorous reconciliation (weighting vendor advisories vs
//!   NVD analysts) is a future enhancement.

use async_trait::async_trait;
use tracing::warn;

use crate::engine::cve::{CveLookup, CveRecord};
use crate::engine::error::Result;

/// Aggregates multiple [`CveLookup`] sub-backends behind a single
/// [`CveLookup`] surface with dedup by canonical CVE ID.
pub struct MultiCveLookup {
    sources: Vec<Box<dyn CveLookup>>,
}

impl std::fmt::Debug for MultiCveLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiCveLookup")
            .field("source_count", &self.sources.len())
            .finish_non_exhaustive()
    }
}

impl MultiCveLookup {
    /// Build a new aggregator over the supplied sub-backends.
    ///
    /// An empty `sources` list yields a lookup that always returns
    /// `Ok(vec![])`; the factory
    /// [`crate::infra::cve_lookup::build_cve_lookup`] rejects empty
    /// sources at config-parse time so that case doesn't occur in
    /// practice.
    #[must_use]
    pub const fn new(sources: Vec<Box<dyn CveLookup>>) -> Self {
        Self { sources }
    }
}

#[async_trait]
impl CveLookup for MultiCveLookup {
    async fn query(&self, cpe: &str) -> Result<Vec<CveRecord>> {
        let mut merged: Vec<CveRecord> = Vec::new();
        for (idx, source) in self.sources.iter().enumerate() {
            match source.query(cpe).await {
                Ok(records) => merged.extend(records),
                Err(e) => {
                    warn!("cve_multi: source #{idx} failed for {cpe}: {e}");
                }
            }
        }
        Ok(dedupe_by_canonical_id(merged))
    }
}

/// Return the canonical dedup key for `record`:
///
/// 1. If `record.id` starts with `CVE-`, use it as-is.
/// 2. Else scan `record.aliases` for a `CVE-`-prefixed entry and use
///    the first match.
/// 3. Else fall back to `record.id` verbatim.
///
/// This means a `GHSA-...` record from OSV with `aliases =
/// ["CVE-2024-9999"]` dedupes cleanly against an NVD record
/// whose `id = "CVE-2024-9999"`.
#[must_use]
pub(crate) fn canonical_cve_key(record: &CveRecord) -> &str {
    if record.id.starts_with("CVE-") {
        return &record.id;
    }
    for alias in &record.aliases {
        if alias.starts_with("CVE-") {
            return alias.as_str();
        }
    }
    &record.id
}

/// Deduplicate `records` by canonical CVE ID, preferring higher
/// `cvss_score`. Equal scores (including both `None`) preserve
/// first-seen order — stable given stable iteration order.
///
/// Allocation is `O(N)` in the input size; stable across identical
/// inputs.
#[must_use]
pub(crate) fn dedupe_by_canonical_id(records: Vec<CveRecord>) -> Vec<CveRecord> {
    // `by_key[canonical_key] = position in `out`.
    let mut out: Vec<CveRecord> = Vec::with_capacity(records.len());
    let mut by_key: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for record in records {
        let key = canonical_cve_key(&record).to_string();
        if let Some(&pos) = by_key.get(&key) {
            // Existing record — keep whichever has the higher CVSS.
            let incoming_score = record.cvss_score.unwrap_or(f64::NEG_INFINITY);
            let existing_score = out[pos].cvss_score.unwrap_or(f64::NEG_INFINITY);
            if incoming_score > existing_score {
                out[pos] = record;
            }
            // On equal score we keep the first-seen record.
        } else {
            by_key.insert(key, out.len());
            out.push(record);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::cve::severity_from_cvss;
    use crate::engine::error::ScorchError;
    use crate::engine::severity::Severity;

    /// Convenience builder for fixture records.
    fn make_record(id: &str, score: Option<f64>, aliases: Vec<&str>) -> CveRecord {
        let severity = score.map_or(Severity::Info, severity_from_cvss);
        CveRecord {
            id: id.to_string(),
            cvss_score: score,
            severity,
            description: format!("fixture {id}"),
            references: Vec::new(),
            cpe: "cpe:2.3:a:fixture:widget:1.0:*:*:*:*:*:*:*".to_string(),
            aliases: aliases.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// Fixture CveLookup wrapping a static Vec<CveRecord>. Calls
    /// `query(cpe)` with no CPE filtering — returns the stored records
    /// unconditionally.
    struct FixtureLookup {
        records: Vec<CveRecord>,
    }

    #[async_trait]
    impl CveLookup for FixtureLookup {
        async fn query(&self, _cpe: &str) -> Result<Vec<CveRecord>> {
            Ok(self.records.clone())
        }
    }

    /// CveLookup that always returns Err — used to verify per-source
    /// error isolation.
    struct FailingLookup;

    #[async_trait]
    impl CveLookup for FailingLookup {
        async fn query(&self, _cpe: &str) -> Result<Vec<CveRecord>> {
            Err(ScorchError::Config("fixture failure".to_string()))
        }
    }

    // ---- canonical_cve_key ----

    #[test]
    fn canonical_key_prefers_cve_prefix() {
        let rec = make_record("CVE-2024-1", Some(7.5), vec![]);
        assert_eq!(canonical_cve_key(&rec), "CVE-2024-1");
    }

    #[test]
    fn canonical_key_uses_alias_cve_id() {
        let rec = make_record("GHSA-abcd-efgh-ijkl", Some(7.5), vec!["CVE-2024-1"]);
        assert_eq!(canonical_cve_key(&rec), "CVE-2024-1");
    }

    #[test]
    fn canonical_key_falls_back_to_raw_id() {
        let rec = make_record("GHSA-abcd-efgh-ijkl", Some(7.5), vec![]);
        assert_eq!(canonical_cve_key(&rec), "GHSA-abcd-efgh-ijkl");
    }

    #[test]
    fn canonical_key_skips_non_cve_aliases() {
        // An alias not starting with `CVE-` should be ignored; the
        // raw id is returned instead.
        let rec = make_record("GHSA-abcd", Some(7.5), vec!["PYSEC-2024-1", "OSV-2024-5"]);
        assert_eq!(canonical_cve_key(&rec), "GHSA-abcd");
    }

    // ---- dedupe_by_canonical_id ----

    #[test]
    fn dedupe_handles_empty_input() {
        let out = dedupe_by_canonical_id(vec![]);
        assert!(out.is_empty());
    }

    #[test]
    fn dedupe_handles_no_duplicates() {
        let a = make_record("CVE-2024-1", Some(7.5), vec![]);
        let b = make_record("CVE-2024-2", Some(8.0), vec![]);
        let c = make_record("GHSA-xxxx", Some(5.0), vec![]);
        let out = dedupe_by_canonical_id(vec![a.clone(), b.clone(), c.clone()]);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].id, a.id);
        assert_eq!(out[1].id, b.id);
        assert_eq!(out[2].id, c.id);
    }

    #[test]
    fn dedupe_preserves_highest_cvss() {
        let lower = make_record("CVE-2024-1", Some(7.5), vec![]);
        let higher = make_record("CVE-2024-1", Some(9.0), vec![]);
        // Insert lower first, higher second — dedup should swap in higher.
        let out = dedupe_by_canonical_id(vec![lower, higher.clone()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cvss_score, higher.cvss_score);
    }

    #[test]
    fn dedupe_tiebreak_first_seen() {
        let first = CveRecord {
            id: "CVE-2024-1".to_string(),
            cvss_score: Some(7.5),
            severity: Severity::High,
            description: "first".to_string(),
            references: Vec::new(),
            cpe: String::new(),
            aliases: Vec::new(),
        };
        let second = CveRecord {
            id: "CVE-2024-1".to_string(),
            cvss_score: Some(7.5),
            severity: Severity::High,
            description: "second".to_string(),
            references: Vec::new(),
            cpe: String::new(),
            aliases: Vec::new(),
        };
        let out = dedupe_by_canonical_id(vec![first.clone(), second]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].description, first.description);
    }

    #[test]
    fn dedupe_collapses_across_cve_and_ghsa_via_alias() {
        // NVD-style: id = CVE-2024-1, no aliases.
        let nvd = make_record("CVE-2024-1", Some(7.5), vec![]);
        // OSV-style: id = GHSA-..., aliases include CVE-2024-1.
        let osv = make_record("GHSA-abcd", Some(9.0), vec!["CVE-2024-1"]);
        let out = dedupe_by_canonical_id(vec![nvd, osv.clone()]);
        assert_eq!(out.len(), 1, "records with the same canonical key must collapse");
        // Higher CVSS (OSV) wins.
        assert_eq!(out[0].cvss_score, osv.cvss_score);
    }

    #[test]
    fn dedupe_none_score_loses_to_numeric() {
        let nvd_none = make_record("CVE-2024-1", None, vec![]);
        let osv_numeric = make_record("CVE-2024-1", Some(5.0), vec![]);
        let out = dedupe_by_canonical_id(vec![nvd_none, osv_numeric.clone()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cvss_score, osv_numeric.cvss_score);
    }

    // ---- MultiCveLookup ----

    #[tokio::test]
    async fn multi_cve_lookup_merges_from_multiple_sources() {
        let a = FixtureLookup { records: vec![make_record("CVE-2024-1", Some(7.5), vec![])] };
        let b = FixtureLookup { records: vec![make_record("CVE-2024-2", Some(8.0), vec![])] };
        let multi = MultiCveLookup::new(vec![Box::new(a), Box::new(b)]);
        let out = multi.query("cpe:2.3:*:*:*:*:*:*:*:*:*:*:*").await.expect("query");
        let ids: Vec<&str> = out.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-2024-1", "CVE-2024-2"]);
    }

    #[tokio::test]
    async fn multi_cve_lookup_dedupes_cross_backend_overlap() {
        // NVD returns CVE-2024-1 with CVSS 7.5.
        // OSV returns GHSA-abcd with CVSS 9.0 aliased to CVE-2024-1.
        let nvd = FixtureLookup { records: vec![make_record("CVE-2024-1", Some(7.5), vec![])] };
        let osv = FixtureLookup {
            records: vec![make_record("GHSA-abcd", Some(9.0), vec!["CVE-2024-1"])],
        };
        let multi = MultiCveLookup::new(vec![Box::new(nvd), Box::new(osv)]);
        let out = multi.query("cpe:2.3:*:*:*:*:*:*:*:*:*:*:*").await.expect("query");
        assert_eq!(out.len(), 1, "overlap must collapse to one record");
        // OSV's record (higher CVSS) wins the tiebreak.
        assert_eq!(out[0].cvss_score, Some(9.0));
    }

    #[tokio::test]
    async fn multi_cve_lookup_isolates_per_source_errors() {
        let fail = FailingLookup;
        let ok = FixtureLookup { records: vec![make_record("CVE-2024-1", Some(7.5), vec![])] };
        let multi = MultiCveLookup::new(vec![Box::new(fail), Box::new(ok)]);
        let out = multi.query("cpe:2.3:*:*:*:*:*:*:*:*:*:*:*").await.expect("aggregate still Ok");
        assert_eq!(out.len(), 1, "only the working source contributes");
        assert_eq!(out[0].id, "CVE-2024-1");
    }

    #[tokio::test]
    async fn multi_cve_lookup_empty_sources_vec_returns_empty() {
        let multi = MultiCveLookup::new(Vec::new());
        let out = multi.query("cpe:2.3:*:*:*:*:*:*:*:*:*:*:*").await.expect("query");
        assert!(out.is_empty());
    }

    /// Debug impl shows source count without leaking internals.
    #[test]
    fn multi_cve_lookup_debug_format() {
        let multi = MultiCveLookup::new(vec![Box::new(FailingLookup), Box::new(FailingLookup)]);
        let s = format!("{multi:?}");
        assert!(s.contains("MultiCveLookup"), "{s}");
        assert!(s.contains("source_count"), "{s}");
    }
}
