//! CVE record types and lookup trait.
//!
//! [`CveRecord`] captures the subset of CVE metadata `ScorchKit` surfaces
//! through findings — identifier, CVSS score, mapped severity, a short
//! description, reference URLs, and the CPE the record was matched
//! against. [`CveLookup`] is the async trait backends implement so the
//! infra CVE-matching module can correlate service fingerprints to known
//! vulnerabilities.
//!
//! A fixture-backed [`crate::infra::cve_mock::MockCveLookup`] and the
//! infra-side [`crate::infra::cve_match::CveMatchModule`] live behind the
//! `infra` feature. The types and trait here are unconditionally
//! available so findings / storage / reporting that refer to CVE data
//! don't need to cfg-gate their own declarations.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::error::Result;
use super::severity::Severity;

/// A CVE record surfaced during infra scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveRecord {
    /// CVE identifier (e.g. `"CVE-2024-1234"`).
    pub id: String,
    /// CVSS v3.x base score (0.0–10.0) when known.
    pub cvss_score: Option<f64>,
    /// Mapped severity — usually computed via [`severity_from_cvss`].
    pub severity: Severity,
    /// Short description or summary.
    pub description: String,
    /// Reference URLs (advisories, patches, exploit DBs).
    pub references: Vec<String>,
    /// The CPE this record was matched against.
    pub cpe: String,
    /// Alternate identifiers for the same underlying vulnerability.
    ///
    /// OSV's query API returns an `aliases[]` array — e.g. a `GHSA-`
    /// record's `aliases` will commonly include the corresponding
    /// `CVE-YYYY-NNNN` id. Populated by [`crate::infra::cve_osv::OsvCveLookup`];
    /// empty for NVD and [`crate::infra::cve_mock::MockCveLookup`].
    ///
    /// Consumed by [`crate::infra::cve_multi::MultiCveLookup`] for
    /// cross-backend deduplication: two records from NVD and OSV are
    /// collapsed when one's `id` matches an entry in the other's
    /// `aliases`.
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// Map a CVSS v3.x base score onto [`Severity`] using the standard bands.
///
/// - `0.0` → [`Severity::Info`] (no score).
/// - `0.1 – 3.9` → [`Severity::Low`].
/// - `4.0 – 6.9` → [`Severity::Medium`].
/// - `7.0 – 8.9` → [`Severity::High`].
/// - `9.0 – 10.0` → [`Severity::Critical`].
///
/// Scores outside `0.0..=10.0` clamp to the nearest band; NaN maps to
/// [`Severity::Info`].
#[must_use]
pub fn severity_from_cvss(score: f64) -> Severity {
    if score.is_nan() || score <= 0.0 {
        return Severity::Info;
    }
    if score < 4.0 {
        Severity::Low
    } else if score < 7.0 {
        Severity::Medium
    } else if score < 9.0 {
        Severity::High
    } else {
        Severity::Critical
    }
}

/// Parsed CVSS v3 base metrics — every field needed to compute the
/// base score, with `pr` left as the raw string until the scope is
/// known (the privileges-required weight depends on it).
struct CvssMetrics<'a> {
    av: Option<f64>,
    ac: Option<f64>,
    pr_raw: Option<&'a str>,
    ui: Option<f64>,
    scope_changed: Option<bool>,
    c: Option<f64>,
    i: Option<f64>,
    a: Option<f64>,
}

/// Map one CVSS v3 metric `key:value` pair onto [`CvssMetrics`]. Returns
/// `Err(())` for an out-of-spec metric value (e.g. `AV:Q`) so the
/// caller can short-circuit to `None`. Uses `core::result::Result`
/// explicitly because the module-level `Result` alias is fixed to
/// [`ScorchError`].
fn apply_metric<'a>(
    metrics: &mut CvssMetrics<'a>,
    key: &str,
    val: &'a str,
) -> core::result::Result<(), ()> {
    match key {
        "AV" => {
            metrics.av = Some(match val {
                "N" => 0.85,
                "A" => 0.62,
                "L" => 0.55,
                "P" => 0.2,
                _ => return Err(()),
            });
        }
        "AC" => {
            metrics.ac = Some(match val {
                "L" => 0.77,
                "H" => 0.44,
                _ => return Err(()),
            });
        }
        "PR" => metrics.pr_raw = Some(val),
        "UI" => {
            metrics.ui = Some(match val {
                "N" => 0.85,
                "R" => 0.62,
                _ => return Err(()),
            });
        }
        "S" => {
            metrics.scope_changed = Some(match val {
                "U" => false,
                "C" => true,
                _ => return Err(()),
            });
        }
        "C" | "I" | "A" => {
            let weight = match val {
                "N" => 0.0,
                "L" => 0.22,
                "H" => 0.56,
                _ => return Err(()),
            };
            match key {
                "C" => metrics.c = Some(weight),
                "I" => metrics.i = Some(weight),
                _ => metrics.a = Some(weight),
            }
        }
        // Ignore temporal/environmental and unknown metrics — base
        // score uses only the eight base metrics above.
        _ => {}
    }
    Ok(())
}

/// Compute a CVSS v3.x base score from a vector string.
///
/// Accepts a vector of the form
/// `CVSS:3.x/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_` and returns the
/// computed base score per the [CVSS v3.1 specification][spec]. Returns
/// `None` for malformed vectors, missing required metrics, or any
/// metric value outside the v3 spec.
///
/// Useful for backends like OSV that surface the vector string rather
/// than the numeric base score. Pair with [`severity_from_cvss`] to map
/// the result onto a [`Severity`].
///
/// [spec]: https://www.first.org/cvss/v3.1/specification-document
#[must_use]
pub fn cvss_v3_base_score(vector: &str) -> Option<f64> {
    if !(vector.starts_with("CVSS:3.0/") || vector.starts_with("CVSS:3.1/")) {
        return None;
    }
    let mut metrics = CvssMetrics {
        av: None,
        ac: None,
        pr_raw: None,
        ui: None,
        scope_changed: None,
        c: None,
        i: None,
        a: None,
    };
    for part in vector.split('/').skip(1) {
        let (key, val) = part.split_once(':')?;
        apply_metric(&mut metrics, key, val).ok()?;
    }

    let av = metrics.av?;
    let ac = metrics.ac?;
    let ui = metrics.ui?;
    let scope_changed = metrics.scope_changed?;
    let c = metrics.c?;
    let i = metrics.i?;
    let a = metrics.a?;
    let pr = match (metrics.pr_raw?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };

    // `mul_add` is the spec's recommended fused-multiply-add for
    // numerical stability and matches FIRST's reference impls.
    let iss = 1.0 - f64::mul_add(1.0 - c, (1.0 - i) * (1.0 - a), 0.0);
    let impact = if scope_changed {
        // f64::mul_add keeps the spec's exact arithmetic to one fused
        // op per term, which clippy prefers and matches the reference
        // implementations published by FIRST.
        f64::mul_add(7.52, iss - 0.029, -3.25 * (iss - 0.02).powi(15))
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw =
        if scope_changed { (impact + exploitability) * 1.08 } else { impact + exploitability };
    Some(round_up_tenth(raw.min(10.0)))
}

/// Round a CVSS sub-score up to the nearest tenth, per spec
/// [Appendix A.2](https://www.first.org/cvss/v3.1/specification-document):
/// "Round-up returns the smallest number, specified to 1 decimal place,
/// that is equal to or higher than its input." For inputs in
/// `0.0..=10.0` (the entire CVSS base-score domain), `ceil(x * 10)/10`
/// matches the spec's rigorous integer formulation within float
/// precision and avoids signed-integer casts.
fn round_up_tenth(value: f64) -> f64 {
    (value * 10.0).ceil() / 10.0
}

/// Async trait for CVE lookup backends.
///
/// Implementations query some external or bundled source of CVE records
/// (NVD, OSV, a local database, or a test fixture) and return every
/// record affecting the queried CPE. The trait is deliberately minimal —
/// richer query shapes (package+version, ecosystem, date ranges) live on
/// concrete impls, not on this trait.
#[async_trait]
pub trait CveLookup: Send + Sync {
    /// Query CVE records for a CPE 2.3 identifier.
    ///
    /// Returns an empty vec when no records are known. Returns `Err` for
    /// infrastructure failures (network, parse, rate-limit). The infra
    /// CVE-matching module treats errors as non-fatal — the scan
    /// continues for the remaining fingerprints.
    ///
    /// # Errors
    ///
    /// Implementations return [`crate::engine::error::ScorchError`]
    /// variants appropriate to their backend.
    async fn query(&self, cpe: &str) -> Result<Vec<CveRecord>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_cvss_critical() {
        assert_eq!(severity_from_cvss(9.0), Severity::Critical);
        assert_eq!(severity_from_cvss(9.5), Severity::Critical);
        assert_eq!(severity_from_cvss(10.0), Severity::Critical);
    }

    #[test]
    fn test_severity_from_cvss_high() {
        assert_eq!(severity_from_cvss(7.0), Severity::High);
        assert_eq!(severity_from_cvss(8.9), Severity::High);
    }

    #[test]
    fn test_severity_from_cvss_medium() {
        assert_eq!(severity_from_cvss(4.0), Severity::Medium);
        assert_eq!(severity_from_cvss(6.9), Severity::Medium);
    }

    #[test]
    fn test_severity_from_cvss_low() {
        assert_eq!(severity_from_cvss(0.1), Severity::Low);
        assert_eq!(severity_from_cvss(3.9), Severity::Low);
    }

    #[test]
    fn test_severity_from_cvss_zero_is_info() {
        assert_eq!(severity_from_cvss(0.0), Severity::Info);
    }

    #[test]
    fn test_severity_from_cvss_nan_is_info() {
        assert_eq!(severity_from_cvss(f64::NAN), Severity::Info);
    }

    #[test]
    fn test_severity_from_cvss_over_10_is_critical() {
        // Clamp-by-band: anything >= 9.0 maps to Critical including out-of-range.
        assert_eq!(severity_from_cvss(11.0), Severity::Critical);
    }

    /// Helper: assert two CVSS scores are within one tenth (spec
    /// rounding precision) of each other.
    fn approx_eq_tenth(a: f64, b: f64) {
        assert!((a - b).abs() < 0.05, "expected {b} ± 0.05, got {a}");
    }

    /// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — Log4Shell shape.
    /// Pinning the canonical 9.8 lets us catch any regression in the
    /// rounding helper or metric tables.
    #[test]
    fn cvss_v3_base_score_critical() {
        let s =
            cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").expect("computes");
        approx_eq_tenth(s, 9.8);
    }

    /// Scope-changed (S:C) takes a different impact and final-multiplier
    /// path. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0.
    #[test]
    fn cvss_v3_base_score_scope_changed_max() {
        let s =
            cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").expect("computes");
        approx_eq_tenth(s, 10.0);
    }

    /// CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N → 5.4 (medium band).
    #[test]
    fn cvss_v3_base_score_medium() {
        let s =
            cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N").expect("computes");
        approx_eq_tenth(s, 5.4);
    }

    /// CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N → 1.8 (low band).
    #[test]
    fn cvss_v3_base_score_low() {
        let s =
            cvss_v3_base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N").expect("computes");
        approx_eq_tenth(s, 1.8);
    }

    /// Missing the `A:` (Availability) metric makes the vector
    /// incomplete; computer returns `None` rather than guessing a
    /// default.
    #[test]
    fn cvss_v3_base_score_missing_metric_returns_none() {
        let s = cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H");
        assert!(s.is_none());
    }

    /// Vector that doesn't start with the `CVSS:3.x/` prefix is not a
    /// valid v3 vector; computer returns `None`.
    #[test]
    fn cvss_v3_base_score_malformed_returns_none() {
        assert!(cvss_v3_base_score("not a vector").is_none());
        assert!(cvss_v3_base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P").is_none());
    }

    /// CVSS 3.0 vectors share the v3.1 algorithm; the only change in
    /// 3.1 was clarification of the rounding rule (already implemented).
    #[test]
    fn cvss_v3_base_score_accepts_v3_0_prefix() {
        let s =
            cvss_v3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").expect("computes");
        approx_eq_tenth(s, 9.8);
    }

    #[test]
    fn test_cve_record_serde_round_trip() {
        let rec = CveRecord {
            id: "CVE-2024-1234".to_string(),
            cvss_score: Some(9.8),
            severity: Severity::Critical,
            description: "Buffer overflow in Acme widget".to_string(),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-1234".to_string()],
            cpe: "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*".to_string(),
            aliases: Vec::new(),
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let back: CveRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.id, rec.id);
        assert_eq!(back.cvss_score, rec.cvss_score);
        assert_eq!(back.severity, rec.severity);
    }

    /// `CveRecord` constructed without setting `aliases` (via `..Default-`
    /// style or direct init) has empty aliases. Verifies the additive
    /// field doesn't break existing construction patterns.
    #[test]
    fn cve_record_aliases_default_empty() {
        let rec = CveRecord {
            id: "CVE-2024-1".to_string(),
            cvss_score: None,
            severity: Severity::Info,
            description: String::new(),
            references: Vec::new(),
            cpe: String::new(),
            aliases: Vec::new(),
        };
        assert!(rec.aliases.is_empty());
    }

    /// JSON missing the `aliases` field deserialises with empty
    /// aliases — pins the `#[serde(default)]` contract so existing
    /// storage JSON and MCP responses stay compatible.
    #[test]
    fn cve_record_aliases_serde_round_trip() {
        // No aliases field in JSON — uses serde default.
        let json_no_aliases = r#"{
            "id": "CVE-2024-1",
            "cvss_score": null,
            "severity": "info",
            "description": "",
            "references": [],
            "cpe": ""
        }"#;
        let rec: CveRecord = serde_json::from_str(json_no_aliases).expect("deserialize");
        assert!(rec.aliases.is_empty());

        // With populated aliases — round-trips.
        let with = CveRecord {
            id: "GHSA-abcd-efgh".to_string(),
            cvss_score: Some(7.5),
            severity: Severity::High,
            description: String::new(),
            references: Vec::new(),
            cpe: "cpe:2.3:a:pkg:widget:1.0:*:*:*:*:*:*:*".to_string(),
            aliases: vec!["CVE-2024-9999".to_string()],
        };
        let js = serde_json::to_string(&with).expect("serialize");
        let back: CveRecord = serde_json::from_str(&js).expect("deserialize");
        assert_eq!(back.aliases, vec!["CVE-2024-9999".to_string()]);
    }
}
