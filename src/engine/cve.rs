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

    #[test]
    fn test_cve_record_serde_round_trip() {
        let rec = CveRecord {
            id: "CVE-2024-1234".to_string(),
            cvss_score: Some(9.8),
            severity: Severity::Critical,
            description: "Buffer overflow in Acme widget".to_string(),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-1234".to_string()],
            cpe: "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*".to_string(),
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        let back: CveRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.id, rec.id);
        assert_eq!(back.cvss_score, rec.cvss_score);
        assert_eq!(back.severity, rec.severity);
    }
}
