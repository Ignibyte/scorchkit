//! In-memory fixture-backed [`CveLookup`] for tests and examples.
//!
//! `MockCveLookup` stores a `HashMap<String, Vec<CveRecord>>` keyed by
//! CPE and returns those records on query. Unknown CPEs return an empty
//! vec. Useful for exercising
//! [`crate::infra::cve_match::CveMatchModule`] end-to-end without a
//! live CVE backend.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::engine::cve::{CveLookup, CveRecord};
use crate::engine::error::Result;

/// Fixture-backed [`CveLookup`] implementation.
#[derive(Debug, Default)]
pub struct MockCveLookup {
    fixtures: HashMap<String, Vec<CveRecord>>,
}

impl MockCveLookup {
    /// Create an empty mock lookup. Every query returns an empty vec.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the mock with a CPE → record mapping. Chainable.
    #[must_use]
    pub fn with_fixture(mut self, cpe: impl Into<String>, records: Vec<CveRecord>) -> Self {
        self.fixtures.insert(cpe.into(), records);
        self
    }
}

#[async_trait]
impl CveLookup for MockCveLookup {
    async fn query(&self, cpe: &str) -> Result<Vec<CveRecord>> {
        Ok(self.fixtures.get(cpe).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::severity::Severity;

    fn fixture_record(id: &str, cpe: &str, score: f64) -> CveRecord {
        CveRecord {
            id: id.to_string(),
            cvss_score: Some(score),
            severity: crate::engine::cve::severity_from_cvss(score),
            description: format!("fixture {id}"),
            references: vec![],
            cpe: cpe.to_string(),
            aliases: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_mock_cve_lookup_empty() {
        let mock = MockCveLookup::new();
        let out = mock.query("cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*").await.expect("query");
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn test_mock_cve_lookup_fixture_match() {
        let cpe = "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*";
        let mock =
            MockCveLookup::new().with_fixture(cpe, vec![fixture_record("CVE-2024-1", cpe, 9.8)]);
        let out = mock.query(cpe).await.expect("query");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "CVE-2024-1");
        assert_eq!(out[0].severity, Severity::Critical);
    }

    #[tokio::test]
    async fn test_mock_cve_lookup_unknown_cpe() {
        let mock = MockCveLookup::new().with_fixture(
            "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*",
            vec![fixture_record("CVE-2024-1", "...", 9.8)],
        );
        let out = mock.query("cpe:2.3:a:unknown:foo:0.0:*:*:*:*:*:*:*").await.expect("query");
        assert!(out.is_empty());
    }
}
