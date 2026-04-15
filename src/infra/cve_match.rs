//! [`InfraModule`] that correlates service fingerprints against a
//! [`CveLookup`] backend and emits one finding per matched CVE.
//!
//! Reads `Vec<ServiceFingerprint>` from `ctx.shared_data` via
//! [`crate::engine::service_fingerprint::read_fingerprints`], iterates
//! fingerprints that carry a `cpe`, queries the injected lookup
//! sequentially, and builds findings tagged with the CVE identifier and
//! CVSS score. Per-fingerprint query errors are logged at `warn` and
//! skipped — a single backend hiccup should not abort the scan.
//!
//! The module is NOT registered in
//! [`crate::infra::register_modules`] because it requires a
//! construction-time lookup injection. Users who want CVE matching build
//! the orchestrator manually today; WORK-105's unified `assess` command
//! will wire the right lookup from config.

use async_trait::async_trait;
use tracing::warn;

use crate::engine::cve::CveLookup;
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::infra_context::InfraContext;
use crate::engine::infra_module::{InfraCategory, InfraModule};
use crate::engine::service_fingerprint::{read_fingerprints, ServiceFingerprint};

/// `InfraModule` that correlates fingerprints to CVEs.
pub struct CveMatchModule {
    lookup: Box<dyn CveLookup>,
}

impl std::fmt::Debug for CveMatchModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CveMatchModule").finish_non_exhaustive()
    }
}

impl CveMatchModule {
    /// Build a new matcher with the given lookup backend.
    #[must_use]
    pub const fn new(lookup: Box<dyn CveLookup>) -> Self {
        Self { lookup }
    }
}

#[async_trait]
impl InfraModule for CveMatchModule {
    fn name(&self) -> &'static str {
        "CVE Match"
    }

    fn id(&self) -> &'static str {
        "cve_match"
    }

    fn category(&self) -> InfraCategory {
        InfraCategory::CveMatch
    }

    fn description(&self) -> &'static str {
        "Correlate service fingerprints against a CveLookup backend"
    }

    async fn run(&self, ctx: &InfraContext) -> Result<Vec<Finding>> {
        let fingerprints = read_fingerprints(&ctx.shared_data);
        let mut findings = Vec::new();

        for fp in fingerprints {
            let Some(cpe) = fp.cpe.as_ref() else {
                continue;
            };
            match self.lookup.query(cpe).await {
                Ok(records) => {
                    for rec in records {
                        findings.push(build_finding(&fp, &rec));
                    }
                }
                Err(e) => {
                    warn!("cve_match: query failed for {cpe}: {e}");
                }
            }
        }

        Ok(findings)
    }
}

fn build_finding(fp: &ServiceFingerprint, rec: &crate::engine::cve::CveRecord) -> Finding {
    let product_version = match (fp.product.as_deref(), fp.version.as_deref()) {
        (Some(p), Some(v)) => format!("{p} {v}"),
        (Some(p), None) => p.to_string(),
        _ => fp.service_name.clone(),
    };
    let title = format!("{}: {} ({})", rec.id, product_version, fp.port);
    let affected = format!("{}:{}", fp.service_name, fp.port);
    let mut f = Finding::new("cve_match", rec.severity, title, rec.description.clone(), affected)
        .with_evidence(format!(
            "CVE: {} | CPE: {} | CVSS: {}",
            rec.id,
            rec.cpe,
            rec.cvss_score.map_or_else(|| "n/a".to_string(), |s| format!("{s:.1}")),
        ))
        .with_confidence(rec.cvss_score.map_or(0.6, |_| 0.9));
    if !rec.references.is_empty() {
        f = f.with_remediation(format!(
            "See references: {}",
            rec.references.iter().take(3).cloned().collect::<Vec<_>>().join(", "),
        ));
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::engine::cve::{severity_from_cvss, CveRecord};
    use crate::engine::infra_target::InfraTarget;
    use crate::engine::service_fingerprint::publish_fingerprints;
    use crate::infra::cve_mock::MockCveLookup;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn ctx() -> InfraContext {
        let target = InfraTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let config = Arc::new(AppConfig::default());
        let client = reqwest::Client::builder().build().expect("client");
        InfraContext::new(target, config, client)
    }

    fn fixture_record(id: &str, cpe: &str, score: f64) -> CveRecord {
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

    fn fingerprint_with_cpe(cpe: &str) -> ServiceFingerprint {
        ServiceFingerprint {
            port: 80,
            protocol: "tcp".into(),
            service_name: "http".into(),
            product: Some("nginx".into()),
            version: Some("1.25".into()),
            cpe: Some(cpe.to_string()),
        }
    }

    #[test]
    fn test_cve_match_module_metadata() {
        let module = CveMatchModule::new(Box::new(MockCveLookup::new()));
        assert_eq!(module.id(), "cve_match");
        assert_eq!(module.category(), InfraCategory::CveMatch);
        assert!(!module.requires_external_tool());
    }

    #[tokio::test]
    async fn test_cve_match_module_emits_findings() {
        let cpe = "cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*";
        let lookup = MockCveLookup::new().with_fixture(
            cpe,
            vec![fixture_record("CVE-2024-A", cpe, 9.8), fixture_record("CVE-2024-B", cpe, 5.3)],
        );
        let module = CveMatchModule::new(Box::new(lookup));
        let ctx = ctx();
        publish_fingerprints(&ctx.shared_data, &[fingerprint_with_cpe(cpe)]);

        let findings = module.run(&ctx).await.expect("run");
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.title.contains("CVE-2024-A")));
        assert!(findings.iter().any(|f| f.title.contains("CVE-2024-B")));
    }

    #[tokio::test]
    async fn test_cve_match_module_skips_no_cpe() {
        let module = CveMatchModule::new(Box::new(MockCveLookup::new()));
        let ctx = ctx();
        let fp = ServiceFingerprint {
            port: 22,
            protocol: "tcp".into(),
            service_name: "ssh".into(),
            product: Some("OpenSSH".into()),
            version: None,
            cpe: None, // no CPE -> skipped
        };
        publish_fingerprints(&ctx.shared_data, &[fp]);
        let findings = module.run(&ctx).await.expect("run");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_cve_match_module_empty_shared_data() {
        let module = CveMatchModule::new(Box::new(MockCveLookup::new()));
        let ctx = ctx();
        let findings = module.run(&ctx).await.expect("run");
        assert!(findings.is_empty());
    }
}
