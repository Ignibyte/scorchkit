//! nmap-based port scan + service fingerprinting as an
//! [`InfraModule`](crate::engine::infra_module::InfraModule).
//!
//! Runs `nmap -sV --top-ports 1000 -oX - <target>`, parses the XML output
//! via the shared [`crate::engine::service_fingerprint::parse_nmap_xml_fingerprints`]
//! helper, publishes the resulting `Vec<ServiceFingerprint>` to
//! `ctx.shared_data` under
//! [`crate::engine::service_fingerprint::SHARED_KEY_FINGERPRINTS`], and
//! emits one `Info` [`Finding`] per open port.
//!
//! Richer severity classification and outdated-version detection live in
//! the DAST [`crate::tools::nmap::NmapModule`] wrapper — this infra
//! version stays minimal because CVE correlation (WORK-103) is the
//! intended consumer of the published fingerprints.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::infra_context::InfraContext;
use crate::engine::infra_module::{InfraCategory, InfraModule};
use crate::engine::infra_target::InfraTarget;
use crate::engine::service_fingerprint::{
    parse_nmap_xml_fingerprints, publish_fingerprints, ServiceFingerprint,
};
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Default nmap CLI timeout — port scans can take a while on `/24`-scale
/// networks or for the top-1000 port set.
const NMAP_TIMEOUT: Duration = Duration::from_secs(600);

/// nmap port scan + fingerprint module.
#[derive(Debug, Default)]
pub struct NmapModule;

#[async_trait]
impl InfraModule for NmapModule {
    fn name(&self) -> &'static str {
        "nmap — port scan + fingerprint"
    }

    fn id(&self) -> &'static str {
        "nmap"
    }

    fn category(&self) -> InfraCategory {
        InfraCategory::PortScan
    }

    fn description(&self) -> &'static str {
        "nmap -sV port scan with service fingerprinting; publishes CPE-tagged fingerprints"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("nmap")
    }

    fn protocols(&self) -> &[&str] {
        &["tcp"]
    }

    async fn run(&self, ctx: &InfraContext) -> Result<Vec<Finding>> {
        let target_arg = nmap_target_arg(&ctx.target);
        if target_arg.is_empty() {
            return Ok(Vec::new());
        }

        let output = subprocess::run_tool(
            "nmap",
            &["-sV", "--top-ports", "1000", "-oX", "-", &target_arg],
            NMAP_TIMEOUT,
        )
        .await?;

        let fingerprints = parse_nmap_xml_fingerprints(&output.stdout);
        if !fingerprints.is_empty() {
            publish_fingerprints(&ctx.shared_data, &fingerprints);
        }

        Ok(fingerprints_to_findings(&fingerprints, &target_arg))
    }
}

/// Build the `nmap` CLI target argument from an [`InfraTarget`].
///
/// - `Ip` / `Cidr` / `Host` → their display form.
/// - `Endpoint` → the host portion (nmap can't restrict to a single port
///   via the positional target).
/// - `Multi` → children joined with spaces so nmap accepts them as a list.
///
/// Returns an empty string if the target has no scannable form.
#[must_use]
pub fn nmap_target_arg(target: &InfraTarget) -> String {
    match target {
        InfraTarget::Ip(ip) => ip.to_string(),
        InfraTarget::Cidr(net) => net.to_string(),
        InfraTarget::Host(host) | InfraTarget::Endpoint { host, .. } => host.clone(),
        InfraTarget::Multi(children) => children
            .iter()
            .map(nmap_target_arg)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// Convert parsed fingerprints into Info-level findings for terminal
/// reporting. CVE correlation against these fingerprints happens in
/// WORK-103.
#[must_use]
pub fn fingerprints_to_findings(
    fingerprints: &[ServiceFingerprint],
    affected_target: &str,
) -> Vec<Finding> {
    fingerprints
        .iter()
        .map(|fp| {
            let product_version = match (fp.product.as_deref(), fp.version.as_deref()) {
                (Some(p), Some(v)) => format!("{p} {v}"),
                (Some(p), None) => p.to_string(),
                _ => fp.service_name.clone(),
            };
            let mut f = Finding::new(
                "nmap",
                Severity::Info,
                format!("Open port {}/{} ({})", fp.port, fp.protocol, fp.service_name),
                format!(
                    "nmap detected an open {}/{} port running {}.",
                    fp.port, fp.protocol, product_version
                ),
                affected_target,
            )
            .with_confidence(0.9);
            if let Some(cpe) = &fp.cpe {
                f = f.with_evidence(format!("CPE: {cpe}"));
            }
            f
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::infra_target::InfraTarget;
    use crate::engine::service_fingerprint::{read_fingerprints, SHARED_KEY_FINGERPRINTS};
    use crate::engine::shared_data::SharedData;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    #[test]
    fn test_infra_nmap_module_metadata() {
        let m = NmapModule;
        assert_eq!(m.id(), "nmap");
        assert_eq!(m.category(), InfraCategory::PortScan);
        assert!(m.requires_external_tool());
        assert_eq!(m.required_tool(), Some("nmap"));
        assert_eq!(m.protocols(), &["tcp"]);
    }

    #[test]
    fn test_nmap_target_arg_for_each_variant() {
        assert_eq!(
            nmap_target_arg(&InfraTarget::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
            "192.0.2.1"
        );
        let cidr = "10.0.0.0/24".parse::<ipnet::IpNet>().expect("cidr");
        assert_eq!(nmap_target_arg(&InfraTarget::Cidr(cidr)), "10.0.0.0/24");
        assert_eq!(nmap_target_arg(&InfraTarget::Host("example.com".into())), "example.com");
        assert_eq!(
            nmap_target_arg(&InfraTarget::Endpoint { host: "example.com".into(), port: 443 }),
            "example.com"
        );
        let multi =
            InfraTarget::Multi(vec![InfraTarget::Host("a".into()), InfraTarget::Host("b".into())]);
        assert_eq!(nmap_target_arg(&multi), "a b");
    }

    #[test]
    fn test_fingerprints_to_findings_emits_one_per_fingerprint() {
        let fps = vec![
            ServiceFingerprint {
                port: 80,
                protocol: "tcp".into(),
                service_name: "http".into(),
                product: Some("nginx".into()),
                version: Some("1.25".into()),
                cpe: Some("cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*".into()),
            },
            ServiceFingerprint {
                port: 22,
                protocol: "tcp".into(),
                service_name: "ssh".into(),
                product: None,
                version: None,
                cpe: None,
            },
        ];
        let findings = fingerprints_to_findings(&fps, "192.0.2.1");
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("80"));
        assert!(findings[0].evidence.as_deref().unwrap_or("").contains("CPE"));
        assert!(findings[1].title.contains("22"));
        assert!(findings[1].evidence.is_none());
    }

    /// Verify the publish → read round-trip through `SharedData` works when
    /// the module would have published fingerprints. We don't actually run
    /// nmap (that requires the binary + network) — we exercise the
    /// publish side via the same helper the module uses.
    #[tokio::test]
    async fn test_infra_nmap_publishes_fingerprints_via_shared_data() {
        let shared = Arc::new(SharedData::new());
        let fps = vec![ServiceFingerprint {
            port: 443,
            protocol: "tcp".into(),
            service_name: "https".into(),
            product: Some("nginx".into()),
            version: Some("1.25".into()),
            cpe: Some("cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*".into()),
        }];
        publish_fingerprints(&shared, &fps);
        assert!(shared.has(SHARED_KEY_FINGERPRINTS));
        let back = read_fingerprints(&shared);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].port, 443);
    }
}
