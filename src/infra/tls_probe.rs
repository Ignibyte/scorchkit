//! [`InfraModule`] that probes non-HTTP TLS services and analyses
//! their certificates.
//!
//! Complements [`crate::scanner::ssl::SslModule`] (which handles HTTPS
//! on a single URL) by scanning a host's broader TLS surface:
//!
//! - **Implicit TLS:** SMTPS (465), LDAPS (636), IMAPS (993),
//!   POP3S (995). Port is TLS-wrapped from byte zero.
//! - **STARTTLS:** SMTP (25, 587), IMAP (143), POP3 (110). Plain TCP
//!   connect → protocol-specific upgrade command → TLS.
//!
//! Per-port, the module runs [`crate::engine::tls_probe::probe_tls`]
//! then pipes the resulting [`crate::engine::tls_probe::CertInfo`]
//! through [`crate::engine::tls_probe::check_certificate`] tagged with
//! the `"tls_infra"` module id. Findings are identical in shape to the
//! DAST SSL path — same severities, same OWASP/CWE mappings.
//!
//! ## What's out of scope (for now)
//!
//! - RDP-TLS on 3389: RDP has its own X.224 negotiation dance before
//!   TLS. Non-trivial; tracked as a follow-up.
//! - TLS protocol-range enumeration (does the server still accept
//!   TLSv1.0/1.1?): requires multiple forced-version handshakes.
//! - Cipher-suite enumeration.

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::infra_context::InfraContext;
use crate::engine::infra_module::{InfraCategory, InfraModule};
use crate::engine::infra_target::InfraTarget;
use crate::engine::severity::Severity;
use crate::engine::tls_probe::{check_certificate, probe_tls, StarttlsProtocol, TlsMode};

/// A `(port, mode, service_label)` probe target.
#[derive(Debug, Clone, Copy)]
pub struct TlsProbeTarget {
    /// TCP port to probe.
    pub port: u16,
    /// How to reach the TLS handshake (implicit or STARTTLS flavour).
    pub mode: TlsMode,
    /// Human-readable service tag for evidence text (`"SMTPS"`,
    /// `"LDAPS"`, etc.).
    pub label: &'static str,
}

/// Default probe list. Covers the common TLS-bearing mail / directory
/// services. HTTPS (443) is intentionally absent — the DAST
/// [`crate::scanner::ssl::SslModule`] owns that path.
pub const DEFAULT_PROBE_TARGETS: &[TlsProbeTarget] = &[
    TlsProbeTarget { port: 465, mode: TlsMode::Implicit, label: "SMTPS" },
    TlsProbeTarget { port: 636, mode: TlsMode::Implicit, label: "LDAPS" },
    TlsProbeTarget { port: 993, mode: TlsMode::Implicit, label: "IMAPS" },
    TlsProbeTarget { port: 995, mode: TlsMode::Implicit, label: "POP3S" },
    TlsProbeTarget {
        port: 25,
        mode: TlsMode::Starttls(StarttlsProtocol::Smtp),
        label: "SMTP+STARTTLS",
    },
    TlsProbeTarget {
        port: 587,
        mode: TlsMode::Starttls(StarttlsProtocol::Smtp),
        label: "Submission+STARTTLS",
    },
    TlsProbeTarget {
        port: 143,
        mode: TlsMode::Starttls(StarttlsProtocol::Imap),
        label: "IMAP+STARTTLS",
    },
    TlsProbeTarget {
        port: 110,
        mode: TlsMode::Starttls(StarttlsProtocol::Pop3),
        label: "POP3+STARTTLS",
    },
];

/// Configuration for [`TlsInfraModule`].
#[derive(Debug, Clone)]
pub struct TlsInfraConfig {
    /// Probe targets (port + mode + label).
    pub targets: Vec<TlsProbeTarget>,
}

impl Default for TlsInfraConfig {
    fn default() -> Self {
        Self { targets: DEFAULT_PROBE_TARGETS.to_vec() }
    }
}

impl TlsInfraConfig {
    /// Override the probe list.
    #[must_use]
    pub fn with_targets(mut self, targets: Vec<TlsProbeTarget>) -> Self {
        self.targets = targets;
        self
    }
}

/// Probe a host for non-HTTP TLS services and analyse each cert.
#[derive(Debug, Default)]
pub struct TlsInfraModule {
    config: TlsInfraConfig,
}

impl TlsInfraModule {
    /// Create a probe module with the supplied configuration.
    #[must_use]
    pub const fn with_config(config: TlsInfraConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl InfraModule for TlsInfraModule {
    fn name(&self) -> &'static str {
        "TLS Infra Probe"
    }

    fn id(&self) -> &'static str {
        "tls_infra"
    }

    fn category(&self) -> InfraCategory {
        InfraCategory::TlsInfra
    }

    fn description(&self) -> &'static str {
        "Probe non-HTTP TLS services (SMTPS/LDAPS/IMAPS/POP3S + STARTTLS variants)"
    }

    async fn run(&self, ctx: &InfraContext) -> Result<Vec<Finding>> {
        let host = probe_host_from_target(&ctx.target);
        let Some(host) = host else {
            return Ok(Vec::new());
        };

        let mut findings = Vec::new();
        for target in &self.config.targets {
            findings.extend(probe_one(&host, *target).await);
        }
        Ok(findings)
    }
}

/// Extract a single probe-worthy host string from an infra target.
///
/// TLS cert validation needs a hostname (for SNI + subject/SAN
/// comparison) rather than an IP. We accept IPs too — cert mismatch
/// findings are still useful — but the hostname form is preferred when
/// available.
fn probe_host_from_target(target: &InfraTarget) -> Option<String> {
    match target {
        InfraTarget::Host(h) => Some(h.clone()),
        InfraTarget::Endpoint { host, .. } => Some(host.clone()),
        InfraTarget::Ip(ip) => Some(ip.to_string()),
        // CIDR and Multi aren't probed at this level — the orchestrator
        // expands CIDRs to individual IPs before the module sees them,
        // and Multi is rare in practice.
        InfraTarget::Cidr(_) | InfraTarget::Multi(_) => None,
    }
}

/// Run one probe; convert errors to a single "handshake failed"
/// Finding rather than failing the whole module run. This matches the
/// scanner/ssl.rs behaviour and keeps a single flaky service from
/// wiping out the report.
async fn probe_one(host: &str, target: TlsProbeTarget) -> Vec<Finding> {
    let affected = format!("{host}:{}", target.port);
    match probe_tls(host, target.port, target.mode).await {
        Ok(cert) => check_certificate(&cert, "tls_infra", host, &affected),
        Err(e) => vec![Finding::new(
            "tls_infra",
            Severity::Info,
            format!("{} — TLS probe skipped", target.label),
            format!(
                "TLS probe on {affected} ({}) did not succeed: {e}. This is expected when the \
                 port is closed or the service doesn't speak TLS — reported as Info rather than \
                 a defect.",
                target.label
            ),
            affected.clone(),
        )
        .with_evidence(format!("label={} port={} error={e}", target.label, target.port))
        .with_confidence(0.3)],
    }
}

#[cfg(test)]
mod tests {
    //! Pure-function coverage for the probe configuration, target
    //! extraction, and default port list. Full handshake tests live
    //! in `engine::tls_probe::tests` (STARTTLS preamble) and in the
    //! `#[ignore]`-gated live smoke tests.

    use super::*;
    use crate::config::AppConfig;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn ctx_for(target: InfraTarget) -> InfraContext {
        let client = reqwest::Client::builder().build().expect("client");
        InfraContext::new(target, Arc::new(AppConfig::default()), client)
    }

    /// Default config includes every common TLS-bearing port in the
    /// v1 scope. Pins the contract `docs/modules/tls-infra.md`
    /// documents.
    #[test]
    fn tls_infra_default_probe_list_coverage() {
        let cfg = TlsInfraConfig::default();
        let ports: Vec<u16> = cfg.targets.iter().map(|t| t.port).collect();
        for expected in [465, 636, 993, 995, 25, 587, 143, 110] {
            assert!(ports.contains(&expected), "missing default probe port {expected}");
        }
        assert!(!ports.contains(&443), "443 belongs to DAST ssl, not infra tls_infra");
        assert!(!ports.contains(&3389), "RDP-TLS is explicitly out of scope for v1");
    }

    /// Every default entry has a non-empty label (used in evidence).
    #[test]
    fn tls_infra_default_labels_non_empty() {
        for target in DEFAULT_PROBE_TARGETS {
            assert!(!target.label.is_empty());
        }
    }

    /// Module metadata pins the category + id that the orchestrator
    /// and `--modules` filter key off.
    #[test]
    fn tls_infra_module_metadata() {
        let module = TlsInfraModule::default();
        assert_eq!(module.id(), "tls_infra");
        assert_eq!(module.category(), InfraCategory::TlsInfra);
        assert!(!module.requires_external_tool());
    }

    /// `InfraTarget::Host` yields the hostname unchanged — cert
    /// validation needs the original string.
    #[test]
    fn probe_host_from_target_host() {
        let h = probe_host_from_target(&InfraTarget::Host("mail.example.com".into()));
        assert_eq!(h.as_deref(), Some("mail.example.com"));
    }

    /// `InfraTarget::Endpoint` extracts the host portion; the port is
    /// ignored at this level (each probe target carries its own port).
    #[test]
    fn probe_host_from_target_endpoint_ignores_port() {
        let h = probe_host_from_target(&InfraTarget::Endpoint {
            host: "mail.example.com".into(),
            port: 25,
        });
        assert_eq!(h.as_deref(), Some("mail.example.com"));
    }

    /// `InfraTarget::Ip` renders to the IP literal — cert mismatch
    /// findings are still useful for IP-only targets.
    #[test]
    fn probe_host_from_target_ip() {
        let h = probe_host_from_target(&InfraTarget::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert_eq!(h.as_deref(), Some("1.2.3.4"));
    }

    /// CIDR targets return `None` — the orchestrator expands CIDRs
    /// into individual IPs before calling into this module.
    #[test]
    fn probe_host_from_target_cidr_is_none() {
        let cidr = "10.0.0.0/24".parse::<ipnet::IpNet>().expect("cidr");
        assert!(probe_host_from_target(&InfraTarget::Cidr(cidr)).is_none());
    }

    /// Running the module against a CIDR yields no findings (no
    /// panic, no error).
    #[tokio::test]
    async fn tls_infra_run_cidr_yields_empty() {
        let cidr = "10.0.0.0/30".parse::<ipnet::IpNet>().expect("cidr");
        let ctx = ctx_for(InfraTarget::Cidr(cidr));
        let module = TlsInfraModule::default();
        let findings = module.run(&ctx).await.expect("run");
        assert!(findings.is_empty());
    }

    /// Running with a custom (empty) probe list short-circuits to
    /// zero findings even when the target is concrete — verifies
    /// the config override works end-to-end.
    #[tokio::test]
    async fn tls_infra_run_empty_probe_list_yields_empty() {
        let ctx = ctx_for(InfraTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let module = TlsInfraModule::with_config(TlsInfraConfig::default().with_targets(vec![]));
        let findings = module.run(&ctx).await.expect("run");
        assert!(findings.is_empty());
    }

    /// Closed port → we get one Info finding per configured probe
    /// (not an error). Uses a high port that's overwhelmingly
    /// unlikely to be in use.
    #[tokio::test]
    async fn tls_infra_closed_port_yields_info_finding() {
        let ctx = ctx_for(InfraTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let module = TlsInfraModule::with_config(TlsInfraConfig::default().with_targets(vec![
            TlsProbeTarget { port: 65529, mode: TlsMode::Implicit, label: "test-closed" },
        ]));
        let findings = module.run(&ctx).await.expect("run");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].title.contains("skipped"));
    }
}
