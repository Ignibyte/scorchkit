//! [`InfraModule`] that probes non-HTTP TLS services and analyses
//! their certificates.
//!
//! Complements the DAST `scanner::ssl::SslModule` (which handles
//! HTTPS on a single URL) by scanning a host's broader TLS surface:
//!
//! - **Implicit TLS:** SMTPS (465), LDAPS (636), IMAPS (993),
//!   POP3S (995). Port is TLS-wrapped from byte zero.
//! - **STARTTLS:** SMTP (25, 587), IMAP (143), POP3 (110). Plain TCP
//!   connect → protocol-specific upgrade command → TLS.
//! - **RDP-TLS:** RDP (3389). Plain TCP connect → X.224 Connection
//!   Request / Connection Confirm negotiation (MS-RDPBCGR) requesting
//!   `PROTOCOL_SSL` → TLS. NLA-only hosts respond with
//!   `RDP_NEG_FAILURE` and surface as Info findings (port speaks RDP
//!   but not plain `PROTOCOL_SSL`), not defects.
//!
//! Per-port, the module runs [`crate::engine::tls_probe::probe_tls`]
//! then pipes the resulting [`crate::engine::tls_probe::CertInfo`]
//! through [`crate::engine::tls_probe::check_certificate`] tagged with
//! the `"tls_infra"` module id. Findings are identical in shape to the
//! DAST SSL path — same severities, same OWASP/CWE mappings.
//!
//! ## Hardening enumeration (WORK-143)
//!
//! When [`TlsInfraConfig::enum_protocols`] is enabled (default), each
//! probe also runs [`crate::engine::tls_enum::enumerate_tls_versions`]
//! and raises findings for accepted deprecated versions:
//! SSLv3/TLSv1.0 → Critical, TLSv1.1 → High. Findings are
//! aggregated per severity tier to keep the report readable.
//!
//! When [`TlsInfraConfig::cipher_enum_limit`] is set, each probe also
//! runs [`crate::engine::tls_enum::enumerate_weak_ciphers`] (opt-in;
//! each probe is a full TCP handshake). Accepted weak suites produce
//! aggregated Critical / High / Medium findings.
//!
//! ## What's out of scope (for now)
//!
//! - (none — protocol-version + cipher-suite enumeration shipped in
//!   WORK-143, RDP-TLS shipped in WORK-148.)

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::infra_context::InfraContext;
use crate::engine::infra_module::{InfraCategory, InfraModule};
use crate::engine::infra_target::InfraTarget;
use crate::engine::severity::Severity;
use crate::engine::tls_enum::{
    enumerate_tls_versions, enumerate_weak_ciphers, CipherSuiteId, CipherWeakness, ProbeOutcome,
    TlsVersionId,
};
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
/// `scanner::ssl::SslModule` owns that path.
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
    TlsProbeTarget { port: 3389, mode: TlsMode::RdpTls, label: "RDP-TLS" },
];

/// Configuration for [`TlsInfraModule`].
#[derive(Debug, Clone)]
pub struct TlsInfraConfig {
    /// Probe targets (port + mode + label).
    pub targets: Vec<TlsProbeTarget>,
    /// Whether to enumerate accepted TLS protocol versions per port.
    ///
    /// Default `true`. Runs five forced-version probes per port (`SSLv3`
    /// through TLSv1.3) and emits aggregated findings for accepted
    /// deprecated versions (see [`crate::engine::tls_enum`]).
    pub enum_protocols: bool,
    /// Maximum number of weak cipher suites to probe per port.
    ///
    /// Default `None` (disabled). Each cipher probe is a full TCP
    /// handshake — expect ~1s per cipher. Set to `Some(N)` to probe
    /// the first N entries from
    /// [`crate::engine::tls_enum::weak_cipher_catalog`].
    pub cipher_enum_limit: Option<usize>,
}

impl Default for TlsInfraConfig {
    fn default() -> Self {
        Self {
            targets: DEFAULT_PROBE_TARGETS.to_vec(),
            enum_protocols: true,
            cipher_enum_limit: None,
        }
    }
}

impl TlsInfraConfig {
    /// Override the probe list.
    #[must_use]
    pub fn with_targets(mut self, targets: Vec<TlsProbeTarget>) -> Self {
        self.targets = targets;
        self
    }

    /// Toggle protocol-version enumeration.
    #[must_use]
    pub const fn with_protocol_enum(mut self, enabled: bool) -> Self {
        self.enum_protocols = enabled;
        self
    }

    /// Set the cipher-enumeration budget (`None` disables cipher probes).
    #[must_use]
    pub const fn with_cipher_enum_limit(mut self, limit: Option<usize>) -> Self {
        self.cipher_enum_limit = limit;
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
            if self.config.enum_protocols {
                findings.extend(enum_protocols_for(&host, *target).await);
            }
            if let Some(limit) = self.config.cipher_enum_limit {
                findings.extend(enum_ciphers_for(&host, *target, limit).await);
            }
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

/// Enumerate TLS protocol versions on one probe target and aggregate
/// into per-severity findings.
///
/// Emits at most one Critical finding (`SSLv3` / `TLSv1.0` accepted) and
/// at most one High finding (TLSv1.1 accepted) per port. Accepted
/// modern versions (TLSv1.2, TLSv1.3) are not surfaced as findings;
/// that's the expected happy path.
async fn enum_protocols_for(host: &str, target: TlsProbeTarget) -> Vec<Finding> {
    let affected = format!("{host}:{}", target.port);
    let results = enumerate_tls_versions(host, target.port, target.mode).await;

    // Bucket by severity tier.
    let mut critical: Vec<TlsVersionId> = Vec::new();
    let mut high: Vec<TlsVersionId> = Vec::new();
    let mut accepted_modern: Vec<TlsVersionId> = Vec::new();

    for (version, outcome) in results {
        if outcome != ProbeOutcome::Accepted {
            continue;
        }
        match version.severity_when_accepted() {
            Some(Severity::Critical) => critical.push(version),
            Some(Severity::High) => high.push(version),
            None => accepted_modern.push(version),
            _ => {}
        }
    }

    let mut findings = Vec::new();

    if !critical.is_empty() {
        findings.push(
            Finding::new(
                "tls_infra",
                Severity::Critical,
                format!("{} — Deprecated TLS protocol accepted (SSLv3/TLSv1.0)", target.label),
                format!(
                    "Server accepted deprecated TLS protocol version(s): {}. These are \
                     prohibited by RFC 8996 and vulnerable to known attacks (POODLE, BEAST).",
                    version_list(&critical)
                ),
                affected.clone(),
            )
            .with_evidence(version_list(&critical))
            .with_remediation(
                "Disable SSLv3, TLSv1.0, and TLSv1.1 on the server. Require TLSv1.2 or later.",
            )
            .with_owasp("A02:2021")
            .with_cwe(326)
            .with_confidence(0.95),
        );
    }

    if !high.is_empty() {
        findings.push(
            Finding::new(
                "tls_infra",
                Severity::High,
                format!("{} — Deprecated TLS protocol accepted (TLSv1.1)", target.label),
                format!(
                    "Server accepted deprecated TLS protocol version(s): {}. TLSv1.1 is \
                     deprecated by RFC 8996.",
                    version_list(&high)
                ),
                affected.clone(),
            )
            .with_evidence(version_list(&high))
            .with_remediation("Disable TLSv1.1 on the server. Require TLSv1.2 or later.")
            .with_owasp("A02:2021")
            .with_cwe(326)
            .with_confidence(0.95),
        );
    }

    if !accepted_modern.is_empty() {
        findings.push(
            Finding::new(
                "tls_infra",
                Severity::Info,
                format!("{} — TLS modern versions accepted", target.label),
                "Informational summary of modern TLS versions negotiated by the server."
                    .to_string(),
                affected,
            )
            .with_evidence(version_list(&accepted_modern))
            .with_confidence(0.9),
        );
    }

    findings
}

/// Enumerate weak cipher suites and aggregate into per-severity findings.
async fn enum_ciphers_for(host: &str, target: TlsProbeTarget, limit: usize) -> Vec<Finding> {
    let affected = format!("{host}:{}", target.port);
    let accepted = enumerate_weak_ciphers(host, target.port, target.mode, Some(limit)).await;

    let mut critical: Vec<CipherSuiteId> = Vec::new();
    let mut weak: Vec<CipherSuiteId> = Vec::new();
    let mut legacy: Vec<CipherSuiteId> = Vec::new();

    for cipher in accepted {
        match cipher.weakness() {
            CipherWeakness::Critical => critical.push(cipher),
            CipherWeakness::Weak => weak.push(cipher),
            CipherWeakness::Legacy => legacy.push(cipher),
            CipherWeakness::Ok => {}
        }
    }

    let mut findings = Vec::new();

    if !critical.is_empty() {
        findings.push(
            Finding::new(
                "tls_infra",
                Severity::Critical,
                format!("{} — Critical TLS cipher suites accepted", target.label),
                format!(
                    "Server accepted {} critical-weakness cipher suite(s). NULL / anonymous / \
                     EXPORT / DES-CBC suites have no confidentiality, integrity, or authentication \
                     guarantees.",
                    critical.len()
                ),
                affected.clone(),
            )
            .with_evidence(cipher_list(&critical))
            .with_remediation(
                "Remove NULL, anonymous DH, EXPORT, and DES ciphers from the server's cipher list.",
            )
            .with_owasp("A02:2021")
            .with_cwe(327)
            .with_confidence(0.95),
        );
    }

    if !weak.is_empty() {
        findings.push(
            Finding::new(
                "tls_infra",
                Severity::High,
                format!("{} — Weak TLS cipher suites accepted", target.label),
                format!(
                    "Server accepted {} weak cipher suite(s). RC4, 3DES, and MD5 MAC suites \
                     have known cryptographic weaknesses.",
                    weak.len()
                ),
                affected.clone(),
            )
            .with_evidence(cipher_list(&weak))
            .with_remediation("Remove RC4, 3DES, and MD5-MAC ciphers. Use only AEAD suites (AES-GCM, ChaCha20-Poly1305).")
            .with_owasp("A02:2021")
            .with_cwe(327)
            .with_confidence(0.95),
        );
    }

    if !legacy.is_empty() {
        findings.push(
            Finding::new(
                "tls_infra",
                Severity::Medium,
                format!("{} — Legacy CBC-mode cipher suites accepted", target.label),
                format!(
                    "Server accepted {} legacy CBC-mode cipher suite(s). Not broken but no \
                     longer recommended; prefer AEAD (AES-GCM, ChaCha20-Poly1305).",
                    legacy.len()
                ),
                affected,
            )
            .with_evidence(cipher_list(&legacy))
            .with_remediation("Prefer AEAD cipher suites over CBC-mode suites.")
            .with_cwe(327)
            .with_confidence(0.8),
        );
    }

    findings
}

/// Format a list of [`TlsVersionId`] values for evidence / description.
fn version_list(versions: &[TlsVersionId]) -> String {
    versions.iter().map(|v| v.label()).collect::<Vec<_>>().join(", ")
}

/// Format a list of [`CipherSuiteId`] values for evidence / description.
fn cipher_list(ciphers: &[CipherSuiteId]) -> String {
    ciphers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
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
        for expected in [465, 636, 993, 995, 25, 587, 143, 110, 3389] {
            assert!(ports.contains(&expected), "missing default probe port {expected}");
        }
        assert!(!ports.contains(&443), "443 belongs to DAST ssl, not infra tls_infra");
        // RDP-TLS is now a supported default probe (WORK-148).
        let rdp = cfg.targets.iter().find(|t| t.port == 3389).expect("3389 present");
        assert_eq!(rdp.label, "RDP-TLS", "port 3389 must be labelled RDP-TLS");
        assert!(matches!(rdp.mode, TlsMode::RdpTls), "port 3389 must use TlsMode::RdpTls");
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
        // Force enum_protocols off so the test stays focused on cert-probe
        // behavior — the enum path also returns no findings for closed
        // ports (all Unknown), covered by its dedicated test below.
        let ctx = ctx_for(InfraTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let module = TlsInfraModule::with_config(
            TlsInfraConfig::default()
                .with_targets(vec![TlsProbeTarget {
                    port: 65529,
                    mode: TlsMode::Implicit,
                    label: "test-closed",
                }])
                .with_protocol_enum(false),
        );
        let findings = module.run(&ctx).await.expect("run");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].title.contains("skipped"));
    }

    /// Default config has protocol enum on and cipher enum off.
    #[test]
    fn tls_infra_default_config_enum_fields() {
        let cfg = TlsInfraConfig::default();
        assert!(cfg.enum_protocols, "protocol enum should be on by default");
        assert_eq!(cfg.cipher_enum_limit, None, "cipher enum should be opt-in");
    }

    /// Enum toggles on the config mutate only what they claim to.
    #[test]
    fn tls_infra_enum_toggles_are_focused() {
        let cfg = TlsInfraConfig::default().with_protocol_enum(false);
        assert!(!cfg.enum_protocols);
        assert_eq!(cfg.cipher_enum_limit, None);

        let cfg = TlsInfraConfig::default().with_cipher_enum_limit(Some(4));
        assert!(cfg.enum_protocols);
        assert_eq!(cfg.cipher_enum_limit, Some(4));
    }

    /// Closed port with enum_protocols=true still emits only the
    /// single Info skipped finding — enum fanned out to 5 probes that
    /// each returned Unknown, which must not fabricate findings.
    #[tokio::test]
    async fn tls_infra_closed_port_with_enum_emits_no_version_findings() {
        let ctx = ctx_for(InfraTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let module = TlsInfraModule::with_config(
            TlsInfraConfig::default()
                .with_targets(vec![TlsProbeTarget {
                    port: 65531,
                    mode: TlsMode::Implicit,
                    label: "test-closed-enum",
                }])
                .with_protocol_enum(true),
        );
        let findings = module.run(&ctx).await.expect("run");
        // Only the cert-probe Info "skipped" finding survives.
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].title.contains("skipped"));
    }

    #[test]
    fn version_list_is_human_readable() {
        let list = version_list(&[TlsVersionId::Tls10, TlsVersionId::Tls11]);
        assert_eq!(list, "TLSv1.0, TLSv1.1");
    }

    #[test]
    fn cipher_list_includes_hex_id() {
        let list = cipher_list(&[CipherSuiteId(0x0004)]);
        assert!(list.contains("TLS_RSA_WITH_RC4_128_MD5"));
        assert!(list.contains("0x0004"));
    }
}
