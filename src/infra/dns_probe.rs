//! [`InfraModule`] that runs native DNS probes against a target zone.
//!
//! Fills [`InfraCategory::Dns`] with four checks — the last category
//! the v2.0 arc declared but left empty:
//!
//! 1. **Wildcard detection** — a random non-existent subdomain that
//!    resolves means the zone uses wildcard A/AAAA. Biases other
//!    recon modules into false-positive noise and is usually
//!    unintentional.
//! 2. **Missing DNSSEC** — no `DNSKEY` at the apex means the zone
//!    isn't signed. Clients can't distinguish spoofed answers from
//!    authentic ones.
//! 3. **Missing CAA** — no `CAA` record at the apex means any
//!    publicly-trusted CA can issue certs for the domain.
//! 4. **NS enumeration** — surface the authoritative servers as Info
//!    evidence for downstream tooling.
//!
//! AXFR zone transfer is **not** in this module — the existing
//! [`crate::tools::dnsrecon`] and [`crate::tools::dnsx`] wrappers
//! already cover that, and a native impl needs `hickory-client`
//! rather than the resolver. Tracked as a follow-up.
//!
//! The module is registered in [`crate::infra::register_modules`] and
//! runs as part of any infra scan whose target resolves to a
//! host/hostname (IP-only targets short-circuit — no zone to probe).

use async_trait::async_trait;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{Name, TokioResolver};
use tracing::warn;
use uuid::Uuid;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::infra_context::InfraContext;
use crate::engine::infra_module::{InfraCategory, InfraModule};
use crate::engine::infra_target::InfraTarget;
use crate::engine::severity::Severity;

/// Probe module for [`InfraCategory::Dns`].
#[derive(Debug, Default)]
pub struct DnsInfraModule;

#[async_trait]
impl InfraModule for DnsInfraModule {
    fn name(&self) -> &'static str {
        "DNS Infra Probe"
    }

    fn id(&self) -> &'static str {
        "dns_infra"
    }

    fn category(&self) -> InfraCategory {
        InfraCategory::Dns
    }

    fn description(&self) -> &'static str {
        "Check DNS hygiene: wildcard A/AAAA, missing DNSSEC, missing CAA, NS enumeration"
    }

    async fn run(&self, ctx: &InfraContext) -> Result<Vec<Finding>> {
        let Some(zone) = zone_from_target(&ctx.target) else {
            return Ok(Vec::new());
        };

        let Ok(resolver_builder) = TokioResolver::builder_tokio() else {
            warn!("dns_infra: failed to construct resolver from system config; skipping");
            return Ok(Vec::new());
        };
        // Keep defaults except: lower the overall attempt count so a
        // zone that doesn't exist fails fast.
        let mut opts = ResolverOpts::default();
        opts.attempts = 2;
        let resolver = resolver_builder.with_options(opts).build();

        let mut findings = Vec::new();
        probe_wildcard(&resolver, &zone, &mut findings).await;
        probe_dnssec(&resolver, &zone, &mut findings).await;
        probe_caa(&resolver, &zone, &mut findings).await;
        probe_ns(&resolver, &zone, &mut findings).await;
        Ok(findings)
    }
}

/// Extract a DNS-probeable zone string from an infra target.
///
/// - `Host(h)` / `Endpoint { host, .. }` → the host string
/// - `Ip(_)` / `Cidr(_)` / `Multi(_)` → `None` (no zone to probe)
fn zone_from_target(target: &InfraTarget) -> Option<String> {
    match target {
        InfraTarget::Host(h) => Some(h.clone()),
        InfraTarget::Endpoint { host, .. } => Some(host.clone()),
        InfraTarget::Ip(_) | InfraTarget::Cidr(_) | InfraTarget::Multi(_) => None,
    }
}

/// Generate a random subdomain label used for wildcard detection.
///
/// 16 hex chars (64 bits of entropy) drawn from a fresh UUID — the
/// probability a real subdomain collides with this is vanishing.
#[must_use]
pub fn random_wildcard_label() -> String {
    let uuid = Uuid::new_v4();
    let bytes = uuid.as_bytes();
    let mut s = String::with_capacity(16);
    for b in bytes.iter().take(8) {
        use std::fmt::Write as _;
        // JUSTIFICATION: write! into a String cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

async fn probe_wildcard(resolver: &TokioResolver, zone: &str, findings: &mut Vec<Finding>) {
    let label = random_wildcard_label();
    let probe = format!("{label}.{zone}");
    let Ok(name) = Name::from_ascii(&probe) else {
        return;
    };
    // NXDOMAIN is the expected healthy case — only act on a successful lookup.
    if let Ok(lookup) = resolver.lookup_ip(name).await {
        let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
        if !ips.is_empty() {
            findings.push(
                Finding::new(
                    "dns_infra",
                    Severity::Medium,
                    "Wildcard DNS Records Configured",
                    format!(
                        "A random nonexistent subdomain `{probe}` resolved to {}. \
                         This means the zone uses wildcard A/AAAA records, which \
                         hides typos and misrouted traffic behind an authoritative \
                         response and can bias recon into false positives.",
                        ips.join(", ")
                    ),
                    zone.to_string(),
                )
                .with_evidence(format!("Probe: {probe} -> {}", ips.join(", ")))
                .with_remediation(
                    "Remove wildcard records unless explicitly required; prefer explicit \
                     per-subdomain records.",
                )
                .with_confidence(0.9),
            );
        }
    }
}

async fn probe_dnssec(resolver: &TokioResolver, zone: &str, findings: &mut Vec<Finding>) {
    let Ok(name) = Name::from_ascii(zone) else {
        return;
    };
    match resolver.lookup(name, RecordType::DNSKEY).await {
        Ok(lookup) if lookup.iter().next().is_some() => {
            // Signed — no finding. Future pipeline could validate the
            // chain from the parent DS record down.
        }
        _ => {
            findings.push(
                Finding::new(
                    "dns_infra",
                    Severity::Medium,
                    "DNSSEC Not Configured",
                    format!(
                        "No DNSKEY records returned for `{zone}`. The zone is not signed, \
                         so clients cannot verify the authenticity of answers — an attacker \
                         who can inject DNS responses can spoof records for this domain."
                    ),
                    zone.to_string(),
                )
                .with_evidence("No DNSKEY records at the zone apex")
                .with_remediation(
                    "Enable DNSSEC at the registrar and your DNS provider; publish DS \
                     records at the parent and DNSKEY + RRSIG records in the zone.",
                )
                .with_owasp("A02:2021 Cryptographic Failures")
                .with_confidence(0.7),
            );
        }
    }
}

async fn probe_caa(resolver: &TokioResolver, zone: &str, findings: &mut Vec<Finding>) {
    let Ok(name) = Name::from_ascii(zone) else {
        return;
    };
    let has_caa = resolver
        .lookup(name, RecordType::CAA)
        .await
        .is_ok_and(|lookup| lookup.iter().next().is_some());
    if !has_caa {
        findings.push(
            Finding::new(
                "dns_infra",
                Severity::Low,
                "CAA Record Missing",
                format!(
                    "No CAA records returned for `{zone}`. Without CAA, any publicly-trusted \
                     CA will accept certificate issuance requests for this domain — raising \
                     the blast radius of a compromised CA or a social-engineered issuance."
                ),
                zone.to_string(),
            )
            .with_evidence("No CAA records at the zone apex")
            .with_remediation(
                "Publish CAA records naming the CAs authorised to issue certificates for \
                 this domain (e.g. `example.com. CAA 0 issue \"letsencrypt.org\"`).",
            )
            .with_confidence(0.7),
        );
    }
}

async fn probe_ns(resolver: &TokioResolver, zone: &str, findings: &mut Vec<Finding>) {
    let Ok(name) = Name::from_ascii(zone) else {
        return;
    };
    let Ok(lookup) = resolver.lookup(name, RecordType::NS).await else {
        return;
    };
    let servers: Vec<String> = lookup
        .iter()
        .filter_map(|rdata| rdata.as_ns().map(std::string::ToString::to_string))
        .collect();
    if servers.is_empty() {
        return;
    }
    findings.push(
        Finding::new(
            "dns_infra",
            Severity::Info,
            "Authoritative Nameservers",
            format!("Zone `{zone}` is served by {} nameserver(s).", servers.len()),
            zone.to_string(),
        )
        .with_evidence(format!("NS: {}", servers.join(", ")))
        .with_confidence(0.95),
    );
}

#[cfg(test)]
mod tests {
    //! Pure-function coverage for target-extraction and the random
    //! wildcard label. Probe tests hit real DNS and live in the
    //! `#[ignore]`-gated live smoke (see `docs/modules/dns-infra.md`).

    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// `InfraTarget::Host` is what we probe — hand it straight back.
    #[test]
    fn zone_from_target_host() {
        let z = zone_from_target(&InfraTarget::Host("example.com".into()));
        assert_eq!(z.as_deref(), Some("example.com"));
    }

    /// `Endpoint { host, port }` yields the host portion; DNS probes
    /// operate at the zone apex regardless of port.
    #[test]
    fn zone_from_target_endpoint_ignores_port() {
        let z = zone_from_target(&InfraTarget::Endpoint { host: "example.com".into(), port: 25 });
        assert_eq!(z.as_deref(), Some("example.com"));
    }

    /// IP-only target yields `None` — there's no reverse-DNS-implied
    /// zone to probe reliably at this layer.
    #[test]
    fn zone_from_target_ip_is_none() {
        let z = zone_from_target(&InfraTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(z.is_none());
    }

    /// CIDR target yields `None` — each IP in the range doesn't carry
    /// a zone with it.
    #[test]
    fn zone_from_target_cidr_is_none() {
        let cidr = "10.0.0.0/24".parse::<ipnet::IpNet>().expect("cidr");
        assert!(zone_from_target(&InfraTarget::Cidr(cidr)).is_none());
    }

    /// The wildcard probe label is exactly 16 hex chars. Guards
    /// against drift in the generator (e.g. bumping entropy in a way
    /// that accidentally changes the alphabet).
    #[test]
    fn random_wildcard_label_shape() {
        let label = random_wildcard_label();
        assert_eq!(label.len(), 16);
        assert!(
            label.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "label {label:?} contained non-lowercase-hex"
        );
    }

    /// Two successive label generations produce different values.
    /// Probability of a collision across two v4 UUIDs is ~2^-64; this
    /// test is effectively deterministic.
    #[test]
    fn random_wildcard_label_uniqueness() {
        let a = random_wildcard_label();
        let b = random_wildcard_label();
        assert_ne!(a, b);
    }

    /// Module metadata pins the id + category orchestrator filters
    /// and `--modules` CLI flags key off.
    #[test]
    fn dns_infra_module_metadata() {
        let module = DnsInfraModule;
        assert_eq!(module.id(), "dns_infra");
        assert_eq!(module.category(), InfraCategory::Dns);
        assert!(!module.requires_external_tool());
    }
}
