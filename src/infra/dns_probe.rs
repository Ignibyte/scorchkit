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
//! The module is registered in [`crate::infra::register_modules`] and
//! runs as part of any infra scan whose target resolves to a
//! host/hostname (IP-only targets short-circuit — no zone to probe).
//!
//! ## Hardening extensions (WORK-145)
//!
//! - **Full DNSSEC chain validation.** `probe_dnssec` now does two
//!   passes: the existing presence check (Medium finding if the apex
//!   has no DNSKEY), then a validating-resolver pass that triggers
//!   hickory's parent-DS → DNSKEY → RRSIG chain walk. Failures map to
//!   severity-tiered findings via [`classify_dnssec_error`] — Critical
//!   for bogus signatures, High for expired RRSIGs, Medium for missing
//!   parent DS, Info for a validated chain.
//! - **Native AXFR zone-transfer probe.** `probe_axfr` fans across each
//!   NS returned for the zone and issues a raw-TCP AXFR query built via
//!   `hickory-proto`. A response whose header shows `NoError` + `AA` flag +
//!   `ANCOUNT>0` with an SOA among the answers means AXFR is open (one
//!   Critical finding per accepting NS). Rejections (every healthy
//!   server) are silent at `debug!`-level — they are the expected
//!   happy path.

use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_resolver::proto::rr::{DNSClass, Name as ProtoName, RecordType};
use hickory_resolver::proto::ProtoError;
use hickory_resolver::ResolveError;
use hickory_resolver::{Name, TokioResolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::infra_context::InfraContext;
use crate::engine::infra_module::{InfraCategory, InfraModule};
use crate::engine::infra_target::InfraTarget;
use crate::engine::severity::Severity;

/// Per-NS timeout budget for the AXFR probe. 2 seconds per server keeps
/// the total budget bounded even on zones with many NS records. TCP
/// connect + query + read of the first record should complete well
/// inside this window against any real server.
const AXFR_NS_TIMEOUT: Duration = Duration::from_secs(2);

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
        "Check DNS hygiene: wildcard A/AAAA, DNSSEC chain validation, CAA, NS enumeration, AXFR"
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
        probe_axfr(&resolver, &zone, &mut findings).await;
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

    // Pass 1 — presence check against the non-validating resolver.
    let has_dnskey = resolver
        .lookup(name.clone(), RecordType::DNSKEY)
        .await
        .is_ok_and(|lookup| lookup.iter().next().is_some());
    if !has_dnskey {
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
        return;
    }

    // Pass 2 — validating resolver. Build a second resolver with
    // `validate = true`, ask for the apex SOA, inspect the outcome.
    // The validating resolver triggers hickory's parent-DS → child
    // DNSKEY → RRSIG chain walk under the hood; we classify its error
    // surface into DnssecOutcome.
    let Ok(validate_builder) = TokioResolver::builder_tokio() else {
        // No validating resolver available — silently skip the chain pass.
        return;
    };
    let mut validate_opts = ResolverOpts::default();
    validate_opts.attempts = 2;
    validate_opts.validate = true;
    let validate_resolver = validate_builder.with_options(validate_opts).build();

    match validate_resolver.lookup(name, RecordType::SOA).await {
        Ok(_) => findings.push(
            Finding::new(
                "dns_infra",
                Severity::Info,
                "DNSSEC Chain Validated",
                format!(
                    "The DNSSEC chain for `{zone}` was validated end-to-end: parent DS → \
                     child DNSKEY → RRSIG over the zone's SOA record. Clients that enforce \
                     DNSSEC validation can trust answers for this zone."
                ),
                zone.to_string(),
            )
            .with_evidence("Validating resolver accepted SOA at the apex")
            .with_confidence(0.9),
        ),
        Err(e) => {
            let outcome = classify_dnssec_error(&e);
            findings.push(dnssec_outcome_to_finding(zone, outcome, &e));
        }
    }
}

/// Outcome of a validating-resolver DNSSEC lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnssecOutcome {
    /// Validator reported signature verification failure (bogus chain).
    Bogus,
    /// At least one RRSIG was outside its validity window.
    Expired,
    /// Parent zone lacks a DS record for this child (broken trust anchor).
    MissingDs,
    /// Validator error but the reason couldn't be classified — report
    /// conservatively at Medium.
    Indeterminate,
}

/// Classify a `ResolveError` from a validating resolver into a
/// [`DnssecOutcome`]. Pure function — string-matches the error's
/// display text against the patterns hickory emits for the documented
/// DNSSEC failure modes.
///
/// Hickory's error surface for DNSSEC isn't a stable tagged enum, so
/// we match on the display string. Unmatched errors fall back to
/// [`DnssecOutcome::Indeterminate`] so we still report the probe, just
/// at lower fidelity. See WORK-145 design §Issues Found.
#[must_use]
pub(crate) fn classify_dnssec_error(err: &ResolveError) -> DnssecOutcome {
    let msg = err.to_string().to_ascii_lowercase();
    // Check expired first — hickory's expiry messages often mention
    // RRSIG by name (e.g. "RRSIG not valid yet"), which would otherwise
    // short-circuit into the Bogus branch.
    if msg.contains("expired") || msg.contains("not valid yet") || msg.contains("validity period") {
        DnssecOutcome::Expired
    } else if msg.contains("bogus")
        || msg.contains("signer name")
        || msg.contains("bad signature")
        || msg.contains("rrsig")
    {
        DnssecOutcome::Bogus
    } else if msg.contains("ds record") || msg.contains("no ds") || msg.contains("insecure") {
        DnssecOutcome::MissingDs
    } else {
        DnssecOutcome::Indeterminate
    }
}

/// Convert a [`DnssecOutcome`] into a finding. The base-case "validator
/// error we can't pin down" still produces a Medium finding so
/// operators see the probe ran, just without a precise cause.
fn dnssec_outcome_to_finding(zone: &str, outcome: DnssecOutcome, err: &ResolveError) -> Finding {
    let (severity, title, description) = match outcome {
        DnssecOutcome::Bogus => (
            Severity::Critical,
            "DNSSEC Chain Validation Failed",
            format!(
                "Validating resolver rejected records for `{zone}` — the chain from the \
                 parent DS through the zone's DNSKEY to an RRSIG is broken. A validating \
                 client will refuse answers from this zone until the signatures are fixed."
            ),
        ),
        DnssecOutcome::Expired => (
            Severity::High,
            "DNSSEC Signature Expired",
            format!(
                "At least one RRSIG protecting `{zone}` is outside its validity window. \
                 Expired signatures cause validating resolvers to treat the zone as bogus \
                 — rotate the zone's signing key(s) and re-sign immediately."
            ),
        ),
        DnssecOutcome::MissingDs => (
            Severity::Medium,
            "DNSSEC DS Record Missing at Parent",
            format!(
                "The zone `{zone}` publishes DNSKEY records but the parent zone has no \
                 corresponding DS record, breaking the chain of trust. Validating \
                 resolvers will treat the zone as insecure. Publish a DS record at the \
                 registrar matching one of the zone's KSK hashes."
            ),
        ),
        DnssecOutcome::Indeterminate => (
            Severity::Medium,
            "DNSSEC Validation Error",
            format!(
                "Validating resolver rejected records for `{zone}` but the specific \
                 failure mode couldn't be classified from the error text. Investigate \
                 the zone's DNSSEC configuration manually."
            ),
        ),
    };

    Finding::new("dns_infra", severity, title, description, zone.to_string())
        .with_evidence(format!("Validator error: {err}"))
        .with_remediation(
            "Inspect the zone's DNSSEC signing state (key expiry, DS publication \
             at the registrar, RRSIG coverage). `dig +dnssec <zone> SOA` + \
             `dig +trace <zone>` are the first debugging steps.",
        )
        .with_owasp("A02:2021 Cryptographic Failures")
        .with_confidence(0.8)
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

// =============================================================
// AXFR zone-transfer probe
// =============================================================

/// Outcome of a single AXFR attempt against one NS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AxfrOutcome {
    /// Response indicates the NS is willing to transfer the zone —
    /// `NoError` RCODE, `AA` flag set, at least one answer, and an SOA
    /// among the answers.
    Accepted { record_count: usize },
    /// Response cleanly declined — any of: RCODE ≠ `NoError`, `ANCOUNT=0`,
    /// no SOA in the answers. Healthy default; surfaced only at
    /// `debug!` level.
    Rejected,
    /// Network error, truncated response, or otherwise indeterminate.
    /// Not surfaced as a finding.
    Unknown,
}

/// Enumerate the zone's NS `RRset` and run [`axfr_attempt`] against each,
/// emitting one Critical finding per accepting NS. Rejections and
/// errors are silent (`debug!`-level trace only).
async fn probe_axfr(resolver: &TokioResolver, zone: &str, findings: &mut Vec<Finding>) {
    let Ok(zone_name) = Name::from_ascii(zone) else {
        return;
    };
    let Ok(lookup) = resolver.lookup(zone_name.clone(), RecordType::NS).await else {
        return;
    };
    let servers: Vec<String> = lookup
        .iter()
        .filter_map(|rdata| rdata.as_ns().map(std::string::ToString::to_string))
        .collect();

    for ns in servers {
        match axfr_attempt(&zone_name, &ns).await {
            AxfrOutcome::Accepted { record_count } => {
                findings.push(
                    Finding::new(
                        "dns_infra",
                        Severity::Critical,
                        "AXFR Zone Transfer Allowed",
                        format!(
                            "Authoritative server `{ns}` granted an AXFR zone transfer for \
                             `{zone}` — the entire zone's contents (every A, AAAA, MX, TXT, \
                             SPF, CNAME, and subdomain) are accessible to any client. This \
                             leaks the full attack surface of the domain."
                        ),
                        format!("{zone} @ {ns}"),
                    )
                    .with_evidence(format!(
                        "AXFR accepted by {ns}; first response contained {record_count} answer record(s) including an SOA."
                    ))
                    .with_remediation(
                        "Restrict AXFR on the authoritative server to the zone's \
                         secondaries by IP (BIND `allow-transfer`, NSD `provide-xfr`, \
                         Knot `acl`, etc.). Best practice is to require TSIG on any \
                         permitted transfer.",
                    )
                    .with_owasp("A01:2021 Broken Access Control")
                    .with_cwe(200)
                    .with_confidence(0.95),
                );
            }
            AxfrOutcome::Rejected => {
                debug!("dns_infra: AXFR for {zone} rejected by {ns} (expected)");
            }
            AxfrOutcome::Unknown => {
                debug!("dns_infra: AXFR probe for {zone} against {ns} was indeterminate");
            }
        }
    }
}

/// Open a TCP connection to the NS, send an AXFR query, read the first
/// response, classify the outcome.
async fn axfr_attempt(zone: &ProtoName, ns: &str) -> AxfrOutcome {
    // NS strings are FQDN-with-trailing-dot (`ns1.example.com.`). We
    // connect to port 53/TCP. Trailing dots and socket-addr parsing
    // don't mix; strip the dot before resolving.
    let host = ns.trim_end_matches('.');
    let addr = format!("{host}:53");

    let Ok(query) = build_axfr_query(zone) else {
        return AxfrOutcome::Unknown;
    };

    let Ok(Ok(tcp)) = timeout(AXFR_NS_TIMEOUT, TcpStream::connect(&addr)).await else {
        return AxfrOutcome::Unknown;
    };
    let mut tcp = tcp;

    // TCP DNS framing: u16 big-endian length + message bytes.
    let Ok(len) = u16::try_from(query.len()) else {
        return AxfrOutcome::Unknown;
    };
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&query);

    if timeout(AXFR_NS_TIMEOUT, tcp.write_all(&framed)).await.is_err() {
        return AxfrOutcome::Unknown;
    }
    if timeout(AXFR_NS_TIMEOUT, tcp.flush()).await.is_err() {
        return AxfrOutcome::Unknown;
    }

    // Read response length prefix.
    let mut len_buf = [0u8; 2];
    if timeout(AXFR_NS_TIMEOUT, tcp.read_exact(&mut len_buf)).await.is_err() {
        return AxfrOutcome::Unknown;
    }
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > 65535 {
        return AxfrOutcome::Unknown;
    }

    let mut resp = vec![0u8; resp_len];
    if timeout(AXFR_NS_TIMEOUT, tcp.read_exact(&mut resp)).await.is_err() {
        return AxfrOutcome::Unknown;
    }

    classify_axfr_response(&resp)
}

/// Build a DNS AXFR query message for `zone` and serialize to wire
/// bytes. Pure function — no network, no allocation outside the
/// returned Vec.
///
/// # Errors
///
/// Returns a `ProtoError` if the hickory encoder fails (should not
/// happen for a well-formed `Name`, but propagating the error lets the
/// caller classify as `Unknown` rather than panicking).
pub(crate) fn build_axfr_query(zone: &ProtoName) -> std::result::Result<Vec<u8>, ProtoError> {
    let mut query = Query::new();
    query.set_name(zone.clone());
    query.set_query_type(RecordType::AXFR);
    query.set_query_class(DNSClass::IN);

    let mut msg = Message::new();
    // 16-bit transaction ID — DNS's `id` field. Truncating the UUID is
    // fine: we don't care which value, we only need it to vary between
    // concurrent probes so matched responses don't cross-talk.
    #[allow(clippy::cast_possible_truncation)]
    // JUSTIFICATION: intentional truncation — DNS ID is 16 bits and we
    // only need per-query uniqueness, not full UUID fidelity.
    let txid = Uuid::new_v4().as_u128() as u16;
    msg.set_id(txid);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);
    msg.set_authentic_data(false);
    msg.set_checking_disabled(false);
    msg.add_query(query);
    msg.to_vec()
}

/// Classify the first TCP DNS response received from an AXFR probe.
///
/// The probe only reads the first response packet — full zone
/// enumeration is out of scope. A response whose DNS header shows
/// `NoError` RCODE, `AA` (authoritative) flag set, `ANCOUNT > 0`, and
/// an SOA record among the answers is a definitive "AXFR accepted"
/// signal. Anything else is a rejection (silent) or indeterminate
/// (also silent — just different log-level).
#[must_use]
pub(crate) fn classify_axfr_response(bytes: &[u8]) -> AxfrOutcome {
    // DNS header is exactly 12 bytes; anything shorter is malformed.
    if bytes.len() < 12 {
        return AxfrOutcome::Unknown;
    }
    let Ok(msg) = Message::from_vec(bytes) else {
        return AxfrOutcome::Unknown;
    };
    if msg.response_code() != ResponseCode::NoError {
        return AxfrOutcome::Rejected;
    }
    if !msg.authoritative() {
        return AxfrOutcome::Rejected;
    }
    let answers = msg.answers();
    if answers.is_empty() {
        return AxfrOutcome::Rejected;
    }
    let has_soa = answers.iter().any(|r| r.record_type() == RecordType::SOA);
    if !has_soa {
        return AxfrOutcome::Rejected;
    }
    AxfrOutcome::Accepted { record_count: answers.len() }
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

    // =============================================================
    // WORK-145: AXFR + DNSSEC classifier tests
    // =============================================================

    use hickory_resolver::proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
    use hickory_resolver::proto::rr::rdata::{NS as NsRdata, SOA};
    use hickory_resolver::proto::rr::{DNSClass, Name as ProtoName, RData, Record, RecordType};

    /// Build a well-formed AXFR query and check the serialised header.
    #[test]
    fn build_axfr_query_header_flags() {
        let zone = ProtoName::from_ascii("example.com.").expect("name");
        let bytes = build_axfr_query(&zone).expect("encode");
        let msg = Message::from_vec(&bytes).expect("parse");
        assert_eq!(msg.message_type(), MessageType::Query);
        assert_eq!(msg.op_code(), OpCode::Query);
        assert!(!msg.recursion_desired(), "AXFR queries are authoritative; no RD");
        assert!(!msg.authentic_data());
        assert!(!msg.checking_disabled());
        assert_eq!(msg.queries().len(), 1);
    }

    #[test]
    fn build_axfr_query_question_section() {
        let zone = ProtoName::from_ascii("example.com.").expect("name");
        let bytes = build_axfr_query(&zone).expect("encode");
        let msg = Message::from_vec(&bytes).expect("parse");
        let q = &msg.queries()[0];
        assert_eq!(q.name().to_string(), "example.com.");
        assert_eq!(q.query_type(), RecordType::AXFR);
        assert_eq!(q.query_class(), DNSClass::IN);
    }

    #[test]
    fn build_axfr_query_reasonable_size() {
        // Header (12) + question with compact name + 4 bytes of type/class.
        // "example.com." encodes to ~13 bytes. Total should sit well under 64.
        let zone = ProtoName::from_ascii("example.com.").expect("name");
        let bytes = build_axfr_query(&zone).expect("encode");
        assert!(bytes.len() >= 12, "must include DNS header");
        assert!(bytes.len() < 128, "AXFR query is tiny; anything big is a bug");
    }

    /// Helper: build a canned DNS response with specified shape.
    fn build_canned_response(
        rcode: ResponseCode,
        authoritative: bool,
        answers: Vec<Record>,
    ) -> Vec<u8> {
        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_message_type(MessageType::Response);
        header.set_op_code(OpCode::Query);
        header.set_response_code(rcode);
        header.set_authoritative(authoritative);
        msg.set_header(header);
        for a in answers {
            msg.add_answer(a);
        }
        msg.to_vec().expect("encode")
    }

    fn soa_record() -> Record {
        let zone = ProtoName::from_ascii("example.com.").expect("name");
        let mname = ProtoName::from_ascii("ns1.example.com.").expect("name");
        let rname = ProtoName::from_ascii("root.example.com.").expect("name");
        let soa = SOA::new(mname, rname, 1, 3600, 600, 604_800, 3600);
        Record::from_rdata(zone, 3600, RData::SOA(soa))
    }

    fn ns_record() -> Record {
        let zone = ProtoName::from_ascii("example.com.").expect("name");
        let ns = ProtoName::from_ascii("ns2.example.com.").expect("name");
        Record::from_rdata(zone, 3600, RData::NS(NsRdata(ns)))
    }

    #[test]
    fn classify_axfr_response_accepted() {
        let bytes = build_canned_response(ResponseCode::NoError, true, vec![soa_record()]);
        match classify_axfr_response(&bytes) {
            AxfrOutcome::Accepted { record_count } => assert_eq!(record_count, 1),
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn classify_axfr_response_refused() {
        let bytes = build_canned_response(ResponseCode::Refused, true, vec![]);
        assert_eq!(classify_axfr_response(&bytes), AxfrOutcome::Rejected);
    }

    #[test]
    fn classify_axfr_response_servfail() {
        let bytes = build_canned_response(ResponseCode::ServFail, false, vec![]);
        assert_eq!(classify_axfr_response(&bytes), AxfrOutcome::Rejected);
    }

    #[test]
    fn classify_axfr_response_empty_answers() {
        let bytes = build_canned_response(ResponseCode::NoError, true, vec![]);
        assert_eq!(classify_axfr_response(&bytes), AxfrOutcome::Rejected);
    }

    #[test]
    fn classify_axfr_response_no_soa() {
        // Authoritative NoError response with answers but no SOA →
        // not a proper AXFR accept, treat as Rejected.
        let bytes = build_canned_response(ResponseCode::NoError, true, vec![ns_record()]);
        assert_eq!(classify_axfr_response(&bytes), AxfrOutcome::Rejected);
    }

    #[test]
    fn classify_axfr_response_non_authoritative() {
        // NoError with SOA in answers but no AA flag → caching resolver
        // answered, not the authoritative server. Not AXFR.
        let bytes = build_canned_response(ResponseCode::NoError, false, vec![soa_record()]);
        assert_eq!(classify_axfr_response(&bytes), AxfrOutcome::Rejected);
    }

    #[test]
    fn classify_axfr_response_truncated_bytes() {
        assert_eq!(classify_axfr_response(&[]), AxfrOutcome::Unknown);
        assert_eq!(classify_axfr_response(&[0x12, 0x34, 0x80]), AxfrOutcome::Unknown);
    }

    // -------- DNSSEC classifier tests --------

    /// Convenience: build a `ResolveError` whose display text we
    /// control, so we can exercise the classifier without standing up
    /// a real validating resolver.
    fn err_from_msg(msg: &str) -> ResolveError {
        // `ResolveError::from(String)` exists for arbitrary messages.
        ResolveError::from(msg.to_string())
    }

    #[test]
    fn classify_dnssec_error_bogus() {
        assert_eq!(
            classify_dnssec_error(&err_from_msg("RRSIG validation failed")),
            DnssecOutcome::Bogus
        );
        assert_eq!(
            classify_dnssec_error(&err_from_msg("chain is bogus — bad signature on DNSKEY")),
            DnssecOutcome::Bogus
        );
    }

    #[test]
    fn classify_dnssec_error_expired() {
        assert_eq!(
            classify_dnssec_error(&err_from_msg("signature expired at 2023-01-01")),
            DnssecOutcome::Expired
        );
        assert_eq!(
            classify_dnssec_error(&err_from_msg("RRSIG not valid yet (inception in future)")),
            DnssecOutcome::Expired
        );
    }

    #[test]
    fn classify_dnssec_error_missing_ds() {
        assert_eq!(
            classify_dnssec_error(&err_from_msg("no DS record found at parent")),
            DnssecOutcome::MissingDs
        );
        assert_eq!(
            classify_dnssec_error(&err_from_msg("chain insecure: zone not signed")),
            DnssecOutcome::MissingDs
        );
    }

    #[test]
    fn classify_dnssec_error_indeterminate() {
        assert_eq!(
            classify_dnssec_error(&err_from_msg("unexpected network error: connection reset")),
            DnssecOutcome::Indeterminate
        );
    }

    // -------- #[ignore]-gated live smoke tests --------

    /// Live smoke — run against a real DNSSEC-signed zone via
    /// `SCORCHKIT_DNS_TEST_ZONE=cloudflare.com cargo test dnssec_chain_live -- --features infra --ignored`.
    #[tokio::test]
    #[ignore = "live-network — requires SCORCHKIT_DNS_TEST_ZONE=<zone>"]
    async fn dnssec_chain_live() {
        let Ok(zone) = std::env::var("SCORCHKIT_DNS_TEST_ZONE") else {
            return;
        };
        let Ok(builder) = TokioResolver::builder_tokio() else {
            return;
        };
        let mut opts = ResolverOpts::default();
        opts.attempts = 2;
        let resolver = builder.with_options(opts).build();
        let mut findings = Vec::new();
        probe_dnssec(&resolver, &zone, &mut findings).await;
        // Just verify it ran without panicking — specific outcomes
        // depend on the operator's choice of zone.
        assert!(findings.len() <= 2, "should emit at most one finding per pass");
    }

    /// Live smoke for AXFR — operator-driven.
    #[tokio::test]
    #[ignore = "live-network — requires SCORCHKIT_DNS_TEST_ZONE=<zone>"]
    async fn axfr_probe_live() {
        let Ok(zone) = std::env::var("SCORCHKIT_DNS_TEST_ZONE") else {
            return;
        };
        let Ok(builder) = TokioResolver::builder_tokio() else {
            return;
        };
        let resolver = builder.with_options(ResolverOpts::default()).build();
        let mut findings = Vec::new();
        probe_axfr(&resolver, &zone, &mut findings).await;
    }
}
