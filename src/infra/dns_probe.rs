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
//!   severity-tiered findings via `classify_dnssec_error` — Critical
//!   for bogus signatures, High for expired RRSIGs, Medium for missing
//!   parent DS, Info for a validated chain.
//! - **Native AXFR zone-transfer probe.** `probe_axfr` fans across each
//!   NS returned for the zone and issues a raw-TCP AXFR query built via
//!   `hickory-proto`. A response whose header shows `NoError` + `AA` flag +
//!   `ANCOUNT>0` with an SOA among the answers means AXFR is open (one
//!   Critical finding per accepting NS). Rejections (every healthy
//!   server) are silent at `debug!`-level — they are the expected
//!   happy path.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_resolver::proto::rr::{DNSClass, Name, Name as ProtoName, RData, RecordType};
use hickory_resolver::proto::ProtoError;
use hickory_resolver::TokioResolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
#[derive(Debug)]
pub struct DnsInfraModule {
    resolver_override: Option<Arc<dyn DnsResolver>>,
    axfr_probe: Arc<dyn AxfrProbe>,
}

impl Default for DnsInfraModule {
    fn default() -> Self {
        Self { resolver_override: None, axfr_probe: Arc::new(SystemAxfrProbe) }
    }
}

impl DnsInfraModule {
    #[cfg(test)]
    fn with_backends(resolver: Arc<dyn DnsResolver>, axfr_probe: Arc<dyn AxfrProbe>) -> Self {
        Self { resolver_override: Some(resolver), axfr_probe }
    }
}

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

        let resolver: Arc<dyn DnsResolver> = if let Some(resolver) = &self.resolver_override {
            Arc::clone(resolver)
        } else {
            let Some(resolver) = SystemDnsResolver::build() else {
                warn!("dns_infra: failed to build resolver from system config; skipping");
                return Ok(Vec::new());
            };
            Arc::new(resolver)
        };

        let mut findings = Vec::new();
        probe_wildcard(ctx, resolver.as_ref(), &zone, &mut findings).await?;
        probe_dnssec(ctx, resolver.as_ref(), &zone, &mut findings).await?;
        probe_caa(ctx, resolver.as_ref(), &zone, &mut findings).await?;
        probe_ns(ctx, resolver.as_ref(), &zone, &mut findings).await?;
        probe_axfr(ctx, resolver.as_ref(), self.axfr_probe.as_ref(), &zone, &mut findings).await?;
        Ok(findings)
    }
}

#[async_trait]
trait DnsResolver: std::fmt::Debug + Send + Sync {
    async fn lookup_ips(&self, name: Name) -> std::result::Result<Vec<String>, String>;
    async fn has_records(
        &self,
        name: Name,
        record_type: RecordType,
    ) -> std::result::Result<bool, String>;
    async fn nameservers(&self, name: Name) -> std::result::Result<Vec<String>, String>;
    async fn validate_soa(&self, name: Name) -> Option<std::result::Result<(), String>>;
}

#[derive(Debug)]
struct SystemDnsResolver {
    resolver: TokioResolver,
    validating_resolver: Option<TokioResolver>,
}

impl SystemDnsResolver {
    fn build() -> Option<Self> {
        let mut options = ResolverOpts::default();
        options.attempts = 2;
        let resolver = TokioResolver::builder_tokio().ok()?.with_options(options).build().ok()?;

        let mut validating_options = ResolverOpts::default();
        validating_options.attempts = 2;
        validating_options.validate = true;
        let validating_resolver = TokioResolver::builder_tokio()
            .ok()
            .and_then(|builder| builder.with_options(validating_options).build().ok());

        Some(Self { resolver, validating_resolver })
    }
}

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn lookup_ips(&self, name: Name) -> std::result::Result<Vec<String>, String> {
        self.resolver
            .lookup_ip(name)
            .await
            .map(|lookup| lookup.iter().map(|ip| ip.to_string()).collect())
            .map_err(|error| error.to_string())
    }

    async fn has_records(
        &self,
        name: Name,
        record_type: RecordType,
    ) -> std::result::Result<bool, String> {
        self.resolver
            .lookup(name, record_type)
            .await
            .map(|lookup| !lookup.answers().is_empty())
            .map_err(|error| error.to_string())
    }

    async fn nameservers(&self, name: Name) -> std::result::Result<Vec<String>, String> {
        self.resolver
            .lookup(name, RecordType::NS)
            .await
            .map(|lookup| {
                let records: Vec<RData> =
                    lookup.answers().iter().map(|record| record.data.clone()).collect();
                extract_nameservers(&records)
            })
            .map_err(|error| error.to_string())
    }

    async fn validate_soa(&self, name: Name) -> Option<std::result::Result<(), String>> {
        let resolver = self.validating_resolver.as_ref()?;
        Some(
            resolver
                .lookup(name, RecordType::SOA)
                .await
                .map(|_| ())
                .map_err(|error| error.to_string()),
        )
    }
}

#[async_trait]
trait AxfrProbe: std::fmt::Debug + Send + Sync {
    async fn attempt(&self, ctx: &InfraContext, zone: &ProtoName, nameserver: &str) -> AxfrOutcome;
}

#[derive(Debug)]
struct SystemAxfrProbe;

#[async_trait]
impl AxfrProbe for SystemAxfrProbe {
    async fn attempt(&self, ctx: &InfraContext, zone: &ProtoName, nameserver: &str) -> AxfrOutcome {
        axfr_attempt(ctx, zone, nameserver).await
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

async fn probe_wildcard(
    ctx: &InfraContext,
    resolver: &dyn DnsResolver,
    zone: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let label = random_wildcard_label();
    let probe = format!("{label}.{zone}");
    ctx.authorize_network_target(&probe)?;
    let Ok(name) = Name::from_ascii(&probe) else {
        return Ok(());
    };
    // NXDOMAIN is the expected healthy case — only act on a successful lookup.
    if let Ok(ips) = resolver.lookup_ips(name).await {
        for ip in &ips {
            ctx.authorize_network_target(ip)?;
        }
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
    Ok(())
}

async fn probe_dnssec(
    ctx: &InfraContext,
    resolver: &dyn DnsResolver,
    zone: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    ctx.authorize_network_target(zone)?;
    let Ok(name) = Name::from_ascii(zone) else {
        return Ok(());
    };

    // Pass 1 — presence check against the non-validating resolver.
    let has_dnskey = resolver.has_records(name.clone(), RecordType::DNSKEY).await.unwrap_or(false);
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
        return Ok(());
    }

    // Pass 2 — the production backend asks a validating resolver for the
    // apex SOA, triggering the parent-DS → DNSKEY → RRSIG chain walk.
    let Some(validation) = resolver.validate_soa(name).await else {
        return Ok(());
    };

    match validation {
        Ok(()) => findings.push(
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
        Err(error) => {
            let outcome = classify_dnssec_error(&error);
            findings.push(dnssec_outcome_to_finding(zone, outcome, &error));
        }
    }
    Ok(())
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

/// Classify an error from a validating resolver into a [`DnssecOutcome`].
/// Pure function — string-matches the text against the patterns hickory emits for the documented
/// DNSSEC failure modes.
///
/// Hickory's error surface for DNSSEC isn't a stable tagged enum, so
/// we match on the display string. Unmatched errors fall back to
/// [`DnssecOutcome::Indeterminate`] so we still report the probe, just
/// at lower fidelity. See WORK-145 design §Issues Found.
#[must_use]
pub(crate) fn classify_dnssec_error(error: &str) -> DnssecOutcome {
    let msg = error.to_ascii_lowercase();
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
fn dnssec_outcome_to_finding(zone: &str, outcome: DnssecOutcome, error: &str) -> Finding {
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
        .with_evidence(format!("Validator error: {error}"))
        .with_remediation(
            "Inspect the zone's DNSSEC signing state (key expiry, DS publication \
             at the registrar, RRSIG coverage). `dig +dnssec <zone> SOA` + \
             `dig +trace <zone>` are the first debugging steps.",
        )
        .with_owasp("A02:2021 Cryptographic Failures")
        .with_confidence(0.8)
}

async fn probe_caa(
    ctx: &InfraContext,
    resolver: &dyn DnsResolver,
    zone: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    ctx.authorize_network_target(zone)?;
    let Ok(name) = Name::from_ascii(zone) else {
        return Ok(());
    };
    let has_caa = resolver.has_records(name, RecordType::CAA).await.unwrap_or(false);
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
    Ok(())
}

fn extract_nameservers(records: &[RData]) -> Vec<String> {
    records
        .iter()
        .filter_map(|record| match record {
            RData::NS(name) => Some(name.to_string()),
            _ => None,
        })
        .collect()
}

async fn probe_ns(
    ctx: &InfraContext,
    resolver: &dyn DnsResolver,
    zone: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    ctx.authorize_network_target(zone)?;
    let Ok(name) = Name::from_ascii(zone) else {
        return Ok(());
    };
    let Ok(servers) = resolver.nameservers(name).await else {
        return Ok(());
    };
    if servers.is_empty() {
        return Ok(());
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
    Ok(())
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
async fn probe_axfr(
    ctx: &InfraContext,
    resolver: &dyn DnsResolver,
    axfr_probe: &dyn AxfrProbe,
    zone: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    ctx.authorize_network_target(zone)?;
    let Ok(zone_name) = Name::from_ascii(zone) else {
        return Ok(());
    };
    let Ok(servers) = resolver.nameservers(zone_name.clone()).await else {
        return Ok(());
    };

    for ns in servers {
        ctx.authorize_network_target(ns.trim_end_matches('.'))?;
        match axfr_probe.attempt(ctx, &zone_name, &ns).await {
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
    Ok(())
}

/// Open a TCP connection to the NS, send an AXFR query, read the first
/// response, classify the outcome.
async fn axfr_attempt(ctx: &InfraContext, zone: &ProtoName, ns: &str) -> AxfrOutcome {
    // NS strings are FQDN-with-trailing-dot (`ns1.example.com.`). We
    // connect to port 53/TCP. Trailing dots and socket-addr parsing
    // don't mix; strip the dot before resolving.
    let host = ns.trim_end_matches('.');
    let Ok(query) = build_axfr_query(zone) else {
        return AxfrOutcome::Unknown;
    };

    let Ok(tcp) = ctx.network_policy().connect(host, 53, AXFR_NS_TIMEOUT).await else {
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
    let Some(resp_len) = dns_frame_length(len_buf) else {
        return AxfrOutcome::Unknown;
    };

    let mut resp = vec![0u8; resp_len];
    if timeout(AXFR_NS_TIMEOUT, tcp.read_exact(&mut resp)).await.is_err() {
        return AxfrOutcome::Unknown;
    }

    classify_axfr_response(&resp)
}

const fn dns_frame_length(length_prefix: [u8; 2]) -> Option<usize> {
    let length = u16::from_be_bytes(length_prefix) as usize;
    if length == 0 {
        None
    } else {
        Some(length)
    }
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

    // 16-bit transaction ID — DNS's `id` field. Truncating the UUID is
    // fine: we don't care which value, we only need it to vary between
    // concurrent probes so matched responses don't cross-talk.
    // JUSTIFICATION: intentional truncation — DNS ID is 16 bits and we
    // only need per-query uniqueness, not full UUID fidelity.
    #[allow(clippy::cast_possible_truncation)]
    let txid = Uuid::new_v4().as_u128() as u16;
    let mut msg = Message::new(txid, MessageType::Query, OpCode::Query);
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
    if msg.response_code != ResponseCode::NoError {
        return AxfrOutcome::Rejected;
    }
    if !msg.authoritative {
        return AxfrOutcome::Rejected;
    }
    let answers = &msg.answers;
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        let module = DnsInfraModule::default();
        assert_eq!(module.name(), "DNS Infra Probe");
        assert_eq!(module.id(), "dns_infra");
        assert_eq!(module.category(), InfraCategory::Dns);
        assert_eq!(
            module.description(),
            "Check DNS hygiene: wildcard A/AAAA, DNSSEC chain validation, CAA, NS enumeration, AXFR"
        );
        assert!(!module.requires_external_tool());
    }

    #[tokio::test]
    async fn system_resolver_builds_from_local_configuration() {
        assert!(SystemDnsResolver::build().is_some());
    }

    #[tokio::test]
    async fn system_resolver_maps_loopback_dns_responses() {
        use std::net::{IpAddr, Ipv4Addr};

        use hickory_resolver::config::{
            ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig,
        };
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use hickory_resolver::proto::rr::rdata::{A, NS as NsRdata};
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind loopback DNS");
        let address = socket.local_addr().expect("loopback DNS address");
        let server = tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            loop {
                let (length, peer) =
                    socket.recv_from(&mut buffer).await.expect("receive DNS query");
                let request = Message::from_vec(&buffer[..length]).expect("decode DNS query");
                let query = request.queries.first().expect("DNS question").clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, request.op_code);
                response.metadata.authoritative = true;
                response.metadata.recursion_available = true;
                response.metadata.recursion_desired = request.metadata.recursion_desired;
                response.add_query(query.clone());

                match query.query_type() {
                    RecordType::A => {
                        response.add_answer(Record::from_rdata(
                            query.name().clone(),
                            60,
                            RData::A(A::new(192, 0, 2, 55)),
                        ));
                    }
                    RecordType::NS => {
                        response.add_answer(Record::from_rdata(
                            query.name().clone(),
                            60,
                            RData::NS(NsRdata(
                                ProtoName::from_ascii("ns1.fixture.test.").expect("fixture NS"),
                            )),
                        ));
                    }
                    RecordType::CAA => response.metadata.response_code = ResponseCode::NXDomain,
                    RecordType::SOA => response.metadata.response_code = ResponseCode::ServFail,
                    _ => response.metadata.response_code = ResponseCode::NotImp,
                }

                let bytes = response.to_vec().expect("encode DNS response");
                socket.send_to(&bytes, peer).await.expect("send DNS response");
            }
        });

        let mut connection = ConnectionConfig::udp();
        connection.port = address.port();
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            vec![NameServerConfig::new(address.ip(), true, vec![connection])],
        );
        let mut options = ResolverOpts::default();
        options.attempts = 1;
        options.timeout = Duration::from_secs(1);
        options.ip_strategy = LookupIpStrategy::Ipv4Only;
        options.cache_size = 0;
        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(options)
            .build()
            .expect("build loopback resolver");
        let production =
            SystemDnsResolver { resolver: resolver.clone(), validating_resolver: Some(resolver) };
        let name = Name::from_ascii("fixture.test.").expect("fixture name");

        assert_eq!(production.lookup_ips(name.clone()).await, Ok(vec!["192.0.2.55".to_string()]));
        assert_eq!(production.has_records(name.clone(), RecordType::A).await, Ok(true));
        assert!(production.has_records(name.clone(), RecordType::CAA).await.is_err());
        assert_eq!(
            production.nameservers(name.clone()).await,
            Ok(vec!["ns1.fixture.test.".to_string()])
        );
        assert!(
            matches!(production.validate_soa(name.clone()).await, Some(Err(error)) if !error.is_empty())
        );

        let without_validation =
            SystemDnsResolver { resolver: production.resolver.clone(), validating_resolver: None };
        assert!(without_validation.validate_soa(name).await.is_none());

        server.abort();
        assert!(matches!(address.ip(), IpAddr::V4(ip) if ip.is_loopback()));
    }

    #[derive(Debug)]
    struct FixtureDnsResolver;

    #[async_trait]
    impl DnsResolver for FixtureDnsResolver {
        async fn lookup_ips(&self, _name: Name) -> std::result::Result<Vec<String>, String> {
            Ok(vec!["192.0.2.44".to_string()])
        }

        async fn has_records(
            &self,
            _name: Name,
            record_type: RecordType,
        ) -> std::result::Result<bool, String> {
            match record_type {
                RecordType::DNSKEY => Ok(true),
                RecordType::CAA => Ok(false),
                other => Err(format!("unexpected record type: {other}")),
            }
        }

        async fn nameservers(&self, _name: Name) -> std::result::Result<Vec<String>, String> {
            Ok(vec!["ns1.example.test.".to_string()])
        }

        async fn validate_soa(&self, _name: Name) -> Option<std::result::Result<(), String>> {
            Some(Err("signature expired at 2026-01-01".to_string()))
        }
    }

    #[derive(Debug)]
    struct FixtureAxfrProbe {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl AxfrProbe for FixtureAxfrProbe {
        async fn attempt(
            &self,
            _ctx: &InfraContext,
            _zone: &ProtoName,
            nameserver: &str,
        ) -> AxfrOutcome {
            assert_eq!(nameserver, "ns1.example.test.");
            self.calls.fetch_add(1, Ordering::SeqCst);
            AxfrOutcome::Accepted { record_count: 3 }
        }
    }

    #[tokio::test]
    async fn run_observes_every_dns_probe_through_fixture_backends() {
        let axfr_calls = Arc::new(AtomicUsize::new(0));
        let module = DnsInfraModule::with_backends(
            Arc::new(FixtureDnsResolver),
            Arc::new(FixtureAxfrProbe { calls: Arc::clone(&axfr_calls) }),
        );
        let target = InfraTarget::Host("example.test".to_string());
        let config = Arc::new(crate::config::AppConfig::default());
        let context = InfraContext::new(target, config, Vec::new());

        let findings = module.run(&context).await.expect("DNS module run");
        assert_eq!(findings.len(), 5);
        assert!(findings.iter().any(|finding| finding.title == "Wildcard DNS Records Configured"));
        assert!(findings.iter().any(|finding| finding.title == "DNSSEC Signature Expired"));
        assert!(findings.iter().any(|finding| finding.title == "CAA Record Missing"));
        assert!(findings.iter().any(|finding| finding.title == "Authoritative Nameservers"));
        assert!(findings.iter().any(|finding| finding.title == "AXFR Zone Transfer Allowed"));
        assert_eq!(axfr_calls.load(Ordering::SeqCst), 1);
    }

    // =============================================================
    // WORK-145: AXFR + DNSSEC classifier tests
    // =============================================================

    use hickory_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};
    use hickory_resolver::proto::rr::rdata::{NS as NsRdata, SOA};
    use hickory_resolver::proto::rr::{DNSClass, Name as ProtoName, RData, Record, RecordType};

    /// Build a well-formed AXFR query and check the serialised header.
    #[test]
    fn build_axfr_query_header_flags() {
        let zone = ProtoName::from_ascii("example.com.").expect("name");
        let bytes = build_axfr_query(&zone).expect("encode");
        let msg = Message::from_vec(&bytes).expect("parse");
        assert_eq!(msg.message_type, MessageType::Query);
        assert_eq!(msg.op_code, OpCode::Query);
        assert!(!msg.recursion_desired, "AXFR queries are authoritative; no RD");
        assert!(!msg.authentic_data);
        assert!(!msg.checking_disabled);
        assert_eq!(msg.queries.len(), 1);
    }

    #[test]
    fn build_axfr_query_question_section() {
        let zone = ProtoName::from_ascii("example.com.").expect("name");
        let bytes = build_axfr_query(&zone).expect("encode");
        let msg = Message::from_vec(&bytes).expect("parse");
        let q = &msg.queries[0];
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
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = rcode;
        msg.metadata.authoritative = authoritative;
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
    fn nameserver_extraction_ignores_other_record_types() {
        let records = vec![ns_record().data, soa_record().data];
        assert_eq!(extract_nameservers(&records), ["ns2.example.com."]);
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

    #[test]
    fn classify_dnssec_error_bogus() {
        for message in [
            "validation state is bogus",
            "signer name mismatch",
            "bad signature on DNSKEY",
            "RRSIG validation failed",
        ] {
            assert_eq!(classify_dnssec_error(message), DnssecOutcome::Bogus, "{message}");
        }
    }

    #[test]
    fn classify_dnssec_error_expired() {
        for message in [
            "signature expired at 2023-01-01",
            "RRSIG not valid yet (inception in future)",
            "outside the validity period",
        ] {
            assert_eq!(classify_dnssec_error(message), DnssecOutcome::Expired, "{message}");
        }
    }

    #[test]
    fn classify_dnssec_error_missing_ds() {
        for message in [
            "missing DS record at parent",
            "no DS found at parent",
            "chain insecure: zone not signed",
        ] {
            assert_eq!(classify_dnssec_error(message), DnssecOutcome::MissingDs, "{message}");
        }
    }

    #[test]
    fn dns_frame_length_accepts_the_full_u16_domain_except_zero() {
        assert_eq!(dns_frame_length([0, 0]), None);
        assert_eq!(dns_frame_length([0, 1]), Some(1));
        assert_eq!(dns_frame_length([u8::MAX, u8::MAX]), Some(usize::from(u16::MAX)));
    }

    #[test]
    fn classify_dnssec_error_indeterminate() {
        assert_eq!(
            classify_dnssec_error("unexpected network error: connection reset"),
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
        let Some(resolver) = SystemDnsResolver::build() else {
            return;
        };
        let ctx = InfraContext::new(
            InfraTarget::Host(zone.clone()),
            Arc::new(crate::config::AppConfig::default()),
            Vec::new(),
        );
        let mut findings = Vec::new();
        probe_dnssec(&ctx, &resolver, &zone, &mut findings).await.expect("authorized DNSSEC probe");
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
        let Some(resolver) = SystemDnsResolver::build() else {
            return;
        };
        let ctx = InfraContext::new(
            InfraTarget::Host(zone.clone()),
            Arc::new(crate::config::AppConfig::default()),
            Vec::new(),
        );
        let mut findings = Vec::new();
        probe_axfr(&ctx, &resolver, &SystemAxfrProbe, &zone, &mut findings)
            .await
            .expect("authorized AXFR probe");
    }
}
