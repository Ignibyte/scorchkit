# `dns_infra` — Native DNS hygiene probe

Fills `InfraCategory::Dns`, the last empty slot in the v2.0 `InfraCategory` enum. Runs native DNS probes against the target zone using `hickory-resolver` (with `dnssec-aws-lc-rs` enabled for chain validation) plus a raw-TCP AXFR probe built on `hickory-proto`.

## Finding catalog

| # | Check | Severity | Trigger |
|---|-------|---------:|---------|
| 1 | Wildcard DNS | Medium | A random non-existent subdomain resolves |
| 2 | DNSSEC Not Configured | Medium | No `DNSKEY` records at the apex (zone is unsigned) |
| 3 | DNSSEC Chain Validated | Info | Parent DS → DNSKEY → RRSIG chain walks cleanly |
| 4 | DNSSEC Chain Validation Failed | **Critical** | Validator reports `bogus` / bad RRSIG / signer-name mismatch |
| 5 | DNSSEC Signature Expired | High | At least one RRSIG is outside its validity window |
| 6 | DNSSEC DS Record Missing at Parent | Medium | Zone publishes DNSKEY but parent has no DS (broken trust anchor) |
| 7 | DNSSEC Validation Error | Medium | Validator rejected the zone but the specific failure mode couldn't be classified |
| 8 | Missing CAA | Low | No `CAA` records at the apex |
| 9 | Authoritative Nameservers | Info | Surface the NS list |
| 10 | AXFR Zone Transfer Allowed | **Critical** | An authoritative NS granted an AXFR (per-NS finding) |

## Quick start

```bash
scorchkit infra example.com --features infra --modules dns_infra
```

Or as part of a full infra scan (registered in `register_modules()` by default):

```bash
scorchkit infra example.com --features infra
```

## What each check does

### Wildcard DNS

Generates a 16-hex-char random subdomain label per scan (64 bits of entropy from a fresh UUID, so the probability of colliding with a real subdomain is vanishing). Queries A/AAAA. If the response is a hit, the zone is using a wildcard record — typos and misrouted traffic are silently absorbed by an authoritative answer, and any subdomain-enumeration tool (including ScorchKit's own `subdomain` recon) will produce false positives.

Healthy zones return NXDOMAIN here.

### DNSSEC — two-pass validation (WORK-145)

The probe runs in two passes:

1. **Presence pass** — non-validating resolver, `DNSKEY` query at the apex. Empty response → **"DNSSEC Not Configured"** (Medium). Non-empty → continue.
2. **Validation pass** — validating resolver with `ResolverOpts::validate = true` + `dnssec-aws-lc-rs` crypto backend. Hickory walks the chain internally (parent DS → child DNSKEY → RRSIG over the apex SOA) and either accepts the records (→ **"DNSSEC Chain Validated"** Info) or returns an error. Errors map to severity-tiered findings via pattern-matching on the validator's display string:

| Validator error pattern | Outcome | Finding |
|------------------------|---------|---------|
| `expired` / `not valid yet` / `validity period` | `Expired` | **High** — signature expired |
| `rrsig` / `bogus` / `signer name` / `bad signature` | `Bogus` | **Critical** — chain validation failed |
| `ds record` / `no ds` / `insecure` | `MissingDs` | Medium — DS missing at parent |
| anything else | `Indeterminate` | Medium — validation error with raw text in evidence |

We delegate the chain walk to hickory rather than re-implementing parent-DS-resolution → DNSKEY retrieval → RRSIG verification by hand. Trade-off: finding *text* for bogus chains is generic when the validator's error is generic, but every failure still produces a finding. The `Indeterminate → Medium` fallback is a deliberate fail-safe — we'd rather surface "something broke in DNSSEC for this zone, check manually" than silently drop.

### Missing CAA

Queries `CAA` for the apex. Without CAA, any publicly-trusted CA will accept issuance requests for the domain — raising the blast radius of a compromised CA or a social-engineered issuance event. Severity is Low because CAA is defence-in-depth rather than a primary control.

### NS enumeration

Surfaces the authoritative servers as Info evidence — useful for downstream tooling (delegation divergence checks, registrar audits, monitoring) without flagging anything as a defect.

### AXFR zone transfer (WORK-145)

Native probe built on `hickory-proto`'s `Message` type over raw `tokio::net::TcpStream`. Fans out across every NS returned in the zone's NS RRset:

1. Build a DNS query with `QTYPE = AXFR` (252), `QCLASS = IN`.
2. Prefix with the standard 2-byte big-endian length field, write to TCP.
3. Read the first response packet (`read_exact` on the length prefix, then the payload).
4. Classify the response:
   - `NoError` RCODE + `AA` flag set + `ANCOUNT > 0` + SOA in the answers → **Critical** "AXFR Zone Transfer Allowed" finding with record count + NS name in evidence.
   - Any rejection (`Refused` / `ServFail` / empty answers / non-authoritative answer / no SOA) → silent `debug!` log, no finding.
   - TCP error, timeout, truncated response → silent.

Every healthy server in the world rejects AXFR from non-secondaries, so the expected outcome is *zero findings* on a well-configured zone. A Critical finding here means operators need to fix the NS's `allow-transfer` / `provide-xfr` / equivalent ACL.

**Budget:** 2s per NS. A zone with 5 NSs costs at most ~10s on the AXFR probe.

## Configuration

No `[infra.dns]` block yet — the module uses built-in defaults (attempts=2, validate on the second pass, 2s AXFR per-NS timeout). A future enhancement could expose these for operators who need to tune against unreliable upstream resolvers.

## Live smoke tests

Two `#[ignore]`-gated tests run against real DNS when an operator provides a zone:

```bash
SCORCHKIT_DNS_TEST_ZONE=cloudflare.com \
    cargo test --features infra -- --ignored dnssec_chain_live

SCORCHKIT_DNS_TEST_ZONE=your-test-zone.example \
    cargo test --features infra -- --ignored axfr_probe_live
```

These follow the same pattern as `cve_nvd_live` (WORK-103b) and `tls_version_enum_live` (WORK-143) — they gate on env-var presence and no-op when absent.

## Limitations

- **Validator error text isn't a stable interface.** Hickory-resolver's `ResolveError` display string is what we pattern-match on for the DNSSEC classifier. A hickory version bump could silently drop granularity — mitigated by the `Indeterminate → Medium` fallback, which still produces a finding.
- **AXFR only reads the first response packet.** Full zone enumeration would span multiple TCP frames and dozens of records; for an acceptance probe we only need the first response. Operators who want the full zone contents should continue to use `dnsrecon` / `dnsx`.
- **NS divergence** (parent vs. child NS records) — single-lookup only in v1.
- **SPF / DMARC / DKIM** — email-security, not DNS hygiene; belongs in a separate module family.
- **IP-only / CIDR targets** are skipped: there's no zone to probe reliably from a raw address.

## What's under the hood

`hickory-resolver` with `dnssec-aws-lc-rs` — the `aws-lc-rs` crypto backend matches the one rustls 0.23 uses elsewhere in the binary (WORK-143), so only one crypto library ends up compiled in. `hickory-proto` is transitive via `hickory-resolver` and exposes the `Message` + `RecordType::AXFR` types we need for the native AXFR probe — no separate `hickory-client` crate required.

Findings tag `module_id = "dns_infra"`.
