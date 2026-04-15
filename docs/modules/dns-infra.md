# `dns_infra` — Native DNS hygiene probe

Fills `InfraCategory::Dns`, the last empty slot in the v2.0 `InfraCategory` enum. Runs four checks against the target zone using a native async resolver (`hickory-resolver`):

| # | Check | Severity | Trigger |
|---|-------|---------:|---------|
| 1 | Wildcard DNS | Medium | A random non-existent subdomain resolves |
| 2 | Missing DNSSEC | Medium | No `DNSKEY` records at the apex |
| 3 | Missing CAA | Low | No `CAA` records at the apex |
| 4 | NS enumeration | Info | Surface the authoritative-server list |

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

### Missing DNSSEC

Queries `DNSKEY` for the apex. If empty, the zone isn't signed and clients can't distinguish authentic answers from spoofed ones. Severity is Medium because exploitation requires on-path or upstream-resolver compromise but the impact is total impersonation of the domain.

This is a **presence** check only. Full chain validation (DS at parent → DNSKEY at zone → RRSIG over every RRset) is a separate pipeline.

### Missing CAA

Queries `CAA` for the apex. Without CAA, any publicly-trusted CA will accept issuance requests for the domain — raising the blast radius of a compromised CA or a social-engineered issuance event. Severity is Low because CAA is defence-in-depth rather than a primary control.

### NS enumeration

Surfaces the authoritative servers as Info evidence — useful for downstream tooling (delegation divergence checks, registrar audits, monitoring) without flagging anything as a defect.

## Limitations

- **AXFR zone transfer** isn't here. The existing `dnsrecon` and `dnsx` tool wrappers already cover that, and a native impl needs `hickory-client` rather than just the resolver. Tracked as a follow-up.
- **NS divergence** (parent vs. child NS records) — single-lookup only in v1.
- **DNSSEC chain validation** — presence only.
- **SPF / DMARC / DKIM** — email-security, not DNS hygiene; belongs in a separate module family.
- **IP-only / CIDR targets** are skipped: there's no zone to probe reliably from a raw address.

## What's under the hood

`hickory-resolver` with default features (`system-config` for `/etc/resolv.conf` parsing + `tokio` for async). The resolver is constructed per-scan (cheap, keeps the module stateless). Attempts are capped at 2 so dead zones fail fast.

Findings tag `module_id = "dns_infra"`.
