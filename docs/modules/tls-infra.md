# `tls_infra` — Non-HTTP TLS probe

Fills `InfraCategory::TlsInfra`. Probes a host's TLS-bearing services (mail, directory) and analyses each peer certificate — expiry, self-signed, weak signature, subject/SAN mismatch.

Complements [`ssl`](../architecture/engine.md) (DAST, HTTPS on a single URL) by scanning the broader TLS surface operators routinely forget.

## Quick start

```bash
scorchkit infra mail.example.com --features infra --modules tls_infra
```

Or as part of a full infra scan (registered in `register_modules()` by default):

```bash
scorchkit infra mail.example.com --features infra
```

## Default probe list

| Port | Mode | Service |
|------|------|---------|
| 465 | Implicit TLS | SMTPS |
| 636 | Implicit TLS | LDAPS |
| 993 | Implicit TLS | IMAPS |
| 995 | Implicit TLS | POP3S |
| 25 | STARTTLS (SMTP) | SMTP submission-on-25 |
| 587 | STARTTLS (SMTP) | SMTP Submission |
| 143 | STARTTLS (IMAP) | IMAP |
| 110 | STARTTLS (POP3) | POP3 |

**Implicit TLS** = TCP connect then immediate TLS handshake. **STARTTLS** = plain TCP → protocol-specific upgrade command (`EHLO` + `STARTTLS`, `a001 STARTTLS`, or `STLS`) → positive response → TLS handshake.

HTTPS (443) is **not** in this list — it's owned by DAST's `ssl` module.

## What gets checked

Identical checks to the DAST `ssl` module (same helpers, same OWASP/CWE mappings, same severities):

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| TLS Certificate Expired | Critical | 295 | `not_after` is in the past |
| TLS Certificate Expiring Soon | Medium | — | < 30 days until expiry |
| Self-Signed TLS Certificate | High | 295 | Subject == Issuer |
| Weak Certificate Signature Algorithm | High | 328 | SHA-1 / MD5 in signature OID |
| Certificate Subject Mismatch | High | 295 | CN + SAN miss for the probed host |
| `{SERVICE}` — TLS probe skipped | Info | — | Port closed / handshake refused — surfaced for visibility, not flagged as a defect |

Findings use `module_id = "tls_infra"` (vs `"ssl"` for the DAST path) so filtering and reporting stay clean.

## What's out of scope (for now)

- **RDP-TLS (3389).** RDP requires an X.224 Connection Request negotiation before TLS; non-trivial. Tracked as a follow-up.
- **TLS protocol-range enumeration.** Detecting whether a server still accepts `TLSv1.0` / `TLSv1.1` requires multiple forced-version handshakes — a separate pipeline.
- **Cipher-suite enumeration.** One handshake per cipher, needs a dedicated enumeration loop.
- **FTPS (`AUTH TLS` on 21).** Easy addition; not in v1.

## Configuration

The module currently takes its probe list from `TlsInfraConfig::default()`. A future enhancement will expose `[infra.tls]` in `config.toml` so operators can add / remove ports and protocols without code changes; for now, custom probe lists require constructing `TlsInfraModule::with_config(...)` in library code.

## How it works under the hood

The `engine::tls_probe` module is the shared core:

- `probe_tls(host, port, TlsMode) -> Result<CertInfo>` — single entry point, used by both DAST (`scanner::ssl`) and infra (`infra::tls_probe`). Owns the rustls client build, root store (WebPKI), SNI, and STARTTLS preamble.
- `StarttlsProtocol::{Smtp, Imap, Pop3}` — each carries its own `initial_command()` wire format + positive-response detection. The SMTP dance is multi-line (EHLO → 250-line bag → STARTTLS → 220), IMAP is tagged (`a001 STARTTLS` → `a001 OK`), POP3 is single-verb (`STLS` → `+OK`).
- `check_certificate(&CertInfo, module_id, hostname, affected) -> Vec<Finding>` — same four checks for any caller; `module_id` lets DAST and infra surface identical shapes tagged with their own id.

## Testing

- Unit tests in `engine::tls_probe` cover every check against fixture `CertInfo`s and script the STARTTLS preamble against an ephemeral `TcpListener` (proves the wire format without a real TLS server).
- Unit tests in `infra::tls_probe` cover the default probe list invariant, target extraction from `InfraTarget`, closed-port `Info` surfacing, and empty-probe-list short-circuit.

To run the infra TLS probes against a live host on your network:

```bash
cargo run --features infra -- infra mail.yourdomain.com --modules tls_infra
```
