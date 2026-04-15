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
| 3389 | RDP-TLS (X.224) | RDP |

**Implicit TLS** = TCP connect then immediate TLS handshake. **STARTTLS** = plain TCP → protocol-specific upgrade command (`EHLO` + `STARTTLS`, `a001 STARTTLS`, or `STLS`) → positive response → TLS handshake. **RDP-TLS** = plain TCP → RDP X.224 Connection Request / Connection Confirm negotiation (MS-RDPBCGR) requesting `PROTOCOL_SSL` → TLS handshake. NLA-only hosts (CredSSP required) respond with `RDP_NEG_FAILURE` and surface as Info findings rather than defects — the probe is about cert discovery, not authentication.

HTTPS (443) is **not** in this list — it's owned by DAST's `ssl` module.

## What gets checked

### Certificate findings (WORK-109)

Identical checks to the DAST `ssl` module (same helpers, same OWASP/CWE mappings, same severities):

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| TLS Certificate Expired | Critical | 295 | `not_after` is in the past |
| TLS Certificate Expiring Soon | Medium | — | < 30 days until expiry |
| Self-Signed TLS Certificate | High | 295 | Subject == Issuer |
| Weak Certificate Signature Algorithm | High | 328 | SHA-1 / MD5 in signature OID |
| Certificate Subject Mismatch | High | 295 | CN + SAN miss for the probed host |
| `{SERVICE}` — TLS probe skipped | Info | — | Port closed / handshake refused — surfaced for visibility, not flagged as a defect |

### Protocol + cipher enumeration findings (WORK-143)

When `enum_protocols = true` (default) and / or `cipher_enum_limit = Some(N)` (opt-in), each probe additionally enumerates accepted versions and / or weak cipher suites and aggregates results **one finding per severity tier per port**. Full per-entry lists appear in the finding's `evidence` field.

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| `{SERVICE}` — Deprecated TLS protocol accepted (SSLv3/TLSv1.0) | Critical | 326 | SSLv3 or TLSv1.0 accepted (POODLE, BEAST) |
| `{SERVICE}` — Deprecated TLS protocol accepted (TLSv1.1) | High | 326 | TLSv1.1 accepted (RFC 8996 deprecated) |
| `{SERVICE}` — TLS modern versions accepted | Info | — | Informational summary of TLSv1.2 / TLSv1.3 negotiated |
| `{SERVICE}` — Critical TLS cipher suites accepted | Critical | 327 | NULL / anonymous DH / EXPORT / DES cipher accepted |
| `{SERVICE}` — Weak TLS cipher suites accepted | High | 327 | RC4 / 3DES / MD5-MAC cipher accepted |
| `{SERVICE}` — Legacy CBC-mode cipher suites accepted | Medium | 327 | Legacy CBC-mode AES cipher accepted (not broken, not recommended) |

Findings use `module_id = "tls_infra"` (vs `"ssl"` for the DAST path) so filtering and reporting stay clean.

## Configuration

### `TlsInfraConfig` fields

| Field | Default | Purpose |
|-------|---------|---------|
| `targets` | 8 default ports (SMTPS / LDAPS / IMAPS / POP3S + STARTTLS variants) | Which ports to probe |
| `enum_protocols` | `true` | Run SSLv3 / TLSv1.0 / TLSv1.1 / TLSv1.2 / TLSv1.3 acceptance probes (5 probes per port, ~5s) |
| `cipher_enum_limit` | `None` (disabled) | Set to `Some(N)` to probe the first N entries from `weak_cipher_catalog()`. Each cipher probe is a full TCP handshake (~1s each). Expect ~30s for the full catalog. |

Library usage:

```rust
use scorchkit::infra::tls_probe::{TlsInfraConfig, TlsInfraModule};

// Full hardening audit — slow but thorough
let config = TlsInfraConfig::default()
    .with_protocol_enum(true)
    .with_cipher_enum_limit(Some(40));
let module = TlsInfraModule::with_config(config);
```

A future enhancement will expose `[infra.tls]` in `config.toml` so operators can add / remove ports and toggle enumeration without code changes; for now, custom probe lists require constructing `TlsInfraModule::with_config(...)` in library code.

## What's out of scope (for now)

- **TLS1.3 cipher enumeration.** RFC 8446 defines only 5 AEAD suites, all modern; enumeration would add no security value.
- **FTPS (`AUTH TLS` on 21).** Easy addition; not in v1.

## How it works under the hood

The `engine::tls_probe` module is the shared core for cert inspection:

- `probe_tls(host, port, TlsMode) -> Result<CertInfo>` — single entry point, used by both DAST (`scanner::ssl`) and infra (`infra::tls_probe`). Owns the rustls client build, root store (WebPKI), SNI, and the optional upgrade preambles.
- `StarttlsProtocol::{Smtp, Imap, Pop3}` — each carries its own `initial_command()` wire format + positive-response detection. The SMTP dance is multi-line (EHLO → 250-line bag → STARTTLS → 220), IMAP is tagged (`a001 STARTTLS` → `a001 OK`), POP3 is single-verb (`STLS` → `+OK`).
- `TlsMode::RdpTls` — drives the RDP X.224 Connection Request / Connection Confirm exchange per MS-RDPBCGR 2.2.1.1–2.2.1.2. The CR is a fixed 38-byte packet (TPKT header + X.224 CR TPDU + empty-cookie stub + `RDP_NEG_REQ` requesting `PROTOCOL_SSL`). The CC is parsed for `RDP_NEG_RSP` (success) vs `RDP_NEG_FAILURE` (NLA-only host → Info finding).
- `check_certificate(&CertInfo, module_id, hostname, affected) -> Vec<Finding>` — same four checks for any caller; `module_id` lets DAST and infra surface identical shapes tagged with their own id.

The `engine::tls_enum` module is the shared core for hardening enumeration:

- `probe_tls_version(host, port, mode, version) -> ProbeOutcome` — dispatches to rustls for TLSv1.2 / TLSv1.3 and to a raw-socket ClientHello for SSLv3 / TLSv1.0 / TLSv1.1.
- `probe_tls_cipher(host, port, mode, cipher) -> ProbeOutcome` — raw-socket ClientHello offering exactly one cipher under `client_version = 0x0303`. Server's first record classifies the outcome.
- `enumerate_tls_versions(host, port, mode) -> Vec<(TlsVersionId, ProbeOutcome)>` — probes every variant of `ALL_PROBED_VERSIONS` in order.
- `enumerate_weak_ciphers(host, port, mode, limit) -> Vec<CipherSuiteId>` — iterates `weak_cipher_catalog()` (up to `limit`) and returns only the accepted suites.

## Testing

- Unit tests in `engine::tls_probe` cover every cert check against fixture `CertInfo`s and script both the STARTTLS and RDP-TLS X.224 preambles against an ephemeral `TcpListener` (proves the wire format without needing a real TLS server). RDP-TLS tests (WORK-148) include a golden-byte CR layout pin, a successful CR→CC exchange, an `RDP_NEG_FAILURE` path (NLA-only hosts), and a peer-close-mid-negotiation no-panic guard.
- Unit tests in `engine::tls_enum` cover version / cipher classifiers, ClientHello byte-layout invariants, server-response parser, and ephemeral-listener round-trips for each `ProbeOutcome` state.
- Unit tests in `infra::tls_probe` cover the default probe list invariant (including the `RDP-TLS` label pin on port 3389), target extraction from `InfraTarget`, closed-port `Info` surfacing, empty-probe-list short-circuit, enum-default contract, and closed-port enum behavior (Unknown must not fabricate findings).
- Live smoke tests `tls_version_enum_live` / `tls_cipher_enum_live` are `#[ignore]`-gated; run via `SCORCHKIT_TLS_ENUM_HOST=host:port cargo test --features infra -- --ignored tls_.*_enum_live`.

To run the infra TLS probes against a live host on your network:

```bash
cargo run --features infra -- infra mail.yourdomain.com --modules tls_infra
```
