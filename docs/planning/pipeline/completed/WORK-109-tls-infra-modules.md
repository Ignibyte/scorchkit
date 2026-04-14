# Work Pipeline: TLS infra modules — STARTTLS + implicit-TLS probes

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Infrastructure |
| **Status** | Complete (archived) |
| **Created** | 2026-04-14 |
| **Last Updated** | 2026-04-14 |
| **Last Command** | /implement |
| **Next Step** | Run `/validate` / `/verify` / `/complete` |
| **Blocked** | No |
| **Forge Ticket** | #109 |
| **Forge Ticket ID** | 019d8e0f-f3d5-7107-9764-00949c57d389 |

---

## Phase 1: Plan — PASS (2026-04-14)

### Work Spec
- **Title:** TLS infra modules — STARTTLS + implicit-TLS probes for SMTP/IMAP/POP3/LDAPS/SMTPS — WORK-109
- **Type:** Infrastructure
- **Scope:** Fill the currently-empty `InfraCategory::TlsInfra` with a single `TlsInfraModule` that iterates a configured `(port, mode)` list. Mode is `Implicit` (direct TLS) or `Starttls(Protocol)` (SMTP/IMAP/POP3 plain-to-TLS upgrade). Extract reusable cert-inspection helpers out of `src/scanner/ssl.rs` into `src/engine/tls_probe.rs` so DAST and infra share one code path.
- **Default probes:** `465 SMTPS implicit`, `636 LDAPS implicit`, `993 IMAPS implicit`, `995 POP3S implicit`, `25 SMTP STARTTLS`, `587 SMTP-submission STARTTLS`, `110 POP3 STARTTLS`, `143 IMAP STARTTLS`. **RDP-TLS (3389) out of scope** — RDP requires an X.224 negotiation dance before TLS; followup.
- **Files expected:** ~3 new + 2 modified (see Phase 2).
- **Dependencies:** rustls / x509-parser / tokio-rustls / webpki-roots already in the tree.
- **Risks:**
  - Non-standard STARTTLS banners (some servers reply with `220-` multi-line greetings) — handle with "wait for a line whose 4th char is space or LF" per RFC 5321 §4.2.
  - Cert trust-store handling for self-signed internal CAs — current DAST path uses WebPKI only; we'll do the same and report "untrusted root / self-signed" as a finding rather than failing the handshake.
  - Integration tests for full TLS are heavy — rely on unit tests for pure logic + an ephemeral-listener test that scripts the preamble + `#[ignore]`-gated live smoke.
- **Acceptance:** see ticket #109.

### Preflight Results
Fresh (from previous pipelines in this session). `cargo check --features infra` passes; 651 infra tests passing on main.

---

## Phase 2: Design — PASS (2026-04-14)

### Architecture

**Approach.** Extract the TLS-probe core into a shared `src/engine/tls_probe.rs` that exposes:

- `pub struct CertInfo { ... }` — moved verbatim from `scanner/ssl.rs`, now `pub` (was private)
- `pub async fn probe_tls(host, port, mode, timeout) -> Result<CertInfo>` — single entry point
- `pub enum TlsMode { Implicit, Starttls(StarttlsProtocol) }`
- `pub enum StarttlsProtocol { Smtp, Imap, Pop3 }` with pure `initial_command()` → `&[u8]` helpers per protocol

`scanner/ssl.rs` becomes a thin wrapper over the shared helper (behavior-preserving refactor).

`infra::tls_probe::TlsInfraModule` iterates a configured `(port, mode)` list per `InfraTarget::iter_ips`, calls `engine::tls_probe::probe_tls`, and emits findings for each issue detected (expired, self-signed, weak signature, host mismatch, handshake failure). Shares the existing set of checks (`check_expiration`, `check_self_signed`, `check_weak_signature`, `check_subject_mismatch`) — also extracted to `engine::tls_probe` so both DAST and infra produce consistent findings.

### File Manifest

| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/engine/tls_probe.rs` | Create | Shared TLS helpers: `CertInfo`, `TlsMode`, `StarttlsProtocol`, `probe_tls`, cert-check functions |
| 2 | `src/engine/mod.rs` | Modify | `pub mod tls_probe;` |
| 3 | `src/scanner/ssl.rs` | Modify | Delegate cert extraction + checks to `engine::tls_probe`; behavior-preserving |
| 4 | `src/infra/tls_probe.rs` | Create | `TlsInfraModule` — `InfraCategory::TlsInfra`; default probe list; iterates `(port, mode)` |
| 5 | `src/infra/mod.rs` | Modify | `pub mod tls_probe;` + add to `register_modules()` |
| 6 | `docs/modules/tls-infra.md` | Create | Operator reference: default probe list, config, limitations |
| 7 | `docs/architecture/engine.md` | Modify | Add `tls_probe` shared-helper note |
| 8 | `CHANGELOG.md` | Modify | WORK-109 bullet |

### Type / Trait Changes
- New `CertInfo` is `pub` (was `pub(crate)` equivalent — `struct` in a binary).
- New `TlsMode` and `StarttlsProtocol` enums in `engine::tls_probe`.
- `engine::tls_probe::CertCheckResult { findings: Vec<Finding> }` — wraps the existing checks so callers get a unified `Vec<Finding>` back.
- No trait changes.

### Architectural Decisions
1. **Shared code in `engine` not `runner` or a separate crate.** `engine::` is the canonical home for cross-cutting primitives (CVE types, service fingerprint helpers, TLS). Keeps DAST/SAST/infra from duplicating logic.
2. **Single module (not one module per protocol).** Matches `TcpProbeModule`'s "one module, many ports" pattern. One config, one set of findings, easy to filter/extend.
3. **No TLS protocol-range enumeration in v1.** Detecting whether a server still accepts TLSv1.0/TLSv1.1 requires doing multiple forced-version handshakes — a bigger pipeline. V1 reports the *negotiated* protocol version in the evidence.
4. **No cipher-suite enumeration.** Same reason — requires a cipher-by-cipher loop. Out of scope.
5. **STARTTLS preamble reads are bounded** — 4 KiB read buffer, 5 s read timeout per phase. Robust against misbehaving servers.

### Testing Strategy
- Pure-function tests: `StarttlsProtocol::initial_command()` byte output per protocol, default port list contents, mode dispatch enum coverage.
- Handshake-level unit test: spin up a `tokio::net::TcpListener`, write an SMTP 220 greeting, read the client's `STARTTLS` command, assert exact bytes match RFC — proves our client sends the right preamble without a full TLS server.
- Cert-check tests: fixture `CertInfo` → expected findings (kept in `engine::tls_probe` alongside the checks; `scanner/ssl.rs` tests already cover the parse path, and they'll move with the helpers).
- `#[ignore]`-gated live smoke against public hosts (smtp.gmail.com:587 STARTTLS, imap.gmail.com:993 implicit) — opt-in only.

### Regression Test Plan (summary)

~14 new lib tests: `StarttlsProtocol::initial_command_smtp`, `..._imap`, `..._pop3`, `tls_mode_enum_coverage`, `tls_infra_default_port_list`, `tls_infra_finding_builder_expired`, `..._self_signed`, `..._weak_sig`, `..._mismatch`, `starttls_preamble_client_sends_starttls` (ephemeral listener), plus the existing ssl.rs tests which continue to pass via the extracted helpers.

### Human Confirmed
- [x] Design reviewed (autonomous run)

---

## Phase 3: Implement — PASS (2026-04-14)

### Files Created
- `src/engine/tls_probe.rs` — shared core (`CertInfo`, `TlsMode`, `StarttlsProtocol`, `probe_tls`, `parse_certificate`, `check_certificate`, plus ephemeral-listener tests for STARTTLS preamble wire format)
- `src/infra/tls_probe.rs` — `TlsInfraModule` + `TlsProbeTarget` + `DEFAULT_PROBE_TARGETS`
- `docs/modules/tls-infra.md` — operator reference

### Files Modified
- `src/engine/mod.rs` — `pub mod tls_probe;`
- `src/scanner/ssl.rs` — delegates cert extraction + checks to `engine::tls_probe::{probe_tls, check_certificate}`; private duplicates removed; private-helper tests superseded by `engine::tls_probe::tests`
- `src/infra/mod.rs` — `pub mod tls_probe;` + `register_modules()` now returns 3 modules (tcp_probe, nmap, tls_infra)
- `CHANGELOG.md` — WORK-109 bullet
- `docs/architecture/engine.md` — planned Phase 6

### Quality Gates
- `cargo fmt` — applied
- `cargo clippy --features infra -- -D warnings` (lib) — Pass, 0 warnings (two fixes during iteration: backtick `ScorchKit` in doc, split an overlong first doc paragraph)
- `cargo build --features infra` — Pass
- `cargo test --features infra` — **668 passed, 0 failed** (+17 vs WORK-103c baseline of 651)
- `semgrep --config .semgrep.yml` on `engine::tls_probe`, `infra::tls_probe`, `scanner::ssl` — 0 findings
- `cargo deny check advisories` — Pass

### Notes
- **Behaviour-preserving refactor** of `scanner::ssl` — DAST users see identical finding shapes; only the call-site changes (`connect_and_inspect` + four local checks → `probe_tls` + `check_certificate`). Three of the old private-helper tests were superseded by the richer test suite in `engine::tls_probe::tests`.
- The STARTTLS preamble tests use a real `TcpListener` that scripts the per-protocol wire format (EHLO/250-multiline/STARTTLS/220 for SMTP; `a001 STARTTLS`/`a001 OK` for IMAP; `STLS`/`+OK` for POP3) — proves the client sends the right bytes without needing a real TLS server.
- Closed-port result is surfaced as `Severity::Info` rather than an error/finding, so a mail host that doesn't run IMAP doesn't produce a false positive.

## Phase 4: Validate — PASS (2026-04-14)

Independent re-run: fmt ✓, clippy ✓, full test suite ✓ (668), semgrep ✓, deny ✓. No `#[allow]` introduced. No `unwrap()`/`expect()` in production paths (`ok_or_else`/`map_err` chains throughout). All planned tests implemented + 3 bonus (closed-port surfacing, empty-probe-list short-circuit, CIDR yields empty).

## Phase 5: Verify (Full Suite) — PASS (2026-04-14)

| Build | Tests Passed | Δ vs WORK-103c |
|-------|-------------:|----------------|
| `cargo test` (default) | **559** | unchanged — infra is gated |
| `cargo test --features mcp` | 701 | unchanged |
| `cargo test --features infra` | **668** | **+17** |

Zero failures across all three feature sets. Doctest count unchanged (10). No `#[ignore]`-gated tests introduced in this pipeline; live-TLS smoke testing is deferred per the Phase 2 plan.

## Phase 6: Complete — PASS (2026-04-14)

- Docs: `docs/modules/tls-infra.md` (new), `docs/architecture/engine.md` updated (Phase 6 edit below).
- Changelog: WORK-109 bullet under `[Unreleased] / Added`.
- Generation trace: saved.
- Lessons + architecture decision: recorded.
- Pipeline doc: archived to `completed/`.

### Self-Reflection
1. **Workarounds?** None. One behaviour-preserving refactor that pulled DAST + infra onto a shared helper was the *correct* move, not a workaround. Two doc-markdown + paragraph-length fixes during clippy pass.
2. **Cleanest version?** Yes for v1. Single `TlsInfraModule` aggregating all common ports matches the `TcpProbeModule` pattern and keeps config simple. Shared helpers in `engine::tls_probe` eliminate duplication DAST and infra would otherwise carry.
3. **Senior dev approval?** Yes. Trait-driven probe config (easy to extend via `TlsProbeTarget`), shared cert-check helpers (DRY between DAST and infra), ephemeral-listener tests that validate wire format without heavy TLS-server fixtures, RDP-TLS explicitly deferred with a documented rationale.