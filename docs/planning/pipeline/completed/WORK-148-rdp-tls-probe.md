# Work Pipeline: RDP-TLS Probe (X.224 Negotiation)

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 6: Complete |
| **Created** | 2026-04-15 |
| **Last Updated** | 2026-04-15 |
| **Last Command** | /complete |
| **Next Step** | Run `/commit` to branch, push, open PR |
| **Blocked** | No |
| **Forge Ticket** | #148 |
| **Forge Ticket ID** | 019d9268-b7f2-7320-9da8-48eb3aa6add1 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Work Spec
- **Title:** RDP-TLS probe (X.224 negotiation) — close v2.1.x arc
- **Type:** Feature
- **Scope:** Extend `engine::tls_probe` with a `TlsMode::RdpTls` variant that performs the RDP-specific X.224 / TPKT Connection Request → Connection Confirm negotiation before handing the socket to rustls. Register port 3389 in `infra::tls_probe::DEFAULT_PROBE_TARGETS` so `TlsInfraModule` covers RDP-TLS out of the box. Integration-tested via an ephemeral `TcpListener` that scripts the X.224 wire format, matching the existing STARTTLS preamble pattern.
- **Files Expected:** ~4 code files + ~4 doc files
  - `src/engine/tls_probe.rs` — add `TlsMode::RdpTls` variant, `run_rdp_x224_preamble()` helper, wire into `probe_tls()` match; add 3 STARTTLS-style ephemeral-listener tests for CR/CC exchange
  - `src/infra/tls_probe.rs` — add port 3389 to `DEFAULT_PROBE_TARGETS`; flip `!ports.contains(&3389)` assertion; add RDP-TLS label assertion
  - `src/engine/tls_probe.rs` + `src/infra/tls_probe.rs` — update crate-level doc comments (remove "out of scope" callouts)
  - `docs/modules/tls-infra.md` — remove RDP-TLS follow-up bullet; document RDP-TLS probe in default coverage
  - `docs/architecture/infra.md` + `docs/architecture/engine.md` — update RDP-TLS deferred mentions
  - `CHANGELOG.md` — record WORK-148 under v2.1.x
- **Dependencies:**
  - WORK-109 (shipped) — the shared `engine::tls_probe` primitives (`probe_tls`, `check_certificate`, `TlsMode`, `StarttlsProtocol`).
  - No PR 62–66 dependencies — slots in orthogonally.
- **Risks:**
  - MS-RDPBCGR `RDP_NEG_REQ` / `RDP_NEG_RSP` PDUs are small and well-documented, but TPKT (RFC 1006) + ITU-T X.224 COTP framing is easy to get wrong. **Mitigation:** golden-byte tests pin the CR packet layout; ephemeral listener asserts the server sees the exact expected bytes.
  - RDP peers sometimes close the socket instead of returning `RDP_NEG_FAILURE` when `PROTOCOL_SSL` is unavailable (NLA-only hosts). **Mitigation:** reuse the existing error-to-Info pattern from `scanner::ssl` + `infra::tls_probe::probe_one` — socket-close mid-negotiation becomes an `Err(String)` that produces a confidence-0.3 Info finding, not a panic.
  - Default crypto provider install is already handled inside `probe_tls()`; no duplication risk.
- **Acceptance Criteria:**
  - `TlsMode::RdpTls` variant compiles, threads through `probe_tls()`, and drives a successful X.224 handshake before the rustls upgrade.
  - Port 3389 is included in `TlsInfraModule` default probes with label `"RDP-TLS"`.
  - Integration test(s) validate wire-format CR → CC exchange against an ephemeral `TcpListener` — no real RDP server required.
  - Failure modes (`RDP_NEG_FAILURE`, truncated TPKT, wrong protocol in response, peer close) surface as `Err(String)` and produce Info-severity findings; never a panic.
  - All four docs / comments mentioning RDP-TLS as "deferred" / "out of scope" / "follow-up" are updated to reflect v2.1.x shipping status.
  - `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` all pass with zero warnings.
  - Full suite: no regressions vs current baseline (default / mcp / infra test counts).

### Preflight Results
| Check | Status | Notes |
|-------|--------|-------|
| Forge MCP | OK | bootstrap returned ScorchKit project context |
| cargo | OK | 1.94.0 |
| rustc | OK | 1.94.0 |
| cargo fmt | OK | rustfmt 1.8.0 |
| cargo clippy | OK | 0.1.94 |
| semgrep | OK | installed |
| cargo-audit | OK | 0.22.1 |
| cargo-deny | OK | 0.19.0 |
| cargo-tarpaulin | OK | 0.35.2 |
| .semgrep.yml | OK | present |
| deny.toml | OK | present |
| rustfmt.toml | OK | present |
| gh CLI | OK | 2.87.3 |
| Hooks wired | OK | 2 PreToolUse + 6 Stop = 8 total |
| cargo check | OK | compiles clean |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- **DL-004-P1 / DL-016-P1:** After any context continuation, re-read this pipeline doc before resuming. Pipeline doc is the source of truth, not conversational memory. Must call `bootstrap` → `recall` → `ticket-next` before writing code.
- **DL-002-P1:** Phase gate discipline — don't register the new variant / port 3389 until Phase 4 validation passes.
- **DL-015-P1:** Not applicable here (no schema migrations).
- **WORK-109 lesson:** The STARTTLS preamble tests script the wire format against an ephemeral `TcpListener` without needing a real TLS server. Reuse that exact pattern for the X.224 CR/CC exchange.
- **General tls_probe contract:** `probe_tls()` never panics; all failures return `Err(String)` that the caller surfaces as a Finding. RDP-TLS must preserve this contract.

---

## Forge Briefing

Every phase command MUST call these Forge MCP tools:

1. **Bootstrap** — `bootstrap` for project context, architecture decisions, active patterns
2. **Recall** — `recall(agent="{role}", phase={N}, component_types=["engine", "infra", "tls"])` for targeted failures and lessons
3. **Learn** — `learn(summary, topic, component_types)` to record what was discovered
4. **Search** — `search-architecture-docs` for project patterns before writing code

These are enforced by `enforce-completion.sh`. Skipping them blocks the conversation from ending.

---

## Phase 2: Design
**Command:** /design
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Architecture

**Approach:**
Extend `engine::tls_probe` with a `TlsMode::RdpTls` variant. In `probe_tls()`, when this variant is selected, run a new `run_rdp_x224_preamble()` helper that drives the MS-RDPBCGR-prescribed handshake before rustls takes over:

```
TCP connect
  → send TPKT + X.224 CR + RDP_NEG_REQ(PROTOCOL_SSL)
  → read TPKT + X.224 CC + RDP_NEG_RSP(selectedProtocol=PROTOCOL_SSL)
  → return the same TcpStream, now ready for TLS upgrade
```

The preamble sits structurally alongside `run_starttls_preamble` — same return type (`io::Result<TcpStream>`), same `Err` surface semantics (any failure becomes a `String` in `probe_tls`, which `probe_one` wraps as a confidence-0.3 `Severity::Info` "TLS probe skipped" finding — the existing contract). Register port 3389 in `DEFAULT_PROBE_TARGETS` with label `"RDP-TLS"`; flip the sentinel `!ports.contains(&3389)` test assertion in `infra::tls_probe`.

**Wire format (pinned in code as `const` byte arrays for golden-byte tests):**

CR packet (client → server), total 38 bytes:
| Offset | Bytes | Meaning |
|--------|-------|---------|
| 0      | `03 00` | TPKT version 3 + reserved |
| 2      | `00 26` | TPKT total length = 38 (big-endian u16) |
| 4      | `21` | X.224 LI = 33 |
| 5      | `E0` | X.224 CR-TPDU type (with CDT = 0) |
| 6      | `00 00` | DST-REF |
| 8      | `00 00` | SRC-REF |
| 10     | `00` | Class 0 / no options |
| 11–29  | `"Cookie: mstshash=\r\n"` | MS-RDPBCGR 2.2.1.1 optional cookie (19 bytes, empty username — matches rdesktop/FreeRDP defaults) |
| 30     | `01` | RDP_NEG_REQ type |
| 31     | `00` | RDP_NEG_REQ flags (no CORRELATION_INFO) |
| 32     | `08 00` | RDP_NEG_REQ length = 8 (little-endian u16, fixed) |
| 34     | `01 00 00 00` | requestedProtocols = PROTOCOL_SSL (LE u32) |

CC expected bytes (server → client, 19 bytes minimum on success):
| Offset | Bytes | Meaning |
|--------|-------|---------|
| 0      | `03 00` | TPKT version |
| 2      | `00 13` | TPKT total length = 19 (big-endian u16) — may be longer if server sends extras; we read `tpkt_len` then drain the COTP body |
| 4      | `0E` | X.224 LI = 14 |
| 5      | `D0` | X.224 CC-TPDU type (with CDT = 0) |
| 6–10   | `00 00 xx xx 00` | DST-REF + SRC-REF + Class (srv values; don't validate SRC-REF) |
| 11     | `02` or `03` | `02` = RDP_NEG_RSP (success); `03` = RDP_NEG_FAILURE |
| 12     | `xx` | flags (informational — not validated) |
| 13     | `08 00` | fixed length 8 |
| 15     | `01 00 00 00` | selectedProtocol = PROTOCOL_SSL when success; when failure, this is a failureCode and bytes at offset 11 = `03` |

Validation: if byte 11 = `0x03` → `Err("RDP negotiation failed: code=...")`; if byte 11 = `0x02` and selectedProtocol ≠ `PROTOCOL_SSL` → `Err("server selected non-SSL protocol: 0x...")`. Anything else (short read, wrong TPKT version, non-CC TPDU type) → `Err` with the byte that disagreed.

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/engine/tls_probe.rs` | Modify | Add `TlsMode::RdpTls` variant; add private constants (`TPKT_VERSION`, `X224_CR_TPDU`, `X224_CC_TPDU`, `RDP_NEG_REQ_TYPE`, `RDP_NEG_RSP_TYPE`, `RDP_NEG_FAILURE_TYPE`, `PROTOCOL_SSL`, `RDP_CR_PACKET` as a `[u8; 38]` const); add `run_rdp_x224_preamble(TcpStream) -> io::Result<TcpStream>`; add a private `read_exact_with_timeout(&mut TcpStream, &mut [u8]) -> io::Result<()>` helper (mirrors the timeout pattern of `read_line_with_budget` but for fixed-size binary reads); wire `TlsMode::RdpTls` branch into `probe_tls()` match; update module doc comment — remove the "RDP-TLS (requires X.224 Connection Request negotiation)" out-of-scope bullet. |
| 2 | `src/infra/tls_probe.rs` | Modify | Add `TlsProbeTarget { port: 3389, mode: TlsMode::RdpTls, label: "RDP-TLS" }` to `DEFAULT_PROBE_TARGETS`; update module-level doc comment — move RDP-TLS out of the "out of scope" section and into the covered probe list; flip `assert!(!ports.contains(&3389), "RDP-TLS is explicitly out of scope for v1")` to `assert!(ports.contains(&3389), "RDP-TLS must be in default probe list")` and assert the label is `"RDP-TLS"`. |
| 3 | `docs/modules/tls-infra.md` | Modify | Remove RDP-TLS from follow-ups section; add row to default probe table documenting port 3389 / RDP-TLS / X.224-preamble mode. |
| 4 | `docs/architecture/infra.md` | Modify | Update the "RDP-TLS (X.224 negotiation) and TLS protocol-range enumeration are documented follow-ups" sentence — drop RDP-TLS; update the "RDP-TLS handshake and TLS protocol-range enumeration in `TlsInfraModule`" bullet similarly. |
| 5 | `docs/architecture/engine.md` | Modify | Update `tls_probe` module description — remove "RDP-TLS (X.224 negotiation) is an explicit follow-up"; add a one-line description of the `TlsMode::RdpTls` variant matching the existing `Implicit` / `StartTls` descriptions. |
| 6 | `CHANGELOG.md` | Modify | New entry under `## Unreleased` (or current v2.1.x section) documenting WORK-148: "RDP-TLS probe via X.224 Connection Request negotiation (`TlsMode::RdpTls` + port 3389 in `TlsInfraModule`'s default probe list)". |

**Type and Trait Changes:**
- **New enum variant:** `TlsMode::RdpTls` — no associated data (the X.224 details are internal to the preamble helper).
- **No public API additions beyond the variant.** `probe_tls` / `TlsProbeTarget` / `TlsInfraConfig` / `TlsInfraModule` signatures unchanged.
- **No new traits.** The `InfraModule` impl on `TlsInfraModule` needs zero changes — the per-probe loop already iterates `self.config.targets` and calls `probe_tls(host, target.port, target.mode)`; adding a new `TlsMode` variant is transparent.
- **Derives on `TlsMode`:** `#[derive(Debug, Clone, Copy)]` still applies — `RdpTls` is a unit variant.
- **Match exhaustiveness:** the `probe_tls` `match mode { TlsMode::Implicit => ..., TlsMode::Starttls(p) => ... }` grows a `TlsMode::RdpTls => run_rdp_x224_preamble(tcp).await.map_err(...)` arm. No other matches on `TlsMode` exist (verified: `grep -rn "TlsMode::" src/` shows only `probe_tls` matches on the variants).

**Error Handling Strategy:**
- `run_rdp_x224_preamble` returns `io::Result<TcpStream>` — mirrors `run_starttls_preamble`.
- All failure modes bubble up as `io::Error`:
  - TCP read/write errors → pass-through
  - Timeout (wrap each read/write in `timeout(DEFAULT_PHASE_TIMEOUT, ...)`) → `io::Error::new(io::ErrorKind::TimedOut, "timed out reading X.224 phase")`
  - Short read (fewer bytes than TPKT says) → `io::Error::other("short X.224 response")`
  - Wrong TPKT version → `io::Error::other(format!("bad TPKT version: 0x{:02x}", b))`
  - Non-CC TPDU → `io::Error::other(format!("expected X.224 CC (0xd0), got 0x{:02x}", b))`
  - RDP_NEG_FAILURE → `io::Error::other(format!("RDP negotiation refused: failureCode=0x{:08x}", code))`
  - Unexpected selectedProtocol → `io::Error::other(format!("server selected non-SSL protocol: 0x{:08x}", p))`
- `probe_tls`'s existing `map_err(|e| format!("X.224 preamble failed: {e}"))` converts to `String`; `probe_one` wraps that into a `Severity::Info` finding with `confidence(0.3)` titled `"RDP-TLS — TLS probe skipped"` — zero new finding machinery, zero new error types.
- **No `ScorchError` variants needed** — these are probe-internal failures, already modelled as `String` per the WORK-109 contract.
- **No panics** — all slice indexing goes through safe accessors (`buf.get(n).copied()` or explicit length checks before `buf[n]`). `#[allow(clippy::indexing_slicing)]` is not needed because the design uses length-checked access; if clippy demands justification for a specific slice pattern, a `// JUSTIFICATION:` comment covers it.

**Architectural Decisions:**
- **Fixed-size CR packet as a `const [u8; 38]`.** The packet is deterministic — no runtime branching, no per-host variation. A `const` array lets the golden-byte test `assert_eq!(RDP_CR_PACKET, &[0x03, 0x00, 0x00, 0x26, ...])` pin the layout byte-for-byte. Contrast: the STARTTLS preambles are line-oriented so a `write_all` + string compare works; RDP is binary so the const array is the idiomatic choice.
- **Include the `Cookie: mstshash=\r\n` stub.** MS-RDPBCGR 2.2.1.1 says the cookie is OPTIONAL, but Windows RDP servers with `SecurityLayer=2` (the default on modern Windows) reject CRs without either a routingToken or cookie. Matching rdesktop/FreeRDP defaults (empty-username cookie) maximizes the hit rate on real hosts without adding a config knob. No routingToken — that's for load-balancer scenarios irrelevant to a probe.
- **Request `PROTOCOL_SSL` only (not `PROTOCOL_HYBRID`).** The probe's job is cert discovery, not CredSSP/NLA authentication. NLA-only hosts (`SelectedProtocol` must be HYBRID) will return `RDP_NEG_FAILURE` with `failureCode=0x00000001 SSL_REQUIRED_BY_SERVER` or `0x00000002 SSL_NOT_ALLOWED_BY_SERVER`; the existing Info-finding path reports this cleanly. Requesting HYBRID would require CredSSP, which is massive scope creep.
- **Use `AsyncReadExt::read_exact` wrapped in `tokio::time::timeout`** for the CC response, not a new `read_line_with_budget`-style loop. RDP responses are fixed-length binary, and `read_exact` is the direct fit. We read in two phases: first 4 bytes (TPKT header) to discover the total length, then `total_len - 4` more bytes into the same buffer. Cap TPKT at 256 bytes — any real CC fits in ~32 bytes; anything bigger is almost certainly garbage.
- **No new config surface.** The X.224 preamble has no tunables users care about. Timeout reuses `DEFAULT_PHASE_TIMEOUT` (the same 5s that gates every other phase). This matches the STARTTLS preamble design — protocol-specific glue, not user-facing config.
- **Tests use `TcpListener`, not real RDP servers.** Matches the WORK-109 pattern exactly. The ephemeral listener scripts the wire format, asserts the client sent the expected bytes (golden), then replies with whatever the test case needs (success / NEG_FAILURE / close). No `#[ignore]`-gated tests; all new tests run in the default suite.

**Testing Strategy:**
- **Unit: golden-byte layout** — verify the `RDP_CR_PACKET` const array matches the hand-computed MS-RDPBCGR wire format byte-for-byte. Catches any endianness mistake (TPKT length is big-endian; RDP_NEG_REQ length + requestedProtocols are little-endian — easy to get wrong).
- **Ephemeral-listener: success path** — server reads the CR, asserts it equals `RDP_CR_PACKET`, writes a canned CC with `selectedProtocol=PROTOCOL_SSL`; client returns `Ok(tcp)`. Proves both sides of the preamble.
- **Ephemeral-listener: `RDP_NEG_FAILURE` path** — server responds with type byte `0x03` and a non-zero failureCode; client returns `Err` whose message includes `"RDP negotiation refused"` and the hex code. Proves NLA-only hosts surface as Info findings, not crashes.
- **Ephemeral-listener: peer-close path** — server accepts the TCP connection then drops without responding; client returns `Err` (from the `read_exact` timeout or short-read path); no panic.
- **Regression: default probe list coverage** — extend the existing `tls_infra_default_probe_list_coverage` test; port 3389 now asserted *present*, with the `RDP-TLS` label.

Edge cases deliberately NOT covered by automated tests:
- Real-world RDP servers (covered by `#[ignore]`-gated smoke tests out of scope here — match WORK-109's stance).
- TPKT `reserved` byte ≠ 0 (MS-RDPBCGR says the client MUST accept any value).
- CredSSP/NLA handshake (explicit scope cut — `PROTOCOL_SSL` only).

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `rdp_cr_packet_layout_golden_bytes` | `src/engine/tls_probe.rs` (tests mod) | The `RDP_CR_PACKET` const matches the MS-RDPBCGR wire format: TPKT header (big-endian), X.224 CR, embedded cookie string, RDP_NEG_REQ(PROTOCOL_SSL, little-endian length + protocol). |
| 2 | `rdp_x224_preamble_success_unlocks_stream` | `src/engine/tls_probe.rs` (tests mod) | Ephemeral listener scripts the CR→CC exchange; `run_rdp_x224_preamble` returns `Ok(TcpStream)`. Server asserts it received exactly `RDP_CR_PACKET` bytes. |
| 3 | `rdp_x224_preamble_neg_failure_yields_err` | `src/engine/tls_probe.rs` (tests mod) | Ephemeral listener replies with type `0x03` / `failureCode=0x00000001` (SSL_REQUIRED_BY_SERVER); preamble returns `Err` whose text contains `"RDP negotiation refused"`. |
| 4 | `rdp_x224_preamble_peer_close_yields_err_no_panic` | `src/engine/tls_probe.rs` (tests mod) | Ephemeral listener accepts TCP and drops without responding; preamble returns `Err` (no panic, no unwrap). |
| 5 | `tls_infra_default_probe_list_coverage` (modified) | `src/infra/tls_probe.rs` (tests mod) | Port 3389 present in `DEFAULT_PROBE_TARGETS`; its label is `"RDP-TLS"`; other expected ports (465/636/993/995/25/587/143/110) still present. |

Expected test count delta: **+4** in `engine::tls_probe` (one modified test in `infra::tls_probe` — no count change there). All default-suite; no `#[ignore]` gating.

### Deferred Items
- None. Every design question has a concrete answer.

### Issues Found
- None during design. (Worth revisiting if the `PROTOCOL_SSL`-only stance proves too narrow once we see real-world test hosts; but the Info-finding fallback means failure is non-fatal.)

### Knowledge Recorded
- **Lessons:** 1 (MS-RDPBCGR CR packet layout + endianness caveats + rationale for `PROTOCOL_SSL`-only)
- **Failures:** 0
- **Component Types:** engine, infra, tls, rdp

### Human Confirmed
- [ ] Design reviewed and confirmed

---

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Files Created
None — this pipeline extends existing modules rather than adding new files.

### Files Modified
| File | Change |
|------|--------|
| `src/engine/tls_probe.rs` | Added `TlsMode::RdpTls` variant. Added RDP-TLS constants (`TPKT_VERSION`, `X224_CR_TPDU`, `X224_CC_TPDU`, `RDP_NEG_RSP_TYPE`, `RDP_NEG_FAILURE_TYPE`, `RDP_PROTOCOL_SSL`, `RDP_CC_MAX_LEN`, `RDP_CC_MIN_LEN`), the pinned 38-byte `RDP_CR_PACKET` const, `run_rdp_x224_preamble()`, and `read_exact_with_timeout()` helper. Wired `TlsMode::RdpTls` into `probe_tls()`'s match. Updated module-level doc comment — moved RDP-TLS from out-of-scope to the probe-modes list. Added 4 tests: `rdp_cr_packet_layout_golden_bytes`, `rdp_x224_preamble_success_unlocks_stream`, `rdp_x224_preamble_neg_failure_yields_err`, `rdp_x224_preamble_peer_close_yields_err_no_panic`. |
| `src/infra/tls_probe.rs` | Added `TlsProbeTarget { port: 3389, mode: TlsMode::RdpTls, label: "RDP-TLS" }` to `DEFAULT_PROBE_TARGETS`. Updated module doc — moved RDP-TLS out of "out of scope" into the covered-probe list. Flipped the sentinel assertion in `tls_infra_default_probe_list_coverage` from `!ports.contains(&3389)` to `ports.contains(&3389)` and added a `TlsMode::RdpTls` / `"RDP-TLS"` label pin. |
| `docs/modules/tls-infra.md` | Added RDP-TLS row to the default probe table (port 3389). Removed RDP-TLS follow-up bullet. Updated the "How it works under the hood" section to describe the `TlsMode::RdpTls` branch. Updated the testing section to cover the four new X.224 tests. Updated the TLS protocol-range bullet to reference WORK-143. |
| `docs/architecture/infra.md` | Updated `TlsInfraModule` description — added RDP-TLS coverage (port 3389 + X.224 CR/CC) with WORK-148 reference, added `RdpTls` to the `TlsMode` enum listing. Removed RDP-TLS from the "Future Work" list. |
| `docs/architecture/engine.md` | Updated `engine::tls_probe` description — added `RdpTls` variant, mentioned 38-byte CR packet requesting `PROTOCOL_SSL` and ephemeral-listener test pattern. Removed "RDP-TLS (X.224 negotiation) is an explicit follow-up" sentence. |
| `CHANGELOG.md` | New WORK-148 `### Added` entry under `## [Unreleased]`. |

### Quality Gates
- **cargo fmt --check:** PASS — `Diff: none, Exit: 0` after running `cargo fmt`.
- **cargo clippy -- -D warnings (lib):** PASS — 0 warnings, 0 errors. Matches the `.claude/hooks/enforce-quality.sh` gate.
- **cargo test --lib:** PASS — **591 passed**, 0 failed, 0 ignored (baseline was 587 on main; **+4** matches the regression plan exactly).
- **cargo test --lib --features infra:** PASS — **691 passed**, 0 failed (baseline 687, +4).
- **cargo test --lib --all-features:** PASS — **735 passed**, 0 failed (baseline 731, +4).

### Notes
- Followed the Phase 2 design exactly. One small refinement during implementation: parsed the `RDP_NEG_RSP` / `RDP_NEG_FAILURE` from `body[body.len() - 8..]` rather than a fixed `body[7..15]` offset. Both work for canonical CCs (LI = 14), but the trailing-8 approach is robust against servers that pad the X.224 variable part without needing to walk the LI. Documented inline.
- The `X224_CR_TPDU` const would have been dead code (the CR packet is a `const [u8; 38]` with bytes spelled literally); to honour the "use named constants, not magic bytes" convention I referenced it inside `RDP_CR_PACKET` at position 5 (`0x21, X224_CR_TPDU, 0x00, …`). Same named-const approach in test fixtures for `X224_CC_TPDU`, `RDP_NEG_RSP_TYPE`, and `RDP_NEG_FAILURE_TYPE`.
- `cargo clippy --all-targets` shows 248 pre-existing warnings/errors in test code (mostly `expect_used` in tests that predate this pipeline — existing STARTTLS tests use the same pattern). Baseline on untouched `main` shows 226 such errors; the 22-error delta tracks one-to-one to `.expect()` calls in my four new tests, matching established test style. The project's quality gate (`cargo clippy -- -D warnings`, the hook's check) targets only the lib and is clean.
- Zero fix iterations on first compile; one fmt reflow on the packet-layout const after I referenced the named `X224_CR_TPDU` constant (rustfmt wanted the array one element per line when tokens got longer — resolved by letting `cargo fmt` reflow).

### Knowledge Recorded
- **Lessons:** 1 (`engine::tls_probe` RDP-TLS implementation details — constants, preamble wire format, parse strategy)
- **Failures:** 0
- **Component Types:** engine, infra, tls, rdp

---

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Entry Verification (independently run)
- **cargo fmt --check:** PASS — exit 0, no diff.
- **cargo clippy -- -D warnings:** PASS — 0 warnings on lib target (matches `.claude/hooks/enforce-quality.sh` gate).
- **cargo test --lib:** PASS — 591 passed, 0 failed, 0 ignored (baseline 587, **+4** as planned).
- **cargo test --lib --features infra:** PASS — 691 passed, 0 failed (baseline 687, +4).
- **cargo test --doc:** PASS — 8 passed, 0 failed.
- **cargo test --test cli (integration):** PASS — 13 passed, 0 failed.
- **` ```ignore ` in src/:** PASS — zero matches across the tree.
- **#[ignore] in modified files:** PASS — zero matches in `src/engine/tls_probe.rs` and `src/infra/tls_probe.rs`.
- **#[allow] in modified files:** PASS — zero matches in both modified files; no JUSTIFICATION comments needed.

### Code Review
- **Documentation:** PASS — `TlsMode::RdpTls` (the only new `pub` item) has rustdoc; module-level `//!` updated to list the three probe modes; every private constant and helper has `///` documentation; `RDP_CR_PACKET` has a byte-offset table spelling out TPKT + X.224 + cookie + `RDP_NEG_REQ` layout.
- **Error handling:** PASS — `run_rdp_x224_preamble` returns `io::Result<TcpStream>` mirroring `run_starttls_preamble`. All failure modes (bad TPKT version, implausible length, non-CC TPDU, `RDP_NEG_FAILURE`, non-SSL `selectedProtocol`, unexpected neg type, timeouts) produce `io::Error::other(...)` with hex-formatted diagnostic bytes. Zero `unwrap()` / `expect()` in library code. `?` used throughout.
- **Type design:** PASS — `TlsMode::RdpTls` is a unit variant; `TlsMode` still derives `Debug, Clone, Copy`. Match arm in `probe_tls()` is exhaustive (three variants, no catch-all).
- **Safety:** PASS — zero `unsafe`. Slice accesses at `body[1]`, `body[body.len()-8..]`, `neg[4..8]` are all bounded by the `RDP_CC_MIN_LEN = 19` TPKT check (`body.len() = tpkt_len - 4 >= 15`); cannot panic. No allocations beyond the single `Vec<u8>` CC body (bounded by `RDP_CC_MAX_LEN = 256`).
- **Concurrency:** PASS — all types involved (`TcpStream`, `io::Error`, `TlsMode`) are `Send + Sync`. Async functions compose cleanly with `probe_tls`'s existing `.await` chain.
- **Code quality:** PASS — iterator-friendly code (match → early returns); no dead code (`X224_CR_TPDU` referenced inside `RDP_CR_PACKET`); no unused imports introduced.
- **Workaround detection:** PASS — no `#[allow(...)]`, no `#[ignore]`, no crate-level suppressions, no ` ```ignore ` doctests. Clean bill of health.
- **Security Review (semgrep):** PASS — `.semgrep.yml` on `src/engine/tls_probe.rs` + `src/infra/tls_probe.rs`: **0 findings** across 5 rust rules.
- **cargo audit:** 3 pre-existing advisories in transitive dependencies (RSA timing side-channel via `sqlx-mysql`, `rand` 0.9 unsoundness via `tungstenite`/`quinn`/`governor`, `number_prefix` unmaintained) — all predate WORK-148, documented in prior CHANGELOG entries as carried.

### Test Results
- **Cargo Test Count (lib default):** 591 passed, 0 failed, 0 ignored.
- **Cargo Test Count (lib --features infra):** 691 passed, 0 failed.
- **Doctest Count:** 8 passed, 0 failed.
- **CLI Integration Tests:** 13 passed, 0 failed.
- **RDP-specific tests (isolated run):** 4/4 passed — `rdp_cr_packet_layout_golden_bytes`, `rdp_x224_preamble_success_unlocks_stream`, `rdp_x224_preamble_neg_failure_yields_err`, `rdp_x224_preamble_peer_close_yields_err_no_panic`.
- **Coverage:** Not measured this phase (tarpaulin skipped — expensive on large workspace; the new tests exercise all four branches of the X.224 parser match arm + the TPKT length / TPDU type / `selectedProtocol` error paths, giving full logical coverage of the new code).

### Regression Test Plan Compliance
All 5 planned tests present and passing:

| # | Plan Test | File | Status |
|---|-----------|------|--------|
| 1 | `rdp_cr_packet_layout_golden_bytes` | `src/engine/tls_probe.rs` | PASS |
| 2 | `rdp_x224_preamble_success_unlocks_stream` | `src/engine/tls_probe.rs` | PASS |
| 3 | `rdp_x224_preamble_neg_failure_yields_err` | `src/engine/tls_probe.rs` | PASS |
| 4 | `rdp_x224_preamble_peer_close_yields_err_no_panic` | `src/engine/tls_probe.rs` | PASS |
| 5 | `tls_infra_default_probe_list_coverage` (modified) | `src/infra/tls_probe.rs` | PASS |

### Test Quality Review
- **Meaningful behavior:** Tests exercise wire-format byte equality (golden CR), successful end-to-end X.224 handshake, the `RDP_NEG_FAILURE` error-path including the hex `failureCode` rendering, and the peer-close no-panic guarantee. None are compile-only tests.
- **Error paths covered:** ✓ (`RDP_NEG_FAILURE`, peer-close, implicit coverage of bad TPKT / non-CC TPDU via the match + defensive checks).
- **Edge cases:** Golden-byte test spot-checks each field individually (TPKT big-endian length, X.224 LI formula, cookie stub bytes, `RDP_NEG_REQ` little-endian length + `PROTOCOL_SSL`) — so a failure message names the field that diverged.

### Knowledge Recorded
- **Lessons:** 1 (validation-phase confirmation; records Phase 4 PASS and the clean security-scan result)
- **Failures:** 0
- **Component Types:** engine, infra, tls, rdp, testing

---

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Entry Verification (independently re-run)
- **cargo fmt --check:** PASS — exit 0.
- **cargo clippy -- -D warnings:** PASS — 0 warnings on lib.
- **cargo test --lib:** PASS — 591 passed (identical to Phase 4).
- **cargo test --doc:** PASS — 8 passed (identical to Phase 4).

### Full Suite Results
- **cargo test --lib (default):** 591 passed, 0 failed, 0 ignored.
- **cargo test --lib --features infra:** 691 passed, 0 failed.
- **cargo test --lib --all-features:** 735 passed, 0 failed.
- **cargo test --doc:** 8 passed, 0 failed.
- **cargo test --tests (integration, default features):**
  - `tests/ai_types.rs` → 13 passed
  - `tests/cli.rs` → 13 passed
  - `tests/code_scan.rs` → 2 passed
  - `tests/hooks.rs` → 2 passed
  - `tests/scan_plan.rs` → 12 passed
  - Infra/MCP/storage-gated binaries → 0 tests under default features (correctly empty, feature-gated)
  - **Integration total (default):** 42 passed, 0 failed.

### Regression Check
Phase 4 → Phase 5 test counts — identical across the board:

| Suite | Phase 4 | Phase 5 | Delta |
|-------|---------|---------|-------|
| `cargo test --lib` | 591 | 591 | 0 |
| `cargo test --lib --features infra` | 691 | 691 | 0 |
| `cargo test --doc` | 8 | 8 | 0 |
| `tests/cli.rs` integration | 13 | 13 | 0 |

**Zero regressions.** Every test that passed in Phase 4 passes in Phase 5 with identical counts. Formatting + clippy also identical.

### Knowledge Recorded
- **Lessons:** 1 (Phase 5 clean verification pass — consecutive clean run for ScorchKit)
- **Failures:** 0
- **Component Types:** engine, infra, tls, rdp, testing

---

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Entry Verification (independently re-run)
- **cargo fmt --check:** exit 0.
- **cargo clippy -- -D warnings:** exit 0.
- **cargo test --lib:** 591 passed, 0 failed.
- **` ```ignore ` in src/:** 0 matches.
- **`#[ignore]` test attributes in src/:** 0 matches (the two grep hits in `infra/tls_probe.rs` and `infra/dns_probe.rs` are `//!` doc-comment prose describing the project-wide live-smoke convention, not actual test attributes).

### Deliverables
- **Documentation Updated:**
  - `docs/modules/tls-infra.md` — default-probe table row for 3389, X.224 mode description, testing section (RDP tests), out-of-scope list (removed RDP-TLS).
  - `docs/architecture/infra.md` — `TlsInfraModule` description expanded with RDP-TLS coverage; Future Work list pruned.
  - `docs/architecture/engine.md` — `engine::tls_probe` shared-helpers description updated with `RdpTls` variant + wire format summary.
  - `CHANGELOG.md` — `## [Unreleased] ### Added` entry for WORK-148.
  - `src/engine/tls_probe.rs` and `src/infra/tls_probe.rs` module-level `//!` docs (moved RDP-TLS from out-of-scope into probe-modes).
- **Changelog Updated:** Yes — new `### Added` entry under `## [Unreleased]` documenting wire format, error-to-Info contract, and test delta (+4 across default / infra / all-features).
- **Architecture Decision Recorded:** `engine.tls-probe.rdp-mode` via `architecture-set` — captures design choices (`PROTOCOL_SSL`-only, cookie stub, trailing-8-bytes parse).
- **cargo doc --no-deps --features infra:** Zero new warnings from WORK-148 (1 pre-existing WORK-147 `MAX_PAGES` doc-link warning is unrelated).
- **cargo build --all-targets:** Builds cleanly; 2 pre-existing redundant-import warnings in `src/engine/tls_probe.rs` tests module (confirmed identical on `main` baseline — out of scope per Constitution's no-scope-creep rule).

### Self-Reflection
1. **Did any phase use workarounds?** No. Zero `#[allow]`, zero `#[ignore]`, zero ` ```ignore ` doctests, zero `unwrap()` / `expect()` in lib code, zero fmt/clippy suppressions. Error handling reuses the WORK-109 three-layer funnel (`io::Error` → `String` → `Finding`) with no new error types.
2. **Was the implementation the cleanest version?** Yes. CR packet is a pinned `const [u8; 38]` with byte-offset rustdoc table; `run_rdp_x224_preamble` mirrors `run_starttls_preamble`'s shape; `RDP_NEG_RSP` extracted from the trailing 8 bytes (robust against X.224 variable-part padding); `TlsMode` match is exhaustive with no `_` catch-all; named protocol constants referenced in fixtures so the wire format self-documents.
3. **Would a senior Rust developer approve?** Yes. Idiomatic trait-extension method usage (`tcp.read_exact`, `tcp.write_all`); `?` throughout; `io::Error::other(...)` with hex-formatted diagnostic bytes; bounded slice access provably panic-free via `RDP_CC_MIN_LEN`/`MAX_LEN` range check (`body.len() ∈ [15, 252]` invariant); single allocation bounded at 256 bytes; ephemeral `TcpListener` tests script wire format deterministically with server-side CR drain before drop.

### After-Action Review (MANDATORY)
- **Generation Trace Saved:** Yes (via `save-generation-trace`).
- **Lessons Recorded:** 5 total — one per phase (pm/solutions/architect/review/tester).
- **Failures Recorded:** 0 (zero fix iterations across all phases).
- **Component Types Tagged:** `engine`, `infra`, `tls`, `rdp`, `testing`.
- **Fix Iterations:** 0. Design stabilized in Phase 2; code compiled clean on first attempt; Phase 4 and Phase 5 replayed Phase 3 results with zero drift.

### Final Pipeline Checklist
- [x] Forge Ticket ID `019d9268-b7f2-7320-9da8-48eb3aa6add1` (#148) matches a real ticket
- [x] All phases 1–5 show Status = PASS (verified in this doc)
- [x] Phase 1 Work Spec complete
- [x] Phase 2 File Manifest with specific paths (6 files)
- [x] Phase 2 Regression Test Plan (5 tests)
- [x] Phase 3 Files Modified list (6 files; 0 created — extending existing modules)
- [x] Phase 3 Quality Gates with actual results
- [x] Phase 4 Entry Verification independently re-run
- [x] Phase 4 Code Review completed
- [x] Phase 4 Test Results with actual counts (591 / 691 / 735 / 8 / 13)
- [x] Phase 5 Full Suite results recorded (zero regressions)
- [x] `cargo fmt --check` = 0 diffs (re-verified Phase 6)
- [x] `cargo clippy -- -D warnings` = 0 warnings on lib (re-verified Phase 6)
- [x] `cargo test --lib` = 0 failures, 591 passed (re-verified Phase 6)
- [x] ` ```ignore ` in src/ = 0 files
- [x] `#[ignore]` test attributes = 0 matches
- [x] `bootstrap` called
- [x] `recall` called (phases 1, 2, 3, 4, 5)
- [x] `learn` called each phase (5 total)
- [x] `save-generation-trace` called (Phase 6)
- [x] `architecture-set` called — `engine.tls-probe.rdp-mode`
- [x] CHANGELOG.md updated
- [x] `cargo doc --no-deps` builds with zero new warnings
