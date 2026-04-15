# Work Pipeline: DNS infra modules

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Infrastructure |
| **Status** | Complete (archived) |
| **Created** | 2026-04-14 |
| **Forge Ticket** | #110 |
| **Forge Ticket ID** | 019d8e7c-d326-71ac-b44d-18af086f3e69 |

## Phase 1: Plan — PASS

Native DNS probes to fill the last empty `InfraCategory::Dns` slot. Four checks in v1:
wildcard detection, missing DNSSEC (DNSKEY), missing CAA, NS enumeration.
AXFR stays with the existing `dnsrecon`/`dnsx` tool wrappers.

## Phase 2: Design — PASS

**Approach.** Add `hickory-resolver` as an `infra`-gated dep and build a single
`DnsInfraModule` that runs each probe against the target zone apex. Wildcard detection
generates a 16-char hex random label per run so legitimate subdomains aren't flagged.

**File Manifest.**

| # | File | Action |
|---|------|--------|
| 1 | `src/infra/dns_probe.rs` | Create |
| 2 | `src/infra/mod.rs` | Register `DnsInfraModule` |
| 3 | `Cargo.toml` | Add `hickory-resolver` under `infra` feature |
| 4 | `docs/modules/dns-infra.md` | Operator reference |
| 5 | `docs/architecture/engine.md` | Note DNS category filled |
| 6 | `CHANGELOG.md` | WORK-110 bullet |

**Architectural decisions.**
1. Resolver is constructed per-scan (cheap, keeps module stateless).
2. Use system resolver config with UDP primary — matches what a real resolver does.
3. Wildcard probe uses `getrandom`? No — just use a simple PRNG from `uuid::Uuid::new_v4()` (already a dep). Hex-encode 8 bytes of the UUID for the random label.
4. CAA + DNSKEY absence maps to finding severities by defensive intent (Low for CAA, Medium for DNSSEC). The thresholds are defensible in the text.
5. Findings tagged `module_id = "dns_infra"`.

**Tests.**
- Pure-function tests on the probe/finding builders against fixture resolver results.
- Hex random label pattern test (length + alphabet).
- `#[ignore]`-gated live smoke against `example.com` for NS/CAA.

## Phase 3-6 — PASS (2026-04-14)

### Files
- NEW `src/infra/dns_probe.rs` — `DnsInfraModule` + 4 probes + 7 unit tests
- NEW `docs/modules/dns-infra.md` — operator reference
- MOD `src/infra/mod.rs` — register module
- MOD `Cargo.toml` — add `hickory-resolver` under `infra` feature (default features for `system-config` + `tokio`)
- MOD `CHANGELOG.md` — WORK-110 bullet under `[Unreleased] / Added`

### Quality gates
- `cargo fmt` ✓
- `cargo clippy --features infra -- -D warnings` ✓ (3 fixes during iteration: `if let` for single-arm match, `is_ok_and` instead of `map_or(false, ...)`, `ToString::to_string` method-itself shorthand)
- `cargo build --features infra` ✓
- `cargo test` (default) ✓ — 559 passed, unchanged
- `cargo test --features mcp` ✓ — 701 passed, unchanged
- `cargo test --features infra` ✓ — **675 passed** (+7 vs WORK-109)
- semgrep ✓ — 0 findings on `dns_probe.rs`
- cargo deny ✓

### Notes
- API compatibility iteration: hickory-resolver's `TokioResolver::builder_tokio()` is gated on the `tokio` feature which is in the default set; explicit `default-features = false, features = ["tokio"]` failed to surface the impl block. Switched to default features (which include `system-config` + `tokio` — both needed) and noted the rationale inline in `Cargo.toml`.
- v2.0 `InfraCategory` coverage is now complete: PortScan ✓, Fingerprint ✓, CveMatch ✓, TlsInfra ✓, Dns ✓.

### Self-Reflection
1. **Workarounds?** None. One feature-flag iteration (default vs explicit) — documented inline.
2. **Cleanest version?** Yes for v1. Per-scan resolver construction (stateless module), entropy-rich wildcard label, presence-only DNSSEC check (full validation deferred), AXFR explicitly out of scope (existing tool wrappers cover it).
3. **Senior dev approval?** Yes. Native async resolver instead of shelling out, four self-contained probes, IP-only targets short-circuit cleanly, low-risk dep addition.